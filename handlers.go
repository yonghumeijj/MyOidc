package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type AuthRequest struct {
	ResponseType string
	ClientID     string
	RedirectURI  string
	Scope        string
	State        string
	Nonce        string
}

type AdminPageData struct {
	Issuer          string
	AllowedDomain   string
	ClientID        string
	ClientSecret    string
	AdminUser       string
	AllowedRedirect string
	Generated       []GeneratedKey
	Keys            []KeyView
	Error           string
}

type LoginPageData struct {
	Auth  AuthRequest
	Error string
}

func (a *App) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (a *App) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.renderAdmin(w, nil, "")
}

func (a *App) handleAdminKeys(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		a.renderAdmin(w, nil, "invalid form")
		return
	}

	count, _ := strconv.Atoi(r.FormValue("count"))
	if count <= 0 {
		count = 1
	}
	expiresHours, _ := strconv.Atoi(r.FormValue("expires_hours"))
	var expiresAt *time.Time
	if expiresHours > 0 {
		t := time.Now().UTC().Add(time.Duration(expiresHours) * time.Hour)
		expiresAt = &t
	}

	boundEmails := parseLines(r.FormValue("bound_emails"))
	for i, email := range boundEmails {
		email = normalizeEmail(email)
		if !emailInDomain(email, a.cfg.AllowedDomain) {
			a.renderAdmin(w, nil, fmt.Sprintf("bound email must end with @%s: %s", a.cfg.AllowedDomain, email))
			return
		}
		boundEmails[i] = email
	}

	generated, err := a.store.GenerateKeys(count, boundEmails, expiresAt)
	if err != nil {
		a.renderAdmin(w, nil, err.Error())
		return
	}
	a.renderAdmin(w, generated, "")
}

func (a *App) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		a.renderAdmin(w, nil, "invalid form")
		return
	}
	if err := a.store.RevokeKey(r.FormValue("id")); err != nil {
		a.renderAdmin(w, nil, err.Error())
		return
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (a *App) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	auth := authRequestFromValues(r.Form)
	if err := a.validateAuthRequest(auth); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if email, ok := a.readSessionEmail(r); ok {
		a.redirectWithCode(w, r, auth, email)
		return
	}
	a.renderLogin(w, auth, "")
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	auth := authRequestFromValues(r.Form)
	if err := a.validateAuthRequest(auth); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email := normalizeEmail(r.FormValue("email"))
	key := strings.TrimSpace(r.FormValue("key"))
	if email == "" || key == "" {
		a.renderLogin(w, auth, "email and key are required")
		return
	}

	user, err := a.store.UseInviteKey(email, key, a.cfg.AllowedDomain)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidEmailDomain):
			a.renderLogin(w, auth, fmt.Sprintf("email must end with @%s", a.cfg.AllowedDomain))
		default:
			a.renderLogin(w, auth, "key is invalid, used, expired, revoked, or bound to another email")
		}
		return
	}

	a.setSessionCookie(w, user.Email)
	a.redirectWithCode(w, r, auth, user.Email)
}

func (a *App) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}

	clientID, clientSecret := clientCredentials(r)
	if clientID == "" {
		clientID = r.FormValue("client_id")
	}
	if clientSecret == "" {
		clientSecret = r.FormValue("client_secret")
	}
	if clientID != a.cfg.ClientID || !constantTimeStringEqual(clientSecret, a.cfg.ClientSecret) {
		w.Header().Set("WWW-Authenticate", `Basic realm="gooidc"`)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}

	if r.FormValue("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
		return
	}

	redirectURI := r.FormValue("redirect_uri")
	if !a.validRedirectURI(redirectURI) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_redirect_uri"})
		return
	}

	user, authCode, err := a.store.ConsumeAuthCode(r.FormValue("code"), clientID, redirectURI)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}

	accessToken, err := a.store.CreateAccessToken(user.Email)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		return
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"iss":                a.cfg.Issuer,
		"sub":                user.Sub,
		"aud":                a.cfg.ClientID,
		"iat":                now.Unix(),
		"exp":                now.Add(time.Hour).Unix(),
		"auth_time":          authCode.CreatedAt.Unix(),
		"email":              user.Email,
		"email_verified":     true,
		"name":               user.Email,
		"preferred_username": user.Email,
	}
	if authCode.Nonce != "" {
		claims["nonce"] = authCode.Nonce
	}

	idToken, err := a.signer.SignIDToken(claims)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func (a *App) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
		return
	}
	token := strings.TrimSpace(auth[len("Bearer "):])
	user, err := a.store.LookupAccessToken(token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":                user.Sub,
		"email":              user.Email,
		"email_verified":     true,
		"name":               user.Email,
		"preferred_username": user.Email,
	})
}

func (a *App) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                a.cfg.Issuer,
		"authorization_endpoint":                a.cfg.Issuer + "/authorize",
		"token_endpoint":                        a.cfg.Issuer + "/token",
		"userinfo_endpoint":                     a.cfg.Issuer + "/userinfo",
		"jwks_uri":                              a.cfg.Issuer + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"claims_supported":                      []string{"sub", "email", "email_verified", "name", "preferred_username"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
	})
}

func (a *App) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{a.signer.JWK()}})
}

func (a *App) redirectWithCode(w http.ResponseWriter, r *http.Request, auth AuthRequest, email string) {
	code, err := a.store.CreateAuthCode(email, auth.ClientID, auth.RedirectURI, auth.Nonce, auth.Scope)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	u, err := url.Parse(auth.RedirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("code", code)
	if auth.State != "" {
		q.Set("state", auth.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (a *App) validateAuthRequest(auth AuthRequest) error {
	if auth.ResponseType != "code" {
		return fmt.Errorf("unsupported response_type")
	}
	if auth.ClientID != a.cfg.ClientID {
		return fmt.Errorf("invalid client_id")
	}
	if auth.RedirectURI == "" || !a.validRedirectURI(auth.RedirectURI) {
		return fmt.Errorf("invalid redirect_uri")
	}
	if !scopeContains(auth.Scope, "openid") {
		return fmt.Errorf("scope must include openid")
	}
	return nil
}

func (a *App) validRedirectURI(uri string) bool {
	if uri == "" {
		return false
	}
	if len(a.cfg.AllowedRedirect) == 0 {
		return true
	}
	return a.cfg.AllowedRedirect[uri]
}

func authRequestFromValues(v url.Values) AuthRequest {
	return AuthRequest{
		ResponseType: v.Get("response_type"),
		ClientID:     v.Get("client_id"),
		RedirectURI:  v.Get("redirect_uri"),
		Scope:        v.Get("scope"),
		State:        v.Get("state"),
		Nonce:        v.Get("nonce"),
	}
}

func clientCredentials(r *http.Request) (string, string) {
	user, pass, ok := r.BasicAuth()
	if ok {
		return user, pass
	}
	return "", ""
}

func scopeContains(scope string, want string) bool {
	for _, item := range strings.Fields(scope) {
		if item == want {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok ||
		!constantTimeStringEqual(user, a.cfg.AdminUser) ||
		!constantTimeStringEqual(pass, a.cfg.AdminPassword) {
		w.Header().Set("WWW-Authenticate", `Basic realm="gooidc admin"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (a *App) renderAdmin(w http.ResponseWriter, generated []GeneratedKey, errText string) {
	redirects := make([]string, 0, len(a.cfg.AllowedRedirect))
	for redirect := range a.cfg.AllowedRedirect {
		redirects = append(redirects, redirect)
	}
	data := AdminPageData{
		Issuer:          a.cfg.Issuer,
		AllowedDomain:   a.cfg.AllowedDomain,
		ClientID:        a.cfg.ClientID,
		ClientSecret:    a.cfg.ClientSecret,
		AdminUser:       a.cfg.AdminUser,
		AllowedRedirect: strings.Join(redirects, "\n"),
		Generated:       generated,
		Keys:            a.store.KeyViews(),
		Error:           errText,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, "admin", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (a *App) renderLogin(w http.ResponseWriter, auth AuthRequest, errText string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, "login", LoginPageData{Auth: auth, Error: errText}); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func parseLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
