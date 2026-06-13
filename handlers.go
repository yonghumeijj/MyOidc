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
	AdminUser string
	Tenants   []Tenant
	Tenant    Tenant
	Origin    string
	Generated []GeneratedKey
	Keys      []KeyView
	Error     string
	Notice    string
}

type LoginPageData struct {
	Auth           AuthRequest
	AllowedDomains string
	Error          string
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
	a.renderAdmin(w, r, nil, "")
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
		a.renderAdmin(w, r, nil, "invalid form")
		return
	}

	tenant, err := a.adminTenantFromRequest(r)
	if err != nil {
		a.renderAdmin(w, r, nil, err.Error())
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
		if !emailInDomains(email, tenant.AllowedDomains) {
			a.renderAdmin(w, r, nil, fmt.Sprintf("bound email must match one of %s: %s", allowedDomainsLabel(tenant), email))
			return
		}
		boundEmails[i] = email
	}

	generated, err := a.store.GenerateKeys(tenant.ID, count, boundEmails, expiresAt)
	if err != nil {
		a.renderAdmin(w, r, nil, err.Error())
		return
	}
	a.renderAdmin(w, r, generated, "")
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
		a.renderAdmin(w, r, nil, "invalid form")
		return
	}
	tenantID := strings.TrimSpace(r.FormValue("tenant_id"))
	if err := a.store.RevokeKey(tenantID, r.FormValue("id")); err != nil {
		a.renderAdmin(w, r, nil, err.Error())
		return
	}
	http.Redirect(w, r, "/admin?tenant="+url.QueryEscape(tenantID), http.StatusFound)
}

func (a *App) handleAdminTenants(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		a.renderAdmin(w, r, nil, "invalid form")
		return
	}

	tenant, err := a.store.SaveTenant(TenantInput{
		ID:             r.FormValue("tenant_id"),
		IssuerURL:      r.FormValue("issuer_url"),
		AllowedDomains: formValueFirst(r, "allowed_domains", "allowed_domain"),
		ClientID:       r.FormValue("client_id"),
		ClientSecret:   r.FormValue("client_secret"),
		RedirectURIs:   r.FormValue("redirect_uris"),
	})
	if err != nil {
		a.renderAdmin(w, r, nil, err.Error())
		return
	}
	http.Redirect(w, r, "/admin?tenant="+url.QueryEscape(tenant.ID)+"&notice=tenant_saved", http.StatusFound)
}

func (a *App) handleAdminPassword(w http.ResponseWriter, r *http.Request) {
	if !a.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		a.renderAdmin(w, r, nil, "invalid form")
		return
	}
	password := strings.TrimSpace(r.FormValue("new_password"))
	confirm := strings.TrimSpace(r.FormValue("confirm_password"))
	if len(password) < 12 {
		a.renderAdmin(w, r, nil, "admin password must be at least 12 characters")
		return
	}
	if password != confirm {
		a.renderAdmin(w, r, nil, "admin password confirmation does not match")
		return
	}
	if err := saveTextSecret(a.cfg.AdminPassPath, password); err != nil {
		a.renderAdmin(w, r, nil, "save admin password failed: "+err.Error())
		return
	}
	a.setAdminPassword(password)
	http.Redirect(w, r, "/admin?tenant="+url.QueryEscape(r.FormValue("tenant_id"))+"&notice=password_saved", http.StatusFound)
}

func (a *App) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	tenant, ok := a.tenantForRequest(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	auth := authRequestFromValues(r.Form)
	if err := a.validateAuthRequest(tenant, auth); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if email, ok := a.readSessionEmail(r, tenant); ok {
		a.redirectWithCode(w, r, tenant, auth, email)
		return
	}
	a.renderLogin(w, tenant, auth, "")
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	tenant, ok := a.tenantForRequest(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	auth := authRequestFromValues(r.Form)
	if err := a.validateAuthRequest(tenant, auth); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	email := normalizeEmail(r.FormValue("email"))
	key := strings.TrimSpace(r.FormValue("key"))
	if email == "" || key == "" {
		a.renderLogin(w, tenant, auth, "email and key are required")
		return
	}

	user, err := a.store.UseInviteKey(tenant.ID, email, key, tenant.AllowedDomains)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidEmailDomain):
			a.renderLogin(w, tenant, auth, fmt.Sprintf("email must match one of: %s", allowedDomainsLabel(tenant)))
		default:
			a.renderLogin(w, tenant, auth, "key is invalid, used, expired, revoked, or bound to another email")
		}
		return
	}

	a.setSessionCookie(w, tenant, user.Email)
	a.redirectWithCode(w, r, tenant, auth, user.Email)
}

func (a *App) handleToken(w http.ResponseWriter, r *http.Request) {
	tenant, ok := a.tenantForRequest(w, r)
	if !ok {
		return
	}
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
	if clientID != tenant.ClientID || !constantTimeStringEqual(clientSecret, tenant.ClientSecret) {
		w.Header().Set("WWW-Authenticate", `Basic realm="gooidc"`)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client"})
		return
	}

	if r.FormValue("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_grant_type"})
		return
	}

	redirectURI := r.FormValue("redirect_uri")
	if !validRedirectURI(tenant, redirectURI) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_redirect_uri"})
		return
	}

	user, authCode, err := a.store.ConsumeAuthCode(tenant.ID, r.FormValue("code"), clientID, redirectURI)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}

	accessToken, err := a.store.CreateAccessToken(tenant.ID, user.Email)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		return
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"iss":                tenant.IssuerURL,
		"sub":                user.Sub,
		"aud":                tenant.ClientID,
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
	tenant, ok := a.tenantForRequest(w, r)
	if !ok {
		return
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
		return
	}
	token := strings.TrimSpace(auth[len("Bearer "):])
	user, err := a.store.LookupAccessToken(tenant.ID, token)
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
	tenant, ok := a.tenantForRequest(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                tenant.IssuerURL,
		"authorization_endpoint":                tenant.IssuerURL + "/authorize",
		"token_endpoint":                        tenant.IssuerURL + "/token",
		"userinfo_endpoint":                     tenant.IssuerURL + "/userinfo",
		"jwks_uri":                              tenant.IssuerURL + "/jwks.json",
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
	if _, ok := a.tenantForRequest(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{a.signer.JWK()}})
}

func (a *App) redirectWithCode(w http.ResponseWriter, r *http.Request, tenant Tenant, auth AuthRequest, email string) {
	code, err := a.store.CreateAuthCode(tenant.ID, email, auth.ClientID, auth.RedirectURI, auth.Nonce, auth.Scope)
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

func (a *App) validateAuthRequest(tenant Tenant, auth AuthRequest) error {
	if auth.ResponseType != "code" {
		return fmt.Errorf("unsupported response_type")
	}
	if auth.ClientID != tenant.ClientID {
		return fmt.Errorf("invalid client_id")
	}
	if auth.RedirectURI == "" || !validRedirectURI(tenant, auth.RedirectURI) {
		return fmt.Errorf("invalid redirect_uri")
	}
	if !scopeContains(auth.Scope, "openid") {
		return fmt.Errorf("scope must include openid")
	}
	return nil
}

func validRedirectURI(tenant Tenant, uri string) bool {
	if uri == "" {
		return false
	}
	redirects := tenant.RedirectURISet()
	if len(redirects) == 0 {
		return true
	}
	return redirects[uri]
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
	adminPassword := a.adminPassword()
	if !ok ||
		!constantTimeStringEqual(user, a.cfg.AdminUser) ||
		!constantTimeStringEqual(pass, adminPassword) {
		w.Header().Set("WWW-Authenticate", `Basic realm="gooidc admin"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (a *App) adminPassword() string {
	a.adminMu.RLock()
	defer a.adminMu.RUnlock()
	return a.cfg.AdminPassword
}

func (a *App) setAdminPassword(password string) {
	a.adminMu.Lock()
	defer a.adminMu.Unlock()
	a.cfg.AdminPassword = password
}

func (a *App) tenantForRequest(w http.ResponseWriter, r *http.Request) (Tenant, bool) {
	tenant, err := a.store.TenantByHost(r.Host)
	if err != nil {
		http.Error(w, "unknown issuer host", http.StatusNotFound)
		return Tenant{}, false
	}
	return tenant, true
}

func (a *App) adminTenantFromRequest(r *http.Request) (Tenant, error) {
	tenantID := strings.TrimSpace(r.FormValue("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.URL.Query().Get("tenant"))
	}
	if tenantID != "" {
		return a.store.TenantByID(tenantID)
	}
	tenants, err := a.store.Tenants()
	if err != nil {
		return Tenant{}, err
	}
	if len(tenants) == 0 {
		return Tenant{}, fmt.Errorf("no tenants configured")
	}
	return tenants[0], nil
}

func (a *App) renderAdmin(w http.ResponseWriter, r *http.Request, generated []GeneratedKey, errText string) {
	noticeText := adminNotice(r)
	tenants, err := a.store.Tenants()
	if err != nil {
		http.Error(w, "load tenants failed", http.StatusInternalServerError)
		return
	}
	var tenant Tenant
	if len(tenants) > 0 {
		tenant, err = a.adminTenantFromRequest(r)
		if err != nil {
			tenant = tenants[0]
			if errText == "" {
				errText = err.Error()
			}
		}
	}
	if tenant.ID != "" {
		if updated, notice, err := a.maybeAdoptCurrentIssuer(r, tenant); err != nil {
			if errText == "" {
				errText = err.Error()
			}
		} else if notice != "" {
			tenant = updated
			if noticeText == "" {
				noticeText = notice
			}
			tenants, _ = a.store.Tenants()
		}
	}
	data := AdminPageData{
		AdminUser: a.cfg.AdminUser,
		Tenants:   tenants,
		Tenant:    tenant,
		Origin:    currentOrigin(r),
		Generated: generated,
		Keys:      a.store.KeyViews(tenant.ID),
		Error:     errText,
		Notice:    noticeText,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, "admin", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func (a *App) maybeAdoptCurrentIssuer(r *http.Request, tenant Tenant) (Tenant, string, error) {
	origin := currentOrigin(r)
	if origin == "" || isLocalOrigin(origin) || !isLocalOrigin(tenant.IssuerURL) {
		return tenant, "", nil
	}
	updated, err := a.store.SaveTenant(TenantInput{
		ID:             tenant.ID,
		IssuerURL:      origin,
		AllowedDomains: tenant.AllowedDomains,
		ClientID:       tenant.ClientID,
		ClientSecret:   tenant.ClientSecret,
		RedirectURIs:   tenant.RedirectURIs,
	})
	if err != nil {
		return tenant, "", err
	}
	return updated, "Default issuer URL updated from localhost to " + origin + ".", nil
}

func currentOrigin(r *http.Request) string {
	host := firstHeaderValue(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	host = normalizeHost(host)
	if host == "" {
		return ""
	}
	proto := strings.ToLower(firstHeaderValue(r.Header.Get("X-Forwarded-Proto")))
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	if proto != "https" && proto != "http" {
		proto = "https"
	}
	return proto + "://" + host
}

func firstHeaderValue(value string) string {
	if idx := strings.Index(value, ","); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}

func isLocalOrigin(origin string) bool {
	u, err := url.Parse(strings.TrimSpace(origin))
	if err != nil {
		return false
	}
	host := normalizeHost(u.Host)
	return host == "localhost" ||
		strings.HasPrefix(host, "localhost:") ||
		host == "127.0.0.1" ||
		strings.HasPrefix(host, "127.0.0.1:")
}

func adminNotice(r *http.Request) string {
	switch r.URL.Query().Get("notice") {
	case "tenant_saved":
		return "Tenant settings saved."
	case "password_saved":
		return "Admin password updated."
	default:
		return ""
	}
}

func (a *App) renderLogin(w http.ResponseWriter, tenant Tenant, auth AuthRequest, errText string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pages.ExecuteTemplate(w, "login", LoginPageData{
		Auth:           auth,
		AllowedDomains: allowedDomainsLabel(tenant),
		Error:          errText,
	}); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func allowedDomainsLabel(tenant Tenant) string {
	var labels []string
	for _, domain := range tenant.AllowedDomainList() {
		labels = append(labels, "@"+domain)
	}
	return strings.Join(labels, ", ")
}

func formValueFirst(r *http.Request, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(r.FormValue(name)); value != "" {
			return value
		}
	}
	return ""
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
