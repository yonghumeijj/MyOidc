package main

import (
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestMaybeAdoptCurrentIssuerFromAdminHost(t *testing.T) {
	store := newTestStore(t)
	tenant := newTestTenant(t, store)
	tenant, err := store.SaveTenant(TenantInput{
		ID:             tenant.ID,
		IssuerURL:      "http://localhost:8080",
		AllowedDomains: tenant.AllowedDomains,
		ClientID:       tenant.ClientID,
		ClientSecret:   tenant.ClientSecret,
		RedirectURIs:   tenant.RedirectURIs,
	})
	if err != nil {
		t.Fatalf("SaveTenant: %v", err)
	}

	app := &App{store: store}
	req := httptest.NewRequest("GET", "http://oidc.ai90.net/admin", nil)
	req.Host = "oidc.ai90.net"
	req.Header.Set("X-Forwarded-Proto", "https")

	updated, notice, err := app.maybeAdoptCurrentIssuer(req, tenant)
	if err != nil {
		t.Fatalf("maybeAdoptCurrentIssuer: %v", err)
	}
	if notice == "" {
		t.Fatalf("notice is empty, want adoption notice")
	}
	if updated.IssuerURL != "https://oidc.ai90.net" {
		t.Fatalf("IssuerURL = %q, want https://oidc.ai90.net", updated.IssuerURL)
	}
	if got, err := store.TenantByHost("oidc.ai90.net"); err != nil || got.ID != tenant.ID {
		t.Fatalf("TenantByHost after adoption = %#v, %v", got, err)
	}
}

func TestClientCredentialsDecodeOAuthBasicAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "https://oidc.example/token", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("openai:secret%2Bwith%2Fchars%3D")))

	clientID, clientSecret, authMethod := clientCredentials(req)
	if clientID != "openai" {
		t.Fatalf("clientID = %q, want openai", clientID)
	}
	if clientSecret != "secret+with/chars=" {
		t.Fatalf("clientSecret = %q, want decoded secret", clientSecret)
	}
	if authMethod != "client_secret_basic" {
		t.Fatalf("authMethod = %q, want client_secret_basic", authMethod)
	}
}

func TestShouldAdoptPublicHTTPToHTTPSIssuer(t *testing.T) {
	if !shouldAdoptIssuer("https://oidc.ai90.net", "http://oidc.ai90.net") {
		t.Fatalf("should adopt public http issuer to https")
	}
	if shouldAdoptIssuer("https://oidc.ai90.net", "https://oidc.ai90.net") {
		t.Fatalf("should not adopt matching https issuer")
	}
}

func TestProfileNamesFromEmail(t *testing.T) {
	given, family := profileNames("First.Last@example.com")
	if given != "first.last" {
		t.Fatalf("given = %q, want email local part", given)
	}
	if family != "" {
		t.Fatalf("family = %q, want empty string", family)
	}
}

func TestLoginEmailFromLocalPartAndDomain(t *testing.T) {
	req := httptest.NewRequest("POST", "https://oidc.example/login", nil)
	req.Form = url.Values{
		"email_local":  {"User.Name"},
		"email_domain": {"ai90.net"},
	}
	got := loginEmailFromRequest(req, Tenant{AllowedDomains: "ai90.net"})
	if got != "user.name@ai90.net" {
		t.Fatalf("email = %q, want user.name@ai90.net", got)
	}
}

func TestLoginEmailStillAcceptsFullEmail(t *testing.T) {
	req := httptest.NewRequest("POST", "https://oidc.example/login", nil)
	req.Form = url.Values{
		"email":        {"Full@Ai90.Net"},
		"email_local":  {"ignored"},
		"email_domain": {"example.com"},
	}
	got := loginEmailFromRequest(req, Tenant{AllowedDomains: "ai90.net"})
	if got != "full@ai90.net" {
		t.Fatalf("email = %q, want full@ai90.net", got)
	}
}
