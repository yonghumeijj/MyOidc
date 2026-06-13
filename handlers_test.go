package main

import (
	"net/http/httptest"
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
