package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := LoadStore(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	t.Cleanup(func() {
		if err := store.db.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	return store
}

func newTestTenant(t *testing.T, store *Store) Tenant {
	t.Helper()
	tenant, err := store.EnsureSeedTenant(TenantInput{
		IssuerURL:      "https://sso.example.com",
		AllowedDomains: "example.com",
		ClientID:       "openai",
		ClientSecret:   "test-secret",
		RedirectURIs:   "https://callback.example",
	})
	if err != nil {
		t.Fatalf("EnsureSeedTenant: %v", err)
	}
	return tenant
}

func TestUseInviteKeyBindsAndAllowsSameEmail(t *testing.T) {
	store := newTestStore(t)
	tenant := newTestTenant(t, store)
	generated, err := store.GenerateKeys(tenant.ID, 1, nil, nil)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}

	user, err := store.UseInviteKey(tenant.ID, "Person@Example.com", generated[0].Key, tenant.AllowedDomains)
	if err != nil {
		t.Fatalf("first UseInviteKey: %v", err)
	}
	if user.Email != "person@example.com" {
		t.Fatalf("user email = %q, want normalized email", user.Email)
	}

	if _, err := store.UseInviteKey(tenant.ID, "person@example.com", generated[0].Key, tenant.AllowedDomains); err != nil {
		t.Fatalf("same email UseInviteKey: %v", err)
	}
	if _, err := store.UseInviteKey(tenant.ID, "other@example.com", generated[0].Key, tenant.AllowedDomains); !errors.Is(err, ErrInvalidInviteKey) {
		t.Fatalf("different email UseInviteKey err = %v, want ErrInvalidInviteKey", err)
	}

	keys := store.KeyViews(tenant.ID)
	if len(keys) != 1 {
		t.Fatalf("KeyViews len = %d, want 1", len(keys))
	}
	if keys[0].BoundEmail != "person@example.com" {
		t.Fatalf("BoundEmail = %q, want person@example.com", keys[0].BoundEmail)
	}
	if keys[0].UsedCount != 1 || keys[0].MaxUses != 1 {
		t.Fatalf("usage = %d/%d, want 1/1", keys[0].UsedCount, keys[0].MaxUses)
	}
}

func TestUseInviteKeyHonorsBoundEmail(t *testing.T) {
	store := newTestStore(t)
	tenant := newTestTenant(t, store)
	generated, err := store.GenerateKeys(tenant.ID, 1, []string{"alice@example.com"}, nil)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}

	if _, err := store.UseInviteKey(tenant.ID, "bob@example.com", generated[0].Key, tenant.AllowedDomains); !errors.Is(err, ErrInvalidInviteKey) {
		t.Fatalf("wrong bound email err = %v, want ErrInvalidInviteKey", err)
	}
	if _, err := store.UseInviteKey(tenant.ID, "alice@example.com", generated[0].Key, tenant.AllowedDomains); err != nil {
		t.Fatalf("correct bound email UseInviteKey: %v", err)
	}
	if _, err := store.UseInviteKey(tenant.ID, "alice@example.com", generated[0].Key, tenant.AllowedDomains); err != nil {
		t.Fatalf("same bound email UseInviteKey: %v", err)
	}
}

func TestUseInviteKeyRejectsExpiredAndRevokedKeys(t *testing.T) {
	store := newTestStore(t)
	tenant := newTestTenant(t, store)

	past := time.Now().UTC().Add(-time.Minute)
	expired, err := store.GenerateKeys(tenant.ID, 1, nil, &past)
	if err != nil {
		t.Fatalf("GenerateKeys expired: %v", err)
	}
	if _, err := store.UseInviteKey(tenant.ID, "person@example.com", expired[0].Key, tenant.AllowedDomains); !errors.Is(err, ErrInvalidInviteKey) {
		t.Fatalf("expired key err = %v, want ErrInvalidInviteKey", err)
	}

	revoked, err := store.GenerateKeys(tenant.ID, 1, nil, nil)
	if err != nil {
		t.Fatalf("GenerateKeys revoked: %v", err)
	}
	if err := store.RevokeKey(tenant.ID, revoked[0].ID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}
	if _, err := store.UseInviteKey(tenant.ID, "person@example.com", revoked[0].Key, tenant.AllowedDomains); !errors.Is(err, ErrInvalidInviteKey) {
		t.Fatalf("revoked key err = %v, want ErrInvalidInviteKey", err)
	}
}

func TestConsumeAuthCodeRejectsReuse(t *testing.T) {
	store := newTestStore(t)
	tenant := newTestTenant(t, store)
	code, err := store.CreateAuthCode(tenant.ID, "person@example.com", "openai", "https://callback.example", "nonce", "openid email")
	if err != nil {
		t.Fatalf("CreateAuthCode: %v", err)
	}

	if _, _, err := store.ConsumeAuthCode(tenant.ID, code, "openai", "https://callback.example"); err != nil {
		t.Fatalf("first ConsumeAuthCode: %v", err)
	}
	if _, _, err := store.ConsumeAuthCode(tenant.ID, code, "openai", "https://callback.example"); !errors.Is(err, ErrInvalidAuthCode) {
		t.Fatalf("second ConsumeAuthCode err = %v, want ErrInvalidAuthCode", err)
	}
}

func TestConcurrentInviteKeyUseBindsOnlyOneEmailByDefault(t *testing.T) {
	store := newTestStore(t)
	tenant := newTestTenant(t, store)
	generated, err := store.GenerateKeys(tenant.ID, 1, nil, nil)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}

	var successes int64
	var invalids int64
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := store.UseInviteKey(tenant.ID, fmt.Sprintf("person%d@example.com", i), generated[0].Key, tenant.AllowedDomains)
			switch {
			case err == nil:
				atomic.AddInt64(&successes, 1)
			case errors.Is(err, ErrInvalidInviteKey):
				atomic.AddInt64(&invalids, 1)
			default:
				t.Errorf("UseInviteKey: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("successes = %d, want 1", successes)
	}
	if invalids != 24 {
		t.Fatalf("invalids = %d, want 24", invalids)
	}
}

func TestInviteKeyMaxUsesAllowsMultipleBoundEmails(t *testing.T) {
	store := newTestStore(t)
	tenant := newTestTenant(t, store)
	generated, err := store.GenerateKeysWithMaxUses(tenant.ID, 1, nil, nil, 2)
	if err != nil {
		t.Fatalf("GenerateKeysWithMaxUses: %v", err)
	}

	if _, err := store.UseInviteKey(tenant.ID, "alice@example.com", generated[0].Key, tenant.AllowedDomains); err != nil {
		t.Fatalf("alice UseInviteKey: %v", err)
	}
	if _, err := store.UseInviteKey(tenant.ID, "bob@example.com", generated[0].Key, tenant.AllowedDomains); err != nil {
		t.Fatalf("bob UseInviteKey: %v", err)
	}
	if _, err := store.UseInviteKey(tenant.ID, "alice@example.com", generated[0].Key, tenant.AllowedDomains); err != nil {
		t.Fatalf("alice repeat UseInviteKey: %v", err)
	}
	if _, err := store.UseInviteKey(tenant.ID, "carol@example.com", generated[0].Key, tenant.AllowedDomains); !errors.Is(err, ErrInvalidInviteKey) {
		t.Fatalf("carol UseInviteKey err = %v, want ErrInvalidInviteKey", err)
	}

	keys := store.KeyViews(tenant.ID)
	if len(keys) != 1 {
		t.Fatalf("KeyViews len = %d, want 1", len(keys))
	}
	if keys[0].UsedCount != 2 || keys[0].MaxUses != 2 {
		t.Fatalf("usage = %d/%d, want 2/2", keys[0].UsedCount, keys[0].MaxUses)
	}
	if !strings.Contains(keys[0].Bindings, "alice@example.com") || !strings.Contains(keys[0].Bindings, "bob@example.com") {
		t.Fatalf("Bindings = %q, want alice and bob", keys[0].Bindings)
	}
}

func TestTenantIsolation(t *testing.T) {
	store := newTestStore(t)
	tenantA := newTestTenant(t, store)
	tenantB, err := store.SaveTenant(TenantInput{
		IssuerURL:      "https://sso.other.example",
		AllowedDomains: "other.example",
		ClientID:       "openai",
		ClientSecret:   "other-secret",
		RedirectURIs:   "https://other-callback.example",
	})
	if err != nil {
		t.Fatalf("SaveTenant: %v", err)
	}

	generated, err := store.GenerateKeys(tenantA.ID, 1, nil, nil)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	if _, err := store.UseInviteKey(tenantB.ID, "person@other.example", generated[0].Key, tenantB.AllowedDomains); !errors.Is(err, ErrInvalidInviteKey) {
		t.Fatalf("tenant B using tenant A key err = %v, want ErrInvalidInviteKey", err)
	}
	if _, err := store.UseInviteKey(tenantA.ID, "person@example.com", generated[0].Key, tenantA.AllowedDomains); err != nil {
		t.Fatalf("tenant A using tenant A key: %v", err)
	}

	code, err := store.CreateAuthCode(tenantA.ID, "person@example.com", tenantA.ClientID, "https://callback.example", "", "openid")
	if err != nil {
		t.Fatalf("CreateAuthCode: %v", err)
	}
	if _, _, err := store.ConsumeAuthCode(tenantB.ID, code, tenantB.ClientID, "https://other-callback.example"); !errors.Is(err, ErrInvalidAuthCode) {
		t.Fatalf("tenant B consuming tenant A code err = %v, want ErrInvalidAuthCode", err)
	}
}

func TestTenantAllowsMultipleEmailDomains(t *testing.T) {
	store := newTestStore(t)
	tenant, err := store.EnsureSeedTenant(TenantInput{
		IssuerURL:      "https://sso.example.com",
		AllowedDomains: "abc.com\nxyz.com, aaa.com",
		ClientID:       "openai",
		ClientSecret:   "test-secret",
		RedirectURIs:   "https://callback.example",
	})
	if err != nil {
		t.Fatalf("EnsureSeedTenant: %v", err)
	}
	if tenant.AllowedDomains != "abc.com\nxyz.com\naaa.com" {
		t.Fatalf("AllowedDomains = %q, want normalized newline list", tenant.AllowedDomains)
	}

	for _, email := range []string{"person@abc.com", "person@xyz.com", "person@aaa.com"} {
		generated, err := store.GenerateKeys(tenant.ID, 1, nil, nil)
		if err != nil {
			t.Fatalf("GenerateKeys: %v", err)
		}
		if _, err := store.UseInviteKey(tenant.ID, email, generated[0].Key, tenant.AllowedDomains); err != nil {
			t.Fatalf("UseInviteKey(%q): %v", email, err)
		}
	}

	generated, err := store.GenerateKeys(tenant.ID, 1, nil, nil)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	if _, err := store.UseInviteKey(tenant.ID, "person@example.net", generated[0].Key, tenant.AllowedDomains); !errors.Is(err, ErrInvalidEmailDomain) {
		t.Fatalf("disallowed domain err = %v, want ErrInvalidEmailDomain", err)
	}
}

func TestLoadStoreMigratesLegacyJSON(t *testing.T) {
	dir := t.TempDir()
	legacyKey := "legacy-key"
	now := time.Now().UTC()
	data := StoreData{
		Keys: []InviteKey{
			{
				ID:        "legacy-id",
				Hash:      hashToken(legacyKey),
				CreatedAt: now,
			},
		},
		Users: map[string]User{},
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Marshal legacy store: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "store.json"), raw, 0o600); err != nil {
		t.Fatalf("WriteFile legacy store: %v", err)
	}

	store, err := LoadStore(filepath.Join(dir, "store.db"))
	if err != nil {
		t.Fatalf("LoadStore: %v", err)
	}
	tenant := newTestTenant(t, store)
	t.Cleanup(func() {
		if err := store.db.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})

	if got := store.KeyViews(tenant.ID); len(got) != 1 || got[0].ID != "legacy-id" {
		t.Fatalf("KeyViews = %#v, want migrated legacy key", got)
	}
	if _, err := store.UseInviteKey(tenant.ID, "person@example.com", legacyKey, tenant.AllowedDomains); err != nil {
		t.Fatalf("UseInviteKey migrated legacy key: %v", err)
	}
}
