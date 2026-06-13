package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Addr          string
	DataDir       string
	AdminUser     string
	AdminPassword string
	SessionHours  int
	SeedTenant    TenantInput
}

type App struct {
	cfg          Config
	store        *Store
	signer       *Signer
	cookieSecret []byte
}

func main() {
	cfg := loadConfig()

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("create data dir: %v", err)
	}

	var generated bool
	cfg.AdminPassword, generated = loadOrCreateTextSecret(
		filepath.Join(cfg.DataDir, "admin_password.txt"),
		os.Getenv("ADMIN_PASSWORD"),
		32,
	)
	if generated {
		log.Printf("generated admin password and saved it to %s", filepath.Join(cfg.DataDir, "admin_password.txt"))
	}

	cfg.SeedTenant.ClientSecret, generated = loadOrCreateTextSecret(
		filepath.Join(cfg.DataDir, "oidc_client_secret.txt"),
		os.Getenv("OIDC_CLIENT_SECRET"),
		32,
	)
	if generated {
		log.Printf("generated OIDC client secret and saved it to %s", filepath.Join(cfg.DataDir, "oidc_client_secret.txt"))
	}

	cookieSecretText, generated := loadOrCreateTextSecret(
		filepath.Join(cfg.DataDir, "app_secret.txt"),
		os.Getenv("APP_SECRET"),
		32,
	)
	if generated {
		log.Printf("generated app secret and saved it to %s", filepath.Join(cfg.DataDir, "app_secret.txt"))
	}

	store, err := LoadStore(filepath.Join(cfg.DataDir, "store.db"))
	if err != nil {
		log.Fatalf("load store: %v", err)
	}

	seedTenant, err := store.EnsureSeedTenant(cfg.SeedTenant)
	if err != nil {
		log.Fatalf("seed tenant: %v", err)
	}

	signer, err := LoadOrCreateSigner(filepath.Join(cfg.DataDir, "oidc_private_key.pem"))
	if err != nil {
		log.Fatalf("load signing key: %v", err)
	}

	app := &App{
		cfg:          cfg,
		store:        store,
		signer:       signer,
		cookieSecret: []byte(cookieSecretText),
	}

	if strings.TrimSpace(seedTenant.RedirectURIs) == "" {
		log.Printf("WARNING: seed tenant %s has no redirect URIs; any redirect_uri will be accepted for that tenant", seedTenant.IssuerURL)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleRoot)
	mux.HandleFunc("/admin", app.handleAdmin)
	mux.HandleFunc("/admin/keys", app.handleAdminKeys)
	mux.HandleFunc("/admin/revoke", app.handleAdminRevoke)
	mux.HandleFunc("/admin/tenants", app.handleAdminTenants)
	mux.HandleFunc("/authorize", app.handleAuthorize)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/token", app.handleToken)
	mux.HandleFunc("/userinfo", app.handleUserinfo)
	mux.HandleFunc("/jwks.json", app.handleJWKS)
	mux.HandleFunc("/.well-known/openid-configuration", app.handleDiscovery)

	log.Printf("seed issuer: %s", seedTenant.IssuerURL)
	log.Printf("admin:       %s/admin", seedTenant.IssuerURL)
	log.Printf("listen: %s", cfg.Addr)
	log.Fatal(http.ListenAndServe(cfg.Addr, securityHeaders(mux)))
}

func loadConfig() Config {
	dataDir := env("DATA_DIR", "data")
	issuer := strings.TrimRight(env("ISSUER_URL", "http://localhost:8080"), "/")
	domain := strings.ToLower(strings.TrimSpace(env("ALLOWED_DOMAIN", "abc.com")))
	domain = strings.TrimPrefix(domain, "@")

	return Config{
		Addr:         env("ADDR", ":8080"),
		DataDir:      dataDir,
		AdminUser:    env("ADMIN_USER", "admin"),
		SessionHours: envInt("SESSION_HOURS", 12),
		SeedTenant: TenantInput{
			IssuerURL:     issuer,
			AllowedDomain: domain,
			ClientID:      env("OIDC_CLIENT_ID", "openai"),
			RedirectURIs:  strings.Join(parseCSVValues(os.Getenv("OIDC_REDIRECT_URIS")), "\n"),
		},
	}
}

func env(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func parseCSVValues(raw string) []string {
	var result []string
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
