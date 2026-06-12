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
	Addr            string
	DataDir         string
	Issuer          string
	AllowedDomain   string
	ClientID        string
	ClientSecret    string
	AdminUser       string
	AdminPassword   string
	SessionHours    int
	AllowedRedirect map[string]bool
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

	cfg.ClientSecret, generated = loadOrCreateTextSecret(
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

	if len(cfg.AllowedRedirect) == 0 {
		log.Printf("WARNING: OIDC_REDIRECT_URIS is empty; any redirect_uri will be accepted")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleRoot)
	mux.HandleFunc("/admin", app.handleAdmin)
	mux.HandleFunc("/admin/keys", app.handleAdminKeys)
	mux.HandleFunc("/admin/revoke", app.handleAdminRevoke)
	mux.HandleFunc("/authorize", app.handleAuthorize)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/token", app.handleToken)
	mux.HandleFunc("/userinfo", app.handleUserinfo)
	mux.HandleFunc("/jwks.json", app.handleJWKS)
	mux.HandleFunc("/.well-known/openid-configuration", app.handleDiscovery)

	log.Printf("issuer: %s", cfg.Issuer)
	log.Printf("admin:  %s/admin", cfg.Issuer)
	log.Printf("listen: %s", cfg.Addr)
	log.Fatal(http.ListenAndServe(cfg.Addr, securityHeaders(mux)))
}

func loadConfig() Config {
	dataDir := env("DATA_DIR", "data")
	issuer := strings.TrimRight(env("ISSUER_URL", "http://localhost:8080"), "/")
	domain := strings.ToLower(strings.TrimSpace(env("ALLOWED_DOMAIN", "abc.com")))
	domain = strings.TrimPrefix(domain, "@")

	return Config{
		Addr:            env("ADDR", ":8080"),
		DataDir:         dataDir,
		Issuer:          issuer,
		AllowedDomain:   domain,
		ClientID:        env("OIDC_CLIENT_ID", "openai"),
		AdminUser:       env("ADMIN_USER", "admin"),
		SessionHours:    envInt("SESSION_HOURS", 12),
		AllowedRedirect: parseCSVSet(os.Getenv("OIDC_REDIRECT_URIS")),
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

func parseCSVSet(raw string) map[string]bool {
	result := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			result[item] = true
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
