package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Signer struct {
	key *rsa.PrivateKey
	kid string
}

func LoadOrCreateSigner(path string) (*Signer, error) {
	key, err := loadPrivateKey(path)
	if err != nil {
		return nil, err
	}
	if key == nil {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		if err := savePrivateKey(path, key); err != nil {
			return nil, err
		}
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pubDER)
	return &Signer{
		key: key,
		kid: base64.RawURLEncoding.EncodeToString(sum[:8]),
	}, nil
}

func (s *Signer) JWK() map[string]string {
	pub := s.key.PublicKey
	e := big.NewInt(int64(pub.E)).Bytes()
	return map[string]string{
		"kty": "RSA",
		"use": "sig",
		"kid": s.kid,
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(e),
	}
}

func (s *Signer) SignIDToken(claims map[string]any) (string, error) {
	header := map[string]any{
		"typ": "JWT",
		"alg": "RS256",
		"kid": s.kid,
	}
	headerRaw, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsRaw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerRaw) + "." +
		base64.RawURLEncoding.EncodeToString(claimsRaw)

	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid RSA private key PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func savePrivateKey(path string, key *rsa.PrivateKey) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}

func randomToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func loadOrCreateTextSecret(path string, envValue string, bytes int) (string, bool) {
	if strings.TrimSpace(envValue) != "" {
		return strings.TrimSpace(envValue), false
	}
	raw, err := os.ReadFile(path)
	if err == nil && strings.TrimSpace(string(raw)) != "" {
		return strings.TrimSpace(string(raw)), false
	}
	secret := randomToken(bytes)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		panic(err)
	}
	return secret, true
}

func (a *App) setSessionCookie(w http.ResponseWriter, email string) {
	expires := time.Now().UTC().Add(time.Duration(a.cfg.SessionHours) * time.Hour)
	payload := normalizeEmail(email) + "|" + strconv.FormatInt(expires.Unix(), 10)
	sig := hmacSign(a.cookieSecret, payload)
	http.SetCookie(w, &http.Cookie{
		Name:     "gooidc_session",
		Value:    payload + "|" + sig,
		Path:     "/",
		HttpOnly: true,
		Secure:   strings.HasPrefix(a.cfg.Issuer, "https://"),
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
}

func (a *App) readSessionEmail(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("gooidc_session")
	if err != nil {
		return "", false
	}
	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 3 {
		return "", false
	}
	payload := parts[0] + "|" + parts[1]
	expected := hmacSign(a.cookieSecret, payload)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(parts[2])) != 1 {
		return "", false
	}
	expUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().UTC().After(time.Unix(expUnix, 0)) {
		return "", false
	}
	email := normalizeEmail(parts[0])
	if !emailInDomain(email, a.cfg.AllowedDomain) {
		return "", false
	}
	return email, true
}

func hmacSign(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func constantTimeStringEqual(a string, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
