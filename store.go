package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidEmailDomain = errors.New("email is not in the allowed domain")
	ErrInvalidInviteKey   = errors.New("key is invalid, used, expired, revoked, or bound to another email")
	ErrInvalidAuthCode    = errors.New("authorization code is invalid or expired")
	ErrInvalidAccessToken = errors.New("access token is invalid or expired")
)

type Store struct {
	path string
	mu   sync.Mutex
	data StoreData
}

type StoreData struct {
	Keys         []InviteKey     `json:"keys"`
	Users        map[string]User `json:"users"`
	AuthCodes    []AuthCode      `json:"auth_codes"`
	AccessTokens []AccessToken   `json:"access_tokens"`
}

type InviteKey struct {
	ID         string     `json:"id"`
	Hash       string     `json:"hash"`
	BoundEmail string     `json:"bound_email,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	UsedAt     *time.Time `json:"used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type User struct {
	Email     string    `json:"email"`
	Sub       string    `json:"sub"`
	CreatedAt time.Time `json:"created_at"`
}

type AuthCode struct {
	Hash        string     `json:"hash"`
	Email       string     `json:"email"`
	ClientID    string     `json:"client_id"`
	RedirectURI string     `json:"redirect_uri"`
	Nonce       string     `json:"nonce,omitempty"`
	Scope       string     `json:"scope,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	UsedAt      *time.Time `json:"used_at,omitempty"`
}

type AccessToken struct {
	Hash      string    `json:"hash"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type GeneratedKey struct {
	ID         string
	Key        string
	BoundEmail string
	ExpiresAt  *time.Time
}

func (g GeneratedKey) ExpiresText() string {
	if g.ExpiresAt == nil {
		return "never"
	}
	return g.ExpiresAt.Local().Format("2006-01-02 15:04")
}

type KeyView struct {
	ID         string
	BoundEmail string
	CreatedAt  string
	ExpiresAt  string
	Status     string
}

func LoadStore(path string) (*Store, error) {
	s := &Store{
		path: path,
		data: StoreData{Users: map[string]User{}},
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		return s, s.saveLocked()
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return nil, err
	}
	if s.data.Users == nil {
		s.data.Users = map[string]User{}
	}
	return s, nil
}

func (s *Store) GenerateKeys(count int, boundEmails []string, expiresAt *time.Time) ([]GeneratedKey, error) {
	if count <= 0 {
		count = 1
	}
	if len(boundEmails) > 0 {
		count = len(boundEmails)
	}
	if count > 1000 {
		return nil, fmt.Errorf("count is too large")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	generated := make([]GeneratedKey, 0, count)
	for i := 0; i < count; i++ {
		key := randomToken(32)
		id := randomToken(9)
		bound := ""
		if len(boundEmails) > 0 {
			bound = normalizeEmail(boundEmails[i])
		}
		s.data.Keys = append(s.data.Keys, InviteKey{
			ID:         id,
			Hash:       hashToken(key),
			BoundEmail: bound,
			CreatedAt:  now,
			ExpiresAt:  expiresAt,
		})
		generated = append(generated, GeneratedKey{
			ID:         id,
			Key:        key,
			BoundEmail: bound,
			ExpiresAt:  expiresAt,
		})
	}
	return generated, s.saveLocked()
}

func (s *Store) RevokeKey(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for i := range s.data.Keys {
		if s.data.Keys[i].ID == id && s.data.Keys[i].RevokedAt == nil {
			s.data.Keys[i].RevokedAt = &now
			break
		}
	}
	return s.saveLocked()
}

func (s *Store) UseInviteKey(email string, key string, allowedDomain string) (User, error) {
	email = normalizeEmail(email)
	if !emailInDomain(email, allowedDomain) {
		return User{}, ErrInvalidEmailDomain
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return User{}, ErrInvalidEmailDomain
	}
	keyHash := hashToken(strings.TrimSpace(key))
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.Keys {
		k := &s.data.Keys[i]
		if subtle.ConstantTimeCompare([]byte(k.Hash), []byte(keyHash)) != 1 {
			continue
		}
		if k.UsedAt != nil || k.RevokedAt != nil {
			return User{}, ErrInvalidInviteKey
		}
		if k.ExpiresAt != nil && now.After(*k.ExpiresAt) {
			return User{}, ErrInvalidInviteKey
		}
		if k.BoundEmail != "" && normalizeEmail(k.BoundEmail) != email {
			return User{}, ErrInvalidInviteKey
		}
		k.UsedAt = &now
		user := s.ensureUserLocked(email, now)
		return user, s.saveLocked()
	}
	return User{}, ErrInvalidInviteKey
}

func (s *Store) CreateAuthCode(email, clientID, redirectURI, nonce, scope string) (string, error) {
	email = normalizeEmail(email)
	now := time.Now().UTC()
	code := randomToken(32)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupLocked(now)
	s.ensureUserLocked(email, now)
	s.data.AuthCodes = append(s.data.AuthCodes, AuthCode{
		Hash:        hashToken(code),
		Email:       email,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Nonce:       nonce,
		Scope:       scope,
		CreatedAt:   now,
		ExpiresAt:   now.Add(5 * time.Minute),
	})
	return code, s.saveLocked()
}

func (s *Store) ConsumeAuthCode(code, clientID, redirectURI string) (User, AuthCode, error) {
	now := time.Now().UTC()
	codeHash := hashToken(strings.TrimSpace(code))

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.data.AuthCodes {
		ac := &s.data.AuthCodes[i]
		if subtle.ConstantTimeCompare([]byte(ac.Hash), []byte(codeHash)) != 1 {
			continue
		}
		if ac.UsedAt != nil || now.After(ac.ExpiresAt) || ac.ClientID != clientID || ac.RedirectURI != redirectURI {
			return User{}, AuthCode{}, ErrInvalidAuthCode
		}
		ac.UsedAt = &now
		user := s.ensureUserLocked(ac.Email, now)
		copied := *ac
		return user, copied, s.saveLocked()
	}
	return User{}, AuthCode{}, ErrInvalidAuthCode
}

func (s *Store) CreateAccessToken(email string) (string, error) {
	email = normalizeEmail(email)
	now := time.Now().UTC()
	token := randomToken(32)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupLocked(now)
	s.data.AccessTokens = append(s.data.AccessTokens, AccessToken{
		Hash:      hashToken(token),
		Email:     email,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	})
	return token, s.saveLocked()
}

func (s *Store) LookupAccessToken(token string) (User, error) {
	now := time.Now().UTC()
	tokenHash := hashToken(strings.TrimSpace(token))

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, at := range s.data.AccessTokens {
		if subtle.ConstantTimeCompare([]byte(at.Hash), []byte(tokenHash)) != 1 {
			continue
		}
		if now.After(at.ExpiresAt) {
			return User{}, ErrInvalidAccessToken
		}
		user, ok := s.data.Users[normalizeEmail(at.Email)]
		if !ok {
			return User{}, ErrInvalidAccessToken
		}
		return user, nil
	}
	return User{}, ErrInvalidAccessToken
}

func (s *Store) KeyViews() []KeyView {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	views := make([]KeyView, 0, len(s.data.Keys))
	for i := len(s.data.Keys) - 1; i >= 0; i-- {
		k := s.data.Keys[i]
		status := "unused"
		if k.RevokedAt != nil {
			status = "revoked"
		} else if k.UsedAt != nil {
			status = "used"
		} else if k.ExpiresAt != nil && now.After(*k.ExpiresAt) {
			status = "expired"
		}
		expires := "never"
		if k.ExpiresAt != nil {
			expires = k.ExpiresAt.Local().Format("2006-01-02 15:04")
		}
		views = append(views, KeyView{
			ID:         k.ID,
			BoundEmail: k.BoundEmail,
			CreatedAt:  k.CreatedAt.Local().Format("2006-01-02 15:04"),
			ExpiresAt:  expires,
			Status:     status,
		})
	}
	return views
}

func (s *Store) ensureUserLocked(email string, now time.Time) User {
	email = normalizeEmail(email)
	if user, ok := s.data.Users[email]; ok {
		return user
	}
	user := User{
		Email:     email,
		Sub:       "u_" + randomToken(18),
		CreatedAt: now,
	}
	s.data.Users[email] = user
	return user
}

func (s *Store) cleanupLocked(now time.Time) {
	authCodes := s.data.AuthCodes[:0]
	for _, code := range s.data.AuthCodes {
		if code.UsedAt == nil && now.Before(code.ExpiresAt) {
			authCodes = append(authCodes, code)
		}
	}
	s.data.AuthCodes = authCodes

	accessTokens := s.data.AccessTokens[:0]
	for _, token := range s.data.AccessTokens {
		if now.Before(token.ExpiresAt) {
			accessTokens = append(accessTokens, token)
		}
	}
	s.data.AccessTokens = accessTokens
}

func (s *Store) saveLocked() error {
	s.cleanupLocked(time.Now().UTC())
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func emailInDomain(email string, domain string) bool {
	domain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "@")
	return strings.HasSuffix(normalizeEmail(email), "@"+domain)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
