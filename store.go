package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrInvalidEmailDomain = errors.New("email is not in the allowed domain")
	ErrInvalidInviteKey   = errors.New("key is invalid, used, expired, revoked, or bound to another email")
	ErrInvalidAuthCode    = errors.New("authorization code is invalid or expired")
	ErrInvalidAccessToken = errors.New("access token is invalid or expired")
)

type Store struct {
	path string
	db   *sql.DB
}

type StoreData struct {
	Keys         []InviteKey     `json:"keys"`
	Users        map[string]User `json:"users"`
	AuthCodes    []AuthCode      `json:"auth_codes"`
	AccessTokens []AccessToken   `json:"access_tokens"`
}

type InviteKey struct {
	ID         string     `json:"id"`
	PlainKey   string     `json:"key,omitempty"`
	Hash       string     `json:"hash"`
	BoundEmail string     `json:"bound_email,omitempty"`
	MaxUses    int        `json:"max_uses,omitempty"`
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

type Tenant struct {
	ID             string
	IssuerURL      string
	Host           string
	AllowedDomains string
	ClientID       string
	ClientSecret   string
	RedirectURIs   string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (t Tenant) AllowedDomainList() []string {
	return normalizeDomainList(t.AllowedDomains)
}

func (t Tenant) PrimaryAllowedDomain() string {
	domains := t.AllowedDomainList()
	if len(domains) == 0 {
		return ""
	}
	return domains[0]
}

func (t Tenant) RedirectURIList() []string {
	return parseLines(t.RedirectURIs)
}

func (t Tenant) RedirectURISet() map[string]bool {
	result := map[string]bool{}
	for _, uri := range t.RedirectURIList() {
		result[uri] = true
	}
	return result
}

type TenantInput struct {
	ID             string
	IssuerURL      string
	AllowedDomains string
	ClientID       string
	ClientSecret   string
	RedirectURIs   string
}

type GeneratedKey struct {
	ID         string
	Key        string
	BoundEmail string
	MaxUses    int
	ExpiresAt  *time.Time
}

func (g GeneratedKey) ExpiresText() string {
	if g.ExpiresAt == nil {
		return "never"
	}
	return g.ExpiresAt.Local().Format("2006-01-02 15:04")
}

type KeyView struct {
	ID           string
	Key          string
	BoundEmail   string
	Bindings     string
	UsedCount    int
	MaxUses      int
	CreatedAt    string
	ExpiresAt    string
	ExpiresInput string
	Status       string
	Revoked      bool
}

type KeyListPage struct {
	Items      []KeyView
	Page       int
	PageSize   int
	Total      int
	TotalPages int
	HasPrev    bool
	HasNext    bool
	PrevPage   int
	NextPage   int
	Start      int
	End        int
	Pages      []int
}

type InviteKeyInput struct {
	TenantID   string
	ID         string
	Key        string
	BoundEmail string
	MaxUses    int
	ExpiresAt  *time.Time
	Revoked    bool
}

func LoadStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	s := &Store{path: path, db: db}
	if err := s.configureDB(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrateSchema(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrateLegacyJSON(filepath.Join(filepath.Dir(path), "store.json")); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) configureDB() error {
	pragmas := []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = NORMAL`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA foreign_keys = ON`,
	}
	for _, pragma := range pragmas {
		if _, err := s.db.Exec(pragma); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) migrateSchema() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS schema_meta (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS tenants (
			id TEXT PRIMARY KEY,
			issuer_url TEXT NOT NULL UNIQUE,
			host TEXT NOT NULL UNIQUE,
			allowed_domain TEXT NOT NULL,
			client_id TEXT NOT NULL,
			client_secret TEXT NOT NULL,
			redirect_uris TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tenants_host ON tenants(host)`,
		`CREATE TABLE IF NOT EXISTS users (
			email TEXT PRIMARY KEY,
			sub TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS invite_keys (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL DEFAULT '',
			plain_key TEXT NOT NULL DEFAULT '',
			hash TEXT NOT NULL UNIQUE,
			bound_email TEXT NOT NULL DEFAULT '',
			max_uses INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			expires_at INTEGER,
			used_at INTEGER,
			revoked_at INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_invite_keys_tenant_id ON invite_keys(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_invite_keys_hash ON invite_keys(hash)`,
		`CREATE INDEX IF NOT EXISTS idx_invite_keys_created_at ON invite_keys(created_at)`,
		`CREATE TABLE IF NOT EXISTS invite_key_bindings (
			tenant_id TEXT NOT NULL,
			key_id TEXT NOT NULL,
			email TEXT NOT NULL,
			first_used_at INTEGER NOT NULL,
			last_used_at INTEGER NOT NULL,
			login_count INTEGER NOT NULL DEFAULT 1,
			PRIMARY KEY(tenant_id, key_id, email),
			FOREIGN KEY(key_id) REFERENCES invite_keys(id) ON DELETE CASCADE,
			FOREIGN KEY(email) REFERENCES users(email)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_invite_key_bindings_key ON invite_key_bindings(tenant_id, key_id)`,
		`CREATE INDEX IF NOT EXISTS idx_invite_key_bindings_email ON invite_key_bindings(email)`,
		`CREATE TABLE IF NOT EXISTS auth_codes (
			hash TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL DEFAULT '',
			email TEXT NOT NULL,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			nonce TEXT NOT NULL DEFAULT '',
			scope TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			used_at INTEGER,
			FOREIGN KEY(email) REFERENCES users(email)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_codes_tenant_id ON auth_codes(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_codes_email ON auth_codes(email)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at ON auth_codes(expires_at)`,
		`CREATE TABLE IF NOT EXISTS access_tokens (
			hash TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL DEFAULT '',
			email TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			FOREIGN KEY(email) REFERENCES users(email)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_tenant_id ON access_tokens(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_email ON access_tokens(email)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at)`,
		`INSERT INTO schema_meta(key, value)
			VALUES ('schema_version', '2')
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
	}
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	for _, migration := range []struct {
		table  string
		column string
		def    string
	}{
		{"invite_keys", "tenant_id", "TEXT NOT NULL DEFAULT ''"},
		{"invite_keys", "plain_key", "TEXT NOT NULL DEFAULT ''"},
		{"invite_keys", "max_uses", "INTEGER NOT NULL DEFAULT 1"},
		{"auth_codes", "tenant_id", "TEXT NOT NULL DEFAULT ''"},
		{"access_tokens", "tenant_id", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := s.ensureColumn(migration.table, migration.column, migration.def); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureColumn(table, column, definition string) error {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid      int
			name     string
			typ      string
			notNull  int
			defaultV any
			primaryK int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultV, &primaryK); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + definition)
	return err
}

func (s *Store) migrateLegacyJSON(path string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return nil
	}

	var migrated string
	err = s.db.QueryRow(`SELECT value FROM schema_meta WHERE key = 'json_store_migrated'`).Scan(&migrated)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	empty, err := s.isEmpty()
	if err != nil {
		return err
	}
	if !empty {
		_, err = s.db.Exec(`INSERT INTO schema_meta(key, value) VALUES ('json_store_migrated', 'skipped_existing_sqlite_data')`)
		return err
	}

	var data StoreData
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("migrate legacy store.json: %w", err)
	}
	if data.Users == nil {
		data.Users = map[string]User{}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := importLegacyData(tx, data); err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO schema_meta(key, value) VALUES ('json_store_migrated', ?)`,
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) isEmpty() (bool, error) {
	tables := []string{"tenants", "users", "invite_keys", "auth_codes", "access_tokens"}
	for _, table := range tables {
		var count int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
			return false, err
		}
		if count > 0 {
			return false, nil
		}
	}
	return true, nil
}

func (s *Store) EnsureSeedTenant(input TenantInput) (Tenant, error) {
	tenants, err := s.Tenants()
	if err != nil {
		return Tenant{}, err
	}
	if len(tenants) > 0 {
		if err := s.assignUnscopedRows(tenants[0].ID); err != nil {
			return Tenant{}, err
		}
		return tenants[0], nil
	}

	tenant, err := s.SaveTenant(input)
	if err != nil {
		return Tenant{}, err
	}
	if err := s.assignUnscopedRows(tenant.ID); err != nil {
		return Tenant{}, err
	}
	return tenant, nil
}

func (s *Store) SaveTenant(input TenantInput) (Tenant, error) {
	input, host, err := normalizeTenantInput(input)
	if err != nil {
		return Tenant{}, err
	}

	now := time.Now().UTC()
	if input.ID == "" {
		input.ID = "t_" + randomToken(12)
		_, err = s.db.Exec(
			`INSERT INTO tenants(id, issuer_url, host, allowed_domain, client_id, client_secret, redirect_uris, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			input.ID,
			input.IssuerURL,
			host,
			input.AllowedDomains,
			input.ClientID,
			input.ClientSecret,
			input.RedirectURIs,
			timeToDB(now),
			timeToDB(now),
		)
		if err != nil {
			return Tenant{}, err
		}
		return s.TenantByID(input.ID)
	}

	_, err = s.db.Exec(
		`UPDATE tenants
			SET issuer_url = ?, host = ?, allowed_domain = ?, client_id = ?, client_secret = ?, redirect_uris = ?, updated_at = ?
			WHERE id = ?`,
		input.IssuerURL,
		host,
		input.AllowedDomains,
		input.ClientID,
		input.ClientSecret,
		input.RedirectURIs,
		timeToDB(now),
		input.ID,
	)
	if err != nil {
		return Tenant{}, err
	}
	return s.TenantByID(input.ID)
}

func (s *Store) Tenants() ([]Tenant, error) {
	rows, err := s.db.Query(
		`SELECT id, issuer_url, host, allowed_domain, client_id, client_secret, redirect_uris, created_at, updated_at
			FROM tenants
			ORDER BY created_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tenants []Tenant
	for rows.Next() {
		tenant, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, tenant)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tenants, nil
}

func (s *Store) TenantByID(id string) (Tenant, error) {
	tenant, err := scanTenant(s.db.QueryRow(
		`SELECT id, issuer_url, host, allowed_domain, client_id, client_secret, redirect_uris, created_at, updated_at
			FROM tenants
			WHERE id = ?`,
		strings.TrimSpace(id),
	))
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, err
	}
	return tenant, err
}

func (s *Store) TenantByHost(host string) (Tenant, error) {
	tenant, err := scanTenant(s.db.QueryRow(
		`SELECT id, issuer_url, host, allowed_domain, client_id, client_secret, redirect_uris, created_at, updated_at
			FROM tenants
			WHERE host = ?`,
		normalizeHost(host),
	))
	if errors.Is(err, sql.ErrNoRows) {
		return Tenant{}, err
	}
	return tenant, err
}

func (s *Store) assignUnscopedRows(tenantID string) error {
	for _, stmt := range []string{
		`UPDATE invite_keys SET tenant_id = ? WHERE tenant_id = ''`,
		`UPDATE auth_codes SET tenant_id = ? WHERE tenant_id = ''`,
		`UPDATE access_tokens SET tenant_id = ? WHERE tenant_id = ''`,
	} {
		if _, err := s.db.Exec(stmt, tenantID); err != nil {
			return err
		}
	}
	return nil
}

func importLegacyData(tx *sql.Tx, data StoreData) error {
	for _, user := range data.Users {
		user.Email = normalizeEmail(user.Email)
		if user.Email == "" || user.Sub == "" {
			continue
		}
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO users(email, sub, created_at) VALUES (?, ?, ?)`,
			user.Email,
			user.Sub,
			timeToDB(user.CreatedAt),
		); err != nil {
			return err
		}
	}
	for _, k := range data.Keys {
		if k.ID == "" || k.Hash == "" {
			continue
		}
		maxUses := k.MaxUses
		if maxUses <= 0 {
			maxUses = 1
		}
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO invite_keys(id, plain_key, hash, bound_email, max_uses, created_at, expires_at, used_at, revoked_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			k.ID,
			strings.TrimSpace(k.PlainKey),
			k.Hash,
			normalizeEmail(k.BoundEmail),
			maxUses,
			timeToDB(k.CreatedAt),
			nullableTimeToDB(k.ExpiresAt),
			nullableTimeToDB(k.UsedAt),
			nullableTimeToDB(k.RevokedAt),
		); err != nil {
			return err
		}
	}
	for _, code := range data.AuthCodes {
		code.Email = normalizeEmail(code.Email)
		if code.Hash == "" || code.Email == "" {
			continue
		}
		if _, err := ensureUserTx(tx, code.Email, code.CreatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO auth_codes(hash, email, client_id, redirect_uri, nonce, scope, created_at, expires_at, used_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			code.Hash,
			code.Email,
			code.ClientID,
			code.RedirectURI,
			code.Nonce,
			code.Scope,
			timeToDB(code.CreatedAt),
			timeToDB(code.ExpiresAt),
			nullableTimeToDB(code.UsedAt),
		); err != nil {
			return err
		}
	}
	for _, token := range data.AccessTokens {
		token.Email = normalizeEmail(token.Email)
		if token.Hash == "" || token.Email == "" {
			continue
		}
		if _, err := ensureUserTx(tx, token.Email, token.CreatedAt); err != nil {
			return err
		}
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO access_tokens(hash, email, created_at, expires_at)
				VALUES (?, ?, ?, ?)`,
			token.Hash,
			token.Email,
			timeToDB(token.CreatedAt),
			timeToDB(token.ExpiresAt),
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GenerateKeys(tenantID string, count int, boundEmails []string, expiresAt *time.Time) ([]GeneratedKey, error) {
	return s.GenerateKeysWithMaxUses(tenantID, count, boundEmails, expiresAt, 1)
}

func (s *Store) GenerateKeysWithMaxUses(tenantID string, count int, boundEmails []string, expiresAt *time.Time, maxUses int) ([]GeneratedKey, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant is required")
	}
	if maxUses <= 0 {
		maxUses = 1
	}
	if count <= 0 {
		count = 1
	}
	if len(boundEmails) > 0 {
		count = len(boundEmails)
		maxUses = 1
	}
	if count > 1000 {
		return nil, fmt.Errorf("count is too large")
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	if err := cleanupTx(tx, now); err != nil {
		return nil, err
	}

	generated := make([]GeneratedKey, 0, count)
	for i := 0; i < count; i++ {
		key := randomToken(32)
		id := randomToken(9)
		bound := ""
		if len(boundEmails) > 0 {
			bound = normalizeEmail(boundEmails[i])
		}
		if _, err := tx.Exec(
			`INSERT INTO invite_keys(id, tenant_id, plain_key, hash, bound_email, max_uses, created_at, expires_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			id,
			tenantID,
			key,
			hashToken(key),
			bound,
			maxUses,
			timeToDB(now),
			nullableTimeToDB(expiresAt),
		); err != nil {
			return nil, err
		}
		generated = append(generated, GeneratedKey{
			ID:         id,
			Key:        key,
			BoundEmail: bound,
			MaxUses:    maxUses,
			ExpiresAt:  expiresAt,
		})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return generated, nil
}

func (s *Store) RevokeKey(tenantID string, id string) error {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return nil
	}
	_, err := s.db.Exec(
		`UPDATE invite_keys
			SET revoked_at = COALESCE(revoked_at, ?)
			WHERE tenant_id = ? AND id = ?`,
		timeToDB(time.Now().UTC()),
		tenantID,
		id,
	)
	return err
}

func (s *Store) RestoreKey(tenantID string, id string) error {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return nil
	}
	_, err := s.db.Exec(
		`UPDATE invite_keys
			SET revoked_at = NULL
			WHERE tenant_id = ? AND id = ?`,
		tenantID,
		id,
	)
	return err
}

func (s *Store) DeleteKey(tenantID string, id string) error {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return nil
	}
	_, err := s.db.Exec(`DELETE FROM invite_keys WHERE tenant_id = ? AND id = ?`, tenantID, id)
	return err
}

func (s *Store) RevokeKeys(tenantID string, ids []string) error {
	tenantID = strings.TrimSpace(tenantID)
	ids = normalizeIDList(ids)
	if tenantID == "" || len(ids) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := timeToDB(time.Now().UTC())
	for _, id := range ids {
		if _, err := tx.Exec(
			`UPDATE invite_keys
				SET revoked_at = COALESCE(revoked_at, ?)
				WHERE tenant_id = ? AND id = ?`,
			now,
			tenantID,
			id,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeleteKeys(tenantID string, ids []string) error {
	tenantID = strings.TrimSpace(tenantID)
	ids = normalizeIDList(ids)
	if tenantID == "" || len(ids) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.Exec(`DELETE FROM invite_keys WHERE tenant_id = ? AND id = ?`, tenantID, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SaveInviteKey(input InviteKeyInput) error {
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.ID = strings.TrimSpace(input.ID)
	input.Key = strings.TrimSpace(input.Key)
	input.BoundEmail = normalizeEmail(input.BoundEmail)
	if input.TenantID == "" {
		return fmt.Errorf("tenant is required")
	}
	if input.MaxUses <= 0 {
		input.MaxUses = 1
	}
	if input.BoundEmail != "" {
		input.MaxUses = 1
	}

	now := time.Now().UTC()
	if input.ID == "" {
		if input.Key == "" {
			input.Key = randomToken(32)
		}
		_, err := s.db.Exec(
			`INSERT INTO invite_keys(id, tenant_id, plain_key, hash, bound_email, max_uses, created_at, expires_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			randomToken(9),
			input.TenantID,
			input.Key,
			hashToken(input.Key),
			input.BoundEmail,
			input.MaxUses,
			timeToDB(now),
			nullableTimeToDB(input.ExpiresAt),
		)
		return err
	}

	var plainKey, hash string
	err := s.db.QueryRow(
		`SELECT plain_key, hash FROM invite_keys WHERE tenant_id = ? AND id = ?`,
		input.TenantID,
		input.ID,
	).Scan(&plainKey, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		if input.Key == "" {
			input.Key = randomToken(32)
		}
		_, err = s.db.Exec(
			`INSERT INTO invite_keys(id, tenant_id, plain_key, hash, bound_email, max_uses, created_at, expires_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			input.ID,
			input.TenantID,
			input.Key,
			hashToken(input.Key),
			input.BoundEmail,
			input.MaxUses,
			timeToDB(now),
			nullableTimeToDB(input.ExpiresAt),
		)
		return err
	}
	if err != nil {
		return err
	}
	if input.Key != "" {
		plainKey = input.Key
		hash = hashToken(input.Key)
	}
	_, err = s.db.Exec(
		`UPDATE invite_keys
			SET plain_key = ?, hash = ?, bound_email = ?, max_uses = ?, expires_at = ?
			WHERE tenant_id = ? AND id = ?`,
		plainKey,
		hash,
		input.BoundEmail,
		input.MaxUses,
		nullableTimeToDB(input.ExpiresAt),
		input.TenantID,
		input.ID,
	)
	return err
}

func (s *Store) UseInviteKey(tenantID string, email string, key string, allowedDomains string) (User, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return User{}, ErrInvalidInviteKey
	}
	email = normalizeEmail(email)
	if !emailInDomains(email, allowedDomains) {
		return User{}, ErrInvalidEmailDomain
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return User{}, ErrInvalidEmailDomain
	}
	keyHash := hashToken(strings.TrimSpace(key))

	tx, err := s.db.Begin()
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	var (
		keyID      string
		boundEmail string
		maxUses    int
		expiresNS  sql.NullInt64
		usedNS     sql.NullInt64
		revokedNS  sql.NullInt64
	)
	err = tx.QueryRow(
		`SELECT id, bound_email, max_uses, expires_at, used_at, revoked_at
			FROM invite_keys
			WHERE tenant_id = ? AND hash = ?`,
		tenantID,
		keyHash,
	).Scan(&keyID, &boundEmail, &maxUses, &expiresNS, &usedNS, &revokedNS)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrInvalidInviteKey
	}
	if err != nil {
		return User{}, err
	}
	if maxUses <= 0 {
		maxUses = 1
	}
	if revokedNS.Valid || (expiresNS.Valid && !now.Before(timeFromDB(expiresNS.Int64))) {
		return User{}, ErrInvalidInviteKey
	}
	if boundEmail != "" && boundEmail != email {
		return User{}, ErrInvalidInviteKey
	}

	user, err := ensureUserTx(tx, email, now)
	if err != nil {
		return User{}, err
	}

	var loginCount int
	err = tx.QueryRow(
		`SELECT login_count
			FROM invite_key_bindings
			WHERE tenant_id = ? AND key_id = ? AND email = ?`,
		tenantID,
		keyID,
		email,
	).Scan(&loginCount)
	if err == nil {
		if _, err := tx.Exec(
			`UPDATE invite_key_bindings
				SET last_used_at = ?, login_count = login_count + 1
				WHERE tenant_id = ? AND key_id = ? AND email = ?`,
			timeToDB(now),
			tenantID,
			keyID,
			email,
		); err != nil {
			return User{}, err
		}
		if err := tx.Commit(); err != nil {
			return User{}, err
		}
		return user, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return User{}, err
	}

	var usedCount int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM invite_key_bindings WHERE tenant_id = ? AND key_id = ?`,
		tenantID,
		keyID,
	).Scan(&usedCount); err != nil {
		return User{}, err
	}
	if usedNS.Valid && boundEmail == "" && usedCount == 0 {
		return User{}, ErrInvalidInviteKey
	}
	if usedCount >= maxUses {
		return User{}, ErrInvalidInviteKey
	}

	if _, err := tx.Exec(
		`INSERT INTO invite_key_bindings(tenant_id, key_id, email, first_used_at, last_used_at, login_count)
			VALUES (?, ?, ?, ?, ?, 1)`,
		tenantID,
		keyID,
		email,
		timeToDB(now),
		timeToDB(now),
	); err != nil {
		return User{}, err
	}
	if _, err := tx.Exec(
		`UPDATE invite_keys
			SET used_at = COALESCE(used_at, ?),
				bound_email = CASE WHEN bound_email = '' AND max_uses <= 1 THEN ? ELSE bound_email END
			WHERE tenant_id = ? AND id = ?`,
		timeToDB(now),
		email,
		tenantID,
		keyID,
	); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return user, nil
}

func (s *Store) CreateAuthCode(tenantID, email, clientID, redirectURI, nonce, scope string) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "", fmt.Errorf("tenant is required")
	}
	email = normalizeEmail(email)
	now := time.Now().UTC()
	code := randomToken(32)

	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	if err := cleanupTx(tx, now); err != nil {
		return "", err
	}
	if _, err := ensureUserTx(tx, email, now); err != nil {
		return "", err
	}
	if _, err := tx.Exec(
		`INSERT INTO auth_codes(hash, tenant_id, email, client_id, redirect_uri, nonce, scope, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hashToken(code),
		tenantID,
		email,
		clientID,
		redirectURI,
		nonce,
		scope,
		timeToDB(now),
		timeToDB(now.Add(5*time.Minute)),
	); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return code, nil
}

func (s *Store) ConsumeAuthCode(tenantID, code, clientID, redirectURI string) (User, AuthCode, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return User{}, AuthCode{}, ErrInvalidAuthCode
	}
	now := time.Now().UTC()
	codeHash := hashToken(strings.TrimSpace(code))

	tx, err := s.db.Begin()
	if err != nil {
		return User{}, AuthCode{}, err
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		`UPDATE auth_codes
			SET used_at = ?
			WHERE tenant_id = ?
				AND hash = ?
				AND used_at IS NULL
				AND expires_at > ?
				AND client_id = ?
				AND redirect_uri = ?`,
		timeToDB(now),
		tenantID,
		codeHash,
		timeToDB(now),
		clientID,
		redirectURI,
	)
	if err != nil {
		return User{}, AuthCode{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return User{}, AuthCode{}, err
	}
	if affected != 1 {
		return User{}, AuthCode{}, ErrInvalidAuthCode
	}

	authCode, err := authCodeByHashTx(tx, tenantID, codeHash)
	if err != nil {
		return User{}, AuthCode{}, err
	}
	user, err := ensureUserTx(tx, authCode.Email, now)
	if err != nil {
		return User{}, AuthCode{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, AuthCode{}, err
	}
	return user, authCode, nil
}

func (s *Store) CreateAccessToken(tenantID, email string) (string, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return "", fmt.Errorf("tenant is required")
	}
	email = normalizeEmail(email)
	now := time.Now().UTC()
	token := randomToken(32)

	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	if err := cleanupTx(tx, now); err != nil {
		return "", err
	}
	if _, err := ensureUserTx(tx, email, now); err != nil {
		return "", err
	}
	if _, err := tx.Exec(
		`INSERT INTO access_tokens(hash, tenant_id, email, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?)`,
		hashToken(token),
		tenantID,
		email,
		timeToDB(now),
		timeToDB(now.Add(time.Hour)),
	); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Store) LookupAccessToken(tenantID, token string) (User, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return User{}, ErrInvalidAccessToken
	}
	now := time.Now().UTC()
	row := s.db.QueryRow(
		`SELECT u.email, u.sub, u.created_at
			FROM access_tokens AS at
			JOIN users AS u ON u.email = at.email
			WHERE at.tenant_id = ? AND at.hash = ? AND at.expires_at > ?`,
		tenantID,
		hashToken(strings.TrimSpace(token)),
		timeToDB(now),
	)
	user, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrInvalidAccessToken
	}
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (s *Store) KeyViews(tenantID string) []KeyView {
	rows, err := s.db.Query(
		`SELECT
				k.id,
				k.plain_key,
				k.bound_email,
				k.max_uses,
				k.created_at,
				k.expires_at,
				k.used_at,
				k.revoked_at,
				COALESCE((
					SELECT GROUP_CONCAT(email, char(10))
					FROM (
						SELECT email
						FROM invite_key_bindings
						WHERE tenant_id = k.tenant_id AND key_id = k.id
						ORDER BY first_used_at
					)
				), ''),
				(SELECT COUNT(*) FROM invite_key_bindings WHERE tenant_id = k.tenant_id AND key_id = k.id)
			FROM invite_keys AS k
			WHERE k.tenant_id = ?
			ORDER BY k.created_at DESC, k.rowid DESC`,
		strings.TrimSpace(tenantID),
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	views, err := scanKeyRows(rows)
	if err != nil {
		return nil
	}
	return views
}

func (s *Store) KeyListPage(tenantID string, page int, pageSize int) (KeyListPage, error) {
	tenantID = strings.TrimSpace(tenantID)
	if page < 1 {
		page = 1
	}
	switch {
	case pageSize <= 0:
		pageSize = 20
	case pageSize > 100:
		pageSize = 100
	}

	var total int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM invite_keys WHERE tenant_id = ?`, tenantID).Scan(&total); err != nil {
		return KeyListPage{}, err
	}
	totalPages := 1
	if total > 0 {
		totalPages = (total + pageSize - 1) / pageSize
	}
	if page > totalPages {
		page = totalPages
	}
	offset := (page - 1) * pageSize

	rows, err := s.db.Query(
		`SELECT
				k.id,
				k.plain_key,
				k.bound_email,
				k.max_uses,
				k.created_at,
				k.expires_at,
				k.used_at,
				k.revoked_at,
				COALESCE((
					SELECT GROUP_CONCAT(email, char(10))
					FROM (
						SELECT email
						FROM invite_key_bindings
						WHERE tenant_id = k.tenant_id AND key_id = k.id
						ORDER BY first_used_at
					)
				), ''),
				(SELECT COUNT(*) FROM invite_key_bindings WHERE tenant_id = k.tenant_id AND key_id = k.id)
			FROM invite_keys AS k
			WHERE k.tenant_id = ?
			ORDER BY k.created_at DESC, k.rowid DESC
			LIMIT ? OFFSET ?`,
		tenantID,
		pageSize,
		offset,
	)
	if err != nil {
		return KeyListPage{}, err
	}
	defer rows.Close()

	items, err := scanKeyRows(rows)
	if err != nil {
		return KeyListPage{}, err
	}

	start := 0
	end := 0
	if total > 0 {
		start = offset + 1
		end = offset + len(items)
	}
	return KeyListPage{
		Items:      items,
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
		HasPrev:    page > 1,
		HasNext:    page < totalPages,
		PrevPage:   maxInt(1, page-1),
		NextPage:   minInt(totalPages, page+1),
		Start:      start,
		End:        end,
		Pages:      pageWindow(page, totalPages),
	}, nil
}

func scanKeyRows(rows *sql.Rows) ([]KeyView, error) {
	now := time.Now().UTC()
	var views []KeyView
	for rows.Next() {
		var (
			id, plainKey       string
			boundEmail         string
			bindings           string
			maxUses, usedCount int
			createdAtNS        int64
			expiresNS          sql.NullInt64
			usedNS, revokedNS  sql.NullInt64
		)
		if err := rows.Scan(&id, &plainKey, &boundEmail, &maxUses, &createdAtNS, &expiresNS, &usedNS, &revokedNS, &bindings, &usedCount); err != nil {
			return nil, err
		}
		if maxUses <= 0 {
			maxUses = 1
		}
		createdAt := timeFromDB(createdAtNS)
		status := "可用"
		if revokedNS.Valid {
			status = "已禁用"
		} else if expiresNS.Valid && now.After(timeFromDB(expiresNS.Int64)) {
			status = "已过期"
		} else if usedNS.Valid && boundEmail == "" && usedCount == 0 {
			status = "历史已用"
		} else if usedCount >= maxUses {
			status = "已满额"
		} else if usedCount > 0 {
			status = "使用中"
		}
		expires := "永不过期"
		expiresInput := ""
		if expiresNS.Valid {
			expiresAt := timeFromDB(expiresNS.Int64).Local()
			expires = expiresAt.Format("2006-01-02 15:04")
			expiresInput = expiresAt.Format("2006-01-02T15:04")
		}
		views = append(views, KeyView{
			ID:           id,
			Key:          plainKey,
			BoundEmail:   boundEmail,
			Bindings:     bindings,
			UsedCount:    usedCount,
			MaxUses:      maxUses,
			CreatedAt:    createdAt.Local().Format("2006-01-02 15:04"),
			ExpiresAt:    expires,
			ExpiresInput: expiresInput,
			Status:       status,
			Revoked:      revokedNS.Valid,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return views, nil
}

func pageWindow(page int, totalPages int) []int {
	if totalPages < 1 {
		totalPages = 1
	}
	start := maxInt(1, page-2)
	end := minInt(totalPages, start+4)
	start = maxInt(1, end-4)
	pages := make([]int, 0, end-start+1)
	for i := start; i <= end; i++ {
		pages = append(pages, i)
	}
	return pages
}

func minInt(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func normalizeIDList(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func cleanupTx(tx *sql.Tx, now time.Time) error {
	nowDB := timeToDB(now)
	if _, err := tx.Exec(`DELETE FROM auth_codes WHERE used_at IS NOT NULL OR expires_at <= ?`, nowDB); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM access_tokens WHERE expires_at <= ?`, nowDB); err != nil {
		return err
	}
	return nil
}

func ensureUserTx(tx *sql.Tx, email string, now time.Time) (User, error) {
	email = normalizeEmail(email)
	user, err := userByEmailTx(tx, email)
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return User{}, err
	}

	if _, err := tx.Exec(
		`INSERT INTO users(email, sub, created_at)
			VALUES (?, ?, ?)
			ON CONFLICT(email) DO NOTHING`,
		email,
		"u_"+randomToken(18),
		timeToDB(now),
	); err != nil {
		return User{}, err
	}
	return userByEmailTx(tx, email)
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(row scanner) (User, error) {
	var (
		user      User
		createdNS int64
	)
	if err := row.Scan(&user.Email, &user.Sub, &createdNS); err != nil {
		return User{}, err
	}
	user.CreatedAt = timeFromDB(createdNS)
	return user, nil
}

func scanTenant(row scanner) (Tenant, error) {
	var (
		tenant               Tenant
		createdNS, updatedNS int64
	)
	if err := row.Scan(
		&tenant.ID,
		&tenant.IssuerURL,
		&tenant.Host,
		&tenant.AllowedDomains,
		&tenant.ClientID,
		&tenant.ClientSecret,
		&tenant.RedirectURIs,
		&createdNS,
		&updatedNS,
	); err != nil {
		return Tenant{}, err
	}
	tenant.CreatedAt = timeFromDB(createdNS)
	tenant.UpdatedAt = timeFromDB(updatedNS)
	return tenant, nil
}

func userByEmailTx(tx *sql.Tx, email string) (User, error) {
	return scanUser(tx.QueryRow(`SELECT email, sub, created_at FROM users WHERE email = ?`, normalizeEmail(email)))
}

func authCodeByHashTx(tx *sql.Tx, tenantID, hash string) (AuthCode, error) {
	var (
		code      AuthCode
		createdNS int64
		expiresNS int64
		usedNS    sql.NullInt64
	)
	err := tx.QueryRow(
		`SELECT hash, email, client_id, redirect_uri, nonce, scope, created_at, expires_at, used_at
			FROM auth_codes
			WHERE tenant_id = ? AND hash = ?`,
		tenantID,
		hash,
	).Scan(
		&code.Hash,
		&code.Email,
		&code.ClientID,
		&code.RedirectURI,
		&code.Nonce,
		&code.Scope,
		&createdNS,
		&expiresNS,
		&usedNS,
	)
	if err != nil {
		return AuthCode{}, err
	}
	code.CreatedAt = timeFromDB(createdNS)
	code.ExpiresAt = timeFromDB(expiresNS)
	code.UsedAt = nullableTimeFromDB(usedNS)
	return code, nil
}

func timeToDB(t time.Time) int64 {
	return t.UTC().UnixNano()
}

func timeFromDB(ns int64) time.Time {
	return time.Unix(0, ns).UTC()
}

func nullableTimeToDB(t *time.Time) any {
	if t == nil {
		return nil
	}
	return timeToDB(*t)
}

func nullableTimeFromDB(ns sql.NullInt64) *time.Time {
	if !ns.Valid {
		return nil
	}
	t := timeFromDB(ns.Int64)
	return &t
}

func normalizeTenantInput(input TenantInput) (TenantInput, string, error) {
	input.ID = strings.TrimSpace(input.ID)
	input.IssuerURL = strings.TrimRight(strings.TrimSpace(input.IssuerURL), "/")
	input.AllowedDomains = strings.Join(normalizeDomainList(input.AllowedDomains), "\n")
	input.ClientID = strings.TrimSpace(input.ClientID)
	input.ClientSecret = strings.TrimSpace(input.ClientSecret)
	if input.ClientSecret == "" {
		input.ClientSecret = randomToken(32)
	}
	input.RedirectURIs = strings.Join(parseLines(input.RedirectURIs), "\n")

	if input.IssuerURL == "" {
		return TenantInput{}, "", fmt.Errorf("issuer URL is required")
	}
	parsed, err := url.Parse(input.IssuerURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return TenantInput{}, "", fmt.Errorf("issuer URL must include scheme and host")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return TenantInput{}, "", fmt.Errorf("issuer URL scheme must be http or https")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return TenantInput{}, "", fmt.Errorf("issuer URL must not include query or fragment")
	}
	host := normalizeHost(parsed.Host)
	if host == "" {
		return TenantInput{}, "", fmt.Errorf("issuer URL host is required")
	}
	if input.AllowedDomains == "" {
		return TenantInput{}, "", fmt.Errorf("at least one allowed domain is required")
	}
	if input.ClientID == "" {
		return TenantInput{}, "", fmt.Errorf("client ID is required")
	}
	input.IssuerURL = parsed.Scheme + "://" + host + strings.TrimRight(parsed.EscapedPath(), "/")
	return input, host, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func normalizeDomainList(raw string) []string {
	seen := map[string]bool{}
	var domains []string
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ';' || r == ' ' || r == '\t'
	}) {
		domain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(item)), "@")
		domain = strings.TrimSuffix(domain, ".")
		if domain == "" || seen[domain] {
			continue
		}
		seen[domain] = true
		domains = append(domains, domain)
	}
	return domains
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if h, port, err := net.SplitHostPort(host); err == nil {
		h = strings.TrimSuffix(strings.ToLower(strings.Trim(h, "[]")), ".")
		if port == "80" || port == "443" {
			return h
		}
		return h + ":" + port
	}
	return host
}

func emailInDomain(email string, domain string) bool {
	return emailInDomains(email, domain)
}

func emailInDomains(email string, domains string) bool {
	email = normalizeEmail(email)
	for _, domain := range normalizeDomainList(domains) {
		if strings.HasSuffix(email, "@"+domain) {
			return true
		}
	}
	return false
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
