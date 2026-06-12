package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
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
		`CREATE TABLE IF NOT EXISTS users (
			email TEXT PRIMARY KEY,
			sub TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS invite_keys (
			id TEXT PRIMARY KEY,
			hash TEXT NOT NULL UNIQUE,
			bound_email TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			expires_at INTEGER,
			used_at INTEGER,
			revoked_at INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS idx_invite_keys_hash ON invite_keys(hash)`,
		`CREATE INDEX IF NOT EXISTS idx_invite_keys_created_at ON invite_keys(created_at)`,
		`CREATE TABLE IF NOT EXISTS auth_codes (
			hash TEXT PRIMARY KEY,
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
		`CREATE INDEX IF NOT EXISTS idx_auth_codes_email ON auth_codes(email)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at ON auth_codes(expires_at)`,
		`CREATE TABLE IF NOT EXISTS access_tokens (
			hash TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			FOREIGN KEY(email) REFERENCES users(email)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_email ON access_tokens(email)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at)`,
		`INSERT INTO schema_meta(key, value)
			VALUES ('schema_version', '1')
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
	}
	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
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
	tables := []string{"users", "invite_keys", "auth_codes", "access_tokens"}
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
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO invite_keys(id, hash, bound_email, created_at, expires_at, used_at, revoked_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
			k.ID,
			k.Hash,
			normalizeEmail(k.BoundEmail),
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
			`INSERT INTO invite_keys(id, hash, bound_email, created_at, expires_at)
				VALUES (?, ?, ?, ?, ?)`,
			id,
			hashToken(key),
			bound,
			timeToDB(now),
			nullableTimeToDB(expiresAt),
		); err != nil {
			return nil, err
		}
		generated = append(generated, GeneratedKey{
			ID:         id,
			Key:        key,
			BoundEmail: bound,
			ExpiresAt:  expiresAt,
		})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return generated, nil
}

func (s *Store) RevokeKey(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	_, err := s.db.Exec(
		`UPDATE invite_keys
			SET revoked_at = COALESCE(revoked_at, ?)
			WHERE id = ?`,
		timeToDB(time.Now().UTC()),
		id,
	)
	return err
}

func (s *Store) UseInviteKey(email string, key string, allowedDomain string) (User, error) {
	email = normalizeEmail(email)
	if !emailInDomain(email, allowedDomain) {
		return User{}, ErrInvalidEmailDomain
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return User{}, ErrInvalidEmailDomain
	}

	tx, err := s.db.Begin()
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	result, err := tx.Exec(
		`UPDATE invite_keys
			SET used_at = ?
			WHERE hash = ?
				AND used_at IS NULL
				AND revoked_at IS NULL
				AND (expires_at IS NULL OR expires_at > ?)
				AND (bound_email = '' OR bound_email = ?)`,
		timeToDB(now),
		hashToken(strings.TrimSpace(key)),
		timeToDB(now),
		email,
	)
	if err != nil {
		return User{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return User{}, err
	}
	if affected != 1 {
		return User{}, ErrInvalidInviteKey
	}

	user, err := ensureUserTx(tx, email, now)
	if err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, err
	}
	return user, nil
}

func (s *Store) CreateAuthCode(email, clientID, redirectURI, nonce, scope string) (string, error) {
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
		`INSERT INTO auth_codes(hash, email, client_id, redirect_uri, nonce, scope, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		hashToken(code),
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

func (s *Store) ConsumeAuthCode(code, clientID, redirectURI string) (User, AuthCode, error) {
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
			WHERE hash = ?
				AND used_at IS NULL
				AND expires_at > ?
				AND client_id = ?
				AND redirect_uri = ?`,
		timeToDB(now),
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

	authCode, err := authCodeByHashTx(tx, codeHash)
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

func (s *Store) CreateAccessToken(email string) (string, error) {
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
		`INSERT INTO access_tokens(hash, email, created_at, expires_at)
			VALUES (?, ?, ?, ?)`,
		hashToken(token),
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

func (s *Store) LookupAccessToken(token string) (User, error) {
	now := time.Now().UTC()
	row := s.db.QueryRow(
		`SELECT u.email, u.sub, u.created_at
			FROM access_tokens AS at
			JOIN users AS u ON u.email = at.email
			WHERE at.hash = ? AND at.expires_at > ?`,
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

func (s *Store) KeyViews() []KeyView {
	rows, err := s.db.Query(
		`SELECT id, bound_email, created_at, expires_at, used_at, revoked_at
			FROM invite_keys
			ORDER BY created_at DESC, rowid DESC`,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	now := time.Now().UTC()
	var views []KeyView
	for rows.Next() {
		var (
			id, boundEmail    string
			createdAtNS       int64
			expiresNS         sql.NullInt64
			usedNS, revokedNS sql.NullInt64
		)
		if err := rows.Scan(&id, &boundEmail, &createdAtNS, &expiresNS, &usedNS, &revokedNS); err != nil {
			return nil
		}
		createdAt := timeFromDB(createdAtNS)
		status := "unused"
		if revokedNS.Valid {
			status = "revoked"
		} else if usedNS.Valid {
			status = "used"
		} else if expiresNS.Valid && now.After(timeFromDB(expiresNS.Int64)) {
			status = "expired"
		}
		expires := "never"
		if expiresNS.Valid {
			expires = timeFromDB(expiresNS.Int64).Local().Format("2006-01-02 15:04")
		}
		views = append(views, KeyView{
			ID:         id,
			BoundEmail: boundEmail,
			CreatedAt:  createdAt.Local().Format("2006-01-02 15:04"),
			ExpiresAt:  expires,
			Status:     status,
		})
	}
	if err := rows.Err(); err != nil {
		return nil
	}
	return views
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

func userByEmailTx(tx *sql.Tx, email string) (User, error) {
	return scanUser(tx.QueryRow(`SELECT email, sub, created_at FROM users WHERE email = ?`, normalizeEmail(email)))
}

func authCodeByHashTx(tx *sql.Tx, hash string) (AuthCode, error) {
	var (
		code      AuthCode
		createdNS int64
		expiresNS int64
		usedNS    sql.NullInt64
	)
	err := tx.QueryRow(
		`SELECT hash, email, client_id, redirect_uri, nonce, scope, created_at, expires_at, used_at
			FROM auth_codes
			WHERE hash = ?`,
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
