# gooidc — Agent Guidelines

## Project Purpose

This is a small self-hosted OpenID Connect provider for one narrow use case:

- The administrator creates and manages login keys.
- A user signs in with an allowed email name/domain and login key.
- The email must belong to one of the selected tenant's allowed email domains, for example `@abc.com`.
- The service issues OIDC tokens so OpenAI / ChatGPT Business can use it as a Custom OIDC SSO provider.

This project is intentionally lightweight. It is not a full identity platform like authentik,
Keycloak, Okta, Google Workspace, or Microsoft Entra ID.

## Current Architecture

Runtime:

- Go standard library plus `modernc.org/sqlite`
- Keep external Go dependencies minimal
- SQLite storage under `DATA_DIR`
- Docker-ready static Go binary

Important files:

- `main.go`: service startup, bootstrap environment config, secret generation, route registration
- `handlers.go`: admin routes, tenant management, login flow, OIDC endpoints
- `store.go`: tenant/key/user/auth-code/access-token storage and login key binding
- `crypto.go`: RSA signing key, JWKS, JWT signing, session cookie HMAC
- `templates.go`: embedded HTML templates for `/admin` and `/login`
- `Dockerfile`: container build
- `README.md`: user-facing run/configuration guide
- `.github/workflows/docker-ghcr.yml`: GitHub Actions build and GHCR publish workflow

## OIDC Endpoints

The service exposes:

- `/.well-known/openid-configuration`
- `/jwks.json`
- `/authorize`
- `/token`
- `/userinfo`
- `/login`
- `/admin`

The supported flow is authorization code flow:

```text
OpenAI -> /authorize -> /login -> redirect with code -> /token -> id_token
```

Requests are routed by HTTP `Host` to a configured tenant. Each tenant has its own issuer URL,
allowed email domain allow-list, OIDC client ID, client secret, and redirect URI allow-list.
One issuer tenant can allow multiple email domains; those email domains do not need their own
SSO DNS records.

Token endpoint client authentication supports:

- `client_secret_basic`
- `client_secret_post`

ID tokens are signed with RS256. The RSA private key is persisted in `DATA_DIR`.

## Storage Model

The service stores data in:

```text
DATA_DIR/store.db
```

If an older `DATA_DIR/store.json` exists and `store.db` is empty, it is imported on startup.

Stored entities:

- OIDC tenants
- login keys and login key email bindings
- users
- authorization codes
- access tokens

Secrets stored in `DATA_DIR` when not provided via environment variables:

- `admin_password.txt`
- `oidc_client_secret.txt`
- `app_secret.txt`
- `oidc_private_key.pem`

Do not log or commit anything from `DATA_DIR`.

## Login Key Rules

Login keys are generated or edited by the admin page.

Security behavior:

- New keys are stored as plaintext for admin visibility and as SHA-256 hashes for lookup.
- Treat `DATA_DIR/store.db` as sensitive because it contains visible login keys.
- Each key can bind to a configured number of email addresses; the default is 1.
- A bound email can reuse the same key for later logins.
- A key can be revoked.
- A key can expire.
- A key can optionally be bound to a specific email.
- If a key is not bound to an email, whoever holds it can bind it to any email in the selected tenant's allowed email domains until the key reaches its max bound email count.
- Invite keys, authorization codes, access tokens, and sessions are scoped to one tenant.

Current behavior is "email-bound reusable login key". This is intentionally lightweight and
does not include password, passkey, email verification, SCIM, or a full user directory.

## Environment Variables

Required or strongly recommended in production for first-run tenant seeding:

```text
ISSUER_URL=https://sso.example.com
ALLOWED_DOMAINS=example.com,other-example.com
OIDC_CLIENT_ID=openai
OIDC_CLIENT_SECRET=<strong random secret>
OIDC_REDIRECT_URIS=<callback URL copied from OpenAI SSO page>
ADMIN_USER=admin
ADMIN_PASSWORD=<strong admin password>
DATA_DIR=/data
ADDR=:8080
```

`ISSUER_URL` must exactly match the public HTTPS URL OpenAI can reach. It is just the OIDC
service address; allowed login email domains are configured separately in the tenant.

`OIDC_REDIRECT_URIS` should be configured. If empty, the service accepts any redirect URI,
which is not recommended for production.

These OIDC variables seed the first tenant when the SQLite database has no tenants. `ALLOWED_DOMAIN`
is still accepted for backward compatibility, but `ALLOWED_DOMAINS` is preferred. After first boot,
tenants and their allowed email domain lists are managed in `/admin`. Multiple public issuer domains
can point to the same container as long as the reverse proxy preserves the original `Host` header,
but the common setup is one issuer with multiple allowed email domains.

If the first tenant is still the default `http://localhost:8080`, the admin page may adopt the
current public admin origin, such as `https://oidc.ai90.net`, as that tenant's issuer URL.

## Docker

Build locally:

```bash
docker build -t gooidc:latest .
```

Run locally:

```bash
docker run -d \
  --name gooidc \
  --restart unless-stopped \
  -p 8080:8080 \
  -v gooidc-data:/data \
  -e ISSUER_URL=https://sso.example.com \
  -e ALLOWED_DOMAINS=example.com,other-example.com \
  -e OIDC_CLIENT_ID=openai \
  -e OIDC_REDIRECT_URIS=https://callback.example/from/openai \
  -e ADMIN_USER=admin \
  -e ADMIN_PASSWORD='change-this-admin-password' \
  -e OIDC_CLIENT_SECRET='change-this-oidc-client-secret' \
  gooidc:latest
```

The GitHub Actions workflow publishes:

```text
ghcr.io/yonghumeijj/myoidc:latest
```

## Build and Validation

Use:

```bash
go test ./...
go build ./...
gofmt -w .
```

There are focused store tests. For non-trivial changes, add or update focused tests around:

- login key binding and reuse
- bound email behavior
- expired/revoked key rejection
- authorization code reuse rejection
- token endpoint client authentication
- redirect URI validation

## Security Notes

Do not weaken these behaviors without explicitly calling out the risk:

- Protect `DATA_DIR/store.db`; new login keys are visible there for admin CRUD.
- Bind keys under a SQLite transaction so one key cannot exceed its configured bound-email limit concurrently.
- Keep `OIDC_REDIRECT_URIS` strict in production.
- Keep `ISSUER_URL` stable after deployment; changing it can break OpenAI SSO.
- Keep `oidc_private_key.pem` persistent; replacing it invalidates published JWKS trust until clients refresh metadata.
- Use HTTPS in production.
- Keep SSO optional in OpenAI until the full login flow is tested.

## Known Limitations

- Multiple OIDC tenants are supported, selected by request `Host`.
- No SCIM/user directory sync.
- No admin audit log.
- No email verification.
- No password/passkey login for returning users.
- SQLite storage is fine for small usage, but this is still not designed for very large user counts.
- No PKCE support at the moment.

These are acceptable for the current "OpenAI SSO with admin-issued login keys" scope.

## Development Guidance

When changing this project:

- Keep the dependency footprint small.
- Prefer standard library code unless a protocol/security feature clearly needs a library.
- Do not hand-roll new crypto primitives.
- Keep admin UI simple and server-rendered.
- Do not add frontend build tooling unless there is a strong reason.
- Preserve Docker volume compatibility for `/data`.
- Avoid breaking the existing SQLite schema; add migrations where needed.
- Preserve one-time migration compatibility for legacy `store.json` where practical.
- Keep tenant-scoped state tenant-scoped; do not let one tenant's unbound key, auth code,
  access token, or session authenticate against another tenant.
- Keep the admin page server-rendered but usable for routine operations, including tenant
  editing, login key CRUD, and admin password changes.
- Update `README.md` when changing environment variables or deployment behavior.
