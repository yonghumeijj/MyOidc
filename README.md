# gooidc

A small OpenID Connect provider for a narrow use case:

- Admin generates one-time login keys.
- User signs in with `email + one-time key`.
- Email must belong to the configured tenant domain.
- OpenAI/ChatGPT Business uses this service as a Custom OIDC SSO provider.

This is intentionally minimal. It is not a general identity platform.

## Run Locally

```bash
go run .
```

Default local issuer:

```text
http://localhost:8080
```

Admin page:

```text
http://localhost:8080/admin
```

If `ADMIN_PASSWORD` is not set, the service generates one and stores it in:

```text
data/admin_password.txt
```

If `OIDC_CLIENT_SECRET` is not set, the service generates one and stores it in:

```text
data/oidc_client_secret.txt
```

Runtime data is stored in SQLite:

```text
data/store.db
```

If an older `data/store.json` exists and `store.db` is empty, the service imports it on startup.

`ISSUER_URL`, `ALLOWED_DOMAIN`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and
`OIDC_REDIRECT_URIS` seed the first tenant when the database has no tenants. After that,
manage tenants in `/admin`.

## Docker

```bash
docker build -t gooidc:latest .

docker run -d \
  --name gooidc \
  --restart unless-stopped \
  -p 8080:8080 \
  -v gooidc-data:/data \
  -e ISSUER_URL=https://sso.abc.com \
  -e ALLOWED_DOMAIN=abc.com \
  -e OIDC_CLIENT_ID=openai \
  -e OIDC_REDIRECT_URIS=https://OPENAI_CALLBACK_URL_FROM_SSO_PAGE \
  -e ADMIN_USER=admin \
  -e ADMIN_PASSWORD='change-this-admin-password' \
  -e OIDC_CLIENT_SECRET='change-this-oidc-client-secret' \
  gooidc:latest
```

`ISSUER_URL` must be the public HTTPS URL that OpenAI can reach.

Multiple issuer domains can point to the same container. Add one tenant per public issuer
host in `/admin`; requests are routed by the HTTP `Host` header.

## GitHub Actions Image

Pushing to `main` builds and publishes:

```text
ghcr.io/yonghumeijj/myoidc:latest
```

Server update example:

```bash
docker pull ghcr.io/yonghumeijj/myoidc:latest

docker stop gooidc
docker rm gooidc

docker run -d \
  --name gooidc \
  --restart unless-stopped \
  -p 8080:8080 \
  -v gooidc-data:/data \
  -e ISSUER_URL=https://sso.abc.com \
  -e ALLOWED_DOMAIN=abc.com \
  -e OIDC_CLIENT_ID=openai \
  -e OIDC_REDIRECT_URIS=https://OPENAI_CALLBACK_URL_FROM_SSO_PAGE \
  -e ADMIN_USER=admin \
  -e ADMIN_PASSWORD='change-this-admin-password' \
  -e OIDC_CLIENT_SECRET='change-this-oidc-client-secret' \
  ghcr.io/yonghumeijj/myoidc:latest
```

## OpenAI Custom OIDC

Use these values in the OpenAI SSO page:

```text
Issuer / Discovery URL:
https://sso.abc.com/.well-known/openid-configuration

Client ID:
openai

Client Secret:
the OIDC_CLIENT_SECRET value
```

Keep SSO optional until a full login test succeeds.

## Multi-Tenant Setup

Open `/admin` to add or edit tenants. Each tenant has:

```text
Issuer URL:      https://sso.abc.com
Allowed domain:  abc.com
Client ID:       openai
Client Secret:   tenant-specific client secret
Redirect URIs:   callback URL copied from the OpenAI SSO page
```

For three domains, point all DNS records at the same server and add three tenants, for example:

```text
https://sso.abc.com  -> abc.com
https://sso.def.com  -> def.com
https://sso.xyz.com  -> xyz.com
```

Your reverse proxy must preserve the original `Host` header:

```nginx
proxy_set_header Host $host;
```

Generate one-time keys from the selected tenant in `/admin`. Unbound keys are scoped to
that tenant only.

## Security Notes

- Keys are random and stored only as SHA-256 hashes.
- Plaintext keys are shown once after generation.
- Each key can be used once.
- A key can optionally be bound to a specific email.
- If a key is not bound to an email, anyone holding it can choose any email in that tenant's allowed domain.
- Keys, authorization codes, and access tokens are scoped to one tenant.
- Configure `OIDC_REDIRECT_URIS`; leaving it empty accepts any redirect URI.
- Put this service behind HTTPS before using it with OpenAI.
- This project is a lightweight OIDC implementation for one client, not a replacement for authentik/Keycloak.
