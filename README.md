# gooidc

A small OpenID Connect provider for a narrow use case:

- Admin creates and manages login keys.
- User signs in with an allowed email name/domain and login key.
- Email must belong to one of the configured tenant email domains.
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

The public root page `/` shows the user login-style page and a key lookup form. The lookup
form lets a user enter a login key and see the email addresses currently bound to it.

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

`ISSUER_URL`, `ALLOWED_DOMAINS` or `ALLOWED_DOMAIN`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and
`OIDC_REDIRECT_URIS` seed the first tenant when the database has no tenants. After that,
manage tenants in `/admin`.

If you start without `ISSUER_URL`, the first admin visit from a real host such as
`https://oidc.ai90.net/admin` updates the default tenant from `http://localhost:8080`
to that public origin.

## Docker

```bash
docker build -t gooidc:latest .

docker run -d \
  --name gooidc \
  --restart unless-stopped \
  -p 8080:8080 \
  -v gooidc-data:/data \
  -e ISSUER_URL=https://sso.abc.com \
  -e ALLOWED_DOMAINS='abc.com,xyz.com,aaa.com' \
  -e OIDC_CLIENT_ID=openai \
  -e OIDC_REDIRECT_URIS=https://OPENAI_CALLBACK_URL_FROM_SSO_PAGE \
  -e ADMIN_USER=admin \
  -e ADMIN_PASSWORD='change-this-admin-password' \
  -e OIDC_CLIENT_SECRET='change-this-oidc-client-secret' \
  gooidc:latest
```

`ISSUER_URL` must be the public HTTPS URL that OpenAI can reach. It is only the OIDC
service address; the email domains users can sign in with are configured separately.

Most deployments only need one issuer tenant, for example `https://sso.abc.com`, with
multiple allowed email domains such as `abc.com`, `xyz.com`, and `aaa.com`.

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
  -e ALLOWED_DOMAINS='abc.com,xyz.com,aaa.com' \
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

If OpenAI reports `invalid_client`, check:

- `https://your-issuer/.well-known/openid-configuration` must return `https://` issuer and token endpoint URLs.
- OpenAI's Client ID and Client Secret must exactly match the selected tenant in `/admin`.
- If you changed OpenAI Team/workspace, update the tenant's allowed redirect URI to the new OpenAI callback URL.

ID tokens include the OpenAI-required `sub`, `email`, `given_name`, and `family_name` claims.
`given_name` is derived from the email local part and `family_name` is an empty string.

## Troubleshooting Logs

Runtime diagnostics are written to standard output. On Docker, watch the latest logs with:

```bash
docker logs -f --tail=200 gooidc
```

For OpenAI SSO failures, retry one login and look for lines beginning with:

```text
oidc authorize
oidc login
oidc token
oidc userinfo
```

`invalid_client` failures include the auth method, client ID match status, redirect URI, and
secret length checks. Logs do not print raw client secrets, login keys, authorization
codes, or access tokens.

## Multi-Tenant Setup

Open `/admin` to add or edit tenants. In the common single-issuer setup, keep one tenant:

```text
Issuer URL:      https://sso.abc.com
Allowed domains: abc.com
                 xyz.com
                 aaa.com
Client ID:       openai
Client Secret:   tenant-specific client secret
Redirect URIs:   callback URL copied from the OpenAI SSO page
```

Only `sso.abc.com` must resolve to this service. `xyz.com` and `aaa.com` are just email
domains in the allow-list; they do not need SSO DNS records.

Optional: multiple issuer hosts are also supported. For that setup, point each issuer DNS
record at the same server and add one tenant per issuer host, for example:

```text
https://sso.abc.com  -> abc.com
https://sso.def.com  -> def.com
https://sso.xyz.com  -> xyz.com
```

Your reverse proxy must preserve the original `Host` header:

```nginx
proxy_set_header Host $host;
```

Create and edit login keys from the selected tenant in `/admin`. A key is scoped to that
tenant only. By default, a key can bind to one email address. On first successful login,
an unbound key is bound to that email; the same email can reuse the same key later. Increase
the key's max bound email count if one key should allow multiple different email addresses.

The admin password can also be changed in `/admin`. When `ADMIN_PASSWORD` is set as an
environment variable, that value will be used again after container restart; omit it if you
want the password stored in `/data/admin_password.txt` to be the source of truth.

Admin authentication uses the `/admin/login` form and a signed session cookie. HTTP Basic
credentials are still accepted for compatibility, but browsers are no longer challenged with
a Basic Auth popup.

## Security Notes

- New keys are stored as plaintext for admin visibility and as SHA-256 hashes for lookup.
- Treat `DATA_DIR/store.db` as sensitive because it contains visible login keys.
- Each key can bind to a configured number of email addresses; the default is 1.
- A bound email can reuse the same key for later logins.
- A key can optionally be restricted to a specific email before first use.
- If a key is unrestricted and unbound, anyone holding it can bind it to an allowed email until its max bound email count is reached.
- Keys, authorization codes, and access tokens are scoped to one tenant.
- Configure `OIDC_REDIRECT_URIS`; leaving it empty accepts any redirect URI.
- Put this service behind HTTPS before using it with OpenAI.
- This project is a lightweight OIDC implementation for one client, not a replacement for authentik/Keycloak.
