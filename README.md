# gooidc

A small OpenID Connect provider for a narrow use case:

- Admin generates one-time login keys.
- User signs in with `email + one-time key`.
- Email must belong to the configured domain.
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

## Security Notes

- Keys are random and stored only as SHA-256 hashes.
- Plaintext keys are shown once after generation.
- Each key can be used once.
- A key can optionally be bound to a specific email.
- If a key is not bound to an email, anyone holding it can choose any `@abc.com` email.
- Configure `OIDC_REDIRECT_URIS`; leaving it empty accepts any redirect URI.
- Put this service behind HTTPS before using it with OpenAI.
- This project is a lightweight OIDC implementation for one client, not a replacement for authentik/Keycloak.
