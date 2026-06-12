package main

import "html/template"

var pages = template.Must(template.New("pages").Parse(adminHTML + loginHTML))

const pageCSS = `
body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #17202a; background: #f6f7f9; }
main { max-width: 1100px; margin: 32px auto; padding: 0 20px 48px; }
h1 { font-size: 28px; margin: 0 0 8px; }
h2 { font-size: 18px; margin: 0 0 16px; }
p { color: #53616f; line-height: 1.5; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; }
.panel { background: #fff; border: 1px solid #dfe4ea; border-radius: 8px; padding: 18px; box-shadow: 0 1px 2px rgba(0,0,0,.04); }
.row { display: grid; grid-template-columns: 170px 1fr; gap: 12px; padding: 7px 0; border-bottom: 1px solid #edf0f3; }
.row:last-child { border-bottom: 0; }
.label { color: #64707d; }
code, textarea, input { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
input, textarea { width: 100%; box-sizing: border-box; border: 1px solid #cfd6de; border-radius: 6px; padding: 9px 10px; background: #fff; color: #17202a; }
textarea { min-height: 130px; resize: vertical; }
button { border: 0; border-radius: 6px; padding: 9px 13px; background: #1f6feb; color: #fff; cursor: pointer; font-weight: 600; }
button.secondary { background: #59636e; }
button.danger { background: #d1242f; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { padding: 9px 8px; border-bottom: 1px solid #edf0f3; text-align: left; vertical-align: top; }
th { color: #53616f; font-weight: 700; }
.error { background: #fff1f1; border: 1px solid #ffb3b3; color: #a40e26; padding: 10px 12px; border-radius: 6px; margin: 0 0 16px; }
.success { background: #f0fff4; border: 1px solid #a7e8ba; color: #116329; padding: 12px; border-radius: 6px; margin: 0 0 16px; }
.muted { color: #6b7682; font-size: 13px; }
.actions { display: flex; gap: 8px; align-items: center; }
.login { max-width: 430px; }
`

const adminHTML = `
{{define "admin"}}
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Go OIDC Admin</title>
  <style>` + pageCSS + `</style>
</head>
<body>
<main>
  <h1>Go OIDC Admin</h1>
  <p>Generate one-time login keys for <code>@{{.AllowedDomain}}</code> users.</p>

  {{if .Error}}<div class="error">{{.Error}}</div>{{end}}

  {{if .Generated}}
  <section class="panel">
    <h2>Generated keys</h2>
    <div class="success">Copy these now. Plaintext keys are not stored and will not be shown again.</div>
    <textarea readonly>{{range .Generated}}{{if .BoundEmail}}{{.BoundEmail}},{{end}}{{.Key}}
{{end}}</textarea>
    <table>
      <thead><tr><th>ID</th><th>Bound email</th><th>Expires</th></tr></thead>
      <tbody>
      {{range .Generated}}
        <tr><td><code>{{.ID}}</code></td><td>{{if .BoundEmail}}{{.BoundEmail}}{{else}}any @domain email{{end}}</td><td>{{.ExpiresText}}</td></tr>
      {{end}}
      </tbody>
    </table>
  </section>
  <br>
  {{end}}

  <div class="grid">
    <section class="panel">
      <h2>OIDC settings for OpenAI</h2>
      <div class="row"><div class="label">Issuer</div><div><code>{{.Issuer}}</code></div></div>
      <div class="row"><div class="label">Discovery</div><div><code>{{.Issuer}}/.well-known/openid-configuration</code></div></div>
      <div class="row"><div class="label">Client ID</div><div><code>{{.ClientID}}</code></div></div>
      <div class="row"><div class="label">Client Secret</div><div><code>{{.ClientSecret}}</code></div></div>
      <div class="row"><div class="label">Allowed redirects</div><div><pre>{{if .AllowedRedirect}}{{.AllowedRedirect}}{{else}}not configured; all redirect_uri values are accepted{{end}}</pre></div></div>
    </section>

    <section class="panel">
      <h2>Generate keys</h2>
      <form method="post" action="/admin/keys">
        <p>
          <label>Count</label>
          <input name="count" type="number" min="1" max="1000" value="10">
        </p>
        <p>
          <label>Expires after hours</label>
          <input name="expires_hours" type="number" min="0" value="168">
          <span class="muted">Use 0 for no expiry. Bound emails below ignore Count.</span>
        </p>
        <p>
          <label>Optional bound emails</label>
          <textarea name="bound_emails" placeholder="user1@{{.AllowedDomain}}
user2@{{.AllowedDomain}}"></textarea>
        </p>
        <button type="submit">Generate</button>
      </form>
    </section>
  </div>

  <br>
  <section class="panel">
    <h2>Keys</h2>
    <table>
      <thead><tr><th>ID</th><th>Bound email</th><th>Created</th><th>Expires</th><th>Status</th><th>Action</th></tr></thead>
      <tbody>
      {{range .Keys}}
        <tr>
          <td><code>{{.ID}}</code></td>
          <td>{{if .BoundEmail}}{{.BoundEmail}}{{else}}any @domain email{{end}}</td>
          <td>{{.CreatedAt}}</td>
          <td>{{.ExpiresAt}}</td>
          <td>{{.Status}}</td>
          <td>
            {{if eq .Status "unused"}}
            <form method="post" action="/admin/revoke" class="actions">
              <input type="hidden" name="id" value="{{.ID}}">
              <button class="danger" type="submit">Revoke</button>
            </form>
            {{end}}
          </td>
        </tr>
      {{else}}
        <tr><td colspan="6" class="muted">No keys yet.</td></tr>
      {{end}}
      </tbody>
    </table>
  </section>
</main>
</body>
</html>
{{end}}
`

const loginHTML = `
{{define "login"}}
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in</title>
  <style>` + pageCSS + `</style>
</head>
<body>
<main class="login">
  <section class="panel">
    <h1>Sign in</h1>
    <p>Use your email and one-time key to continue.</p>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <form method="post" action="/login">
      <input type="hidden" name="response_type" value="{{.Auth.ResponseType}}">
      <input type="hidden" name="client_id" value="{{.Auth.ClientID}}">
      <input type="hidden" name="redirect_uri" value="{{.Auth.RedirectURI}}">
      <input type="hidden" name="scope" value="{{.Auth.Scope}}">
      <input type="hidden" name="state" value="{{.Auth.State}}">
      <input type="hidden" name="nonce" value="{{.Auth.Nonce}}">
      <p>
        <label>Email</label>
        <input name="email" type="email" autocomplete="username" required>
      </p>
      <p>
        <label>One-time key</label>
        <input name="key" type="password" autocomplete="one-time-code" required>
      </p>
      <button type="submit">Continue</button>
    </form>
  </section>
</main>
</body>
</html>
{{end}}
`
