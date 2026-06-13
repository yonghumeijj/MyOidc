package main

import "html/template"

var pages = template.Must(template.New("pages").Parse(adminHTML + loginHTML))

const pageCSS = `
:root {
  color-scheme: light;
  --bg: #f4f6f8;
  --panel: #ffffff;
  --ink: #17202a;
  --muted: #667381;
  --line: #dde3ea;
  --soft: #eef3f8;
  --brand: #1f6feb;
  --brand-dark: #1558c0;
  --danger: #c62835;
  --success-bg: #edfdf4;
  --success-line: #9ae6b4;
  --success-ink: #116329;
  --error-bg: #fff1f1;
  --error-line: #ffb3b3;
  --error-ink: #a40e26;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: var(--ink);
  background: var(--bg);
}
button, input, textarea, select { font: inherit; }
code, textarea, input.mono, .token, pre {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
a { color: inherit; }
.admin-shell {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 280px minmax(0, 1fr);
}
.sidebar {
  background: #111827;
  color: #f8fafc;
  padding: 22px 18px;
  display: flex;
  flex-direction: column;
  gap: 18px;
}
.brand {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(255,255,255,.12);
}
.brand strong { font-size: 18px; letter-spacing: .2px; }
.brand span, .side-label { color: #a8b3c3; font-size: 12px; }
.tenant-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.tenant-link {
  display: block;
  text-decoration: none;
  padding: 10px 11px;
  border: 1px solid rgba(255,255,255,.10);
  border-radius: 8px;
  color: #dbe5f1;
  overflow-wrap: anywhere;
}
.tenant-link.active {
  background: #233046;
  border-color: #4a90e2;
  color: #fff;
}
.sidebar .foot {
  margin-top: auto;
  color: #a8b3c3;
  font-size: 12px;
  overflow-wrap: anywhere;
}
.workspace {
  min-width: 0;
  padding: 26px;
}
.topbar {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 18px;
  margin-bottom: 20px;
}
h1 { font-size: 25px; margin: 0 0 5px; }
h2 { font-size: 17px; margin: 0; }
h3 { font-size: 14px; margin: 0 0 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
p { color: var(--muted); line-height: 1.5; margin: 0; }
.pill {
  background: #e8f0ff;
  color: #174ea6;
  border: 1px solid #c7d7ff;
  border-radius: 999px;
  padding: 7px 10px;
  font-size: 13px;
  white-space: nowrap;
}
.grid {
  display: grid;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  gap: 16px;
}
.span-4 { grid-column: span 4; }
.span-5 { grid-column: span 5; }
.span-6 { grid-column: span 6; }
.span-7 { grid-column: span 7; }
.span-8 { grid-column: span 8; }
.span-12 { grid-column: span 12; }
.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  box-shadow: 0 1px 2px rgba(16,24,40,.04);
  min-width: 0;
}
.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 16px 18px;
  border-bottom: 1px solid var(--line);
}
.panel-body { padding: 18px; }
.stack { display: flex; flex-direction: column; gap: 14px; }
.summary {
  display: grid;
  grid-template-columns: 170px minmax(0, 1fr);
  border-top: 1px solid var(--line);
}
.summary:first-child { border-top: 0; }
.summary dt, .summary dd {
  margin: 0;
  padding: 10px 0;
}
.summary dt { color: var(--muted); }
.summary dd { min-width: 0; overflow-wrap: anywhere; }
.token, pre {
  display: block;
  margin: 0;
  padding: 10px 11px;
  border: 1px solid #cfd8e3;
  border-radius: 7px;
  background: #f8fafc;
  color: #111827;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  word-break: break-word;
}
label {
  display: block;
  color: #405062;
  font-weight: 650;
  font-size: 13px;
  margin-bottom: 7px;
}
input, textarea, select {
  width: 100%;
  border: 1px solid #cfd8e3;
  border-radius: 7px;
  background: #fff;
  color: var(--ink);
  padding: 10px 11px;
}
textarea { min-height: 112px; resize: vertical; }
input:focus, textarea:focus, select:focus {
  outline: 2px solid rgba(31,111,235,.20);
  border-color: var(--brand);
}
.form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}
.full { grid-column: 1 / -1; }
.actions {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
button {
  border: 0;
  border-radius: 7px;
  padding: 10px 14px;
  background: var(--brand);
  color: #fff;
  cursor: pointer;
  font-weight: 700;
}
button:hover { background: var(--brand-dark); }
button.secondary { background: #59636e; }
button.danger { background: var(--danger); }
.muted { color: var(--muted); font-size: 13px; }
.notice, .error {
  border-radius: 8px;
  padding: 11px 13px;
  margin-bottom: 16px;
}
.notice { background: var(--success-bg); border: 1px solid var(--success-line); color: var(--success-ink); }
.error { background: var(--error-bg); border: 1px solid var(--error-line); color: var(--error-ink); }
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 14px;
}
th, td {
  padding: 10px 8px;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
}
th { color: var(--muted); font-weight: 700; }
td { overflow-wrap: anywhere; }
.status {
  display: inline-block;
  padding: 4px 8px;
  border-radius: 999px;
  background: var(--soft);
  color: #344054;
  font-size: 12px;
}
.login {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 24px;
}
.login-card {
  width: min(460px, 100%);
  background: #fff;
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 22px;
}
@media (max-width: 980px) {
  .admin-shell { grid-template-columns: 1fr; }
  .sidebar { position: static; }
  .workspace { padding: 18px; }
  .span-4, .span-5, .span-6, .span-7, .span-8, .span-12 { grid-column: span 12; }
}
@media (max-width: 640px) {
  .topbar { flex-direction: column; }
  .form-grid { grid-template-columns: 1fr; }
  .summary { grid-template-columns: 1fr; gap: 0; }
  .summary dt { padding-bottom: 0; }
}
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
<div class="admin-shell">
  <aside class="sidebar">
    <div class="brand">
      <strong>gooidc</strong>
      <span>OIDC provider</span>
    </div>

    <div class="tenant-list">
      <div class="side-label">Tenants</div>
      {{range .Tenants}}
      <a class="tenant-link {{if eq .ID $.Tenant.ID}}active{{end}}" href="/admin?tenant={{.ID}}">{{.IssuerURL}}</a>
      {{end}}
    </div>

    <div class="foot">
      <div>Admin</div>
      <strong>{{.AdminUser}}</strong>
    </div>
  </aside>

  <main class="workspace">
    <div class="topbar">
      <div>
        <h1>OIDC Administration</h1>
        <p>{{.Tenant.IssuerURL}}</p>
      </div>
      <div class="pill">{{.Origin}}</div>
    </div>

    {{if .Notice}}<div class="notice">{{.Notice}}</div>{{end}}
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}

    {{if .Generated}}
    <section class="panel span-12" style="margin-bottom:16px;">
      <div class="panel-head"><h2>Generated keys</h2></div>
      <div class="panel-body stack">
        <div class="notice">Copy these now. Plaintext keys are not stored.</div>
        <textarea readonly>{{range .Generated}}{{if .BoundEmail}}{{.BoundEmail}},{{end}}{{.Key}}
{{end}}</textarea>
        <table>
          <thead><tr><th>ID</th><th>Bound email</th><th>Expires</th></tr></thead>
          <tbody>
          {{range .Generated}}
          <tr>
            <td><code>{{.ID}}</code></td>
            <td>{{if .BoundEmail}}{{.BoundEmail}}{{else}}Any allowed domain{{end}}</td>
            <td>{{.ExpiresText}}</td>
          </tr>
          {{end}}
          </tbody>
        </table>
      </div>
    </section>
    {{end}}

    <div class="grid">
      <section class="panel span-7">
        <div class="panel-head"><h2>Tenant overview</h2></div>
        <div class="panel-body">
          {{if .Tenant.ID}}
          <dl>
            <div class="summary"><dt>Issuer</dt><dd><span class="token">{{.Tenant.IssuerURL}}</span></dd></div>
            <div class="summary"><dt>Discovery</dt><dd><span class="token">{{.Tenant.IssuerURL}}/.well-known/openid-configuration</span></dd></div>
            <div class="summary"><dt>Host</dt><dd><code>{{.Tenant.Host}}</code></dd></div>
            <div class="summary"><dt>Allowed domains</dt><dd><pre>{{.Tenant.AllowedDomains}}</pre></dd></div>
            <div class="summary"><dt>Client ID</dt><dd><code>{{.Tenant.ClientID}}</code></dd></div>
            <div class="summary"><dt>Client Secret</dt><dd><span class="token">{{.Tenant.ClientSecret}}</span></dd></div>
            <div class="summary"><dt>Redirect URIs</dt><dd><pre>{{if .Tenant.RedirectURIs}}{{.Tenant.RedirectURIs}}{{else}}not configured; all redirect_uri values are accepted{{end}}</pre></dd></div>
          </dl>
          {{end}}
        </div>
      </section>

      <section class="panel span-5">
        <div class="panel-head"><h2>Generate keys</h2></div>
        <div class="panel-body">
          <form method="post" action="/admin/keys" class="stack">
            <input type="hidden" name="tenant_id" value="{{.Tenant.ID}}">
            <div class="form-grid">
              <div>
                <label>Count</label>
                <input name="count" type="number" min="1" max="1000" value="10">
              </div>
              <div>
                <label>Expires after hours</label>
                <input name="expires_hours" type="number" min="0" value="168">
              </div>
              <div class="full">
                <label>Optional bound emails</label>
                <textarea name="bound_emails" placeholder="user1@{{.Tenant.PrimaryAllowedDomain}}
user2@{{.Tenant.PrimaryAllowedDomain}}"></textarea>
              </div>
            </div>
            <div class="actions"><button type="submit">Generate</button><span class="muted">Use 0 for no expiry.</span></div>
          </form>
        </div>
      </section>

      <section class="panel span-7">
        <div class="panel-head"><h2>Edit tenant</h2></div>
        <div class="panel-body">
          <form method="post" action="/admin/tenants" class="stack">
            <input type="hidden" name="tenant_id" value="{{.Tenant.ID}}">
            <div class="form-grid">
              <div class="full">
                <label>Issuer URL</label>
                <input name="issuer_url" value="{{.Tenant.IssuerURL}}" placeholder="https://sso.example.com" required>
              </div>
              <div class="full">
                <label>Allowed email domains</label>
                <textarea name="allowed_domains" placeholder="example.com
xyz.com
aaa.com" required>{{.Tenant.AllowedDomains}}</textarea>
              </div>
              <div>
                <label>Client ID</label>
                <input name="client_id" value="{{.Tenant.ClientID}}" placeholder="openai" required>
              </div>
              <div>
                <label>Client Secret</label>
                <input class="mono" name="client_secret" value="{{.Tenant.ClientSecret}}" required>
              </div>
              <div class="full">
                <label>Allowed redirect URIs</label>
                <textarea name="redirect_uris" placeholder="https://callback.example/from/openai">{{.Tenant.RedirectURIs}}</textarea>
              </div>
            </div>
            <div class="actions"><button type="submit">Save tenant</button></div>
          </form>
        </div>
      </section>

      <section class="panel span-5">
        <div class="panel-head"><h2>Add tenant</h2></div>
        <div class="panel-body">
          <form method="post" action="/admin/tenants" class="stack">
            <div>
              <label>Issuer URL</label>
              <input name="issuer_url" placeholder="https://sso.other-example.com" required>
            </div>
            <div>
              <label>Allowed email domains</label>
              <textarea name="allowed_domains" placeholder="example.com
xyz.com
aaa.com" required></textarea>
            </div>
            <div>
              <label>Client ID</label>
              <input name="client_id" value="openai" required>
            </div>
            <div>
              <label>Client Secret</label>
              <input class="mono" name="client_secret" placeholder="leave blank to generate">
            </div>
            <div>
              <label>Allowed redirect URIs</label>
              <textarea name="redirect_uris" placeholder="https://callback.example/from/openai"></textarea>
            </div>
            <div class="actions"><button type="submit">Add tenant</button></div>
          </form>
        </div>
      </section>

      <section class="panel span-5">
        <div class="panel-head"><h2>Admin password</h2></div>
        <div class="panel-body">
          <form method="post" action="/admin/password" class="stack">
            <input type="hidden" name="tenant_id" value="{{.Tenant.ID}}">
            <div>
              <label>New password</label>
              <input name="new_password" type="password" autocomplete="new-password" minlength="12" required>
            </div>
            <div>
              <label>Confirm password</label>
              <input name="confirm_password" type="password" autocomplete="new-password" minlength="12" required>
            </div>
            <div class="actions"><button type="submit">Update password</button></div>
          </form>
        </div>
      </section>

      <section class="panel span-12">
        <div class="panel-head"><h2>Keys</h2></div>
        <div class="panel-body">
          <table>
            <thead><tr><th>ID</th><th>Bound email</th><th>Created</th><th>Expires</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>
            {{range .Keys}}
            <tr>
              <td><code>{{.ID}}</code></td>
              <td>{{if .BoundEmail}}{{.BoundEmail}}{{else}}Any allowed domain{{end}}</td>
              <td>{{.CreatedAt}}</td>
              <td>{{.ExpiresAt}}</td>
              <td><span class="status">{{.Status}}</span></td>
              <td>
                {{if eq .Status "unused"}}
                <form method="post" action="/admin/revoke" class="actions">
                  <input type="hidden" name="tenant_id" value="{{$.Tenant.ID}}">
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
        </div>
      </section>
    </div>
  </main>
</div>
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
  <section class="login-card">
    <h1>Sign in</h1>
    <p>Use an allowed email domain and one-time key.</p>
    <pre style="margin:14px 0;">{{.AllowedDomains}}</pre>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <form method="post" action="/login" class="stack">
      <input type="hidden" name="response_type" value="{{.Auth.ResponseType}}">
      <input type="hidden" name="client_id" value="{{.Auth.ClientID}}">
      <input type="hidden" name="redirect_uri" value="{{.Auth.RedirectURI}}">
      <input type="hidden" name="scope" value="{{.Auth.Scope}}">
      <input type="hidden" name="state" value="{{.Auth.State}}">
      <input type="hidden" name="nonce" value="{{.Auth.Nonce}}">
      <div>
        <label>Email</label>
        <input name="email" type="email" autocomplete="username" required>
      </div>
      <div>
        <label>One-time key</label>
        <input name="key" type="password" autocomplete="one-time-code" required>
      </div>
      <div class="actions"><button type="submit">Continue</button></div>
    </form>
  </section>
</main>
</body>
</html>
{{end}}
`
