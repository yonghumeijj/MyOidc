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
.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 18px;
  border-bottom: 1px solid var(--line);
}
.tab-link {
  display: inline-flex;
  align-items: center;
  min-height: 42px;
  padding: 0 14px;
  color: var(--muted);
  text-decoration: none;
  border-bottom: 3px solid transparent;
  font-weight: 700;
}
.tab-link.active {
  color: var(--brand);
  border-bottom-color: var(--brand);
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
textarea.compact { min-height: 62px; }
input.compact, textarea.compact, select.compact {
  padding: 8px 9px;
  font-size: 13px;
}
input:focus, textarea:focus, select:focus {
  outline: 2px solid rgba(31,111,235,.20);
  border-color: var(--brand);
}
.form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}
.email-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 150px;
  gap: 8px;
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
.table-wrap {
  width: 100%;
  overflow-x: auto;
  border: 1px solid var(--line);
  border-radius: 8px;
}
.data-table {
  min-width: 1120px;
  background: #fff;
}
th, td {
  padding: 10px 8px;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
}
.data-table th {
  background: #f8fafc;
  color: #526071;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: .04em;
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
.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}
.batch-actions, .pager {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.toolbar select.compact {
  width: auto;
}
.page-link {
  display: inline-flex;
  min-width: 34px;
  height: 34px;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--line);
  border-radius: 7px;
  color: #344054;
  text-decoration: none;
  background: #fff;
}
.page-link.active {
  color: #fff;
  background: var(--brand);
  border-color: var(--brand);
}
.page-link.disabled {
  color: #98a2b3;
  pointer-events: none;
  background: #f8fafc;
}
.select-cell { width: 42px; text-align: center; }
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
  .form-grid, .email-row { grid-template-columns: 1fr; }
  .summary { grid-template-columns: 1fr; gap: 0; }
  .summary dt { padding-bottom: 0; }
}
`

const adminHTML = `
{{define "admin"}}
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>gooidc 管理后台</title>
  <style>` + pageCSS + `</style>
</head>
<body>
<div class="admin-shell">
  <aside class="sidebar">
    <div class="brand">
      <strong>gooidc</strong>
      <span>OIDC 服务</span>
    </div>

    <div class="tenant-list">
      <div class="side-label">租户</div>
      {{range .Tenants}}
      <a class="tenant-link {{if eq .ID $.Tenant.ID}}active{{end}}" href="/admin?tenant={{.ID}}&tab={{$.ActiveTab}}">{{.IssuerURL}}</a>
      {{end}}
    </div>

    <div class="foot">
      <div>管理员</div>
      <strong>{{.AdminUser}}</strong>
    </div>
  </aside>

  <main class="workspace">
    <div class="topbar">
      <div>
        <h1>OIDC 管理后台</h1>
        <p>{{.Tenant.IssuerURL}}</p>
      </div>
      <div class="pill">{{.Origin}}</div>
    </div>

    <nav class="tabs" aria-label="管理功能">
      <a class="tab-link {{if eq .ActiveTab "overview"}}active{{end}}" href="/admin?tenant={{.Tenant.ID}}&tab=overview">租户设置</a>
      <a class="tab-link {{if eq .ActiveTab "keys"}}active{{end}}" href="/admin?tenant={{.Tenant.ID}}&tab=keys">卡密管理</a>
    </nav>

    {{if .Notice}}<div class="notice">{{.Notice}}</div>{{end}}
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}

    {{if eq .ActiveTab "overview"}}
    <div class="grid">
      <section class="panel span-7">
        <div class="panel-head"><h2>租户概览</h2></div>
        <div class="panel-body">
          {{if .Tenant.ID}}
          <dl>
            <div class="summary"><dt>签发地址</dt><dd><span class="token">{{.Tenant.IssuerURL}}</span></dd></div>
            <div class="summary"><dt>Discovery</dt><dd><span class="token">{{.Tenant.IssuerURL}}/.well-known/openid-configuration</span></dd></div>
            <div class="summary"><dt>访问 Host</dt><dd><code>{{.Tenant.Host}}</code></dd></div>
            <div class="summary"><dt>允许邮箱域名</dt><dd><pre>{{.Tenant.AllowedDomains}}</pre></dd></div>
            <div class="summary"><dt>Client ID</dt><dd><code>{{.Tenant.ClientID}}</code></dd></div>
            <div class="summary"><dt>Client Secret</dt><dd><span class="token">{{.Tenant.ClientSecret}}</span></dd></div>
            <div class="summary"><dt>回调地址</dt><dd><pre>{{if .Tenant.RedirectURIs}}{{.Tenant.RedirectURIs}}{{else}}未配置，当前会接受任意 redirect_uri{{end}}</pre></dd></div>
          </dl>
          {{end}}
        </div>
      </section>

      <section class="panel span-5">
        <div class="panel-head"><h2>管理员密码</h2></div>
        <div class="panel-body">
          <form method="post" action="/admin/password" class="stack">
            <input type="hidden" name="tenant_id" value="{{.Tenant.ID}}">
            <div>
              <label>新密码</label>
              <input name="new_password" type="password" autocomplete="new-password" minlength="12" required>
            </div>
            <div>
              <label>确认密码</label>
              <input name="confirm_password" type="password" autocomplete="new-password" minlength="12" required>
            </div>
            <div class="actions"><button type="submit">更新密码</button></div>
          </form>
        </div>
      </section>

      <section class="panel span-7">
        <div class="panel-head"><h2>编辑租户</h2></div>
        <div class="panel-body">
          <form method="post" action="/admin/tenants" class="stack">
            <input type="hidden" name="tenant_id" value="{{.Tenant.ID}}">
            <div class="form-grid">
              <div class="full">
                <label>签发地址</label>
                <input name="issuer_url" value="{{.Tenant.IssuerURL}}" placeholder="https://sso.example.com" required>
              </div>
              <div class="full">
                <label>允许邮箱域名</label>
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
                <label>允许回调地址</label>
                <textarea name="redirect_uris" placeholder="https://callback.example/from/openai">{{.Tenant.RedirectURIs}}</textarea>
              </div>
            </div>
            <div class="actions"><button type="submit">保存租户</button></div>
          </form>
        </div>
      </section>

      <section class="panel span-5">
        <div class="panel-head"><h2>新增租户</h2></div>
        <div class="panel-body">
          <form method="post" action="/admin/tenants" class="stack">
            <div>
              <label>签发地址</label>
              <input name="issuer_url" placeholder="https://sso.other-example.com" required>
            </div>
            <div>
              <label>允许邮箱域名</label>
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
              <input class="mono" name="client_secret" placeholder="留空自动生成">
            </div>
            <div>
              <label>允许回调地址</label>
              <textarea name="redirect_uris" placeholder="https://callback.example/from/openai"></textarea>
            </div>
            <div class="actions"><button type="submit">新增租户</button></div>
          </form>
        </div>
      </section>
    </div>
    {{end}}

    {{if eq .ActiveTab "keys"}}
    <div class="grid">
      <section class="panel span-5">
        <div class="panel-head"><h2>批量生成卡密</h2></div>
        <div class="panel-body">
          <form method="post" action="/admin/keys" class="stack">
            <input type="hidden" name="tenant_id" value="{{.Tenant.ID}}">
            <div class="form-grid">
              <div>
                <label>数量</label>
                <input name="count" type="number" min="1" max="1000" value="10">
              </div>
              <div>
                <label>有效小时</label>
                <input name="expires_hours" type="number" min="0" value="168">
              </div>
              <div>
                <label>最大绑定邮箱数</label>
                <input name="max_uses" type="number" min="1" max="1000" value="1">
              </div>
              <div class="full">
                <label>指定邮箱</label>
                <textarea name="bound_emails" placeholder="user1@{{.Tenant.PrimaryAllowedDomain}}
user2@{{.Tenant.PrimaryAllowedDomain}}"></textarea>
              </div>
            </div>
            <div class="actions"><button type="submit">生成卡密</button></div>
          </form>
        </div>
      </section>

      <section class="panel span-7">
        <div class="panel-head"><h2>新增卡密</h2></div>
        <div class="panel-body">
          <form id="key-create" method="post" action="/admin/key/save" class="stack">
            <input type="hidden" name="tenant_id" value="{{.Tenant.ID}}">
            <div class="form-grid">
              <div class="full">
                <label>卡密</label>
                <input class="mono" name="key" placeholder="留空自动生成">
              </div>
              <div>
                <label>限定邮箱</label>
                <input name="bound_email" placeholder="可选">
              </div>
              <div>
                <label>最大绑定邮箱数</label>
                <input name="max_uses" type="number" min="1" max="1000" value="1">
              </div>
              <div>
                <label>过期时间</label>
                <input name="expires_at" type="datetime-local">
              </div>
            </div>
            <div class="actions"><button type="submit">新增卡密</button></div>
          </form>
        </div>
      </section>

      <section class="panel span-12">
        <div class="panel-head">
          <h2>卡密列表</h2>
          <span class="muted">第 {{.KeyPage.Start}}-{{.KeyPage.End}} 条 / 共 {{.KeyPage.Total}} 条</span>
        </div>
        <div class="panel-body">
          <div class="toolbar">
            <form id="key-batch" method="post" action="/admin/key/batch" class="batch-actions">
              <input type="hidden" name="tenant_id" value="{{.Tenant.ID}}">
              <button class="secondary" type="submit" name="action" value="revoke">批量禁用</button>
              <button class="danger" type="submit" name="action" value="delete" onclick="return confirm('删除选中的卡密？');">批量删除</button>
            </form>
            <form method="get" action="/admin" class="batch-actions">
              <input type="hidden" name="tenant" value="{{.Tenant.ID}}">
              <input type="hidden" name="tab" value="keys">
              <label style="margin:0;">每页</label>
              <select class="compact" name="page_size" onchange="this.form.submit()">
                <option value="10" {{if eq .KeyPage.PageSize 10}}selected{{end}}>10</option>
                <option value="20" {{if eq .KeyPage.PageSize 20}}selected{{end}}>20</option>
                <option value="50" {{if eq .KeyPage.PageSize 50}}selected{{end}}>50</option>
                <option value="100" {{if eq .KeyPage.PageSize 100}}selected{{end}}>100</option>
              </select>
            </form>
          </div>

          <div class="table-wrap">
            <table class="data-table">
              <thead>
                <tr>
                  <th class="select-cell"><input id="select-all-keys" type="checkbox" aria-label="全选"></th>
                  <th>卡密 ID</th>
                  <th>卡密</th>
                  <th>限定邮箱</th>
                  <th>已绑定用户</th>
                  <th>使用数</th>
                  <th>创建时间</th>
                  <th>过期时间</th>
                  <th>状态</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
              {{range .Keys}}
              <tr>
                <td class="select-cell"><input class="key-select" form="key-batch" type="checkbox" name="ids" value="{{.ID}}"></td>
                <td>
                  <code>{{.ID}}</code>
                  <input form="key-save-{{.ID}}" type="hidden" name="tenant_id" value="{{$.Tenant.ID}}">
                  <input form="key-save-{{.ID}}" type="hidden" name="id" value="{{.ID}}">
                </td>
                <td>
                  {{if .Key}}
                  <input form="key-save-{{.ID}}" class="mono compact" name="key" value="{{.Key}}">
                  {{else}}
                  <input form="key-save-{{.ID}}" class="mono compact" name="key" placeholder="历史卡密隐藏，输入新值可替换">
                  {{end}}
                </td>
                <td><input form="key-save-{{.ID}}" class="compact" name="bound_email" value="{{.BoundEmail}}" placeholder="不限"></td>
                <td>{{if .Bindings}}<textarea class="compact" readonly>{{.Bindings}}</textarea>{{else}}<span class="muted">无</span>{{end}}</td>
                <td><input form="key-save-{{.ID}}" class="compact" name="max_uses" type="number" min="1" max="1000" value="{{.MaxUses}}"><div class="muted">{{.UsedCount}} / {{.MaxUses}}</div></td>
                <td>{{.CreatedAt}}</td>
                <td><input form="key-save-{{.ID}}" class="compact" name="expires_at" type="datetime-local" value="{{.ExpiresInput}}"><div class="muted">{{.ExpiresAt}}</div></td>
                <td><span class="status">{{.Status}}</span></td>
                <td>
                  <div class="actions">
                    <form id="key-save-{{.ID}}" method="post" action="/admin/key/save"></form>
                    <button form="key-save-{{.ID}}" type="submit">保存</button>
                    {{if .Revoked}}
                    <form method="post" action="/admin/restore">
                      <input type="hidden" name="tenant_id" value="{{$.Tenant.ID}}">
                      <input type="hidden" name="id" value="{{.ID}}">
                      <button class="secondary" type="submit">恢复</button>
                    </form>
                    {{else}}
                    <form method="post" action="/admin/revoke">
                      <input type="hidden" name="tenant_id" value="{{$.Tenant.ID}}">
                      <input type="hidden" name="id" value="{{.ID}}">
                      <button class="secondary" type="submit">禁用</button>
                    </form>
                    {{end}}
                    <form method="post" action="/admin/key/delete" onsubmit="return confirm('删除这条卡密？');">
                      <input type="hidden" name="tenant_id" value="{{$.Tenant.ID}}">
                      <input type="hidden" name="id" value="{{.ID}}">
                      <button class="danger" type="submit">删除</button>
                    </form>
                  </div>
                </td>
              </tr>
              {{else}}
              <tr><td colspan="10" class="muted">暂无卡密。</td></tr>
              {{end}}
              </tbody>
            </table>
          </div>

          <div class="toolbar" style="margin-top:14px;margin-bottom:0;">
            <div class="muted">第 {{.KeyPage.Page}} / {{.KeyPage.TotalPages}} 页</div>
            <div class="pager">
              <a class="page-link {{if not .KeyPage.HasPrev}}disabled{{end}}" href="/admin?tenant={{.Tenant.ID}}&tab=keys&key_page={{.KeyPage.PrevPage}}&page_size={{.KeyPage.PageSize}}">上一页</a>
              {{range .KeyPage.Pages}}
              <a class="page-link {{if eq . $.KeyPage.Page}}active{{end}}" href="/admin?tenant={{$.Tenant.ID}}&tab=keys&key_page={{.}}&page_size={{$.KeyPage.PageSize}}">{{.}}</a>
              {{end}}
              <a class="page-link {{if not .KeyPage.HasNext}}disabled{{end}}" href="/admin?tenant={{.Tenant.ID}}&tab=keys&key_page={{.KeyPage.NextPage}}&page_size={{.KeyPage.PageSize}}">下一页</a>
            </div>
          </div>
        </div>
      </section>
    </div>
    {{end}}
  </main>
</div>
<script>
const selectAllKeys = document.getElementById('select-all-keys');
if (selectAllKeys) {
  selectAllKeys.addEventListener('change', () => {
    document.querySelectorAll('.key-select').forEach((item) => {
      item.checked = selectAllKeys.checked;
    });
  });
}
</script>
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
    <p>Use your email name and key.</p>
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
        <div class="email-row">
          <input name="email_local" autocomplete="username" placeholder="name" required>
          <select name="email_domain" aria-label="Email domain">
            {{range .AllowedDomainList}}
            <option value="{{.}}" {{if eq . $.PrimaryDomain}}selected{{end}}>@{{.}}</option>
            {{end}}
          </select>
        </div>
      </div>
      <div>
        <label>Login key</label>
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
