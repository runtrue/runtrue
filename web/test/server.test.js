import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import test from "node:test";
import { createRuntrueServer } from "../server.js";

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return server.address().port;
}

async function close(server) {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

test("serves the full backend-supported POC surface with a strict CSP", async (t) => {
  const backend = createServer((_request, response) => response.end());
  const backendPort = await listen(backend);
  const frontend = createRuntrueServer({ backendOrigin: `http://127.0.0.1:${backendPort}` });
  const frontendPort = await listen(frontend);
  t.after(() => Promise.all([close(frontend), close(backend)]));

  const response = await fetch(`http://127.0.0.1:${frontendPort}/ui/github/installations`);
  const html = await response.text();

  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-security-policy"), /script-src 'self'/);
  assert.match(response.headers.get("content-security-policy"), /img-src 'self'/);
  assert.doesNotMatch(response.headers.get("content-security-policy"), /github\.ibm\.com/);
  assert.match(html, /data-view="repositories"/);
  assert.match(html, /data-view="github"/);
  assert.match(html, /data-view="runs"/);
  assert.match(html, /data-view="approvals"/);
  assert.match(html, /data-view="repository"/);
  assert.match(html, /data-view="organization"/);
  assert.match(html, /data-view="runners"/);
  assert.match(html, /data-view="api-tokens"/);
  assert.match(html, /data-view="audit"/);
  assert.match(html, /id="boot-shell"[^>]*aria-busy="true"/);
  assert.match(html, /id="login-shell"[^>]*hidden/);
  assert.match(html, /id="run-detail-dialog"/);
  assert.match(html, /id="run-job-list"/);
  assert.match(html, /id="run-log-view"/);
  assert.match(html, /data-repository-section="secrets"/);
  assert.match(html, /data-repository-section="variables"/);
  assert.match(html, /data-repository-section="settings"/);
  assert.match(html, /id="organization-secrets-body"/);
  assert.match(html, /id="organization-variables-body"/);
  assert.match(html, /id="uninstall-repository-dialog"/);
  assert.match(html, /id="repository-setting-dialog"/);
  assert.match(html, /id="repository-workflow-directory"/);
  assert.match(html, /id="repository-workflow-directory-form"/);
  assert.match(html, /id="user-initials"/);
  assert.match(html, /id="delete-setting-dialog"/);
  assert.doesNotMatch(html, /id="tenant-name"/);
  assert.doesNotMatch(html, /class="settings-security-note"/);
  assert.doesNotMatch(html, /run_01/);
  assert.doesNotMatch(html, /apr_207/);
  assert.doesNotMatch(html, /<script(?! src=)/);
  assert.doesNotMatch(html, /<style/);

  const inlineIcons = [...html.matchAll(/<svg\b[^>]*>/g)].map((match) => match[0]);
  assert.ok(inlineIcons.length > 0, "the interface should include inline icons");
  for (const icon of inlineIcons) {
    assert.match(icon, /\bwidth="\d+"/, "inline SVGs need an intrinsic width before CSS loads");
    assert.match(icon, /\bheight="\d+"/, "inline SVGs need an intrinsic height before CSS loads");
  }

  const scriptResponse = await fetch(`http://127.0.0.1:${frontendPort}/assets/app.js`);
  assert.equal(scriptResponse.status, 200);
  assert.equal(scriptResponse.headers.get("cache-control"), "no-cache");

  const diagnosticResponse = await fetch(`http://127.0.0.1:${frontendPort}/frontend-client-error`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ detail: "TypeError: fixture" }),
  });
  assert.equal(diagnosticResponse.status, 204);
});

test("proxies backend cookies, redirects, and request bodies", async (t) => {
  const backend = createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => { body += chunk; });
    request.on("end", () => {
      response.writeHead(303, { location: "/ui/github/installations?github=linked", "set-cookie": ["runtrue_access=sealed; HttpOnly; Path=/", "runtrue_csrf=sealed; HttpOnly; Path=/"] });
      response.end(`${request.method}:${request.url}:${body}`);
    });
  });
  const backendPort = await listen(backend);
  const frontend = createRuntrueServer({ backendOrigin: `http://127.0.0.1:${backendPort}` });
  const frontendPort = await listen(frontend);
  t.after(() => Promise.all([close(frontend), close(backend)]));

  const response = await fetch(`http://127.0.0.1:${frontendPort}/ui/github/repositories/link`, {
    method: "POST",
    body: "csrf_token=proof",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    redirect: "manual",
  });

  assert.equal(response.status, 303);
  assert.equal(response.headers.get("location"), "/ui/github/installations?github=linked");
  assert.deepEqual(response.headers.getSetCookie(), ["runtrue_access=sealed; HttpOnly; Path=/", "runtrue_csrf=sealed; HttpOnly; Path=/"]);
  assert.equal(await response.text(), "POST:/ui/github/repositories/link:csrf_token=proof");
});

test("browser script references existing unique controls", async () => {
  const [html, script] = await Promise.all([
    readFile(new URL("../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/app.js", import.meta.url), "utf8"),
  ]);
  const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]);
  const referenced = [...script.matchAll(/byId\("([^"]+)"\)/g)].map((match) => match[1]);

  assert.equal(new Set(ids).size, ids.length, "HTML ids must be unique");
  for (const id of new Set(referenced)) assert.ok(ids.includes(id), `missing #${id}`);
  assert.match(script, /\/api\/v1\/ui\/runs\//);
  assert.match(script, /function renderRunLogs\(\)/);
  assert.match(script, /\/api\/v1\/ui\/repositories\//);
  assert.match(script, /function loadRepositorySettings/);
  assert.match(script, /function loadOrganizationSettings/);
  assert.match(script, /function saveRepositorySetting/);
  assert.match(script, /function saveRepositoryWorkflowDirectory/);
  assert.match(script, /\/workflow-directory/);
  assert.doesNotMatch(script, /session\.avatarUrl/);
  assert.match(script, /function deleteRepositorySetting/);
  assert.match(script, /data-delete-setting/);
  assert.match(script, /function uninstallRepository/);
  assert.match(script, /byId\("boot-shell"\)\.hidden = true/);
  assert.match(script, /\/uninstall/);
  assert.match(script, /kind === "secret" \? "secrets" : "variables"/);
  assert.match(script, /\/api\/v1\/ui\/organization\/settings/);
  assert.doesNotMatch(script, /encrypted at rest and only exposed/);
  assert.match(script, /You cannot view this value after saving/);
});

test("login uses a compact centered card", async () => {
  const [html, styles] = await Promise.all([
    readFile(new URL("../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/styles.css", import.meta.url), "utf8"),
  ]);

  assert.match(styles, /\.login-shell\s*\{[^}]*place-items:\s*center/s);
  assert.match(styles, /\.auth-card\s*\{[^}]*420px/s);
  assert.doesNotMatch(styles, /\.auth-card\s*\{[^}]*min-height/s);
  assert.doesNotMatch(html, /class="trust-note"/);
  assert.doesNotMatch(html, /class="login-footer"/);
});

test("add repositories opens the local picker without starting GitHub installation", async () => {
  const script = await readFile(new URL("../public/app.js", import.meta.url), "utf8");
  const openDialog = script.match(/function openAddDialog\(\) \{([\s\S]*?)\n  \}/)?.[1] || "";

  assert.match(openDialog, /add-repo-dialog/);
  assert.match(openDialog, /showModal\(\)/);
  assert.match(openDialog, /loadOrganizations\(\)/);
  assert.match(openDialog, /status: "loading"/);
  assert.match(script, /\/api\/v1\/ui\/github\?catalog=true/);
  assert.match(script, /catalog=true&organization=/);
  assert.match(script, /cache: "no-store"/);
  assert.doesNotMatch(script, /sessionStorage/);
  assert.doesNotMatch(script, /status: "cached"/);
  assert.match(script, /dialog-manage-github.*submitInstallAction/);
  assert.doesNotMatch(openDialog, /submitInstallAction/);
});

test("repository picker uses signed-in GitHub visibility and exposes app installation gaps", async () => {
  const [html, script] = await Promise.all([
    readFile(new URL("../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/app.js", import.meta.url), "utf8"),
  ]);

  assert.match(html, /Select an organization, then choose repositories to add/);
  assert.match(html, /id="dialog-refresh-github"/);
  assert.match(html, /Reload GitHub data/);
  assert.match(script, /repository\.state === "added"/);
  assert.match(script, /repository\.state === "needs_installation"/);
  assert.match(script, /repository\.state === "existing_installation"/);
  assert.match(script, /"Import selected"/);
  assert.match(script, /"Install selected"/);
  assert.match(script, /fields\.repository_ids/);
  assert.match(script, /function confirmSelectedRepositories\(\)/);
  assert.match(script, /Update GitHub App access/);
  assert.match(script, /function refreshGitHubAccess\(\)/);
  assert.match(script, /function reloadGitHubData\(\)/);
  assert.match(script, /function loadOrganizationRepositories\(organizationId\)/);
});

test("audit events expose search and structured filters", async () => {
  const [html, script] = await Promise.all([
    readFile(new URL("../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../public/app.js", import.meta.url), "utf8"),
  ]);

  assert.match(html, /id="audit-search"/);
  assert.match(html, /id="audit-action-filter"/);
  assert.match(html, /id="audit-result-filter"/);
  assert.match(script, /function configureAuditFilters\(\)/);
  assert.match(script, /action === "all" \|\| event\.action === action/);
  assert.match(script, /result === "all" \|\| event\.result === result/);
});
