(() => {
  "use strict";

  const state = {
    data: null,
    repositorySource: "all",
    activeRepository: null,
    activeOrganization: null,
    organizationRequestId: 0,
    repositoryRequestId: 0,
    approvalFilter: "all",
    activeApprovalId: null,
    selectedRepositories: new Map(),
    activeRunId: null,
    activeRunDetails: null,
    repositorySettings: null,
    repositorySettingsLoading: false,
    organizationSettings: null,
    organizationSettingsLoading: false,
    settingScope: null,
    settingKind: null,
    pendingSettingDelete: null,
    repositoryUninstalling: false,
    toastTimer: null,
  };

  const byId = (id) => document.getElementById(id);
  const escapeHtml = (value) => String(value ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;").replaceAll("'", "&#39;");
  const titleCase = (value) => String(value ?? "Unknown").replaceAll(/[-_]/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  const formatDate = (value) => value ? new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)) : "Not recorded";
  const formatLogTime = (value) => value ? new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit", second: "2-digit" }).format(new Date(value)) : "—";
  const compactId = (value, bodyLength = 8) => {
    const id = String(value || "");
    const separator = id.indexOf("-");
    const prefix = separator > 0 ? `${id.slice(0, separator)}-` : "";
    const body = separator > 0 ? id.slice(separator + 1) : id;
    return body.length > bodyLength ? `${prefix}${body.slice(0, bodyLength)}…` : id;
  };
  const formatDuration = (startedAt, completedAt) => {
    if (!startedAt) return "Not started";
    const end = completedAt ? new Date(completedAt).getTime() : Date.now();
    const elapsed = Math.max(0, end - new Date(startedAt).getTime());
    if (elapsed < 1000) return "Less than a second";
    if (elapsed < 60_000) return `${Math.round(elapsed / 1000)} sec`;
    if (elapsed < 3_600_000) return `${Math.floor(elapsed / 60_000)} min ${Math.round((elapsed % 60_000) / 1000)} sec`;
    return `${Math.floor(elapsed / 3_600_000)} hr ${Math.round((elapsed % 3_600_000) / 60_000)} min`;
  };
  const formatBytes = (value) => {
    const bytes = Number(value || 0);
    if (bytes < 1024 ** 2) return `${Math.round(bytes / 1024)} KB`;
    if (bytes < 1024 ** 3) return `${Math.round(bytes / 1024 ** 2)} MB`;
    return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
  };

  function initials(name) {
    const parts = String(name || "User").split(/[^\p{L}\p{N}]+/u).filter(Boolean);
    return (parts.slice(0, 2).map((part) => part[0]).join("") || "U").toUpperCase();
  }

  function tone(value) {
    const normalized = String(value || "").toLowerCase();
    if (["ready", "active", "online", "succeeded", "approved", "consumed", "good", "success"].includes(normalized)) return "success";
    if (["failed", "canceled", "timed_out", "lost", "rejected", "error"].includes(normalized)) return "danger";
    if (["running", "queued", "offered"].includes(normalized)) return "running";
    if (["pending", "degraded", "missing", "warning", "awaiting event", "needs selection", "draining"].includes(normalized)) return "warning";
    return "neutral";
  }

  function showToast(message) {
    const toast = byId("toast");
    toast.textContent = message;
    toast.hidden = false;
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => { toast.hidden = true; }, 4200);
  }

  function showLogin(message = "") {
    byId("boot-shell").hidden = true;
    byId("login-shell").hidden = false;
    byId("workspace").hidden = true;
    if (message) document.querySelector(".auth-view .muted-copy").textContent = message;
  }

  function applyCapabilities() {
    const capabilities = state.data.capabilities || {};
    document.querySelectorAll("[data-capability]").forEach((element) => {
      element.hidden = !capabilities[element.dataset.capability];
    });
  }

  function showWorkspace() {
    const { session } = state.data;
    byId("boot-shell").hidden = true;
    byId("login-shell").hidden = true;
    byId("workspace").hidden = false;
    byId("user-name").textContent = session.principalName;
    byId("menu-user-name").textContent = session.principalName;
    byId("menu-tenant-name").textContent = session.tenantName;
    byId("organization-page-title").textContent = session.tenantName;
    byId("user-initials").textContent = initials(session.principalName);
    byId("user-initials").hidden = false;
    applyCapabilities();
  }

  function renderRepositories() {
    const query = byId("catalog-search").value.trim().toLowerCase();
    const repositories = state.data.repositories.filter((repository) => {
      const matchesSearch = `${repository.organization}/${repository.name}`.toLowerCase().includes(query);
      const matchesSource = state.repositorySource === "all" || repository.source === state.repositorySource;
      return matchesSearch && matchesSource;
    });
    byId("sidebar-repo-count").textContent = state.data.repositories.length;
    byId("visible-count").textContent = repositories.length;
    byId("total-count").textContent = `${state.data.repositories.length} total`;

    if (!repositories.length) {
      const empty = state.data.repositories.length
        ? ["No repositories match", "Adjust the search or source filter."]
        : ["No repositories yet", "Add repositories from a GitHub organization to begin."];
      byId("catalog-content").innerHTML = `<div class="catalog-empty"><div><div class="empty-icon" aria-hidden="true">+</div><h3>${empty[0]}</h3><p>${empty[1]}</p></div></div>`;
      return;
    }
    const rows = repositories.map((repository) => `<tr><td><button class="repo-link" type="button" data-open-repository="${escapeHtml(repository.id)}"><span class="repo-glyph" aria-hidden="true">R</span><span><strong>${escapeHtml(repository.organization)}/${escapeHtml(repository.name)}</strong><small>${escapeHtml(repository.visibility)} · ${escapeHtml(repository.defaultBranch)}</small></span></button></td><td>${escapeHtml(repository.source)}</td><td><span class="status-badge">${escapeHtml(repository.state)}</span></td></tr>`).join("");
    byId("catalog-content").innerHTML = `<div class="table-wrap"><table class="repo-table"><thead><tr><th>Repository</th><th>Source</th><th>State</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function renderAlert() {
    const alert = state.data.github.alert;
    const target = byId("page-alert");
    if (!alert) return void (target.hidden = true);
    target.innerHTML = `<div><strong>${escapeHtml(alert.title)}</strong><p>${escapeHtml(alert.detail)}</p></div>`;
    target.hidden = false;
  }

  function renderRuns() {
    const runs = state.data.runs || [];
    const search = byId("run-search").value.trim().toLowerCase();
    const status = byId("run-status-filter").value;
    const visible = runs.filter((run) => {
      const matchesSearch = `${run.id} ${run.planId} ${run.repository}`.toLowerCase().includes(search);
      return matchesSearch && (status === "all" || String(run.status) === status);
    });
    byId("sidebar-run-count").textContent = runs.length;
    byId("run-visible-count").textContent = visible.length;
    byId("run-total-count").textContent = `${runs.length} total`;
    const tbody = byId("runs-body");
    tbody.innerHTML = visible.map((run) => `<tr><td><strong class="mono run-id" title="${escapeHtml(run.id)}">${escapeHtml(compactId(run.id))}</strong><small class="mono" title="${escapeHtml(run.planId)}">Capsule ${escapeHtml(compactId(run.planId))}</small></td><td><strong class="table-primary">${escapeHtml(run.repository)}</strong></td><td><span class="state-badge ${tone(run.status)}">${escapeHtml(titleCase(run.status))}</span></td><td class="date-cell">${escapeHtml(formatDate(run.createdAt))}</td><td><button class="text-button run-open-button" type="button" data-open-run="${escapeHtml(run.id)}">Details <span aria-hidden="true">→</span></button></td></tr>`).join("");
    byId("runs-empty").hidden = visible.length > 0;
    tbody.closest("table").hidden = visible.length === 0;
  }

  function configureRunFilters() {
    const select = byId("run-status-filter");
    const statuses = [...new Set((state.data.runs || []).map((run) => String(run.status)))].sort();
    select.innerHTML = `<option value="all">All statuses</option>${statuses.map((status) => `<option value="${escapeHtml(status)}">${escapeHtml(titleCase(status))}</option>`).join("")}`;
  }

  function renderApprovals() {
    const approvals = state.data.approvals || [];
    const visible = approvals.filter((approval) => state.approvalFilter === "all" || (state.approvalFilter === "pending" ? approval.status === "pending" : approval.status !== "pending"));
    const pending = approvals.filter((approval) => approval.status === "pending").length;
    byId("sidebar-approval-count").textContent = pending;
    byId("approval-count-copy").textContent = `${pending} pending · ${approvals.length} total`;
    byId("approval-list").innerHTML = visible.map((approval) => `<article class="approval-row"><div class="approval-main"><span class="state-badge ${tone(approval.status)}">${escapeHtml(titleCase(approval.status))}</span><h3>${escapeHtml(titleCase(approval.kind))}</h3><p><span class="mono">${escapeHtml(approval.id)}</span> · Rule ${escapeHtml(approval.ruleId)}</p><ul class="approval-signals"><li>${escapeHtml(approval.requiredApprovals)} required</li><li>${escapeHtml(approval.decisionCount)} decisions</li><li>Expires ${escapeHtml(formatDate(approval.expiresAt))}</li></ul></div><div class="risk-score ${approval.riskScore >= 70 ? "high" : ""}"><span>Risk</span><strong>${escapeHtml(approval.riskScore)}</strong></div><button class="btn btn-secondary btn-inline" type="button" data-open-approval="${escapeHtml(approval.id)}">Review</button></article>`).join("");
    byId("approvals-empty").hidden = visible.length > 0;
  }

  function renderGitHub() {
    const github = state.data.github;
    const overall = byId("github-overall");
    overall.className = `state-badge ${tone(github.overall)}`;
    overall.textContent = github.overall;
    const labels = { app: "GitHub App", signer: "Non-exportable signer", webhook: "Webhook verification", callback: "Setup callback" };
    byId("github-health").innerHTML = Object.entries(github.health).map(([key, value]) => `<article class="health-card"><span>${escapeHtml(labels[key] || key)}</span><strong class="state-badge ${tone(value)}">${escapeHtml(value)}</strong></article>`).join("");
    const metadata = [["Provider", github.metadata.providerHost], ["App slug", github.metadata.appSlug || "Not configured"], ["App ID", github.metadata.appId ?? "Not configured"]];
    byId("github-metadata").innerHTML = metadata.map(([label, value]) => definitionCard(label, value)).join("");
    byId("installation-count").textContent = `${github.installations.length} total`;
    byId("installation-content").innerHTML = github.installations.length ? `<table class="data-table"><thead><tr><th>Account</th><th>Installation</th><th>Repository access</th><th>Permissions</th><th>State</th></tr></thead><tbody>${github.installations.map((installation) => `<tr><td><strong>${escapeHtml(installation.accountLogin)}</strong><small>${escapeHtml(installation.accountKind)}</small></td><td>${escapeHtml(installation.installationId)}</td><td>${escapeHtml(installation.repositorySelection)}</td><td><span class="scope-list">${installation.permissions.map((permission) => `<span class="scope-chip">${escapeHtml(permission)}</span>`).join("") || "None"}</span></td><td><span class="state-badge ${tone(installation.state)}">${escapeHtml(installation.state)}</span></td></tr>`).join("")}</tbody></table>` : emptyInline("No installations yet", "Install the GitHub App to connect an account.");
    byId("event-count").textContent = `${github.events.length} recent`;
    byId("event-content").innerHTML = github.events.length ? github.events.map((event) => `<article><span class="event-mark" aria-hidden="true">GH</span><div><strong>${escapeHtml(event.repository)}</strong><p>${escapeHtml(event.providerEventName)} · ${escapeHtml(event.eventKind)}${event.refName ? ` · ${escapeHtml(event.refName)}` : ""} · @${escapeHtml(event.actorLogin)}</p></div><time datetime="${escapeHtml(event.receivedAt)}">${escapeHtml(formatDate(event.receivedAt))}</time></article>`).join("") : emptyInline("No webhook events", "");
    byId("manage-github").disabled = !state.data.installAction;
  }

  function renderRunners() {
    const runners = state.data.runners?.items || [];
    const online = runners.filter((runner) => runner.status === "online").length;
    byId("runner-online-count").textContent = online;
    byId("runner-total-count").textContent = `${runners.length} total`;
    byId("runners-body").innerHTML = runners.map((runner) => `<tr><td><strong class="mono">${escapeHtml(runner.id)}</strong><small>${escapeHtml(runner.region || "No region")}${runner.ephemeral ? " · Auto-remove" : ""}</small></td><td>${escapeHtml(runner.pool)}</td><td>${escapeHtml(titleCase(runner.os))} / ${escapeHtml(titleCase(runner.arch))}</td><td>${escapeHtml(runner.logicalCpus)} CPU · ${escapeHtml(formatBytes(runner.memoryBytes))}</td><td>${escapeHtml(runner.activeJobs)}</td><td><span class="state-badge ${tone(runner.status)}">${escapeHtml(titleCase(runner.status))}</span></td><td>${escapeHtml(formatDate(runner.lastHeartbeatAt))}</td></tr>`).join("");
    byId("runners-empty").hidden = runners.length > 0;
    byId("runners-body").closest("table").hidden = runners.length === 0;
  }

  function renderTokens() {
    const tokens = state.data.apiTokens || [];
    byId("token-count-copy").textContent = `${tokens.length} issued tokens`;
    byId("token-list").innerHTML = tokens.map((token) => {
      const status = token.revokedAt ? "Revoked" : new Date(token.expiresAt) < new Date() ? "Expired" : "Active";
      return `<button class="token-item" type="button" data-open-token="${escapeHtml(token.id)}"><span class="token-item-main"><strong>${escapeHtml(token.name)}</strong><small class="mono">${escapeHtml(token.principalId)}</small></span><span class="token-item-access"><small>Access</small><strong>${escapeHtml(token.scopes.length)} scopes</strong></span><span class="token-item-expiry"><small>Expires</small><strong>${escapeHtml(formatDate(token.expiresAt))}</strong></span><span class="token-item-trailing"><span class="state-badge ${tone(status)}">${status}</span></span></button>`;
    }).join("");
    byId("tokens-empty").hidden = tokens.length > 0;
    byId("token-list").hidden = tokens.length === 0;
  }

  function renderAudit() {
    const events = state.data.audit || [];
    const query = byId("audit-search").value.trim().toLowerCase();
    const action = byId("audit-action-filter").value;
    const result = byId("audit-result-filter").value;
    const visible = events.filter((event) => {
      const matchesSearch = `${event.action} ${event.actor.kind} ${event.actor.id} ${event.resource.kind} ${event.resource.id} ${event.result}`.toLowerCase().includes(query);
      return matchesSearch && (action === "all" || event.action === action) && (result === "all" || event.result === result);
    });
    const filtered = query.length > 0 || action !== "all" || result !== "all";
    byId("audit-count").textContent = visible.length;
    byId("audit-count-suffix").textContent = filtered ? ` of ${events.length} latest events` : " latest events";
    byId("audit-list").innerHTML = visible.map((event) => `<article><span class="event-mark" aria-hidden="true">${escapeHtml(event.sequence)}</span><div><strong>${escapeHtml(event.action)}</strong><p>${escapeHtml(event.actor.kind)}/${escapeHtml(event.actor.id)} · ${escapeHtml(event.resource.kind)}/${escapeHtml(event.resource.id)} · ${escapeHtml(event.result)}</p></div><time datetime="${escapeHtml(event.observedAt)}">${escapeHtml(formatDate(event.observedAt))}</time></article>`).join("");
    byId("audit-empty").hidden = visible.length > 0;
    byId("audit-list").hidden = visible.length === 0;
  }

  function configureAuditFilters() {
    const events = state.data.audit || [];
    const actions = [...new Set(events.map((event) => String(event.action)))].sort();
    const results = [...new Set(events.map((event) => String(event.result)))].sort();
    byId("audit-action-filter").innerHTML = `<option value="all">All actions</option>${actions.map((action) => `<option value="${escapeHtml(action)}">${escapeHtml(action)}</option>`).join("")}`;
    byId("audit-result-filter").innerHTML = `<option value="all">All results</option>${results.map((result) => `<option value="${escapeHtml(result)}">${escapeHtml(titleCase(result))}</option>`).join("")}`;
  }

  function openRepository(id) {
    const repository = state.data.repositories.find((item) => String(item.id) === String(id));
    if (!repository) return;
    state.activeRepository = repository;
    state.repositorySettings = null;
    renderRepositorySettings();
    const runs = (state.data.runs || []).filter((run) => run.repositoryId === repository.id);
    byId("repository-page-title").textContent = repository.key;
    const providerLink = byId("repository-provider-link");
    providerLink.hidden = !repository.repositoryUrl;
    if (repository.repositoryUrl) {
      providerLink.href = repository.repositoryUrl;
      providerLink.setAttribute("aria-label", `View ${repository.key} on GitHub`);
    } else {
      providerLink.removeAttribute("href");
      providerLink.removeAttribute("aria-label");
    }
    byId("repository-state").textContent = repository.state;
    byId("repository-state").className = `state-badge ${tone(repository.state)}`;
    byId("repository-detail-summary").innerHTML = [["Source", repository.source], ["Visibility", repository.visibility], ["Default branch", repository.defaultBranch], ["Installation", repository.installationAccount]].map(([label, value]) => definitionCard(label, value)).join("");
    byId("repository-connection-state").textContent = repository.state;
    byId("repository-connection-state").className = `state-badge ${tone(repository.state)}`;
    byId("repository-connection-metadata").innerHTML = definitionLinkCard("GitHub repository", repository.key, repository.repositoryUrl) + definitionCard("External ID", repository.externalId);
    byId("repository-execution-metadata").innerHTML = definitionCard("Runs", runs.length) + definitionCard("Latest activity", runs[0] ? formatDate(runs[0].createdAt) : "No runs yet");
    byId("repository-uninstall-name").textContent = repository.key;
    renderRepositoryRuns(runs);
    setRepositorySection("overview");
    switchView("repository");
  }

  function renderRepositoryRuns(runs) {
    byId("repository-runs-body").innerHTML = runs.map((run) => `<tr><td><strong class="mono run-id" title="${escapeHtml(run.id)}">${escapeHtml(compactId(run.id))}</strong><small class="mono" title="${escapeHtml(run.planId)}">Capsule ${escapeHtml(compactId(run.planId))}</small></td><td><span class="state-badge ${tone(run.status)}">${escapeHtml(titleCase(run.status))}</span></td><td class="date-cell">${escapeHtml(formatDate(run.createdAt))}</td><td><button class="text-button run-open-button" type="button" data-open-run="${escapeHtml(run.id)}">Details <span aria-hidden="true">→</span></button></td></tr>`).join("");
    byId("repository-runs-empty").hidden = runs.length > 0;
    byId("repository-runs-body").closest("table").hidden = runs.length === 0;
  }

  function setRepositorySection(section) {
    document.querySelectorAll("[data-repository-panel]").forEach((panel) => { panel.hidden = panel.dataset.repositoryPanel !== section; });
    document.querySelectorAll("[data-repository-section]").forEach((button) => {
      const active = button.dataset.repositorySection === section;
      button.classList.toggle("active", active);
      if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
    });
    if (["secrets", "variables", "settings"].includes(section)) loadRepositorySettings();
  }

  function renderRepositorySettings() {
    const settings = state.repositorySettings || { secrets: [], variables: [] };
    const secrets = settings.secrets.filter((secret) => secret.status !== "tombstoned");
    byId("repository-secrets-body").innerHTML = secrets.map((secret) => `<tr><td><strong class="mono setting-name">${escapeHtml(secret.name)}</strong><small>${escapeHtml(titleCase(secret.secret_type || "opaque"))} · ${escapeHtml(secret.provider || "built-in")}</small></td><td><span class="state-badge ${tone(secret.status)}">${escapeHtml(titleCase(secret.status))}</span></td><td class="setting-version">${escapeHtml(secret.current_version ?? "External")}</td><td class="setting-updated">${escapeHtml(formatDate(secret.updated_unix_ms))}</td><td><div class="setting-actions"><button class="setting-action" type="button" data-setting-scope="repository" data-edit-secret="${escapeHtml(secret.name)}">Update</button><button class="setting-action danger-text" type="button" data-setting-scope="repository" data-delete-setting="secret" data-setting-name="${escapeHtml(secret.name)}">Delete</button></div></td></tr>`).join("");
    byId("repository-secrets-empty").hidden = secrets.length > 0;
    byId("repository-secrets-body").closest("table").hidden = secrets.length === 0;
    byId("repository-variables-body").innerHTML = settings.variables.map((variable) => { const value = typeof variable.value === "string" ? variable.value : JSON.stringify(variable.value); return `<tr><td><strong class="mono setting-name">${escapeHtml(variable.name)}</strong></td><td class="setting-value"><code title="${escapeHtml(value)}">${escapeHtml(value)}</code></td><td class="setting-version">${escapeHtml(variable.version)}</td><td class="setting-updated">${escapeHtml(formatDate(variable.updated_unix_ms))}</td><td><div class="setting-actions"><button class="setting-action" type="button" data-setting-scope="repository" data-edit-variable="${escapeHtml(variable.name)}">Edit</button><button class="setting-action danger-text" type="button" data-setting-scope="repository" data-delete-setting="variable" data-setting-name="${escapeHtml(variable.name)}">Delete</button></div></td></tr>`; }).join("");
    byId("repository-variables-empty").hidden = settings.variables.length > 0;
    byId("repository-variables-body").closest("table").hidden = settings.variables.length === 0;
    byId("repository-workflow-directory").value = settings.workflow_directory || "";
    byId("repository-workflow-directory-help").textContent = state.repositorySettings
      ? settings.workflow_directory_inherited
        ? "Using the server default. Saving creates an override for this repository."
        : "This repository overrides the server default."
      : "Loading workflow location…";
    byId("save-repository-workflow-directory").disabled = !state.repositorySettings;
  }

  function renderOrganizationSettings() {
    const settings = state.organizationSettings || { secrets: [], variables: [] };
    const secrets = settings.secrets.filter((secret) => secret.status !== "tombstoned");
    byId("organization-secrets-body").innerHTML = secrets.map((secret) => `<tr><td><strong class="mono setting-name">${escapeHtml(secret.name)}</strong><small>${escapeHtml(titleCase(secret.secret_type || "opaque"))} · ${escapeHtml(secret.provider || "built-in")}</small></td><td><span class="state-badge ${tone(secret.status)}">${escapeHtml(titleCase(secret.status))}</span></td><td class="setting-version">${escapeHtml(secret.current_version ?? "External")}</td><td class="setting-updated">${escapeHtml(formatDate(secret.updated_unix_ms))}</td><td><div class="setting-actions"><button class="setting-action" type="button" data-setting-scope="organization" data-edit-secret="${escapeHtml(secret.name)}">Update</button><button class="setting-action danger-text" type="button" data-setting-scope="organization" data-delete-setting="secret" data-setting-name="${escapeHtml(secret.name)}">Delete</button></div></td></tr>`).join("");
    byId("organization-secrets-empty").hidden = secrets.length > 0;
    byId("organization-secrets-body").closest("table").hidden = secrets.length === 0;
    byId("organization-variables-body").innerHTML = settings.variables.map((variable) => { const value = typeof variable.value === "string" ? variable.value : JSON.stringify(variable.value); return `<tr><td><strong class="mono setting-name">${escapeHtml(variable.name)}</strong></td><td class="setting-value"><code title="${escapeHtml(value)}">${escapeHtml(value)}</code></td><td class="setting-version">${escapeHtml(variable.version)}</td><td class="setting-updated">${escapeHtml(formatDate(variable.updated_unix_ms))}</td><td><div class="setting-actions"><button class="setting-action" type="button" data-setting-scope="organization" data-edit-variable="${escapeHtml(variable.name)}">Edit</button><button class="setting-action danger-text" type="button" data-setting-scope="organization" data-delete-setting="variable" data-setting-name="${escapeHtml(variable.name)}">Delete</button></div></td></tr>`; }).join("");
    byId("organization-variables-empty").hidden = settings.variables.length > 0;
    byId("organization-variables-body").closest("table").hidden = settings.variables.length === 0;
  }

  async function loadOrganizationSettings(force = false) {
    if (state.organizationSettingsLoading || (state.organizationSettings && !force)) return;
    state.organizationSettingsLoading = true;
    try {
      const response = await fetch("/api/v1/ui/organization/settings", { credentials: "same-origin", headers: { accept: "application/json" } });
      if (!response.ok) throw new Error(response.status === 403 ? "You do not have access to these settings." : "Could not load organization settings.");
      state.organizationSettings = await response.json();
      renderOrganizationSettings();
    } catch (error) { showToast(error.message || "Could not load organization settings."); }
    finally { state.organizationSettingsLoading = false; }
  }

  async function loadRepositorySettings(force = false) {
    if (!state.activeRepository || state.repositorySettingsLoading || (state.repositorySettings && !force)) return;
    state.repositorySettingsLoading = true;
    try {
      const response = await fetch(`/api/v1/ui/repositories/${encodeURIComponent(state.activeRepository.id)}/settings`, { credentials: "same-origin", headers: { accept: "application/json" } });
      if (!response.ok) throw new Error(response.status === 403 ? "You do not have access to these settings." : "Could not load repository settings.");
      state.repositorySettings = await response.json();
      renderRepositorySettings();
    } catch (error) { showToast(error.message || "Could not load repository settings."); }
    finally { state.repositorySettingsLoading = false; }
  }

  async function saveRepositoryWorkflowDirectory(event) {
    event.preventDefault();
    if (!state.activeRepository) return;
    const input = byId("repository-workflow-directory");
    const button = byId("save-repository-workflow-directory");
    const workflowDirectory = input.value.trim();
    if (!workflowDirectory) return input.reportValidity();
    button.disabled = true; button.textContent = "Saving…";
    try {
      const body = new URLSearchParams({ csrf_token: state.data.session.csrfToken, workflow_directory: workflowDirectory });
      const response = await fetch(`/api/v1/ui/repositories/${encodeURIComponent(state.activeRepository.id)}/workflow-directory`, { method: "POST", body, credentials: "same-origin" });
      if (!response.ok) { const problem = await response.json().catch(() => null); throw new Error(problem?.detail || "Could not save the workflow location."); }
      state.repositorySettings = null;
      await loadRepositorySettings(true);
      showToast("Workflow location saved.");
    } catch (error) { showToast(error.message || "The workflow location could not be saved."); }
    finally { button.disabled = false; button.textContent = "Save location"; }
  }

  function openUninstallRepository() {
    if (!state.activeRepository) return;
    byId("uninstall-repository-name").textContent = state.activeRepository.key;
    byId("uninstall-repository-dialog").showModal();
    byId("confirm-uninstall-repository").focus();
  }

  async function uninstallRepository() {
    if (!state.activeRepository || state.repositoryUninstalling) return;
    const repository = state.activeRepository;
    const button = byId("confirm-uninstall-repository");
    state.repositoryUninstalling = true;
    button.disabled = true;
    button.textContent = "Disconnecting…";
    try {
      const body = new URLSearchParams({ csrf_token: state.data.session.csrfToken, repository: repository.key });
      const response = await fetch(`/api/v1/ui/repositories/${encodeURIComponent(repository.id)}/uninstall`, { method: "POST", body, credentials: "same-origin" });
      if (!response.ok) { const problem = await response.json().catch(() => null); throw new Error(problem?.detail || "Could not disconnect repository."); }
      byId("uninstall-repository-dialog").close();
      state.data.repositories = state.data.repositories.filter((item) => item.id !== repository.id);
      state.activeRepository = null;
      renderRepositories();
      switchView("repositories");
      showToast(`${repository.key} disconnected.`);
    } catch (error) { showToast(error.message || "Could not disconnect repository."); }
    finally { state.repositoryUninstalling = false; button.disabled = false; button.textContent = "Disconnect"; }
  }

  function openRepositorySetting(kind, name = "") {
    openSetting("repository", kind, name);
  }

  function openOrganizationSetting(kind, name = "") {
    openSetting("organization", kind, name);
  }

  function openSetting(scope, kind, name = "") {
    const isSecret = kind === "secret";
    const existing = name !== "";
    state.settingScope = scope;
    state.settingKind = kind;
    byId("repository-setting-kicker").textContent = `${titleCase(scope)} ${kind}`;
    byId("repository-setting-title").textContent = `${existing ? "Update" : "Add"} ${kind}`;
    byId("repository-setting-copy").textContent = scope === "organization" ? state.data.session.tenantName : state.activeRepository?.key || "";
    byId("repository-setting-name").value = name;
    byId("repository-setting-name").readOnly = existing;
    const settings = scope === "organization" ? state.organizationSettings : state.repositorySettings;
    const current = !isSecret && existing ? settings?.variables.find((item) => item.name === name)?.value : "";
    byId("repository-setting-value").value = typeof current === "string" ? current : "";
    byId("repository-setting-value-label").textContent = isSecret ? "Secret value" : "Value";
    byId("repository-setting-help").textContent = isSecret ? "You cannot view this value after saving." : "Do not use variables for secrets.";
    byId("repository-setting-footnote").textContent = "";
    byId("repository-setting-footnote").hidden = true;
    byId("repository-setting-dialog").showModal();
    (existing ? byId("repository-setting-value") : byId("repository-setting-name")).focus();
  }

  async function saveRepositorySetting(event) {
    event.preventDefault();
    if (!state.settingScope || !state.settingKind || (state.settingScope === "repository" && !state.activeRepository)) return;
    const button = byId("save-repository-setting");
    button.disabled = true; button.textContent = "Saving…";
    try {
      const body = new URLSearchParams({ csrf_token: state.data.session.csrfToken, idempotency_key: crypto.randomUUID(), name: byId("repository-setting-name").value.trim(), value: byId("repository-setting-value").value });
      const plural = state.settingKind === "secret" ? "secrets" : "variables";
      const base = state.settingScope === "organization" ? "/api/v1/ui/organization" : `/api/v1/ui/repositories/${encodeURIComponent(state.activeRepository.id)}`;
      const response = await fetch(`${base}/${plural}`, { method: "POST", body, credentials: "same-origin" });
      if (!response.ok) { const problem = await response.json().catch(() => null); throw new Error(problem?.detail || `Could not save ${state.settingKind}.`); }
      byId("repository-setting-dialog").close();
      if (state.settingScope === "organization") { state.organizationSettings = null; await loadOrganizationSettings(true); }
      else { state.repositorySettings = null; await loadRepositorySettings(true); }
      showToast(`${titleCase(state.settingKind)} saved.`);
    } catch (error) { showToast(error.message || "The setting could not be saved."); }
    finally { button.disabled = false; button.textContent = "Save"; }
  }

  function openDeleteSetting(kind, name, scope = "repository") {
    state.pendingSettingDelete = { kind, name, scope };
    byId("delete-setting-title").textContent = `Delete ${kind}?`;
    byId("delete-setting-name").textContent = name;
    byId("confirm-delete-setting").textContent = `Delete ${kind}`;
    byId("delete-setting-dialog").showModal();
  }

  async function deleteRepositorySetting() {
    if (!state.pendingSettingDelete) return;
    const { kind, name, scope } = state.pendingSettingDelete;
    if (scope === "repository" && !state.activeRepository) return;
    const plural = kind === "secret" ? "secrets" : "variables";
    const button = byId("confirm-delete-setting");
    button.disabled = true; button.textContent = "Deleting…";
    try {
      const body = new URLSearchParams({ csrf_token: state.data.session.csrfToken, name });
      const base = scope === "organization" ? "/api/v1/ui/organization" : `/api/v1/ui/repositories/${encodeURIComponent(state.activeRepository.id)}`;
      const response = await fetch(`${base}/${plural}/delete`, { method: "POST", body, credentials: "same-origin" });
      if (!response.ok) { const problem = await response.json().catch(() => null); throw new Error(problem?.detail || `Could not delete the ${kind}.`); }
      byId("delete-setting-dialog").close();
      if (scope === "organization") { state.organizationSettings = null; await loadOrganizationSettings(true); }
      else { state.repositorySettings = null; await loadRepositorySettings(true); }
      showToast(`${titleCase(kind)} deleted.`);
    } catch (error) { showToast(error.message || `The ${kind} could not be deleted.`); }
    finally { state.pendingSettingDelete = null; button.disabled = false; button.textContent = `Delete ${kind}`; }
  }

  function showRecordDetails(kicker, title, copy, fields) {
    state.activeApprovalId = null;
    byId("approve-workflow-approval").hidden = true;
    byId("deny-workflow-approval").hidden = true;
    byId("record-detail-footer-copy").textContent = "Read-only.";
    byId("record-detail-kicker").textContent = kicker;
    byId("record-detail-title").textContent = title;
    byId("record-detail-copy").textContent = copy;
    byId("record-detail-grid").innerHTML = fields.map(([label, value, mono = false]) => `<div><dt>${escapeHtml(label)}</dt><dd${mono ? ' class="mono"' : ""}>${escapeHtml(value)}</dd></div>`).join("");
    byId("record-detail-dialog").showModal();
  }

  function runRequirementSummary(requirements = {}) {
    const platform = [requirements.os, requirements.arch].filter(Boolean).map(titleCase).join(" / ") || "Platform not recorded";
    const isolation = requirements.isolation ? titleCase(requirements.isolation) : "Default isolation";
    const cpu = requirements.cpu ? `${requirements.cpu} CPU` : null;
    const memory = requirements.memory_bytes ? formatBytes(requirements.memory_bytes) : null;
    return [platform, isolation, cpu, memory].filter(Boolean).join(" · ");
  }

  function renderRunLogs() {
    const detail = state.activeRunDetails;
    if (!detail) return;
    const selected = byId("run-log-filter").value;
    const visible = detail.logs.filter((frame) => selected === "all" || `${frame.jobId}:${frame.stepId}` === selected);
    const jobNames = new Map(detail.jobs.map((job) => [job.id, job.key]));
    byId("run-log-view").innerHTML = visible.length ? visible.map((frame) => `<article class="run-log-entry ${frame.stream === "stderr" ? "is-stderr" : ""}"><div class="run-log-meta"><time datetime="${escapeHtml(frame.timestamp)}">${escapeHtml(formatLogTime(frame.timestamp))}</time><span>${escapeHtml(jobNames.get(frame.jobId) || compactId(frame.jobId))}</span><span>${escapeHtml(frame.stepId)}</span><span class="stream-label">${escapeHtml(frame.stream)}</span></div><pre>${escapeHtml(frame.payload)}</pre></article>`).join("") : `<div class="run-detail-empty"><strong>No logs</strong><p>${detail.logs.length ? "No logs match this filter." : "This run has no logs."}</p></div>`;
  }

  function renderRunDetail(run, detail) {
    state.activeRunDetails = detail;
    const duration = formatDuration(run.startedAt, run.completedAt);
    byId("run-summary").innerHTML = [
      ["Status", `<span class="state-badge ${tone(run.status)}">${escapeHtml(titleCase(run.status))}</span>`],
      ["Duration", escapeHtml(duration)],
      ["Started", escapeHtml(formatDate(run.startedAt))],
      ["Completed", escapeHtml(formatDate(run.completedAt))],
    ].map(([label, value]) => `<div><span>${label}</span><strong>${value}</strong></div>`).join("");
    byId("run-identifiers").innerHTML = `<div><dt>Run ID</dt><dd class="mono">${escapeHtml(run.id)}</dd></div><div><dt>Capsule ID</dt><dd class="mono">${escapeHtml(run.planId)}</dd></div><div><dt>Execution</dt><dd>${run.remote ? "Remote runner" : "Local"}${run.priority ? ` · Priority ${escapeHtml(run.priority)}` : ""}</dd></div>${run.cancelReason ? `<div><dt>Cancel reason</dt><dd>${escapeHtml(run.cancelReason)}</dd></div>` : ""}`;

    byId("run-job-count").textContent = `${detail.jobs.length} ${detail.jobs.length === 1 ? "job" : "jobs"}`;
    byId("run-job-list").innerHTML = detail.jobs.length ? detail.jobs.map((job, index) => {
      const steps = job.steps || [];
      return `<article class="run-job"><div class="job-index" aria-hidden="true">${index + 1}</div><div class="run-job-main"><header><div><h4>${escapeHtml(job.name || titleCase(job.key))}</h4><p class="mono" title="${escapeHtml(job.id)}">${escapeHtml(compactId(job.id, 10))} · Attempt ${escapeHtml(job.attempt)}</p></div><span class="state-badge ${tone(job.status)}">${escapeHtml(titleCase(job.status))}</span></header><p class="job-requirements">${escapeHtml(runRequirementSummary(job.requirements))}</p><div class="job-steps">${steps.length ? steps.map((step) => `<span title="${escapeHtml(step.id)}">${escapeHtml(step.name || step.id)}${step.finalizer ? " · finalizer" : ""}</span>`).join("") : "<span>No planned steps recorded</span>"}</div></div><div class="job-duration"><span>Duration</span><strong>${escapeHtml(formatDuration(job.createdAt, job.completedAt))}</strong></div></article>`;
    }).join("") : `<div class="run-detail-empty"><strong>No jobs</strong></div>`;

    const options = [];
    detail.logs.forEach((frame) => {
      const value = `${frame.jobId}:${frame.stepId}`;
      if (!options.some((option) => option.value === value)) {
        const job = detail.jobs.find((item) => item.id === frame.jobId);
        options.push({ value, label: `${job ? titleCase(job.key) : compactId(frame.jobId)} / ${frame.stepId}` });
      }
    });
    byId("run-log-filter").innerHTML = `<option value="all">All jobs and steps</option>${options.map((option) => `<option value="${escapeHtml(option.value)}">${escapeHtml(option.label)}</option>`).join("")}`;
    byId("run-log-filter-wrap").hidden = options.length < 2;
    byId("run-logs-copy").textContent = `${detail.logs.length} ${detail.logs.length === 1 ? "entry" : "entries"}`;
    byId("run-logs-truncated").hidden = !detail.logsTruncated;
    renderRunLogs();
    byId("run-detail-loading").hidden = true;
    byId("run-detail-error").hidden = true;
    byId("run-detail-content").hidden = false;
  }

  async function openRun(id) {
    const run = (state.data.runs || []).find((item) => item.id === id);
    if (!run) return;
    state.activeRunId = id;
    state.activeRunDetails = null;
    byId("run-detail-title").textContent = `Run ${compactId(run.id).replace(/^run-/, "")}`;
    byId("run-detail-copy").textContent = run.repository;
    byId("run-detail-loading").hidden = false;
    byId("run-detail-error").hidden = true;
    byId("run-detail-content").hidden = true;
    if (!byId("run-detail-dialog").open) byId("run-detail-dialog").showModal();
    try {
      const response = await fetch(`/api/v1/ui/runs/${encodeURIComponent(id)}`, { credentials: "same-origin", headers: { accept: "application/json" } });
      if (!response.ok) throw new Error(response.status === 403 ? "You do not have access to this run." : "Could not load run.");
      const detail = await response.json();
      if (state.activeRunId === id) renderRunDetail(run, detail);
    } catch (error) {
      if (state.activeRunId !== id) return;
      byId("run-detail-loading").hidden = true;
      byId("run-detail-content").hidden = true;
      byId("run-detail-error-copy").textContent = error.message || "Could not load run.";
      byId("run-detail-error").hidden = false;
    }
  }

  function openApproval(id) {
    const approval = (state.data.approvals || []).find((item) => item.id === id);
    if (!approval) return;
    showRecordDetails("Approval request", titleCase(approval.kind), approval.id, [["Status", titleCase(approval.status)], ["Risk score", approval.riskScore], ["Rule", approval.ruleId, true], ["Required approvals", approval.requiredApprovals], ["Decisions", approval.decisionCount], ["Subject digest", approval.subjectDigest, true], ["Created", formatDate(approval.createdAt)], ["Expires", formatDate(approval.expiresAt)]]);
    if (approval.status === "pending" && approval.kind === "workflow-definition") {
      state.activeApprovalId = approval.id;
      byId("approve-workflow-approval").hidden = false;
      byId("deny-workflow-approval").hidden = false;
      byId("record-detail-footer-copy").textContent = "Approval applies to this commit only.";
    }
  }

  async function decideWorkflowApproval(decision) {
    const approval = (state.data.approvals || []).find((item) => item.id === state.activeApprovalId);
    if (!approval) return;
    const approve = byId("approve-workflow-approval");
    const deny = byId("deny-workflow-approval");
    approve.disabled = true; deny.disabled = true;
    try {
      const body = new URLSearchParams({
        csrf_token: state.data.session.csrfToken,
        idempotency_key: crypto.randomUUID(),
        subject_digest: approval.subjectDigest,
        decision,
      });
      const response = await fetch(`/api/v1/ui/approvals/${encodeURIComponent(approval.id)}/decisions`, { method: "POST", body, credentials: "same-origin", headers: { accept: "application/json" } });
      if (!response.ok) throw new Error(response.status === 403 ? "You are not authorized to decide this workflow approval." : "The approval decision could not be recorded.");
      const result = await response.json();
      approval.status = result.status;
      approval.decisionCount = Number(approval.decisionCount || 0) + (result.replayed ? 0 : 1);
      renderApprovals();
      byId("record-detail-dialog").close();
      showToast(decision === "approve" ? "Proposed workflow approved and queued." : "Proposed workflow rejected.");
    } catch (error) {
      showToast(error.message || "The approval decision could not be recorded.");
    } finally {
      approve.disabled = false; deny.disabled = false;
    }
  }

  function openToken(id) {
    const token = (state.data.apiTokens || []).find((item) => item.id === id);
    if (!token) return;
    showRecordDetails("API token", token.name, "", [["Token ID", token.id, true], ["Principal", token.principalId, true], ["Scopes", token.scopes.join(", ") || "None"], ["Created", formatDate(token.createdAt)], ["Expires", formatDate(token.expiresAt)], ["Last used", formatDate(token.lastUsedAt)], ["Revoked", formatDate(token.revokedAt)]]);
  }

  function switchView(view, updateHash = true) {
    const allowed = ["repositories", "repository", "organization", "github", "runs", "approvals", "runners", "api-tokens", "audit"];
    const target = document.querySelector(`[data-view="${view}"]`);
    const capability = target?.dataset.capability;
    if (!allowed.includes(view) || !target || (capability && !state.data.capabilities?.[capability])) view = "repositories";
    document.querySelectorAll("[data-view]").forEach((element) => { element.hidden = element.dataset.view !== view; });
    document.querySelectorAll("[data-view-target]").forEach((button) => {
      const active = button.dataset.viewTarget === view || (view === "repository" && button.dataset.viewTarget === "repositories");
      button.classList.toggle("active", active);
      if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
    });
    if (updateHash && view !== "repository") history.replaceState(null, "", `${location.pathname}${location.search}#${view}`);
    if (view === "organization") loadOrganizationSettings();
    closeNavigation();
    document.querySelector(`[data-view="${view}"] h1`)?.focus({ preventScroll: true });
  }

  function openNavigation() { byId("workspace").classList.add("nav-open"); byId("mobile-menu").setAttribute("aria-expanded", "true"); }
  function closeNavigation() { byId("workspace").classList.remove("nav-open"); byId("mobile-menu").setAttribute("aria-expanded", "false"); }
  function definitionCard(label, value) { return `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value ?? "Not available")}</strong></div>`; }
  function definitionLinkCard(label, value, href) {
    if (!href) return definitionCard(label, value);
    return `<div><span>${escapeHtml(label)}</span><a class="metadata-link" href="${escapeHtml(href)}" target="_blank" rel="noopener noreferrer"><strong>${escapeHtml(value ?? "Not available")}</strong><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M7 17 17 7M8 7h9v9"/></svg></a></div>`;
  }
  function emptyInline(title, detail) { return `<div class="inline-empty"><h3>${escapeHtml(title)}</h3><p>${escapeHtml(detail)}</p></div>`; }

  function renderOrganizations() {
    const query = byId("org-search").value.trim().toLowerCase();
    const organizations = state.data.organizations.filter((organization) => organization.name.toLowerCase().includes(query));
    byId("org-result-count").textContent = `${organizations.length} available`;
    const catalogStatus = state.data.userCatalog?.status;
    const empty = state.data.organizations.length
      ? ["No organizations found", "Try a different search."]
      : catalogStatus === "reauthentication_required"
        ? ["GitHub access needs refreshing", "Refresh your GitHub sign-in to load organizations."]
        : catalogStatus === "loading"
          ? ["Loading organizations", ""]
        : catalogStatus === "unavailable"
          ? ["Could not load organizations", "Use Reload to try again."]
          : ["No organizations", ""];
    byId("org-list").innerHTML = organizations.length ? organizations.map((organization) => {
      const count = organization.repositoriesStatus === "ready" ? organization.repositories.length : "›";
      return `<button class="org-option ${organization.id === state.activeOrganization ? "active" : ""}" type="button" data-org-id="${escapeHtml(organization.id)}"><span class="org-avatar">${escapeHtml(organization.initials)}</span><strong>${escapeHtml(organization.name)}</strong><span>${count}</span></button>`;
    }).join("") : `<div class="org-empty"><h4>${empty[0]}</h4><p>${empty[1]}</p></div>`;
    byId("org-list").querySelectorAll("[data-org-id]").forEach((button) => button.addEventListener("click", () => selectOrganization(button.dataset.orgId)));
  }

  function renderRepositoryChoices() {
    const organization = state.data.organizations.find((item) => item.id === state.activeOrganization);
    byId("repo-search").disabled = !organization || organization.repositoriesStatus !== "ready";
    if (!organization) {
      const hasOrganizations = state.data.organizations.length > 0;
      const loading = state.data.userCatalog?.status === "loading";
      byId("repo-browser-title").textContent = hasOrganizations ? "Choose an organization" : loading ? "Loading organizations" : "No repositories available";
      byId("repo-browser-copy").textContent = hasOrganizations ? "Repositories load after you make a selection." : loading ? "Fetching the latest GitHub access…" : "Reload and try again.";
      byId("repo-list").innerHTML = `<div class="repo-empty">${hasOrganizations ? "Select an organization to load its repositories." : loading ? "Loading organizations…" : "No repositories."}</div>`;
      return;
    }
    byId("repo-browser-title").textContent = organization.name;
    if (organization.repositoriesStatus === "loading") {
      byId("repo-browser-copy").textContent = "Loading the latest repositories from GitHub…";
      byId("repo-list").innerHTML = `<div class="repo-empty">Loading repositories…</div>`;
      return;
    }
    if (organization.repositoriesStatus === "unavailable") {
      byId("repo-browser-copy").textContent = "Repositories could not be loaded.";
      byId("repo-list").innerHTML = `<div class="repo-empty">Use Reload to try again.</div>`;
      return;
    }
    byId("repo-browser-copy").textContent = `${organization.repositories.length} repositories`;
    const query = byId("repo-search").value.trim().toLowerCase();
    const repositories = organization.repositories.filter((repository) => repository.name.toLowerCase().includes(query));
    byId("repo-list").innerHTML = repositories.length ? repositories.map((repository) => {
      if (repository.state === "added") {
        const status = "Already added";
        return `<div class="repo-option imported"><span aria-hidden="true">•</span><span><strong>${escapeHtml(repository.name)}</strong><small>${escapeHtml(repository.defaultBranch)}</small></span><span>${status}</span></div>`;
      }
      const key = `${repository.state}:${repository.externalRepositoryId}`;
      const selected = state.selectedRepositories.has(key);
      const status = repository.state === "existing_installation" ? "Import repository" : repository.state === "needs_installation" ? "Install App" : repository.visibility;
      return `<label class="repo-option ${selected ? "selected" : ""}"><input type="checkbox" data-repository-key="${escapeHtml(key)}" ${selected ? "checked" : ""}><span><strong>${escapeHtml(repository.name)}</strong><small>${escapeHtml(repository.defaultBranch)}</small></span><span>${escapeHtml(status)}</span></label>`;
    }).join("") : `<div class="repo-empty">No matching repositories.</div>`;
    byId("repo-list").querySelectorAll("[data-repository-key]").forEach((input) => input.addEventListener("change", () => {
      const repository = organization.repositories.find((item) => `${item.state}:${item.externalRepositoryId}` === input.dataset.repositoryKey);
      if (input.checked) {
        const selected = [...state.selectedRepositories.values()];
        const modeChanged = selected.some((item) => item.state !== repository.state);
        const accountChanged = ["needs_installation", "existing_installation"].includes(repository.state)
          && selected.some((item) => item.ownerId !== repository.ownerId);
        if (modeChanged || accountChanged) {
          state.selectedRepositories.clear();
          showToast(modeChanged ? "Select repositories to add or install in one step at a time." : "Install the App on one GitHub account at a time.");
        }
        state.selectedRepositories.set(input.dataset.repositoryKey, repository);
      } else state.selectedRepositories.delete(input.dataset.repositoryKey);
      updateSelection(); renderRepositoryChoices();
    }));
  }

  function updateSelection() {
    const selected = [...state.selectedRepositories.values()];
    const requiresInstallation = selected.some((repository) => repository.state === "needs_installation");
    const importsExisting = selected.some((repository) => repository.state === "existing_installation");
    byId("selection-count").textContent = selected.length;
    byId("confirm-add").disabled = selected.length === 0;
    byId("confirm-add").textContent = requiresInstallation ? "Install selected" : importsExisting ? "Import selected" : "Add selected";
  }

  function updateGitHubDialogActions() {
    const manageButton = byId("dialog-manage-github");
    manageButton.hidden = !state.data.installAction;
    manageButton.textContent = state.data.github.installations.some((installation) => installation.state === "Active") ? "Update GitHub App access" : "Install GitHub App";
    const reloadButton = byId("dialog-refresh-github");
    reloadButton.disabled = state.data.userCatalog?.status === "loading";
    reloadButton.textContent = state.data.userCatalog?.status === "reauthentication_required" ? "Refresh GitHub sign-in" : "Reload GitHub data";
  }

  async function loadOrganizationRepositories(organizationId) {
    const organization = state.data.organizations.find((item) => item.id === organizationId);
    if (!organization) return;
    const requestId = ++state.repositoryRequestId;
    organization.repositories = [];
    organization.repositoriesStatus = "loading";
    renderOrganizations(); renderRepositoryChoices(); updateGitHubDialogActions();
    try {
      const response = await fetch(`/api/v1/ui/github?catalog=true&organization=${encodeURIComponent(organization.name)}`, { credentials: "same-origin", headers: { accept: "application/json" }, cache: "no-store" });
      if (response.status === 401) { byId("add-repo-dialog").close(); return showLogin(); }
      if (!response.ok) throw new Error(`GitHub repositories failed (${response.status})`);
      const catalog = await response.json();
      if (requestId !== state.repositoryRequestId) return;
      state.data.userCatalog = catalog.userCatalog || { status: "unavailable" };
      state.data.installAction = catalog.installAction;
      state.data.github = catalog.github;
      const loaded = (catalog.organizations || []).find((item) => item.name.toLowerCase() === organization.name.toLowerCase());
      organization.repositories = loaded?.repositories || [];
      organization.repositoriesStatus = state.data.userCatalog.status === "ready" ? "ready" : "unavailable";
    } catch (error) {
      if (requestId !== state.repositoryRequestId) return;
      organization.repositoriesStatus = "unavailable";
      state.data.userCatalog = { status: "unavailable" };
      showToast(error.message || "Could not load GitHub repositories.");
    }
    renderOrganizations(); renderRepositoryChoices(); updateSelection(); updateGitHubDialogActions();
  }

  function selectOrganization(organizationId) {
    state.activeOrganization = organizationId;
    byId("repo-search").value = "";
    renderOrganizations(); renderRepositoryChoices();
    loadOrganizationRepositories(organizationId);
  }

  async function loadOrganizations({ preserveSelection = false, reloadSelected = false } = {}) {
    const selectedOrganization = preserveSelection ? state.activeOrganization : null;
    const requestId = ++state.organizationRequestId;
    state.repositoryRequestId += 1;
    state.data.organizations = [];
    state.activeOrganization = null;
    state.data.userCatalog = { status: "loading" };
    state.selectedRepositories.clear();
    renderOrganizations(); renderRepositoryChoices(); updateSelection(); updateGitHubDialogActions();
    try {
      const response = await fetch("/api/v1/ui/github?catalog=true", { credentials: "same-origin", headers: { accept: "application/json" }, cache: "no-store" });
      if (response.status === 401) { byId("add-repo-dialog").close(); return showLogin(); }
      if (!response.ok) throw new Error(`GitHub organizations failed (${response.status})`);
      const catalog = await response.json();
      if (requestId !== state.organizationRequestId) return;
      state.data.organizations = (catalog.organizations || []).map((organization) => ({ ...organization, repositories: [], repositoriesStatus: "not_loaded" }));
      state.data.userCatalog = catalog.userCatalog || { status: "unavailable" };
      state.data.installAction = catalog.installAction;
      state.data.github = catalog.github;
      if (selectedOrganization && state.data.organizations.some((organization) => organization.id === selectedOrganization)) state.activeOrganization = selectedOrganization;
    } catch (error) {
      if (requestId !== state.organizationRequestId) return;
      state.data.userCatalog = { status: "unavailable" };
      showToast(error.message || "Could not load GitHub organizations.");
    }
    renderOrganizations(); renderRepositoryChoices(); updateSelection(); updateGitHubDialogActions();
    if (reloadSelected && state.activeOrganization) await loadOrganizationRepositories(state.activeOrganization);
  }

  async function openAddDialog() {
    state.selectedRepositories.clear(); byId("org-search").value = ""; byId("repo-search").value = "";
    state.activeOrganization = null;
    state.data.organizations = [];
    state.data.userCatalog = { status: "loading" };
    renderOrganizations(); renderRepositoryChoices(); updateSelection(); byId("add-repo-dialog").showModal();
    updateGitHubDialogActions();
    await loadOrganizations();
  }

  function submitLocalForm(path, fields) {
    const form = document.createElement("form"); form.method = "post"; form.action = path;
    Object.entries(fields).forEach(([name, value]) => { const input = document.createElement("input"); input.type = "hidden"; input.name = name; input.value = value; form.append(input); });
    document.body.append(form); form.submit();
  }

  function submitInstallAction(repositories = []) {
    const action = state.data.installAction;
    if (!action) return showToast("GitHub App configuration is not ready.");
    const fields = { csrf_token: action.csrfToken, idempotency_key: action.idempotencyKey };
    if (repositories.length) fields.repository_ids = repositories.map((repository) => repository.externalRepositoryId).join(",");
    submitLocalForm("/ui/github/installations/start", fields);
  }

  function refreshGitHubAccess() {
    location.assign("/auth/login?return_to=%2Fui%2Fgithub%2Finstallations");
  }

  async function reloadGitHubData() {
    if (state.data.userCatalog?.status === "reauthentication_required") return refreshGitHubAccess();
    await loadOrganizations({ preserveSelection: true, reloadSelected: true });
  }

  async function logout() {
    const body = new URLSearchParams({ csrf_token: state.data.session.csrfToken });
    const response = await fetch("/auth/session/logout", { method: "POST", body, credentials: "same-origin" });
    if (response.ok) location.assign("/ui/github/installations"); else showToast("Could not end the current session.");
  }

  async function addSelectedRepositories() {
    const button = byId("confirm-add"); button.disabled = true; button.textContent = "Adding…";
    try {
      for (const repository of state.selectedRepositories.values()) {
        const body = new URLSearchParams({ csrf_token: repository.csrfToken, installation_id: repository.installationId, external_repository_id: repository.externalRepositoryId });
        const response = await fetch("/ui/github/repositories/link", { method: "POST", body, credentials: "same-origin" });
        if (!response.ok) throw new Error(`Repository link failed (${response.status})`);
      }
      location.assign("/ui/github/installations?github=linked");
    } catch (error) { showToast(error.message || "Could not add the selected repositories."); button.disabled = false; button.textContent = "Add selected"; }
  }

  function confirmSelectedRepositories() {
    const selected = [...state.selectedRepositories.values()];
    if (selected.some((repository) => ["needs_installation", "existing_installation"].includes(repository.state))) {
      submitInstallAction(selected);
    } else {
      addSelectedRepositories();
    }
  }

  function bindEvents() {
    byId("github-signin").addEventListener("click", () => location.assign("/auth/login?return_to=%2Fui%2Fgithub%2Finstallations"));
    byId("logout").addEventListener("click", logout);
    byId("catalog-search").addEventListener("input", renderRepositories);
    document.querySelectorAll("[data-source]").forEach((button) => button.addEventListener("click", () => { state.repositorySource = button.dataset.source; document.querySelectorAll("[data-source]").forEach((item) => { const active = item === button; item.classList.toggle("active", active); item.setAttribute("aria-pressed", String(active)); }); renderRepositories(); }));
    byId("run-search").addEventListener("input", renderRuns); byId("run-status-filter").addEventListener("change", renderRuns);
    document.querySelectorAll("[data-approval-status]").forEach((button) => button.addEventListener("click", () => { state.approvalFilter = button.dataset.approvalStatus; document.querySelectorAll("[data-approval-status]").forEach((item) => item.classList.toggle("active", item === button)); renderApprovals(); }));
    byId("audit-search").addEventListener("input", renderAudit);
    byId("audit-action-filter").addEventListener("change", renderAudit);
    byId("audit-result-filter").addEventListener("change", renderAudit);
    document.querySelectorAll("[data-view-target]").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.viewTarget)));
    byId("catalog-content").addEventListener("click", (event) => { const button = event.target.closest("[data-open-repository]"); if (button) openRepository(button.dataset.openRepository); });
    document.addEventListener("click", (event) => { const run = event.target.closest("[data-open-run]"); const approval = event.target.closest("[data-open-approval]"); const token = event.target.closest("[data-open-token]"); const secret = event.target.closest("[data-edit-secret]"); const deleteSetting = event.target.closest("[data-delete-setting]"); const variable = event.target.closest("[data-edit-variable]"); if (run) openRun(run.dataset.openRun); if (approval) openApproval(approval.dataset.openApproval); if (token) openToken(token.dataset.openToken); if (secret) openSetting(secret.dataset.settingScope || "repository", "secret", secret.dataset.editSecret); if (deleteSetting) openDeleteSetting(deleteSetting.dataset.deleteSetting, deleteSetting.dataset.settingName, deleteSetting.dataset.settingScope || "repository"); if (variable) openSetting(variable.dataset.settingScope || "repository", "variable", variable.dataset.editVariable); });
    byId("back-to-repositories").addEventListener("click", () => switchView("repositories"));
    document.querySelectorAll("[data-repository-section]").forEach((button) => button.addEventListener("click", () => setRepositorySection(button.dataset.repositorySection)));
    byId("mobile-menu").addEventListener("click", openNavigation); byId("sidebar-scrim").addEventListener("click", closeNavigation);
    byId("open-add-dialog").addEventListener("click", openAddDialog); byId("manage-github").addEventListener("click", submitInstallAction); byId("dialog-manage-github").addEventListener("click", submitInstallAction); byId("dialog-refresh-github").addEventListener("click", reloadGitHubData);
    byId("close-dialog").addEventListener("click", () => byId("add-repo-dialog").close()); byId("cancel-add").addEventListener("click", () => byId("add-repo-dialog").close()); byId("confirm-add").addEventListener("click", confirmSelectedRepositories);
    byId("org-search").addEventListener("input", renderOrganizations); byId("repo-search").addEventListener("input", renderRepositoryChoices);
    byId("run-log-filter").addEventListener("change", renderRunLogs);
    byId("retry-run-detail").addEventListener("click", () => { if (state.activeRunId) openRun(state.activeRunId); });
    const closeRunDetail = () => { state.activeRunId = null; state.activeRunDetails = null; byId("run-detail-dialog").close(); };
    byId("close-run-detail").addEventListener("click", closeRunDetail); byId("dismiss-run-detail").addEventListener("click", closeRunDetail);
    byId("run-detail-dialog").addEventListener("close", () => { state.activeRunId = null; state.activeRunDetails = null; });
    byId("close-record-detail").addEventListener("click", () => byId("record-detail-dialog").close()); byId("dismiss-record-detail").addEventListener("click", () => byId("record-detail-dialog").close());
    byId("approve-workflow-approval").addEventListener("click", () => decideWorkflowApproval("approve")); byId("deny-workflow-approval").addEventListener("click", () => decideWorkflowApproval("deny"));
    byId("add-repository-secret").addEventListener("click", () => openRepositorySetting("secret"));
    byId("add-repository-variable").addEventListener("click", () => openRepositorySetting("variable"));
    byId("add-organization-secret").addEventListener("click", () => openOrganizationSetting("secret"));
    byId("add-organization-variable").addEventListener("click", () => openOrganizationSetting("variable"));
    byId("repository-setting-form").addEventListener("submit", saveRepositorySetting);
    byId("repository-workflow-directory-form").addEventListener("submit", saveRepositoryWorkflowDirectory);
    byId("close-repository-setting").addEventListener("click", () => byId("repository-setting-dialog").close());
    byId("cancel-repository-setting").addEventListener("click", () => byId("repository-setting-dialog").close());
    byId("cancel-delete-setting").addEventListener("click", () => byId("delete-setting-dialog").close());
    byId("confirm-delete-setting").addEventListener("click", deleteRepositorySetting);
    byId("delete-setting-dialog").addEventListener("close", () => { state.pendingSettingDelete = null; });
    byId("open-uninstall-repository").addEventListener("click", openUninstallRepository);
    byId("cancel-uninstall-repository").addEventListener("click", () => byId("uninstall-repository-dialog").close());
    byId("confirm-uninstall-repository").addEventListener("click", uninstallRepository);
    window.addEventListener("hashchange", () => switchView(location.hash.slice(1), false));
  }

  async function start() {
    bindEvents();
    try {
      const query = new URLSearchParams(location.search);
      const apiQuery = query.has("github") ? `?github=${encodeURIComponent(query.get("github"))}` : "";
      const response = await fetch(`/api/v1/ui/github${apiQuery}`, { credentials: "same-origin", headers: { accept: "application/json" } });
      if (response.status === 401) return showLogin();
      if (!response.ok) return showLogin("The workspace is temporarily unavailable. Please sign in again or retry shortly.");
      state.data = await response.json();
      showWorkspace(); configureRunFilters(); configureAuditFilters(); renderRepositories(); renderAlert(); renderRuns(); renderApprovals(); renderGitHub(); renderRunners(); renderTokens(); renderAudit();
      switchView(location.hash.slice(1), false);
    } catch (error) {
      const detail = error instanceof Error ? `${error.name}: ${error.message}` : "Unknown rendering error";
      fetch("/frontend-client-error", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ detail }),
        keepalive: true,
      }).catch(() => {});
      showLogin("The workspace loaded, but the page could not be rendered. Please retry shortly.");
    }
  }

  start();
})();
