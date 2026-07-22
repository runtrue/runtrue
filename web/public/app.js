(() => {
  "use strict";

  const workspacePath = "/";

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
    repositorySection: "overview",
    repositoryRunsRefreshing: false,
    organizationSettings: null,
    organizationSettingsLoading: false,
    secretInventory: null,
    secretInventoryLoading: false,
    identity: null,
    identityLoading: false,
    activeTeamId: null,
    activeUserId: null,
    retryingRuns: new Set(),
    pendingScopedSecretDelete: null,
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
  const shortRef = (value) => String(value || "").replace(/^refs\/(heads|tags)\//, "");
  const presentableEmail = (user) => {
    const email = String(user?.primary_email || "").trim();
    return email && !email.toLowerCase().endsWith("@github.invalid") ? email : "";
  };

  function runEventLabel(run) {
    const source = run.source || {};
    if (source.pullRequestNumber) return `Pull request #${source.pullRequestNumber}`;
    const labels = {
      push: "Push",
      pull_request: "Pull request",
      merge_group: "Merge group",
      issue_comment: "Issue comment",
      check_run: "Check run",
      api: "API request",
      manual: "Manual run",
    };
    return labels[source.eventKind] || titleCase(source.eventKind || "Manual run");
  }

  function runTriggerMeta(run) {
    const source = run.source || {};
    const values = [];
    if (source.eventAction) values.push(titleCase(source.eventAction));
    if (source.refName) values.push(shortRef(source.refName));
    if (source.actor) values.push(`@${source.actor}`);
    if (source.commitSha) values.push(String(source.commitSha).slice(0, 8));
    return values;
  }

  function runTriggerMarkup(run) {
    const source = run.source || {};
    const label = escapeHtml(runEventLabel(run));
    const title = source.url
      ? `<a class="run-source-link" href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer">${label}<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M7 17 17 7M8 7h9v9"/></svg></a>`
      : `<strong class="table-primary">${label}</strong>`;
    const meta = runTriggerMeta(run);
    return `${title}${meta.length ? `<small>${meta.map(escapeHtml).join(" · ")}</small>` : ""}`;
  }

  function runSourceCardMarkup(run) {
    const source = run.source || {};
    const label = escapeHtml(runEventLabel(run));
    const title = source.url
      ? `<a class="run-source-link run-source-primary" href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer"><span>${label}</span><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M7 17 17 7M8 7h9v9"/></svg><span class="sr-only"> (opens in a new tab)</span></a>`
      : `<strong class="run-source-primary">${label}</strong>`;
    const meta = runTriggerMeta(run);
    const workflow = source.workflowPath
      ? `<div class="run-source-workflow"><span>Workflow file</span><code title="${escapeHtml(source.workflowPath)}">${escapeHtml(source.workflowPath)}</code></div>`
      : "";
    return `<div class="run-source-icon" aria-hidden="true"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="6" cy="18" r="2"/><path d="M6 8v8m2-8h4a6 6 0 0 1 6 6v2"/></svg></div><div class="run-source-content"><span class="run-source-eyebrow">Triggered by</span>${title}${meta.length ? `<div class="run-source-meta">${meta.map((value) => `<span>${escapeHtml(value)}</span>`).join("")}</div>` : ""}</div>${workflow}`;
  }

  function runActionsMarkup(run) {
    const queued = state.retryingRuns.has(run.id);
    const unavailable = !run.canRetry || queued;
    const title = queued ? "Retry queued" : run.canRetry ? "" : "Retry is available for completed GitHub event runs";
    return `<div class="run-actions"><button class="btn btn-secondary btn-inline btn-compact" type="button" data-retry-run="${escapeHtml(run.id)}" ${unavailable ? "disabled" : ""} ${title ? `title="${escapeHtml(title)}"` : ""} aria-label="Retry ${escapeHtml(run.source?.workflowName || "workflow run")}">${queued ? "Queued" : "Retry"}</button><button class="text-button run-open-button" type="button" data-open-run="${escapeHtml(run.id)}">Details <span aria-hidden="true">→</span></button></div>`;
  }

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
    const rows = repositories.map((repository) => {
      const pending = pendingApprovalsForRepository(repository.id).length;
      return `<tr><td><button class="repo-link" type="button" data-open-repository="${escapeHtml(repository.id)}"><span class="repo-glyph" aria-hidden="true">R</span><span><strong>${escapeHtml(repository.organization)}/${escapeHtml(repository.name)}</strong><small>${escapeHtml(repository.visibility)} · ${escapeHtml(repository.defaultBranch)}</small></span></button></td><td>${escapeHtml(repository.source)}</td><td>${pending ? `<span class="approval-count-badge">${escapeHtml(pending)} pending</span>` : `<span class="muted-cell">None</span>`}</td><td><span class="state-badge ${tone(repository.state)}">${escapeHtml(repository.state)}</span></td></tr>`;
    }).join("");
    byId("catalog-content").innerHTML = `<div class="table-wrap"><table class="repo-table"><thead><tr><th>Repository</th><th>Source</th><th>Approvals</th><th>State</th></tr></thead><tbody>${rows}</tbody></table></div>`;
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
      const matchesSearch = `${run.id} ${run.planId} ${run.repository} ${Object.values(run.source || {}).join(" ")}`.toLowerCase().includes(search);
      return matchesSearch && (status === "all" || String(run.status) === status);
    });
    byId("sidebar-run-count").textContent = runs.length;
    byId("run-visible-count").textContent = visible.length;
    byId("run-total-count").textContent = `${runs.length} total`;
    const tbody = byId("runs-body");
    tbody.innerHTML = visible.map((run) => `<tr><td><strong class="table-primary">${escapeHtml(run.source?.workflowName || "Workflow")}</strong><small><span class="mono" title="${escapeHtml(run.id)}">${escapeHtml(compactId(run.id))}</span> · ${escapeHtml(run.source?.jobCount ?? "—")} ${run.source?.jobCount === 1 ? "job" : "jobs"}</small></td><td><strong class="table-primary">${escapeHtml(run.repository)}</strong></td><td class="run-trigger-cell">${runTriggerMarkup(run)}</td><td><span class="state-badge ${tone(run.status)}">${escapeHtml(titleCase(run.status))}</span></td><td class="date-cell">${escapeHtml(formatDate(run.startedAt || run.createdAt))}</td><td>${runActionsMarkup(run)}</td></tr>`).join("");
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
    byId("approval-list").innerHTML = visible.map(approvalRow).join("");
    byId("approvals-empty").hidden = visible.length > 0;
  }

  function pendingApprovalsForRepository(repositoryId) {
    return (state.data?.approvals || []).filter((approval) => approval.repositoryId === repositoryId && approval.status === "pending");
  }

  function approvalRow(approval) {
    const waitingPullRequests = approval.waitingPullRequests || [];
    const trigger = waitingPullRequests.length
      ? `Pull request${waitingPullRequests.length === 1 ? "" : "s"} ${waitingPullRequests.map((number) => `#${number}`).join(", ")}`
      : approval.source?.pullRequest ? `Pull request #${approval.source.pullRequest}` : titleCase(approval.source?.event || "Execution request");
    const remaining = Number(approval.remainingApprovals ?? approval.requiredApprovals ?? 0);
    const waiting = Number(approval.waitingExecutions || 0);
    const scope = approval.kind === "privileged-execution" && approval.oneShot === false ? "Reusable capability grant" : titleCase(approval.kind);
    return `<article class="approval-row"><div class="approval-main"><div class="approval-row-heading"><span class="state-badge ${tone(approval.status)}">${escapeHtml(titleCase(approval.status))}</span><span class="approval-repository">${escapeHtml(approval.repository || "Repository")}</span></div><h3>${escapeHtml(approval.workflow?.name || titleCase(approval.kind))}</h3><p>${escapeHtml(scope)} · ${escapeHtml(trigger)}</p><ul class="approval-signals"><li>${escapeHtml(remaining)} approval${remaining === 1 ? "" : "s"} needed</li>${waiting ? `<li>${escapeHtml(waiting)} execution${waiting === 1 ? "" : "s"} waiting</li>` : ""}<li>${escapeHtml(approval.jobs?.length || 0)} job${approval.jobs?.length === 1 ? "" : "s"}</li><li>Expires ${escapeHtml(formatDate(approval.expiresAt))}</li></ul></div><div class="risk-score ${approval.riskScore >= 70 ? "high" : ""}"><span>Risk</span><strong>${escapeHtml(approval.riskScore)}</strong></div><button class="btn btn-secondary btn-inline" type="button" data-open-approval="${escapeHtml(approval.id)}">Review</button></article>`;
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

  function renderIdentity() {
    const identity = state.identity || { users: [], teams: [] };
    const teamById = new Map(identity.teams.map((team) => [team.id, team]));
    const activeTeams = identity.teams.filter((team) => team.status === "active").length;
    byId("identity-team-count").textContent = `${activeTeams} active`;
    byId("team-list").innerHTML = identity.teams.map((team) => {
      const members = team.member_ids.map((id) => identity.users.find((user) => user.id === id)).filter(Boolean);
      return `<article class="team-card"><header><div><h3>${escapeHtml(team.name)}</h3><p>${escapeHtml(team.description || "No description")}</p></div><span class="state-badge ${tone(team.status)}">${escapeHtml(titleCase(team.status))}</span></header><div class="team-members"><span>${escapeHtml(members.length)} member${members.length === 1 ? "" : "s"}</span><div>${members.slice(0, 5).map((user) => `<span class="member-avatar" title="${escapeHtml(user.display_name)}">${escapeHtml(initials(user.display_name))}</span>`).join("")}${members.length > 5 ? `<span class="member-more">+${escapeHtml(members.length - 5)}</span>` : ""}</div></div><footer><span class="mono team-id">${escapeHtml(team.id)}</span><button class="btn btn-secondary btn-inline btn-compact" type="button" data-edit-team="${escapeHtml(team.id)}">Manage</button></footer></article>`;
    }).join("");
    byId("teams-empty").hidden = identity.teams.length > 0;
    byId("team-list").hidden = identity.teams.length === 0;

    const query = byId("identity-user-search").value.trim().toLowerCase();
    const users = identity.users.filter((user) => `${user.display_name} ${user.primary_email} ${user.id}`.toLowerCase().includes(query));
    byId("identity-users-body").innerHTML = users.map((user) => {
      const teams = user.team_ids.map((id) => teamById.get(id)).filter(Boolean);
      const lastSeen = user.last_seen_at ? escapeHtml(formatDate(user.last_seen_at)) : `<span class="muted-cell">Never</span>`;
      const email = presentableEmail(user);
      const userMeta = email ? `${escapeHtml(email)} · ` : "";
      return `<tr><td><strong>${escapeHtml(user.display_name)}</strong><small>${userMeta}<span class="mono">${escapeHtml(user.id)}</span></small></td><td><span class="scope-list">${teams.map((team) => `<span class="scope-chip">${escapeHtml(team.name)}</span>`).join("") || `<span class="muted-cell">No teams</span>`}</span></td><td>${lastSeen}</td><td><span class="state-badge ${tone(user.status)}">${escapeHtml(titleCase(user.status))}</span></td><td><button class="text-button" type="button" data-edit-user="${escapeHtml(user.id)}">Edit</button></td></tr>`;
    }).join("");
    byId("identity-users-empty").hidden = users.length > 0;
    byId("identity-users-body").closest("table").hidden = users.length === 0;
  }

  async function loadIdentity(force = false) {
    if (state.identityLoading || (state.identity && !force)) return;
    state.identityLoading = true;
    try {
      const response = await fetch("/api/v1/ui/identity", { credentials: "same-origin", headers: { accept: "application/json" }, cache: "no-store" });
      if (!response.ok) throw new Error(response.status === 403 ? "You do not have permission to manage users and teams." : "Could not load users and teams.");
      state.identity = await response.json();
      renderIdentity();
    } catch (error) { showToast(error.message || "Could not load users and teams."); }
    finally { state.identityLoading = false; }
  }

  function openCreateTeam() {
    state.activeTeamId = null;
    byId("team-dialog-title").textContent = "Create team";
    byId("team-dialog-copy").textContent = "Create a team for authorization policies.";
    byId("team-id-input").value = "";
    byId("team-id-input-wrap").hidden = false;
    byId("team-name").value = "";
    byId("team-description").value = "";
    byId("team-status").value = "active";
    byId("team-status-wrap").hidden = true;
    byId("team-members-field").hidden = true;
    byId("team-dialog").showModal();
    byId("team-name").focus();
  }

  function openEditTeam(teamId) {
    const team = state.identity?.teams.find((item) => item.id === teamId);
    if (!team) return;
    state.activeTeamId = team.id;
    byId("team-dialog-title").textContent = team.name;
    byId("team-dialog-copy").textContent = "Update details, lifecycle state, and membership.";
    byId("team-id-input").value = team.id;
    byId("team-id-input-wrap").hidden = true;
    byId("team-name").value = team.name;
    byId("team-description").value = team.description;
    byId("team-status").value = team.status;
    byId("team-status-wrap").hidden = false;
    byId("team-members-field").hidden = false;
    byId("team-member-picker").innerHTML = (state.identity?.users || []).map((user) => `<label><input type="checkbox" value="${escapeHtml(user.id)}" ${team.member_ids.includes(user.id) ? "checked" : ""}><span><strong>${escapeHtml(user.display_name)}</strong><small>${escapeHtml(presentableEmail(user) || user.id)}</small></span></label>`).join("") || `<p class="muted-copy">No users are available.</p>`;
    byId("team-dialog").showModal();
  }

  function openCreateUser() {
    state.activeUserId = null;
    byId("user-dialog-title").textContent = "Add user";
    byId("user-dialog-copy").textContent = "Create a user record for policy and team assignment.";
    byId("user-display-name").value = "";
    byId("user-primary-email").value = "";
    byId("user-status").value = "active";
    byId("user-status-wrap").hidden = true;
    byId("user-access-note").hidden = false;
    byId("user-dialog-footnote").textContent = "The user can be added to teams after creation.";
    byId("save-user").textContent = "Add user";
    byId("user-dialog").showModal();
    byId("user-display-name").focus();
  }

  function openEditUser(userId) {
    const user = state.identity?.users.find((item) => item.id === userId);
    if (!user) return;
    state.activeUserId = user.id;
    byId("user-dialog-title").textContent = user.display_name;
    byId("user-dialog-copy").textContent = user.id;
    byId("user-display-name").value = user.display_name;
    byId("user-primary-email").value = user.primary_email;
    byId("user-status").value = user.status;
    byId("user-status-wrap").hidden = false;
    byId("user-access-note").hidden = true;
    byId("user-dialog-footnote").textContent = "Suspended or disabled users cannot start new sessions.";
    byId("save-user").textContent = "Save user";
    byId("user-dialog").showModal();
  }

  async function identityMutation(path, fields) {
    const body = new URLSearchParams({ csrf_token: state.data.session.csrfToken, ...fields });
    const response = await fetch(path, { method: "POST", body, credentials: "same-origin", headers: { accept: "application/json" } });
    if (!response.ok) {
      const problem = await response.json().catch(() => ({}));
      throw new Error(problem.detail || "The identity change could not be saved.");
    }
    state.identity = await response.json();
    renderIdentity();
  }

  async function saveTeam(event) {
    event.preventDefault();
    const button = byId("save-team");
    button.disabled = true;
    try {
      if (!state.activeTeamId) {
        await identityMutation("/api/v1/ui/teams", { id: byId("team-id-input").value, name: byId("team-name").value, description: byId("team-description").value });
        byId("team-dialog").close();
        showToast("Team created.");
        return;
      }
      const teamId = state.activeTeamId;
      const original = state.identity.teams.find((team) => team.id === teamId);
      if (!original) throw new Error("The team no longer exists.");
      const selected = new Set([...byId("team-member-picker").querySelectorAll("input:checked")].map((input) => input.value));
      await identityMutation(`/api/v1/ui/teams/${encodeURIComponent(teamId)}`, { expected_version: original.version, name: byId("team-name").value, description: byId("team-description").value, status: byId("team-status").value });
      for (const user of state.identity.users) {
        const hadMember = original.member_ids.includes(user.id);
        const wantsMember = selected.has(user.id);
        if (hadMember !== wantsMember) await identityMutation(`/api/v1/ui/teams/${encodeURIComponent(teamId)}/members`, { user_id: user.id, action: wantsMember ? "add" : "remove" });
      }
      byId("team-dialog").close();
      showToast("Team updated.");
    } catch (error) { showToast(error.message || "The team could not be saved."); }
    finally { button.disabled = false; }
  }

  async function saveUser(event) {
    event.preventDefault();
    const button = byId("save-user");
    button.disabled = true;
    try {
      if (!state.activeUserId) {
        await identityMutation("/api/v1/ui/users", { display_name: byId("user-display-name").value, primary_email: byId("user-primary-email").value });
        byId("user-dialog").close();
        showToast("User added without UI access.");
        return;
      }
      const user = state.identity?.users.find((item) => item.id === state.activeUserId);
      if (!user) throw new Error("The user no longer exists.");
      await identityMutation(`/api/v1/ui/users/${encodeURIComponent(user.id)}`, { expected_version: user.version, display_name: byId("user-display-name").value, primary_email: byId("user-primary-email").value, status: byId("user-status").value });
      byId("user-dialog").close();
      showToast("User updated.");
    } catch (error) { showToast(error.message || "The user could not be saved."); }
    finally { button.disabled = false; }
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

  const repositorySections = new Set(["overview", "runs", "secrets", "variables", "settings"]);

  function repositoryRoute(repository = state.activeRepository, section = state.repositorySection) {
    if (!repository) return "repositories";
    return `repository/${encodeURIComponent(repository.organization)}/${encodeURIComponent(repository.name)}/${section}`;
  }

  function updateRoute(route, replace = false) {
    const repositoryPrefix = "repository/";
    const url = route.startsWith(repositoryPrefix)
      ? `${workspacePath}repositories/${route.slice(repositoryPrefix.length)}${location.search}`
      : `${workspacePath}${location.search}#${route}`;
    if (`${location.pathname}${location.search}${location.hash}` === url) return;
    history[replace ? "replaceState" : "pushState"](null, "", url);
  }

  function openRepository(id, section = "overview", updateHash = true) {
    const repository = state.data.repositories.find((item) => String(item.id) === String(id));
    if (!repository) return false;
    state.activeRepository = repository;
    state.repositorySettings = null;
    renderRepositorySettings();
    const runs = (state.data.runs || []).filter((run) => run.repositoryId === repository.id);
    const approvals = (state.data.approvals || []).filter((approval) => approval.repositoryId === repository.id);
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
    byId("repository-detail-summary").innerHTML = [["Source", repository.source], ["Visibility", repository.visibility], ["Default branch", repository.defaultBranch], ["Installation", repository.installationAccount]].map(([label, value]) => definitionCard(label, value)).join("");
    byId("repository-connection-state").textContent = repository.state;
    byId("repository-connection-state").className = `state-badge ${tone(repository.state)}`;
    byId("repository-connection-metadata").innerHTML = definitionLinkCard("GitHub repository", repository.key, repository.repositoryUrl) + definitionCard("External ID", repository.externalId);
    const pendingApprovals = approvals.filter((approval) => approval.status === "pending").length;
    byId("repository-execution-metadata").innerHTML = definitionCard("Runs", runs.length) + definitionCard("Pending approvals", pendingApprovals) + definitionCard("Latest activity", runs[0] ? formatDate(runs[0].createdAt) : "No runs yet");
    byId("repository-uninstall-name").textContent = repository.key;
    renderRepositoryRuns(runs);
    renderRepositoryApprovals(approvals);
    switchView("repository", false);
    setRepositorySection(section, false);
    if (updateHash) updateRoute(repositoryRoute());
    return true;
  }

  function renderRepositoryRuns(runs) {
    byId("repository-runs-body").innerHTML = runs.map((run) => `<tr><td><strong class="table-primary">${escapeHtml(run.source?.workflowName || "Workflow")}</strong><small><span class="mono" title="${escapeHtml(run.id)}">${escapeHtml(compactId(run.id))}</span> · ${escapeHtml(run.source?.jobCount ?? "—")} ${run.source?.jobCount === 1 ? "job" : "jobs"}</small></td><td class="run-trigger-cell">${runTriggerMarkup(run)}</td><td><span class="state-badge ${tone(run.status)}">${escapeHtml(titleCase(run.status))}</span></td><td class="date-cell">${escapeHtml(formatDate(run.startedAt || run.createdAt))}</td><td>${runActionsMarkup(run)}</td></tr>`).join("");
    byId("repository-runs-empty").hidden = runs.length > 0;
    byId("repository-runs-body").closest("table").hidden = runs.length === 0;
  }

  function renderRepositoryApprovals(approvals) {
    const pending = approvals.filter((approval) => approval.status === "pending").length;
    byId("repository-approval-count").textContent = pending;
    byId("repository-approval-count").hidden = pending === 0;
    byId("repository-approval-list").innerHTML = approvals.map(approvalRow).join("");
    byId("repository-approvals-empty").hidden = approvals.length > 0;
  }

  function setRepositorySection(section, updateHash = true) {
    if (!repositorySections.has(section)) section = "overview";
    state.repositorySection = section;
    document.querySelectorAll("[data-repository-panel]").forEach((panel) => { panel.hidden = panel.dataset.repositoryPanel !== section; });
    document.querySelectorAll("[data-repository-section]").forEach((button) => {
      const active = button.dataset.repositorySection === section;
      button.classList.toggle("active", active);
      if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
    });
    if (["secrets", "variables", "settings"].includes(section)) loadRepositorySettings();
    if (updateHash && state.activeRepository) updateRoute(repositoryRoute());
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

  function secretScope(scope = "") {
    const separator = scope.indexOf(":");
    const prefix = separator < 0 ? "" : scope.slice(0, separator);
    const id = separator < 0 ? scope : scope.slice(separator + 1);
    const kind = { tenant: "workspace", "scm-account": "scm_account", project: "project", repository: "repository" }[prefix] || "unknown";
    return { kind, id };
  }

  function secretScopeLabel(scope) {
    const inventory = state.secretInventory || { projects: [], scm_accounts: [], repositories: [] };
    if (scope.kind === "workspace") return state.data.session.tenantName || "Workspace";
    if (scope.kind === "project") return inventory.projects.find((item) => item.id === scope.id)?.name || scope.id;
    if (scope.kind === "scm_account") return inventory.scm_accounts.find((item) => item.id === scope.id)?.name || scope.id;
    if (scope.kind === "repository") {
      const repository = inventory.repositories.find((item) => item.id === scope.id);
      return repository ? `${repository.owner}/${repository.name}` : scope.id;
    }
    return scope.id;
  }

  function renderSecretInventory() {
    const inventory = state.secretInventory || { secrets: [], projects: [], scm_accounts: [], repositories: [] };
    const query = byId("secret-search").value.trim().toLowerCase();
    const filter = byId("secret-scope-filter").value;
    const rows = inventory.secrets.map((secret) => ({ ...secret, parsedScope: secretScope(secret.scope) })).filter((secret) => {
      const label = secretScopeLabel(secret.parsedScope);
      return (filter === "all" || filter === secret.parsedScope.kind) && `${secret.name} ${label}`.toLowerCase().includes(query);
    });
    byId("secret-visible-count").textContent = rows.length;
    byId("secret-total-count").textContent = `${inventory.secrets.length} total`;
    byId("secret-inventory-body").innerHTML = rows.map((secret) => {
      const scopeLabel = secretScopeLabel(secret.parsedScope);
      const actions = secret.status === "active" ? `<div class="setting-actions"><button class="setting-action" type="button" data-edit-scoped-secret="${escapeHtml(secret.name)}" data-secret-scope-kind="${escapeHtml(secret.parsedScope.kind)}" data-secret-scope-id="${escapeHtml(secret.parsedScope.id)}">Rotate</button><button class="setting-action danger-text" type="button" data-delete-scoped-secret="${escapeHtml(secret.name)}" data-secret-scope-kind="${escapeHtml(secret.parsedScope.kind)}" data-secret-scope-id="${escapeHtml(secret.parsedScope.id)}">Delete</button></div>` : "";
      return `<tr><td><strong class="mono setting-name">${escapeHtml(secret.name)}</strong><small>${escapeHtml(titleCase(secret.secret_type || "opaque"))}</small></td><td><span class="scope-chip">${escapeHtml(titleCase(secret.parsedScope.kind))}</span><small>${escapeHtml(scopeLabel)}</small></td><td>${escapeHtml(secret.provider)}</td><td><span class="state-badge ${tone(secret.status)}">${escapeHtml(titleCase(secret.status))}</span></td><td>${escapeHtml(secret.current_version ?? "External")}</td><td>${escapeHtml(formatDate(secret.updated_unix_ms))}</td><td>${actions}</td></tr>`;
    }).join("");
    byId("secret-inventory-empty").hidden = rows.length > 0;
    byId("secret-inventory-body").closest("table").hidden = rows.length === 0;

    byId("secret-project-count").textContent = `${inventory.projects.length} project${inventory.projects.length === 1 ? "" : "s"}`;
    byId("secret-project-list").innerHTML = inventory.projects.map((project) => {
      const targets = project.targets.map((target) => secretScopeLabel({ kind: target.kind, id: target.id }));
      return `<article class="secret-project-card"><div><span class="state-badge ${tone(project.status)}">${escapeHtml(titleCase(project.status))}</span><h3>${escapeHtml(project.name)}</h3><p>${escapeHtml(project.description || "No description")}</p><small>${escapeHtml(targets.length ? targets.join(" · ") : "No targets")}</small></div><button class="btn btn-secondary btn-inline btn-compact" type="button" data-edit-secret-project="${escapeHtml(project.id)}">Edit</button></article>`;
    }).join("");
    byId("secret-project-empty").hidden = inventory.projects.length > 0;
  }

  async function loadSecretInventory(force = false) {
    if (state.secretInventoryLoading || (state.secretInventory && !force)) return;
    state.secretInventoryLoading = true;
    try {
      const response = await fetch("/api/v1/ui/secrets", { credentials: "same-origin", headers: { accept: "application/json" }, cache: "no-store" });
      if (!response.ok) throw new Error(response.status === 403 ? "You do not have access to secrets." : "Could not load secrets.");
      state.secretInventory = await response.json();
      renderSecretInventory();
    } catch (error) { showToast(error.message || "Could not load secrets."); }
    finally { state.secretInventoryLoading = false; }
  }

  function secretScopeOptions() {
    const inventory = state.secretInventory || { projects: [], scm_accounts: [], repositories: [] };
    const options = [{ kind: "workspace", id: inventory.workspace_id, label: `Workspace · ${state.data.session.tenantName}` }];
    inventory.projects.filter((item) => item.status === "active").forEach((item) => options.push({ kind: "project", id: item.id, label: `Project · ${item.name}` }));
    inventory.scm_accounts.forEach((item) => options.push({ kind: "scm_account", id: item.id, label: `GitHub organization · ${item.name}` }));
    inventory.repositories.forEach((item) => options.push({ kind: "repository", id: item.id, label: `Repository · ${item.owner}/${item.name}` }));
    return options;
  }

  function openScopedSecret(name = "", scopeKind = "", scopeId = "") {
    const select = byId("scoped-secret-scope");
    const options = secretScopeOptions();
    select.innerHTML = options.map((option) => `<option value="${escapeHtml(`${option.kind}:${option.id}`)}">${escapeHtml(option.label)}</option>`).join("");
    if (scopeKind && scopeId) select.value = `${scopeKind}:${scopeId}`;
    select.disabled = Boolean(name);
    byId("scoped-secret-title").textContent = name ? "Rotate secret" : "Add secret";
    byId("scoped-secret-name").value = name;
    byId("scoped-secret-name").readOnly = Boolean(name);
    byId("scoped-secret-value").value = "";
    byId("scoped-secret-dialog").showModal();
    (name ? byId("scoped-secret-value") : byId("scoped-secret-name")).focus();
  }

  async function saveScopedSecret(event) {
    event.preventDefault();
    const button = byId("save-scoped-secret");
    const [scopeKind, ...scopeId] = byId("scoped-secret-scope").value.split(":");
    button.disabled = true; button.textContent = "Saving…";
    try {
      const body = new URLSearchParams({ csrf_token: state.data.session.csrfToken, idempotency_key: crypto.randomUUID(), scope_kind: scopeKind, scope_id: scopeId.join(":"), name: byId("scoped-secret-name").value.trim(), value: byId("scoped-secret-value").value });
      const response = await fetch("/api/v1/ui/secrets", { method: "POST", body, credentials: "same-origin" });
      if (!response.ok) { const problem = await response.json().catch(() => null); throw new Error(problem?.detail || "Could not save secret."); }
      byId("scoped-secret-dialog").close();
      state.secretInventory = null; await loadSecretInventory(true); showToast("Secret saved.");
    } catch (error) { showToast(error.message || "Could not save secret."); }
    finally { byId("scoped-secret-value").value = ""; button.disabled = false; button.textContent = "Save secret"; }
  }

  function openSecretProject(projectId = "") {
    const project = state.secretInventory?.projects.find((item) => item.id === projectId);
    byId("secret-project-title").textContent = project ? "Edit project" : "New project";
    byId("secret-project-id").value = project?.id || "";
    byId("secret-project-version").value = project?.version || 0;
    byId("secret-project-name").value = project?.name || "";
    byId("secret-project-description").value = project?.description || "";
    const selected = new Set((project?.targets || []).map((target) => `${target.kind}:${target.id}`));
    const targets = secretScopeOptions().filter((item) => ["scm_account", "repository"].includes(item.kind));
    byId("secret-project-targets").innerHTML = targets.map((target) => `<label class="project-target-option"><input type="checkbox" value="${escapeHtml(`${target.kind}:${target.id}`)}" ${selected.has(`${target.kind}:${target.id}`) ? "checked" : ""}><span>${escapeHtml(target.label)}</span></label>`).join("") || `<p class="muted-copy">Connect a GitHub organization or repository first.</p>`;
    byId("secret-project-dialog").showModal();
    byId("secret-project-name").focus();
  }

  async function saveSecretProject(event) {
    event.preventDefault();
    const button = byId("save-secret-project");
    const targets = [...byId("secret-project-targets").querySelectorAll("input:checked")].map((input) => { const [kind, ...id] = input.value.split(":"); return { kind, id: id.join(":") }; });
    button.disabled = true; button.textContent = "Saving…";
    try {
      const body = new URLSearchParams({ csrf_token: state.data.session.csrfToken, id: byId("secret-project-id").value, expected_version: byId("secret-project-version").value, name: byId("secret-project-name").value.trim(), description: byId("secret-project-description").value.trim(), targets: JSON.stringify(targets) });
      const response = await fetch("/api/v1/ui/secret-projects", { method: "POST", body, credentials: "same-origin" });
      if (!response.ok) { const problem = await response.json().catch(() => null); throw new Error(problem?.detail || "Could not save project."); }
      byId("secret-project-dialog").close();
      state.secretInventory = null; await loadSecretInventory(true); showToast("Project saved.");
    } catch (error) { showToast(error.message || "Could not save project."); }
    finally { button.disabled = false; button.textContent = "Save project"; }
  }

  function openScopedSecretDelete(name, scopeKind, scopeId) {
    state.pendingScopedSecretDelete = { name, scopeKind, scopeId };
    byId("delete-setting-title").textContent = "Delete secret?";
    byId("delete-setting-name").textContent = name;
    byId("confirm-delete-setting").textContent = "Delete secret";
    byId("delete-setting-dialog").showModal();
  }

  async function deleteScopedSecret() {
    const pending = state.pendingScopedSecretDelete;
    if (!pending) return;
    const button = byId("confirm-delete-setting");
    button.disabled = true; button.textContent = "Deleting…";
    try {
      const body = new URLSearchParams({ csrf_token: state.data.session.csrfToken, scope_kind: pending.scopeKind, scope_id: pending.scopeId, name: pending.name });
      const response = await fetch("/api/v1/ui/secrets/delete", { method: "POST", body, credentials: "same-origin" });
      if (!response.ok) { const problem = await response.json().catch(() => null); throw new Error(problem?.detail || "Could not delete secret."); }
      byId("delete-setting-dialog").close(); state.secretInventory = null; await loadSecretInventory(true); showToast("Secret deleted.");
    } catch (error) { showToast(error.message || "Could not delete secret."); }
    finally { state.pendingScopedSecretDelete = null; button.disabled = false; button.textContent = "Delete secret"; }
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
    finally { state.repositoryUninstalling = false; button.disabled = false; button.textContent = "Disconnect repository"; }
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
    if (state.pendingScopedSecretDelete) return deleteScopedSecret();
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
    byId("record-detail-dialog").classList.remove("approval-dialog");
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
    const source = run.source || {};
    byId("run-source-card").innerHTML = runSourceCardMarkup(run);
    byId("run-summary").innerHTML = [
      ["Status", `<span class="state-badge ${tone(run.status)}">${escapeHtml(titleCase(run.status))}</span>`],
      ["Duration", escapeHtml(duration)],
      ["Started", escapeHtml(formatDate(run.startedAt))],
      ["Completed", escapeHtml(formatDate(run.completedAt))],
    ].map(([label, value]) => `<div><span>${label}</span><strong>${value}</strong></div>`).join("");
    byId("run-identifiers").innerHTML = `<div><dt>Workflow</dt><dd>${escapeHtml(source.workflowName || "Not recorded")}</dd></div><div><dt>Execution</dt><dd>${run.remote ? "Remote runner" : "Local"}${run.priority ? ` · Priority ${escapeHtml(run.priority)}` : ""}</dd></div><div><dt>Run ID</dt><dd class="mono">${escapeHtml(run.id)}</dd></div><div><dt>Capsule ID</dt><dd class="mono">${escapeHtml(run.planId)}</dd></div>${run.cancelReason ? `<div><dt>Cancel reason</dt><dd>${escapeHtml(run.cancelReason)}</dd></div>` : ""}`;

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
    const retry = byId("retry-run");
    const retryQueued = state.retryingRuns.has(run.id);
    retry.disabled = !run.canRetry || retryQueued;
    retry.textContent = retryQueued ? "Retry queued" : "Retry run";
    retry.title = retryQueued ? "Retry queued" : run.canRetry ? "" : "Retry is available for completed GitHub event runs";
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
    byId("run-detail-title").textContent = run.source?.workflowName || `Run ${compactId(run.id).replace(/^run-/, "")}`;
    byId("run-detail-copy").textContent = `${run.repository} · ${runEventLabel(run)}`;
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

  async function retryRun(id, button) {
    const run = (state.data.runs || []).find((item) => item.id === id);
    if (!run?.canRetry || state.retryingRuns.has(id)) return;
    const originalText = button?.textContent || "Retry";
    if (button) {
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
      button.textContent = "Queuing…";
    }
    try {
      const body = new URLSearchParams({
        csrf_token: state.data.session.csrfToken,
        idempotency_key: crypto.randomUUID(),
      });
      const response = await fetch(`/api/v1/ui/runs/${encodeURIComponent(id)}/retry`, { method: "POST", body, credentials: "same-origin", headers: { accept: "application/json" } });
      if (!response.ok) {
        const problem = await response.json().catch(() => ({}));
        throw new Error(problem.detail || (response.status === 403 ? "You are not authorized to retry this run." : "The run could not be retried."));
      }
      state.retryingRuns.add(id);
      renderRuns();
      if (state.activeRepository) renderRepositoryRuns((state.data.runs || []).filter((item) => item.repositoryId === state.activeRepository.id));
      if (state.activeRunId === id && state.activeRunDetails) renderRunDetail(run, state.activeRunDetails);
      showToast("Retry queued from the original GitHub event. A new run will appear shortly.");
    } catch (error) {
      showToast(error.message || "The run could not be retried.");
      if (button) {
        button.disabled = false;
        button.textContent = originalText;
      }
    } finally {
      if (button) button.removeAttribute("aria-busy");
    }
  }

  function openApproval(id) {
    const approval = (state.data.approvals || []).find((item) => item.id === id);
    if (!approval) return;
    const waitingPullRequests = approval.waitingPullRequests || [];
    const trigger = waitingPullRequests.length
      ? `Pull request${waitingPullRequests.length === 1 ? "" : "s"} ${waitingPullRequests.map((number) => `#${number}`).join(", ")}`
      : approval.source?.pullRequest
        ? `Pull request #${approval.source.pullRequest}`
        : `${titleCase(approval.source?.event || "Repository event")}${approval.source?.action ? ` · ${titleCase(approval.source.action)}` : ""}`;
    const reasons = (approval.reasons || []).map((reason) => `<li><strong>${escapeHtml(approvalReasonTitle(reason))}</strong><span>${escapeHtml(approvalReasonDescription(reason))}</span></li>`).join("");
    const permissions = approvalPermissionSummary(approval.permissions).map((permission) => `<li><div class="approval-access-copy"><span>${escapeHtml(permission.label)}</span>${(permission.details || []).map((detail) => `<small>${escapeHtml(detail)}</small>`).join("")}</div><strong class="${permission.elevated ? "danger-text" : ""}">${escapeHtml(permission.value)}</strong></li>`).join("");
    const jobs = (approval.jobs || []).map((job) => `<li><span class="job-index" aria-hidden="true">${escapeHtml((approval.jobs || []).indexOf(job) + 1)}</span><div><strong>${escapeHtml(job.name || job.id)}</strong><small class="mono">${escapeHtml(job.id)}</small></div></li>`).join("");
    const decisions = (approval.decisions || []).map((decision) => `<li><div><strong>${escapeHtml(titleCase(decision.decision))} by ${escapeHtml(decision.actor)}</strong><small>${escapeHtml(formatDate(decision.decidedAt))}</small></div><span>${escapeHtml(decision.reason)}</span></li>`).join("");
    const reusableGrant = approval.kind === "privileged-execution" && approval.oneShot === false;
    showRecordDetails("Approval request", approvalTitle(approval), `${approval.repository} · ${trigger}`, []);
    byId("record-detail-dialog").classList.add("approval-dialog");
    byId("record-detail-grid").innerHTML = `<div class="approval-review">
      <section class="approval-review-lead"><div><span class="state-badge ${tone(approval.status)}">${escapeHtml(titleCase(approval.status))}</span><h3>${escapeHtml(approval.workflow?.name || "Workflow execution")}</h3><p>Review the exact execution plan and requested access before deciding.</p></div><div class="risk-score ${approval.riskScore >= 70 ? "high" : ""}"><span>Risk</span><strong>${escapeHtml(approval.riskScore)}</strong></div></section>
      <section class="approval-review-section"><h3>What will run</h3><div class="approval-context-grid"><div><span>Repository</span><strong>${escapeHtml(approval.repository)}</strong></div><div><span>Workflow</span><strong>${escapeHtml(approval.workflow?.name || "Not recorded")}</strong><small class="mono">${escapeHtml(approval.workflow?.path || "")}</small></div><div><span>Trigger</span><strong>${escapeHtml(trigger)}</strong></div><div><span>Source commit</span><strong class="mono">${escapeHtml(compactId(approval.source?.commit, 12))}</strong><small>${escapeHtml(approval.source?.ref || "Repository source")}</small></div></div></section>
      <section class="approval-review-section"><h3>Why approval is required</h3><p>${escapeHtml(approvalKindDescription(approval.kind, approval.oneShot))}</p><ul class="approval-reason-list">${reasons || "<li><strong>Policy review</strong><span>The active policy requires a human decision for this capability set.</span></li>"}</ul></section>
      <section class="approval-review-section"><h3>Access requested</h3><ul class="approval-access-list">${permissions || "<li><span>Additional access</span><strong>None</strong></li>"}</ul></section>
      <section class="approval-review-section"><h3>Jobs (${escapeHtml(approval.jobs?.length || 0)})</h3><ul class="approval-job-list">${jobs || "<li><div><strong>No jobs recorded</strong></div></li>"}</ul></section>
      ${decisions ? `<section class="approval-review-section"><h3>Decisions</h3><ul class="approval-decision-list">${decisions}</ul></section>` : ""}
      <details class="approval-exact-plan"><summary>${reusableGrant ? "Capability identity" : "Exact-plan identity"}</summary><dl><div><dt>Capsule</dt><dd class="mono">${escapeHtml(approval.capsuleId)}</dd></div><div><dt>${reusableGrant ? "Capability digest" : "Subject digest"}</dt><dd class="mono">${escapeHtml(approval.subjectDigest)}</dd></div><div><dt>Rule</dt><dd class="mono">${escapeHtml(approval.ruleId)}</dd></div><div><dt>Requested</dt><dd>${escapeHtml(formatDate(approval.createdAt))}</dd></div><div><dt>${approval.status === "approved" && reusableGrant ? "Valid until" : "Approval deadline"}</dt><dd>${escapeHtml(formatDate(approval.expiresAt))}</dd></div></dl><p>${reusableGrant ? "This grant authorizes future matching executions for this repository until it expires. A workflow, action, access, or policy change creates a new approval request." : "This approval authorizes one execution of this exact plan. If it is not approved before the deadline, the request expires and the run will not start."}</p></details>
    </div>`;
    if (approval.status === "pending" && approval.canDecide) {
      state.activeApprovalId = approval.id;
      byId("approve-workflow-approval").hidden = false;
      byId("deny-workflow-approval").hidden = false;
      byId("record-detail-footer-copy").textContent = reusableGrant ? "Approval grants this unchanged workflow capability set until it expires." : "Approval authorizes this exact execution once and must be decided before the deadline.";
    } else {
      byId("record-detail-footer-copy").textContent = approval.status === "pending" ? "You do not have permission to decide this request." : `This request is ${titleCase(approval.status).toLowerCase()}.`;
    }
  }

  function approvalTitle(approval) {
    if (approval.kind === "privileged-execution" && approval.oneShot === false) return "Approve workflow capabilities";
    return approval.kind === "privileged-execution" ? "Approve privileged execution" : "Approve workflow changes";
  }

  function approvalKindDescription(kind, oneShot = true) {
    if (kind === "privileged-execution" && oneShot === false) return "This unchanged workflow requests capabilities that can change repository or external state. Approval grants this exact capability set to matching executions in this repository until it expires.";
    if (kind === "privileged-execution") return "This plan requests capabilities that can change repository or external state. Approval releases only this signed plan to the runner.";
    return "The workflow definition or execution inputs changed. Approval authorizes only the reviewed definition and source commit.";
  }

  function approvalReasonTitle(code) {
    const titles = {
      "scm-contents-write": "Repository contents write",
      "scm-issues-write": "Issue write access",
      "scm-pull-requests-write": "Pull request write access",
      "scm-statuses-write": "Commit status write access",
      "secret-access": "Secret access",
      "step-secret-access": "Step secret access",
      "network-egress": "Network access",
      "wildcard-network-egress": "Unrestricted network access",
      "oidc-access": "OIDC identity access",
      "signing-access": "Signing access",
      "verified-cache-write": "Verified cache write",
      "repository-write": "Repository write access",
    };
    return titles[code] || titleCase(code);
  }

  function approvalReasonDescription(code) {
    const descriptions = {
      "scm-contents-write": "The workflow can create or modify repository content.",
      "scm-issues-write": "The workflow can create or update issues and comments.",
      "scm-pull-requests-write": "The workflow can create or update pull requests.",
      "scm-statuses-write": "The workflow can publish statuses on commits.",
      "secret-access": "The plan can receive one or more protected secret values.",
      "step-secret-access": "A workflow step can receive protected secret values.",
      "network-egress": "The plan can connect to approved external destinations.",
      "wildcard-network-egress": "The plan can connect to destinations not individually listed.",
      "oidc-access": "The plan can request a workload identity token.",
      "signing-access": "The plan can request a protected signing operation.",
      "verified-cache-write": "The plan can update shared verified cache state.",
      "repository-write": "The workflow can modify checked-out repository content.",
    };
    return descriptions[code] || "This capability raised the plan's policy risk and requires review.";
  }

  function approvalPermissionSummary(permissions = {}) {
    const entries = [];
    const add = (label, value, details = []) => { if (value && value !== "deny") entries.push({ label, value: titleCase(value), elevated: value === "write" || value === "allow", details }); };
    add("Repository", permissions.repository);
    Object.entries(permissions.scm || {}).forEach(([name, value]) => add(`GitHub ${titleCase(name)}`, value));
    add("Checks", permissions.checks); add("Artifacts", permissions.artifacts); add("Registry", permissions.registry);
    if (permissions.network?.mode && permissions.network.mode !== "deny") {
      const destinations = (permissions.network.destinations || []).map((destination) => {
        const host = destination.host || "Any host";
        const port = destination.port ? `:${destination.port}` : "";
        const protocol = destination.protocol ? ` (${String(destination.protocol).toUpperCase()})` : "";
        return `${host}${port}${protocol}`;
      });
      const details = [
        destinations.length ? `Destinations: ${destinations.join(", ")}` : "Destinations: Any destination",
        `DNS: ${titleCase(permissions.network.dns || "Not specified")}`,
        `Private network ranges: ${permissions.network.deny_private_ranges ? "Blocked" : "Allowed"}`,
      ];
      if (permissions.network.listen?.length) details.push(`Listening ports: ${permissions.network.listen.join(", ")}`);
      add("Network", permissions.network.mode, details);
    }
    if (permissions.secrets?.length) {
      const details = permissions.secrets.map((secret) => {
        if (typeof secret === "string") return secret;
        const name = secret?.name || "Protected secret";
        return secret?.purpose ? `${name} · ${titleCase(secret.purpose)}` : name;
      });
      entries.push({ label: "Secrets", value: `${permissions.secrets.length} requested`, elevated: true, details });
    }
    if (permissions.oidc_audiences?.length) entries.push({ label: "OIDC audiences", value: `${permissions.oidc_audiences.length} requested`, elevated: true });
    if (permissions.signing?.length) entries.push({ label: "Signing capabilities", value: `${permissions.signing.length} requested`, elevated: true });
    return entries;
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
      if (!response.ok) throw new Error(response.status === 403 ? "You are not authorized to decide this approval." : "The approval decision could not be recorded.");
      const result = await response.json();
      approval.status = result.status;
      approval.decisionCount = Number(approval.decisionCount || 0) + (result.replayed ? 0 : 1);
      approval.remainingApprovals = result.status === "approved" ? 0 : approval.remainingApprovals;
      renderApprovals();
      renderRepositories();
      if (state.activeRepository) renderRepositoryApprovals((state.data.approvals || []).filter((item) => item.repositoryId === state.activeRepository.id));
      byId("record-detail-dialog").close();
      showToast(decision === "approve" ? "Execution approved. Runtrue is preparing the run." : "Execution rejected.");
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
    const allowed = ["repositories", "repository", "organization", "secrets", "github", "identity", "runs", "approvals", "runners", "api-tokens", "audit"];
    const target = document.querySelector(`[data-view="${view}"]`);
    const capability = target?.dataset.capability;
    if (!allowed.includes(view) || !target || (capability && !state.data.capabilities?.[capability])) view = "repositories";
    document.querySelectorAll("[data-view]").forEach((element) => { element.hidden = element.dataset.view !== view; });
    document.querySelectorAll("[data-view-target]").forEach((button) => {
      const active = button.dataset.viewTarget === view || (view === "repository" && button.dataset.viewTarget === "repositories");
      button.classList.toggle("active", active);
      if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
    });
    if (updateHash) updateRoute(view === "repository" ? repositoryRoute() : view);
    if (view === "organization") loadOrganizationSettings();
    if (view === "secrets") loadSecretInventory();
    if (view === "identity") loadIdentity();
    closeNavigation();
    document.querySelector(`[data-view="${view}"] h1`)?.focus({ preventScroll: true });
    return view;
  }

  function restoreRoute() {
    const repositoryPathPrefix = `${workspacePath}repositories/`;
    const route = location.pathname.startsWith(repositoryPathPrefix)
      ? `repository/${location.pathname.slice(repositoryPathPrefix.length)}`
      : location.hash.slice(1);
    const parts = route.split("/");
    if (parts[0] === "repository" && parts.length >= 3) {
      let organization;
      let name;
      try {
        organization = decodeURIComponent(parts[1]);
        name = decodeURIComponent(parts[2]);
      } catch {
        organization = "";
        name = "";
      }
      const repository = state.data.repositories.find((item) => item.organization === organization && item.name === name);
      if (repository) {
        const section = repositorySections.has(parts[3]) ? parts[3] : "overview";
        openRepository(repository.id, section, false);
        updateRoute(repositoryRoute(), true);
        return;
      }
    }
    const requestedView = parts.length === 1 ? parts[0] : "repositories";
    const view = switchView(requestedView, false);
    if (route !== view) updateRoute(view, true);
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
      const active = organization.id === state.activeOrganization;
      return `<button class="org-option ${active ? "active" : ""}" type="button" role="option" aria-selected="${active}" data-org-id="${escapeHtml(organization.id)}"><span class="org-avatar">${escapeHtml(organization.initials)}</span><strong>${escapeHtml(organization.name)}</strong><span>${count}</span></button>`;
    }).join("") : `<div class="org-empty"><h4>${empty[0]}</h4><p>${empty[1]}</p></div>`;
    byId("org-list").querySelectorAll("[data-org-id]").forEach((button) => button.addEventListener("click", () => selectOrganization(button.dataset.orgId)));
  }

  function repositoryKey(repository) {
    return `${repository.state}:${repository.externalRepositoryId}`;
  }

  function repositoriesAreCompatible(first, candidate) {
    if (!first || first.state !== candidate.state) return false;
    if (!["needs_installation", "existing_installation"].includes(first.state)) return true;
    return first.ownerId === candidate.ownerId;
  }

  function visibleSelectableRepositories() {
    const organization = state.data.organizations.find((item) => item.id === state.activeOrganization);
    if (!organization || organization.repositoriesStatus !== "ready") return [];
    const query = byId("repo-search").value.trim().toLowerCase();
    return organization.repositories.filter((repository) => repository.state !== "added" && repository.name.toLowerCase().includes(query));
  }

  function updateSelectAll() {
    const button = byId("select-all-repositories");
    const visible = visibleSelectableRepositories();
    const selected = [...state.selectedRepositories.values()];
    const reference = selected[0] || visible[0];
    const compatible = visible.filter((repository) => repositoriesAreCompatible(reference, repository));
    const allSelected = compatible.length > 0 && compatible.every((repository) => state.selectedRepositories.has(repositoryKey(repository)));
    button.disabled = compatible.length === 0;
    button.textContent = allSelected ? "Clear" : "Select all";
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
      const key = repositoryKey(repository);
      const selected = state.selectedRepositories.has(key);
      const status = repository.state === "existing_installation" ? "Import repository" : repository.state === "needs_installation" ? "Install App" : repository.visibility;
      return `<label class="repo-option ${selected ? "selected" : ""}"><input type="checkbox" data-repository-key="${escapeHtml(key)}" ${selected ? "checked" : ""}><span><strong>${escapeHtml(repository.name)}</strong><small>${escapeHtml(repository.defaultBranch)}</small></span><span>${escapeHtml(status)}</span></label>`;
    }).join("") : `<div class="repo-empty">No matching repositories.</div>`;
    byId("repo-list").querySelectorAll("[data-repository-key]").forEach((input) => input.addEventListener("change", () => {
      const repository = organization.repositories.find((item) => repositoryKey(item) === input.dataset.repositoryKey);
      if (input.checked) {
        const selected = [...state.selectedRepositories.values()];
        const incompatible = selected.find((item) => !repositoriesAreCompatible(item, repository));
        if (incompatible) {
          state.selectedRepositories.clear();
          showToast(incompatible.state !== repository.state ? "Select repositories to add or install in one step at a time." : "Install the App on one GitHub account at a time.");
        }
        state.selectedRepositories.set(input.dataset.repositoryKey, repository);
      } else state.selectedRepositories.delete(input.dataset.repositoryKey);
      updateSelection(); renderRepositoryChoices();
    }));
    updateSelectAll();
  }

  function updateSelection() {
    const selected = [...state.selectedRepositories.values()];
    const requiresInstallation = selected.some((repository) => repository.state === "needs_installation");
    const importsExisting = selected.some((repository) => repository.state === "existing_installation");
    byId("selection-count").textContent = selected.length;
    byId("confirm-add").disabled = selected.length === 0;
    byId("confirm-add").textContent = requiresInstallation ? "Install selected" : importsExisting ? "Import selected" : "Add selected";
    updateSelectAll();
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
      organization.repositoriesStatus = loaded ? "ready" : "unavailable";
    } catch (error) {
      if (requestId !== state.repositoryRequestId) return;
      organization.repositoriesStatus = "unavailable";
      state.data.userCatalog = { status: "unavailable" };
      showToast(error.message || "Could not load GitHub repositories.");
    }
    renderOrganizations(); renderRepositoryChoices(); updateSelection(); updateGitHubDialogActions();
  }

  function selectOrganization(organizationId) {
    const changed = state.activeOrganization !== organizationId;
    state.activeOrganization = organizationId;
    byId("repo-search").value = "";
    if (changed) state.selectedRepositories.clear();
    renderOrganizations(); renderRepositoryChoices();
    loadOrganizationRepositories(organizationId);
  }

  function toggleVisibleRepositories() {
    const visible = visibleSelectableRepositories();
    const selected = [...state.selectedRepositories.values()];
    const reference = selected[0] || visible[0];
    const compatible = visible.filter((repository) => repositoriesAreCompatible(reference, repository));
    const allSelected = compatible.length > 0 && compatible.every((repository) => state.selectedRepositories.has(repositoryKey(repository)));
    if (allSelected) compatible.forEach((repository) => state.selectedRepositories.delete(repositoryKey(repository)));
    else compatible.forEach((repository) => state.selectedRepositories.set(repositoryKey(repository), repository));
    if (!allSelected && compatible.length < visible.length) showToast("Selected repositories that use the same add action.");
    renderRepositoryChoices(); updateSelection();
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
    submitLocalForm("/github/installations/start", fields);
  }

  function refreshGitHubAccess() {
    location.assign(`/auth/login?return_to=${encodeURIComponent(`${location.pathname}${location.search}`)}`);
  }

  async function reloadGitHubData() {
    if (state.data.userCatalog?.status === "reauthentication_required") return refreshGitHubAccess();
    await loadOrganizations({ preserveSelection: true, reloadSelected: true });
  }

  async function refreshRepositoryRuns() {
    if (!state.activeRepository || state.repositoryRunsRefreshing) return;
    const button = byId("refresh-repository-runs");
    state.repositoryRunsRefreshing = true;
    button.disabled = true;
    button.setAttribute("aria-busy", "true");
    button.textContent = "Refreshing…";
    try {
      const response = await fetch("/api/v1/ui/github", { credentials: "same-origin", headers: { accept: "application/json" }, cache: "no-store" });
      if (response.status === 401) return showLogin();
      if (!response.ok) throw new Error("Could not refresh repository runs.");
      const dashboard = await response.json();
      state.data.runs = dashboard.runs || [];
      configureRunFilters();
      renderRuns();
      if (state.activeRepository) {
        const runs = state.data.runs.filter((run) => run.repositoryId === state.activeRepository.id);
        renderRepositoryRuns(runs);
        byId("repository-execution-metadata").innerHTML = definitionCard("Runs", runs.length) + definitionCard("Latest activity", runs[0] ? formatDate(runs[0].createdAt) : "No runs yet");
      }
      showToast("Repository runs refreshed.");
    } catch (error) {
      showToast(error.message || "Could not refresh repository runs.");
    } finally {
      state.repositoryRunsRefreshing = false;
      button.disabled = false;
      button.removeAttribute("aria-busy");
      button.textContent = "Refresh runs";
    }
  }

  async function logout() {
    const body = new URLSearchParams({ csrf_token: state.data.session.csrfToken });
    const response = await fetch("/auth/session/logout", { method: "POST", body, credentials: "same-origin" });
    if (response.ok) location.assign("/"); else showToast("Could not end the current session.");
  }

  async function addSelectedRepositories() {
    const button = byId("confirm-add"); button.disabled = true; button.textContent = "Adding…";
    try {
      for (const repository of state.selectedRepositories.values()) {
        const body = new URLSearchParams({ csrf_token: repository.csrfToken, installation_id: repository.installationId, external_repository_id: repository.externalRepositoryId });
        const response = await fetch("/ui/github/repositories/link", { method: "POST", body, credentials: "same-origin" });
        if (!response.ok) throw new Error(`Repository link failed (${response.status})`);
      }
      location.assign("/?github=linked");
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
    byId("github-signin").addEventListener("click", () => refreshGitHubAccess());
    byId("logout").addEventListener("click", logout);
    byId("catalog-search").addEventListener("input", renderRepositories);
    document.querySelectorAll("[data-source]").forEach((button) => button.addEventListener("click", () => { state.repositorySource = button.dataset.source; document.querySelectorAll("[data-source]").forEach((item) => { const active = item === button; item.classList.toggle("active", active); item.setAttribute("aria-pressed", String(active)); }); renderRepositories(); }));
    byId("run-search").addEventListener("input", renderRuns); byId("run-status-filter").addEventListener("change", renderRuns);
    document.querySelectorAll("[data-approval-status]").forEach((button) => button.addEventListener("click", () => { state.approvalFilter = button.dataset.approvalStatus; document.querySelectorAll("[data-approval-status]").forEach((item) => item.classList.toggle("active", item === button)); renderApprovals(); }));
    byId("audit-search").addEventListener("input", renderAudit);
    byId("audit-action-filter").addEventListener("change", renderAudit);
    byId("audit-result-filter").addEventListener("change", renderAudit);
    byId("secret-search").addEventListener("input", renderSecretInventory);
    byId("secret-scope-filter").addEventListener("change", renderSecretInventory);
    byId("identity-user-search").addEventListener("input", renderIdentity);
    document.querySelectorAll("[data-view-target]").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.viewTarget)));
    byId("catalog-content").addEventListener("click", (event) => { const button = event.target.closest("[data-open-repository]"); if (button) openRepository(button.dataset.openRepository); });
    document.addEventListener("click", (event) => { const run = event.target.closest("[data-open-run]"); const retry = event.target.closest("[data-retry-run]"); const approval = event.target.closest("[data-open-approval]"); const token = event.target.closest("[data-open-token]"); const secret = event.target.closest("[data-edit-secret]"); const scopedSecret = event.target.closest("[data-edit-scoped-secret]"); const scopedDelete = event.target.closest("[data-delete-scoped-secret]"); const project = event.target.closest("[data-edit-secret-project]"); const deleteSetting = event.target.closest("[data-delete-setting]"); const variable = event.target.closest("[data-edit-variable]"); const team = event.target.closest("[data-edit-team]"); const user = event.target.closest("[data-edit-user]"); if (run) openRun(run.dataset.openRun); if (retry) retryRun(retry.dataset.retryRun, retry); if (approval) openApproval(approval.dataset.openApproval); if (token) openToken(token.dataset.openToken); if (secret) openSetting(secret.dataset.settingScope || "repository", "secret", secret.dataset.editSecret); if (scopedSecret) openScopedSecret(scopedSecret.dataset.editScopedSecret, scopedSecret.dataset.secretScopeKind, scopedSecret.dataset.secretScopeId); if (scopedDelete) openScopedSecretDelete(scopedDelete.dataset.deleteScopedSecret, scopedDelete.dataset.secretScopeKind, scopedDelete.dataset.secretScopeId); if (project) openSecretProject(project.dataset.editSecretProject); if (deleteSetting) openDeleteSetting(deleteSetting.dataset.deleteSetting, deleteSetting.dataset.settingName, deleteSetting.dataset.settingScope || "repository"); if (variable) openSetting(variable.dataset.settingScope || "repository", "variable", variable.dataset.editVariable); if (team) openEditTeam(team.dataset.editTeam); if (user) openEditUser(user.dataset.editUser); });
    byId("back-to-repositories").addEventListener("click", () => switchView("repositories"));
    document.querySelectorAll("[data-repository-section]").forEach((button) => button.addEventListener("click", () => setRepositorySection(button.dataset.repositorySection)));
    byId("refresh-repository-runs").addEventListener("click", refreshRepositoryRuns);
    byId("mobile-menu").addEventListener("click", openNavigation); byId("sidebar-scrim").addEventListener("click", closeNavigation);
    byId("open-add-dialog").addEventListener("click", openAddDialog); byId("manage-github").addEventListener("click", submitInstallAction); byId("dialog-manage-github").addEventListener("click", submitInstallAction); byId("dialog-refresh-github").addEventListener("click", reloadGitHubData);
    byId("close-dialog").addEventListener("click", () => byId("add-repo-dialog").close()); byId("cancel-add").addEventListener("click", () => byId("add-repo-dialog").close()); byId("confirm-add").addEventListener("click", confirmSelectedRepositories); byId("select-all-repositories").addEventListener("click", toggleVisibleRepositories);
    byId("org-search").addEventListener("input", renderOrganizations); byId("repo-search").addEventListener("input", renderRepositoryChoices);
    byId("run-log-filter").addEventListener("change", renderRunLogs);
    byId("retry-run-detail").addEventListener("click", () => { if (state.activeRunId) openRun(state.activeRunId); });
    byId("retry-run").addEventListener("click", (event) => { if (state.activeRunId) retryRun(state.activeRunId, event.currentTarget); });
    const closeRunDetail = () => { state.activeRunId = null; state.activeRunDetails = null; byId("run-detail-dialog").close(); };
    byId("close-run-detail").addEventListener("click", closeRunDetail); byId("dismiss-run-detail").addEventListener("click", closeRunDetail);
    byId("run-detail-dialog").addEventListener("close", () => { state.activeRunId = null; state.activeRunDetails = null; });
    byId("close-record-detail").addEventListener("click", () => byId("record-detail-dialog").close()); byId("dismiss-record-detail").addEventListener("click", () => byId("record-detail-dialog").close());
    byId("approve-workflow-approval").addEventListener("click", () => decideWorkflowApproval("approve")); byId("deny-workflow-approval").addEventListener("click", () => decideWorkflowApproval("deny"));
    byId("add-repository-secret").addEventListener("click", () => openRepositorySetting("secret"));
    byId("add-repository-variable").addEventListener("click", () => openRepositorySetting("variable"));
    byId("add-organization-secret").addEventListener("click", () => openOrganizationSetting("secret"));
    byId("add-organization-variable").addEventListener("click", () => openOrganizationSetting("variable"));
    byId("add-scoped-secret").addEventListener("click", () => openScopedSecret());
    byId("add-secret-project").addEventListener("click", () => openSecretProject());
    byId("scoped-secret-form").addEventListener("submit", saveScopedSecret);
    byId("close-scoped-secret").addEventListener("click", () => byId("scoped-secret-dialog").close());
    byId("cancel-scoped-secret").addEventListener("click", () => byId("scoped-secret-dialog").close());
    byId("secret-project-form").addEventListener("submit", saveSecretProject);
    byId("close-secret-project").addEventListener("click", () => byId("secret-project-dialog").close());
    byId("cancel-secret-project").addEventListener("click", () => byId("secret-project-dialog").close());
    byId("open-create-user").addEventListener("click", openCreateUser);
    byId("open-create-team").addEventListener("click", openCreateTeam);
    byId("team-form").addEventListener("submit", saveTeam);
    byId("user-form").addEventListener("submit", saveUser);
    byId("close-team-dialog").addEventListener("click", () => byId("team-dialog").close());
    byId("cancel-team-dialog").addEventListener("click", () => byId("team-dialog").close());
    byId("close-user-dialog").addEventListener("click", () => byId("user-dialog").close());
    byId("cancel-user-dialog").addEventListener("click", () => byId("user-dialog").close());
    byId("repository-setting-form").addEventListener("submit", saveRepositorySetting);
    byId("repository-workflow-directory-form").addEventListener("submit", saveRepositoryWorkflowDirectory);
    byId("close-repository-setting").addEventListener("click", () => byId("repository-setting-dialog").close());
    byId("cancel-repository-setting").addEventListener("click", () => byId("repository-setting-dialog").close());
    byId("cancel-delete-setting").addEventListener("click", () => byId("delete-setting-dialog").close());
    byId("confirm-delete-setting").addEventListener("click", deleteRepositorySetting);
    byId("delete-setting-dialog").addEventListener("close", () => { state.pendingSettingDelete = null; state.pendingScopedSecretDelete = null; });
    byId("open-uninstall-repository").addEventListener("click", openUninstallRepository);
    byId("cancel-uninstall-repository").addEventListener("click", () => byId("uninstall-repository-dialog").close());
    byId("confirm-uninstall-repository").addEventListener("click", uninstallRepository);
    window.addEventListener("popstate", restoreRoute);
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
      restoreRoute();
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
