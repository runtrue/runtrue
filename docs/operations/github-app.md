# GitHub App source and check projection

Runtrue can refresh an authenticated GitHub repository into the hardened
mirror manager and publish a durable workflow check. This is an explicit
production mode; setting only `RUNTRUE_GIT_MIRROR_ROOT` retains the separate
operator-refreshed/air-gapped mirror mode and performs no outbound provider
operation.

## Configuration

Set the mirror root, App id, credential reference, and signer socket together.
Add the public App slug when tenant self-service installation is enabled:

- `RUNTRUE_GIT_MIRROR_ROOT`: private mode-0700 mirror root;
- `RUNTRUE_GITHUB_APP_ID`: the positive numeric GitHub App id;
- `RUNTRUE_GITHUB_APP_SLUG`: required to enable tenant self-service setup; the
  public lowercase GitHub App slug from the App's settings page (for example
  `runtrue`);
- `RUNTRUE_GITHUB_WEB_ORIGIN`: exact HTTPS web origin. It defaults to
  `https://github.com`; for GitHub Enterprise Server use the instance origin,
  for example `https://github.example.com`;
- `RUNTRUE_GITHUB_APP_CREDENTIAL_REFERENCE`: an exact
  `provider://github-app/...` identifier also stored on the tenant-owned SCM
  installation;
- `RUNTRUE_GITHUB_APP_JWT_PROVIDER_SOCKET`: a root- or server-owned local Unix
  socket with no group/other permissions;
- optionally `RUNTRUE_GITHUB_API_ORIGIN` (default
  `https://api.github.com`). For GitHub Enterprise Server it must be the exact
  web origin plus `/api/v3`, for example
  `https://github.example.com/api/v3`.

Partial core configuration fails startup. An App configuration without a
mirror root also fails startup. The server does not accept an App private-key file,
environment private key, ambient Git credential helper, proxy, redirect, or
plaintext API origin.

For Docker Compose, use `deploy/compose.github-app.yml` together with the base
`deploy/compose.yml`. Run `deploy/bootstrap.sh --with-github-app`, copy and edit
`deploy/github-app.env.example`, then follow the exact build/start commands in
`deploy/README.md`. The overlay bind-mounts only a pre-existing mode-0600 signer
socket; it does not put the App private key in the image, Compose environment,
or server container.

GitHub.com and GitHub Enterprise Server use different installation paths.
Runtrue constructs `https://github.com/apps/<slug>/installations/new` for
GitHub.com and `<web-origin>/github-apps/<slug>/installations/new` for GitHub
Enterprise Server. The web/API pair is validated as one immutable provider
identity and is carried through setup, installation, repository catalog,
source fetch, reusable-workflow reads, checks, lifecycle reconciliation, and
audit digests. An origin change cannot silently rebind an existing
installation or repository with the same numeric provider id.

Only one exact GitHub provider/App identity is configured by a server process.
Run separate Runtrue control-plane deployments when independent GitHub.com and
GitHub Enterprise Server App identities must be served simultaneously.

Provider-side installation and Runtrue onboarding are separate trust stages.
A GitHub organization or repository administrator may install the App without
a Runtrue account. A setup callback without Runtrue state verifies the exact App
and installation through the provider, displays a neutral success page, and
does not choose a tenant, create a repository, or grant access. An authorized
Runtrue user subsequently starts the dashboard install action and claims the
provider-selected repository catalog into an exact tenant. Callback query
values alone are never tenant authority.

The authenticated dashboard groups the verified catalog by organization.
Installing or synchronizing an App updates that catalog but does not silently
onboard newly selected repositories. A tenant administrator must submit the
CSRF-bound `+ Add repository` action, which re-resolves the active
installation and exact external repository id before creating the local link.

Migration 26 journals accepted repository webhook receipts for operations and
support. Each row contains the exact tenant/repository/installation binding,
delivery id, provider event name, normalized event kind, actor login, ref,
receipt time, and normalized/raw-payload digests. It never stores raw webhook
bytes, signatures, headers, App JWTs, or installation tokens. Dashboard event
queries are tenant- and repository-filtered and capped at 50 rendered rows.
After signature verification and exact active repository resolution, repository
events that are not executable Runtrue trigger types are still journaled and
acknowledged, but never placed on the SCM execution queue. Executable push,
pull-request, and merge-queue events are evaluated against the trusted
workflow's canonical `on:` declaration; an absent event trigger or a failing
branch/path filter completes intake without creating a run. This release
evaluates the configured `.runtrue/workflows/ci.yaml` path. Directory-wide
multi-workflow discovery remains a separate feature and must not be inferred
from the dashboard journal.

## Tenant installation setup

The server-rendered administration page is available at
`/` after human OIDC is configured. Its operator-console
layout puts installation health and required permissions before the repository
catalog. All mutations use authenticated POST requests with session-bound CSRF
and one-use idempotency values. Page responses are `Cache-Control: no-store`;
no App JWT, installation token, private-key material, signer reference, webhook
secret, or raw setup state is rendered into HTML.

Automation uses the same application service through:

- `GET /api/v1/scm/github?tenant_id=...` for redaction-safe status;
- `POST /api/v1/scm/github/setup-transactions` to create an install action;
- `POST /api/v1/scm/github/installations/{id}/sync?tenant_id=...` for an
  authenticated provider refresh; and
- `DELETE /api/v1/scm/github/installations/{id}?tenant_id=...` to revoke local
  access immediately.

The setup callback is `/auth/github/app/callback`. Configure that URL in the
GitHub App settings using the externally reachable HTTPS origin of this Runtrue
server. The webhook URL is `/webhooks/github`; it must use the same secret
configured for Runtrue's webhook verifier. API callers require the `scm:read` or
`scm:write` scope as appropriate, and every lookup is tenant-filtered before
existence is disclosed.

An authenticated tenant administrator starts setup through Runtrue. The server
creates a short-lived, one-use, installation-keyed state value and returns the
provider-owned GitHub.com or GitHub Enterprise Server installation URL with an
opaque `state` query parameter. The
state is at least 256 bits, bound to the exact tenant, principal, return path,
App id and expiry, and is stored only as a digest. A callback with a missing,
expired, already-used, or changed state is rejected before provider metadata is
looked up.

After GitHub returns an installation id, Runtrue authenticates as the configured
App through the non-exportable signer and reads that exact installation. It
requires the returned App id, installation id, account id/type, target id/type,
repository selection and known permissions to agree. It then mints a separate
metadata-read-only token solely to enumerate the installation repository
catalog. That token remains inside the provider adapter, lives for at most one
hour, is never stored or returned to the browser, and is not reused for source
fetching or check publication. Catalog enumeration is limited to 1,000
repositories and 100 records per page; an over-limit or inconsistent catalog
fails closed.

Migration 25 journals setup as `pending`, `exchanging`, and `completed`, with
terminal `rejected`/`expired` states and at most eight callback attempts. A
server restart while provider inspection is in progress resumes the exact
`exchanging` transaction; it does not extend the original fifteen-minute
expiry. Completion atomically records the verified installation profile and
complete bounded repository catalog. Exact replay returns the durable result,
while a changed installation, account, permission, or repository selection
conflicts. The journal contains only request/state/completion digests and
numeric provider identities—never callback state, App JWTs, installation
tokens, private keys, credential values, or clone credentials.

Selected repositories are not silently linked from callback strings. The
link transaction first resolves the active tenant-owned installation and its
authenticated selected-repository catalog, then requires the exact numeric
repository id, owner, name, default branch, visibility, and tenant. It may
create the deterministic local repository id chosen by Runtrue only when no
same-tenant mapping exists. Catalog removal or installation suspension
suspends linked access immediately; uninstall revokes it terminally.

Runtrue reports the installation unhealthy when the exact CI permission set is
not available: Metadata read, Contents read, Pull requests read, and Checks
write. Contents write is not accepted as a substitute for read-only source
access. Suspending or deleting the installation disables linked access;
unsuspension, permission changes, and repository additions/removals are
reconciled from authenticated, strictly parsed GitHub lifecycle webhooks and a
provider refresh. A bound lifecycle delivery is journaled by delivery id and
payload digest before Runtrue acknowledges it; raw webhook bytes are not retained
in this journal. The reconciliation worker uses a fenced lease of at most five
minutes, retry backoff of at most one hour, and at most eight claims. Exact
completion/failure replay binds the worker, lease generation, and result/error
digest; exhaustion is terminal. A duplicate, server restart, stale worker, or
transient provider failure therefore cannot substitute or silently lose the
event. A creation event that races setup and has no
tenant-owned installation binding is not allowed to select a tenant. Unknown
actions, duplicate JSON keys, changed account/App identities and
repository-owner substitutions are rejected.

The tenant installation record must use the same credential reference and its
GitHub `external_id` must be the provider's positive numeric installation id.
The linked repository `external_repository_id` must be GitHub's positive
numeric repository id. Neither value is substituted with Runtrue's installation
or repository id. Source fetch requires `metadata:read` and `contents:read`;
check publication additionally requires `checks:write` in the stored App
permission set.

Installation metadata may contain additional explicitly modeled App
permissions, such as Issues. They remain visible in the verified permission
snapshot but never broaden a repository token minted by Runtrue. Unknown
permission names still fail closed. In particular, `contents:write` does not
satisfy Runtrue's required exact `contents:read` posture; the installation is
shown as needing permission correction instead of being hidden as a provider
transport failure.

## Non-exportable signer protocol

The first-party Go signer in `components/github-signer` owns the App private
key. Runtrue sends one length-prefixed
(big-endian u32), bounded JSON request:

```json
{
  "version": 1,
  "operation": "github.app-jwt.mint",
  "app_id": 123,
  "credential_reference": "provider://github-app/production",
  "now_unix_seconds": 1783728000
}
```

It returns a length-prefixed JSON object containing only `version: 1` and a
short-lived `jwt`. Frames are limited to 16 KiB and reads/writes to five
seconds. Runtrue validates RS256 header claims, exact App issuer, issue time, and
the ten-minute maximum lifetime before using the JWT once to mint a
repository-scoped installation token. The private key never enters Runtrue. The
installation token is zeroized, never persisted, and is passed to Git only
through the exact read-only child credential channel.

Build the signer from the same reviewed Runtrue checkout with `go test ./...`
and `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -buildid='`. It remains a
separate process and may be replaced by any conforming implementation; choosing
Go does not add Go to the Rust execution kernel. Run it with networking disabled
and expose only its mode-0600 socket to the server. Exact environment, build,
and readiness commands are in `components/github-signer/README.md`.

## Network and resource posture

GitHub API calls are HTTPS-only with environment proxies and redirects
disabled. Connect and total timeouts are fixed and response headers/bodies are
bounded. A DNS resolution containing any loopback, private, link-local,
documentation, multicast, or other special address is rejected as a whole.
GitHub Enterprise Server certificates must chain to the host operating
system's configured trust store. An internal instance must be exposed through
an operator-controlled public-address egress path; configuring a private-IP
exception is intentionally unsupported.

GitHub.com requests pin Runtrue's supported GitHub REST API version. GitHub
Enterprise Server requests do not send that GitHub.com-only version header;
the appliance selects its bundled default REST version and Runtrue continues to
strictly validate every response shape and identity. This avoids rejecting an
otherwise supported appliance merely because its release supports a different
dated API version.
Mirror fetches retain their independent object, pack, disk, process and time
bounds. A source integrity failure remains terminal; provider unavailability
uses bounded durable retry and never falls back to ambient credentials or a
native checkout.

## Check durability and recovery

Creation of an immediate SCM run atomically creates a
`scm.check.publish` durable task. Migration 22 adds
`scm_check_publications`, keyed by provider, repository, commit, run and
logical check name. Before contacting GitHub, the worker stores the exact
request digest. After a timeout or lost create response it searches the exact
commit and adopts a check only when name and external id also match. It reads
the provider annotation count and resumes from that cursor; multiple exact
matches fail closed. A recorded provider id cannot be substituted.

GitHub `429` responses use the bounded `Retry-After` value and the durable task
backoff. Restart after reservation, provider creation, progress recording, or
publication replays the same journal. Cross-tenant lookups are filtered before
existence disclosure, and every task mutation verifies the current task lease
owner and expiry. Successful projection appends an audit event containing only
the request digest and provider numeric check id.

Worker metrics expose source-fetch attempts/rejections/replays and check
publish attempts, completed publications, reconciliations, rate limits,
retries and terminal failures. Tokens, JWTs, response bodies and annotation
contents are never metric or audit attributes.

## Current boundary

This slice publishes the initial run check for immediate GitHub runs and
provides the durable lost-response machinery. Final job/run status, pending
approval projections, report annotations, and checks for approval-continuation
runs still require their producers to enqueue updates through the same journal
before R8 can be called L2/L3 complete.
