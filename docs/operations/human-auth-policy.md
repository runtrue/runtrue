# Human authentication and active policy bundles

This document describes the bounded domain primitives, migration-23 durable
storage, and the initial HTTP adapter supplied by the current R9 implementation
slice. It does not mark R9 complete. The adapter is intentionally limited to
pre-provisioned users and EdDSA-signed ID tokens; broader real-provider and UI
evidence remains required before the feature reaches L2/L3.

## Enabling browser authentication

Browser routes are absent unless both of these settings are present:

- `--public-origin https://runtrue.example` or `RUNTRUE_PUBLIC_ORIGIN`; and
- `--browser-cookie-sealing-key-file /run/credentials/runtrue-cookie-key` or
  `RUNTRUE_BROWSER_COOKIE_SEALING_KEY_FILE`.

### GitHub OAuth quick deployment

Runtrue can use GitHub.com or GitHub Enterprise Server OAuth as the default
interactive login for a small self-managed deployment. Configure
`RUNTRUE_GITHUB_OAUTH_CLIENT_ID`,
`RUNTRUE_GITHUB_OAUTH_CLIENT_SECRET_FILE`, and at least one stable numeric user
id in `RUNTRUE_GITHUB_OAUTH_ADMIN_USER_IDS` or
`RUNTRUE_GITHUB_OAUTH_OPERATOR_USER_IDS`. The tenant defaults to `quickstart` and
can be named with `RUNTRUE_GITHUB_OAUTH_TENANT_ID` and
`RUNTRUE_GITHUB_OAUTH_TENANT_NAME`.

The client secret must be a protected file and is never accepted from an
environment value. The web/API origins come from the same exact
`RUNTRUE_GITHUB_WEB_ORIGIN` and `RUNTRUE_GITHUB_API_ORIGIN` pair as the GitHub App.
Opening `/` without a session redirects through
`/auth/login` and returns at `/auth/callback`.

OAuth state is a durable, expiring, one-use transaction and is also bound into
an authenticated, encrypted callback cookie. With a GitHub App client, user
authorization authenticates the person but does not discover repositories for
the picker. Repository discovery is install-first: GitHub owns the account and
`All repositories` or `Only select repositories` grant, Runtrue reconciles the
installation, and the picker lists exactly that granted catalog. The user then
enables repositories individually; installing the App does not implicitly add
every granted repository to Runtrue.

The provider token is retained only in an encrypted, HttpOnly cookie bound to
the exact Runtrue session. It is never returned to frontend JavaScript or
written to durable storage, and is cleared on logout. It is used only for
user-bound setup validation, never as a substitute for GitHub App installation
authorization. Unknown GitHub users, login-name substitutions, changed
tenant/provider bindings, callback replay,
private-address provider endpoints, redirects, ambient proxies, and oversized
responses are rejected. The stable numeric user allowlist is the authority; a
matching login name alone grants nothing.

The key file must be a separate, exact 32-byte, non-symlink regular file with
the same private-file permission checks as other server keys. It is not the
installation security key and is never accepted from an environment value.
Supplying only one setting fails startup. The public origin is an exact HTTPS
origin with no path, query, fragment, user information, or trailing slash.

Configure a migration-23 tenant OIDC provider with the exact callback
`$RUNTRUE_PUBLIC_ORIGIN/auth/oidc/callback`. The initial adapter is an OAuth
public client: token exchange sends `client_id`, code, registered redirect, and
the S256 verifier, and sends no client secret. Providers requiring a client
secret are unsupported until a non-exportable provider reference is wired;
there is no ambient credential or basic-auth fallback.

Current browser routes are:

- `GET /auth/oidc/login` and `GET /auth/oidc/callback`;
- `POST /auth/session/refresh` and `POST /auth/session/logout`;
- `GET /api/v1/session` and `GET /api/v1/policy-status`; and
- `GET /ui/session` and `GET /ui/policy`.

Only an exact pre-provisioned `(tenant, provider, issuer, subject)` identity
with an active tenant user and active membership can receive a session. There
is no just-in-time user or membership grant.

## Security boundary

The `runtrue-auth` crate owns opaque browser credentials and OIDC login
transactions. The `runtrue-policy` crate owns canonical policy drafts,
simulation, shadow comparison, activation, and immutable request snapshots.
Neither crate performs network I/O or chooses a tenant from untrusted request
data.

An HTTP adapter must preserve these rules:

- use OIDC Authorization Code with `S256` PKCE only;
- store only the transaction record; state, nonce, and verifier plaintext are
  returned once and are carried in an XChaCha20-Poly1305 sealed and
  authenticated `runtrue_login` cookie;
- set login/session cookies with `Secure`, `HttpOnly`, an explicit host/path,
  and `SameSite=Lax` or stricter; never place credentials in a URL or log;
- resolve issuer, client, redirect URI, tenant, and provider configuration from
  server-owned configuration, then pass those exact bindings when consuming a
  transaction;
- parse and validate issuer and redirect values with a standards-compliant URL
  implementation during provider configuration (including HTTPS authority,
  issuer query/fragment restrictions, redirect policy, normalization, and
  exact registered-redirect comparison); the domain primitive's conservative
  URI-shape check and exact string binding are defense in depth, not a URL
  parser;
- validate the ID-token signature, issuer, audience, time claims, and
  authorization-code response before presenting its nonce to the transaction
  primitive;
- map unknown, cross-binding, expired, replayed, and malformed login attempts
  to the same externally safe rejection; detailed categories are for bounded
  audit/metrics labels only;
- require the current CSRF credential for refresh and every state-changing
  browser request; a configured recent-MFA requirement is checked before a
  live refresh token is rotated;
- commit refresh-family rotation and its consumed-token digest atomically.
  Reuse of a consumed refresh token revokes the whole family and must be
  persisted before returning the rejection.

Transactions are deliberately short lived and one use. Starting an exchange
consumes the authorization callback opportunity. A nonce mismatch is terminal;
there is no retry or fallback login mode. Expired and rejected transaction rows
may be deleted only after the configured security-event retention window.

The login cookie is `Secure`, `HttpOnly`, `SameSite=Lax`, scoped only to the
callback, and limited to ten minutes. Access and CSRF cookies use
`SameSite=Lax` so both are available on the first top-level GET after an
external provider callback; refresh cookies use `SameSite=Strict`. All three session cookies are
sealed, `Secure`, and `HttpOnly`. The raw CSRF value appears only in an
authenticated `no-store` session response or escaped same-origin logout form;
it never appears in a cookie value, URL, log, or problem detail. A mutation
must present that value through `X-CSRF-Token` or the bounded `csrf_token` form
field in addition to the sealed CSRF cookie. `SameSite=Lax` alone never
authorizes a mutation.

Outbound token and JWKS calls are HTTPS-only with environment proxies and
redirects disabled. DNS resolution rejects the complete answer set if any
address is private, loopback, link-local, documentation, multicast, or another
special range. Header, response, code, token, key-count, connect, total-time,
and concurrent-exchange limits are fixed. Capacity exhaustion rejects before
spawning blocking I/O. Current ID-token support is strict `EdDSA` with an
Ed25519 `OKP` JWK and exact `kid`; `RS256`, `ES256`, `none`, ambiguous keys, and
algorithm substitution fail closed.
The initial adapter also requires query-free authorization, token, and JWKS
endpoint URLs so configured query parameters cannot substitute reserved OAuth
parameters; providers requiring endpoint query components are unsupported.

## Durable records and recovery

Migration 23 adds an authoritative `tenants` registry and bounded tables for
tenant OIDC provider metadata, users, external identities, memberships, OIDC
browser transactions and their transition journal, browser sessions and
refresh-family tokens, policy drafts, simulation/shadow reports, active policy
state, activations, and emergency-deny replacements. Existing tenant IDs are
backfilled into conservative tenant roots during upgrade.

OIDC provider rows contain issuer/client/endpoints/redirect/scopes/MFA-claim
metadata and a configuration digest. They contain no client secret,
authorization code, ID/access/refresh token, state, nonce, PKCE verifier, or
cookie plaintext. Browser tables store only installation-keyed token digests
and bounded serialized domain records. Use the built-in secret store or an
external provider for an OIDC client credential; never add it to provider
configuration JSON.

Every tenant-owned child uses a tenant-qualified lookup. Refresh-family rows
reference `(tenant_id, session_id)` and policy evidence references
`(tenant_id, draft_id)`, so a valid identifier from another tenant cannot be
substituted through a foreign key. The database also checks session deadline
ordering, one active refresh token per family, monotonic activation/cache
generations, and consumed/revoked timestamps.

The storage adapter uses an immediate transaction and exact compare-and-swap
for each state change:

1. `pending -> exchanging` when issuer/client/redirect, state, and verifier all
   match;
2. `exchanging -> consumed` only after a verified ID-token nonce matches;
3. any nonce mismatch becomes terminal `rejected`;
4. refresh rotation inserts the old keyed digest, new credential digests, and
   new generation in one commit;
5. refresh replay writes family revocation in the same transaction that detects
   the consumed digest.

After a process restart, the persisted status is authoritative. An
`exchanging`, `consumed`, `rejected`, or expired OIDC transaction cannot return
to `pending`. A stale browser response cannot recreate or substitute a
transaction. The installation-owned HMAC key is required to verify opaque
values and must come from the configured secret provider, not a repository,
runner, or ambient workload credential.

## Policy workflow

A policy administrator creates a draft from Cedar source. Draft creation
parses and validates against Runtrue's embedded schema, rejects templates and
oversized input, converts the policy set to canonical JSON, and binds a
domain-separated digest to those canonical bytes. Invalid source is never a
draft that can later be activated.

The lifecycle is intentionally monotonic:

1. simulate the draft against a bounded stored corpus plus bounded
   caller-supplied examples;
2. inspect expectation mismatches and evaluation errors (both fail closed);
3. enter shadow mode only with the exact simulation digest;
4. compare a bounded request batch against the current active version without
   letting the shadow result grant or deny;
5. activate with an independent approver, the exact draft and simulation
   digests, and the expected current policy epoch;
6. publish one immutable snapshot for each browser policy-status request.
   Activation increments the tenant policy epoch and changed replay conflicts.

The draft author cannot independently activate their draft. An activation
race using an old epoch is rejected. There is no implicit promotion from draft
to active. For compatibility, the existing same-tenant engine remains only
before a tenant has any durable active or emergency policy state. Once such
state exists, load/evaluation failure denies and there is no fallback. Removing
that preactivation compatibility path in favor of recovery-only bootstrap is
still required for full R9 completion.

Emergency denies are a separate server-owned input. They are evaluated before
the active Cedar bundle, including before the first permit bundle exists and
for ordinary bootstrap bearer requests. Replacing them uses an expected cache
generation and increments that generation immediately, so decision caches
cannot survive a security-critical deny update. With no active permit,
authorization remains default deny once a durable emergency state exists.

## Bounds and observability

The crates expose constants for transaction lifetime, policy bytes, simulation
case counts, serialized corpus bytes, and shadow batch counts. Adapters may
configure smaller limits but must not raise them. Do not accept an unbounded
historical corpus, request body, diagnostic, group set, or emergency rule set.

Recommended metrics use low-cardinality result labels and never include token,
nonce, verifier, policy source, principal email, or request entities:

- OIDC transactions issued, expired, binding-rejected, replay-rejected, and
  consumed;
- browser refresh success, invalid CSRF, stale MFA, replay revocation, family
  exhaustion, and expiry;
- policy drafts validated/rejected and their byte/case bound rejections;
- simulation/shadow evaluations, expectation mismatches, and evaluation
  errors;
- activations, stale-epoch conflicts, separation-of-duties rejections, active
  policy epoch, and emergency-deny cache generation.

`AppState::human_auth_metrics` currently exposes bounded counters for login,
callback success/failure, refresh, replay revocation, logout, and live policy
snapshot success/failure. An installation metrics exporter still needs to
publish this snapshot.

Audit records should reference transaction/session/policy IDs, actor,
tenant/resource, policy/simulation digests, epochs, decision category, and
correlation ID. They must never contain opaque credential plaintext, OIDC
codes/tokens, Cedar entities with sensitive attributes, or policy source.

## Upgrade, backup, and recovery

Migration 23 is the additive human-auth/policy schema and must never be edited
after it ships. Upgrade validation starts from schema 1 and schema 22, verifies
`PRAGMA foreign_key_check`, reopens the database, and exercises exact replay
and changed replay conflicts. Migration conformance must remain contiguous and
the backup verifier must match the repository's current schema head as later
additive migrations land.

All migration-23 tables are authoritative metadata and are included in the
SQLite online backup. Backup verification rejects a schema-23 database missing
any required identity/session/policy table; restore activation remains in safe
mode on verification failure. Restore the installation token-HMAC key through
its existing protected key-continuity mechanism. Without the same key, stored
opaque credential digests intentionally cannot authenticate.

On a suspected refresh replay, do not delete the consumed-token journal. Revoke
the family, retain its bounded digests for the security-event retention window,
and investigate by session ID and audit correlation ID. On policy-state
integrity failure, keep authorization default-deny, repair from a verified
backup, and do not synthesize a lower epoch or cache generation.

## Remaining release work

R9 remains below the Capsule's completion threshold. Remaining work includes
RS256/ES256 and real-provider interoperability, confidential-client support
through a non-exportable credential provider, discovery metadata validation
and JWKS caching/rotation policy, identity/group claim administration, step-up
WebAuthn/TOTP, session inventory, application audit-sink and production metrics
export, and broader accessible UI. Existing API helpers can still load policy
more than once when one HTTP handler authorizes several resources; a future
request middleware must pin one verified tenant snapshot in request extensions
before full request-snapshot completion can be claimed. Full restore, chaos,
multi-instance refresh-race, and real IdP/browser end-to-end evidence is also
outstanding.
