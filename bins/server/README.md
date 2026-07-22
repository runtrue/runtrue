# Runtrue server API status

`runtrue-server` is the durable control-plane HTTP process. It intentionally has
no executor or `runtrue-engine` dependency. All `/api/v1` routes require the
configured bootstrap bearer token; health/readiness and GitHub's independently
HMAC-authenticated webhook route are exceptions. OIDC discovery and JWKS are
public; workload-token minting is available only through the runner mTLS
broker, which validates the exact active execution lease, job, step, capsule,
audience, and fencing values.

Implemented routes:

- `GET /healthz` and `GET /readyz`
- `GET|POST /api/v1/repositories` and `GET /api/v1/repositories/{id}`
- tenant-scoped user and team administration under
  `/api/v1/tenants/{tenant_id}/users` and
  `/api/v1/tenants/{tenant_id}/teams`, including versioned user updates and
  team membership management
- provider-neutral direct user or team repository grants at
  `/api/v1/repositories/{id}/access`; grants use `read`, `write`, or `admin`,
  and `GET /api/v1/tenants/{tenant_id}/users/{user_id}/repositories` resolves
  the strongest effective permission across direct and inherited team access
- workflow compilation and Capsule signing with
  `POST /api/v1/repositories/{id}/capsules`, plus `GET /api/v1/capsules/{id}`
- run creation/list/get/cancel and canonical replay-bundle create/get routes
- immutable durable-event metadata plus idempotent failed-event replay routes
- approval collection/get routes and
  `POST /api/v1/approval-requests/{id}/decisions`
- scoped secret metadata/create/rotate/tombstone routes and versioned variables;
  built-in values are encrypted and never returned by read endpoints
- runner and runner-pool metadata, one-time enrollment creation, and draining
- cache/artifact promotion request queues, immutable policy versions, and
  verified audit-event listing
- OIDC discovery/JWKS and runner-mTLS-only short-lived workload JWT minting
- `POST /webhooks/github`, which authenticates exact bytes, normalizes the
  provider event, and atomically stores the immutable event with its deduplicated
  background task

Webhook acknowledgement never waits for Git or workflow compilation. Configure
`--git-mirror-root` / `RUNTRUE_GIT_MIRROR_ROOT` to enable the bounded SCM task
worker; with no configured root, authenticated events remain durably pending.

Failed event deliveries can be redelivered with
`POST /api/v1/events/{event_id}/replay`. The caller must provide an
`Idempotency-Key`; replay requeues the same task with the exact stored payload
and stable processing identity while preserving the original event. Pending, claimed, and completed
events are rejected, and replay acceptance is written to the audit chain.
The root and each `<owner>/<repository>` directory must be real mode-0700 Unix
directories (not symlinks), with a real `.git` directory. The worker does not
fetch or execute repository content. It opens only the exact normalized
`<owner>/<repository>` path and reads `.runtrue/workflows/ci.yaml`, `.runtrue.lock`,
and other planner inputs through bounded Git object reads at the full commit IDs
already present in the authenticated event. Mirror refresh is an independent
operator responsibility.

With the `github-actions` feature, workflows may reference a root action as
`owner/repository@<40-character lowercase commit>`. The worker accepts only a
Docker action whose exact commit contains one strict `action.yml` or
`action.yaml`; tags, branches, subdirectory actions, JavaScript actions, and
composite actions remain rejected. Authorization comes from the tenant's live
GitHub App installation catalog, so the action repository does not need to be
enabled as a Runtrue execution repository.

Repository-action builds are disabled unless both
`RUNTRUE_REPOSITORY_ACTION_BUILDER_SOCKET` and
`RUNTRUE_REPOSITORY_ACTION_CONTEXT_ROOT` are configured. The server stages the
exact Git tree into a private content-addressed context and sends only a bounded
build request over the Unix socket. The separate trusted builder emits an OCI
archive, returns its exact manifest digest, and admits the signed, preloaded
image to the worker; the server never receives Docker or Podman access.

Each claimed `scm.event` is re-verified before planning. Pushes and merge-group
events use their exact source commit. Pull requests test the head commit with
the exact target/base workflow and lockfile. A changed proposed definition is
compiled and signed for bounded risk analysis, but its exact run/jobs are only
persisted as pending state. Independent workflow-definition and privileged-
execution requests bind the complete compiler approval subject. The trusted-
base run may still be created in the same transaction when it has no gate.

Each approval decision transaction enqueues a bounded
`scm.approval.continue` task without reading a repository. The worker pauses in
restore safe mode, rereads only the exact Git objects, rechecks policy/source/
lock/reusable identities and canonical capsule bytes, and then atomically consumes
or links every required approval, records per-run authorization, creates the
run/jobs, and completes the task. Concurrent decisions and worker restarts
converge on one run. Denial, expiry, source/policy drift, or tampering closes
the pending execution without jobs. Stable IDs bind the normalized event
digest, external repository name, and internal repository ID.

Reusable workflow lock entries are hydrated only from exact Git objects.
GitHub HTTPS/SSH references must authenticate the expected owner/repository;
cross-repository sources require a private secure mirror at
`<mirror-root>/<owner>/<repository>` whose single local `remote.origin.url`
matches that identity. The worker never fetches, executes, or falls back to a
worktree for reusable source resolution.

The complete preliminary contract is in `api/openapi.yaml`. Requests to
unsupported paths return an RFC 7807 `404` response rather than a placeholder
success. Promotion responses mean validation work was durably queued; this
server does not execute promotion work or runner workloads.

Mutations document `Idempotency-Key` (maximum 200 bytes). A repeated enrollment
request never creates a second token, but returns `409` because one-time bearer
plaintext is deliberately not persisted for replay. Every error response is
`application/problem+json`, and every response includes `X-Request-ID`.

API-token scope checks are the route-level capability gate. A separately
schema-validated built-in Cedar policy is then evaluated against each concrete
resource and permits only resources owned by the token's tenant. Repository,
run, approval, runner-pool/runner, audit, and API-token collection queries are
tenant-filtered in SQLite before rows are returned. Cross-tenant object access
is reported as not found to avoid confirming object existence; Cedar default
deny or evaluation errors deny the request. Secret and variable authorization
uses the tenant resolved from `repository:<id>` or `tenant:<id>` scope. API
tokens cannot operate on promotion or policy-version resources until those
records have durable tenant ownership. Bootstrap authentication remains an
installation-wide recovery/administration principal, and approval decisions
record the actual authenticated principal ID.

User-management authorization has dedicated Cedar actions (`ManageUser`,
`ManageTeam`, and `ManageRepositoryAccess`) and resources. Tenant identity
routes always include the tenant in the path; repository grant routes derive
the tenant from the durable repository record. Cross-tenant requests therefore
follow the same not-found concealment behavior as the rest of the API. The
model is independent of GitHub accounts and installations so provider-facing
UIs can be added without becoming the source of truth for access.

Production startup creates or reloads a durable 32-byte mode-0600 installation
key from `--security-key-file` / `RUNTRUE_SECURITY_KEY_FILE` (default
`.runtrue/server/security.key`). That key independently derives capsule-signing,
secret-vault, and OIDC-signing keys. Configure the public issuer with
`--oidc-issuer` / `RUNTRUE_OIDC_ISSUER`; non-loopback listeners must set it
explicitly.

## Secure runner enrollment and control

Runner enrollment and control are disabled by default. Enabling them requires
all six settings together. The two gRPC addresses and the HTTP address must be
distinct; neither runner listener has a plaintext mode:

```text
--runner-grpc-listen 0.0.0.0:8443
--runner-enrollment-listen 0.0.0.0:8444
--runner-tls-certificate /etc/runtrue/runner-server-chain.pem
--runner-tls-private-key /etc/runtrue/runner-server-key.pem
--runner-ca-certificate /etc/runtrue/runner-ca.pem
--runner-ca-private-key /etc/runtrue/runner-ca-key.pem
```

The equivalent environment variables are `RUNTRUE_RUNNER_GRPC_LISTEN`,
`RUNTRUE_RUNNER_ENROLLMENT_LISTEN`,
`RUNTRUE_RUNNER_TLS_CERTIFICATE`, `RUNTRUE_RUNNER_TLS_PRIVATE_KEY`,
`RUNTRUE_RUNNER_CA_CERTIFICATE`, and `RUNTRUE_RUNNER_CA_PRIVATE_KEY`. Every file
must be a real, non-symlink, mode-0600 file. Startup verifies that the
installation CA has `CA:TRUE` and `keyCertSign`, is currently valid, and
matches its private key.

Runner cache and artifact content is stored under `--data-root` /
`RUNTRUE_DATA_ROOT` (by default, a sibling data path derived from the SQLite
database). The root is created as a real mode-0700 directory. Keep it on the
same protected storage and backup schedule as the control-plane database;
immutable CAS objects are separate from the durable object-transfer ledger.
Schema 14 generalizes the schema-12 upload journal to source, cache, artifact,
and report transfers in both directions and backfills existing verified upload
rows without rewriting the shipped schema-12 table. Authorization is resolved
from the certificate-owned session and active lease before CAS existence is
inspected.

The enrollment listener uses TLS server authentication only and exposes only
`Enroll`. All control, lease, and rotation RPCs are rejected on that listener.
The control listener requires a client certificate chaining to the installation
CA. There is no static fingerprint registry or plaintext fallback.

Enrollment accepts a one-time, expiring, pool-bound bearer created by the HTTP
API and a PKCS#10 CSR of at most 16 KiB. The server consumes the token, creates
the runner, and records the initial certificate in one SQLite transaction. CSR
signature verification must succeed, the key must be Ed25519, and the entire
DER input must be consumed. CSR names and requested extensions are discarded;
the server supplies the exact runner/pool identity, `CA:FALSE`, digital-signing
key usage, client-auth EKU, short validity, and a random positive serial.
After that transaction, the response includes v1 field 7,
`authoritative_posture_digest`, derived from the durable accepted inventory.
The field is additive: older runners ignore it and older servers omit it.
Certificate rotation does not alter the enrollment posture binding, and the
subsequent authenticated Open still validates the exact durable digest.

Authorization hashes the verified peer leaf DER and resolves that fingerprint
through durable runner, pool, certificate-status, and expiry state. Rotation is
permitted only from the exact active fingerprint for the authenticated runner.
The replaced certificate enters a bounded overlap, then becomes durably
revoked; an older overlap is revoked when another rotation occurs. Open streams
recheck this state on heartbeats, and the server sends one
`RotateCertificateNow` before expiry.

Implemented runner control covers enrollment, certificate rotation, `Open`,
exact signed-capsule fetch, fenced lease accept/reject and heartbeat renewal,
drain/cancel controls, disconnect cleanup, step-scoped built-in secret
delivery/revocation, audience-scoped OIDC minting, and idempotent fenced
completion. One live Open session is permitted per certificate-bound runner.
Every unary operation must present the same leaf fingerprint that owns that
session, including during certificate-overlap windows. Fetches must match an
offer on that session;
completion retries may reconnect but must still match the durable runner,
lease, generation, installation epoch, expiry, and result.

Cache and artifact commit acknowledgements are preceded by a schema-13
`runner_data_commits` journal entry bound to tenant, repository, run, job,
attempt, step, lease, fence, ticket, and declared output name. Successful
completion requires exactly the signed job's artifact declarations and binds
the ordered artifact/cache IDs atomically with the terminal job transition in
`job_result_objects`. An exact retry, including object order, succeeds;
substitution, omission, duplication, stale fences/attempts, and cross-tenant
IDs fail closed. After a crash, operators may inspect unbound journal rows as
GC candidates, but must not manually attach them to another attempt or lease.

Secret and OIDC requests additionally require an accepted active lease and the
exact declared step to be running on the current Open session. The server
revalidates canonical signed-capsule capabilities, repository/tenant scope,
per-run approval authorization, posture, audience, and both fences in an
immediate transaction. Secret values are delivered once in a versioned
X25519/HKDF-SHA-256/XChaCha20-Poly1305 envelope and are never persisted in
plaintext. Issuance/revocation metadata and tamper-evident audit events survive
restart. Only the built-in secret provider is served; unknown external
providers fail closed.

Cache restore/commit and artifact ticket/commit RPCs require the same
certificate-owned Open session, exact active lease, fence, current job attempt,
signed job/step declaration, and granted cache/artifact permissions. Blob
uploads and cache downloads use bounded streaming RPCs; ticket scope, expiry,
digest, offsets, per-blob size, aggregate durable byte budget, immutable tree
summary, and CAS content are reverified. Restore callers cannot select the
cache head. Artifact finalization derives retention and signed provenance from
the canonical capsule and runner posture rather than accepting runner-supplied
claims. Cache errors degrade to misses; artifact capture errors fail the
declared output contract. Remote Native, OCI, and Wasm execution use this host
data plane. The v1 MicroVM guest rejects cache/artifact declarations until a
guest filesystem transfer protocol is available.

The server verifies a CAS object completely before releasing a download and
then streams it through a bounded queue. Uploads use private staging and are
published only after the declared digest and size match. Cancellation drops the
queue and staging file. Protocol generation 2 is the newest-common wire
generation; generation 1 remains accepted for N-1 runners and for exact replay
of legacy durable pending completions. Generation 2 uploads send one binding
header followed by bounded offset-bearing chunks, and generation 2 completion
uses typed terminal states plus lease-scoped cache/artifact claims whose names
and attempts are durably verified before the terminal transition. Current
fixed-bound and L3 certification caveats are documented in
`docs/operations/runner-object-transfers.md`.

Step/log/health/locality stream messages are bounded and fence-validated;
terminal authority remains `CompleteLease`. Log frames are durably sequenced by
lease, attempt, step, stream, and sequence and exposed only through the
tenant-authorized no-store run-log API.

A database restored by `runtrue-backup` starts in durable safe mode. Readiness
stays false and all HTTP mutations are rejected until the documented recovery
checks and exact-epoch activation complete. The SCM worker also pauses before
claiming and rechecks safe mode inside the atomic run-creation transaction. See
`docs/operations/single-node-backup-restore.md`.
