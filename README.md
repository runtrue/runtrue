# Runtrue

**Run local. Run remote. Run true.**

Runtrue is a trust-preserving execution system whose execution kernel is
implemented in Rust. It binds an immutable
**Program** and exact runtime contract into an **Execution Capsule** or
**Session Capsule**, then binds approval through a **Seal** to that exact
subject. The **Bisim** conformance suite compares portable Provider behavior,
while a graded, credential-free **Replay Bundle** makes admitted execution
state reproducible on a developer machine.

CI workflows—and GitHub Actions workflows in particular—remain Runtrue's first
main use case. They are implemented as a source frontend and orchestration
integration over the public execution boundary, so the adapter can move to a
separate repository without moving GitHub concepts into the execution kernel.

The canonical product vocabulary is defined in the
[Runtrue naming contract](docs/adr/0005-runtrue-naming.md).

This repository implements a v0.x release candidate for the supported
single-node evaluation profile described in the
[technical design](docs/technical-design.md), including local execution,
isolated executor libraries, a durable SQLite control plane, SCM planning,
runner admission/fencing, policy, secrets, identity, artifacts, and recovery.
It is not a hosted-service or high-availability production recommendation, and
does not claim that every roadmap item in the design is complete. The explicit
v0.x support boundaries are listed below.

## What is implemented

Workflow and planning:

- A domain-neutral public Rust facade for canonical Program, runtime,
  Execution, Session, Capsule, Seal, Provider, capability, external-effect,
  Checkpoint, Replay Bundle, Evidence, warm-pool, failure, and Bisim contracts.
  The generic kernel has no workflow, SCM, GitHub, executor, database, or
  transport dependency.
- Exact runtime inventory matching is separate from expiring capacity hints;
  Session children use bounded reservations and fenced single-winner workspace
  publication; warm runtime members are one-shot and can never become sterile
  after assignment begins.
- Strict, bounded workflow-v1 YAML decoding with unknown/duplicate-field
  rejection, typed values, deny-by-default permissions, expressions, DAGs,
  conditions, static matrices, retries, services, caches, and artifact
  declarations.
- Deterministic canonical Capsule generation, qualified SHA-256 identity,
  immutable lock resolution, semantic risk comparison, exact Seal subject
  construction, and secret-free Replay Bundles.
- A trusted SCM planner that reads exact Git objects. Pull requests execute the
  target-branch workflow by default; proposed workflow changes are independently
  compiled and risk-analyzed and require an exact matching approval subject
  before they can be selected.
- A bounded, fail-closed GitHub Actions frontend with `SUPPORTED`, `EMULATED`,
  `REQUIRES_GITHUB`, `UNSAFE`, and `UNSUPPORTED` findings. Standard
  `.github/workflows/*.yml` files are discovered directly; translated input,
  native output, and compatibility report identities are digest-bound.

Execution boundaries:

- One shared job/step lifecycle engine used by local and remote execution code,
  including cancellation, timeouts, retries, deterministic events, and a
  no-downgrade executor dispatcher for mixed-isolation Capsules.
- Bisim fixtures exercise the shared engine contract and detect behavioral
  drift between local and remote execution providers.
- Explicitly gated native execution for trusted local workflows.
- A rootless Podman OCI backend with exact image/signature admission,
  read-only roots, user namespaces, seccomp, capability removal, bounded
  output/time/resources, and cleanup verification.
- A Wasmtime 46.0.1 Component backend with signed digest-pinned components,
  a deny-ambient WASI 0.3 host, authenticated capability handles, rooted Linux
  `openat2` filesystem access, bounded adapters, and authenticated AOT cache.
- A Firecracker/jailer boundary with signed image sets, an authenticated guest
  protocol, copy-on-write job state, and signed sterile snapshot restore that
  binds the full runtime, kernel, rootfs, guest, CPU, memory, CID, and network
  compatibility tuple before the snapshot API is called.

Control plane and security:

- An unprivileged Axum server backed by SQLite migrations, atomic idempotent
  mutations, durable tasks, recovery safe mode, signed Capsules, runs/jobs,
  approvals, runners/pools, leases/fences, variables, encrypted secret state,
  promotions, policy versions, OIDC grants, and an append-only audit chain.
- HMAC-authenticated and deduplicated GitHub webhooks. A bounded background
  worker re-verifies normalized events and atomically commits the signed Capsule,
  remote run/jobs, idempotency record, and task completion, including across a
  database close/reopen.
- A first-party, Linux-only Go GitHub App signer keeps the App private key out
  of the server behind the bounded, language-neutral Unix-socket protocol.
- Hashed-at-rest, one-time, scoped, expiring, revocable API tokens plus rotating
  browser-session primitives with CSRF and refresh-reuse revocation semantics.
- Embedded schema-validated Cedar authorization, typed Runtrue resources/actions,
  default deny, forbid-overrides, same-tenant isolation, separation of duties,
  policy lifecycle primitives, and immediate emergency denies.
- Built-in envelope-encrypted, versioned secrets; Vault/OpenBao provider
  contracts; fence-bound step leases; log masking; audience-bound workload OIDC;
  and a bounded OIDC signing-key rotation/revocation/snapshot lifecycle.
- The mTLS runner control plane now serves one-use built-in secret envelopes
  and short-lived OIDC tokens only to the exact certificate-owned Open session,
  accepted fence, run-authorized signed Capsule, and currently running declared
  step. Remote Wasm consumes both just in time through opaque WIT handles,
  authenticated ephemeral envelopes, zeroizing host adapters, and live fenced
  step transitions. OCI steps can receive only explicitly sealed SCM or local
  secret grants through private, step-scoped runtime files; provider grants also
  require the signed SCM context and declared permission, and credentials are
  never injected as ambient environment variables. Native execution cannot
  receive brokered credentials. Firecracker rejects secret and OIDC capabilities
  before invoking the driver because its guest adapter does not yet implement
  credential delivery.
  Remote retries are attempt-bound across step transitions, logs, secret/OIDC
  brokers, revocation, completion journals, and durable broker records. Native,
  OCI, and Wasm jobs support whole-job retries; the v1 MicroVM guest remains
  fail-closed until its guest report carries the same attempt identity.
- Credential taint becomes monotonic after a credential is successfully exposed
  to a Wasm guest or written to an OCI private runtime file. Generation-two
  runner completion persists that evidence across restarts; legacy or missing
  evidence is treated as unknown and fails closed. Tainted execution suppresses
  subsequent durable logs, cache publication, artifacts, and Replay Bundles.
  The same fail-closed predicate is defined for execution Checkpoint publication;
  no tenant execution-Checkpoint publication route is implemented in v0.x.
- Tamper-evident audit events and signed checkpoints, break-glass and debug
  session state machines, non-exportable signing-operation contracts, protected
  deployment gates, and restore-time fencing.

Data, delivery, and operations:

- Immutable filesystem CAS, local Capsule-private cache, quarantine/promotion
  semantics, immutable artifact manifests, one-use tickets, signed provenance,
  JUnit/SARIF/coverage ingestion, and safe report rendering.
- Durable, exactly sequenced runner logs keyed by fenced lease and job attempt,
  with restart-safe replay rejection and a tenant-authorized no-store run-log
  API. Cache and artifact stores expose durable, random, expiring, one-use
  upload tickets and fully reverify pre-uploaded CAS snapshots before commit.
  The authenticated runner data plane streams bounded CAS blobs over mTLS,
  durably accounts ticket bytes, restores server-selected immutable cache
  generations, captures declared step caches and job artifacts, signs artifact
  provenance on the server, and returns committed IDs with lease completion.
- Security-filter-first scheduling with fairness, quotas, locality scoring,
  lease expiry/requeue, runner drain/quarantine, and protocol negotiation.
- Bounded single-node backup, verification, restore, explicit activation, audit
  and signing continuity checks, and an automated restore drill.
- A bounded TUF-style release trust core with separated threshold roles,
  dual-threshold sequential root rotation, expiring linked metadata,
  rollback/freeze protection, exact target verification, and a crash-safe
  serialized monotonic trust store. The `runtrue-update` CLI also emits
  dependency-complete CycloneDX SBOMs bound to `Cargo.lock` identities and
  registry checksums, plus canonical release provenance.
- A release toolchain and manual promotion runbook for amd64/arm64 archives,
  out-of-band roots, signed metadata, SBOM/provenance evidence, and exact target
  verification. Automated publication remains disabled until it runs on
  Runtrue. See the [release runbook](docs/operations/releases.md).
- Pinned Rust 1.94, Go 1.24, and Node.js 22.17 verification gates for formatting,
  all targets, workspace and component tests, Clippy, schema/API/migration
  conformance, deployment validation, dependency auditing, and every shipped
  image build.

## Build and verify

The project MSRV is pinned to Rust 1.94.0:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 tests/conformance/check_schema.py
python3 tests/conformance/check_openapi_routes.py
python3 tests/conformance/check_migrations.py
deploy/tests/validate.sh

npm --prefix web test

(cd components/github-signer && go test ./...)
```

## Local workflow path

The smallest end-to-end path uses the native executor:

```bash
cargo run -p runtrue-cli -- validate \
  --workflow examples/workflows/secure-ci.yaml

cargo run -p runtrue-cli -- capsule smoke \
  --workflow examples/workflows/secure-ci.yaml \
  --json

cargo run -p runtrue-cli -- run smoke \
  --workflow examples/workflows/secure-ci.yaml \
  --allow-native \
  --replay-bundle runtrue.replay.json

cargo run -p runtrue-cli -- replay runtrue.replay.json --allow-native

cargo run -p runtrue-cli -- compare-capsule runtrue.replay.json smoke \
  --workflow examples/workflows/secure-ci.yaml
```

Without `--workflow`, the CLI discovers YAML files in `.runtrue/workflows/`.
`--json` provides machine-readable success and error output. Run
`cargo run -p runtrue-cli -- --help` for the complete command surface, including
workspace-local secrets and variables.

Native execution is not a sandbox. It runs processes as the invoking user and
cannot enforce filesystem or network denial against them. `--allow-native` is
an explicit acknowledgement, not an isolation mechanism; use only reviewed
workflows on a trusted or disposable host.

## GitHub Actions import

The released server and CLI composition enables the `github-actions` frontend
feature by default. Core-only builds can omit the adapter with
`--no-default-features`; the private-repository dependency and extraction rules
are defined in
[`docs/architecture/workflow-frontend-extraction.md`](docs/architecture/workflow-frontend-extraction.md).

Analyze a workflow and emit native YAML only if no blocking compatibility
finding remains:

```bash
cargo run -p runtrue-cli -- import github path/to/github-workflow.yml \
  --output .runtrue/workflows/ci.yaml \
  --report-output runtrue-compatibility.json \
  --lock-output .runtrue.lock
```

Unsafe interpolation, `pull_request_target` trust conflicts, mutable action or
service references, raw secret transfer, host mounts, and unsupported GitHub
runtime behavior are reported rather than silently approximated.

The importer supports the common checkout-and-run shape. `actions/checkout`
materializes the exact authenticated event commit as a verified source snapshot
before any step runs; it does not persist provider credentials or trust a
pull-request-controlled remote. Static Linux `run` steps execute with `bash` or
`sh`. A digest-pinned Node container action can request a short-lived provider
credential and publish a commit status, check run, or pull-request review using
only the permissions declared by the workflow:

```yaml
on: pull_request

permissions:
  contents: read
  pull-requests: write
  checks: write
  statuses: write

jobs:
  review:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/build.sh
        shell: bash
      - uses: docker://registry.example/runtrue/review@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        with:
          github-token: ${{ github.token }}
```

The credential is delivered through a private step-scoped file and the SCM
egress broker, never through the environment. Shell steps do not receive it.

Runner checkout materialization keeps verified source manifests and blobs in a
bounded, persistent local CAS. Runners advertise only complete source snapshots,
and scheduling treats the signed Capsule's source-tree digest as a soft locality
preference. Every run still obtains a short-lived, lease-bound source ticket;
local hits avoid object transfer but never bypass authorization. Workspaces are
created independently from immutable cached bytes, so jobs never share a
writable checkout.

Requested report, lock, and workflow files must use distinct non-symlink
paths. They are fully staged before publication, with the native workflow
published last so a failed lock/report write cannot leave a partial import.

## Remote submission with exact parity

`runtrue submit [JOB]` compiles the exact workflow, event, source/base commits,
selected job, lockfile, and server policy context locally. It creates the
signed server Capsule idempotently, compares its canonical bytes and digest with
the local Capsule, and creates a run only after an exact match:

```bash
cargo run -p runtrue-cli -- submit build \
  --workflow .runtrue/workflows/ci.yaml \
  --server https://runtrue.example \
  --repository-id repo-ci \
  --token-file .runtrue/api.token
```

Direct API workflow bytes are intentionally treated as a changed definition,
not as authenticated SCM content. The first submit therefore stores the exact
signed Capsule and reports `run_created: false` plus every required approval. An
eligible reviewer records each decision against the displayed subject digest:

```bash
cargo run -p runtrue-cli -- seal approve APPROVAL_ID \
  --subject-digest sha256:... \
  --reason "Reviewed the exact workflow and risk diff" \
  --rule-id workflow-security-owner \
  --server https://runtrue.example \
  --token-file .runtrue/approver.token
```

Rerun the identical `submit` command after all listed gates are approved. Its
idempotency keys recover the same Capsule and create exactly one run. A pending
approval is a successful Capsule submission; denied or expired approvals return a
validation exit without attempting run creation.

The token file must be a non-symlink regular file with mode `0600`. Proxies
and redirects are disabled. Plaintext HTTP requires
`--allow-loopback-http` and an IP-literal loopback server, for local evaluation
only.

## Control plane and recovery

`runtrue-server` defaults to loopback HTTP and requires a bootstrap token. For a
local evaluation, create a private mode-`0600` token file, then run:

```bash
cargo run -p runtrue-server -- \
  --bootstrap-token-file .runtrue/server/bootstrap.token \
  --database .runtrue/server/control-plane.sqlite \
  --data-root .runtrue/server/data
```

Use `Authorization: Bearer ...` for the API. The preliminary contract is
[api/openapi.yaml](api/openapi.yaml), and server/SCM configuration is described
in [bins/server/README.md](bins/server/README.md). Configure a mode-`0700` Git
mirror root to enable durable webhook-to-run planning; mirror refresh remains
an operator responsibility. Caller-supplied Capsule YAML is always treated as a
changed workflow and requires exact workflow-definition approval. Workload
OIDC tokens are minted only through the runner mTLS broker; bearer API clients
can read discovery/JWKS but cannot mint workload identity.

Backup and restore use the `runtrue-backup` binary. Restore always enters safe
mode, increments the installation fence, expires old leases, marks in-flight
jobs lost, and requires explicit activation after verification. Follow the
[single-node recovery runbook](docs/operations/single-node-backup-restore.md).
Air-gapped installations should also follow the
[air-gapped deployment architecture](docs/operations/air-gapped-deployment.md).

## Important remaining boundaries

The historical workstream decomposition is retained in the
[version-one remainder implementation plan](docs/architecture/version-one-remainder-plan.md),
but this section and the executable release gates define the current v0.x
boundary.

- Native, OCI, Wasm, and Firecracker execution are wired into the runner. The
  remaining backend work is production-grade image/catalog provisioning and
  attempt-aware retry reporting in the v1 Firecracker guest protocol. The v1
  MicroVM guest also rejects host cache/artifact capture until its authenticated
  guest protocol carries an explicit filesystem transfer contract.
- Service declarations are compiled and the remote OCI runner supports
  literal-environment services, but Native, Wasm, and Firecracker paths reject
  service lifecycle they cannot enforce. Dynamic matrices are also not
  complete. Reusable workflows are expanded from exact
  locked local content or authenticated SCM mirror objects as described in
  [reusable workflow compilation](docs/architecture/reusable-workflows.md).
- GitHub human OIDC, durable browser-session HTTP wiring, installation setup,
  and repository onboarding are implemented. Passkeys/TOTP and provider-neutral
  browser administration remain outside the v0.x profile; bootstrap and scoped
  API credentials remain available for operator automation.
- The secure Git mirror/hydration library implements pinned public DNS,
  scoped credentials, private mirrors, quarantine, bounded maintenance, and
  immutable dissociated hydration. GitHub App webhook, repository selection,
  planning, and check publication are wired; broader SCM providers and fully
  automated mirror lifecycle management remain outside the v0.x profile.
- Promotion requests are durable, but a complete asynchronous scan/promotion
  worker and cloud-specific signing/deployment integrations are not complete.
- The default deployment is SQLite plus local files. PostgreSQL, S3-compatible
  blobs, multi-replica HA, regional cache agents, persistent BuildKit/sticky
  volume services, and full air-gap tooling remain roadmap work. The runnable
  [single-node evaluation package](deploy/README.md) and signed release assets
  are not an HA or production TLS topology.
- Windows/macOS agents, Kubernetes/GPU pools, and heterogeneous remote
  execution are not implemented.

Every unsupported security-relevant behavior is intended to reject explicitly;
it must not degrade to native execution, ambient credentials, mutable content,
or a permissive policy result.

## Repository map

- [docs/technical-design.md](docs/technical-design.md): product, threat model,
  architecture, protocols, roadmap, and acceptance criteria.
- [schemas/workflow/v1.json](schemas/workflow/v1.json): native workflow schema.
- [proto/runner/v1/runner.proto](proto/runner/v1/runner.proto): versioned runner
  protocol.
- [docs/adr](docs/adr): architecture decisions.
- `crates/`: compiler, engine, executors, policy, storage, security, and control
  primitives.
- `bins/`: CLI, server, runner, guest, image, and signed-update tooling.
