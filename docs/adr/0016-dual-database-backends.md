# ADR 0016: Embedded SQLite and external PostgreSQL backends

- **Status:** Accepted, implemented
- **Date:** 2026-07-17
- **Compatibility scope:** unreleased v0.x
- **Detailed decision under:** ADR 0014

## Context

Runtrue's durable control plane stores queue claims, runner heartbeats, leases,
fencing generations, idempotency records, audit chains, encrypted secret
material, and lifecycle state. Small and local installations benefit from a
single embedded database with no service dependency. Larger installations need
concurrent writers, database-native high availability, managed backups, and
operational tooling that do not fit a single SQLite writer.

The current store is not a portable repository abstraction. It is one
`rusqlite::Connection` behind a mutex, with transaction logic distributed
across more than one hundred tables and hundreds of immediate transactions.
Changing placeholders and column types mechanically would risk the exact
atomicity, fencing, and idempotency properties the store exists to enforce.

## Decision

### Backends

SQLite remains the embedded, zero-service default and continues to use
`rusqlite`. PostgreSQL is the supported external backend. We do not add MySQL,
a generic SQL dialect, or an ORM abstraction.

PostgreSQL is selected because this workload needs transactional row locking,
serializable transactions, `FOR UPDATE SKIP LOCKED` queue claims, advisory
locks for bounded coordination, mature connection pooling, replication, and
managed high-availability offerings. SQLite remains suitable for evaluation,
developer, edge, and modest single-server installations.

### Extraction boundary

Persistence contracts are extracted at complete use-case or transaction
boundaries, never per SQL statement. A boundary owns validation, locking,
idempotency, state transition, audit append, and commit together. Both
backends implement the complete boundary inventory:

1. installations, identity, tenants, and authorization;
2. SCM installations, repositories, and webhook normalization;
3. runs, Capsules, approvals, and workflow expansion;
4. runner pools, enrollment, scheduler claims, leases, and brokers;
5. secrets, variables, and provider configuration;
6. artifacts, cache, lifecycle, audit, and durable background tasks.

A backend is not advertised as a complete server backend until every boundary
passes the same behavioral contract suite. The existence of a PostgreSQL pool
or migration is not sufficient.

### Secrets, variables, and policy boundary inventory

The migration-8 boundary is intentionally broader than secret CRUD. Its
complete transaction contract includes:

- configuration grouping: `configuration_projects` and
  `configuration_project_targets`;
- secret state: `secret_metadata` and `secret_vault_snapshots`, including
  create, rotate, delete, scoped resolution, project/repository precedence,
  and encrypted snapshot replacement;
- variables: `variables`, `variable_versions`, and `variable_snapshots`,
  including idempotent version creation and immutable snapshot digests;
- policy lifecycle: `policy_versions`, `policy_bundle_drafts`,
  `policy_simulation_reports`, `policy_shadow_reports`,
  `tenant_policy_states`, `policy_activations`, and
  `emergency_deny_replacements`;
- provider release authority: `external_secret_release_journal`, including
  reservation, delivery, indeterminate recovery, revocation, and exact subject
  binding; and
- workload identity grants: `oidc_grants` and `oidc_issuances`, including
  authorization, revocation, and unique audience/JTI issuance.

Runner secret leases and runner OIDC issuance journals are owned by the runner
authority boundary, while signer policy versions are owned by deployment and
provider state. They are dependencies of authorization checks but are not
duplicated in migration 8. Secret plaintext remains absent from metadata and
project tables; encrypted vault snapshot bytes remain exact bytes.

Migration 8 creates the sixteen independent tables above. Migration 11 owns
`external_secret_release_journal` because its reservation mutation must lock
and verify provider-configuration versions, repositories, runs, job attempts,
runners, and execution leases in one transaction.

Migration 11 persists and verifies deployment request/event rows against the
stable migration-9 run, job, approval, repository, environment, and lease
keys. Migration 10 owns `artifacts_catalog`, so reservation and start
transitions authorize the exact artifact
tenant, repository, source run/job/attempt, content/manifest/provenance
digests, classification, scan state, availability, retention, and promotion
evidence in the same transaction. Omitting those checks is not an admissible
partial PostgreSQL implementation.

### Transaction semantics

PostgreSQL implementations use explicit transactions. State transitions that
can race use row locks or compare-and-swap predicates. Queue consumers use
`FOR UPDATE SKIP LOCKED` only where an unlocked eligible row has equivalent
meaning; it is not used for arbitrary reads. Serialization and deadlock
failures retry only an entire declared transaction boundary, with a bounded
attempt count and jitter. An individual SQL statement is never retried after a
partially observed transaction.

Fencing epochs, lease generations, idempotency request digests, terminal-state
first-writer rules, restore safe mode, and audit append ordering have identical
meaning on both backends. Multi-server operation is a separate release gate;
PostgreSQL selection alone does not make every worker or maintenance loop
multi-replica safe.

### Data representation

Canonical JSON, Capsule bytes, signed material, digests, encrypted secret
payloads, and values participating in identities are stored as exact bytes or
text. They are not round-tripped through PostgreSQL `jsonb`, because its
normalization may change byte identity. `jsonb` may be used only for an
operational projection that does not participate in a signature, digest,
idempotency key, approval subject, or audit chain.

Unsigned Rust integers that can exceed PostgreSQL `BIGINT` require an explicit
checked encoding decision at their owning boundary. Silent casts are
forbidden. Timestamps retain the current checked Unix-millisecond semantics
unless a later protocol decision changes both backends.

### Configuration and credentials

Embedded configuration remains `RUNTRUE_DATABASE=/path/control-plane.sqlite`.
The external contract is a PostgreSQL URL loaded from
`RUNTRUE_DATABASE_URL_FILE`; the URL itself is not accepted as an environment
variable so credentials do not appear in ordinary environment inspection.
The runtime URL file and the migration/transfer URL file are separate
credentials. Each must be a regular UTF-8 file owned by the effective user,
with mode `0600`, exactly one link, no symbolic-link path component, at most
8192 bytes, and exactly one URL with no whitespace. The runtime role has only
schema usage and data privileges; only the explicitly invoked initialize,
migration, or transfer command receives schema-owner credentials.

Remote PostgreSQL requires `sslmode=verify-full` and a trusted server
certificate. Unix sockets and loopback development databases may explicitly
disable TLS. Production guidance uses separate migration and runtime roles;
the runtime role does not receive schema ownership. Connection limits and
timeouts are bounded configuration, not unbounded pool defaults.

The server exposes the external selector only while the machine-readable
boundary, transfer, and runtime inventories are complete. Startup verifies the
PostgreSQL schema generation, installation identity, and restore-safe-mode
state before starting HTTP, SCM, runner, or maintenance work. It never falls
back to SQLite after PostgreSQL is selected.

### Migrations

ADR 0019 freezes the separate historical SQLite and PostgreSQL directories and
bridges both into one ordered logical catalog. Each logical migration records
the SHA-256 digest of its shared definition and selected backend payload in the
portable `runtrue_schema_migrations` ledger. PostgreSQL migration execution
takes a fixed transaction-scoped advisory lock; SQLite takes an immediate write
transaction. Both bind schema, ledger, and installation identity atomically.

Migration roles apply forward-only DDL through an explicit command. Runtime
processes use a connect-existing path that starts with a read-only transaction,
requires the exact logical migration IDs and digests, and
verifies installation and recovery identity without taking a migration lock or
issuing DDL. Missing and outdated schemas direct the operator to initialize or
migrate with the separate migration credential. A changed digest is
corruption or an operator error and fails startup.

### SQLite to PostgreSQL transfer

`runtrue-db-transfer` provides `inventory`, `initialize`, `transfer`, and
`activate`. `initialize` creates or verifies a fresh active PostgreSQL control
plane using migration-owner credentials. The offline transfer path:

1. requires an offline SQLite database already in restore safe mode, opens it
   once with exclusive locking, and verifies its owner, mode, link count,
   inode, and data version throughout the copy;
2. migrate an empty PostgreSQL database;
3. copy exact canonical bytes and durable rows by owning boundary;
4. verify row counts, audit roots, object references, encrypted ciphertext,
   installation identity, and schema generation;
5. advance the installation fence and expire copied execution, broker, and
   enrollment leases; and
6. commits a durable verified report digest and requires explicit activation
   before accepting PostgreSQL writes.

There is no dual-write mode. Rollback to the source SQLite database is allowed
only before PostgreSQL accepts a new authoritative write. Afterwards rollback
is a restore operation with a new fence, not DNS or configuration reversal.

`runtrue-db-transfer inventory` emits the authoritative machine-readable
boundary inventory. `transfer` refuses with exit code 10 while any boundary is
unported and does not open either database or read the PostgreSQL URL file in
that state. A successful transfer leaves PostgreSQL in restore safe mode and
prints the exact installation identity and fencing epoch required by
`activate`. Activation locks and consumes the durable `verified` transfer
state, checks the report digest and exact fence, and refuses prepared, partial,
wrong-fence, or previously activated destinations.

### Backup and readiness

SQLite retains Runtrue's verified backup manifest and safe-mode activation.
PostgreSQL production backup uses database-native snapshots or base backup plus
WAL/PITR. Runtrue manifests continue to cover authoritative local object data.

Readiness verifies connectivity, supported migration generation, installation
identity, and restore-safe-mode state. Later gates add object-store and key
continuity. Liveness never claims database durability.

## Validation and rollout gates

- Every extracted boundary runs the same contract tests against SQLite and a
  disposable PostgreSQL database.
- Tests cover conflicting idempotency keys, terminal-state races, fencing,
  safe-mode restore, serialization retries, deadlocks, connection loss, and
  failover at each commit boundary.
- Migration CI upgrades every shipped schema and detects modified migration
  checksums.
- Canonical byte and audit-root comparisons are exact across backends.
- PostgreSQL server selection requires complete boundary, transfer, and runtime
  inventories. Multi-replica operation remains a separate release gate.

## Consequences

Runtrue keeps its simple embedded startup while gaining a deliberate path to a
managed external database. Backend SQL can use each database's concurrency
primitives without contaminating domain code with dialect branches.

The port is more work than a generic query wrapper because both backends retain
the same fencing, audit, idempotency, and recovery semantics. New durable
features must extend both backend contracts before their runtime paths can be
enabled.
