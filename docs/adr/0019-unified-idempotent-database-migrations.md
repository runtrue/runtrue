# ADR 0019: Unified idempotent database migrations

- **Status:** Accepted
- **Date:** 2026-07-17
- **Compatibility scope:** target architecture for unreleased v0.x
- **Detailed decision under:** ADR 0016

## Context

Runtrue supports an embedded SQLite control-plane database and is adding an
external PostgreSQL backend under ADR 0016. Both backends hold security- and
correctness-critical state, including installation identity, leases, fencing
generations, idempotency records, audit chains, secrets, approvals,
deployments, Artifacts, and lifecycle operations.

Database work is retried after process interruption, serialization failure,
connection loss, recovery, or an ambiguous acknowledgement. A retry must not
create a duplicate row, repeat a state transition, advance a generation or
budget twice, or resend an external effect.

Migration safety comes first. Runtime mutation guarantees are meaningful only
when every process agrees on the schema, migration history is immutable,
concurrent starters serialize correctly, and an interrupted migration can be
retried without exposing a partial result.

The current backends do not have one migration contract. SQLite uses
`PRAGMA user_version` to select migration files and separately records versions
in `schema_migrations`. PostgreSQL uses `runtrue_schema_migrations`, SHA-256
checksums, and a transaction-scoped advisory lock. Their histories also have
different local version sequences because PostgreSQL is being introduced by
persistence boundary rather than by mechanically translating every SQLite
migration.

One SQL dialect cannot describe both schemas cleanly. SQLite and PostgreSQL
differ in types, locking, catalog inspection, DDL, constraint evolution, and
online-operation facilities. Conversely, duplicating migration ordering,
identity, checksumming, validation, and reporting for every future backend
would make those guarantees drift.

Defaults and backfills are another source of divergence. A database default
may be evaluated at a different time, use backend-specific behavior, or hide
that application code failed to provide a domain value. Runtrue needs one
source of truth for semantic defaults and deterministic treatment of existing
rows.

## Decision

### 1. Migration-first rollout

Runtrue completes and validates the migration contract before beginning the
repository-wide remediation of runtime mutation SQL.

The ordered work is:

1. inventory and freeze the existing SQLite and PostgreSQL histories;
2. introduce the unified migration catalog, ledger contract, and interface;
3. bridge each recognized legacy history to a verified baseline;
4. validate fresh creation, upgrades, retries, concurrent startup, and drift;
5. declare the migration gate complete; and only then
6. inventory and remediate runtime mutations by persistence boundary.

Idempotence-related runtime SQL changes are not mixed into the migration phase
unless they are required to implement or validate the migration machinery.

### 2. One logical catalog, backend-specific implementations

Every new schema change is one logical migration with:

- a stable migration ID and monotonically ordered sequence;
- a backend-independent purpose and logical schema generation;
- shared preconditions, postconditions, and data invariants;
- a digest of that shared definition;
- one implementation for each backend that supports the affected persistence
  boundary; and
- a digest of the exact selected backend implementation.

The catalog declares the order once. Backend implementations may use different
SQL or typed migration code, but they cannot assign different meaning to the
same migration ID.

The repository stores new migrations as logical units with backend payloads,
rather than extending independent backend migration lists. A future backend
adds its implementation of the catalog and passes the same migration contract
suite. It does not reimplement ordering, checksum policy, ledger semantics,
failure classification, or reporting.

This is not a generic SQL dialect, schema ORM, or runtime repository
abstraction. Backend SQL remains free to use the correct database-native
types, constraints, locks, and DDL.

### 3. Historical cutover

Published or applied migration files are immutable. Their local version
numbers are not retroactively renumbered or forced into a false one-to-one
mapping.

Each backend receives a one-time bridge into the unified catalog:

- SQLite validates a recognized legacy `PRAGMA user_version`, legacy ledger,
  and schema shape before recording its baseline.
- PostgreSQL validates its existing ledger checksums and schema shape before
  recording its baseline.
- The baseline identifies the exact supported legacy lineage and its verified
  logical schema state.
- An unrecognized version, missing legacy record, modified PostgreSQL
  checksum, or incompatible schema fails closed.

The bridge does not claim to know the exact bytes that created a legacy SQLite
database whose old ledger did not record checksums. It records that the
database matched a reviewed legacy lineage and schema baseline at cutover.

A defect in published history is corrected by a new forward migration. Pending
or unpublished migrations may be corrected before they become part of an
accepted history.

### 4. One migration ledger contract

Every backend exposes a ledger named `runtrue_schema_migrations` with the same
logical fields and constraints:

- ordered sequence;
- stable migration ID;
- shared-definition SHA-256 digest;
- backend-implementation SHA-256 digest; and
- application time in checked Unix milliseconds.

The table name, field meanings, uniqueness rules, digest encodings, and API
semantics are portable. Physical column types and bootstrap DDL may differ
where a backend requires it. Runtrue does not weaken SQLite typing or
PostgreSQL constraints merely to make the two `CREATE TABLE` statements
textually identical.

The ledger has one row per applied logical migration. Replaying the same
migration ID with the same definition and implementation digests is a no-op.
Reusing an ID or sequence with a different digest is invalid migration history
and fails startup.

If the ledger says a migration is applied but its required postcondition does
not hold, startup fails closed. If target objects exist without the matching
ledger entry, Runtrue does not silently adopt them. Reconciliation requires an
explicit reviewed recovery operation.

### 5. Retirement of `PRAGMA user_version`

The unified ledger is the sole continuing source of migration truth.
`PRAGMA user_version` is not advanced alongside it and is not consulted during
ordinary startup after the SQLite bridge.

During the one-time bridge, Runtrue:

1. reads the pragma and legacy `schema_migrations` ledger;
2. verifies that they describe a recognized legacy lineage;
3. verifies the corresponding schema invariants;
4. records the unified baseline atomically; and
5. writes a reserved unsupported legacy value so an older binary fails closed
   instead of opening a newer unified-ledger schema.

Subsequent binaries use only `runtrue_schema_migrations`. Maintaining two
authoritative version counters is forbidden.

### 6. Stable migration interface

All database backends implement the same migration operation:

```text
ensure current schema(backend, catalog, installation identity, time)
    -> migration report
```

The operation has these backend capabilities:

- acquire an exclusive migration session;
- begin the transaction that owns the migration decision;
- bootstrap or verify the ledger;
- read applied migration identities and digests;
- inspect migration-specific schema and data invariants;
- execute the selected backend implementation;
- record successful application;
- commit the schema and ledger atomically; and
- classify retryable contention separately from invalid history or drift.

SQLite implements the exclusive session with an immediate write transaction.
PostgreSQL implements it with the fixed transaction-scoped advisory lock and
transactional DDL. A waiting starter rereads the ledger after acquiring the
session; it never acts on a version observed before waiting.

The public interface and behavioral contract are shared. Transaction types,
catalog queries, placeholder syntax, and lock primitives remain private to the
backend adapter. Runtrue does not introduce a universal normalized schema AST;
migration-specific invariant IDs are shared while their inspection queries are
backend-specific.

### 7. Atomic application and retry

The migration body, postcondition verification, and ledger insert commit in
one transaction.

If the process fails before commit, neither the schema change nor its ledger
row is durable and the complete migration may be retried. If acknowledgement
is lost after commit, the next attempt observes matching digests and performs
no mutation.

Concurrent starters produce either one successful application followed by
verified no-op startups, or the same deterministic failure when history or
schema state is invalid. Duplicate application and partially recorded schema
generations are forbidden.

`IF NOT EXISTS`, `IF EXISTS`, `INSERT OR IGNORE`, and `ON CONFLICT DO NOTHING`
do not establish migration idempotence by themselves. They may be used only
when the migration also verifies that the existing or absent object represents
the exact expected condition.

### 8. Preconditions, postconditions, and drift

Each migration declares only the invariants it needs rather than a portable
serialization of the entire backend catalog.

Preconditions cover the source objects, constraints, and data assumptions on
which the migration depends. Postconditions cover the complete target
invariants introduced or changed by the migration. Backend adapters evaluate
those invariants using native catalog and data queries.

An object with the expected name but incompatible columns, types, constraints,
indexes, triggers, or behavior is drift. A conflicting existing value during a
backfill is also drift. Either condition fails without adding the ledger row.

Fresh-database golden-schema tests and supported-version upgrade tests provide
whole-schema coverage. Runtime startup does not build or compare a generic
cross-database schema AST.

### 9. Table rebuilds and destructive changes

A table rebuild uses migration-specific intermediate names and verifies:

- the exact required source invariants;
- absence of unexpected intermediate objects;
- an explicit mapping for authoritative columns;
- required row-count and data-integrity conditions;
- dependent indexes, constraints, triggers, and views; and
- the complete target postcondition.

The rebuild, copy, verification, replacement, and ledger update occur in the
same migration transaction where the backend supports the operation.

A destructive or contract-narrowing migration includes an explicit
preservation, archival, or intentional-deletion decision. Existing data is not
discarded merely because a target object already exists.

### 10. Code-owned defaults and deterministic backfills

Application code is the source of truth for defaults with domain meaning.
Writers explicitly provide those values instead of depending on a database to
choose them.

A new required value follows an expand, write, backfill, and constrain
sequence:

1. add a nullable or otherwise backward-compatible representation;
2. update application writers to provide the canonical value explicitly;
3. backfill existing rows with a deterministic value or derivation supplied by
   typed migration code;
4. verify every backfilled value;
5. add the final required constraint; and
6. remove transitional compatibility after older writers are unsupported.

When old and new binaries may overlap, these steps are separate logical
migrations across compatible releases. When migration occurs under exclusive
offline ownership, compatible steps may share one transaction.

Backfills do not use a backend clock, randomness, session setting, row-order
accident, or backend-specific interpretation of a default. Timestamps,
identifiers, digests, generations, and security states are selected explicitly
by code. Set-based SQL may be used for scale, but semantic values are passed
from the shared migration definition rather than independently duplicated in
backend SQL.

A database `DEFAULT` is retained only when it is an invariant storage default,
has the same meaning on every supported backend, agrees with the code-owned
value, and is covered by cross-backend tests. It is not the primary expression
of business behavior. A non-null existing value is validated, not overwritten
merely because it differs from a new default.

### 11. Migration validation gate

The migration phase is complete only when automated tests cover:

- fresh SQLite and PostgreSQL databases;
- every supported legacy baseline and upgrade path;
- repeated startup at the current generation;
- concurrent starters;
- failure before execution, during execution, and before commit;
- loss of acknowledgement after commit;
- changed definition and implementation digests;
- missing, reordered, duplicated, and future ledger entries;
- incompatible schema objects and backfill values;
- deterministic defaults and backfills;
- table rebuild preservation;
- installation identity mismatch; and
- SQLite-to-PostgreSQL transfer inventory compatibility.

The same contract suite is required for a future backend. Migration catalog
validation, digest verification, and supported-upgrade tests are required
repository checks for migration changes.

### 12. Runtime mutation phase

After the migration gate passes, every durable runtime mutation is classified
as one of:

- create once under a stable operation identity;
- convergent upsert;
- compare-and-set state transition;
- append once with identity and content digest;
- scoped delete or expiry, with a tombstone where proof is required; or
- identified accumulation for counters and budgets.

Repeating the same logical operation and equivalent input produces the same
durable state and semantic result. Reusing an operation identity with different
input is an explicit conflict.

A zero-row update is a successful replay only after the stored target state is
verified. Otherwise it is a missing resource, stale fence, invalid transition,
or conflict. `INSERT OR IGNORE` and `ON CONFLICT DO NOTHING` require equivalent
read-back validation.

Logical operations spanning statements use one transaction. Serialization,
deadlock, busy, and connection retries apply to the complete declared
transaction, never an individual statement after partially observed work.

Database idempotence does not make an external effect idempotent. External
mutations retain ADR 0011's durable operation identity and requested,
accepted, rejected, or indeterminate protocol.

## Consequences

- Migration correctness is established before runtime SQL remediation.
- New backends reuse one catalog, ledger contract, interface, and conformance
  suite while retaining database-native SQL.
- SQLite no longer has two authoritative migration counters.
- Historical SQLite and PostgreSQL sequences remain honest and immutable; the
  unified model begins at verified baselines.
- Shared-definition and backend-implementation digests detect both semantic
  and physical migration changes.
- Migration-specific invariants avoid the complexity of a generic schema AST.
- Domain defaults and backfills have one code-owned meaning across backends.
- Migration manifests, adapter verification, fixtures, and failure-injection
  tests add implementation work.
- Idempotence does not imply commutativity, unrestricted retry, or exactly-once
  external effects.

## Alternatives considered

### One SQL file for every backend

Rejected because portable syntax would either exclude required backend
features or encode an incomplete lowest-common-denominator schema.

### Independent migration frameworks per backend

Rejected because ordering, checksums, drift policy, error handling, and tests
would diverge and would have to be rebuilt for every future database.

### A generic schema AST or ORM

Rejected because Runtrue needs shared migration semantics, not a new runtime
persistence abstraction. Native schema features remain important to correctness
and operations.

### Keep `PRAGMA user_version` synchronized with a ledger

Rejected because two authorities can disagree and require lineage-specific
reconciliation. The unified ledger is sufficient.

### Rewrite or renumber historical migrations

Rejected because already-applied databases would retain the old meaning and
create divergent histories under the same identifiers.

### Add conditional DDL and conflict suppression everywhere

Rejected because suppressing an error does not prove that an existing object or
row matches the requested state.

### Let database defaults define application behavior

Rejected because defaults may differ by backend, deployment order, and database
evaluation time. Domain semantics belong in typed code.

### Remediate runtime SQL before migrations

Rejected because runtime guarantees depend on a known, verified, and
consistently upgraded schema.

## Review triggers

- A backend cannot atomically bind a ledger record to its schema change.
- A future database cannot implement the migration interface without exposing
  backend-specific behavior through the public contract.
- A logical migration cannot retain one meaning across supported backends.
- Legacy state cannot be distinguished safely from schema drift.
- A migration requires non-transactional DDL or an online multi-phase process.
- A backfill cannot be deterministic or code-owned.
- A migration-specific invariant proves too weak to detect a material schema
  mismatch.
- An external mutation is proposed for automatic retry without a destination
  idempotency or recovery contract.
