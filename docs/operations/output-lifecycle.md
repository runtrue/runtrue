# Durable output lifecycle operations

Schemas 19 and 21 add the bounded lifecycle ledger used for artifact scanning,
evidence-bound promotion, tenant storage admission, backup pins, and
two-generation CAS collection. These records are authoritative. Never delete
or edit them to recover space.

Artifact identity has three deliberately different values. `artifact_id` is
the digest of the immutable `ArtifactRecord` CAS object. `content_digest` and
the catalog's current `manifest_digest` identify the file blob or directory
tree manifest referenced by that record. `provenance_digest` identifies the
signed statement embedded in the record; it is not by itself a CAS object.
Lifecycle and backup code begin at `artifact_id`, cryptographically verify the
record, and then traverse content and promotion ancestry. Treating a content
or provenance digest as an `ArtifactRecord` is a correctness error.

## Admission and quarantine

Configure `tenant_storage_quotas` before enabling cache, artifact, report, or
source create tickets. A newly observed tenant receives the conservative
single-node default of 64 GiB and 100,000 objects until an operator replaces
it. Ticket issuers first call the atomic reservation API;
concurrent reservations charge both bytes and object count under an immediate
SQLite transaction. Schema 21 binds each reservation to exactly one
filesystem ticket. An unbound ticket left by a crash is not authority and is
rejected at commit; retry issues or recovers one bound ticket. Immutable commit
keeps the reservation charged until catalog or cache-generation metadata
atomically creates the logical `tenant_storage_objects` charge and releases
the reservation. An exact reservation, ticket, and object replay succeeds. A changed replay,
unknown tenant/quota, expired reservation, or either quota overflow fails
closed before a ticket is issued. Committed reservations remain charged until
the corresponding catalog transaction is durable and explicitly releases the
reservation.

Artifact scan requests bind the tenant, immutable artifact record,
classification, manifest, provenance statement, and scanner identity. The
bounded worker verifies the ArtifactStore record, signature, provenance link,
and complete content graph before calling the
narrow scanner client. Scanner processes run under a separate service identity
without runner, SCM, signing, or object-store credentials. Timeout, malformed
response, crash, or unavailable scanner records a bounded error code and leaves
the artifact quarantined. Scanner evidence is non-empty, byte-bounded, hashed,
and published into CAS before the journal can say passed or failed. Trusted promotion requires the exact passed scan
result or an explicit waiver/approval digest.

Promotion creates a durable intent before changing the immutable store. The
worker reloads the tenant-filtered catalog record, verifies immutable bytes and
provenance, checks the single permitted classification/trust edge and exact
evidence, then writes a new immutable record. Source bytes are never replaced.
A lost response replays the same store operation and completes the same journal
result. The promotion timestamp is anchored to the durable intent so its ID
cannot drift across restart. Canonical intent evidence and referenced
scan/approval evidence must exist in CAS. Source, evidence, target, or result
substitution conflicts. Cache promotion likewise recognizes and reconciles an
already-published exact target generation instead of promoting twice.

`RunnerDataPlane::{scan_artifact_once,promote_artifact_once,collect_outputs_once}`
are the production invocation adapters. Invoke them from a bounded durable-task
loop with unique worker identities and fresh random GC lease tokens. The
scanner remains an isolated service client; do not replace it with in-process
repository or workload execution.

## Garbage collection

Run only one lifecycle worker per installation unless all workers use the
fenced `lifecycle_gc_control` lease. Configure positive bounds for root count,
reachable objects, inventory objects, manifest bytes, lease duration, and the
safety horizon. Recommended initial safety horizon is 24 hours and must exceed
the longest upload, reconciliation, backup, and clock-skew window.

Each cycle performs these durable phases:

1. Acquire or resume the installation-wide lease and generation.
2. Load roots for active cache heads, retained/legal-hold artifacts, pending
   transfers/commits/promotions, referenced source snapshots, scan/promotion
   evidence, and active backup pins.
3. Verify and expand the exact cache, artifact-record, Git-source, and tree manifest
   formats under configured limits.
4. Inventory the private CAS namespace. Unexpected names, links, special
   files, corrupt objects, or a bound overflow stop the cycle.
5. Sweep only objects older than the horizon and absent from two consecutive
   mark generations. Bytes are digest-verified immediately before unlink.
6. Commit per-generation counters and a content-free audit summary.

An interrupted mark is abandoned after its fenced lease expires. An unlink
followed by a database crash is reconciled from the persisted candidate row;
missing-object replay is accepted only for that exact second-generation
candidate. Newly committed objects remain protected by the horizon. Legal
holds and unreleased backup pins have no expiry fallback.

Alert on `scan_failed_or_error`, stalled `scan_pending`, active reservations
near either quota, GC lease expiry, root/inventory bound errors, corrupt CAS,
and unexpected growth in candidate or swept bytes. The lifecycle metrics API
reports only counts, generation, and byte totals; audit events contain IDs and
digests, never object contents.

## Backup and restore

`RUNTRUE_DATA_ROOT` is authoritative and must be passed as `--blobs-dir`. The
Docker Compose deployment does this explicitly. Backup verification checks
that every database catalog root is present in the archived CAS namespace and
then decodes each typed root under explicit bounds. Artifact records are
signature/provenance verified; cache, artifact-directory, and Git-source
manifests are traversed; every reachable blob is rehashed. A present root with
a missing child is an invalid backup, not a successful partial archive.
Missing artifact content/records, source manifests, active cache manifests,
pending transfer objects, scan/promotion evidence, or backup pins reject the
archive. Restore therefore remains in safe mode when an authoritative root is
missing; activation acknowledgement cannot bypass local root verification.

Cache may be omitted only after a future explicit non-authoritative-cache
configuration records that policy in the backup manifest. Version one does
not infer disposability from a missing cache directory.

## Current boundary

The bounded invocation adapters are available to the server, but the
evaluation binary does not yet configure an external scanner client or start a
continuous lifecycle task loop. Until that wiring is configured, scans,
promotions, retention, and GC advance only when an operator-owned worker calls
the adapters. This is an L1 production boundary, not L2/L3 completion; do not
enable trusted promotion or rely on automatic reclamation without the worker
and its alerts running.
