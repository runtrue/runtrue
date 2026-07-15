# Cache trust, reuse, and promotion operations

Runtrue derives cache scope on the server. Runners provide only declared
input digests and an optional user suffix; they cannot select a trust domain,
head, or generation.

## Scope rules

- Untrusted changes may read a policy-permitted verified-main candidate before
  their own quarantine candidate. They write only quarantine (or run-private
  state when the signed permission is narrower).
- Trusted branch jobs may read their exact normalized branch followed by
  verified main. If the signed Capsule lacks a branch identity, Runtrue deliberately
  falls back to an exact-commit branch scope, reducing reuse without broadening
  trust.
- Protected-main jobs may write `repository-main-verified` only when the
  signed permission requests verified writes and the active lease proves the
  exact Capsule passed approval and policy gates.
- Main/verified reads never include pull-request quarantine. A normal cache
  write can never change trust scope.

`CacheKeyMaterial` includes tenant, repository, purpose, platform, toolchain or
lock identity, canonical action/declaration/runtime definition, declared input
snapshot, policy epoch, and optional suffix. Run and source-commit identifiers
are excluded. Changing any material field produces a miss.

## Durable state and recovery

Schema 17 adds immutable generation records, compare-and-swap current heads,
an evidence-bearing promotion journal, and bounded access observations. Cache
bytes and manifests remain in the filesystem CAS.

A cache store commit occurs before its SQLite generation journal. If the
response is lost, the same claim ticket recovers the immutable generation and
the SQLite insert replays exactly. A changed replay conflicts. The first
post-upgrade journal entry may anchor an already-existing filesystem generation
at the exact store generation; subsequent SQLite head advances are strict CAS.

Promotion is a two-phase worker operation:

1. Persist a tenant-scoped intent binding source entry, target identity/scope,
   expected target head, and evidence digest.
2. Reload and fully verify the source manifest graph, evidence, trust edge, and
   target head.
3. Publish a new immutable target generation without mutating source bytes.
4. Atomically journal the target generation, advance the SQLite head, complete
   the intent, and append a tamper-evident audit event.

A restart after step 3 re-runs the same filesystem CAS operation and completes
the same journal result. A different source, evidence, target, or head is
rejected. Unknown and cross-tenant source IDs use the same not-found behavior.

## Bounds and failure behavior

Cache transfer time, bytes, concurrency, staging disk, and circuit breaking are
configured by the object-transfer data plane. Cache metadata/CAS outage during
lookup is a bounded miss; source and artifact integrity failures remain terminal.
Promotion failures never alter the source or silently downgrade to a normal
write.

Access observations cap the server-derived candidate list at 16 and contain
only digests, trust metadata, generation, byte count, latency, outcome, and
breaker state—never cached contents. Operators can query tenant-scoped counters
for hits, misses, health bypasses, saves, failures, denials, and promotion state.

## Lifecycle worker

Scheduling, scanning, evidence retention, quota admission, and immutable-object
collection are described in [durable output lifecycle operations](output-lifecycle.md).
No runner or repository workload receives direct promotion authority.
