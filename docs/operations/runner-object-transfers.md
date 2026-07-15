# Runner object-transfer operations

Runner cache and artifact bytes are streamed through the authenticated gRPC
channel; runners never receive object-store credentials. Protocol v1 remains
accepted as the N-1 generation. Protocol v2 is the preferred newest-common
generation and its object service is registered on the authenticated runner
listener. A v1 runner continues to use the frozen v1 cache/artifact data path;
v2 source hydration is never silently translated into an ambient clone or a
native fallback.

Generation two uploads send exactly one authorization header followed by
offset-bearing chunks; zero-byte objects are header-only. The server rejects a
chunk before the header, a second header, empty or oversized chunks, gaps,
overlaps, bytes beyond the declared size, early EOF, and final size/digest
mismatch. Generation two completion uses typed terminal states and typed
cache/artifact claims. Artifact claims include the declaration name and job
attempt, which are checked against the exact durable lease-scoped commit before
the terminal transition. Legacy durable pending completions remain replayable
through generation one.

CI freezes the encoded v1 and v2 descriptor sets with checked-in SHA-256
fixtures and separately asserts their service, field-presence, oneof, and
streaming shapes. A fixture change requires an explicit compatibility review;
operators must not infer that refreshing a hash makes an incompatible runner
safe for a rolling upgrade.

The current bounded single-node profile uses 256 KiB chunks, a four-chunk
runner upload queue, an eight-chunk server download queue, and at most eight
concurrent server transfers. Ticket byte limits bound each blob and aggregate
upload. Uploads have a 15-second per-frame idle bound and an absolute lifetime
no longer than ten minutes, the ticket expiry, or the lease expiry. The
deadline is rechecked before every frame, CAS publication, durable journaling,
and acknowledgement. Uploads use private mode-0600 staging, are synced, and
become visible in CAS only after exact digest and size verification. Downloads
verify immutable CAS content before releasing the first byte and publish
runner-local staging only after inline size/digest verification.
CAS-to-workspace materialization
also uses a fixed-size copy buffer, rehashes private create-new staging, and
links it into the destination only after exact size and digest verification.
Cancellation drops queues and private staging is removed.

The semaphore, chunk size, queue depths, and staging-disk allocation are still
fixed single-node values rather than per-runner configuration with a durable
staging quota. This is an explicit L3 closure risk; operators must not treat the
bounded single-node profile as multi-runner or disk-pressure certification.

Cache lookup has a two-second deadline and cache transfer has a ten-second
deadline. The first unavailable or unverifiable cache operation opens the
run-local breaker; later cache RPCs are counted as bypassed and the structured
reason is `cache_transfer_unavailable_or_unverified`. Cache failure remains a
bounded miss. Artifact and source transfer errors remain terminal and retain
the correctness timeout.

`runner_object_transfers` is the durable transfer journal. Migration 14 copies
schema-12 upload records as verified generation-one uploads. Operators should
alert on transfer concurrency exhaustion, digest/size rejection, ticket-budget
rejection, staging I/O failure, and sustained cache-breaker bypasses. These
events contain identities and byte counts, never object contents.

During restore, the database and data root must come from the same backup
epoch. A verified journal record without a terminal job is safe: the active
lease/fence/attempt is revalidated before commit, and abandoned immutable
objects remain future GC candidates.

Source downloads reserve a `transferring` row before the first frame and mark
it `verified` only after the exact verified CAS reader reaches its declared
length. A disconnect leaves recoverable transfer state. Exact ticket/digest
retry is allowed; changed lease, fence, attempt, digest metadata, or aggregate
ticket bytes is rejected. The first response frame is one immutable header and
all later chunks have contiguous offsets beginning at zero. The current
server idle bound is 15 seconds per downstream frame and the global source
ticket bound is 8 GiB, additionally capped by the configured CAS tree limit.
