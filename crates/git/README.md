# Runtrue Git intake and mirror

`runtrue-git` performs bounded object reads and maintains incremental bare mirrors for
trust-scoped runner acceleration. The mirror key is a domain-separated digest of the exact tenant and
repository identity. A normalized origin is recorded as immutable metadata, but credentials are
never written to the mirror.

Production origins are exact-host allowlisted HTTPS URLs. Every fetch resolves the hostname,
rejects the entire answer set if any address is private or special-purpose, and pins the accepted
A/AAAA set into the same Git/libcurl child with `http.curloptResolve`. The URL remains a hostname
so certificate validation and SNI retain their intended semantics. Redirects, proxies, interactive
authentication, inherited Git configuration, hooks, LFS filters, submodules, and non-HTTPS
origin transports are disabled. The authorization header is supplied only through Git's
`--config-env` mechanism and held in zeroizing memory.

Mirrors are constructed in private staging directories, checked with `git fsck`, bounded by
reference, object, file, pack, individual-object, and total-byte limits, synced, and atomically
published with operations relative to retained directory descriptors. Existing mirrors receive a
bounded `fetch --prune`; invalid state is renamed to quarantine. Writer contention and network or
mirror availability return an explicit cache miss so a caller can use its ordinary direct-clone
path.

Hydration accepts only a full object ID. It makes a non-local, non-hardlinked checkout, removes the
remote, rejects alternates, runs a full integrity check, records the exact mirror/commit binding,
and publishes through the retained destination-parent descriptor. Every published regular file
and directory, including `.git`, is non-writable. The runner must still mount this view read-only
when handing it to an untrusted guest; filesystem mode bits are defense in depth, not a sandbox.

Garbage collection is an explicit maintenance operation and never runs on the hydration critical
path. `maintenance_gc` uses `--prune=never` and follows with a full verification pass.

## Locked source submodules

The default source-manifest builder rejects every Git link. An opt-in primitive
can expand exact locked submodules only from caller-supplied `GitRepository`
handles whose local origin, Git-link object ID, committed `.gitmodules` entry,
and available commit all match a canonical `GitSubmoduleLock`. It recursively
preflights the complete graph under shared entry, byte, path, and depth limits,
rejects duplicate mounts and repository/origin cycles, and performs no fetch or
repository discovery. Validation failures happen before the CAS callback is
invoked.

Nested files are flattened beneath their mount paths in the existing
`GitTreeManifest` wire shape. The returned domain-separated submodule-lock
digest is an additional planning/approval input; it does not authorize SCM
access by itself. The current production SCM worker does not yet supply these
locks and therefore continues to reject submodules. There is no ambient
credential, `git submodule`, direct-clone, runner-network, or native-execution
fallback. End-to-end authenticated mirror acquisition, durable recovery, and a
clean remote runner test remain required before an L2/L3 claim.

## Reproducible benchmark report

The ignored test harness creates a declared two-commit local fixture and emits versioned JSON with
every raw sample plus nearest-rank p50/p95 values:

```console
CARGO_INCREMENTAL=0 cargo test -p runtrue-git mirror_benchmark_report -- --ignored --nocapture
```

The report includes the fixture name, repository bytes, ref/object counts, exact source/base
commits, iteration counts, and cold-fetch, warm-fetch, and hydration milliseconds. No fixture
numbers are checked in or presented as universal performance claims; preserve the emitted JSON and
machine/storage description when publishing a result.
