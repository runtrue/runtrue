# Bisim end-to-end conformance

**Bisim** is Runtrue's shared-engine conformance suite. Its release evidence
must prove equivalent observable behavior across the local and remote engine
providers; Capsule digest equality alone is not sufficient.

The server integration target `runner_e2e` is the release-facing runner
transport harness. It allocates real loopback sockets, creates an installation
CA and server identity, enrolls a runner through the server-auth-only listener,
and reconnects to the control listener with the issued short-lived client
certificate. The control service is constructed with a private configured data
root. It does not inject a test identity or disable TLS.

Run the focused gate with the pinned toolchain:

```text
cargo +1.88.0 test --locked -p runtrue-server --test runner_e2e
```

The fixture uses a temporary database, CA, object root, runner state, and
workspace root per test. Tests must never use ambient SCM or object-store
credentials, relax a fence or tenant check, or substitute an in-process fake
for release evidence. Failure paths retain their production status codes.

Current evidence covers real enrollment and authoritative posture binding,
rejection of an unauthenticated control RPC, an actual `RunnerDaemon` Open
session, protocol-v2 source ticket/download and header-first cache/artifact
upload, clean-workspace Native execution,
an exact full commit resolved from a real local Git repository through the
production manifest builder, cache and artifact upload/commit, durable typed
completion-ID/declaration binding, exact v2 and v1 completion replay, changed
completion-ID/name conflict,
stale completion fence and attempt rejection, changed-commit substitution
rejection, durable artifact-catalog recovery, cross-tenant catalog
non-disclosure, bootstrap-authorized artifact metadata, a one-use download
ticket, exact verified artifact bytes with attachment/no-store headers, download
replay rejection, and database/CAS reopen verification. A second independently
enrolled runner in another tenant proves that a real source ticket and a guessed
ticket receive the same denial before ticket or object existence can be
disclosed.

The Linux-only `runtrue-storage` integration target `bounded_rss` streams a
generated 256 MiB object into a child-process CAS, re-verifies it before
release, materializes it through fixed-buffer private staging with an inline
size/digest recheck, drains the verified reader, and fails if observed resident
memory grows by more than 32 MiB. It also interrupts a stream after private
staging begins and verifies that neither staging nor a public immutable object
remains. Run it with:

```text
cargo +1.88.0 test --locked -p runtrue-storage --test bounded_rss
```

The portable `object_transfer_chaos` target exercises the same production CAS
reader, verified staging, publication, reopen, inventory, and deletion APIs. It
uses a progress-gated reader to hold a transfer after private staging exists,
then injects a deterministic timeout and verifies that neither staging nor an
immutable object survives. It also proves that a corrupt committed object is
classified as corruption, rejected by `verified_reader`, retained by guarded
deletion, and rejected again after reopen; that an exact verified commit can be
streamed and idempotently replayed after reopen; and that declared-size,
streamed-byte, digest/size-integrity, and inventory-count bounds retain distinct
production error classifications. Run it with:

```text
cargo +1.88.0 test --locked -p runtrue-storage --test object_transfer_chaos
```

This is bounded-resource regression evidence, not the Capsule's multi-gigabyte L3
performance certification. The deterministic stalled-reader case injects the
reader timeout; it is not evidence for a real object-store or network idle
watchdog. No multi-GiB transfer, real disk-full/read-only filesystem, cgroup
memory pressure, network partition, or process-kill cleanup was run. M0/M1
release closure still requires restart/kill
injection between each individual source, transfer, commit-journal, and lease
completion boundary; real disk-full and read-only SQLite cases; slow/stalled
network matrices; multi-gigabyte RSS evidence; and runner restart during live
hydration. Those tests must preserve the production time, byte, concurrency,
authorization, and failure-classification bounds rather than substituting
test-only permissive behavior.

## Required Bisim result contract

Every Bisim fixture records the Capsule digest, provider identity, normalized
job and step transitions, exit classification, declared outputs, and permitted
side effects. Provider-specific transport details may differ, but any
undeclared difference in those observations fails conformance. Fixtures that
cannot run on a provider must report an explicit unsupported capability rather
than silently selecting a different executor.
