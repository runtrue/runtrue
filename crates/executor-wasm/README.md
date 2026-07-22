# runtrue-executor-wasm

This crate is Runtrue's embedded WebAssembly Component backend. It accepts only
digest-pinned components implementing `runtrue:action/run@1.0.0`, verifies their
exact signed image manifest and expected image-signing key, and then compiles
them with the pinned Wasmtime 46.0.1 runtime and final WASI 0.3.0 host.

The guest receives a fresh WASI context with no inherited filesystem, network,
environment, arguments, working directory, standard streams, process, or
secret access. TCP and UDP are disabled. WASI clocks and randomness use the
standard runtime implementations. Runtrue-specific host imports are defined in
[`wit/action.wit`](wit/action.wit). Filesystem, network,
secret, and OIDC access must be both declared in the step capability set and
backed by an explicitly installed adapter. Grants are represented by
invocation-local authenticated handles; unknown or forged handles fail closed.
OIDC minting accepts only an audience handle, never an arbitrary audience
string. Other workflow capabilities are rejected until this ABI has a
corresponding adapter.

Execution is bounded by Wasmtime store memory/table/instance limits, fuel, an
epoch watchdog, a wall timeout, and size limits for component bytes, inputs,
outputs, logs, adapter traffic, secret values, and OIDC tokens. Output must be
a duplicate-free canonical JSON object. Delivered secret and OIDC values are
kept in redacting, zeroizing wrappers, masked from host logs, and rejected if a
component attempts to publish them as structured output. No command or native
fallback exists.

The remote runner may execute multiple Wasm jobs in one process. Wasmtime
Engines, admitted Components, and authenticated AOT state are shared; every
job invocation receives a fresh Store, WASI context, capability handles, fuel
budget, deadline, and output budget. `WasmLimits::max_instances` remains a
per-Store component limit and is not the runner concurrency setting. Configure
runner concurrency with `RUNTRUE_RUNNER_WASM_MAX_CONCURRENT_JOBS` (1 through
64); non-Wasm backends remain exclusive within the runner process.

The executor runs only the current host's baseline target: Linux or macOS on
`x86_64` or `aarch64`. Cross-target execution and Windows are rejected. This
keeps native AOT bytes bound to the machine-code target and lets the cache
enforce Unix owner-only directory/file modes and no-follow opens; platforms
without those checks fail closed during cache setup.

The AOT key binds the component and WIT digests, WASI and Wasmtime versions, target
triple, CPU feature floor, compiler settings, mitigation profile, and
Wasmtime's engine compatibility hash. Cache metadata and serialized component
artifacts are HMAC-authenticated, size-bounded, and checked as component AOT
objects before admission into an immutable in-memory AOT tier. Cold source
compilation uses a separate engine with Wasmtime's internal cache disabled.
The cache-enabled engine deserializes only an artifact bound to the complete
engine compatibility key. This unsafe Wasmtime boundary is isolated behind a
private admitted-artifact type whose bytes cannot be mutated after admission.
Corrupt entries are quarantined and rebuilt as misses.
The cache authentication key and capability-handle key are installation
secrets and are zeroized on drop.

Remote runners call `preflight_components` before advertising Wasm. This
verifies and compiles every registered signed component. The bounded package
cache retains up to 64 compiled components by default. Its separate immutable
AOT tier lets component evictions demote to warmish while the artifact remains
inside that tier's limits, which default to 1,024 entries and 512 MiB.
Both limits are configurable through `WasmPackageCacheConfig`. Normal cold-cache
publication does not create an integrity event; corrupt or unauthenticated AOT
state is quarantined and recorded so a runner can fail that startup instead of
silently advertising from repaired state. Atomic cache publication and rooted
filesystem temporary names treat operating-system entropy failure as a typed,
fail-closed error.

On Linux, `RootedFilesystemAdapter` provides the concrete workspace adapter. It
walks from a retained root descriptor with kernel `openat2` resolution using
`RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, and `RESOLVE_NO_XDEV`; kernels without
that boundary fail closed. It rejects non-regular and hard-linked files and
writes through an unpredictable private in-directory temporary file followed
by an atomic rename. The workspace tree must be exclusively owned by the
executor while a step runs: no filesystem API can preserve write integrity
against an unrelated same-UID process that can concurrently mutate the same
directory. macOS execution remains available with custom capability adapters,
but the concrete rooted filesystem adapter is intentionally not exported there.

## Performance measurements

The executor emits backend-neutral phase measurements for request validation,
package verification, warm and warmish in-memory lookup, authenticated AOT
inspection, compilation/deserialization, cache publication, invocation
preparation, instantiation, guest execution, and output finalization. It distinguishes a
source compile, authenticated disk AOT hit, immutable in-memory AOT hit,
memory-resident component, and quarantined cache miss.

Run the reproducible no-op benchmark in release mode once for each preparation
state:

```text
cargo run --release -p runtrue-executor-wasm --example runtime_benchmark -- \
  --state cold --iterations 30 --warmup 3 --output cold.json
cargo run --release -p runtrue-executor-wasm --example runtime_benchmark -- \
  --state aot --iterations 30 --warmup 3 --output aot.json
cargo run --release -p runtrue-executor-wasm --example runtime_benchmark -- \
  --state warmish --iterations 1000 --warmup 100 --output warmish.json
cargo run --release -p runtrue-executor-wasm --example runtime_benchmark -- \
  --state hot --iterations 1000 --warmup 100 --output hot.json
```

Set `RUNTRUE_HARNESS_COMMIT` at compile time to bind a report to a source
revision. Each JSON report retains raw samples and nearest-rank p50/p90/p95/p99
summaries using the shared `runtrue-runtime-metrics` schema. Cold and AOT
iterations use independent temporary cache roots and verify the observed state
before accepting a sample.
