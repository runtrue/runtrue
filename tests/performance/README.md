# Runtime performance suite

This directory is the stable entry point for runtime performance and capacity
evidence. The lifecycle, scenario matrix, placement rules, and release gates
are defined in
[`docs/architecture/runtime-performance-test-plan.md`](../../docs/architecture/runtime-performance-test-plan.md).

The first implemented layer measures the Wasm executor. It emits raw samples
and p50/p90/p95/p99 summaries using schema version 1 from
`runtrue-runtime-metrics`.

Build once in release mode and run each state independently:

```text
export RUNTRUE_HARNESS_COMMIT="$(git rev-parse HEAD)"
cargo build --release -p runtrue-executor-wasm --example runtime_benchmark

target/release/examples/runtime_benchmark \
  --state cold --iterations 30 --warmup 3 --output cold.json
target/release/examples/runtime_benchmark \
  --state aot --iterations 30 --warmup 3 --output aot.json
target/release/examples/runtime_benchmark \
  --state warmish --iterations 1000 --warmup 100 --output warmish.json
target/release/examples/runtime_benchmark \
  --state hot --iterations 1000 --warmup 100 --output hot.json
```

`cold` constructs a new executor with an isolated empty cache for every sample.
`aot` seeds an isolated authenticated cache, drops the seed executor, and times
a fresh executor loading that AOT entry. `warmish` alternates two components
through a one-entry warm cache and verifies that the measured package loads
from immutable in-memory AOT. `hot` keeps one executor alive and
verifies that every measured sample uses the memory-resident component. A
sample whose observed preparation state differs from the requested state is
rejected.

Package placement uses three package-specific preparation tiers. Compare them
with the dedicated tier harness:

```text
cargo run --release -p runtrue-executor-wasm \
  --example package_tier_benchmark -- \
  --output /tmp/wasm-package-tiers.json
```

The tier definitions are deliberately narrower than a general worker warm
pool:

- `cold` retains source bytes and includes compilation, instantiation, and one
  guest call;
- `warmish` retains an authenticated immutable in-memory AOT artifact and
  includes deserialization, instantiation, and one guest call;
- `warm` retains a compiled `Component` and includes instantiation and one
  guest call.

Authentication is measured separately as an admission cost. It happens before
an artifact enters the warmish cache, not on every hit. The report also gives
exact AOT entry capacity for 256 MiB and 1 GiB memory budgets. A production
cache binds admission to the executor's complete engine compatibility key and
enforces immutable ownership. The dedicated tier harness remains a synthetic
fixture-size comparison; the `runtime_benchmark --state warmish` path exercises
the production cache implementation.

For placement, compare candidates by `queue delay + package-state p95 startup`
after all hard compatibility and resource filters. The report calculates the
queue-delay break-even points at which an idle lower tier should beat a busy
higher tier. Preparation is package-specific: one worker may be warm for one
digest, warmish for another, and cold for a third.

Do not compare debug-build results or results from busy shared hosts. Record
kernel, CPU governor, cgroup limits, storage, machine image, and runtime
configuration as report attributes when publishing controlled baselines.

The shared crate also provides a constant-rate `OpenLoopSchedule`. Remote load
drivers must submit against its intended offsets even when earlier requests
are slow; this prevents coordinated omission. Load samples include intended and
actual start offsets, queue depth, active workers/executions, completion offset,
throughput, and maximum start lag.

## Current boundaries

- The local executor harness is implemented.
- Wasm warm and warmish preparation is advertised as graded tenant-scoped
  runner locality after successful startup preflight.
- Scheduler placement diagnostics are available through
  `Scheduler::offer_for_runner_observed`.
- The production runner remains one-active-lease-per-worker. Multi-lease Wasm
  execution is not enabled by this suite.
- A production HTTP/mTLS open-loop driver, long soak orchestration, resource
  sampling, and controlled-host baseline publication remain later milestones.

Never delete or mutate an operator cache to manufacture a cold result. The
benchmark uses temporary isolated cache roots. Never publish private package
references, tenant identifiers, secrets, or bearer credentials in reports.
