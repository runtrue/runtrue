# Runtime performance and capacity test plan

- **Status:** In progress
- **Primary runtime:** Wasmtime Component executor
- **Scope:** local executor, remote runner, scheduler placement, and end-to-end
  control-plane behavior
- **Design goal:** one harness and result contract that can be reused for OCI,
  Firecracker, Native, and future runtime providers

Implemented foundation:

- backend-neutral phases, preparation states, raw samples, percentile summaries,
  load timing, and constant-rate open-loop schedules in
  `runtrue-runtime-metrics`;
- Wasm executor timings and distinct cold compile, authenticated disk AOT,
  immutable in-memory AOT, memory-resident, and quarantined-miss classification;
- release-mode Wasm benchmarks for cold, disk AOT, warmish, and warm samples;
- graded warmish/warm Wasm package locality advertisement from remote runners; and
- bounded scheduler placement observations covering hard-filter counts,
  selected score, locality hits, and decision duration.

## 1. Questions this plan must answer

The test program must produce evidence for five operator questions:

1. How long does every phase of an execution take?
2. What is the difference between a genuinely cold worker, an AOT-prepared
   worker, and an already-running worker?
3. How much concurrent and sustained work can one worker, one pool, and the
   complete deployment handle before latency or errors become unacceptable?
4. Does placement reliably prefer a compatible worker that already has the
   required immutable package preparation without violating exact scheduling,
   tenant isolation, or fairness?
5. Can the same tests and result schema qualify the next runtime without
   redefining "cold", "ready", "running", "cleanup", or "capacity"?

The output is a reproducible measurement report, not a single headline startup
number. It includes distributions, hardware and configuration identity, raw
samples, failure counts, resource use, and the exact preparation state used by
each sample.

## 2. Important current behavior

The first baseline must record the implementation as it exists rather than
assuming a future concurrency or caching model:

- A remote runner currently holds at most one active lease. It rejects another
  offer as `runner_busy`. Therefore the current remote per-worker job
  concurrency is one, even if the embedded runtime could theoretically run
  more than one component.
- `SharedWasmExecutor` serializes access to one `WasmExecutor`. Executor-level
  concurrency must be measured separately before proposing multiple active
  Wasm leases on one runner.
- Runner startup calls `preflight_components` for every configured component.
  The bounded cache retains the most recently used compiled components and
  demotes the remainder to immutable in-memory AOT while budget permits.
- An authenticated AOT hit primarily improves worker startup/preflight after a
  process restart. It is not a reused tenant Store: each invocation still
  creates a fresh Store, WASI context, resource table, limiter, host state,
  capability handles, output buffers, cancellation scope, and guest instance.
- Scheduler locality prefers matching immutable content after hard
  compatibility, quota, priority, and fairness filters. The runner advertises
  exact warmish and warm package tiers while retaining a flat digest union for
  protocol compatibility.

These facts yield three distinct Wasm startup states. They must never be
collapsed into a generic cold/warm label:

| State | Worker process | Authenticated AOT | In-memory component | Meaning |
|---|---|---|---|---|
| `process-cold-cache-cold` | new | absent | absent | construct engine, verify, compile, publish AOT, and become schedulable |
| `process-cold-cache-hit` | new/restarted | present and valid | absent | construct engine, authenticate and deserialize AOT, validate, and become schedulable |
| `process-warm-aot-prepared` | running | immutable memory entry | absent | check its exact admission key, deserialize AOT, instantiate, and call |
| `process-warm-component-hot` | running | present | present | accept a lease, create fresh invocation state, instantiate, and call |

A corrupt, incompatible, or unauthenticated AOT entry is a separate
`process-cold-quarantined-miss` security/failure experiment, never a cache miss
sample added to the normal cold distribution.

### Proposed placement rule to validate

The scheduler should retain its existing ordering principles and make package
preparation a preference, never an admission fact:

```text
hard filter by exact runtime, trust, tenant, pool, region, posture, and resources
apply tenant quota, fair share, priority, and priority aging
prefer a worker with valid scoped preparation for the exact package/runtime key
prefer lower active load when preparation value is equal
use a stable final tie-breaker
```

An AOT claim is useful only when it covers the complete AOT cache identity, not
merely the component digest. A prepared worker that is busy should not make
compatible idle capacity invisible. The default experiment should schedule on
idle compatible capacity and pay the preparation cost; any policy that waits
briefly for a prepared worker needs an explicit maximum wait and must prove it
improves tail latency under the measured arrival distribution.

## 3. Shared runtime lifecycle vocabulary

Every runtime adapter must map its implementation into the same lifecycle.
Backend-specific subphases may be added, but these boundaries and meanings do
not change:

| Phase | Start boundary | End boundary |
|---|---|---|
| `request_admission` | request received | immutable identity, policy, and runtime requirements accepted |
| `queue_wait` | admitted work queued | scheduling attempt begins |
| `placement` | candidate selection begins | exact compatible capacity is reserved |
| `lease_delivery` | lease is durably issued | selected runner receives offer |
| `lease_acceptance` | runner receives offer | admission, fence, and local preflight succeed |
| `runtime_acquire` | accepted work requests backend | usable isolated runtime is acquired |
| `package_prepare` | immutable package is selected | executable preparation is available |
| `invocation_prepare` | fresh invocation begins | guest-specific state and capabilities are ready |
| `instantiate` | executable and fresh state are ready | guest entry point can be called |
| `guest_run` | entry point is called | entry point returns or is interrupted |
| `output_finalize` | guest stops | output, logs, effects, and result hashes are finalized |
| `cleanup` | finalization ends | disposable state is removed and isolation is proven |
| `completion_publish` | cleanup succeeds | durable result and required Evidence are accepted |
| `end_to_end` | client submits | client observes terminal result |

For Wasm, `package_prepare` is further divided into manifest verification, AOT
key construction, authenticated cache inspection, source compilation or AOT
deserialization, interface validation, serialization, and cache publication.
`invocation_prepare` includes input serialization, capability grant creation,
Store/WASI/resource-table creation, limits/fuel/epoch setup, and linker setup.

For a future runtime, an adapter maps equivalent work into the same phases. For
example, OCI maps pull/verify/unpack to `package_prepare` and container creation
to `runtime_acquire`; Firecracker maps sterile snapshot selection to
`package_prepare` and VM lease/boot to `runtime_acquire`.

## 4. Measurement contract

### 4.1 One record per execution plus child phase records

Use a versioned, append-only JSON Lines report. Preserve raw samples; generate
summaries from them instead of retaining only aggregates. A run record contains:

```text
schema_version
suite_version, fixture_digest, harness_commit
provider_id, pool_id, worker_id_hash, tenant_scope
runtime_family, runtime_compatibility_digest, runtime_version
host_os, kernel, architecture, cpu_model, logical_cpus, memory_bytes
storage_kind, filesystem, cgroup_limits, power_profile
control_plane_topology, worker_count, configured_worker_capacity
package_digest, package_size_bytes, workload_class
preparation_state, cache_status, cache_key_digest, placement_reason
execution_id, attempt, offered_worker, selected_worker
phase_name, monotonic_start_ns, duration_ns
outcome, portable_failure_class, diagnostic_code
cpu_time_ns, peak_rss_bytes, io_read_bytes, io_write_bytes
network_rx_bytes, network_tx_bytes, fuel_consumed, output_bytes
queue_depth_at_submit, active_workers, active_executions
```

High-cardinality identities belong in the benchmark artifact or Evidence, not
unbounded production metric labels. Production histograms use bounded labels
such as runtime family, compatibility profile, phase, preparation state,
outcome, provider, pool, and workload class.

### 4.2 Required statistics

For each unique scenario, report:

- sample count, successes, failures, timeouts, cancellations, and rejected
  offers;
- min, median, p90, p95, p99, maximum, mean, and standard deviation;
- throughput in completed executions/second and completed guest calls/second;
- offered, accepted, and successfully completed rates;
- CPU utilization, peak and steady RSS, storage I/O, network I/O, and cache
  bytes;
- queue depth and queue-wait distribution; and
- cache-hit, miss, quarantine, eviction, and placement-hit ratios.

Percentiles are calculated from individual requests, never from averages of
interval averages. Coordinated omission is avoided by load generators that
record the intended send time and continue the configured arrival schedule
when the system slows.

### 4.3 Clocks and trace correlation

- Measure durations with a monotonic clock on the process that owns a phase.
- Use a trace/execution identifier to join server, scheduler, runner, and
  executor records.
- Do not subtract wall clocks on different hosts to calculate a phase. For
  cross-host spans, record sender duration, receiver duration, and observed
  transport interval separately, or use synchronized tracing with an explicit
  clock-error bound.
- Record wall time only for correlation and evidence ordering.
- Benchmark instrumentation overhead with telemetry enabled and disabled. The
  release configuration must keep the measured overhead under an agreed
  budget.

## 5. Workload fixture set

Fixtures are immutable, digest-pinned, signed where the runtime requires it,
and generated reproducibly. Each fixture implements an equivalent portable
result contract on every runtime that claims support.

| Fixture | Purpose | Variants |
|---|---|---|
| `noop` | isolates framework and startup overhead | smallest valid package |
| `cpu` | discovers CPU saturation and fairness | 1 ms, 10 ms, 100 ms, 1 s calibrated work |
| `memory` | allocation/limit/cleanup behavior | 1 MiB to configured limit; retain/touch patterns |
| `input-output` | serialization and output cost | 0 B, 1 KiB, 64 KiB, maximum admitted size |
| `host-call` | capability adapter overhead | no-op, filesystem, secret metadata, OIDC mock, bounded network mock |
| `mixed` | representative production action | CPU + host call + structured output |
| `long-running` | cancellation, timeout, and lease heartbeat | cooperative and non-cooperative loops |
| `hostile` | isolation and exhaustion | fuel, memory, table, handle, log, output, and malformed-interface limits |

Package-size variants should include tiny, typical, large, and maximum admitted
components. The Wasm suite must include both a minimal component and a
dependency-rich component because compile/deserialization cost does not scale
only with byte size.

## 6. Test layers

### Layer A: deterministic phase microbenchmarks

Purpose: detect code-level regressions with low noise.

Measure engine construction, signature and manifest verification, AOT cache
authentication, source compilation, AOT deserialization, interface validation,
Store creation, linker setup, instantiation, entry-point call, output
validation, and cleanup independently where production APIs allow it.

Run on pinned bare-metal or dedicated hosts with fixed toolchain, CPU governor,
core set, memory limit, and local storage. CI may run a smoke version for
correctness, but regression enforcement uses the controlled performance host.

### Layer B: executor lifecycle benchmarks

Purpose: measure one backend through its real executor facade.

For every fixture, run the complete startup-state matrix:

1. New cache directory and new executor (`process-cold-cache-cold`).
2. Preserved authenticated cache and new executor
   (`process-cold-cache-hit`).
3. Same live executor after preflight (`process-warm-component-hot`).
4. Different component on the same engine/cache.
5. Same digest with an incompatible runtime tuple, which must miss or reject.
6. Corrupt metadata, corrupt AOT bytes, wrong authentication key, partial
   entry, and oversized entry, which must quarantine/fail closed as specified.

Each invocation verifies a fresh Store and absence of prior guest state; speed
never substitutes for the isolation assertion.

### Layer C: real runner startup and lease benchmarks

Purpose: include process startup, configuration, component preflight,
inventory advertisement, lease handling, workspace setup, execution, cleanup,
and completion publication.

Measure these milestones:

```text
process spawned
configuration loaded
runtime engine constructed
component verification started/finished
AOT inspection or compile started/finished
backend inventory ready
control stream authenticated
locality advertised
runner schedulable
lease offered/received/accepted
guest invoked/completed
cleanup completed
completion accepted
```

Run with empty AOT storage, preserved valid AOT storage, many configured
components, and a single configured component. This exposes the startup cost of
the current eager-preflight model and supplies data for deciding whether bounded
lazy preparation is worth designing later.

### Layer D: scheduler placement tests

Purpose: prove that preparation-aware placement lowers latency without changing
security or fairness semantics.

Typed locality lets a worker advertise exact package digests as warmish or
warm. The server preserves the tier while retaining the flat locality union;
a bare digest never implies reusable authorization.

For each case, record candidates after hard filters, scores, selected worker,
placement reason, and whether the selected preparation claim was still valid:

1. Two otherwise equal workers; only one has compatible authenticated AOT.
2. A warm worker has insufficient resources; choose the cold compatible worker.
3. A warm worker is in a disallowed pool, region, tenant, trust domain, runtime
   tuple, or CPU feature floor; never choose it for warmth.
4. A higher-priority or fair-share decision competes with locality; verify the
   documented score ordering.
5. Locality is stale, evicted, invalidated, or withdrawn between offer and
   acceptance; safely fall back to local preparation or reject within deadline.
6. Several packages and workers; measure hit rate for random, round-robin,
   least-loaded, and locality-aware placement using the same arrivals.
7. A hot worker is busy while cold compatible capacity is idle; quantify wait
   versus cold-placement tradeoffs under an explicit bounded policy.
8. Private package digests from another tenant cannot influence or disclose
   placement.

Placement success metrics are `prepared-placement-hit-rate`, avoided compile
time, queue-time change, end-to-end change, load imbalance, starvation count,
and incorrect/stale claim count. The correctness requirement is zero placement
outside the sealed compatible set.

### Layer E: capacity, saturation, and scale

Purpose: answer "how many can we handle?" at each system boundary.

Run open-loop arrival tests rather than only fixed-concurrency loops. For each
workload, increase offered rate in small steps and hold each step long enough to
reach steady state. Then run a binary search around the knee. Measure:

- maximum sustainable throughput where p95/p99 and error rate remain inside
  the declared objective;
- saturation point where queue depth grows continuously;
- service time and queue time separately;
- CPU, memory, file descriptor, thread, storage, network, database, and control
  stream saturation; and
- recovery time after offered load returns below capacity.

Run the following matrix:

| Dimension | Values |
|---|---|
| Workers | 1, 2, 4, 8, then deployment target |
| Current per-worker active leases | 1; verify additional offers are rejected/fenced correctly |
| Future per-worker concurrency experiment | 1, 2, 4, 8, CPU count; only after executor and isolation design supports it |
| Preparation | all cold, all AOT-ready, all memory-hot, 10/50/90% prepared |
| Package popularity | single hot package, uniform, Zipf-like, rotating working set |
| Work duration | noop, 10 ms, 100 ms, 1 s, mixed |
| Tenant mix | one tenant, many equal tenants, noisy neighbor, quota-limited tenant |
| Arrival pattern | constant, burst, ramp, spike, diurnal replay |
| Failure injection | worker loss, cache corruption, slow disk, server restart, network delay |

For the current implementation, expect no more than one active remote job per
worker. Capacity should initially scale through worker count. If a later design
allows multiple active Wasm jobs per runner, rerun the complete isolation,
resource accounting, cancellation, fairness, broker, and cleanup suite before
claiming the higher capacity.

### Layer F: soak and churn

Purpose: detect leaks, fragmentation, cache pathologies, and tail-latency drift.

- 6-hour pre-merge/nightly smoke soak and 24-72-hour release soak.
- Sustained 60-70% measured capacity plus periodic bursts to 100-120%.
- Continuous package churn, AOT eviction, runner restart, certificate rotation,
  cancellation, and tenant changes.
- Track RSS slope, allocator growth, open handles, threads/tasks, cache size,
  quarantine growth, queue age, p99 drift, and cleanup failures.
- Finish with a sterile-state probe and compare output/resource behavior to a
  fresh worker.

The acceptance condition is bounded stable resource use after expected cache
growth, no cross-invocation state, no unbounded queue growth below measured
capacity, and no degradation trend beyond the agreed statistical tolerance.

### Layer G: adversarial correctness and security under load

Performance certification is invalid if the optimized path weakens security.
Repeat the relevant load states while checking:

- signature, digest, runtime tuple, AOT authentication, and interface checks;
- fresh invocation state and no prior tenant memory, resource, handle, output,
  or broker state;
- exact placement and tenant/trust-domain scoping;
- fuel, memory, output, timeout, and cancellation enforcement;
- stale lease/fence rejection and worker-loss recovery;
- AOT corruption quarantine and no execution of unauthenticated code;
- completion only after cleanup proof; and
- no secret or private-cache identity in metrics, traces, or result artifacts.

## 7. Experimental method

Every published result follows this procedure:

1. Pin the source commit, lockfile, runtime version, fixture digests,
   configuration, machine image, kernel, firmware, and hardware identity.
2. Reserve the host; disable unrelated workloads and record CPU frequency/power
   settings, NUMA placement, storage, and network topology.
3. Validate clock and telemetry health.
4. Build release binaries once. Do not include compilation of the Runtrue host
   binaries in runtime startup measurements.
5. Prepare the exact state for the scenario. Cache deletion is allowed only in
   the benchmark's isolated temporary data root.
6. Run correctness checks before timing.
7. Run warm-up iterations that are recorded but excluded from the primary
   summary.
8. Collect at least 30 independent cold process samples and enough warm/load
   samples for stable p99 estimates; use more when variance demands it.
9. Randomize A/B ordering when comparing a change. Repeat across at least three
   trials and report confidence intervals or bootstrap intervals for the delta.
10. Preserve raw JSONL, summary JSON, logs, configuration, flamegraphs/profiles,
    and the generator's offered-load schedule as one immutable report bundle.

Do not run cold and warm samples in the same directory without proving the
intended state. The harness verifies cache contents and reports the observed
state; a mismatch invalidates the sample rather than silently relabeling it.

## 8. Performance objectives and regression gates

Do not invent final SLOs before collecting a baseline on target hardware. Use
the first controlled results to set explicit objectives for each workload and
deployment class:

```text
objective = {
  maximum_p95_end_to_end,
  maximum_p99_end_to_end,
  maximum_p95_queue_wait_at_declared_capacity,
  minimum_sustainable_throughput,
  maximum_error_rate,
  maximum_peak_rss_per_worker,
  maximum_cleanup_failure_rate = 0,
  maximum_security_or_isolation_failure_rate = 0
}
```

Recommended initial regression policy after baselining:

- deterministic phase benchmarks: fail on a statistically significant 5-10%
  regression outside expected noise;
- runner/end-to-end benchmarks: alert at 10%, require review at 15%, with both
  relative and absolute minimum thresholds;
- throughput: fail when sustainable throughput falls more than 10% without an
  accepted tradeoff;
- resource use: fail on an unexplained leak or more than 10% increase in the
  steady-state per-execution cost; and
- correctness, isolation, authentication, fencing, and cleanup: zero tolerance.

Small benchmarks run per pull request on controlled hosts. Startup matrices,
placement simulations, and short load tests run nightly. Multi-worker
saturation, chaos, and long soak tests run before a release and after runtime,
scheduler, protocol, kernel, or machine-image changes.

## 9. Harness architecture

Keep the runtime-specific code behind a small benchmark adapter:

```text
RuntimeBenchmarkAdapter
  identity() -> runtime family + exact compatibility digest
  prepare_package(state, fixture) -> observed preparation state
  start_worker(config) -> worker handle + readiness milestones
  verify_preparation(worker, fixture) -> authenticated observed state
  execute(request) -> portable result + phase samples
  resource_snapshot(worker) -> bounded resource counters
  invalidate(worker, fixture) -> verified invalidation result
  stop_worker(worker) -> cleanup result
```

The shared harness owns fixture selection, arrival scheduling, concurrency,
worker topology, fault injection, trace correlation, statistics, report
generation, comparison, and acceptance rules. Runtime adapters cannot redefine
portable outcomes or skip shared correctness assertions.

Suggested repository layout:

```text
tests/performance/
  README.md
  schema/runtime-benchmark-report-v1.json
  fixtures/
  scenarios/
  adapters/wasm/
  adapters/oci/
  harness/
  analysis/
  baselines/
```

Use a dedicated benchmark binary for local phase/executor measurements and a
load-driver binary for remote tests. Both emit the same schema. The remote
driver uses production HTTP, mTLS runner protocol, scheduler, leases, runner
daemon, and completion paths; an in-process fake is not end-to-end evidence.

## 10. Delivery plan

### Milestone 0: definitions and baseline inventory

- Approve the lifecycle phases, preparation states, result schema, fixture
  contract, and target hardware classes.
- Document current one-lease runner capacity and eager Wasm preflight.
- Select representative production packages and sanitize or replace them with
  reproducible public fixtures.

**Exit:** reviewers can unambiguously classify every sample as cold-cache,
AOT-ready, memory-hot, or invalid.

### Milestone 1: instrumentation

- Add phase timers at server admission/queue/schedule/lease/completion, runner
  offer/preflight/workspace/cleanup, and Wasm verification/cache/compile/store/
  instantiate/call boundaries.
- Add bounded resource counters and correlation IDs.
- Add the JSONL report writer and validate it against a versioned schema.
- Measure telemetry overhead.

**Exit:** one no-op remote execution produces a complete waterfall whose child
durations reconcile with the owning parent durations within documented bounds.

### Milestone 2: Wasm cold/warm correctness benchmark

- Build the immutable Wasm fixture set.
- Automate isolated cache setup for miss, hit, incompatible, and corrupt states.
- Run Layers A-C and establish target-host baselines.
- Verify fresh invocation state for every warm execution.

**Exit:** reproducible p50/p95/p99 distributions exist for every valid Wasm
package state, and every cache-security negative case has the expected result.

### Milestone 3: preparation-aware placement

- Validate typed, scoped prepared-content locality expiry/invalidation.
- Exercise compatible AOT/in-memory package preparation advertisements.
- Extend scheduler reason telemetry with queue-delay estimates.
- Run Layer D, including privacy, staleness, fairness, and incompatible-profile
  cases.

**Exit:** compatible preparation improves measured latency/hit rate, while no
hard filter, quota, tenant boundary, or fairness invariant is bypassed.

### Milestone 4: capacity and scale

- Implement the open-loop load generator and coordinated-omission-safe
  histograms.
- Measure the current one-lease-per-worker system from one to the target fleet
  size.
- Identify the bottleneck at the throughput knee with profiles and resource
  evidence.
- Only then evaluate whether multi-lease Wasm workers are needed; treat that as
  a separately reviewed runtime/runner change.

**Exit:** each deployment class has a measured sustainable capacity, scaling
curve, limiting resource, and recovery behavior.

### Milestone 5: soak, chaos, and release gates

- Run Layers F-G.
- Store signed or content-addressed report bundles with release evidence.
- Add comparison tooling and regression policies to controlled CI.

**Exit:** the release has reproducible performance, capacity, isolation, and
cleanup evidence tied to its exact runtime and provider generation.

### Milestone 6: qualify the next runtime

- Implement only the new runtime adapter and backend-specific fixtures.
- Reuse the shared workload contract, scenario definitions, driver, result
  schema, analysis, capacity method, and gates.
- Add the runtime family's required adversarial suite without weakening shared
  assertions.

**Exit:** reports compare runtimes phase by phase without pretending that AOT,
image layers, snapshots, or native processes are the same preparation
mechanism.

## 11. First reports to publish

The first useful report set should be small enough to finish and broad enough
to guide architecture:

1. Wasm no-op and mixed fixture on one controlled host for the three valid
   startup states.
2. Worker readiness with 1, 10, and 100 configured components for empty and
   authenticated AOT caches.
3. One worker saturation at the current one-active-lease limit, followed by 2,
   4, and 8 workers.
4. Two-worker placement: compatible AOT worker versus cold worker, including
   busy, stale, wrong-tenant, wrong-runtime, and wrong-region cases.
5. Six-hour mixed-workload soak with restarts and cache churn.
6. The same no-op/mixed portable fixtures through the next runtime adapter.

Together these reports answer startup, AOT value, placement value, current
capacity, scaling behavior, stability, and harness reuse without waiting for
every long-tail scenario to be implemented.
