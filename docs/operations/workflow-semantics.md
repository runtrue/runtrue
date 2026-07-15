# Workflow semantics operations

Runtrue's generation-one workflow core treats runtime fan-out, cleanup,
and outputs as signed control data. These features do not grant permissions and
do not introduce a native or ambient-credential fallback.

## Dynamic matrices

A dynamic matrix job declares `dynamic-matrix.from` as
`needs.<producer>.outputs.<name>` and a positive `max-jobs` no greater than the
installation compiler limit (256 by default, with an engine hard ceiling of
1024). The producer must be one non-matrix signed job and must project a
required `json` structured step output. That source step is unconditional and
execution-critical: it cannot use `continue-on-error`, and a finalizer source
must itself be required. Producer success therefore cannot omit the expansion
input. Static jobs plus every dynamic maximum share the installation fan-out
limit; limits are not multiplied per template. This release supports dynamic
matrices only for terminal jobs.

The compiler signs a `DynamicJobTemplate`, including its runner requirements,
capabilities, permissions, steps, and ceiling. The shared expansion function:

- accepts only a JSON object whose values are arrays of finite scalar values;
- sorts axis names and values deterministically and removes duplicate values;
- rejects before producing more than the signed ceiling;
- changes only the generated job ID and matrix values;
- emits canonical `ExpandedJobSet` bytes bound to the parent Capsule digest,
producer job/output, exact matrix-input digest, and policy epoch.

Component actions, service images, and OCI runner images in dynamic templates
or finalizers are resolved through the same validated lock as normal steps.
Their immutable digests, permissions, runner profiles, and environment targets
are included in approval summaries and semantic risk comparisons. A template
with pre-expanded matrix data, a detached producer dependency, or a non-static
dependency is rejected before executor preflight.

Remote schedulers persist the domain-separated Ed25519 signature and canonical
bytes in migration 20's `expanded_job_sets`. Exact replay succeeds. A changed
record for the same run/template conflicts. Tenant/repository/run/Capsule
authorization is checked before looking up an existing expansion. Operators
should alert on expansion conflicts and fan-out-limit rejections. The durable
materializer additionally requires the active producer lease, runner, attempt,
installation epoch, and fencing generation. In one SQLite transaction it
persists the verified record and deterministic scheduler jobs; exact replay
verifies the immutable job requirements and inserts nothing. Generated jobs
remain subject to the signed source-trust, capability, concurrency, approval,
and runner filters.

## Structured outputs

Steps declare output schemas under `outputs`; jobs project public typed values
under `value-outputs`. Supported types are string, integer, number, boolean,
JSON, and immutable artifact reference. Executors return one JSON object over
their structured result channel. The engine never parses stdout or stderr.

The structured record is limited to 64 KiB and must be a duplicate-free
canonical JSON object. Undeclared records, unknown keys, missing required keys,
type mismatches, non-finite numbers, NUL strings, and malformed artifact
references fail the step. Accepted values carry a digest and provenance over
the exact Capsule, job, step, attempt, and structured channel. JSON is available
to dynamic expansion; scalar and verified artifact identities may enter typed
`steps.*`/`needs.*` contexts. Native process execution currently has no bounded
structured-output adapter and rejects such Capsules during whole-Capsule preflight;
it does not run a process and then fall back to stdout parsing.

## Finalizers

`finalizers` are separate from normal steps and run once per started job
attempt. They share the normal job permission ceiling and executor. The cleanup
deadline defaults to two minutes and cannot exceed ten minutes. A required
finalizer can turn primary success into failure, timeout, or cancellation; no
finalizer can replace a primary failure or cancellation with success.

When cancellation begins, only finalizers marked `run-on-cancel: true` run.
These steps receive the remaining bounded cleanup deadline. Executor resource
teardown still runs exactly once after workflow finalizers.

## Trigger durability

Migration 20 also adds normalized trigger identities for tag, schedule,
manual, API, repository-dispatch, and dependent-workflow producers. Envelopes
are canonical JSON, limited to 256 KiB, and addressed by their normalized
digest. `(tenant, repository, kind, idempotency identity)` is unique: exact
delivery replay succeeds and changed replay conflicts.

Schedule cursors accept five-field numeric UTC cron expressions. Updates use a
version compare-and-swap. Catch-up policy is explicit (`skip`, `latest`, or
`all-bounded`) and operators must configure `all-bounded` with a positive
maximum no greater than 100 windows. A stale process cannot overwrite a newer
next-fire cursor after restart. Each server maintenance tick processes at most
100 due cursors. Normalized schedule-trigger insertion and cursor advancement
share one immediate transaction; cron search is bounded to one UTC year per
next/previous calculation. A malformed or non-matching durable cursor fails
closed and is reported rather than firing an invented time.

`POST /api/v1/capsules/{capsule_id}/runs` now records an `api` trigger after Cedar
authorization and durable idempotent run creation, but before returning a
success response. The trigger identity binds tenant, repository, principal,
and the request idempotency key; its canonical envelope binds the resulting
run, Capsule, priority, and actor. A crash between the run transaction and trigger
transaction is recovered by the same request: run replay supplies the original
run ID and timestamp, so trigger replay is exact. A changed request conflicts,
and a cross-tenant principal is rejected before trigger metadata is written.

Expose `WorkflowSemanticsMetrics` as counters/gauges for durable expanded job
sets, normalized trigger envelopes, and schedules due at the observation time.
Metrics and logs must use identities/digests only; never include output values
or raw trigger text.

## Alerts and recovery

Alert on `schedule reconciliation failed`, expansion idempotency conflicts,
fan-out-limit rejection, a nonzero due-schedule gauge that does not decline,
and repeated trigger replay counts outside an expected client retry. Logs and
metrics contain only identifiers, digests, counts, and cursor times; they must
not include matrix input values, structured output values, or raw trigger
payloads. Repair an invalid schedule through an authorized cursor update; do
not edit SQLite directly. Restart is safe because both cursor reconciliation
and expansion materialization use immediate transactions and deterministic
identities.

## Current boundary and completion level

The shared compiler/IR/engine path, lease-bound durable materializer, normalized
API producer, and bounded schedule maintenance caller are an L1 adapter slice.
The runner completion protocol does not yet carry the producer's canonical
typed output to the server-side materializer, so no production completion call
site exists outside the runner-service hotspot. Manual,
repository-dispatch, dependent-workflow, and tag producers are also not all
wired through public surfaces. Do not claim R7 L2/L3 until a real remote runner
drives producer output through materialization and leasing, restart/parity
evidence covers that public path, and every documented trigger producer is
connected. Services remain executor-specific: OCI is the intended first full
implementation, while Wasm continues to reject process services.
