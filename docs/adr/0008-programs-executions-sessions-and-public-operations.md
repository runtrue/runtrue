# ADR 0008: Programs, Executions, Sessions, and public operations

- **Status:** Accepted
- **Date:** 2026-07-15
- **Compatibility scope:** target architecture for unreleased v0.x
- **Detailed decision under:** ADR 0007

## Context

Runtrue needs one execution vocabulary for local commands, remote jobs,
interactive development, agents, functions, plugins, and future integrations.
Workflow terms such as job and step are insufficient for stateful interaction,
while provider terms such as worker and VM expose implementation details.

The model must distinguish immutable executable input, a single attempt, and a
long-lived workspace without making a client connection or a runner process the
owner of durable state. It must also give the CLI and remote clients the same
operations so local execution does not become a second semantic path.

## Decision

### 1. Program identity

A **Program** is immutable executable input. Its kind is explicit and includes
the material needed to interpret its identity, for example:

- a content-addressed source or filesystem tree plus an exact entry point;
- a script or command encoded in a Capsule;
- a signed WebAssembly Component and WIT world;
- a signed OCI image manifest and platform; or
- a signed native executable admitted for trusted execution.

A mutable tag, branch, path, or package range may be a resolver input but is
never the Program identity admitted by a runner. Resolution produces a digest,
signature identity, media type, platform, and compatibility metadata before the
Capsule is sealed. Changing any execution-affecting Program material creates a
different Program identity.

### 2. Execution semantics

An **Execution** is one bounded attempt to run one Program under one immutable
Execution Capsule. It has one identity, one lease and fence generation, one
ordered event stream, and one terminal classification.

An Execution moves monotonically through:

```text
proposed -> admitted -> queued -> leased -> running -> finalizing -> terminal
```

Policy denial or invalid input may move directly from proposed to terminal.
Cancellation may be requested in any non-terminal state, but the terminal
record is emitted only after the provider has stopped accepting effects and has
either proved cleanup or reported runner-integrity failure.

Terminal state is immutable. Restart recovery may finish an incomplete durable
transition, but it may not reopen a terminal Execution or replace its Evidence.
An automatic or user-requested retry is a new Execution with its own Capsule,
lease, Evidence, and `retry-of` lineage. Attempt counters are presentation
metadata and never collapse distinct attempts into one security subject.

### 3. Session semantics

A **Session** is a durable security and workspace envelope for an ordered or
concurrent set of child Executions. A live provider environment is a Session
incarnation, not the Session itself.

Each Session binds exactly one tenant and owning security principal. Knowledge
of its identifier grants no authority. Sharing requires an explicit grant that
names the grantee, allowed operations, expiry, and whether further delegation
is forbidden.

A Session has an explicit idle expiry and hard lifetime bound in its Capsule.
Client disconnection does not terminate it or extend either deadline. Renewal
is an authenticated, policy-admitted mutation within the sealed maximum; it is
never inferred from activity. A Session moves monotonically through:

```text
proposed -> admitted -> provisioning -> active
active -> suspending -> suspended
active|suspended -> destroying -> terminal
suspended -> restoring -> active
suspending -> active
suspending -> destroying -> terminal
restoring -> suspended
restoring -> destroying -> terminal
```

Suspended means no tenant VM, container, Store, credentials, handles, lease, or
network connection remains live. The Session references an admitted Checkpoint.
Restore creates a new incarnation with a new lease, fence, runtime instance,
resource table, and capability set. Transparent migration of live process or
connection state is not part of this contract.

`suspending -> active` is allowed only before Checkpoint publication and after
all running children and external effects are durably resolved. It advances the
Session fence and issues fresh handles and capabilities; it never revives
revoked authority. After Checkpoint publication, suspension must either prove
destruction and become suspended or pass through destroying to a terminal
integrity result.

`restoring -> suspended` is allowed only when failure occurred before a tenant
runtime or authority was assigned and the original Checkpoint remains intact.
Once assignment begins, failed restore destroys the new incarnation and proves
cleanup before it may return to suspended; otherwise it becomes terminal with
runner-integrity failure. A capacity failure may leave the Session suspended
and retryable without mutating it.

Child Executions receive immutable child Capsules. They may run concurrently
only when their aggregate CPU, memory, storage, task, effect, and concurrency
use fits the Session Capsule. A Session scheduler must reserve resources
atomically; racing children cannot each observe the full remaining envelope.

### 4. Workspace and output ownership

The Session owns a logical workspace whose initial identity and permitted
mutable roots are declared by its Capsule. A child Execution receives an exact
workspace generation. Its committed filesystem changes create the next
generation through a fenced atomic transition. Failed, canceled, stale, or
concurrent losing children cannot publish a workspace generation.

Stateless Executions receive an ephemeral workspace and destroy it at terminal
cleanup. Outputs that must survive are published as Artifacts or Evidence
before destruction under the output contract.

### 5. Public operations

Expose one domain-neutral facade through the Rust API and versioned remote
protocol. HTTP and language SDKs adapt the same contract. The CLI calls this
facade in process for local Providers and over the protocol for remote
Providers; it does not implement a separate lifecycle.

The minimum operations are:

- create, inspect, cancel, and stream events for an Execution;
- create, inspect, renew, suspend, restore, and destroy a Session;
- execute an admitted child Capsule within a Session;
- create and retrieve a Checkpoint;
- publish and retrieve authorized Programs and Artifacts;
- retrieve, stream, verify, and export authorized Evidence;
- construct and verify Capsules and approval subjects;
- request and record authorization decisions; and
- retrieve, verify, and revoke permitted Seals.

Portable Evidence is appended only by authenticated execution-plane producers.
Client-supplied claims or attachments use a distinct typed namespace and do not
inherit Provider Evidence semantics.

Every mutating request has a caller-chosen idempotency key scoped to tenant,
principal, operation, and target. An exact replay returns the original response;
a conflicting replay fails without mutation. Listing and event APIs use opaque
bounded cursors and never treat ordering timestamps as authorization tokens.

Local and remote requests use the same typed validation, canonical identities,
failure classifications, and lifecycle engine. Transport authentication and
Provider placement may differ; portable semantics may not.

## Consequences

- A Session survives client and transport churn without making a live runner
  the durable source of truth.
- Every retry and child command remains an independently attributable attempt.
- Integrations can map their own jobs, agent turns, or function invocations to
  the same portable operations.
- Concurrent Session work requires durable resource reservation and fenced
  workspace commits.
- Initial implementation work must separate existing workflow/job types from
  the public domain model without silently changing current Capsule identity.

## Review triggers

- A supported workload requires shared ownership not expressible as an
  explicit grant.
- Transparent live migration becomes a product requirement.
- Retry lineage cannot represent a Provider recovery safely.
- Concurrent workspace generations need merge semantics beyond one atomic
  winner.
- The stable public API requires cross-language encoding guarantees.
