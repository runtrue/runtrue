# ADR 0007: Generic trust-preserving execution model

- **Status:** Accepted
- **Compatibility scope:** target architecture for unreleased v0.x
- **Date:** 2026-07-15
- **Generalizes:** ADR 0003, which remains the CI-specific trust decision
- **Supersedes:** the stronger-backend substitution rule in ADR 0002; ADR 0010
  replaces ADR 0002 in full

## Context

Runtrue began with workflow and continuous-integration use cases, but its core
primitives apply to a broader problem: running arbitrary or untrusted programs
locally or remotely while bounding their authority and producing verifiable
evidence of what occurred.

AI coding agents are one demanding consumer of that system. They need to write
arbitrary files, invoke shells and subprocesses, install dependencies, run
compilers and tests, use Git, and iterate in a stateful workspace. Serverless
functions, customer-supplied plugins, evaluation systems, data processing,
interactive interactive workspaces, and security analysis need many of the
same controls. None of those domains should be embedded in the execution core.

The sandbox boundary alone is insufficient. Arbitrary code must not imply
arbitrary authority over host files, networks, credentials, external services,
or other tenants. Conversely, requiring a human to approve every command in an
interactive session would make agents and interactive workspaces unusable.
Runtrue needs a generic model that permits dynamic computation inside a sealed
authority envelope while retaining exact, immutable records of each execution.

Local, self-hosted, private-cluster, and managed providers must expose the same
portable semantics. Warm pools, placement, storage backends, and autoscaling
are necessary execution-plane facilities, but they must not change the meaning
of a Capsule or the observable result of a program.

This ADR establishes the foundational model. It records target architecture;
it does not claim that every operation, backend, or evidence grade described
here is already implemented.

## Decision

### 1. Product boundary

Runtrue is a portable, policy-controlled execution plane. Its core promise is:

> Run arbitrary code in an isolated environment, grant it only the authority
> described by an immutable approved plan, and produce verifiable evidence of
> everything it was allowed to affect.

The execution core contains no GitHub, pull-request, repository-hosting,
continuous-integration, deployment-product, or AI-agent behavior. Those systems
are clients, integrations, and independently versioned products that translate
their domain concepts into Runtrue's public execution API.

General workflow and agent-loop orchestration are not part of the execution
kernel. An optional orchestration layer may create and observe Runtrue
executions, but it uses the same public API as every other client and receives
no implicit authority.

### 2. Core vocabulary

Use the following domain-neutral nouns throughout the model, protocol, API, and
public documentation:

- **Program:** executable input such as a source tree, script, command, Wasm
  Component, OCI image, native executable, or content-addressed filesystem
  tree.
- **Execution:** one bounded attempt to run a Program.
- **Session:** a stateful sequence of Executions sharing one isolated
  workspace and authority envelope.
- **Capsule:** the immutable specification of an Execution or Session,
  including runtime identity, inputs, limits, capabilities, and output
  contract.
- **Seal:** approval of an exact Capsule approval subject.
- **Capability:** narrowly scoped authority over an external resource or
  effect.
- **Artifact:** immutable content-addressed input or output.
- **Checkpoint:** immutable content-addressed Session state suitable for a
  later restore.
- **Evidence:** recorded facts about admission, execution, resource use,
  capability calls, effects, and outputs.
- **Provider:** a local, self-hosted, private-cluster, or managed implementation
  of the Runtrue execution contract.

Terms such as action, job, step, repository, pull request, and agent belong to
integration layers. Existing implementation types may migrate incrementally,
but new core protocols must use the generic model.

### 3. Stateless Executions and stateful Sessions

Support two execution shapes:

1. A stateless Execution accepts a Program and immutable inputs, produces
   outputs and Evidence, and destroys its environment.
2. A Session leases an isolated environment and workspace across a sequence of
   child Executions. It remains available across client disconnects until it
   expires, is canceled, is suspended to a Checkpoint, or is destroyed.

A Session belongs to exactly one tenant and one authenticated security
principal. Possession of an identifier grants no access. Sharing or delegation
requires an explicit capability. Concurrent child Executions are allowed only
within the sealed resource and concurrency limits.

The initial Session contract does not promise transparent live migration after
a runner failure. Recovery occurs from an explicit Checkpoint. A restore
creates a new lease, fence, runtime instance, resource table, and set of
capabilities.

### 4. Capsule hierarchy and delegated Seal authority

An untrusted Program or agent may propose a Capsule but may never Seal its own
authority. A Seal is issued only by an authenticated human, policy service, or
trusted planner whose delegation is itself bounded by an existing Seal.

A Session Capsule defines the maximum authority and resource envelope for a
dynamic interaction. Each command or program chosen during the Session creates
an immutable child Execution Capsule that binds at least:

- the parent Session Capsule and Seal;
- Program, command, arguments, and working-directory identity;
- input Checkpoint or filesystem identity;
- runtime and environment identity;
- capabilities and limits used by that child;
- idempotency and external-effect declarations; and
- output and Evidence contract.

A delegated planner may authorize a child without a new human decision only
after proving that the child is a strict subset of the sealed Session envelope.
The child still receives its own canonical identity and Seal record. Exceeding
the envelope requires a new Capsule and authorization decision.

High-impact external effects may require a separate Seal even when computation
inside the Session is already authorized. Policy decides which effects require
that boundary.

### 5. Runtime and isolation selection

Support these isolation profiles:

- Wasmtime Components for compact, capability-oriented Programs.
- Firecracker microVMs as the default floor for arbitrary untrusted code and
  multi-tenant Linux environments.
- OCI for explicitly trusted shared-kernel workloads or as an inner runtime
  inside a microVM.
- Native execution only on an explicitly trusted local machine or dedicated
  trusted worker.

The final Capsule binds the exact isolation class and runtime compatibility
profile. Planning tools may recommend a runtime, but the scheduler may not
change it, substitute a supposedly stronger class, or fall back after an
admission or capacity failure. This exact-selection rule supersedes ADR 0002's
permission to select an equivalent or stronger backend.

Scheduling may choose any worker or prepared runtime instance that advertises
the exact required compatibility tuple and lies within the Capsule's permitted
provider, region, tenant, and trust constraints.

### 6. Capability and credential boundary

Code inside an admitted sandbox may be arbitrary. Effects outside the sandbox
must never be arbitrary.

The default authority set is empty. Capabilities may grant bounded access to
filesystem scopes, artifacts, network destinations, services, secrets,
identity, model inference, devices, external mutations, or other resources.
Every grant is explicit, policy-admitted, revocable, and attributable to a
Capsule.

Network access is denied by default. An admitted grant expands to concrete
destinations, protocols, ports, and constraints. Reusable profiles such as
package registries are reviewed policy expansions, not unrestricted internet
access. Metadata endpoints, private control networks, storage infrastructure,
and runner-management services remain denied unless named explicitly.

Long-lived plaintext credentials do not enter a guest by default. Prefer a
broker that applies a credential only to an authorized operation and
destination. Where an incompatible tool requires guest-visible credentials,
policy may issue a short-lived, Session-scoped derivative through an explicit
high-risk capability. Such material is excluded from Checkpoints and Replay
Bundles, redacted from output, and revoked at terminal cleanup.

### 7. External effects, idempotency, and retries

Model external mutations as capability calls with stable operation and
idempotency identifiers. Examples include publishing, deployment, messages,
payments, database mutation, signing, identity issuance, and source-control
updates.

Evidence records whether each effect was requested, rejected, accepted, or
left indeterminate. A provider may automatically retry only when it can prove
that no non-idempotent effect was accepted, or when the effect's protocol and
idempotency key make repetition safe. Otherwise a retry requires a new Capsule
or an explicit recovery decision.

### 8. Checkpoint requirements

Checkpoints are immutable, content-addressed, encrypted, authenticated, and
tenant-scoped. They include only the Session state declared by the Checkpoint
contract. They exclude plaintext secrets, active credentials, live network
connections, capability handles, runner identity, leases, fences, and pending
external operations.

A Checkpoint derived from tenant execution is never a sterile shared runtime
template. Restoring it recreates all external authority from the new Capsule
and policy decision rather than reviving prior handles.

### 9. Warm pools are execution-plane infrastructure

Warm pools remain part of Runtrue's execution plane. The portable core defines
their compatibility, sterility, leasing, fencing, cleanup, destruction, and
Evidence requirements. Provider implementations manage concrete pools,
placement, replenishment, draining, and autoscaling.

Warm versus cold start is not a Capsule semantic choice. If a compatible warm
instance is unavailable, a provider may start the same runtime cold without
changing the Program's authority or observable contract.

Use one-shot tenant leases:

- A microVM restored from an authenticated sterile snapshot serves exactly one
  Execution or Session and is destroyed afterward. A used VM is never cleaned
  and returned to the sterile pool.
- A Wasm provider may reuse an engine and authenticated AOT code, but creates a
  fresh Store, WASI context, resource table, and host capability state for each
  invocation.
- An OCI provider may reuse authenticated image layers and preparation
  metadata, but creates a new container for each Execution and does not return
  a used container to a general sterile pool.

Evidence records cold or warm acquisition, template identity, provider and
pool identity, lease and fence identifiers, compatibility tuple, and cleanup
or destruction result.

### 10. Portable providers and storage

Local, self-hosted, private-cluster, and managed Providers implement one
versioned execution contract. The CLI uses that contract rather than a separate
local execution path. Bisim verifies equivalent portable behavior and failure
classification across Providers; backend-specific security suites verify
isolation details.

Capsules, Seals, Programs, Artifacts, Checkpoints, Evidence, and Replay Bundles
use content-addressed logical storage interfaces. Local filesystems,
S3-compatible services, and managed stores are implementations. The core
protocol does not depend on a specific cloud object store.

### 11. Public operations

Expose domain-neutral operations through a stable Rust facade and versioned
remote protocol. HTTP or other language SDKs may adapt the same protocol. The
minimum operation set is:

- create, inspect, cancel, and stream events for an Execution;
- create, inspect, renew, suspend, restore, and destroy a Session;
- execute a child Capsule within a Session;
- create and retrieve a Checkpoint;
- publish and retrieve authorized Programs and Artifacts;
- retrieve, stream, verify, and export authorized Evidence;
- construct and verify Capsules and approval subjects;
- request and record authorization decisions; and
- retrieve, verify, and revoke permitted Seals.

An integration translates its domain events to these operations and translates
portable Evidence back into domain output. Portable Evidence is produced only
by authenticated execution-plane components under ADR 0015. Client-supplied
claims or attachments, if supported, use a distinct typed namespace and never
become Provider Evidence merely because a client uploaded them.

### 12. Evidence and Replay Bundles

Every Execution record supports terminal status, bounded stdout and stderr,
structured output, produced Artifacts, filesystem changes, resource usage,
capability calls, network activity, runtime and provider identity, parent/child
relationships, cleanup proof, and signed attestation. Empty fields remain part
of the stable model where applicable.

Evidence is append-only and tamper-evident. Payload retention is controlled by
tenant policy: hashes, identities, and terminal metadata may outlive source,
logs, network bodies, or sensitive Artifacts.

A Replay Bundle declares one of three grades:

- **Hermetic:** all execution inputs are content-addressed and no mutable
  external service or effect influenced execution.
- **Exact:** mutable interactions were replaced by a complete, policy-safe,
  authenticated recorded-interaction contract, so equivalent replay is
  expected without contacting or mutating the original service.
- **Evidence-only:** commands, inputs, effects, and observed results are
  retained, but mutable external behavior cannot be recreated exactly.

Runtrue never claims deterministic replay merely because a destination or
request was logged. Sensitive broker responses and network bodies are included
only when policy permits and their inclusion does not expose credentials.

### 13. Portable failure model

Use stable platform-level classifications:

- admission rejected;
- policy denied;
- capacity unavailable;
- runtime failure;
- Program failure;
- timed out;
- canceled;
- resource exhausted;
- external effect indeterminate; and
- runner integrity failure.

Provider-specific details are bounded diagnostics, not portable semantics. A
Provider must not turn an integrity failure into Program failure or success.

### 14. Multi-tenant isolation

Apply layered isolation:

- tenant-scoped workspaces, storage identities, and encryption domains;
- one microVM per untrusted Execution or Session;
- a fresh Wasm Store and host state per invocation;
- separate processes, pools, or hosts for stronger administrative trust
  boundaries; and
- no return of tenant-used instances to a sterile warm pool.

Session identifiers, content digests, pool membership, or placement metadata
are never authorization credentials.

## Non-goals

- Defining an AI-agent loop, CI workflow language, source-control integration,
  deployment product, or other domain orchestration.
- Treating Wasm alone as the sufficient tenant boundary for arbitrary Linux
  development workloads.
- Giving Programs unrestricted host access for compatibility.
- Promising transparent live Session migration in the initial implementation.
- Promising exact replay of mutable external systems without a safe recorded
  interaction contract.

## Consequences

- Runtrue's core can serve agents, serverless functions, plugins, evaluation,
  data processing, and future integrations without adopting their domain
  vocabulary.
- Supporting arbitrary untrusted code makes microVM lifecycle, guest images,
  capability brokering, and cleanup proof core security responsibilities.
- Interactive Sessions remain usable because one Seal can delegate a bounded
  envelope while every dynamic command still has an immutable child Capsule.
- Exact runtime selection prevents availability pressure from changing the
  approved trust boundary.
- Warm pools improve latency without becoming observable execution semantics
  or permitting cross-tenant instance reuse.
- Brokered credentials and default-deny networking reduce the value of a guest
  compromise.
- Portable Evidence and explicit Replay grades avoid overstating
  reproducibility.
- Managed features may scale the same engine without creating a managed-only
  Capsule or authority model.

## Detailed decisions

The following accepted ADRs own the detailed contracts introduced here:

1. ADR 0008: Programs, Executions, Sessions, and public operations.
2. ADR 0009: Capsule hierarchy and delegated Seal authority.
3. ADR 0010: runtime selection, isolation, and exact scheduling.
4. ADR 0011: capabilities, brokers, external effects, and retries.
5. ADR 0012: Checkpoints and Replay Bundles.
6. ADR 0013: warm pools and sterile execution.
7. ADR 0014: Provider contracts, storage, and Bisim conformance.
8. ADR 0015: Evidence, retention, attestations, and portable failures.

Each follow-up may strengthen this ADR's security requirements but must not
weaken them silently.

## Review triggers

- A supported workload cannot be expressed without domain-specific core
  behavior.
- Dynamic child-Capsule containment cannot be verified safely or efficiently.
- A credential or external-effect incident exposes a missing capability
  boundary.
- Session recovery requires transparent migration rather than explicit
  Checkpoints.
- Warm-pool latency goals conflict with sterile one-shot leasing.
- Bisim identifies an unavoidable semantic difference between local and
  managed Providers.
- A new isolation backend or hardware class changes the minimum trust model.
- Runtrue commits to a stable v1 public protocol or cross-language canonical
  Capsule encoding.
