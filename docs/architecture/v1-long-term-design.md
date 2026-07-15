# Runtrue v1: long-term product and architecture

- **Status:** Proposed design for review
- **Audience:** maintainers, contributors, Provider implementers, frontend authors,
  security reviewers, and early operators
- **Decision horizon:** the contract Runtrue intends to make before declaring v1
- **Related decisions:** [ADR 0001 through ADR 0015](../adr/)
- **Supersedes:** no accepted ADR; this document integrates them into one product
  direction and release boundary

## 1. Purpose

Runtrue began by solving a concrete problem: organizations sometimes need to
run GitHub Actions workflows where the GitHub Actions control plane is
unavailable, disabled, unsuitable for the security boundary, unable to reach
required infrastructure, or not permitted to hold the organization's code and
credentials.

That is Runtrue's first product and adoption path. It is not Runtrue's final
architectural boundary.

Runtrue's long-term goal is to be an open-source, trust-preserving control and
execution plane for arbitrary programs. A caller should be able to submit a
bounded stateless Execution or create a stateful Session, select an explicitly
supported runtime, grant only declared authority, and receive verifiable
Evidence of admission, effects, outputs, and cleanup. GitHub Actions, other CI
systems, coding agents, evaluation systems, plugin hosts, and future automation
products are frontends over that common execution contract.

This document defines that destination before the project claims v1. It exists
to prevent the first successful frontend from becoming an accidental permanent
architecture and to prevent the long-term goal from expanding into an
unbounded promise to replace every scheduler, workflow engine, or application
platform.

The existing technical design remains the detailed source for the current
CI-oriented product, threat model, components, and implementation history. When
its older product or roadmap language treats CI/CD as Runtrue's permanent
boundary, this document defines the intended v1 product boundary instead.
Accepted ADRs remain authoritative for their individual decisions; any future
change to those decisions still requires a superseding ADR.

It answers five questions:

1. What product is Runtrue ultimately building?
2. What does “arbitrary workload” mean within a testable contract?
3. Which responsibilities belong to the generic kernel, a Provider, or a
   frontend?
4. What must be real, public, and supportable before Runtrue calls itself v1?
5. How does the current GitHub Actions-oriented implementation reach that
   destination without a rewrite?

## 2. Product thesis

Runtrue's durable product statement is:

> Runtrue is an open-source, trust-preserving execution control plane. It runs
> arbitrary programs locally or remotely under an immutable authority envelope
> and produces verifiable Evidence of what they were allowed to affect.

The shorter public promise remains:

> **Run local. Run remote. Run true.**

“Run true” means all of the following:

- the admitted Program, runtime, inputs, limits, and authority have immutable,
  canonical identities;
- the authorization decision applies to the exact subject that executes;
- availability pressure cannot silently weaken or replace the selected
  isolation boundary;
- external authority is default-deny, bounded, attributable, and revocable;
- accepted and possibly accepted external mutations are not hidden behind a
  generic success or retry result;
- local, self-hosted, private-cluster, and managed Providers implement the same
  advertised portable semantics; and
- Evidence states what Runtrue observed without claiming guarantees beyond its
  observation boundary.

Runtrue is valuable when code and authority have different trust levels. The
code may be untrusted, dynamically generated, supplied by a customer, or merely
less trusted than the credentials and systems it needs to use. Runtrue does not
attempt to prove that the code is correct. It constrains and records the code's
authority.

## 3. The first frontend and the long-term platform

### 3.1 GitHub Actions is the first frontend

GitHub Actions compatibility is the initial user-facing wedge because it
exercises the generic kernel against demanding real workloads:

- immutable source and dependency resolution;
- hostile pull-request code;
- graphs, retries, timeouts, services, caches, and artifacts;
- secrets, workload identity, signing, and deployment authority;
- human and policy approval;
- external source-control mutations; and
- local reproduction of remote failure.

The GitHub Actions frontend discovers and parses workflow files, reports
compatibility, resolves action and image identities, and translates supported
semantics into generic Runtrue Programs, Capsules, capabilities, and public
operations. GitHub installation management, webhook normalization, source
fetching, and check publication are integration services. None of them defines
the execution kernel.

Runtrue does not promise complete behavioral emulation of GitHub Actions. A
frontend must classify unsupported, unsafe, Provider-specific, and emulated
behavior explicitly. It may never approximate a security-relevant behavior by
granting ambient authority or falling back to native execution.

### 3.2 GitHub Actions is not the public kernel

The following concepts must not be required by a generic Execution or Session:

- GitHub, a repository host, a pull request, a check run, or a webhook;
- a workflow, job, step, action marketplace, or `runs-on` label;
- a Git checkout, branch, tag, or repository credential;
- CI-specific cache, artifact, environment, or deployment semantics; or
- a YAML workflow language.

They may be represented by frontend-owned records and translated into generic
objects. A generic client must be able to use Runtrue without creating a fake
repository, workflow, job, or pull request.

### 3.3 Future frontends

The generic boundary is intended to support, without embedding their domain
logic in the kernel:

- coding-agent and software-development Sessions;
- model, tool, and agent evaluation;
- customer-supplied extension and plugin execution;
- secure build, test, analysis, and release automation;
- bounded serverless-style functions and event handlers;
- batch and data-transformation tasks; and
- organization-specific automation products.

These are compatibility targets, not claims that every frontend will ship in
the core repository or before v1.

## 4. Meaning of arbitrary workload

Runtrue uses “arbitrary workload” in a bounded sense:

> A workload is arbitrary program code expressible as a Program and executable
> by an advertised runtime profile under a finite Capsule contract.

The Program may be a command, script, source tree and entry point, signed Wasm
Component, signed OCI image, native executable admitted on a trusted host, or a
future explicitly versioned Program kind. Program identity is immutable before
admission. Mutable names such as branches, tags, image tags, or package ranges
are resolver inputs, never admitted runtime identity.

Runtrue supports two portable workload shapes:

1. **Execution:** one bounded attempt that consumes immutable inputs, produces
   outputs and Evidence, and disposes of its runtime.
2. **Session:** a durable tenant and authority envelope containing a sequence of
   child Executions over a logical workspace. The live runtime is a replaceable
   Session incarnation, not the durable source of truth.

An advertised Provider feature profile may support only one of these shapes.
Unsupported shapes and runtime features fail admission.

### 4.1 What arbitrary does not mean

The long-term goal is not an unconditional promise to run every application
topology. Unless a later ADR defines a portable contract, Runtrue does not claim
to be:

- a general replacement for Kubernetes, Nomad, or operating-system service
  management;
- a deployment controller for indefinitely running production services;
- a distributed database, message broker, or service mesh;
- a transparent live-migration system;
- an MPI, gang-scheduling, or distributed-training control plane;
- a complete workflow or agent-loop orchestration language;
- a universal compatibility layer for every operating system, device, and CPU;
  or
- an exactly-once facade over external systems that do not provide an
  idempotency or transaction contract.

Some of those workloads may later be expressed through new Program, Session,
runtime, placement, or orchestration profiles. They do not enter the portable
contract merely because a Provider can start an underlying process or VM.

## 5. System boundaries

Runtrue is divided into five architectural layers.

```text
domain frontends and products
        |
public Program, Execution, Session, Seal, and Evidence operations
        |
generic admission, policy, scheduling, capability, and lifecycle kernel
        |
versioned Provider contract and conformance boundary
        |
runner, guest, runtime, storage, network, and infrastructure implementations
```

### 5.1 Frontends and products

A frontend translates domain input into generic Runtrue objects and translates
Evidence back into domain output. It may perform domain-specific planning but
receives no private execution authority and uses the same public operations as
other clients.

An independently versioned product may orchestrate many Runtrue objects. It may
own agent loops, CI graphs, deployment workflows, evaluation campaigns, or user
experiences. It is not loaded as a native control-plane plugin.

### 5.2 Public execution contract

The public contract owns the stable nouns and operations that clients and
Providers share. It is available through:

- the stable Rust facade;
- a versioned remote protocol and documented HTTP mapping;
- generated or hand-maintained SDKs whose behavior is checked against common
  conformance vectors; and
- a CLI that calls the same facade locally or remotely.

Local execution is a Provider implementation, not an alternate semantics path.

### 5.3 Generic kernel

The kernel owns canonical identity, validation, admission, policy evaluation,
Seal verification, containment, scheduling constraints, lifecycle state,
capability grants, external-effect state, portable failures, and Evidence
requirements. It contains no domain-specific frontend behavior.

### 5.4 Provider

A Provider implements the Runtrue contract for one administrative and trust
domain. It may be local, single-node, self-hosted cluster, private cloud, or
managed. It owns concrete runtime inventory, capacity, leases, storage,
brokers, runner communication, cleanup, and infrastructure operations.

Provider-specific installation, billing, autoscaling, maintenance, and fleet
APIs are outside the portable workload contract. They cannot grant workload
authority or redefine a portable failure.

### 5.5 Runtime and guest

Workload code executes only on a runner or inside an isolated runtime selected
by the Capsule. The control-plane process remains unprivileged and never loads
or executes workload code, repository code, action code, user policy
executables, or third-party native plugins.

## 6. Core domain model

### 6.1 Program

A Program is immutable executable input. Its identity binds its kind, digest,
signature or provenance requirements, platform, entry point, ABI, and material
needed to interpret it. Resolution is complete before the containing Capsule is
sealed.

Programs are content-addressed data, not authority. Knowing a digest or storage
location does not grant read or execution permission.

### 6.2 Capsule

A Capsule is the immutable specification of an Execution or Session. It binds,
as applicable:

- Program and immutable inputs;
- exact runtime compatibility profile;
- parent Capsule, Seal, and delegation identity;
- resource, duration, task, and concurrency limits;
- Provider, region, trust-domain, and placement constraints;
- filesystem, network, secret, identity, device, and service capabilities;
- declared external effects and idempotency requirements;
- nondeterminism profile;
- workspace or Checkpoint generation;
- output and Artifact contract;
- Evidence and retention profile; and
- compatibility generation.

All execution-affecting defaults are materialized before canonical identity is
computed. Unknown fields or unknown compatibility generations fail closed.

### 6.3 Approval subject and Seal

The approval subject binds the Capsule digest and authorization inputs that are
intentionally outside the Capsule, including current policy, issuer,
revocation, environment, source, or other decision context. A Seal records an
authorization decision over exactly that subject.

Changing executable content changes the Capsule. Changing an external
authorization input changes the approval subject. Either invalidates reuse of
the prior decision.

A Seal may be issued by an authenticated human, activated policy service, or
delegated planner. Authentication alone never grants authority to Seal.

### 6.4 Execution

An Execution is one bounded attempt with one immutable Capsule, lifecycle,
event stream, lease and fence generation, terminal result, and Evidence chain.
A retry is a new Execution with explicit lineage; a Provider never erases or
reopens the prior attempt.

### 6.5 Session

A Session is a durable security, resource, and workspace envelope. It has one
tenant and owning principal. Sharing and delegation are explicit grants;
knowledge of the Session identifier grants nothing.

Each child command or Program is an immutable child Execution Capsule. A
trusted verifier proves that the child is contained by the parent Session
Capsule and delegation before admission. Dynamic planning does not make an
agent or guest its own authority source.

Active Sessions may retain one tenant runtime incarnation. Suspension creates a
safe logical Checkpoint and destroys the incarnation. Restore creates a new
lease, fence, runtime, handles, and capabilities. Runtrue does not initially
promise transparent preservation of live processes, connections, or device
state.

### 6.6 Capability

Every Program begins with no external authority. A Capability is typed,
versioned authority over a bounded resource or operation. A grant identifies
its resource, operations, constraints, budget, lifetime, revocation behavior,
and Capsule attribution.

Guests receive invocation-local handles rather than Provider credentials or
host paths where the runtime permits it. Every broker call revalidates the
current lease, fence, revocation, cancellation, limits, and remaining budget.

### 6.7 Evidence

Evidence is a canonical, append-only record produced by authenticated
execution-plane components. It covers the advertised profile's admission,
scheduling, lifecycle, capability, effect, output, cleanup, and terminal
observations. Client attachments remain distinct claims and cannot satisfy
Provider Evidence requirements.

An attestation is a signed bounded statement over finalized Evidence. It never
claims semantic correctness, complete tracing, or isolation guarantees not
observed by its declared grade.

## 7. Authorization and delegated execution

The authorization model must support both exact review and usable interactive
work.

For stateless automation, a human or policy service may Seal one exact
Execution subject. For a Session, the parent Seal may delegate a finite envelope
to a trusted planner. The planner can propose children within that envelope,
but the trusted Runtrue verifier independently recomputes typed containment.

Containment is field-specific. Numeric limits narrow, allowed sets select
members, filesystem scopes descend without gaining access, network scopes
narrow destinations and protocols, and capabilities preserve or reduce their
operations and budgets. Unknown, dynamic, or incomparable values fail.

Aggregate Session reservation is part of admission. Two concurrent children
cannot each consume the same remaining resource or effect budget.

Policy may require a separate just-in-time Seal for high-impact effects such as
deployment, signing, payment, production mutation, identity issuance, or
privileged source-control updates. Authorization to compute never implicitly
authorizes those effects.

## 8. Runtime and isolation model

The Capsule selects one exact, versioned runtime compatibility profile. A
runtime family is not a scheduler hint and is not silently replaceable by a
supposedly stronger backend.

The intended families are:

- Wasmtime Components for compact capability-oriented Programs;
- rootless OCI for explicitly trusted shared-kernel workloads;
- Firecracker microVMs for arbitrary untrusted Linux code and multi-tenant
  execution;
- OCI inside a microVM when container compatibility and a tenant kernel
  boundary are both required; and
- native execution only on an explicitly trusted local machine or dedicated
  trusted worker.

Additional operating systems, VMMs, hardware devices, confidential-computing
profiles, GPUs, and accelerators require explicit profiles. A missing profile is
unsupported, not permission to downgrade.

Runtime identity binds the security- and behavior-relevant platform, engine,
kernel, rootfs, guest, ABI, mitigation, protocol, device, and compiler contract.
The v1 compatibility schema must distinguish fields that change portable
semantics or security from operational build identity. Patch publication must
remain fail-closed without causing unnecessary Capsule churn for fields that a
reviewed compatibility generation declares non-semantic.

Every advertised profile passes portable Bisim cases and a runtime-specific
adversarial suite. Bisim establishes portable behavior; it does not claim that
Wasm, a container, and a microVM provide equal security.

## 9. Scheduling and Provider selection

Providers publish authenticated runtime inventory separately from expiring
capacity observations. Scheduling filters by:

- exact runtime compatibility identity;
- permitted Provider and administrative trust domain;
- tenant boundary and runner posture;
- region, locality, and data residency;
- devices and resources; and
- non-revoked inventory and security generation.

Capacity is leased and fenced. A stale runner or scheduler generation cannot
claim or continue work after a newer decision.

The scheduler may select any concrete worker, pool, zone, or sterile prepared
instance inside the Capsule's allowed sets. It may choose cold or warm
acquisition when both implement the same exact runtime contract. It may not
rewrite the Program, runtime, authority, limits, or placement constraints.

No compatible capacity produces `capacity unavailable`. It never triggers a
weaker isolation profile or native fallback.

## 10. External authority and effects

Arbitrary computation inside the sandbox must not imply arbitrary authority
outside it.

### 10.1 Filesystem and workspace

Filesystem grants name normalized roots, access modes, bounds, and publication
rules. Host paths are never ambient authority. Stateless workspaces are
destroyed after outputs are published. Session workspace changes use fenced,
atomic generations so stale or racing children cannot publish state.

### 10.2 Network

Network access is denied by default. Grants name destinations, protocols,
ports, DNS behavior, direction, time, and byte constraints. Metadata services,
Provider control networks, storage infrastructure, and private addresses remain
denied unless explicitly admitted.

Reusable network profiles are reviewed expansions of exact constraints, not an
`internet: true` shortcut. Raw sockets, listeners, proxies, and tunnels are
separate high-risk capability classes.

### 10.3 Credentials and identity

Runtrue prefers a broker that applies authority to an admitted operation
without revealing a credential to the guest. When an incompatible tool
requires guest-visible material, policy may release only a short-lived bounded
derivative through an explicit high-risk capability.

Guest-visible credential release taints reachable guest-mutable state. Scanning
and redaction cannot prove that an adversarial Program did not transform the
credential. Strong Checkpoint and Replay grades therefore require discarding
tainted state or a future admitted information-flow boundary.

### 10.4 External mutations

Every non-read external mutation has a stable operation identity and
idempotency key. Before transmission or enabling a coarse mutation-capable
channel, the Provider durably records `requested`. The operation then becomes
`rejected`, `accepted`, or `indeterminate`.

An automatic retry is permitted only when Runtrue can prove that repetition is
safe. A lost response after possible transmission is not silently classified as
failure or rejection. Exactly-once execution is claimed only when the external
system provides an atomic idempotency or transaction contract that the broker
verifies.

## 11. Checkpoints, Replay Bundles, and nondeterminism

A Checkpoint is an immutable, encrypted, authenticated, tenant-scoped logical
state manifest. It may contain declared workspace and process-independent tool
state. It excludes live credentials, connections, handles, leases, fences,
pending effects, and unapproved memory or device state.

A Replay Bundle binds the admitted Program, Capsule, inputs, runtime, outputs,
and permitted Evidence needed to investigate or reproduce an Execution. It
declares one honest grade:

- **Hermetic:** all relevant inputs are immutable and no mutable external
  service influenced execution.
- **Exact:** mutable interactions were replaced by a complete, authenticated,
  policy-safe recorded-interaction contract.
- **Evidence-only:** the bundle records what happened but cannot reproduce all
  mutable behavior safely.

Runtrue does not promise deterministic output merely because it logged a
destination, request, clock, or random source. Live nondeterminism is an
explicit Capsule input profile and may limit replay grade.

## 12. Evidence, failure, and finalization

Portable failure classes are protocol data. They distinguish admission,
authorization, capacity, Program behavior, runtime failure, cancellation,
resource exhaustion, indeterminate effects, and lost integrity. Provider logs
and diagnostic codes may add detail but cannot redefine the portable result.

Program output completion is not terminal finalization. Before publishing a
terminal result, the Provider fences new activity, classifies effects,
publishes admitted outputs, revokes authority, disposes of the runtime as
required, and commits cleanup and terminal Evidence.

An unresolved effect overrides an ordinary result with `external effect
indeterminate`. An unproven isolation, fencing, runtime, Evidence, or cleanup
boundary produces `runner integrity failure`. All observed causes remain in
Evidence even when a safety override controls the primary status.

Evidence retention separates durable identity and integrity metadata from
logs, source, bodies, outputs, and specially governed content. Expiry leaves a
signed or chained tombstone that distinguishes intentional deletion from
corruption. Historical claims remain immutable while current replay and payload
verification availability may degrade.

## 13. Warm capacity and reusable state

Warmth is a Provider optimization, not a workload semantic. A Capsule requests
an exact runtime contract, not a warm worker.

Reusable state is limited by runtime family:

- Firecracker may restore authenticated sterile snapshots created before any
  tenant data or authority enters the VM.
- Wasm may reuse an Engine and authenticated AOT code but creates a fresh Store,
  WASI context, resource table, handles, and host state per invocation.
- OCI may reuse authenticated immutable image material but creates a fresh
  container, writable layer, namespaces, resource boundary, and process tree.

A runtime instance that begins assignment to tenant work never returns to a
sterile pool. Ambiguous assignment, handoff, cleanup, or destruction leads to
quarantine and destruction, not reclassification.

Providers may omit warm capacity entirely. Absence affects latency and
capacity, not Capsule meaning.

## 14. Provider contract and Bisim

The Provider boundary is the principal OSS extension point. A Provider
advertises exact contract and feature profiles rather than a general claim of
compatibility.

Profiles may cover:

- stateless Executions;
- Sessions and concurrent child Executions;
- Checkpoint suspend and restore;
- runtime compatibility identities;
- capability and external-effect classes;
- Evidence and attestation grades; and
- Replay Bundle grades.

Absence means unsupported. A Provider never approximates an unavailable
feature.

Bisim compares the portable projection of controlled Executions across two
Providers. It may normalize declared operational facts such as concrete worker
identity, bounded timestamps, or cold-versus-warm acquisition. It never
normalizes Program output, a capability decision, external-effect state,
runtime compatibility, missing Evidence, or a security failure.

Every published conformance statement binds the exact suite, fixture, Provider
generation, runtime, configuration, policy, image, and key identities tested.
Skipped, flaky, or indeterminate required cases are not passes.

Managed Providers may add scale, placement, availability, administration, and
support. They must not create a managed-only Capsule field, hidden authority,
Seal bypass, or different meaning for a portable failure. Commercial
differentiation belongs in operating the same contract well.

## 15. Storage model

The generic kernel depends on typed logical stores, not a particular cloud SDK,
object store, or host path. Interfaces cover immutable objects, canonical
manifests, tenant-encrypted state, Evidence append, leases, and atomic
publication.

Implementations must provide digest and size verification, create-once or
compare-and-swap publication, independent authorization, bounded recovery,
safe filesystem materialization, retention tombstones, and auditability.

A content digest is integrity metadata, not access authority. Cross-tenant
deduplication is forbidden when equality leaks protected information. Public,
immutable content may share physical bytes only under an explicit shared trust
policy.

The supported v1 deployment may use SQLite and local filesystem storage. The
portable contract must not depend on either, so later PostgreSQL, S3-compatible,
or managed implementations do not fork execution semantics.

## 16. Public API and SDK contract

Before v1, the remote public API must expose the generic model directly. A
client must be able to perform at least:

- publish and inspect an authorized Program;
- construct, verify, and inspect a Capsule and approval subject;
- request authorization and retrieve or revoke permitted Seals;
- create, inspect, cancel, and stream events for an Execution;
- create, inspect, renew, suspend, restore, and destroy a Session when the
  Provider advertises that profile;
- create a child Execution within a Session;
- publish and retrieve authorized Artifacts;
- create and retrieve a Checkpoint;
- stream, retrieve, verify, and export Evidence; and
- retrieve Provider descriptors, runtime inventory, and supported feature and
  conformance profiles.

All mutating requests use caller-chosen idempotency keys with explicit scope.
Exact replay returns the original response; conflicting reuse fails without
mutation. Event and list pagination uses opaque cursors, never timestamps as
authorization or ordering proof.

The HTTP and SDK model may offer ergonomic builders, but canonical identity and
signature behavior must be defined by a language-independent v1 encoding with
published cross-language positive and adversarial vectors. No SDK may invent
defaults or canonicalization that diverge from the protocol generation.

Repository, workflow, run, job, and step endpoints may remain as
frontend-specific APIs. They adapt to the generic operations and do not replace
them.

## 17. Open-source project shape

Runtrue's long-term goal benefits from an open implementation because Provider
portability, security review, conformance, air-gapped operation, and ecosystem
trust require inspectable contracts and testable behavior.

The core project should publish:

- canonical protocol schemas and compatibility policy;
- Capsule, approval-subject, Seal, and Evidence encodings;
- a Provider development kit;
- Bisim and runtime-security conformance harnesses;
- positive and adversarial test vectors;
- a local reference Provider;
- at least one strongly isolated Linux Provider profile;
- threat models and security response policy; and
- release provenance, SBOMs, and signed compatibility metadata.

Independent repositories may own domain frontends, Provider integrations,
capability brokers, SDKs, examples, and products. Security-critical extension
code runs as a separately authenticated service or Capsule workload, never as
an unreviewed native plugin in the control-plane process.

Before public v1, the project should also publish governance, maintainer and
review responsibilities, a compatibility and deprecation policy, a Code of
Conduct, and a process for accepting new runtime, capability, and Evidence
profiles.

## 18. v1 product boundary

The long-term architecture is intentionally broader than the minimum feature
set required for v1. Runtrue v1 means the generic contract is stable and real;
it does not mean every planned frontend, Provider, runtime, or scale backend is
complete.

### 18.1 Required v1 profiles

The proposed minimum v1 distribution includes:

- a generic stateless Execution API;
- a bounded Session profile sufficient for a coding or interactive automation
  reference flow;
- the GitHub Actions frontend over the generic API;
- the local Provider;
- one remote single-node Provider deployment;
- rootless OCI for admitted trusted Linux workloads;
- one microVM-backed profile for arbitrary untrusted Linux Programs;
- canonical Capsule, approval-subject, Seal, Artifact, and baseline Evidence
  contracts;
- filesystem, bounded network, brokered secret or identity, Artifact output,
  and source-control effect capabilities;
- durable effect states and retry safety;
- Evidence-only Replay Bundles, with Hermetic grade where its proof is
  satisfied;
- public Provider profile and Bisim conformance results; and
- documented installation, upgrade, backup, restore, revocation, and security
  response paths.

Wasm may be a required v1 profile only if its SDK, toolchain, runtime authority,
and conformance path are supportable for users. Its presence in the codebase
alone does not make it a release requirement.

### 18.2 Optional or post-v1 profiles

The following may remain experimental, optional, or post-v1 without weakening
the generic v1 claim:

- exact recorded-interaction replay;
- transparent process or device checkpointing;
- warm microVM pools and advanced autoscaling;
- multi-replica control-plane HA;
- PostgreSQL and remote object storage;
- Windows and macOS runtimes;
- GPUs, accelerators, confidential computing, and specialist devices;
- Kubernetes-native fleet management;
- additional SCM and CI frontends;
- arbitrary raw-socket authority;
- complete GitHub Actions compatibility; and
- managed regional or multi-cloud placement.

Experimental profiles are versioned and fail closed. They do not receive a
stable v1 compatibility promise until promoted through their own review and
conformance gates.

### 18.3 Explicit v1 non-goals

Runtrue v1 does not promise:

- support for every GitHub Actions workflow;
- a production service deployment platform;
- transparent live migration;
- automatic safe retry after an unclassified external mutation;
- deterministic replay of live networks, clocks, or randomness;
- equivalent security between runtime families;
- execution on an unadvertised operating system or device; or
- high availability from the minimal single-node installation.

## 19. Declaration gates for v1

Runtrue must not declare v1 merely because the existing CI path is useful or
because public Rust types use generic names. All of the following gates must be
satisfied.

### 19.1 Product and API gate

- A non-CI client can publish a Program and complete an Execution through the
  public remote API without creating repository or workflow records.
- A reference Session client can execute at least two immutable children over a
  durable workspace envelope.
- The GitHub Actions frontend uses the same generic admission and execution
  operations rather than a privileged internal path.
- Public documentation describes GitHub Actions as the first frontend, not the
  kernel identity.

### 19.2 Compatibility gate

- Runtrue adopts a language-independent canonical v1 encoding.
- Cross-language vectors cover canonical identity, unknown fields, defaults,
  signatures, containment, and approval-subject construction.
- The remote protocol publishes support, negotiation, and deprecation rules.
- The server and runner support the documented rolling-upgrade generations.

### 19.3 Security gate

- The control plane runs without executor privileges and cannot load workload
  code or native extensions.
- The microVM and OCI profiles pass their advertised adversarial suites.
- Stale leases, fences, handles, credentials, tickets, and runner identities
  fail before reading protected inputs or publishing effects and outputs.
- Guest-visible credentials follow the declared taint and output restrictions.
- Unproven cleanup and indeterminate mutations cannot be presented as ordinary
  Program failures or safe retries.

### 19.4 Provider and parity gate

- Local and remote Providers pass the same pinned Bisim suite for every common
  advertised feature.
- Each Provider publishes exact, signed conformance metadata and unsupported
  cases.
- Cold and warm acquisition, where advertised, preserve the same portable
  contract.
- Provider-specific diagnostics never alter the portable failure or Evidence
  projection.

### 19.5 Operations gate

- The minimal deployment has documented install, TLS, enrollment, upgrade,
  backup, restore, key rotation, retention, and revocation procedures.
- Server and runner restart, lost lease, partial publication, storage
  corruption, and cleanup uncertainty have tested recovery outcomes.
- Required data paths are bounded in memory, disk, concurrency, and time.
- The release identifies which topology is evaluation-only and which is
  recommended for supported operation.

### 19.6 OSS readiness gate

- The repository is buildable and testable from documented public inputs.
- Contribution, governance, security, compatibility, and release policies are
  published.
- The Provider and frontend extension boundaries have independent examples.
- Required conformance gates run without access to a private managed service.

## 20. Migration from the current implementation

The current implementation has substantial CI-oriented control-plane,
workflow, runner, storage, policy, and executor code. Reaching the generic v1
contract should be an extraction and convergence program, not a rewrite.

### Phase A: make the boundary observable

1. Keep the current workflow and run APIs operational.
2. Inventory every durable type and endpoint that assumes repository, workflow,
   job, or step identity.
3. Classify each as frontend-owned, generic with legacy naming, or genuinely
   CI-specific.
4. Add architectural tests that keep generic crates free from workflow, SCM,
   GitHub, database, transport, and executor dependencies.

### Phase B: make generic execution real

1. Implement generic Program publication and Execution admission in the
   control plane.
2. Persist generic Execution lifecycle and Evidence independently from CI run
   presentation records.
3. Adapt runner leasing and completion to generic Execution identity while
   preserving a mapping for workflow jobs.
4. Expose the public generic HTTP operations and at least one non-Rust SDK.
5. Provide a CLI flow that executes the same Program locally and remotely
   without a workflow file.

### Phase C: converge the first frontend

1. Translate a compiled workflow graph into generic Executions and, where
   appropriate, a parent orchestration record owned by the frontend.
2. Ensure workflow approvals become generic Seals over exact subjects.
3. Map cache, Artifact, OIDC, secret, and source-control behavior to generic
   capability and effect classes.
4. Generate GitHub checks and UI views from generic Evidence plus
   frontend-owned metadata.
5. Remove any CI-only bypass of generic admission, scheduling, capability,
   cleanup, or failure behavior.

### Phase D: prove Sessions and a second frontend

1. Implement the Session lifecycle, child containment, reservation, workspace
   generation, and Checkpoint path for one supported profile.
2. Build a small coding-agent or interactive automation reference frontend
   using only public operations.
3. Demonstrate that the second frontend requires no GitHub, repository,
   workflow, job, or step objects in the kernel.

### Phase E: stabilize v1

1. Adopt the language-independent canonical encoding.
2. Freeze the supported protocol and compatibility generations.
3. Publish Provider tooling and conformance metadata.
4. Complete the declaration gates in Section 19.
5. Promote only the profiles that meet their release and operations bars.

## 21. Scope-control rules

The long-term goal is broad, so Runtrue needs explicit rules for deciding what
enters the kernel.

A proposed feature belongs in the generic kernel only when:

1. at least two independent frontend domains need the semantic primitive, or
   the primitive is necessary to preserve a core security invariant;
2. it can be expressed without embedding one product's vocabulary;
3. its authority, failure, Evidence, compatibility, and cleanup behavior can be
   specified and tested;
4. a Provider can advertise it explicitly rather than approximating support;
   and
5. it does not require workload code to enter the control-plane trust boundary.

Otherwise the feature belongs in a frontend, product, Provider-specific
control API, broker integration, or experimental profile.

New runtime and capability classes require positive and adversarial
conformance. New Capsule fields require explicit containment rules. New
portable failure states require a client-handling and retry analysis. New
attestation claims require an observation source and declared limitation.

## 22. Success measures

The project should measure progress toward the long-term goal through behavior,
not the number of supported workload labels.

### 22.1 Adoption measures

- Time from installation to the first local and remote Execution.
- Percentage of supported GitHub Actions workflows translated without unsafe
  approximation.
- Number of non-CI clients using the generic API.
- Number of independently maintained frontends, Providers, brokers, and SDKs.
- Upgrade success across supported compatibility generations.

### 22.2 Security and correctness measures

- Conformance coverage and unresolved required cases per advertised profile.
- Time to revoke a runtime, key, Seal, runner, or capability generation.
- Incidence of indeterminate effects, integrity failures, and unsafe retry
  requests.
- Cleanup and destruction proof success rate.
- Cross-Provider Bisim differences and time to resolution.

### 22.3 Operational measures

- Admission, queue, cold-start, warm-start, finalization, and Evidence latency.
- Storage and Evidence cost per Execution and retained grade.
- Capacity-unavailable rate by exact runtime profile.
- Runner utilization without cross-tenant state reuse.
- Backup, restore, and recovery drill success.

Performance targets never authorize weaker isolation, skipped Evidence, ambient
credentials, or runtime substitution.

## 23. ADR alignment

This design incorporates every accepted or superseded decision as follows:

| ADR | v1 alignment |
| --- | --- |
| [0001](../adr/0001-rust-core-and-extension-boundaries.md) | Keeps the Rust core and separate-process extension boundary; frontends and products remain independently versionable. |
| [0002](../adr/0002-execution-isolation.md) | Retained only as history; ADR 0010 owns exact runtime selection. |
| [0003](../adr/0003-workflow-trust-and-approval.md) | Preserves the safe GitHub Actions frontend and exact workflow/effect approval model without generalizing CI nouns into the kernel. |
| [0004](../adr/0004-capsule-identity-and-versioning.md) | Uses the current v0.x identity during migration and requires a language-independent canonical format before v1. |
| [0005](../adr/0005-runtrue-naming.md) | Keeps Runtrue, Capsule, Seal, Bisim, Replay Bundle, and public naming rules. |
| [0006](../adr/0006-wasi-0.3-runtime.md) | Keeps the pinned, deny-ambient WASI profile while making its v1 release status depend on usable toolchain and conformance support. |
| [0007](../adr/0007-generic-trust-preserving-execution.md) | Makes its generic product boundary the explicit long-term product goal. |
| [0008](../adr/0008-programs-executions-sessions-and-public-operations.md) | Requires the generic public operations to be implemented remotely before v1. |
| [0009](../adr/0009-capsule-hierarchy-and-delegated-seal-authority.md) | Preserves typed containment and bounded planner delegation as the Session authorization model. |
| [0010](../adr/0010-runtime-selection-isolation-and-exact-scheduling.md) | Preserves exact runtime profiles and no fallback while requiring v1 to classify semantic versus operational identity fields deliberately. |
| [0011](../adr/0011-capabilities-brokers-external-effects-and-retries.md) | Makes default-deny authority, broker preference, durable effect state, and safe retry part of the required core. |
| [0012](../adr/0012-checkpoints-and-replay-bundles.md) | Preserves safe logical Checkpoints, taint, and honest replay grades without promising live process snapshots. |
| [0013](../adr/0013-warm-pools-and-sterile-execution.md) | Keeps one-shot tenant use and sterile publication while allowing v1 Providers to omit warm capacity. |
| [0014](../adr/0014-provider-contracts-storage-and-bisim-conformance.md) | Makes the Provider development and conformance boundary a primary OSS surface. |
| [0015](../adr/0015-evidence-failures-attestations-and-retention.md) | Preserves append-only Evidence, stable failures, finalization, scoped attestations, and payload expiry. |

## 24. Decisions still requiring ADRs

This design intentionally does not decide the following durable details:

1. The language-independent v1 canonical encoding and signature domains.
2. The exact v1 remote protocol, transport, and support window.
3. Which Session profile and runtime are mandatory in the v1 distribution.
4. The separation between semantic runtime compatibility identity and
   operational build or attestation identity.
5. The baseline versus enhanced Evidence profiles required by v1.
6. The Provider SDK packaging, discovery, and conformance publication format.
7. Whether the GitHub Actions frontend remains in this repository at v1.
8. The governance and profile-acceptance process for the public project.

Each decision requires alternatives, compatibility impact, migration behavior,
and adversarial tests. This document sets their direction but does not replace
those ADRs.

## 25. Final v1 claim

When the declaration gates are complete, Runtrue v1 should be able to make this
claim precisely:

> Runtrue v1 is an open-source execution control plane for bounded stateless and
> stateful workloads. It admits immutable Programs under exact runtime and
> authority Capsules, authorizes exact subjects through Seals, runs them through
> conforming local or remote Providers, and produces portable Evidence of their
> effects and cleanup. GitHub Actions is the first supported workflow frontend;
> it uses the same public execution contract available to other clients.

That claim is intentionally narrower than “runs every application” and
intentionally broader than “GitHub Actions replacement.” It defines a durable
platform destination while allowing implementation and ecosystem breadth to
grow in reviewed, conforming profiles.
