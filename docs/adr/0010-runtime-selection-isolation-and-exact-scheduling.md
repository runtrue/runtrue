# ADR 0010: Runtime selection, isolation, and exact scheduling

- **Status:** Accepted
- **Date:** 2026-07-15
- **Compatibility scope:** target architecture for unreleased v0.x
- **Supersedes:** ADR 0002
- **Detailed decision under:** ADR 0007

## Context

ADR 0002 allowed a scheduler to substitute an equivalent or stronger admitted
backend. That rule is unsafe once runtime behavior, kernel surface, device
model, capability mediation, and reproducibility are part of the approved
Capsule. A microVM is not semantically interchangeable with Wasm, and a
container inside a microVM is not the same Program contract as a container on a
shared host kernel.

Availability must not change the authorized execution boundary.

## Decision

### 1. Explicit runtime profiles

The Capsule selects one exact versioned runtime profile. Supported profile
families are:

- Wasmtime Components for compact capability-oriented Programs;
- Firecracker microVMs for arbitrary untrusted code and multi-tenant Linux;
- rootless OCI for explicitly trusted shared-kernel workloads;
- OCI inside a microVM when container compatibility and a tenant kernel
  boundary are both required; and
- native execution only on an explicitly trusted local machine or dedicated
  trusted worker.

Policy may reject a requested profile or require the planner to produce a new
Capsule using another profile. The scheduler never rewrites an admitted
Capsule, falls back, or substitutes a supposedly stronger profile.

### 2. Runtime compatibility identity

A runtime profile binds at least:

- isolation family and implementation generation;
- operating system, architecture, and CPU feature floor;
- engine, VMM, container runtime, kernel, rootfs, guest, and relevant library
  versions or digests;
- Program ABI, WIT world, syscall or device contract;
- memory, task, process, filesystem, network, and device model;
- compiler, AOT, snapshot-compatibility, and mitigation settings;
- capability-adapter and guest-protocol generations; and
- security patch and revocation generation.

Fields not applicable to a family are absent by schema, not populated with
wildcards. The canonical tuple has a qualified digest used by Capsules,
inventory, scheduling, snapshots, caches, Evidence, and attestations.

An implementation patch may preserve portable behavior, but it is still a new
runtime identity unless the compatibility schema explicitly defines the field
as non-semantic. Cached code or snapshots never cross incompatible identities.

Snapshot compatibility binds the format, restore ABI, guest-visible initial
state contract, and security-relevant restore settings. It does not bind a
concrete sterile-template digest or pool member. Those are operational
acquisition identities recorded under ADR 0013. Cold construction and warm
restore may satisfy the same runtime profile only when they produce the same
declared guest-visible initial state and security boundary.

### 3. Policy floors are planning constraints

Policy expresses permitted profile sets and minimum security properties before
the final Capsule is sealed. For example, untrusted multi-tenant Linux requires
a microVM-family profile; trusted OCI may permit a shared kernel; native
requires explicit trusted-host acknowledgement.

Once the planner selects an exact member and the Capsule is sealed, the policy
floor no longer authorizes scheduler substitution. A change requires a new
Capsule and, where its approval subject changes, a new Seal.

### 4. Exact scheduling

Providers advertise immutable compatibility identities separately from
mutable capacity and placement. Scheduling matches the Capsule against:

- exact runtime compatibility digest;
- permitted Provider identities and immutable pool trust profiles;
- tenant and administrative trust domain;
- allowed region, locality, and data-residency set;
- required devices and resource quantities; and
- current non-revoked runner posture.

The scheduler may choose any concrete worker, pool, sterile prepared instance,
or availability zone whose authenticated attributes fall within those sealed
sets. A Capsule may constrain a stable pool trust profile or administrative
trust domain, but never names a mutable concrete pool or member as workload
semantics. Concrete pool and member identities are placement Evidence. The
scheduler may choose cold or warm acquisition because that is operational
Evidence, not functional semantics. It may not change runtime, isolation,
Program, capabilities, limits, or placement constraints.

Capacity reservations are leased and fenced. A stale offer or runner cannot
claim work after a newer scheduling generation. Inventory identity is
authenticated; self-reported capacity is bounded by server policy and active
lease accounting.

### 5. Failure behavior

No exact compatible capacity produces `capacity unavailable`, possibly after a
bounded queue deadline declared by the Capsule. It does not produce Program
failure and never triggers an isolation downgrade.

An inventory or runtime identity mismatch is `admission rejected` before guest
code runs. A runner that advertises an identity it cannot prove, or that loses
the required boundary during execution, reports `runner integrity failure` and
is quarantined from new work.

Retries preserve the exact profile and placement constraints unless a newly
authorized Capsule changes them.

### 6. Backend requirements

Every advertised profile implements the shared lifecycle, cancellation,
resource, Evidence, cleanup, and effect contracts. It passes Bisim for portable
semantics and a family-specific adversarial suite for its security boundary.

Windows, macOS, accelerators, confidential-computing hardware, and new VMMs are
new explicit profiles. Their absence never weakens an existing one.

## Consequences

- Availability pressure cannot silently change the approved trust boundary.
- Planning may offer alternatives, but authorization always sees the selected
  exact runtime.
- Inventory and compatibility tuple construction are security-critical.
- Runtime upgrades deliberately invalidate incompatible AOT and snapshot
  state.
- More executions may fail with capacity unavailable instead of using a
  convenient fallback; that is the intended fail-closed behavior.

## Review triggers

- A compatibility field causes excessive safe cache invalidation.
- A Provider cannot attest its advertised runtime identity.
- A new backend or hardware class passes the required conformance suites.
- Product requirements demand an explicitly authorized set of interchangeable
  runtime identities.
- Exact scheduling cannot meet an accepted availability objective.
