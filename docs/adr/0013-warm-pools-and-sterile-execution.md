# ADR 0013: Warm pools and sterile execution

- **Status:** Accepted
- **Date:** 2026-07-15
- **Compatibility scope:** target architecture for unreleased v0.x
- **Detailed decision under:** ADR 0007

## Context

Cold runtime construction can dominate short Execution latency. Managed
Providers therefore need compiled-code caches, prepared images, prebooted VMs,
and capacity pools. If a workload can request warming as part of its semantics,
or if a used environment can return to a general pool, the optimization changes
the security contract and creates cross-tenant residual-state risk.

Runtrue needs one portable sterility and lifecycle contract while allowing each
runtime family to warm only the state it can reuse safely.

## Decision

### 1. Warmth is operational, not semantic

A Capsule says:

> Run this exact Program under this runtime identity with these resources and
> capabilities.

It does not request a warm worker. A Provider may satisfy the exact Capsule by
starting cold or leasing compatible sterile prepared capacity. The choice may
affect latency and Evidence, but not Program inputs, authority, runtime
identity, limits, output contract, or failure semantics. A deterministic input
profile must produce equivalent observable results on both paths. When a
Capsule explicitly admits live time, randomness, or another nondeterministic
input, only values delivered through that declared profile may differ; warm or
cold acquisition cannot introduce another difference.

If warm capacity is absent, the Provider may construct the same runtime cold.
It may not choose another runtime or weaken isolation. If neither path can
satisfy the exact profile before the queue deadline, the result is `capacity
unavailable`.

### 2. Sterile template publication

A **sterile template** is created before tenant code, tenant data, credentials,
or capability handles enter the environment. Publication requires:

- an immutable builder definition and trusted builder identity;
- exact kernel, rootfs, guest, runtime, libraries, tools, CPU, memory, device,
  network, mitigation, and protocol compatibility metadata;
- a content digest, signature, provenance, SBOM, vulnerability and policy
  Evidence, creation time, expiry, and revocation generation;
- a scan proving that no tenant state, credential, host identity, lease, fence,
  or active external connection is present; and
- cold boot plus restore probes under the exact advertised tuple.

The canonical template identity is part of runner inventory and warm-acquisition
Evidence. Any bound field change, security revocation, failed integrity check,
or expiry removes the template and every derived unused instance from service.

The runtime compatibility profile binds snapshot format, restore ABI,
guest-visible initial-state semantics, and security settings. The concrete
template digest is a separately authenticated operational identity. Multiple
templates may satisfy one profile only when cold boot and every admitted
template produce the same declared boundary and observable initial state.

### 3. One-shot tenant lease rule

The invariant is absolute:

> A runtime instance that has executed tenant code must never return to a
> sterile warm pool.

Assignment atomically binds one unused instance to one tenant, Capsule,
Execution or Session, lease, and fence. Once assignment begins it is treated as
tenant-used for reuse eligibility even if guest initialization fails or no user
instruction is observed. It can only be destroyed, not reclassified as sterile.

Cleaning, scanning, rollback, filesystem deletion, memory zeroing, or a new
tenant namespace does not make a used instance eligible for the sterile pool.
Destruction and replenishment from the original template are required.

### 4. Durable pool-member lifecycle

The Provider's authenticated pool manager owns a durable compare-and-swap state
machine for every prepared instance:

```text
creating -> sterile -> assigning -> tenant-used -> destroying -> destroyed
creating|sterile|assigning|tenant-used -> quarantined -> destroying
```

Entering `assigning` atomically removes the member from sterile inventory and
binds the template and membership generations, tenant, Capsule, Execution or
Session, lease, and fence. From that point, a crash, timeout, ambiguous commit,
failed initialization, or failed handoff can lead only to quarantine and
destruction. Reconciliation never moves `assigning`, `tenant-used`, or
`quarantined` back to `sterile`.

The assignment transaction has one durable owner and idempotency identity. A
stale pool manager, runner, or replenisher cannot publish a competing state.
Destruction is complete only after the Provider proves the runtime is stopped,
tenant storage and networks are detached, broker authority is revoked, and the
member cannot be addressed by a live lease.

### 5. Pre-lease authority and handoff

An unused restored microVM is paused at a minimal authenticated bootstrap point.
It has no tenant code or data, reusable credential, general network or DNS,
tenant storage, control-plane API, metadata service, capability broker, or pool
management authority. Its only channel is a bounded single-use handoff path to
the Provider manager.

After the durable `assigning` transition, the manager injects fresh entropy,
instance and network identity, boot keys, tenant, runtime identity, lease, and
fence through that path. Before any tenant payload or general capability is
enabled, the guest reseeds itself, rotates derived identities, verifies the
handoff, and returns authenticated attestation bound to the exact assignment.
A cloned random state or identity is never allowed to reach guest execution.
Failure at any point quarantines and destroys the instance.

### 6. Firecracker microVM pools

MicroVM warming follows this sequence:

1. Build, scan, sign, and admit a sterile snapshot.
2. Bind it to the exact runtime compatibility tuple.
3. Restore paused, zero-authority VM instances into a fenced pool.
4. Atomically assign one VM to exactly one Execution or Session.
5. Complete the authenticated fresh-identity and lease handoff.
6. Attach a new tenant-encrypted copy-on-write workspace and fresh network
   namespace.
7. Issue fresh capabilities only after lease, fence, and attestation
   verification.
8. Execute and capture outputs, effects, resource use, and cleanup Evidence.
9. Revoke brokers, detach tenant storage, stop and destroy the used VM.
10. Verify destruction and replenish only from the sterile snapshot.

Snapshot memory and devices must not contain builder credentials or live
control-plane sessions. Randomness, VM identity, network identity, lease, fence,
and guest session keys are injected fresh through the post-assignment handoff,
not retained in the sterile snapshot.

### 7. Wasm warming

A Wasm Provider may reuse:

- a Wasmtime Engine for one exact engine configuration and trust domain;
- authenticated AOT-compiled component code keyed by the complete runtime and
  Program compatibility identity; and
- allocation infrastructure only where Wasmtime documents safe reset and
  Runtrue's adversarial suite proves isolation.

The reusable Engine may retain only configuration and non-tenant compiler
infrastructure. Tenant-derived telemetry, profiles, resources, identifiers, and
mutable host adapter state are reset or partitioned. AOT artifacts for private
Programs are tenant- and encryption-domain scoped. Cross-tenant AOT reuse is
allowed only for explicitly public immutable Programs admitted to the same
shared trust domain.

Every invocation creates a fresh Store, WASI context, resource table, limiter,
fuel and epoch state, host capability state, handles, output buffers, and
cancellation scope. Guest linear memory, tables, globals, resources, futures,
streams, and host objects are never reused between invocations.

An AOT cache hit is admitted code reuse, not a reused tenant runtime instance.

### 8. OCI warming

An OCI Provider may cache authenticated image layers, manifests, signatures,
seccomp data, and preparation metadata. It creates a new container, writable
layer, namespaces, cgroup, secret delivery scope, network boundary, and process
tree for every Execution.

Private image layers and preparation metadata are tenant- and disclosure-domain
scoped. Cross-tenant physical reuse is allowed only for explicitly public,
immutable image content admitted to a shared trust domain; a digest alone never
authorizes or reveals a cache hit.

A used container is destroyed and never returned to a general pool. Hostile or
multi-tenant OCI Programs execute inside a one-shot leased microVM when their
Capsule selects that explicit profile; the scheduler cannot add or remove that
boundary implicitly.

### 9. Sessions and Checkpoints

A Session keeps its one-shot leased microVM or other Session runtime while
active, including across client disconnects, until expiry, suspension, or
destruction. It is never shared with another Session.

Suspension creates an ADR 0012 Checkpoint, destroys the prior instance, and
leaves no live pool member. Resume leases a new compatible instance and restores
tenant state into it. A Session-derived Checkpoint can never be published as a
sterile template or used across tenants.

### 10. Pool control and failure behavior

Each Provider's authenticated pool manager manages desired capacity, minimum
and maximum size, placement, replenishment, draining, expiry, revocation, and
autoscaling. The portable Runtrue contract defines its states, fencing,
sterility, handoff, destruction, and Evidence requirements; concrete scaling
and maintenance APIs remain Provider-specific.

A Capsule may bind an immutable pool trust profile or administrative trust
domain. Concrete pool identity, membership, and mutable capacity are placement
and Evidence fields, not workload semantics. Stronger administrative or tenant
boundaries may require physically or cryptographically separate pools even when
their runtime tuples match.

Every pool transition is fenced and bounded. A stale manager cannot assign,
return, or publish an instance. A runner crash, lost destruction response,
unexpected residual resource, or inability to prove cleanup produces `runner
integrity failure`, quarantines the affected runner or pool generation, and
prevents new leases until reconciliation proves safety.

### 11. Evidence

Evidence records cold or warm acquisition, Provider and pool identity, sterile
template digest, runtime compatibility digest, instance creation and assignment
generation, tenant lease and fence, workspace identity, revocation checks, and
destruction result. Warmth is excluded from functional output comparison but is
available for performance and security analysis.

## Consequences

- Providers can improve latency without making pooling part of workload
  semantics.
- MicroVM capacity is consumed one-shot and must be continuously replenished.
- Destroying used environments costs more than cleanup-and-reuse but gives a
  substantially clearer isolation proof.
- Wasm and OCI reuse immutable preparation state, not mutable guest state.
- Pool lifecycle, revocation, and destruction Evidence become core execution-
  plane responsibilities.

## Review triggers

- A runtime offers hardware-backed reset with a proof equivalent to destruction.
- Warm-pool cost cannot meet an accepted service objective.
- A residual-state or cross-tenant side-channel incident changes the sterility
  model.
- Wasmtime or a container runtime documents a new safely reusable state class.
- Session migration requires a live-instance handoff.
- The pre-lease bootstrap path needs broader network, storage, or broker access.
- A new cache class could reveal private Program equality across tenants.
