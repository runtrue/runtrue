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
identity, limits, output contract, failure semantics, or observable result.

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

### 3. One-shot tenant lease rule

The invariant is absolute:

> A runtime instance that has executed tenant code must never return to a
> sterile warm pool.

Assignment atomically binds one unused instance to one tenant, Capsule,
Execution or Session, lease, and fence. After assignment it is tenant-used even
if guest initialization fails or no user instruction is observed. It can only
be destroyed, not reclassified as sterile.

Cleaning, scanning, rollback, filesystem deletion, memory zeroing, or a new
tenant namespace does not make a used instance eligible for the sterile pool.
Destruction and replenishment from the original template are required.

### 4. Firecracker microVM pools

MicroVM warming follows this sequence:

1. Build, scan, sign, and admit a sterile snapshot.
2. Bind it to the exact runtime compatibility tuple.
3. Restore unused prebooted VM instances into a fenced pool.
4. Lease one VM to exactly one Execution or Session.
5. Attach a new tenant-encrypted copy-on-write workspace and fresh network
   namespace.
6. Issue fresh capabilities only after lease and fence verification.
7. Execute and capture outputs, effects, resource use, and cleanup Evidence.
8. Revoke brokers, detach tenant storage, stop and destroy the used VM.
9. Verify destruction and replenish only from the sterile snapshot.

Snapshot memory and devices must not contain builder credentials or live
control-plane sessions. Randomness, VM identity, network identity, lease, fence,
and guest session keys are injected fresh after restore through authenticated
bootstrapping.

### 5. Wasm warming

A Wasm Provider may reuse:

- a Wasmtime Engine for one exact engine configuration and trust domain;
- authenticated AOT-compiled component code keyed by the complete runtime and
  Program compatibility identity; and
- allocation infrastructure only where Wasmtime documents safe reset and
  Runtrue's adversarial suite proves isolation.

Every invocation creates a fresh Store, WASI context, resource table, limiter,
fuel and epoch state, host capability state, handles, output buffers, and
cancellation scope. Guest linear memory, tables, globals, resources, futures,
streams, and host objects are never reused between invocations.

An AOT cache hit is code reuse, not a reused tenant runtime instance.

### 6. OCI warming

An OCI Provider may cache authenticated image layers, manifests, signatures,
seccomp data, and preparation metadata. It creates a new container, writable
layer, namespaces, cgroup, secret delivery scope, network boundary, and process
tree for every Execution.

A used container is destroyed and never returned to a general pool. Hostile or
multi-tenant OCI Programs execute inside a one-shot leased microVM when their
Capsule selects that explicit profile; the scheduler cannot add or remove that
boundary implicitly.

### 7. Sessions and Checkpoints

A Session keeps its one-shot leased microVM or other Session runtime while
active, including across client disconnects, until expiry, suspension, or
destruction. It is never shared with another Session.

Suspension creates an ADR 0012 Checkpoint, destroys the prior instance, and
leaves no live pool member. Resume leases a new compatible instance and restores
tenant state into it. A Session-derived Checkpoint can never be published as a
sterile template or used across tenants.

### 8. Pool control and failure behavior

The control plane manages desired capacity, minimum and maximum size,
placement, replenishment, draining, expiry, revocation, and autoscaling. Pool
identity and mutable capacity are not Capsule fields. Stronger administrative
or tenant boundaries may require physically or cryptographically separate
pools even when their runtime tuples match.

Every pool transition is fenced and bounded. A stale manager cannot assign,
return, or publish an instance. A runner crash, lost destruction response,
unexpected residual resource, or inability to prove cleanup produces `runner
integrity failure`, quarantines the affected runner or pool generation, and
prevents new leases until reconciliation proves safety.

### 9. Evidence

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
