# ADR 0002: Policy-selected execution isolation

- **Status:** Accepted
- **Date:** 2026-07-15

## Context

Runtrue executes hostile pull-request code, ordinary trusted builds,
capability-scoped components, and specialist native workloads. No single
runtime provides the required combination of compatibility, containment, and
performance.

Backend selection is a security decision. Availability or scheduling pressure
must never cause a job to run with weaker isolation than the Capsule and policy
permit.

## Decision

Support four policy-selected backend classes:

1. Wasmtime Components for compact, capability-scoped workloads.
2. Rootless OCI for trusted Linux container workloads.
3. Firecracker microVMs as the default isolation floor for untrusted or
   multi-tenant Linux workloads.
4. Native host execution only when explicitly requested and admitted on a
   dedicated trusted worker or acknowledged trusted local machine.

The Capsule declares execution requirements. Policy establishes the minimum
isolation and capabilities. Scheduling may select an equivalent or stronger
admitted backend, but never a weaker backend. An unavailable or incompatible
backend fails closed; it never falls back to native execution.

Every backend must implement the shared lifecycle contract and pass Bisim plus
backend-specific security tests before it is advertised as supported.

## Consequences

- Public fork safety does not depend on a shared workload host kernel.
- OCI remains available for workloads whose policy admits shared-kernel
  isolation.
- Wasm components receive only explicit host capabilities.
- Firecracker image, snapshot, guest-protocol, and host-patching operations are
  security-critical responsibilities.
- Native execution remains a deliberate trust boundary, not a sandbox.
- Windows, macOS, accelerators, and specialist devices require explicit future
  backend profiles rather than implicit weakening.

## Review triggers

- A new backend passes Bisim and the applicable adversarial security suite.
- Firecracker cannot satisfy a supported platform or hardware requirement.
- Kernel, container-runtime, hypervisor, or Wasmtime changes materially alter
  the threat model.
- Measurements show that the selected isolation floor cannot meet an accepted
  service objective.
