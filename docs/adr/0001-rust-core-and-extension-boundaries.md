# ADR 0001: Rust core and extension boundaries

- **Status:** Accepted
- **Date:** 2026-07-15

## Context

Runtrue needs a shared compiler and execution engine across its CLI, control
plane, runner, guest, and isolated executors. It also needs independently
versioned automation products and integrations without turning the core
repository or server process into a plugin host.

Repository ownership and process isolation are separate boundaries. Sharing a
Rust workspace is appropriate for code that must evolve with the core protocol,
while an independently released product should not remain in the core merely
because it executes on a Runtrue worker.

## Decision

Use Rust as the primary implementation language for the Runtrue core. Keep the
compiler, shared engine, protocol, control plane, runner, guest, CLI, and core
executors in the `runtrue/runtrue` Cargo workspace with explicit crate
dependency rules. Ship the control plane as an unprivileged process and the
runner, guest, CLI, image builder, and other host agents as separate binaries.

Place independently versioned automation products and integrations, including
Backport, in separate repositories with their own release lifecycle. The core
may provide provider-neutral protocols, capability types, importers, and worker
primitives, but it must not contain product-specific review, backport, or other
automation behavior.

The control plane must never load or execute repository code, actions, shell
commands, user policy executables, or third-party native plugins. Extensions
execute only as digest-pinned Capsule workloads on workers under the selected
isolation and capability policy. They communicate with core services through
versioned, authenticated protocols rather than in-process extension APIs.

## Consequences

- Local and remote execution share the exact compiler and engine crates.
- Core protocol changes can be reviewed atomically across first-party binaries.
- Independent products can release without changing the core repository.
- Product-specific behavior cannot silently become part of the control-plane
  trust boundary.
- Cross-repository compatibility requires explicit protocol versions and
  conformance tests.

## Review triggers

- A core component requires independent security isolation or scaling based on
  measured behavior.
- A protocol boundary causes unacceptable correctness or operability costs.
- An extension cannot run safely through the worker capability model.
- Workspace build time or binary size violates the supported release budgets.
