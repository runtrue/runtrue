# ADR 0005: Runtrue public identity and product vocabulary

- **Status:** Accepted
- **Date:** 2026-07-15

## Context

The working name no longer describes the public product, and several important
security and reproducibility concepts need names that remain precise across the
CLI, API, documentation, and implementation. This decision is being made before
the first public release, so the repository does not carry a user-facing legacy
namespace or compatibility layer.

## Decision

The public project is **Runtrue**, with the tagline:

> **Run local. Run remote. Run true.**

The canonical product vocabulary is:

- **Capsule:** the immutable execution plan, including the digest-bound inputs
  and policy context required to execute it.
- **Seal:** approval authorizing one exact approval subject for a Capsule. A
  Seal is invalid when any bound input changes.
- **Bisim:** the shared-engine conformance suite that verifies equivalent
  behavior across local and remote execution providers.
- **Replay Bundle:** the portable, secret-free material required to reproduce
  an execution locally.

Use `Runtrue` for the product, organization, and prose; use `runtrue` for the
CLI, packages, repositories, images, and filesystem paths; and use `RUNTRUE_`
for environment variables.

The public Rust packages are `runtrue` for the stable library facade and
`runtrue-cli` for the package that provides the `runtrue` binary. Published
JavaScript packages use the `@runtrue` scope. Published OCI images use a
Runtrue-owned namespace.

Product terms are proper nouns when referring to the defined artifacts. In
implementation code, use `CapsuleSeal` for the approval value and
`ApprovalSubject` for its exact bound subject when the shorter words would be
ambiguous.

The rename is a clean break. Public documentation and examples must not teach
old command names, environment variables, configuration paths, or package
names. Cryptographic domain separators and persisted protocol identifiers are
changed only through their own explicitly versioned design decisions.

## Consequences

- CLI help, documentation, releases, packages, images, services, and the web UI
  share one public identity.
- The Capsule, approval-subject, and Seal distinction makes exact approval
  explicit.
- Bisim cannot be used as a synonym for digest comparison; it must exercise
  observable engine behavior.
- Replay Bundle retains its reproducibility and secret-exclusion contract.
- A release check must reject unintended user-facing references to superseded
  names.

## Reservation requirements

Before public announcement, verify and reserve the GitHub organization, primary
developer domains, `runtrue` and `runtrue-cli` Rust crates, OCI namespace,
`@runtrue` npm scope, and planned package-manager names. Track ownership and
verification in the [public namespace reservation runbook](../operations/public-namespace-reservations.md).
