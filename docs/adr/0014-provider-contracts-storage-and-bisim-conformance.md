# ADR 0014: Provider contracts, storage, and Bisim conformance

- **Status:** Accepted
- **Date:** 2026-07-15
- **Compatibility scope:** target architecture for unreleased v0.x
- **Detailed decision under:** ADR 0007

## Context

Runtrue must behave consistently on a developer machine, a self-hosted runner,
a private cluster, and a managed service without forcing every Provider to use
the same process topology or storage product. A managed-only semantic path
would make local reproduction unreliable, while requiring a local Provider to
implement autoscaling or remote object storage would confuse portability with
deployment architecture.

The Provider boundary therefore needs a versioned portable contract, explicit
feature profiles, integrity-preserving storage interfaces, and a conformance
suite that compares meaningful observable behavior without claiming identical
security internals.

## Decision

### 1. Provider boundary

A **Provider** implements the Runtrue execution contract for one administrative
and trust domain. The contract covers:

- Capsule, Seal, Program, and policy admission;
- exact runtime inventory and capacity leasing;
- Execution and Session lifecycle operations;
- event streaming, cancellation, fencing, and recovery;
- capability brokerage and external-effect journaling;
- Artifact, Checkpoint, Evidence, and Replay Bundle storage;
- terminal cleanup and integrity reporting; and
- portable failure classification.

Local, self-hosted, private-cluster, and managed implementations use the same
typed Rust facade and versioned protocol model. A local Provider may call the
facade in process and use local storage. It does not bypass canonical identity,
policy, lifecycle, Evidence, or cleanup rules.

Provider-specific control APIs for installation, billing, autoscaling, host
maintenance, or regional operations remain outside the portable execution
contract and cannot grant workload authority.

### 2. Contract and feature profiles

The protocol negotiates one exact compatible contract generation. Within it, a
Provider advertises versioned feature profiles such as:

- stateless Executions;
- Sessions and concurrent child Executions;
- Checkpoint suspend and restore;
- specific runtime compatibility identities;
- capability and external-effect classes;
- warm-pool acquisition;
- Replay Bundle grades; and
- Evidence and attestation grades.

Features are explicit positive claims with limits and compatibility metadata.
Absence means unsupported, not best effort. A Capsule requiring an unavailable
profile fails admission before placement. Feature negotiation never removes a
Capsule requirement or selects an older protocol generation after a newer
mutual generation was authenticated.

### 3. Inventory and scheduling interface

Providers publish authenticated immutable runtime inventory separately from
mutable capacity observations. Inventory names the exact ADR 0010 compatibility
digest, security and revocation generation, Provider and pool trust domain,
placement attributes, devices, and supported limits.

Capacity observations are bounded, expiring hints reconciled against durable
leases and fences. They are not proof of runtime identity. The central or local
scheduler chooses only an exact compatible inventory entry within the Capsule's
allowed placement set.

A runner proves its inventory during enrollment and preflight. Losing a
required runtime, key, patch, storage, network, or cleanup boundary withdraws
the entry immediately. An unauthenticated self-report cannot advertise a new
security property.

### 4. Logical content-addressed storage

Core code depends on typed logical stores, not S3, a cloud SDK, or a host path.
Separate interfaces cover immutable objects, canonical manifests, tenant-
scoped encrypted objects, append-only Evidence, leases, and atomic publication.

Local filesystem, S3-compatible services, and managed storage may implement
those interfaces if they provide:

- digest and size verification before publication and after every read;
- create-once or compare-and-swap publication with exact idempotent replay;
- tenant and trust-domain authorization independent of object names;
- authenticated encryption where the object contract requires it;
- bounded reads, listings, retries, and recovery;
- no-follow and safe materialization semantics for filesystem targets;
- durable tombstones that distinguish expiry from corruption; and
- auditability of promotion, retention, deletion, and restore.

A content digest is integrity metadata, not access authority. Cross-tenant
deduplication is forbidden for secrets, Checkpoints, private Programs, or any
object whose equality leaks protected information. Public immutable objects
may share physical bytes only when policy explicitly admits that trust domain.

Storage credentials stay in the Provider or broker and never enter a guest.

### 5. Bisim conformance

**Bisim** compares the portable execution semantics of two Providers using the
same canonical Capsule and controlled inputs. It covers at least:

- admission and exact identity checks;
- lifecycle and terminal transitions;
- normalized stdout, stderr, structured output, and Artifacts;
- capability call and external-effect state transitions;
- cancellation, deadlines, resource exhaustion, and retries;
- Session child ordering, fencing, and Checkpoint behavior;
- Replay grade and portable Evidence fields;
- cleanup result and portable failure classification; and
- rejection of unsupported features and prohibited fallback.

Bisim normalizes only fields declared operational, such as timestamps within
documented bounds, worker IDs, cold-versus-warm acquisition, and Provider-
specific diagnostics. It never normalizes a Program result, capability decision,
effect state, runtime compatibility identity, security failure, or missing
Evidence into equivalence.

Bisim does not prove that two isolation mechanisms have equal security. Each
runtime family and Provider also passes its own adversarial suite for escape,
residual state, network enforcement, broker isolation, storage boundaries,
cleanup, and control-plane compromise assumptions.

### 6. Conformance publication

Every advertised contract and feature profile has:

- canonical positive and negative test vectors;
- a pinned Bisim suite generation and fixture digest;
- Provider and runtime-specific security suite results;
- unsupported and skipped case disclosure;
- the exact binary, configuration, policy, image, and key identities tested;
  and
- signed, expiring conformance Evidence.

A Provider advertises only profiles passed by the deployed generation. Passing
a newer or broader build does not authorize an older deployment. A required
test that is skipped, flaky, or indeterminate is not a pass.

### 7. Managed and local parity

Managed Providers may add scale, placement, durable availability, administration,
and operational support. They do not create a managed-only Capsule field,
capability meaning, failure status, or Seal bypass. Local Providers may have
lower capacity or fewer feature profiles, but any feature they advertise has
the same portable semantics.

Integrations use the public operations in ADR 0008 and translate their domain
objects outside the Provider. No integration receives an in-process control-
plane plugin path or implicit Provider credential.

## Consequences

- Runtrue can support different deployment architectures without semantic
  forks.
- Providers must make unsupported features explicit instead of approximating
  them.
- Storage adapters and inventory attestation become security-critical
  interfaces with adversarial tests.
- Bisim gives strong behavioral evidence but deliberately does not replace
  backend isolation review.
- Managed differentiation occurs in operations and scale, not hidden workload
  authority.

## Review triggers

- A required Provider cannot implement an atomic logical-store operation.
- Bisim normalization hides a user-visible or security-relevant difference.
- A managed feature cannot be represented in the portable contract.
- Cross-tenant physical deduplication is proposed for protected data.
- A new protocol generation needs cross-language conformance.
- Provider security Evidence cannot be bound to the deployed generation.
