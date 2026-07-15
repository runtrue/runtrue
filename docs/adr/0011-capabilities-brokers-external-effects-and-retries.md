# ADR 0011: Capabilities, brokers, external effects, and retries

- **Status:** Accepted
- **Date:** 2026-07-15
- **Compatibility scope:** target architecture for unreleased v0.x
- **Detailed decision under:** ADR 0007

## Context

Arbitrary code inside an isolation boundary is useful only when it can interact
with selected files, services, credentials, and outputs. Passing ambient host
authority into the guest defeats the boundary, while logging an attempted
mutation does not make retries safe.

Runtrue needs a common capability model that separates access from authority,
prefers brokered operations over credential release, and makes indeterminate
external effects a portable terminal condition.

## Decision

### 1. Default-deny capability vocabulary

Every Program starts with an empty external authority set. A Capsule may request
typed, versioned capabilities for:

- filesystem and workspace scopes;
- immutable Program, Artifact, cache, and Checkpoint content;
- network destinations and protocols;
- secrets and short-lived identity;
- model inference and external services;
- devices and accelerators;
- output publication, signing, deployment, messaging, payment, database, or
  source-control mutation; and
- other explicitly versioned Provider-neutral resources.

Each capability names its resource, operations, constraints, lifetime, budget,
and revocation behavior. Unknown operations or constraints fail admission.
Possession of a content digest, resource name, Session ID, URL, or file path is
not authority.

### 2. Invocation handles

The guest receives invocation-local unforgeable handles rather than Provider
credentials or host paths. A handle is bound to tenant, Capsule, Execution,
lease, fence, capability type, exact grant, and expiry. It cannot be serialized
into a Checkpoint, Replay Bundle, cache entry, or later invocation.

Every host call revalidates the handle and current cancellation, deadline,
fence, revocation, request, response, concurrency, and byte budgets. Validation
at handle issuance alone is insufficient.

### 3. Credential brokers

Prefer a broker that performs the authorized operation using a credential the
guest never sees. The broker binds the destination, operation, request shape,
tenant, and Execution before applying authority.

When an incompatible tool requires guest-visible material, policy may issue a
short-lived derivative credential with the narrowest possible audience and
scope. Release is a separately evidenced high-risk capability. The material is
redacted, zeroized, excluded from structured output and persistent state, and
revoked at terminal cleanup. A long-lived provider or tenant root credential is
never placed in a guest.

### 4. Network authority

Network is denied by default. A grant expands to normalized destination names
or addresses, protocol, port, DNS behavior, connection direction, request and
response limits, and time bounds. DNS resolution is pinned for the authorized
operation and rejects private, metadata, control-plane, storage, and rebinding
addresses unless they are explicitly named by policy.

Profiles such as package registries are reviewed policy expansions into exact
constraints, not an `internet: true` escape hatch. Raw sockets, listening,
proxies, and tunnels require distinct capability classes.

### 5. External-effect protocol

Every non-read external mutation has a stable operation ID and idempotency key
bound to the Capsule and capability grant. The Provider records these states:

```text
requested -> rejected
requested -> accepted
requested -> indeterminate
```

`Accepted` means the authoritative destination acknowledged the operation
under its idempotency contract. It does not mean the desired business outcome
was later observed. `Indeterminate` means Runtrue cannot prove rejection or
safe acceptance, including a lost response after transmission.

Exactly-once execution is not claimed unless the destination protocol provides
an atomic idempotency or transaction contract that Runtrue verifies. Local
deduplication alone cannot prove exactly-once mutation of an external system.

Pending or indeterminate effects prevent creation of a resumable Checkpoint
until policy resolves them. Checkpointing never captures a live broker request
or revives it after restore.

### 6. Retry rules

Runtrue may automatically retry only when one of these is proven:

- no effect-capable call was accepted or left indeterminate;
- all attempted effects were read-only;
- every accepted call is safely replayable under a destination-enforced
  idempotency key; or
- a protocol-specific recovery operation established the exact final state.

Otherwise the Execution terminates with `external effect indeterminate` or its
other applicable terminal status and requires an explicit recovery decision.
A retry is a new Execution and Evidence lineage. A new idempotency key or
expanded authority requires a new Capsule.

### 7. Revocation and Evidence

Cancellation and terminal transition stop accepting new calls before output is
finalized. Capability brokers reject stale fences and revoked grants. Cleanup
records whether all handles, credentials, connections, and in-flight broker
operations were closed or whether integrity is unproven.

Evidence records capability identity and version, operation ID, bounded request
and destination metadata, state transitions, destination acknowledgement
identity, retries, revocation, and cleanup. Secret values, bearer credentials,
and prohibited payloads are never Evidence.

## Consequences

- Arbitrary computation does not imply ambient authority.
- Broker integrations and idempotency adapters become part of the trusted
  execution plane.
- Some failures cannot be retried automatically and require human or
  integration-specific reconciliation.
- Tool compatibility that requires raw credentials is explicit high-risk
  behavior rather than a hidden environment-variable fallback.
- Checkpoint creation must coordinate with the external-effect journal.

## Review triggers

- A destination cannot expose a safe idempotency or reconciliation contract.
- A supported tool cannot operate without long-lived guest credentials.
- A network or credential incident reveals missing per-call validation.
- Capability vocabulary becomes Provider-specific or unbounded.
- Checkpoint quiescence cannot prove that broker activity has stopped.
