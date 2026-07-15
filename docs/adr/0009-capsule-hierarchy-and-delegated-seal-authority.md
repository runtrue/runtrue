# ADR 0009: Capsule hierarchy and delegated Seal authority

- **Status:** Accepted
- **Date:** 2026-07-15
- **Compatibility scope:** target architecture for unreleased v0.x
- **Detailed decision under:** ADR 0007

## Context

Interactive Programs and agents choose commands after a Session begins. Sealing
every command manually is unusable, but allowing a Program to expand its own
authority would make the sandbox the authorization root. Runtrue needs bounded
delegation in which dynamically proposed child Capsules become immutable and
attributable before authorization.

The exact Capsule, the approval subject, the authority of the issuer, and the
proof that a child fits its parent are distinct security objects.

## Decision

### 1. Capsule hierarchy

Use two explicit Capsule kinds:

- a **Session Capsule** defines the maximum runtime, resource, capability,
  placement, duration, concurrency, external-effect, and output envelope; and
- an **Execution Capsule** defines one exact Program attempt, either stateless
  or as a child of a Session Capsule.

A child Execution Capsule binds the parent Capsule digest, parent Seal identity,
delegation identity, Program, arguments, working directory, workspace or
Checkpoint generation, runtime profile, limits, capabilities, external-effect
declarations, output contract, and Evidence contract.

Capsule inheritance is never implicit. A missing child field does not inherit
ambient parent authority; canonical construction materializes the effective
value before identity and containment are computed.

### 2. Who may Seal

An untrusted Program may propose a Capsule but may not Seal its own authority,
act as the policy decision point for itself, or choose the identity used to
approve it.

A Seal may be issued only by:

- an authenticated human with the required tenant role;
- an activated policy service whose policy version is part of the approval
  subject; or
- a delegated trusted planner operating under an already valid parent Seal.

Authentication alone is insufficient. The issuer must be authorized for the
exact approval subject, Capsule kind, tenant, capability classes, effect
classes, limits, and time window. Separation-of-duty and quorum policy apply
before issuance.

### 3. Delegation grants

Delegation is an explicit object bound into the parent approval subject. It
names:

- the planner principal and implementation identity;
- the parent Capsule and Seal;
- allowed child Program kinds and resolvers;
- maximum resource and concurrency limits;
- allowed capabilities, destinations, and effect classes;
- permitted child lifetime and count;
- whether subdelegation is forbidden; and
- expiry, revocation generation, and policy version.

Delegation defaults to non-transitive. Subdelegation requires a separate
explicit grant and can never extend the original envelope or expiry.

The planner emits a child proposal and deterministic containment proof. The
trusted Runtrue verifier, not the planner, recomputes and validates that proof
against canonical typed Capsules before issuing or recording the child Seal.

### 4. Containment rules

Containment is field-specific; it is not generic JSON subset comparison.

- Runtime and isolation identities must be equal unless the parent enumerates
  a finite allowed set and the child selects exactly one member.
- Numeric resources, durations, counts, and byte limits must be positive and
  no greater than the parent maximum.
- Placement, Provider, and region choices must be members of the parent's
  allowed sets.
- Filesystem scopes must be equal or a normalized descendant with no stronger
  access mode.
- Network grants must narrow destination, protocol, port, DNS, request, and
  byte constraints.
- Secret and identity grants must preserve exact name, purpose, audience,
  issuer, and maximum lifetime.
- External effects and output channels must be members of the admitted parent
  classes with equal or narrower operation constraints.
- Denied, unknown, dynamic, or incomparable fields fail containment.

Aggregate Session limits are checked in addition to per-child containment. A
valid child cannot run when doing so would exceed the already reserved parent
budget.

Any compatibility-generation change requires a new containment implementation
and conformance vectors. Unknown fields never compare as harmless.

### 5. Approval boundaries and revocation

Policy may require a separate effect Seal for high-impact operations such as
deployment, signing, payment, production mutation, or identity issuance. A
Session computation Seal does not imply that effect authorization.

Seal and delegation revocation prevents new admission and new capability
issuance at or after the durable revocation generation. It does not rewrite
completed Evidence. Active work observes revocation according to the declared
capability contract; emergency revocation stops new effects immediately and
requests cancellation when policy requires it.

A child is admitted only after the verifier rechecks parent Seal validity,
delegation, containment, policy generation, Session fence, and remaining
budget in one durable decision. A stale proof cannot win a time-of-check versus
time-of-use race.

### 6. Evidence

Evidence records proposal identity, planner identity, canonical proof digest,
parent and child Capsule digests, approval subject, Seal issuer and method,
policy versions, reservation decision, and any revocation observed. Sensitive
policy inputs may be retained by digest, but their identity cannot be omitted.

## Consequences

- Agents can plan dynamically without becoming their own authority source.
- Containment verification becomes security-critical typed code with published
  positive and negative vectors.
- High-impact effects can retain a just-in-time approval boundary.
- Revocation and concurrent resource reservation require a durable atomic
  admission path.
- New Capsule fields are incompatible until their containment semantics are
  defined explicitly.

## Review triggers

- A useful capability cannot be compared conservatively.
- Delegated child volume makes per-child immutable identity impractical.
- A revocation incident exposes a stale-admission window.
- A supported policy requires controlled transitive delegation.
- Runtrue adopts a stable cross-language Capsule and proof encoding.
