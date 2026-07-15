# ADR 0015: Evidence, failures, attestations, and retention

- **Status:** Accepted
- **Date:** 2026-07-15
- **Compatibility scope:** target architecture for unreleased v0.x
- **Detailed decision under:** ADR 0007

## Context

Runtrue must explain what it admitted, ran, allowed, affected, produced, and
cleaned up without turning Provider logs into the portable contract. Evidence
also has to survive retries, runner loss, payload expiry, and differences
between local and managed Providers.

A single success boolean cannot represent an admission rejection, Program
exit, lost external-effect response, or failed sandbox destruction. Conversely,
retaining every input and output forever would expose sensitive tenant data and
make the audit system itself a liability.

Runtrue therefore needs a stable Evidence envelope, portable failure classes,
signed attestations, and retention rules that preserve verifiability while
allowing sensitive payloads to expire.

## Decision

### 1. Evidence envelope

Every durable Evidence event uses a versioned canonical envelope containing at
least:

- a closed, versioned scope kind and primary subject identity;
- tenant and administrative trust domain where applicable;
- applicable Provider, Program, Capsule, Seal, Execution, Session, sterile
  template, pool, runtime, and conformance-profile identities;
- the deployed Provider generation where applicable;
- a subject-local sequence number and previous-event digest;
- event type, schema generation, canonical payload digest, and event digest;
- the authenticated producer identity and signing-key generation;
- observed wall and monotonic times with their declared precision; and
- links to related parent Executions, retries, Checkpoints, Artifacts, external
  operations, and Replay Bundles when applicable.

Fields defined by the negotiated schema retain a canonical position and type
when they are not applicable; they are represented as absent values rather
than removed or repurposed by a Provider.

Sequence and digest linkage establish ordering. Timestamps are observations and
never resolve a race or replace a durable sequence. Provider-specific fields
are confined to a namespaced diagnostics payload and cannot change portable
event meaning or terminal classification.

Secrets, bearer credentials, prohibited content, and unrestricted request or
response bodies are not Evidence. Sensitive identifiers and low-entropy values
use a tenant- or trust-domain-scoped keyed digest or are omitted; an ordinary
hash is not sufficient protection against guessing.

### 2. Required coverage

Execution and Session Evidence profiles record, within declared bounds:

- admission inputs, canonical identities, policy and Seal decisions, and
  rejected requirements;
- scheduling, exact runtime identity, Provider generation, lease, fence,
  placement, and cold-or-warm acquisition;
- lifecycle transitions, parent and retry lineage, deadlines, cancellation,
  and Session child relationships;
- bounded stdout and stderr with truncation markers, structured output,
  Artifact and filesystem-change manifests, and resource use;
- capability decisions and calls, bounded network metadata, external effects,
  and credential-release events;
- Checkpoint, restore, Replay Bundle, and storage-publication results; and
- revocation, runtime disposal, cleanup, terminal classification, and
  attestation publication.

Provider infrastructure profiles separately record sterile-template
publication and revocation, pool-member transitions and reconciliation,
inventory and deployed generations, and Bisim and backend-specific conformance
results. Those subjects exist before or outside a tenant Execution and have
their own authenticated chains; they are never forced into a synthetic
Execution identity.

Profiles may add observations, but they cannot silently omit a required event.
The baseline does not promise full syscall, packet, instruction, or memory
tracing. A stronger Evidence grade states its extra observation boundary and
limits explicitly.

### 3. Append-only publication and integrity

Evidence is appended durably under a subject-scoped compare-and-swap
sequence. Replaying the exact same canonical event is idempotent. Reusing a
sequence for different content, observing a gap after finalization, or changing
an earlier event is an integrity failure.

Providers publish signed chain checkpoints so a verifier can validate a prefix
without trusting the serving store. Storage verifies digest, size, tenant or
trust domain, and authorization on every read as required by ADR 0014.
Replication may lag, but a Provider cannot report a durable terminal result or
conformance publication until the required Evidence and chain checkpoint are
committed.

Events received from a runner are untrusted claims until the execution plane
authenticates the runner, lease, fence, Capsule, sequence, and schema. The
execution plane adds its own admission, lease, cancellation, effect, cleanup,
and terminal observations rather than allowing a runner to attest to them on
its behalf.

Ordinary clients and integrations cannot append portable Provider Evidence.
Client-supplied claims or attachments, if supported, use a separate typed scope
that preserves their authenticated producer and cannot satisfy a required
execution-plane event or Evidence grade.

### 4. Stable failure classes

The portable failure classes are:

- `admission rejected`: the Capsule, Seal, Program, protocol, or required
  feature was invalid before policy evaluation completed;
- `policy denied`: an authenticated, valid request was not authorized;
- `capacity unavailable`: no exact compatible admitted placement could be
  leased within the scheduling bound;
- `runtime failure`: the selected runtime or Provider failed while the
  isolation and cleanup boundary remained proven;
- `Program failure`: the Program completed unsuccessfully under its declared
  result contract;
- `timed out`: a sealed deadline expired first;
- `canceled`: an authenticated cancellation won the terminal race;
- `resource exhausted`: a sealed resource limit was reached;
- `external effect indeterminate`: an external mutation cannot be proven
  rejected or safely accepted; and
- `runner integrity failure`: runtime identity, lease, fencing, Evidence,
  isolation, revocation, or cleanup could not be proven.

Their applicability is closed:

- `admission rejected`, `policy denied`, and `capacity unavailable` describe a
  request or initial-subject failure before guest execution. They may terminate
  a proposed Session during creation. During renew, suspend, or restore they are
  operation outcomes, and the Session follows ADR 0008's recovery transition
  instead of being reclassified automatically.
- `Program failure` applies only to an Execution. A child Program failure is
  retained in the child Evidence and does not by itself terminate its Session.
- `runtime failure`, `timed out`, `canceled`, `resource exhausted`, `external
  effect indeterminate`, and `runner integrity failure` may terminate an
  Execution or an active Session when their definitions apply.

A successful Execution result or successfully destroyed Session is a successful
terminal outcome outside this failure list. An explicit successful Session
destroy is not relabeled `canceled`.

Spelling and meaning are protocol data. Providers may attach bounded diagnostic
codes and retry hints, but may not invent a portable class or map an unknown
condition to `Program failure`.

For a given subject, admission, policy, and capacity failures are mutually
exclusive with its running-state outcomes. After an Execution starts, the first
durably committed terminal cause wins ordinary races among Program completion,
deadline, cancellation, resource exhaustion, and runtime failure. For an active
Session, the same first-winner rule applies among hard or idle lifetime expiry,
forced cancellation, aggregate resource exhaustion, and runtime failure; child
Program completion is not a Session terminal cause.

Two safety overrides apply even after an ordinary cause was selected:

1. an unresolved accepted-or-possibly-accepted mutation makes the primary
   class `external effect indeterminate`; and
2. an unproven subject runtime or cleanup boundary makes the primary class
   `runner integrity failure`.

All observed causes remain in Evidence. The primary class controls terminal
status presentation and ordinary handling; it does not erase the earlier
Program exit, cancellation request, Provider fault, or effect state. An
integrity failure takes precedence over an indeterminate effect while retaining
the effect state as a required unresolved cause.

Retry eligibility is a separate signed deny-overrides decision across every
observed cause and external operation. An unresolved indeterminate effect
always denies automatic retry until ADR 0011's safety proof succeeds, regardless
of the primary class or a Provider retry hint. A runner-integrity failure also
denies automatic retry until the affected runtime or Provider is quarantined or
remediated and an independent effect-safety proof is available. No single
terminal class implies retry safety.

### 5. Finalization and cleanup

Output completion is not terminal finalization. Before publishing an Execution
or Session terminal result, the Provider must, where applicable:

1. fence new guest and capability activity;
2. close or classify every external operation;
3. finalize declared output and Artifact manifests;
4. revoke handles, derivative credentials, connections, and leases;
5. prove required runtime destruction or one-shot disposal; and
6. durably append the cleanup and terminal Evidence.

A client disconnect does not skip this sequence. If a runner disappears, the
control plane uses its own lease, fence, broker, and infrastructure observations
to finish what it can. Anything that remains unproven produces `runner integrity
failure`; absence of an error log is not cleanup proof.

### 6. External-effect Evidence

Each effect records the stable operation and idempotency identities, capability
grant, bounded destination and request metadata, and the `requested`,
`rejected`, `accepted`, or `indeterminate` transitions defined by ADR 0011.
Evidence never changes an indeterminate transition to accepted merely because a
later retry appears successful. Reconciliation appends a new linked event that
identifies the authoritative destination result and method used.

Terminal finalization requires every requested effect to reach a durable state.
An indeterminate state is itself durable and terminal; it blocks automatic
retry unless ADR 0011's safety proof is later established.

### 7. Attestations

A Runtrue attestation is a signed canonical statement binding, as applicable:

- the Evidence schema, chain root, and sequence range;
- the scope kind and primary subject identity;
- Program, Capsule, Seal, policy, runtime, Provider, and deployed-generation
  identities;
- admission, lease, fence, capability, and external-effect summaries;
- the primary terminal class and all safety-override causes;
- output, Artifact, Checkpoint, and Replay Bundle manifest digests;
- cleanup or destruction result;
- issuer, signing-key generation, issue time, expiry, and revocation reference;
  and
- the claimed Evidence and isolation grade.

An attestation says only what its declared grade observed. It does not imply
complete syscall tracing, absence of a Provider vulnerability, semantic
correctness of the Program, or equal isolation across runtime families. Bisim
conformance and backend security results remain separate claims under ADR 0014.

Signing occurs only after the subject's required Evidence prefix is finalized.
For an Execution, that prefix ends with terminal cleanup Evidence. The Provider
then appends an attestation-publication event that refers to the signed
attestation; the attestation does not include its own publication event in its
chain root. This avoids a circular digest while retaining a durable publication
record.

Key rotation preserves verification of unexpired historical attestations,
while key compromise publishes a signed revocation or trust-policy update with
an explicit affected range.

### 8. Retention and payload expiry

Retention policy separates:

- identity, authorization, lifecycle, effect-state, cleanup, chain, and
  attestation metadata needed for the minimum verification baseline;
- logs, source, network metadata, structured output, and ordinary Artifact
  payloads; and
- secrets, regulated data, high-risk diagnostics, and other specially governed
  payloads.

Each class has an admitted tenant policy, expiry, location constraint, and
deletion method. Legal hold may extend retention but cannot silently shorten
the sealed minimum. Access remains tenant- and purpose-scoped even when content
is addressed by digest.

Expiry removes the protected payload and appends a tombstone containing its
original digest, object class, governing policy, deletion time, method, and
available deletion proof, but never the deleted contents. The tombstone keeps
the Evidence chain verifiable and lets a verifier distinguish intentionally
expired data from corruption or an unauthorized missing object.

An attestation remains cryptographically verifiable after allowed payload
expiry, but verification reports that the payload is unavailable under the
named retention policy. It must not report a full reproduction or content
validation. The declared historical Replay Bundle grade remains immutable;
current replay availability and verification status degrade under ADR 0012
when required inputs expire.

### 9. Evidence access and export

The public operations in ADR 0008 expose bounded streaming, range retrieval,
verification, and export. An identifier or digest is not access authority.
Exports preserve canonical events, signatures, chain checkpoints, tombstones,
and manifests, and state which payloads were omitted, redacted, or expired.

Local and managed Providers produce the same portable envelope and failure
classes. A local Provider may store its chain locally and use a local signing
identity, but it cannot omit Evidence required by a feature profile it
advertises.

## Consequences

- Clients can automate against stable failures without parsing Provider logs.
- Cleanup and indeterminate effects cannot be hidden behind a simpler Program
  result.
- Evidence storage and signing become trusted, versioned security boundaries.
- Retention can delete sensitive payloads without making expiry look like
  corruption.
- Attestations are deliberately scoped claims rather than guarantees beyond
  what Runtrue observed.

## Review triggers

- A terminal race cannot be resolved by durable first-winner semantics.
- A new failure class changes client retry or security behavior.
- An external-effect protocol adds a state not represented here.
- Payload deletion cannot leave a verifiable tombstone.
- A signing-key compromise invalidates the current revocation model.
- A requested attestation claim requires observations Runtrue does not collect.
