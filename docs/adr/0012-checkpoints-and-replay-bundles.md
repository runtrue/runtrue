# ADR 0012: Checkpoints and Replay Bundles

- **Status:** Accepted
- **Date:** 2026-07-15
- **Compatibility scope:** target architecture for unreleased v0.x
- **Detailed decision under:** ADR 0007

## Context

Sessions need explicit suspension and recovery without preserving a live VM,
credential, connection, or capability handle. Separately, users need portable
material for reproducing an Execution or understanding why exact reproduction
is impossible.

A VM snapshot is not automatically a safe Checkpoint, and a collection of logs
is not automatically a Replay Bundle. Both artifacts require declared content,
canonical identity, tenant isolation, sanitization, and honest reproducibility
claims.

## Decision

### 1. Checkpoint contract

A **Checkpoint** is an immutable, authenticated, encrypted, tenant-scoped
manifest and object graph representing quiescent Session state. It may include:

- declared workspace files and metadata;
- content-addressed Program and dependency references;
- process-independent tool and cache state explicitly allowed by policy;
- the Session Capsule, runtime compatibility, and source workspace generation;
- logical filesystem, ownership, and permission metadata; and
- sanitization, scanner, and creation Evidence.

It excludes:

- plaintext secrets and bearer credentials;
- active or derivative identity material;
- live network connections, sockets, and listeners;
- capability handles and broker sessions;
- runner, Provider, lease, fence, device, or pool identity as restorable state;
- pending or indeterminate external operations;
- kernel entropy, host paths, and Provider control channels; and
- any memory or device page not covered by an explicit safe serializer.

A raw hypervisor, container, process, or memory snapshot is not a Checkpoint
until the Checkpoint pipeline proves and records these exclusions.

### 2. Guest-visible credential taint

Broker-only external operations do not expose credential material to guest
state. If policy releases any guest-visible secret or derivative credential,
however, every guest-mutable state location reachable from that release point
is tainted. An adversarial Program can encode, encrypt, compress, split, or
transform the value, so expiry, redaction, secret scanning, and malware scanning
cannot prove its exclusion.

A resumable Checkpoint or Hermetic or Exact Replay Bundle may not contain
tainted state. Taint can be removed only by either:

- discarding all affected guest-mutable state back to an authenticated
  generation created before release and destroying the tainted runtime; or
- a future runtime-enforced information-flow or safe-serialization profile
  whose soundness is part of the admitted security boundary.

An Evidence-only bundle may retain permitted metadata about the release but not
the tainted payload. This restriction is an explicit compatibility cost of
tools that require raw credentials; scanners remain defense in depth, not a
noninterference proof.

### 3. Quiescence and construction

Checkpoint creation is a fenced Session transition:

1. Fence admission of new child Executions without revoking authority from a
   child that is already admitted.
2. Under Capsule policy, either let each running child finish using its existing
   fence or durably cancel it, then await its terminal cleanup.
3. Reject new capability calls, drain broker activity, and durably classify
   every in-flight external operation.
4. Resolve or reject every external operation; a pending or indeterminate
   operation blocks a resumable Checkpoint.
5. Revoke and destroy guest-visible credentials, handles, and connections.
6. Enforce the guest-visible credential-taint rule above.
7. Flush and atomically freeze the declared workspace generation.
8. Walk content without following symlinks or crossing undeclared mounts.
9. Apply exclusion, size, file-type, ownership, malware, and secret scanners.
10. Construct the canonical manifest and authenticated object graph.
11. Encrypt under the tenant Checkpoint key generation and publish atomically.
12. Destroy the previous live Session incarnation and record cleanup Evidence.

Failure before atomic publication may return the prior workspace generation to
active only through ADR 0008's recovery transition with a new fence and freshly
issued authority. Otherwise it moves the Session through destruction to a
terminal integrity state. It never exposes a partial Checkpoint as restorable.

### 4. Identity and encryption

Each Checkpoint has two distinct identities:

- a **state digest** over the canonical logical manifest and plaintext content
  digests, computed inside the tenant trust boundary; and
- a **storage digest** over the authenticated encrypted envelope used by the
  storage Provider.

The state digest is tenant-scoped and is never used for cross-tenant lookup or
deduplication. The storage envelope uses randomized authenticated encryption,
binds tenant, Checkpoint, key generation, algorithm, schema, and object
metadata as associated data, and is verified before decryption.

Keys are versioned, rotatable, and separate from object-store credentials.
Deleting a tenant key is not a substitute for enforcing retention or deleting
stored ciphertext. Cross-tenant copy, restore, and equality queries are denied.

### 5. Restoration

Restore requires an authorized Session Capsule that names the exact Checkpoint
state digest and a compatible runtime profile. The Provider verifies signature,
tenant, encryption, object graph completeness, bounds, sanitization Evidence,
schema, runtime compatibility, and revocation state before provisioning.

Restore creates a new Session incarnation with a fresh lease, fence, runtime,
network namespace, resource table, handles, and credentials. Capabilities are
reissued from the new Capsule and current policy; they are not restored from
the Checkpoint.

Restoration never mutates the Checkpoint. Subsequent work produces a new
workspace generation and, if suspended again, a new Checkpoint identity.

### 6. Sterile templates are different

A tenant-derived Checkpoint can resume only authorized state for that tenant.
It can never become a globally shared sterile template, warm-pool source,
runner image, or other tenant's input. A sterile template is constructed before
tenant execution through the separate ADR 0013 publication process.

### 7. Replay Bundle contract

A **Replay Bundle** is a secret-free, immutable manifest that binds an
Execution Capsule, Program, admitted inputs, runtime profile, relevant
Checkpoint or workspace generation, outputs, Evidence references, and the
material permitted for replay.

Every bundle declares one reproducibility grade:

- **Hermetic:** all execution inputs are content-addressed and no mutable
  external service or effect influenced execution.
- **Exact:** mutable interactions were replaced by a complete, policy-safe,
  authenticated recorded-interaction contract, so equivalent replay is
  expected without contacting or mutating the original service.
- **Evidence-only:** the bundle records what was requested and observed but
  lacks sufficient safe material for equivalent replay.

Hermetic and Exact are different proofs, not marketing synonyms. Evidence-only
is explicitly not a reproducibility claim. A missing, expired, redacted,
mutable, or indeterminate interaction prevents the stronger grades.
Guest-visible credential taint also prevents the stronger grades unless all
affected state was safely discarded or excluded by an admitted sound mechanism
under Section 2.

Replay runs are new Executions. They receive no original credential or effect
authority. Recorded external responses are served only by a bounded replay
adapter, and external mutations are disabled unless a new Capsule explicitly
authorizes a new real operation, in which case the run is no longer an exact
replay of the original effect history.

### 8. Retention and verification

Checkpoint payloads and Replay Bundle payloads follow tenant retention policy.
Their manifests retain digests and tombstones sufficient to distinguish
expired material from corruption or never-published material. Expiration of a
required object downgrades current replay availability and verification status;
it never changes the declared historical grade.

Runtrue publishes positive and adversarial vectors for canonical manifests,
encryption binding, exclusion scans, restore fencing, missing objects,
cross-tenant substitution, and each replay grade.

## Consequences

- Session suspension does not preserve live authority or depend on a live
  worker.
- Checkpointing requires coordinated quiescence with the effect journal and
  capability brokers.
- Tenant-scoped state identity avoids cross-tenant deduplication and equality
  leakage.
- Replay claims become explicit and testable rather than inferred from logs.
- Some Sessions cannot be checkpointed safely and must remain live or end.

## Review triggers

- A supported runtime offers a safe memory or device-state serializer.
- Checkpoint scanning cannot reliably exclude a sensitive state class.
- Cross-region restore introduces a new key or residency boundary.
- A replay adapter cannot reproduce an interaction without credential or
  privacy leakage.
- Retention rules make the declared replay grades misleading.
