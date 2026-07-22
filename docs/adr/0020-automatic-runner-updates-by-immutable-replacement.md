# ADR 0020: Automatic runner updates by immutable replacement

- **Status:** Accepted
- **Date:** 2026-07-17
- **Compatibility scope:** target architecture for unreleased v0.x
- **Extends:** ADR 0018

## Context

A runner enrollment binds one runner identity and credential to the exact
canonical inventory accepted by the control plane. The inventory includes the
runner binary and deployment-image digests, software versions, protocol
generation, isolation backends, capabilities, and host properties. Every
authenticated `Open` verifies that binding.

Replacing a runner binary therefore correctly prevents the existing credential
from reconnecting. Accepting a different inventory on reconnect would let
possession of a runner key silently change the deployment posture used by
scheduling, secret, OIDC, artifact-provenance, and lease decisions.

[ADR 0018](0018-runner-fleet-autoscaling.md) already defines a safer model for
automatic capacity replacement: the control plane creates a short-lived launch
claim bound to one immutable provider instance and template, and the new runner
generates a fresh key and enrolls exactly once. The autoscaler provisions the
instance but never becomes an enrollment authority.

Runner software updates should use the same identity model. Operators also need
the rollout and enrollment to happen in the background after they enable an
update policy; requiring a human to approve or copy a token for every worker
would defeat automatic fleet maintenance.

Runtrue already has a bounded TUF-style verifier with pinned root trust,
threshold roles, exact target binding, expiry, monotonic metadata, and rollback
protection. It authenticates release files but deliberately does not install a
target or authorize enrollment.

## Decision

An automatic runner update creates and enrolls a **new runner identity** for the
approved deployment posture. Runtrue never changes the inventory binding of an
existing runner and never copies its private key or certificate into the
replacement.

The control plane automatically authorizes each replacement when all of these
preconditions hold:

- an operator has enabled an automatic-update policy for the pool;
- the selected release and installed component are authenticated through the
  configured update root and monotonic metadata state;
- an exact registered pool template permits the target deployment posture;
- rollout, capacity, protocol, revocation, and attestation policy permit the
  replacement; and
- the provider or fixed host supplies the identity evidence required by the
  launch claim.

This is background authorization by previously approved policy, not an
authorization bypass. Release promotion and enabling or changing the pool
policy remain reviewed administrative actions. Once those decisions exist, no
human approval, reusable enrollment token, or manual credential transfer is
required for an individual worker.

The control plane remains the only enrollment authority. The autoscaler and
host updater may request or deliver an exact launch claim, but cannot create,
broaden, sign, or reuse one.

### Immutable runner generations and replacement lineage

A runner ID names one enrolled deployment posture for its entire lifetime. Its
inventory digest and authoritative posture digest are immutable. Certificate
rotation preserves that same identity and posture; it is not an update
mechanism.

Every software replacement creates:

- a new runner ID, locally generated private key, CSR, and certificate;
- a new immutable enrollment inventory and authoritative posture;
- a durable replacement record linking source and target runners;
- a monotonically increasing replacement generation; and
- Evidence linking release selection, enrollment, activation, drain,
  revocation, and termination.

A durable `runner_slot_id` identifies a replaceable logical position on a fixed
host. Autoscaled instances use their fleet request and provider instance
lineage instead. User interfaces and metrics may present this stable lineage,
but leases, certificates, fences, posture, and audit events always name the
concrete runner ID that performed the work.

The source and target identities may coexist during a rolling replacement, but
they never share a key, certificate, Open session, lease, or posture. A fixed
host permits only one active slot generation to receive work.

### Signed target and template binding

The control plane independently verifies the signed target description. The
autoscaler verifies the immutable provider template or image selection, and a
fixed-host updater independently verifies the same metadata chain plus the
downloaded bytes through its own monotonic trust state.

An automatically installable runner target has a closed signed component
profile binding at least:

- component name and release version;
- artifact name, length, digest, and media type;
- platform and architecture;
- installed executable or immutable image digest;
- runner and engine versions;
- protocol minimum and maximum; and
- package format plus allowed installation paths and modes where extraction is
  required.

The artifact digest and installed executable digest are distinct values. A
verified archive is not assumed to identify a file extracted from it. Unknown
or missing component-profile fields make the target ineligible for automatic
installation.

Pool policy maps the signed component profile to an exact immutable runner
template and scheduling demand class. An update cannot silently add a
capability, reduce isolation, move region, or substitute a similar template.
Such a change requires a separately reviewed pool-template or policy revision.

### Replacement launch claims

Software replacement reuses ADR 0018's normal single-use enrollment token and
launch-claim transaction. All claim profiles bind the pool, immutable template,
identity-evidence digest, creation time, and expiry. The autoscaled profile also
binds its fleet request, provider, and provider instance. The fixed-host profile
instead binds its registered runner slot and updater/installation identity.

A software-replacement claim additionally binds:

- purpose `software-update` and replacement mode;
- source runner and source authoritative posture digests;
- runner slot or provider replacement lineage;
- monotonically increasing replacement generation;
- target artifact and installed binary or image digests;
- release, component-profile, update-root, targets, snapshot, and timestamp
  metadata identities;
- rollout policy version, channel, and ring;
- protocol compatibility and required attestation grade; and
- a fresh attestation nonce when applicable.

Claims expire after at most fifteen minutes. Only one unconsumed claim may
exist for a fixed runner slot and replacement generation. A newer generation
cancels older pending claims. Claim creation is atomic with its enrollment
token and durable replacement record.

The claim is injected only into the exact new provider instance or fixed-host
candidate credential generation as an owner-only, create-new file. It is never
placed in a command line, environment variable, log, guest workspace, source
runner credential directory, or release artifact.

The candidate runs `enroll-if-needed` against an empty credential generation,
generates its private key locally, and presents the claim, bound identity
evidence, exact inventory, and CSR. The control plane revalidates current
policy and metadata, consumes the enrollment token and claim, creates the new
runner and posture binding, links the replacement, and installs the issued
credentials atomically. A replay, wrong target, wrong host or instance,
expired claim, stale generation, or mismatched inventory fails before
certificate issue.

The newly enrolled runner starts as probationary. It cannot receive a lease or
use a secret, OIDC, cache-write, artifact-publication, or broker operation until
the control plane accepts its health, protocol, attestation, and exact posture.

### Identity evidence

Autoscaled replacements use the provider-native identity evidence required by
ADR 0018. The claim is created only after the provider returns an immutable new
instance identity.

A fixed host uses a separately registered updater/installation identity or an
approved hardware/platform identity. Its private key is generated during the
initial host bootstrap, stored separately from runner credentials, and is
non-exportable where supported. It proves only that a control-plane-selected
claim reached the registered host; it cannot select a target, issue a claim,
read workloads, or enroll without an unconsumed claim.

Fresh hardware evidence does not replace the pinned update root, and release
signatures do not replace a platform quote required by pool policy. A fixed
host without acceptable independent identity evidence is not eligible for
unattended replacement and continues to use explicit manual re-enrollment.

### Autoscaled and immutable workers

For an autoscaled pool, the control plane reconciles a desired deployment
generation in addition to desired capacity:

1. It creates bounded replacement fleet requests for the exact new template.
2. The autoscaler provisions new instances and requests ordinary launch claims.
3. Each new instance enrolls with a fresh identity and remains probationary.
4. After a replacement becomes healthy and online, the control plane drains a
   corresponding old-generation runner.
5. The autoscaler terminates that old instance only after drain completion;
   the control plane revokes its certificates and retires its runner identity.

This is a surge-first rolling replacement. Maximum surge, maximum unavailable,
minimum healthy, minimum idle, exact-demand, cooldown, and autoscaler fencing
bounds continue to apply. The old and new postures may both run temporarily
only while pool policy permits both.

An immutable OCI runner is always replaced this way. A process inside a
container never rewrites its filesystem and claims a new image identity.

### Fixed-host workers

`runtrue-updater` provides the same enrollment semantics when a registered host
cannot be replaced:

1. It downloads, verifies, safely extracts, and stages a new immutable runner
   installation without changing the active selector.
2. The runner completes normal drain. Activation waits for active and offered
   leases, guests, handles, derivative credentials, object transfers, and
   required Evidence finalization to close.
3. The control plane revalidates policy and drain, then automatically creates
   the short-lived replacement claim for that host and slot.
4. The updater stops the source runner, selects the staged installation, and
   starts `enroll-if-needed` with a new empty credential generation and the
   claim. It never copies or exposes the source runner key.
5. The candidate enrolls as a new probationary runner. After local health and
   control-plane checks succeed, the control plane atomically activates the new
   slot generation and revokes and retires the source identity.

The updater alone can write the installation and its update trust state. It has
no enrollment-CA, Capsule-signing, tenant-secret, control-plane database,
provider-management, or guest-workspace access. It never executes
package-supplied hooks. Extraction rejects absolute or escaping paths, links,
devices, unexpected entries, modes, owners, sizes, and decompression bounds;
the installed executable is rehashed against the signed component profile.

The runner cannot write the installation or updater trust state. The updater
cannot read runner private keys. Deployments that cannot enforce these
permissions document the updater as part of the runner-host trusted computing
base.

### Rollout policy and automatic approval boundary

Automatic updates are disabled by default. Enabling them creates a versioned
pool policy containing the allowed signed channel, template mapping,
maintenance windows, canary and ring ordering, minimum capacity, maximum surge
and unavailable counts, failure threshold, pause state, and attestation and
protocol requirements.

The control plane, not each worker, selects one exact release. A runner,
autoscaler, or updater never resolves `latest`. After the policy is enabled,
the control plane creates replacement requests and launch claims in the
background without individual human approval. Every automatic decision records
the policy version and signed release identities that authorized it.

A canary failure pauses later rings. A security-critical policy may raise a
minimum version or accelerate a window, but it cannot skip release
verification, exact template matching, identity evidence, fresh enrollment,
drain, or fencing.

### Failure and rollback

Before claim consumption, failure leaves the source identity unchanged. An
autoscaler terminates the failed candidate. A fixed host may restore the source
installation and credential generation only if the source remains permitted by
current policy.

After candidate enrollment but before fixed-slot activation, the candidate has
no workload authority. The control plane may revoke it and allow the drained
source to resume if policy still permits the source. Exact retries after an
ambiguous enrollment response are idempotent and cannot create a second runner.

After replacement activation, the source runner and its certificates remain
retired. Rollback is another forward replacement: freshly versioned and signed
metadata must name the approved payload, and a new launch claim enrolls another
new identity. Restoring old metadata, trusted state, credentials, runner IDs,
or replacement generations is never a rollback procedure.

If emergency policy prohibits the source version, it cannot resume even when
the candidate fails. Capacity remains unavailable until another approved
replacement enrolls.

All updater, autoscaler, and control-plane transitions are durable and
idempotent across process crash, host reboot, network partition, and lost
responses. Garbage collection never removes an active installation, source
needed for an allowed pre-activation fallback, pending candidate, unconsumed
claim, or Evidence required by retention policy.

## Consequences

- One runner identity always means one exact enrollment posture; update support
  adds no exception to reconnect validation.
- Autoscaling, host-loss replacement, immutable image rollout, and software
  updates share one bound launch-claim and fresh-enrollment security boundary.
- Routine worker enrollment happens in the background without per-worker human
  approval or reusable enrollment credentials.
- A compromised autoscaler or updater cannot choose an arbitrary target or
  issue enrollment authority, although both remain security-sensitive members
  of their provider or host trusted computing base.
- Runner IDs and certificates churn during updates. Stable operational views
  therefore use slot, fleet, and replacement lineage rather than pretending
  that one runner identity changed software.
- Fixed hosts require an independently registered installer identity and
  atomically versioned installation and credential stores.
- Extra replacement capacity improves availability for autoscaled pools;
  fixed-host updates still incur a drained interval.
- Automatic control-plane/server updates and forward-only database migration
  orchestration remain outside this ADR and use the installation upgrade and
  backup/restore procedure.

## Rejected alternatives

- **Mutate the enrolled inventory after a signed update:** this creates an
  exceptional path where one runner identity represents multiple postures and
  requires a new posture-transition authorization protocol.
- **Reuse the source runner key or certificate:** credential continuity would
  obscure generation boundaries and let old and new software claim one
  identity.
- **Automatically issue an ordinary enrollment token:** an unbound bearer can
  enroll on the wrong host, target, pool, or generation.
- **Give the autoscaler or updater enrollment authority:** provider or host
  compromise could mint runners outside control-plane policy.
- **Require human approval for every replacement:** this prevents unattended
  maintenance without adding cryptographic binding beyond the signed release,
  pool policy, identity evidence, and one-time claim.
- **Trust a package repository, TLS endpoint, checksum, or version string:**
  none supplies threshold release authority, expiry, exact installed-component
  identity, and rollback protection.
- **Let each worker choose the newest release:** canaries, incident pause,
  capacity bounds, and audit would become host-local races.
- **Modify an immutable runner container in place:** the process could no
  longer truthfully claim the orchestrator's image identity.

## Required verification

- A changed binary presenting an existing runner certificate still receives
  the current inventory-mismatch failure.
- Every successful update has distinct source and target runner IDs, keys,
  certificates, inventory bindings, and posture digests connected by one
  durable replacement generation.
- A forged, expired, canceled, replayed, wrong-pool, wrong-source, wrong-slot,
  wrong-instance, wrong-template, wrong-target, or stale-generation claim fails
  before certificate issue.
- Token consumption, claim consumption, runner creation, posture binding, and
  replacement linkage are atomic and exactly idempotent after a lost response.
- No probationary runner can receive a lease or brokered authority.
- Autoscaled rollout provisions healthy exact-generation capacity before drain
  and cannot exceed surge, unavailable, minimum-capacity, or autoscaler-fence
  bounds.
- Fixed-host slot activation and source revocation are atomic. The old and new
  slot generations can never both receive work.
- Candidate failure before activation can restore only a still-permitted source;
  failure after activation cannot revive its identity or credentials.
- Mutation of target bytes, component metadata, installed executable, provider
  or host evidence, inventory, capability, isolation, region, or protocol fails
  closed.
- Power loss at every download, extraction, selector, drain, claim, enrollment,
  credential-install, activation, revocation, and termination boundary recovers
  to one unambiguous durable state.
- A compromised mirror, stale metadata backup, or restored old target cannot
  bypass the control plane's and updater's independent monotonic trust states.
- Canary failure pauses later rings, while an enabled healthy rollout creates
  claims and enrolls replacements without per-worker human action.
- The autoscaler and updater cannot read Capsules, tenant secrets, job payloads,
  runner private keys, or the control-plane database, and neither can create or
  broaden a launch claim.
