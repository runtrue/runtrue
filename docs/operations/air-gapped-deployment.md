# Air-gapped deployment architecture

This document defines the supported security shape for a Runtrue installation
that cannot reach public networks. It is an architecture and operating
procedure. The repository now contains offline-verifiable TUF-style release
metadata and durable update trust state, but the planned `runtrue-mirror`
import/export utility and repository proxy are not implemented.

## Trust boundary

The offline installation has no route to the public Internet. Its only ingress
is an operator-controlled transfer station. Firewall policy denies outbound
traffic from the control plane, runners, workload networks, cache storage, and
SCM mirrors. DNS for those zones resolves only approved internal services.

Use separate network zones for:

- the unprivileged control plane and its SQLite/blob storage;
- runner management mTLS;
- isolated job networks;
- internal SCM, OCI, component, package, and toolchain mirrors; and
- backup storage.

Job networks must not reach the management, storage, backup, or transfer
station zones. A workflow requiring an external endpoint is rejected unless an
approved internal mirror or proxy is represented in its signed Capsule and policy.

## Offline trust roots

Maintain offline copies of the public verification material for:

- Runtrue release artifacts and provenance;
- installation Capsule, image, snapshot, audit-checkpoint, and OIDC keys;
- internal OCI and Wasm-component registries;
- guest kernels, root filesystems, runner images, and toolchains; and
- backup manifests.

Private installation keys remain inside the offline zone. The transfer station
receives verification keys, never signing or decryption keys. Record key ids,
validity, revocation state, and an independently verified digest on removable
media stored separately from the payload.

## Import ceremony

Every transfer is fail-closed and two-person reviewed:

1. Acquire exact immutable source, crate/vendor data, OCI manifests and blobs,
   Wasm components, guest images, SBOMs, provenance, and signatures on a
   connected staging host.
2. Malware-scan the staging media without rewriting signed payloads.
3. Generate a canonical inventory containing media type, byte length,
   qualified SHA-256 digest, signer/key id, provenance digest, SBOM digest,
   and expiry for every object.
4. Sign the inventory with an approved transfer key and copy the inventory,
   payloads, and public verification chain to fresh media.
5. On the offline transfer station, verify the inventory signature and every
   byte length/digest before making any object visible to a mirror.
6. Quarantine imported objects under a non-serving path. Verify image,
   component, snapshot, SBOM, and provenance policy using offline trust roots.
7. Promote by immutable digest into the appropriate tenant/repository trust
   domain. Promotion changes metadata; it never rewrites payload bytes.
8. Append the import and promotion decisions to Runtrue's audit log and retain
   the signed inventory with the release evidence.

A missing, expired, revoked, mutable, unlisted, or mismatched object aborts the
whole import. Partial imports remain quarantined and cannot satisfy a lockfile.

## Mirror layout and resolution

Private Git mirrors, cache entries, artifacts, action components, and image
metadata are tenant/repository scoped. Public content may be shared only after
independent signature and digest verification; private objects are never
deduplicated across tenants by an observable identifier.

Workflow lockfiles contain exact digests. Registry and package configuration
points exclusively at internal names. The trusted SCM worker reads only exact
commits already present in its mode-`0700` mirror root. Mirror refresh is a
separate privileged operator action and never executes repository content.

Runner pools advertise only content and capabilities actually present in the
offline zone. The scheduler applies isolation and policy filters before
locality. Missing mirror or cache content becomes a bounded miss or an explicit
resolution failure; it never enables Internet egress or a less isolated
executor.

## Installation and updates

Build Runtrue from a reviewed, immutable source archive with a vendored Cargo
dependency set whose `Cargo.lock` matches this repository. Run the same format,
all-target check, test, Clippy, schema, and RustSec gates in the offline build
environment. Preserve the compiler version, source digest, dependency
inventory, SBOM, provenance, and resulting binary digest.

Before an update, restore a backup into an isolated drill environment and test
schema migration plus server/runner compatibility. Upgrade the control plane
first only when the documented protocol window permits it; otherwise drain
runners before replacement. Never import an unsigned emergency binary. Import
revocation metadata with at least the same urgency as release media.
Bootstrap the update root from an independently recorded digest and verify each
transferred target with the procedure in
[secure update trust and recovery](secure-updates.md). Preserve the monotonic
trusted-state file across upgrades and restores.

## Backup, restore, and incident response

Follow the [single-node backup and restore runbook](single-node-backup-restore.md).
Keep encrypted backups and verification keys in separate offline locations.
Restores enter safe mode, increment the installation fencing epoch, expire old
leases, and require audit/key verification before activation.

For a suspected transfer, registry, or signing-key compromise:

- stop promotion and runner scheduling;
- revoke the affected key/digests in policy;
- quarantine derived cache, image, snapshot, and artifact state;
- verify audit checkpoints from an independent copy;
- import signed revocation/recovery material through the full ceremony; and
- resume only after a restore drill or complete provenance re-verification.

## Current tooling boundary

Runtrue currently provides signed image metadata, immutable CAS/artifact/cache
primitives, exact lock resolution, tenant-scoped policy, audit checkpoints,
backup verification, dependency-complete release SBOMs, provenance, and
threshold TUF-style update verification with root rotation and rollback/freeze
protection. Automated mirror bundles, repository/package proxy configuration,
and removable-media import/export orchestration remain follow-on tooling.
Operators must not replace those missing controls with mutable tags, ambient
credentials, or temporary Internet access from the offline zone.
