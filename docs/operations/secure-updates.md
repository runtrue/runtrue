# Secure update trust and recovery

Runtrue release updates use a bounded TUF-style trust core in `runtrue-update` and
the `runtrue-update` CLI. It authenticates files and advances durable monotonic
trust state; it does not download, install, or execute a target.

## Trust model

Every signed envelope has a closed schema, canonical JSON encoding, explicit
role and version, issue time, expiry, and sorted Ed25519 signatures. Qualified
SHA-256 key identifiers are derived from public-key bytes. Unknown fields,
duplicate JSON keys, non-canonical bytes, unsafe target paths, excessive sizes,
unassigned signatures, and threshold failures are rejected.

The four roles have disjoint keys and responsibilities:

- `root` authorizes every role. Keep threshold root keys offline and in
  separately controlled locations.
- `targets` signs exact target names, byte lengths, digests, media types,
  platform/architecture, and release version.
- `snapshot` binds the exact version, digest, and length of targets metadata.
- `timestamp` binds the exact snapshot envelope and expires most frequently.

The implementation caps a metadata envelope at 4 MiB, a target at 8 GiB, a
targets set at 4,096 entries, a root at 64 keys/signatures, a root chain at 32
sequential rotations, and JSON nesting at 64 levels. Maximum lifetimes are ten
years for root, 366 days for targets, 90 days for snapshot, and 14 days for
timestamp. Operators should use substantially shorter online-role lifetimes.

## Initial root ceremony

Initial trust is an out-of-band operation. Obtain the canonical signed root and
its `sha256:<lowercase-hex>` envelope digest over independent channels. At least
two people should compare the digest against separately held records. Never
derive the expected digest from the root file being accepted.

The state directory must already exist, be owned by the effective user, and be
mode `0700`. All CLI paths are absolute and normalized; ancestor symlinks,
hard-linked inputs, swapped inodes, and unsafe output parents fail closed.

```bash
install -d -m 0700 /var/lib/runtrue/update
runtrue-update root-digest --root /secure-media/runtrue-update-root.json
runtrue-update bootstrap \
  --root /secure-media/runtrue-update-root.json \
  --expected-root-digest sha256:REVIEWED_OUT_OF_BAND_DIGEST \
  --state /var/lib/runtrue/update/trusted-state.json
```

Bootstrap creates state exactly once with an atomic no-replace operation. Do
not delete or replace that state during ordinary recovery. The retained-dirfd
store uses a mode-`0600` lock and state file, verifies the complete file snapshot
before and after reads, serializes writers with an exclusive lock, proves the
locked inode is still the directory entry, and compares the expected canonical
state digest before replacement. Concurrent or stale apply operations cannot
overwrite newer trust state.

## Verification and application

Use `verify` to check a complete root-rotation/timestamp/snapshot/targets chain
and one exact file without mutation. Use `apply` only after all release files
needed by the installation have passed verification; it repeats full validation
and durably advances state after the final target succeeds.

```bash
runtrue-update verify \
  --state /var/lib/runtrue/update/trusted-state.json \
  --bundle /srv/runtrue-release/runtrue-update-bundle.json \
  --target-path runtrue-runner-0.1.0-linux-amd64.tar.gz \
  --target-file /srv/runtrue-release/runtrue-runner-0.1.0-linux-amd64.tar.gz

runtrue-update apply \
  --state /var/lib/runtrue/update/trusted-state.json \
  --bundle /srv/runtrue-release/runtrue-update-bundle.json \
  --target-path runtrue-runner-0.1.0-linux-amd64.tar.gz \
  --target-file /srv/runtrue-release/runtrue-runner-0.1.0-linux-amd64.tar.gz
```

Timestamp, snapshot, and targets versions may only increase. Reusing a version
with changed bytes, presenting an older version, using expired/future metadata,
mixing envelopes from different releases, or changing a target byte is rejected.
A controlled software rollback therefore requires newly versioned and freshly
signed metadata that explicitly names the approved safe payload; restoring old
metadata or old client state is not a rollback procedure.

Back up trusted state with the installation backup and restore it atomically.
After a lost state file, re-bootstrap only through the same two-person root-pin
ceremony and audit the loss. A restored stale state must not be allowed to write
until it has consumed the current metadata chain.

## Root rotation and revocation

A new root must be exactly version `current + 1` and meet both the old-root and
new-root thresholds. Include every intermediate root in order when a client may
have missed rotations. A skipped version, only-old signature set, only-new
signature set, cross-role key reuse, or unrelated signature is rejected.

For planned rotation, prepare and review the next root offline, sign it under
both thresholds, publish it before retiring old keys, and retain recovery copies
of the previous root material according to policy. Rotation envelopes can be
included at the front of a release bundle.

If an online targets, snapshot, or timestamp key is compromised, stop release
promotion, rotate that role through a dual-threshold root update, publish short-
lived replacement metadata with higher versions, and add known malicious
digests or minimum versions to emergency policy. If a root key is compromised,
use the remaining old threshold plus the new threshold. If the old root
threshold can no longer be met, there is deliberately no online bypass: clients
require a new out-of-band trust ceremony.

An expired current root cannot authorize ordinary metadata, but an explicitly
provided sequential root rotation signed by both thresholds can recover clients.
An expired initial root cannot be bootstrapped.

## Signing-key handling

`runtrue-update keygen --output /absolute/private/path` uses operating-system
randomness, refuses overwrite, writes mode `0600` beneath an owner-only parent,
zeroizes seed buffers, and never prints private material. Its JSON output
contains only the public key and key identifier. Production release signing
should use an audited offline or non-exportable signing service; do not put raw
role keys in a workflow, runner, repository secret, build artifact, or command
line. Root keys and online-role keys must remain separate.

## Air-gapped operation and runner compatibility

Transfer the pinned root, signed bundle, target files, dependency-complete
CycloneDX SBOMs, provenance, and attestations through the quarantine ceremony in
[air-gapped deployment](air-gapped-deployment.md). Verification uses no network.
Import current revocation metadata with the same urgency as binaries.

During rolling upgrades the server supports protocol generations N and N-1.
Upgrade the control plane within that window, drain old runners before removing
N-1, and raise the policy minimum immediately for a security fix. A runner that
cannot meet the minimum is drained or revoked, never silently admitted through
an older update channel.
