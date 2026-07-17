# Single-node backup and restore

> [!CAUTION]
> Do not open or copy the live `control-plane.sqlite` database with `sqlite3`,
> filesystem copy tools, or container-side ad hoc scripts. Use `runtrue-backup`
> for a consistent online snapshot, then inspect the snapshot. Direct access to
> a live SQLite database can interfere with journal lifecycle across a bind-mount
> namespace and is not a supported diagnostic or backup path.

This procedure applies to the SQLite plus local-filesystem deployment. The
`runtrue-backup` archive is a private directory, not an encrypted container. Put
it on encrypted storage and protect it as production control-plane data.

The tool captures SQLite with SQLite's online backup API, so normal backups do
not require stopping `runtrue-server`. Filesystem inputs are copied as regular
files only. Symlinks, sockets, devices, FIFOs, non-UTF-8 names, changing files,
overlapping source/destination paths, and group/world-writable archive
directories fail closed. Every file has a bounded byte length and SHA-256
digest in `manifest.json`.

## What to include

- The control-plane SQLite database.
- The complete authoritative local blob directory, including durable
  artifacts and logs within retention.
- Reviewed server, policy, SCM, TLS, OIDC, update-trust, and audit-checkpoint
  configuration.
- Encrypted key material, encrypted DEKs, provider configuration, and recovery
  documentation. The built-in secret ciphertext is already in SQLite.

Do not include runner-local cache, ephemeral workspaces, regional replicas, or
warm VM state.

The local 32-byte installation security key is supplied separately with
`--security-key-file` for cryptographic verification. It is not copied
automatically. If an operator deliberately includes a copy under
`--key-ciphertext-dir`, that archive must receive the same protection as the
live key. Prefer a separately encrypted recovery escrow.

## Create and verify

Use a destination whose parent and final directory are private and which is
either absent or empty:

```sh
runtrue-backup create \
  --database /var/lib/runtrue/control-plane.sqlite \
  --blobs-dir /var/lib/runtrue/blobs \
  --config-dir /etc/runtrue/recovery-config \
  --key-ciphertext-dir /var/lib/runtrue/key-ciphertext \
  --security-key-file /var/lib/runtrue/security.key \
  --output /var/backups/runtrue/2026-07-11T020000Z

runtrue-backup verify \
  --backup /var/backups/runtrue/2026-07-11T020000Z \
  --security-key-file /var/lib/runtrue/security.key
```

Record the reported manifest digest in an independently protected operations
log. The digest detects accidental substitution only when the recorded value
is trusted; the archive manifest is not currently signed.

Verification performs all of the following:

- manifest version, path, entry-count, per-file, and total-byte bounds;
- an exact archive file-set comparison and every file digest;
- SQLite `integrity_check`, `foreign_key_check`, supported `user_version`, and
  contiguous migration history;
- the complete database audit hash chain;
- canonical Capsule decoding and every stored Capsule signature against the supplied
  installation key;
- eager authentication/decryption of every built-in encrypted secret version;
- Capsule-signing and OIDC public-key continuity derived from the local key.
- typed, bounded traversal of every authoritative artifact, cache, source,
  promotion, scan-evidence, pending-transfer, and backup-pin CAS graph;
- ArtifactStore signature/provenance validation and digest verification of
  every reachable manifest and file blob.

Backups containing Capsules, built-in secret snapshots, or OIDC grants require the
matching local installation key during create, verify, and restore.

## Restore into a clean target

Stop `runtrue-server`, schedulers, and every process with direct database access.
Never restore over a live or populated data directory.

```sh
runtrue-backup restore \
  --backup /var/backups/runtrue/2026-07-11T020000Z \
  --target /var/lib/runtrue-restored \
  --security-key-file /secure-recovery/runtrue-security.key
```

The target must be absent or an empty private directory. Restore verifies the
archive before creating target content, copies every regular file without
replacement, restores SQLite through the online backup API, applies supported
forward migrations, and re-verifies the resulting database and key state.

Before restore returns success, one SQLite transaction:

1. increments the installation fencing epoch;
2. marks every copied offered, active, or cancel-requested lease expired;
3. moves affected jobs to `lost` where their lifecycle permits; and
4. sets durable restore safe mode.

`runtrue-server` permits authenticated reads in safe mode but returns RFC 7807
`503` responses for all HTTP mutations, webhook ingestion, Capsule signing, run
creation, and OIDC minting. Readiness also remains false. The restored database
and copied files are left in `/var/lib/runtrue-restored`; configure the server to
use that directory only after the checks below.

## Checks required before activation

The restore command verifies bytes and the local cryptographic state it can
reach. An operator must independently complete these checks:

- Verify signed audit checkpoints against their offline/public verification
  keys and compare the latest checkpoint to an independently retained value.
- Verify TLS, OIDC issuer, update-trust, policy, SCM installation, and retention
  configuration against reviewed desired state.
- Revoke and re-enroll runners if runner identity or certificate state is
  uncertain. Confirm old runners cannot publish at the new installation epoch.
- Exercise read-only artifact/log retrieval and verify representative database
  references have corresponding restored blobs.
- Prove external secret, KMS, HSM, and signer access with non-production test
  identities and purpose-scoped challenge operations.
- Confirm deployment and signing workers are stopped or independently honor
  safe mode.

Only then activate the exact epoch printed by restore:

Stop the safe-mode server and every direct database client before activation.

```sh
runtrue-backup activate \
  --target /var/lib/runtrue-restored \
  --security-key-file /secure-recovery/runtrue-security.key \
  --expected-fencing-epoch 42 \
  --acknowledge-restore-verification
```

Activation re-runs database, audit-chain, complete authoritative object-graph,
blob/config/key-file, secret
ciphertext, Capsule-signature, and local-key continuity checks. It refuses a
different fencing epoch or any open execution lease. The acknowledgement is an
operator assertion for the external checks; it is not a substitute for them.
Removing or corrupting a manifest child after restore leaves durable safe mode
enabled; the acknowledgement cannot override an incomplete graph.

## Automated restore drill

Run at least monthly and after schema, key, storage, or recovery-procedure
changes. The drill must use an isolated host/account with no production write
credentials.

1. Select the newest backup and independently recorded manifest digest.
2. Run `runtrue-backup verify` and compare its digest to the recorded value.
3. Restore to a newly created throwaway parent filesystem.
4. Assert the restored epoch equals the source epoch plus one and safe mode is
   true.
5. Start `runtrue-server` on loopback with outbound network blocked. Assert
   `/readyz` is `503`, authenticated reads work, and representative POST, OIDC,
   and webhook requests are `503` without creating durable work.
6. Validate audit checkpoints, policies, SCM metadata, representative blobs,
   and the external-provider challenges listed above.
7. Re-enroll a disposable runner and prove a request using the pre-restore
   epoch is rejected.
8. Stop the safe-mode server, activate with the exact epoch, restart it, assert
   readiness succeeds, then run a
   non-secret, non-deploying smoke workflow.
9. Destroy the drill target and credentials. Record elapsed restore time,
   backup age, manifest digest, source/restored epochs, evidence, and failures.

Alert when the observed recovery point or recovery time exceeds the
installation's declared RPO/RTO.

## Non-exportable KMS/HSM recovery boundary

Private material in a KMS, HSM, TPM, or non-exportable signing service must not
be exported merely to make this archive self-contained. Back up and review:

- provider, account/project, region, key URI/version, algorithm, and public-key
  fingerprint;
- authorization policy, workload identity binding, network route, quorum, and
  break-glass procedure;
- provider-native replication/backup status and destruction/rotation policy;
- an offline public verification key or certificate chain where supported.

Recovery requires the provider's own disaster-recovery mechanism and a live
purpose-separated sign/decrypt challenge. This release has no generic KMS/HSM
client in `runtrue-backup`; it cryptographically verifies the local installation
seed path only. For non-exportable deployments, keep the restored node in safe
mode until the external challenges, public-key continuity, policy review, and
audit evidence are complete. Do not use the activation acknowledgement to
bypass an unavailable provider.

## Current boundaries

- Archives are directory snapshots with digests, not encrypted or signed
  packages.
- Local filesystem blobs are supported; S3/object-store version capture is not.
- Database audit chains are verified automatically, while separately exported
  signed checkpoints require the explicit operator check above.
- The HTTP server enforces safe mode. Any future out-of-process worker with
  direct database access must also check durable recovery state before side
  effects.
