# Single-node evaluation deployment runbook

The runnable Docker Compose assets, bootstrap procedure, state layout, backup
commands, opt-in runner enrollment profile, validation, and security boundaries
are maintained in
[`deploy/README.md`](../../deploy/README.md).

Use that package only for a one-host evaluation, integration environment, or
isolated recovery drill. The default API publication is plaintext HTTP on
`127.0.0.1`; it is not a production ingress design. Do not expose it by changing
the bind address. A non-loopback deployment needs a reviewed HTTPS issuer and
ingress, network access policy, certificate lifecycle, scoped operator tokens,
off-host encrypted backups, alerting, and an independently tested restore
procedure.

For authenticated outbound source refresh and durable provider checks, follow
the separate [`GitHub App source and check projection`](github-app.md) runbook.
It requires a non-exportable local signer and explicit outbound network policy;
the default Compose network is intentionally internal and does not enable this
mode.

Before handling durable data, also complete the full
[`single-node backup and restore`](single-node-backup-restore.md) runbook. For
offline installations, apply the signed import and quarantine requirements in
[`air-gapped deployment`](air-gapped-deployment.md); the Compose build's pinned
base-image references still need to be mirrored and verified in the offline
registry.
