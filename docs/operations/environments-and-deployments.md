# Environments, deployments, and external-effect recovery

Migration 24 adds the durable control-plane boundary for external provider
configuration, protected environments, deployment gates, external-secret
release reconciliation, and signing-result replay. This is a storage and
scheduler vertical slice. It is below the remainder Capsule's L2/L3 completion
bar: public environment/deployment APIs, runner broker RPC wiring, real
OpenBao/HSM end-to-end evidence, and deployment UI are still required.

## Provider and signer configuration

Provider configurations are tenant-owned and have one capability:
`external-secret` or `signing`. External-secret endpoints are explicit HTTPS
origins. Signing endpoints are explicit HTTPS origins or reviewed absolute
Unix-socket endpoints. Proxies, redirects, ambient environment credentials,
home-directory profiles, instance identity, and repository-supplied endpoints
are not configuration sources.

Credential references use a server-owned grammar:

- `secret-metadata://IDENTIFIER` for a provider credential stored through the
  encrypted control-plane secret boundary;
- `signer-identity://IDENTIFIER` for a non-exportable signer identity.

Raw tokens, secret values, and private keys have no migration-24 column. A
provider ID is semantically immutable: endpoint, credential reference, trust
bundle, provider kind, and public key cannot change in place. Rotation creates
a new ID. Status changes create append-only provider-version snapshots.

Signer policies map the workflow-visible opaque `key-policy` ID to one exact
provider generation and `signer-key://IDENTIFIER` backend reference. Debug
output redacts backend references. The signed step must declare the exact
purpose, operation, and key policy; a job-level permission alone is not
sufficient.

## Environment gates

An environment version snapshots its target identity, active policy epoch,
provider IDs, approval rule digest and TTL, artifact classification/scan and
promotion requirements, wait timer, concurrency limit, deployment actors, and
allowed signer policies. `deployment-target://IDENTIFIER` is non-credential
identity material and is converted to a domain-separated target digest.

A deployment request binds all of the following before approval:

- tenant, repository, environment version, and policy epoch;
- deployer run, job, attempt, and exact signed Capsule digest;
- producer run, job, attempt, immutable artifact, manifest, provenance, and
  optional promoted-record identity;
- target digest, rollback ancestry, approval rule/subject, and new approval ID.

The scheduler does not offer a job whose signed Capsule declares an environment
until the exact request has passed its timer and approval and owns a current
concurrency gate. Lease creation and gate binding occur in one SQLite
transaction. The gate is extended through the execution hard deadline and is
released only by terminal deployment reconciliation. Restore safe mode, stale
installation epochs, expired gates, stale lease fences, changed policy,
disabled providers, retired/quarantined artifacts, failed scan state, and
changed evidence fail closed.

Rollback is a new deployment request. It must name a succeeded deployment and
use a different one-shot approval whose subject binds the rollback ancestry;
an earlier approval is never reused.

## Restart and reconciliation

The append-only `deployment_request_events`, `environment_versions`, provider
versions, and signer-policy versions allow exact state reconstruction across
restart. An expired unbound concurrency gate is journaled and can be reacquired
under a higher environment fence. A gate already bound to a live lease is not
expired by the pre-lease timer.

`external_secret_release_journal` stores a canonical plaintext-free reservation,
provider-reference digest, exact provider generation, lease/fence/attempt/epoch,
and bounded provider lease metadata needed for revoke. It never stores the
released value or provider token. Delivered, revoking, revoked, and
indeterminate transitions are exact-compare and bounded to eight journal
attempts. Indeterminate entries require operator/provider reconciliation; do
not issue the secret again.

`signing_result_journal` reserves the exact signed-step request before signer
I/O and stores only the public signature/certificate/attestation result. A lost
caller response returns the same completed result; a changed request ID
conflicts. The production runner signing RPC remains disabled until the server
adapter consumes this authority and the non-exportable backend in one tested
end-to-end path.

## Operator checks

Before enabling an environment:

1. Verify the active tenant policy epoch and immutable environment version.
2. Verify provider CA/public-key digests and append-only generation snapshots.
3. Verify the exact approval rule digest, one-shot behavior, TTL, target, scan,
   promotion, and signer-policy requirements.
4. Keep restore safe mode enabled until provider, policy, audit, runner, and
   signing continuity checks pass.
5. Reconcile `indeterminate` external releases and `reserved`/`signed` signing
   entries before retrying workers.

The low-cardinality deployment metrics report request counts, ready requests,
active concurrency gates, succeeded/failed deployments, release entries that
still require revoke/reconciliation, and durable signing results. IDs and
digests may appear in audit metadata; provider values, tokens, key references,
signatures, and response bodies must not be metric labels or error strings.

