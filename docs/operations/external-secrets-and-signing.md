# External secrets and local signing

Runtrue treats a secret-provider call and a signing operation as privileged
control-plane effects. Neither interface is a general-purpose HTTP client, a
workload credential source, or a way to export a signing key. This runbook covers
the bounded Vault/OpenBao KV v2 transport and the local Ed25519 signer adapter.

## Vault/OpenBao trust configuration

Production endpoints must use `https://`. Construct the hardened transport with
an explicit, reviewed PEM CA bundle for that Vault/OpenBao installation. The
transport configures rustls with only those certificates: it does not add the
platform store, WebPKI roots, a native-TLS fallback, or a certificate-verification
bypass. Treat a CA-bundle change as a security-sensitive configuration change and
review it like a provider endpoint change.

The transport also enforces these network rules:

- environment proxies are disabled;
- redirects are not followed;
- every address returned by DNS must be public; a mixed public/private answer is
  rejected as a unit;
- direct private, loopback, link-local, documentation, multicast, and other
  special-purpose addresses are rejected;
- the configured origin is pinned for every request;
- connect, send, receive, and total deadlines are fixed and bounded;
- request headers and request/response bodies have fixed byte limits.

An explicit `LoopbackTestOnly` mode exists for integration tests that bind an
exact `127.0.0.1` or `::1` listener over HTTP. Never enable it in a production
configuration. It accepts neither hostnames nor non-loopback answers and cannot
silently become a remote HTTP transport.

Vault tokens must come from an explicitly constructed token source. The library
does not inspect environment variables, home-directory files, cloud instance
metadata, or CLI configuration. Prefer a short-lived workload/AppRole source;
the static token source is intended for isolated installations and tests. Token
values and provider response bodies are zeroized when dropped and redacted from
`Debug` and errors.

Register providers under explicit identifiers. There is no default-provider
fallback: an unknown provider identifier, duplicate registration, or metadata
whose provider identifier does not match its registry lane fails closed. A
lease remains bound to its durable release ID and subject digest, configured
provider, tenant, repository, run, runner, secret metadata, execution lease,
fencing generation, installation epoch, job attempt, step, purpose, provider
version, and expiry. When a provider returns a lease identifier, call `revoke`
during normal cleanup and cancellation. Record and alert on the registry's
aggregate lease, revoke, failure, and rejection counters without adding secret
names, provider references, or values as metric labels.

## Runner external-secret broker boundary

The runner-facing request continues to carry only the declared secret metadata
ID and its authenticated lease/fence/job-attempt/step/purpose envelope. It does
not carry a provider identifier, provider URL, provider reference, or provider
credential. The server-side authority must resolve those values from the exact
active Capsule and tenant-owned metadata after checking the running step,
privileged approval, environment policy, runner posture, installation epoch,
and current fence. Cross-tenant failures must be resolved before provider or
secret existence is disclosed.

The `ExternalSecretRunnerBroker` then enforces this order:

1. obtain that trusted authorization grant;
2. compute the domain-separated release-subject digest;
3. durably reserve the exact release ID and subject before provider I/O;
4. dispatch through the explicitly named registry lane, with no default;
5. verify every returned metadata binding against the reservation;
6. durably record provider lease/version metadata;
7. only then return plaintext to the existing one-use envelope and redaction
   path.

An exact replay of a delivered release is recognized but never returns
plaintext again. Reuse of a release ID with a changed provider, reference,
tenant, attempt, fence, step, purpose, or expiry conflicts. A restart with only
a `reserved`, `revoking`, or `indeterminate` record fails closed and requires a
bounded reconciliation worker; the broker does not guess that repeating an
arbitrary provider side effect is safe. If the delivered-state commit fails,
the broker attempts bounded explicit revocation and leaves an indeterminate
record. Operator metrics distinguish rejection, provider failure, journal
failure, denied exact replay, and indeterminate recovery without secret data.

The concrete durable authority/journal implementation is intentionally not in
this slice. Migration 24 must extend the control-plane runner-secret journal to
store an optional external provider identity/reference digest, provider lease
ID/version, release-subject digest, job attempt/fence/epoch, and recovery state.
The current table requires a built-in `secret_version` and cannot safely encode
those facts. Until that migration and runner-service adapter exist, do not
configure external metadata as remotely releasable; the built-in broker's
current rejection remains authoritative.

### CA rotation

1. Obtain the new CA bundle through the installation's reviewed configuration
   channel; do not fetch it from the target endpoint during startup.
2. Validate the new bundle and endpoint in a isolated validation installation.
3. During an overlap window, deploy a reviewed bundle containing the required
   old and new trust anchors.
4. Rotate the Vault/OpenBao server certificate.
5. Remove the retired CA in a second reviewed deployment.

A malformed, empty, oversized, or certificate-free bundle is a startup error.
Do not work around rotation failures by enabling the platform trust store,
disabling verification, adding a proxy, or switching to HTTP.

## Local non-exportable signer

The local adapter accepts a 32-byte Ed25519 seed through an explicit sensitive
constructor and keeps it only inside the adapter. It exposes the derived public
verification key, key identifier, algorithm, purpose, and signatures; it has no
private-key export or serialization API. It never discovers a key from ambient
credentials and does not fall back to another signer.

Place the signer's SQLite effect ledger on durable storage with ownership and
permissions appropriate for key-service state. Before computing a signature,
the adapter durably reserves `(request_id, payload_digest, key_id, algorithm)`.
After signing it durably stores the exact signature. On restart:

- an exact signed request returns the stored, verified signature;
- an exact reserved request is recovered with deterministic Ed25519 signing;
- reuse of a request identifier with different bytes, key, or algorithm is
  rejected;
- corrupt or unverifiable ledger rows fail closed.

This ledger is separate from the broker's approval/audit ledger. The two layers
together handle a lost provider response and a lost caller response: neither
case authorizes a changed request or produces a new observable signature. Back
up the effect ledger consistently with the control-plane database. Do not edit
rows manually; restore or quarantine the signer if integrity validation fails.

The adapter applies a fixed payload-size bound and stores only digests,
identifiers, state, and public signature bytes. Key material and payload bytes
must never appear in the database, metrics, logs, crash reports, or audit event
payloads. Alert on conflicts, recovery attempts, ledger failures, and audit
failures.

## Current scope and readiness

This slice supplies the provider registry, hardened Vault/OpenBao transport, and
durable local signing adapter, plus the fail-closed external-secret broker
contract and adversarial adapter tests. The concrete migration-24 journal,
runner-service wiring, lifecycle-wide revocation worker, HA ownership, real
OpenBao fault-injection tests, external KMS/HSM adapters, and operational
restore drills remain integration work.

No signing RPC is added by this slice. A safe RPC needs migration-24 environment
and deployment gates, exact approval and artifact/provenance lookup, signer
policy state, and a durable signing-result adapter. It must be an additive
protocol-v2 capability coordinated with N/N-1 compatibility work; it must not
accept those authorities from a workload or reinterpret protocol v1. Until
those gates and the remainder Capsule's L2/L3 adversarial suites pass, R10 is not
production-ready and must not be reported as complete.
