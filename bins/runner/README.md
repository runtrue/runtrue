# Runtrue runner

`runtrue-runner` enrolls with a one-time token and automatically rotates its
short-lived mTLS identity. The Ed25519 private key is generated locally; only a
signed PKCS#10 request is sent to the control plane.

Current enrollment responses include the server-authoritative posture digest
derived from the durable accepted inventory and pool binding. The runner uses
that value for its first authenticated Open session. During a rolling upgrade,
an older server may omit this additive field and the runner retains its legacy
locally derived posture behavior; older runners ignore the new field.
Enrollment also advertises generations 1–2 while retaining `1` in the shipped
singleton inventory field for an old server. The server-owned newest-common
selection is persisted in the credential generation and reused for every
Hello. Direct certificate/key provisioning requires `--protocol-version`; a
runner never guesses from the endpoint. See
[`runner-protocol-upgrades.md`](../../docs/operations/runner-protocol-upgrades.md)
for legacy credential upgrades and the generation-one drain procedure.

For non-loopback control planes, the endpoint must be HTTPS and all of the CA,
client certificate, and client private-key files are required. TLS material and
trusted Ed25519 capsule keys must be real, bounded, mode-`0600` files. The capsule
keyring directory must be mode `0700`. Plain HTTP is accepted only for a
numeric loopback IP together with `--insecure-loopback`.

The runner supports four commands:

- `enroll` connects only to the TLS-server-auth enrollment listener and
  atomically installs the returned client certificate with its local key.
- `daemon` keeps the authenticated Open stream alive until it is drained or
  the stream fails.
- `once` accepts and completes one eligible lease, including durable exact
  completion retries.
- `doctor` validates paths, mTLS configuration, trusted signing keys, local
  inventory/posture, protocol selection, and durable state without connecting.

Enrollment requires the server CA, a mode-`0600` token file, and a private
credential directory:

```text
runtrue-runner \
  --enrollment-endpoint https://control.example:8444 \
  --ca-certificate /etc/runtrue/server-ca.pem \
  --enrollment-token-file /run/secrets/runtrue-enrollment-token \
  --credential-directory /var/lib/runtrue/credentials \
  --trusted-native \
  enroll
```

Disposable development and CI workers can add `--ephemeral` to that enrollment
command. The lifecycle choice is stored by the control plane, so subsequent
`daemon` or `once` commands do not repeat the flag. After an ephemeral runner
has been offline for five minutes, scheduler maintenance removes its identity
when it has no lease history. The grace period covers the gap between
enrollment and the first connection. A runner with lease history is retired
from the fleet instead, preserving its addressable audit record. Persistent
enrollment remains the default.

The credential root and immutable generation directories are mode `0700`.
Each private key, certificate chain, metadata document, and the atomic `current`
marker is mode `0600`; the additive `protocol-version` sidecar is also mode
`0600`. Symlinks, partial generations, permissive files, and
key/certificate or runner/pool identity mismatches fail closed. A daemon with
no explicit `--runner-id`/client files loads this current generation. Direct
out-of-band identity remains available only when runner id, certificate, and
key are configured together with an explicit supported protocol generation.

On `RotateCertificateNow`, the runner stops accepting offers. It never abandons
an active lease to swap credentials: work is allowed to finish, or is
cooperatively canceled near the certificate deadline, and its terminal
completion is persisted first. The runner then generates a new local key,
calls the mTLS-fenced rotation RPC, atomically switches generations, reconnects
with the new certificate, and retries any durable completion after reconnect.

Native execution is disabled unless `--trusted-native` is present. Native
preflight rejects unsupported services, protected environments,
cache/artifact handling, secrets, OIDC, components, and other features the
local backend cannot honor. No isolation request is ever substituted with the
native backend.

## Rootless OCI execution

OCI is advertised only when all seven settings below are present and validate:

- `--oci-state-directory`: private mode-`0700` per-lease runtime state root.
- `--oci-podman`: absolute, real, non-group/world-writable Podman executable.
- `--oci-seccomp-profile`: mode-`0600`, default-deny seccomp JSON.
- `--oci-image-store`: mode-`0700`, prehydrated Podman `--imagestore` used with
  `--pull=never`.
- `--oci-runtime-environment`: mode-`0600` JSON object. Only the OCI executor's
  narrow Podman allowlist (`HOME`, `PATH`, `XDG_RUNTIME_DIR`, `TMPDIR`, `LANG`,
  and `LC_ALL`) is accepted.
- `--oci-manifest-directory`: mode-`0700` directory of mode-`0600` signed image
  manifests.
- `--oci-image-keyring`: mode-`0700` directory of mode-`0600` raw or hex
  Ed25519 image-verification keys.

The equivalent environment variables use the upper-case names prefixed with
`RUNTRUE_RUNNER_`, for example `RUNTRUE_RUNNER_OCI_STATE_DIRECTORY`. Partial OCI
configuration is a startup error. Podman must run as a non-root host user.

Each manifest is a Runtrue `SignedImageManifest` with `kind: "oci-image"`. Its
signed `compatibility` map must contain:

```json
{
  "runtrue-capsule-digest": "sha256:<canonical execution-capsule digest>",
  "runtrue-job-id": "build",
  "runtrue-service-id": "$job",
  "runtrue-oci-reference": "registry.example/build@sha256:<digest>",
  "runtrue-signature-identity": "release@runtrue.example"
}
```

`$job` assigns the job image; a service assignment uses the exact service ID.
The signed payload digest and platform must match the immutable reference and
planned runner. The `$job` reference must also equal the digest-only
`capsule.jobs[].runner.image` emitted from the workflow's platform-specific lock
entry; a correctly signed manifest for a different image is rejected. There
must be exactly one assignment for the job and every declared service, with no
stale service assignment for that capsule/job. All manifests are verified at
startup, selected assignments are re-verified before lease acceptance (before
workspace/runtime side effects), and admission re-verifies them when
constructing the per-lease executor.

The remote executor creates an OCI-only dispatcher for an OCI lease. Services
start on an internal per-job network before the job container; job-attempt
finalization proves containers, anonymous volumes, and the network absent
before a retry or terminal result. Cancellation and lease expiry propagate to
the process supervisor and finalization hook. On restart, abandoned private
Podman graph roots are swept and deleted only after Podman proves containers,
volumes, and Runtrue networks absent; an unproven cleanup prevents the runner
from opening its control stream.

Service environment values currently must be capsule literals. Dynamic or
secret-backed service bindings remain fail-closed until the engine exposes a
resolved job-scoped service handoff.

## Firecracker microVM execution

Firecracker is optional and is advertised only when all eleven settings are
present and the production startup preflight succeeds:

- `--firecracker-state-directory`: absolute private recovery/quarantine root.
- `--firecracker-jailer`, `--firecracker-binary`, and
  `--firecracker-reflink-copy`: absolute real executables. The jailer and VMM
  must match the exact size and SHA-256 identity in the runtime profile; none
  may be writable by group/other or reachable through a symlink.
- `--firecracker-jail-root`: absolute mode-`0700` jailer chroot base.
- `--firecracker-cgroup-parent`: nonempty relative cgroup-v2 parent.
- `--firecracker-cid-lock-directory`: absolute mode-`0700` host-wide lock
  directory. The runner holds an exclusive lock for the configured guest CID
  for as long as it advertises microVM support.
- `--firecracker-image-payload-directory`: absolute mode-`0700` directory of
  payloads named by their bare 64-character SHA-256 hex digest.
- `--firecracker-image-manifest-directory`: absolute mode-`0700` directory
  containing exactly one signed kernel, rootfs, and guest manifest, plus
  either both sterile snapshot state/memory manifests or neither.
- `--firecracker-image-keyring`: absolute mode-`0700` directory of mode-`0600`
  raw or hex Ed25519 image-verification keys.
- `--firecracker-runtime-profile`: mode-`0600` strict JSON host/runtime policy.

Environment variables use the corresponding `RUNTRUE_RUNNER_FIRECRACKER_*`
names. A partial group is a startup error. The runtime profile has this shape:

```json
{
  "profile_version": 1,
  "architecture": "amd64",
  "firecracker_version": "1.12.0",
  "firecracker_binary_digest": "sha256:<digest>",
  "firecracker_binary_size_bytes": 123456,
  "jailer_version": "1.12.0",
  "jailer_binary_digest": "sha256:<digest>",
  "jailer_binary_size_bytes": 123456,
  "snapshot_format_version": "1.8.0",
  "cpu_template": "T2",
  "cpu_feature_digest": "sha256:<runner-probed digest>",
  "mitigation_profile_digest": "sha256:<runner-probed digest>",
  "vcpu_count": 2,
  "memory_bytes": 268435456,
  "guest_cid": 42,
  "jailed_uid": 1000,
  "jailed_gid": 1000,
  "guest_vsock_port": 5000,
  "guest_capsule_trust_directory": "/etc/runtrue/capsule-keys"
}
```

The profile's version labels and exact executable digests are one policy
identity. For snapshots, the signed state and memory manifests must also bind
that Firecracker identity, snapshot format, CPU template, normalized host CPU
feature digest, host mitigation digest, vCPU/memory/CID topology, disconnected
network profile, exact in-jail paths, each other, and the exact signed
kernel/rootfs/guest tuple. Both manifests must be in the `sterile` phase.
Tampering, expiry, mixed snapshot halves, incompatible host evidence, or a
missing KVM/vhost-vsock/cgroup controller prevents inventory advertisement.

The runner performs a real `--reflink=always` probe before advertisement,
stages a fresh per-lease COW root, uses one authenticated vsock session for the
exact scheduler-selected job, and forwards the already-verified capsule signature
unchanged for independent guest admission. Cold and snapshot boots use the
profile's exact CPU/memory topology. Every error path terminates and reaps the
complete jailer process group, erases the boot secret, and quarantines state;
successful jobs prove a clean VMM exit and delete their writable layer.
Startup recovery refuses to touch a jail with a live process and quarantines
only proven-abandoned state. No OCI/native fallback exists.

The current guest data plane is intentionally narrow. It accepts only absolute
literal commands and `sh`/`bash` scripts against the image's empty `/workspace`.
Source/workspace mounts, filesystem grants, services, network, secrets, OIDC,
cache, artifact/check operations, dynamic context bindings, and component
actions are rejected before boot until their exact host/guest proxy adapters
exist. The authenticated resource frames emitted during a step are liveness
samples; usage counters remain zero until a pidfd-backed metrics reader is
wired.

[`examples/workflows/microvm-job.yaml`](../../examples/workflows/microvm-job.yaml)
is the currently supported no-data-plane smoke shape. Its CPU and memory must
exactly match the configured runtime profile.

## Embedded Wasm execution

Wasm is advertised only after all five settings are present and a startup
probe verifies and compiles every configured component:

- `--wasm-component-directory`: mode-`0700` directory of mode-`0600`
  preloaded component payloads. A payload is named `<64 lowercase sha256
  hex>.wasm`.
- `--wasm-manifest-directory`: mode-`0700` directory of mode-`0600` canonical
  `SignedImageManifest` JSON files.
- `--wasm-component-keyring`: mode-`0700` directory of mode-`0600` raw or hex
  Ed25519 component-verification keys.
- `--wasm-aot-cache`: absolute private path for HMAC-authenticated Wasmtime AOT
  entries. Missing directories are initialized privately; unsafe paths or
  incompatible cache configuration fail startup.
- `--wasm-runtime-key`: mode-`0600` file containing 64 raw bytes or 128 hex
  characters. The distinct nonzero halves authenticate AOT entries and
  invocation-local capability handles respectively.

The equivalent environment variables are prefixed with `RUNTRUE_RUNNER_`, such
as `RUNTRUE_RUNNER_WASM_COMPONENT_DIRECTORY`. Partial configuration is a startup
error.

For remote execution, a signed Wasm manifest's `name` is the complete immutable
`wasm://...@sha256:<digest>` or `oci://...@sha256:<digest>` component reference.
Its signed payload digest selects the digest-named local file. The manifest
must also exactly match the embedded runtime's component media type, WIT
digest/world, Wasmtime version, target triple, CPU feature floor, architecture,
and validity interval. Every Component action anywhere in the canonical signed
capsule must have an exact local assignment; a matching digest under a different
locator is not interchangeable. No registry lookup, network fetch, mutable
selector, or command/native fallback exists.

Private OCI registries are handled by the provisioning plane, not by the
runner daemon. `runtrue-image stage-component` accepts only an exact OCI
manifest digest, an expected Wasm-layer digest, a digest-pinned ORAS binary,
and, for private registries, an owner-only Docker/ORAS credential file. It
validates the OCI artifact type, single `application/wasm` layer, declared
size, manifest digest, and payload digest before creating the runner's
mode-`0600`, digest-named payload:

```text
runtrue-image stage-component \
  --oras /opt/runtrue/bin/oras \
  --oras-digest sha256:<trusted-oras-digest> \
  --reference registry.example/team/action@sha256:<manifest-digest> \
  --payload-digest sha256:<wasm-layer-digest> \
  --registry-config /run/runtrue/registry/action.json \
  --output /var/lib/runtrue/components/<wasm-layer-digest-hex>.wasm
```

When supplied, the registry config must be a regular, nonsymlink, mode-`0600`
file owned by the invoking user. Its contents are copied into private staging
and are never printed, placed in a Capsule, or passed to a workflow. Use a
registry-scoped, read-only credential and remove the config after provisioning.
The runner still performs its independent signed-manifest and payload checks at
startup.

The startup probe verifies signatures and payloads, compiles every component,
and requires clean authenticated AOT state before adding `wasm` to inventory.
A normal cold compile is accepted and publishes an authenticated entry. A
malformed, incompatible, or unauthenticated existing entry is quarantined and
rebuilt by the executor, but the runner still refuses to advertise Wasm for
that startup so the integrity event cannot be hidden.

After successful preflight, the runner advertises exact component payload
digests as tenant-scoped `wasm-component-warm` or `wasm-component-warmish`
locality. The protocol retains the exact digest union for compatibility and
adds a digest-to-tier binding for graded placement. Scheduler hard
filters still decide runtime, pool, tenant, region, posture, and resources;
locality only prefers an otherwise admissible signed job whose component digest
is already prepared; warm wins over warmish only after those filters. The runner
caps the combined prepared-component and source
snapshot locality list at 256 exact digests.

Remote Wasm leases use the same signed-capsule admission, fencing, cancellation,
workspace cleanup, result hashing, and exact selected-job engine path as other
backends. Only the offered Wasm job is dispatched. Services, command/script
steps, ambient environment, runner capabilities, filesystem/network grants,
and all capabilities without installed WIT adapters fail preflight. The remote
runner installs only its live secret and OIDC broker adapters; the workspace
path is never ambiently exposed to a component.

Secret and OIDC calls are available only to Wasm components through opaque
invocation-local WIT handles declared by the signed step. The runner sends the
step's fenced `running` transition first, then uses the existing mTLS channel
owned by that Open session for a just-in-time broker RPC. Secret requests use a
fresh ephemeral X25519 key, authenticate the complete lease/epoch/job/step/
grant/expiry binding, decrypt the versioned XChaCha20-Poly1305 envelope, and
revoke it before returning. Private keys, plaintext, and tokens are zeroized;
they are never persisted or placed in the environment. The host masks exact
delivered values from component logs and rejects structured output containing
them. Only the precise "running state not observed yet" response is retried;
certificate, fence, capability, replay, and approval failures remain terminal.
Native and OCI jobs carrying secret or OIDC grants are rejected before
execution, with no environment fallback.

Protocol v1 step transitions do not carry a job-attempt number. The remote
runner therefore rejects every selected job with whole-job retries before
accepting its lease, for native, OCI, Wasm, and microVM alike; otherwise a
repeated step identifier could not be fenced unambiguously and one-shot broker
grants could be misinterpreted. Local engine execution retains its bounded
retry behavior.

`LeaseOffer.expires_at` is a rolling server-side heartbeat fence and never
terminates local work by itself. Field 14, `hard_deadline`, is the immutable
runner/guest execution bound; authority ends when `now >= hard_deadline`. An
older v1 server that omits the field is accepted only with the conservative
fallback `hard_deadline = expires_at`.

[`examples/workflows/wasm-job.yaml`](../../examples/workflows/wasm-job.yaml)
and its companion lock file show the workflow-side immutable resolution. The
preloaded signed manifest name for that example is
`wasm://registry.example/runtrue/analyze@sha256:aaaa...` using the complete
64-hex digest from the lock.

The verified memory/storage inventory probes are currently implemented for
Linux runner hosts. Other hosts fail doctor/startup instead of advertising
guessed capacity. A broken authenticated stream cancels active work and
exits; a process supervisor may restart the daemon, at which point durable
terminal completions are retried but incomplete leases are never resumed.

Cache and artifact objects are transferred incrementally. Upload producers and
gRPC use a fixed-depth queue with 256 KiB chunks; downloads write directly to
private staging and enter the local CAS only after exact size and digest
verification. A gap, overlap, oversized chunk, cancellation, or integrity
failure cannot publish partial bytes. Protocol v1 remains negotiated;
generation 2 object framing is a separate, currently unadvertised skeleton.

Protocol v1 does not include a run id in `LeaseOffer`; until a later protocol
generation adds one, bounded `LogFrame.run_id` uses the unique fenced lease id
as its stream scope. Log frames and serialized results have hard byte limits.
No secret broker material is available to native or OCI jobs.
