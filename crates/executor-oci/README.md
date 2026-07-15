# Runtrue rootless OCI executor

This backend executes Linux OCI jobs through a local, absolute `podman` binary
running as a non-root host user. Job and service images must be digest-only
references and must exactly match an image-admission result, including signing
identity and platform. The executor never pulls during execution and has no
Docker/containerd socket fallback.

An OCI workflow job must declare `runner.image`. The compiler resolves that
logical reference through the job's exact OS/architecture entry in
`.runtrue.lock`, writes the digest-only result into the execution capsule, and binds
the digest into the approval subject. `preflight_capsule` requires the configured
job-image assignment to equal that planned reference byte-for-byte. Legacy
capsules can still be decoded when the field is absent, but OCI preflight rejects
them before image admission or runtime activity.

Production callers may configure a prehydrated Podman `image_store`. Podman
uses it through `--imagestore` while container metadata and writable layers
remain in the private per-job graph root. This is required when immutable
images are shared across otherwise isolated job roots.

## Service lifecycle

Callers register a locked job image with `insert_job_image` and each locked
service image with `insert_service_image`, then call `preflight_capsule`. Preflight
rejects missing, unused, mismatched, tagged, unverified, or wrong-platform image
assignments before any runtime command is issued. Each step request repeats the
planned runner requirements and is checked against the same exact job-image
assignment, so request construction cannot substitute an image after capsule
preflight.

On the first step of a job attempt, the executor:

1. creates a rootless `--internal` bridge in that attempt's private runtime
   state;
2. starts every service, in capsule order, before the job container;
3. attaches services under their validated DNS-label IDs without publishing
   host ports;
4. runs declared health checks with bounded commands, retries, per-attempt
   timeouts, cancellation, and one overall startup deadline; and
5. attaches each job step only to the same private network.

Services have a read-only root, a bounded tmpfs, private PID/IPC namespaces,
rootless user namespaces, seccomp, no-new-privileges, no capabilities, and no
host mounts/devices/sockets. Declared ports use OCI `expose` metadata only; no
`publish`/host-port argument is emitted. With no services, steps retain
`--network=none`.

The shared engine calls the fail-closed `finish_job_attempt` executor hook once
for every started attempt before reporting its outcome or beginning a retry.
OCI routes that hook to `finish_job(job_id, attempt)`, which force-removes and
then proves the absence of all containers before removing and proving the
absence of the network. Direct users of `execute_request` must invoke
`finish_job` themselves for successful attempts. Startup errors,
runtime-supervision errors, and cancellation also clean up immediately; `Drop`
is a final best-effort guard.

After an unclean process restart, `recover_abandoned_job_state` uses the same
private graph/run roots to force-remove all containers and anonymous volumes,
prune volumes and internal networks, and prove all three resource sets empty.
Only then does it delete abandoned state. Recovery output, process lifetime,
and process-group cleanup are bounded; uncertainty preserves state and fails.

Service environment values are written to mode-0600, no-follow ephemeral files
and never interpolated into runtime arguments. The current step execution API
does not carry resolved service bindings, so this backend deliberately accepts
literal service environment values only. Dynamic/secret-backed service values
fail during preflight until the engine exposes a job-scoped resolved-service
handoff; they are never guessed or silently omitted.
