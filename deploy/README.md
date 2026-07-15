# Runtrue single-node evaluation deployment

This directory is a runnable, security-biased deployment package for the v0.1
SQLite control plane. It is suitable for local evaluation, integration testing,
and recovery drills on one Linux host. It is not an HA topology, a production
TLS termination design, or a substitute for a dedicated runner security
boundary.

The default Compose deployment starts only `runtrue-server`. Its HTTP port is
published on `127.0.0.1`, the container network is internal, and no host
container-runtime socket or device is mounted. The backup utility and local
runner-control experiment are explicit profiles.

## Host prerequisites

- Linux with a reachable Docker Engine 24 or newer and Docker Compose v2.20 or
  newer. Rootless Docker is preferred where it works for the host.
- Bash 4+, OpenSSL 3, and GNU `coreutils`, `findutils`, and `grep`.
- Go 1.24 or newer when the GitHub App integration is enabled.
- Enough disk for a release Rust build and retained SQLite backups. The first
  image build compiles the workspace and can take several minutes.
- A checked-out source tree with the exact `Cargo.lock` being evaluated.

The server, runner, and backup Containerfiles use named BuildKit caches for the
Cargo registry, Cargo Git checkouts, and Rust release artifacts. These caches
are shared across image builds on the same builder and locked so parallel
builds cannot mutate them concurrently. The pinned build toolchain also avoids
installing development-only formatter and linter components during an image
build. Cargo still performs its normal dependency and fingerprint validation,
and `--locked` remains enforced.

Use `docker buildx du` to inspect cache usage. Build caches are
non-authoritative and may be removed to reclaim disk, but `docker builder
prune` affects the entire selected builder and should only be run
intentionally.

The Containerfiles use Rust 1.94.0 and Debian bookworm images pinned by
multi-platform manifest digest. Cargo is invoked with `--locked`. Runtime
images install no packages from a moving package repository. To reproduce an
image bit-for-bit, also fix the build platform, BuildKit version, source-tree
digest, and `RUNTRUE_REVISION`; multi-platform manifest pins do not make build
metadata or cross-architecture output identical.

## Bootstrap and start

The bootstrap creates a private host state tree, a 256-bit bootstrap bearer
token, and the 32-byte installation seed. Random values come from OpenSSL's OS
CSPRNG. Existing credentials are validated and never replaced. Existing
symlinks, hard-linked credentials, wrong owners, or any managed group/world
permissions fail closed.

Run bootstrap as the unprivileged account that will run the containers. If it
is deliberately run as root, the default runtime identity is numeric
`10001:10001`; override both `RUNTRUE_RUNTIME_UID` and `RUNTRUE_RUNTIME_GID` only
before first initialization.

```sh
chmod 0700 deploy/bootstrap.sh
deploy/bootstrap.sh

docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  build --pull

docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  up -d --wait server

curl --fail --silent --show-error http://127.0.0.1:8080/healthz
curl --fail --silent --show-error http://127.0.0.1:8080/readyz
```

`--pull` verifies the pinned base manifests are available; it cannot silently
move the digest. Set `RUNTRUE_IMAGE_REVISION` in `deploy/state/compose.env` to the
reviewed source revision before a release build. The generated file is mode
`0600`; changing it is an explicit operator action, and a later bootstrap will
refuse a mismatching file rather than rewriting it.

The API uses the exact current server variables:

- `RUNTRUE_LISTEN=0.0.0.0:8080` only inside the container;
- `RUNTRUE_DATABASE=/var/lib/runtrue/server/control-plane.sqlite`;
- `RUNTRUE_BOOTSTRAP_TOKEN_FILE=/run/runtrue-secrets/bootstrap.token`;
- `RUNTRUE_SECURITY_KEY_FILE=/var/lib/runtrue/server/security.key`; and
- `RUNTRUE_OIDC_ISSUER=http://127.0.0.1:8080/oidc`.

The host publication remains `127.0.0.1`. Do not change it to `0.0.0.0` to
make the service remote. Put a reviewed TLS proxy or private access gateway in
front, set the externally correct HTTPS OIDC issuer, and define authentication,
firewall, certificate rotation, and backup policy first.

## GitHub App / GitHub Enterprise Server Compose overlay

The server image includes the HTTPS Git client and helper libraries copied
from the same digest-pinned Rust/Debian build image. The final runtime stage
does not run `apt` or resolve moving package versions. Source mirrors remain
under the authoritative private server mount at
`/var/lib/runtrue/server/git-mirrors`.

Initialize the additional webhook, browser-cookie, and mirror state:

```sh
deploy/bootstrap.sh --with-github-app

cp deploy/github-app.env.example deploy/state/github-app.env
chmod 0600 deploy/state/github-app.env
${EDITOR:-vi} deploy/state/github-app.env
```

The example defaults to GitHub Enterprise Server. For GitHub.com, replace the
web/API origins with `https://github.com` and `https://api.github.com`.
`RUNTRUE_PUBLIC_ORIGIN` must be the externally reachable HTTPS origin of this
Runtrue deployment.

Before starting Compose, build and test the first-party GitHub App signer from
`components/github-signer`, then run it at the
absolute host path in `RUNTRUE_GITHUB_SIGNER_SOCKET`. The socket must be a Unix
stream socket, owned by root or the numeric Compose runtime uid, with exact
mode `0600`. Compose bind-mounts only that socket, read-only; it never mounts an
App private key into the Runtrue server container. The signer process and
private-key lifecycle remain an independently isolated security boundary described in
[`docs/operations/github-app.md`](../docs/operations/github-app.md).

```sh
(
  cd components/github-signer
  go test ./...
  CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -buildid=' \
    -o runtrue-github-signer .
)
```

Use the exact environment and readiness command in
`components/github-signer/README.md`. Run the signer with networking disabled,
as the same numeric uid as the server, and give only the signer read access to
the private key.

Build and start the GitHub-enabled server:

```sh
docker compose \
  --env-file deploy/state/compose.env \
  --env-file deploy/state/github-app.env \
  -f deploy/compose.yml \
  -f deploy/compose.github-app.yml \
  build --pull server

docker compose \
  --env-file deploy/state/compose.env \
  --env-file deploy/state/github-app.env \
  -f deploy/compose.yml \
  -f deploy/compose.github-app.yml \
  up -d --wait server
```

Configure the GitHub App with:

```text
Setup URL:   https://runtrue.example.com/auth/github/app/callback
Webhook URL: https://runtrue.example.com/webhooks/github
```

Use the actual `RUNTRUE_PUBLIC_ORIGIN`, not the example hostname. The overlay
adds one ordinary bridge network named `scm-egress` because the base evaluation
network is deliberately internal. Only the server joins this egress network;
no container-runtime socket, host network, additional published port, private
key, or ambient Git credential is introduced. Hardened DNS and HTTPS checks
still reject private/special addresses, redirects, proxies, and untrusted
certificates.

To use the bootstrap principal without placing its bearer value in a process
argument, pass the header on standard input to `curl`:

```sh
curl --fail --silent --show-error --config - <<EOF
url = "http://127.0.0.1:8080/api/v1/repositories"
header = "Authorization: Bearer $(tr -d '\r\n' < deploy/state/secrets/bootstrap.token)"
EOF
```

The expansion is not printed, but it is present in the shell and curl process
memory. Prefer a short-lived, minimally scoped API token after initial setup.
Never commit `deploy/state`, export the bootstrap token into a global shell
environment, or paste it into logs.

## Runtime confinement and state

Compose applies a non-root numeric identity, read-only root filesystem, all
capabilities dropped, `no-new-privileges`, bounded tmpfs mounts, PID/FD/CPU/
memory limits, and an internal bridge. The server receives write access only
to the database directory. The installation key is a nested read-only file
mount inside that directory (its parent must remain writable because server
startup verifies and normalizes the parent mode); the bootstrap token directory
is a separate read-only mount.

The Containerfiles define different fallback image users (`10001`, `10002`,
and `10003`), but Compose deliberately overrides them with the single
unprivileged host uid/gid recorded by bootstrap so rootless bind-mounted files
remain accessible without privileged ownership changes. Server, runner,
workspace, secret, key, and backup paths are still separate mounts, but that
path separation is not Unix-user isolation: a host compromise of the shared
uid can read all state owned by it. Use the systemd deployment's distinct
`runtrue-server` and `runtrue-runner` users, or separate runner hosts, when an
independent host identity is required.

Managed paths under `deploy/state` are:

| Path | Purpose | Backup treatment |
| --- | --- | --- |
| `server/` | SQLite database, journals, and authoritative blobs | Capture online with `runtrue-backup`, including `server/blobs` |
| `keys/security.key` | installation seed | Separate protected recovery escrow; not copied automatically |
| `secrets/bootstrap.token` | installation-wide bootstrap bearer | Rotate/restrict; do not put in ordinary archives |
| `recovery-config/` | reviewed non-secret recovery configuration | Included when requested |
| `backups/` | private backup archives | Move to encrypted, access-controlled storage |
| `restores/` | isolated restore-drill targets | Never point the live server at one before verification |
| `runner*`, `workspaces/`, `tls/` | opt-in runner evaluation state | Runner cache/workspaces are not authoritative backups |

`RUNTRUE_DATA_ROOT` points the server at `server/blobs`, inside the authoritative
server bind mount. Both Compose and systemd backup commands pass that exact
directory as `--blobs-dir`; omitting it would produce an incomplete recovery
archive. Runner caches and workspaces remain non-authoritative and excluded.

## Backup, verify, and restore drill

Create archive names from a trusted clock and ensure the destination does not
already exist:

```sh
backup_id=$(date -u +%Y%m%dT%H%M%SZ)
docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  --profile tools run --rm backup create \
  --database /var/lib/runtrue/server/control-plane.sqlite \
  --blobs-dir /var/lib/runtrue/server/blobs \
  --config-dir /etc/runtrue/recovery-config \
  --security-key-file /run/runtrue-keys/security.key \
  --output "/var/backups/runtrue/${backup_id}"

docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  --profile tools run --rm backup verify \
  --backup "/var/backups/runtrue/${backup_id}" \
  --security-key-file /run/runtrue-keys/security.key
```

Record the reported manifest digest outside the archive. The archive is
digest-checked but neither encrypted nor signed.

For a drill, restore into an absent target under the dedicated restore mount:

```sh
restore_id="drill-${backup_id}"
docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  --profile tools run --rm backup restore \
  --backup "/var/backups/runtrue/${backup_id}" \
  --target "/var/lib/runtrue/restores/${restore_id}" \
  --security-key-file /run/runtrue-keys/security.key
```

Do not copy that database over `state/server`. A restore intentionally enters
durable safe mode and increments the fencing epoch. Follow the independent
checks and explicit activation procedure in
[`docs/operations/single-node-backup-restore.md`](../docs/operations/single-node-backup-restore.md).

## Opt-in local runner TLS and enrollment

The runner-control implementation now has separate ports for mTLS control and
TLS-server-auth-only one-time enrollment. Generate the local evaluation PKI
only when exercising that path:

```sh
deploy/bootstrap.sh --with-runner-tls

docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  -f deploy/compose.runner-tls.yml \
  up -d --wait server
```

This creates an Ed25519 local CA and a 30-day server certificate for `server`,
`localhost`, and `127.0.0.1`. The control listener is `8443`; enrollment is
`8444`. Neither is published to the host. The CA private key is mounted into
the server because the current control plane signs enrolled and rotated runner
certificates. Runner services receive only the public `runner-ca.pem` as an
exact read-only file mount; the CA and server private keys are never mounted
into a runner workload. The one-time enrollment bearer is also an exact
read-only file mount on `runner-enroll` only and is absent from the long-running
runner daemon. Treat this self-signed PKI as disposable evaluation material,
not a production PKI design.

Runner enrollment is intentionally not claimed as turnkey. Before starting a
runner, an operator must provision a tenant-owned runner-pool record, issue its
one-time enrollment token through
`POST /api/v1/runner-pools/{pool}/enrollment-tokens`, atomically save only the
returned `token` value as
`deploy/state/runner-secrets/enrollment.token` with owner equal to the Compose
runtime uid/gid and exact mode `0600`, and install the server Capsule-verification
public key as a raw 32-byte or 64-character hex mode-`0600` file under
`deploy/state/runner-trust/capsule-keys`. The v0.1 HTTP API lists runner pools but
does not create them or export the Capsule public key, so those two trust anchors
must currently be provisioned by an installation tool or operator workflow.
Do not scrape private installation seed material to work around that boundary.

After those prerequisites:

```sh
docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  -f deploy/compose.runner-tls.yml \
  --profile runner-enroll run --rm runner-enroll

rm -- deploy/state/runner-secrets/enrollment.token

docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  -f deploy/compose.runner-tls.yml \
  --profile runner-native-eval up -d server runner
```

The profile name is deliberate: it enables `RUNTRUE_RUNNER_TRUSTED_NATIVE=true`.
Native job processes share the runner's Unix identity and are not a sandbox;
run only reviewed workflows on a disposable host. The internal Compose network
also denies normal outbound Internet access.

The runner image does not include Podman. Current OCI execution requires an
absolute rootless Podman binary plus a private state root, default-deny seccomp
profile, prehydrated image store, allowlisted runtime environment, signed image
manifest directory, and verification keyring. Rootless Podman nested inside a
read-only, capability-free container additionally depends on host user
namespaces, cgroup delegation, storage drivers, and networking that this
package has not validated. Use a dedicated Linux runner host or build a
reviewed derivative image. Never make it work by mounting `docker.sock`,
`podman.sock`, or by setting `privileged: true`.

## Hardened systemd examples

`deploy/systemd` contains static, distinct `runtrue-server` and `runtrue-runner`
users, tmpfiles declarations, non-secret environment templates, services, an
online backup template, and an optional same-host runner TLS drop-in. They use
systemd credentials for bearer and private-key files and enforce private state
directories, empty capability sets, read-only system paths, namespace/kernel/
device protections, IP policy, and resource ceilings.

Install into a staging host and review the paths before enabling anything:

```sh
sudo install -D -m 0755 target/release/runtrue-server /usr/libexec/runtrue/runtrue-server
sudo install -D -m 0755 target/release/runtrue-runner /usr/libexec/runtrue/runtrue-runner
sudo install -D -m 0755 target/release/runtrue-backup /usr/libexec/runtrue/runtrue-backup
sudo install -D -m 0644 deploy/systemd/runtrue.sysusers /usr/lib/sysusers.d/runtrue.conf
sudo install -D -m 0644 deploy/systemd/runtrue.tmpfiles /usr/lib/tmpfiles.d/runtrue.conf
sudo systemd-sysusers /usr/lib/sysusers.d/runtrue.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/runtrue.conf
sudo install -m 0644 deploy/systemd/server.env.example /etc/runtrue/server.env
sudo install -m 0644 deploy/systemd/runtrue-server.service /etc/systemd/system/runtrue-server.service
```

Create the bootstrap credential once without shell tracing or overwrite:

```sh
sudo bash -c 'set -o noclobber; umask 077; openssl rand -hex 32 > /etc/runtrue/credentials/bootstrap.token'
sudo systemctl daemon-reload
sudo systemctl enable --now runtrue-server.service
```

The server creates `/var/lib/runtrue-server/security.key` once with mode `0600`.
Escrow it separately. Inspect effective confinement with
`systemd-analyze security runtrue-server.service` and tailor `IPAddressAllow`,
memory, tasks, and file-descriptor ceilings to the reviewed host.

For the same-host runner experiment, install the four evaluation PKI files
under `/etc/runtrue/pki` as root mode `0600`, install
`runtrue-server-runner-tls.conf` as
`/etc/systemd/system/runtrue-server.service.d/runner-tls.conf`, and restart the
server. Install `runner.env.example`, a runner Capsule key, and a one-time
enrollment token with the owners/modes declared by `runtrue.tmpfiles`; run
`runtrue-runner-enroll.service` once, delete the source enrollment token, then
enable `runtrue-runner.service`. Both gRPC listeners and the provided IP policy
stay loopback-only.

Create a timestamped online backup with:

```sh
sudo systemctl start "runtrue-backup@$(date -u +%Y%m%dT%H%M%SZ).service"
```

Do not add an automatic timer until retention, off-host transfer, independent
manifest-digest recording, failure alerting, and restore drills are defined.

## Validation and current limits

Run the deployment-specific checks with:

```sh
deploy/tests/validate.sh
```

They validate shell syntax, fixed permissions, security assertions, digest
pins, Compose models when Compose is installed, systemd unit syntax when
available, bootstrap idempotence/non-disclosure, TLS consistency, and rejection
of symlinks and insecure modes. Full image builds remain a separate, slower
gate.

This package deliberately does not claim:

- high availability, live database failover, object-storage durability, or
  automated backup retention;
- production TLS termination, public ingress, external certificate lifecycle,
  or a hardened remote runner network;
- a turnkey runner-pool/capsule-key provisioning API; or
- supported rootless Podman-inside-container execution.

Those boundaries are safer than silently adding a host socket, a privileged
container, mutable image tags, public plaintext API exposure, or placeholder
configuration names.
