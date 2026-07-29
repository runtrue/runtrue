# Runtrue with Docker Compose

This directory contains the single-node Docker Compose deployment. It is for
local development and evaluation, not a high-availability production setup.

## Requirements

- Linux
- Docker Engine
- Docker Compose v2
- OpenSSL

## Start the base stack

From the repository root:

```sh
deploy/bootstrap.sh

docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  up -d --build --wait
```

The control API listens on `127.0.0.1:8080`.

Check the deployment:

```sh
docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  ps

curl --fail http://127.0.0.1:8080/healthz
```

## Optional Compose files

- `compose.github-app.yml` enables GitHub App integration.
- `compose.github-app-provider.yml` gives a separately built, digest-pinned JWT
  provider image a Docker-only lifecycle.
- `compose.traefik.yml` adds the public HTTPS edge.
- `compose.runner-tls.yml` enables runner enrollment and control TLS.
- `compose.runner-wasm.yml` configures the local WASM runner profile.
- `compose.runner-oci.yml` deploys the same runner image with the explicit
  privileges and state required for rootless Podman OCI execution.
- `compose.runner-combined.yml` applies those OCI settings to the Wasm service
  so one enrolled runner can advertise both backends.
- `compose.autoscaler.yml` enables capacity-aware Docker autoscaling.

Initialize the state needed by the optional services:

```sh
deploy/bootstrap.sh \
  --with-github-app \
  --with-traefik \
  --with-runner-tls

cp deploy/github-app.env.example deploy/state/github-app.env
chmod 0600 deploy/state/github-app.env
```

Edit `deploy/state/github-app.env`, then start the public stack:

```sh
export GITHUB_TOKEN="$(gh auth token)"

docker compose \
  --env-file deploy/state/compose.env \
  --env-file deploy/state/github-app.env \
  -f deploy/compose.yml \
  -f deploy/compose.github-app.yml \
  -f deploy/compose.github-app-provider.yml \
  -f deploy/compose.runner-tls.yml \
  -f deploy/compose.runner-wasm.yml \
  -f deploy/compose.traefik.yml \
  up -d --build --wait
```

Runtrue does not ship or build the JWT provider. Use an independently reviewed
provider that implements the bounded protocol in
[`docs/operations/github-app.md`](../docs/operations/github-app.md). Give only
that provider access to the App private key and no network access. The Runtrue
server mounts the provider directory read-only and receives only its private
Unix socket.
The optional provider overlay enforces those container boundaries and waits
for the image's mandatory health check before starting the server. It does not
select, build, or trust an image for the operator.

After the provider becomes healthy, independently exercise its public contract:

```sh
deploy/github-app-provider-probe.py \
  --socket deploy/state/github-app-provider/provider.sock \
  --app-id "$RUNTRUE_GITHUB_APP_ID" \
  --credential-reference "$RUNTRUE_GITHUB_APP_CREDENTIAL_REFERENCE"
```

## Docker-managed OCI runner

The Wasm and OCI services use the same `runtrue-runner` image and binary. The
Wasm profile remains unprivileged; the OCI overlay adds only the service-level
devices, privileges, configuration, and state required by Podman. A deployment
may run either profile or both without publishing a second runner image.

To use one runner identity for both backends, include the combined overlay
after the Wasm overlay and start its explicit profile:

```sh
docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  -f deploy/compose.runner-tls.yml \
  -f deploy/compose.runner-wasm.yml \
  -f deploy/compose.runner-combined.yml \
  --profile runner-combined-eval \
  up -d --build --wait runner
```

The combined service is privileged because OCI execution requires nested
rootless Podman. Keep the split topology when Wasm jobs must retain the smaller
unprivileged container boundary.

The OCI runner uses a prehydrated, signed Podman image store. Set
`RUNTRUE_OCI_STATE_DIR` to its private absolute state directory and include the
OCI overlay after `compose.runner-tls.yml`:

```sh
export RUNTRUE_OCI_STATE_DIR=/var/lib/runtrue-oci

docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  -f deploy/compose.runner-tls.yml \
  -f deploy/compose.runner-oci.yml \
  up -d --build --wait runner-oci
```

The directory must be owned by `RUNTRUE_RUNTIME_UID:RUNTRUE_RUNTIME_GID` with
mode `0700`. It contains the enrolled identity, runner CA, capsule and image
verification keys, default-deny seccomp policy, runtime environment, signed
manifests, and the preloaded Podman graph store described in the runner README.
The one-shot `runner-oci-enroll` profile uses `enrollment.token` in that same
directory.

Only the OCI runner service is privileged because it launches nested rootless
containers. Both the runner and Podman execute as the configured non-root uid.
Docker enforces the aggregate 6 GiB memory, 2 CPU, and 768 PID defaults for the
single-concurrency service. Nested Podman cgroups are disabled, avoiding a
systemd user-manager dependency while retaining the outer Docker limits.

## Autoscaling

Before enabling autoscaling, create a scoped autoscaler API token at
`deploy/state/runner-secrets/autoscaler.token` and configure the runner pool's
scaling policy and template. The Docker template example is
`autoscaler-docker-template.json.example`.

Then validate the state and add the autoscaler overlay:

```sh
deploy/bootstrap.sh --with-runner-tls --with-autoscaler

docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  -f deploy/compose.runner-tls.yml \
  -f deploy/compose.runner-wasm.yml \
  -f deploy/compose.autoscaler.yml \
  up -d --build --wait
```

Only the autoscaler receives the Docker socket. Autoscaled runners are created
as non-root, read-only containers with bounded CPU, memory, and process limits.

## Common commands

```sh
# Logs
docker compose --env-file deploy/state/compose.env -f deploy/compose.yml logs -f

# Stop containers without deleting state
docker compose --env-file deploy/state/compose.env -f deploy/compose.yml down

# Validate deployment files
deploy/tests/validate.sh
```

Persistent data and credentials live in `deploy/state/`, which is ignored by
Git. Do not use `docker compose down -v` for this deployment.
