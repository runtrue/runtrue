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

The API listens on `127.0.0.1:8080` and the frontend on
`127.0.0.1:3000`.

Check the deployment:

```sh
docker compose \
  --env-file deploy/state/compose.env \
  -f deploy/compose.yml \
  ps

curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:3000/frontend-healthz
```

## Optional Compose files

- `compose.github-app.yml` enables GitHub App integration.
- `compose.traefik.yml` adds the public HTTPS edge.
- `compose.runner-tls.yml` enables runner enrollment and control TLS.
- `compose.runner-wasm.yml` configures the local WASM runner profile.
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
  -f deploy/compose.runner-tls.yml \
  -f deploy/compose.runner-wasm.yml \
  -f deploy/compose.traefik.yml \
  up -d --build --wait
```

The GitHub App signer must already be running at the socket configured by
`RUNTRUE_GITHUB_SIGNER_SOCKET`. The private key is never mounted into the
Runtrue server container.

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
