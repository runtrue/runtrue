#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly DEPLOY_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
TEMPORARY_ROOT=''

cleanup() {
  if [[ -n "$TEMPORARY_ROOT" && -d "$TEMPORARY_ROOT" && ! -L "$TEMPORARY_ROOT" ]]; then
    rm -rf -- "$TEMPORARY_ROOT"
  fi
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf 'deploy validation: %s\n' "$*" >&2
  exit 1
}

required=(
  compose.yml
  compose.github-app.yml
  compose.runner-tls.yml
  compose.runner-wasm.yml
  compose.autoscaler.yml
  compose.traefik.yml
  Containerfile.server
  Containerfile.runner
  Containerfile.autoscaler
  Containerfile.backup
  bootstrap.sh
  healthcheck.sh
  traefik-entrypoint.sh
)
for file in "${required[@]}"; do
  [[ -f "${DEPLOY_DIR}/${file}" ]] || fail "missing ${file}"
done

[[ ! -d "${DEPLOY_DIR}/systemd" ]] || fail 'systemd assets do not belong in the Compose package'
[[ ! -e "${DEPLOY_DIR}/compose.action-builder.yml" ]] || fail 'host action-builder overlay is still present'

bash -n "${DEPLOY_DIR}/bootstrap.sh"
bash -n "${DEPLOY_DIR}/healthcheck.sh"
sh -n "${DEPLOY_DIR}/traefik-entrypoint.sh"

[[ "$(stat -c '%a' "${DEPLOY_DIR}/bootstrap.sh")" == 700 ]] || fail 'bootstrap.sh must have mode 0700'
[[ "$(stat -c '%a' "${DEPLOY_DIR}/healthcheck.sh")" == 555 ]] || fail 'healthcheck.sh must have mode 0555'
[[ "$(stat -c '%a' "${DEPLOY_DIR}/traefik-entrypoint.sh")" == 555 ]] || fail 'traefik-entrypoint.sh must have mode 0555'

command -v docker >/dev/null 2>&1 || fail 'Docker is required'
docker compose version >/dev/null 2>&1 || fail 'Docker Compose v2 is required'

TEMPORARY_ROOT=$(mktemp -d)
chmod 0700 "$TEMPORARY_ROOT"
for directory in server secrets keys backups restores recovery-config runner workspaces tls runner-trust runner-secrets traefik autoscaler; do
  install -d -m 0700 "${TEMPORARY_ROOT}/${directory}"
done
install -d -m 0700 "${TEMPORARY_ROOT}/autoscaler/claims"
touch "${TEMPORARY_ROOT}/traefik/acme.json" "${TEMPORARY_ROOT}/runner-secrets/autoscaler.token"
chmod 0600 "${TEMPORARY_ROOT}/traefik/acme.json" "${TEMPORARY_ROOT}/runner-secrets/autoscaler.token"

cat >"${TEMPORARY_ROOT}/compose.env" <<EOF
RUNTRUE_RUNTIME_UID=10001
RUNTRUE_RUNTIME_GID=10001
RUNTRUE_DOCKER_GID=$(stat -c '%g' /var/run/docker.sock)
RUNTRUE_AUTOSCALER_POOL_ID=validation
RUNTRUE_STATE_DIR=${TEMPORARY_ROOT}
RUNTRUE_HTTP_PORT=8080
RUNTRUE_INSTALLATION_ID=deployment-validation
RUNTRUE_IMAGE_REPOSITORY=local/runtrue
RUNTRUE_IMAGE_TAG=0.1.0
RUNTRUE_IMAGE_REVISION=validation
EOF
chmod 0600 "${TEMPORARY_ROOT}/compose.env"

common=(docker compose --env-file "${TEMPORARY_ROOT}/compose.env" -f "${DEPLOY_DIR}/compose.yml")
"${common[@]}" config --quiet
"${common[@]}" -f "${DEPLOY_DIR}/compose.runner-tls.yml" \
  -f "${DEPLOY_DIR}/compose.runner-wasm.yml" --profile runner-wasm-eval config --quiet

rendered="${TEMPORARY_ROOT}/full.json"
env \
  GITHUB_TOKEN=deployment-validation-token \
  RUNTRUE_PUBLIC_ORIGIN=https://runtrue.example.com \
  RUNTRUE_ACME_EMAIL=operator@example.com \
  RUNTRUE_GITHUB_APP_ID=123 \
  RUNTRUE_GITHUB_APP_SLUG=runtrue \
  RUNTRUE_GITHUB_APP_CREDENTIAL_REFERENCE=provider://github-app/production \
  RUNTRUE_GITHUB_OAUTH_CLIENT_ID=Iv1.validation \
  RUNTRUE_GITHUB_OAUTH_ADMIN_USER_IDS=123456 \
  RUNTRUE_GITHUB_SIGNER_SOCKET="${TEMPORARY_ROOT}/github-app-signer.sock" \
  "${common[@]}" \
    -f "${DEPLOY_DIR}/compose.github-app.yml" \
    -f "${DEPLOY_DIR}/compose.runner-tls.yml" \
    -f "${DEPLOY_DIR}/compose.runner-wasm.yml" \
    -f "${DEPLOY_DIR}/compose.autoscaler.yml" \
    -f "${DEPLOY_DIR}/compose.traefik.yml" \
    config --format json >"$rendered"

python3 - "$rendered" <<'PY'
import json
import pathlib
import sys

model = json.loads(pathlib.Path(sys.argv[1]).read_text())
services = model["services"]
required = {"server", "traefik", "autoscaler"}
if set(services) != required:
    raise SystemExit(f"unexpected default services: {set(services)!r}")
for name, service in services.items():
    if service.get("privileged") is True or service.get("network_mode") == "host":
        raise SystemExit(f"{name} has unsafe host privileges")
    if name != "autoscaler" and "docker.sock" in json.dumps(service).lower():
        raise SystemExit(f"{name} received the Docker socket")
if "/var/run/docker.sock" not in json.dumps(services["autoscaler"]):
    raise SystemExit("autoscaler is missing the Docker socket")
if services["server"].get("ports"):
    raise SystemExit("Traefik overlay retained direct application ports")
if "frontend" in services:
    raise SystemExit("Runtrue core must not define a product frontend service")
if "control" not in services["traefik"].get("networks", {}):
    raise SystemExit("Traefik must reach the control server over the internal network")
published = {port["published"] for port in services["traefik"].get("ports", [])}
if published != {"80", "443"}:
    raise SystemExit(f"unexpected public ports: {published!r}")
PY

grep -q 'RUNTRUE_RUNNER_WASM_MAX_CONCURRENT_JOBS: "${RUNTRUE_RUNNER_WASM_MAX_CONCURRENT_JOBS:-1}"' \
  "${DEPLOY_DIR}/compose.runner-wasm.yml" ||
  fail 'WASM runner overlay is missing its explicit concurrency ceiling'

printf 'Docker Compose deployment assets validated\n'
