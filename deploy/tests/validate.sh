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
  compose.github-app-provider.yml
  compose.runner-tls.yml
  compose.runner-wasm.yml
  compose.runner-oci.yml
  compose.runner-combined.yml
  compose.autoscaler.yml
  compose.traefik.yml
  Containerfile.server
  Containerfile.runner
  Containerfile.autoscaler
  Containerfile.backup
  bootstrap.sh
  healthcheck.sh
  github-app-provider-probe.py
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
PYTHONDONTWRITEBYTECODE=1 python3 "${DEPLOY_DIR}/tests/test-github-app-provider-probe.py"

validate_tracked_executable() {
  local path=$1 mode
  mode=$(stat -c '%a' "$path")
  ((8#$mode & 0100)) || fail "${path##*/} must be executable by its owner"
  ((! (8#$mode & 0022))) || fail "${path##*/} must not be writable by group or other"
}

validate_tracked_executable "${DEPLOY_DIR}/bootstrap.sh"
validate_tracked_executable "${DEPLOY_DIR}/healthcheck.sh"
validate_tracked_executable "${DEPLOY_DIR}/traefik-entrypoint.sh"
validate_tracked_executable "${DEPLOY_DIR}/github-app-provider-probe.py"

command -v docker >/dev/null 2>&1 || fail 'Docker is required'
docker compose version >/dev/null 2>&1 || fail 'Docker Compose v2 is required'

TEMPORARY_ROOT=$(mktemp -d)
chmod 0700 "$TEMPORARY_ROOT"
for directory in server secrets keys backups restores recovery-config runner workspaces tls runner-trust runner-secrets runner-oci traefik autoscaler github-app-provider; do
  install -d -m 0700 "${TEMPORARY_ROOT}/${directory}"
done
install -d -m 0700 "${TEMPORARY_ROOT}/autoscaler/claims"
touch "${TEMPORARY_ROOT}/traefik/acme.json" "${TEMPORARY_ROOT}/runner-secrets/autoscaler.token"
touch "${TEMPORARY_ROOT}/github-app-private-key.pem"
chmod 0600 "${TEMPORARY_ROOT}/traefik/acme.json" "${TEMPORARY_ROOT}/runner-secrets/autoscaler.token" \
  "${TEMPORARY_ROOT}/github-app-private-key.pem"

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
RUNTRUE_OCI_STATE_DIR=${TEMPORARY_ROOT}/runner-oci
EOF
chmod 0600 "${TEMPORARY_ROOT}/compose.env"

common=(docker compose --env-file "${TEMPORARY_ROOT}/compose.env" -f "${DEPLOY_DIR}/compose.yml")
"${common[@]}" config --quiet
"${common[@]}" -f "${DEPLOY_DIR}/compose.runner-tls.yml" \
  -f "${DEPLOY_DIR}/compose.runner-wasm.yml" --profile runner-wasm-eval config --quiet
"${common[@]}" -f "${DEPLOY_DIR}/compose.runner-tls.yml" \
  -f "${DEPLOY_DIR}/compose.runner-oci.yml" config --quiet
"${common[@]}" -f "${DEPLOY_DIR}/compose.runner-tls.yml" \
  -f "${DEPLOY_DIR}/compose.runner-wasm.yml" \
  -f "${DEPLOY_DIR}/compose.runner-combined.yml" \
  --profile runner-combined-eval config --quiet

rendered="${TEMPORARY_ROOT}/full.json"
env \
  RUNTRUE_PUBLIC_ORIGIN=https://runtrue.example.com \
  RUNTRUE_ACME_EMAIL=operator@example.com \
  RUNTRUE_GITHUB_APP_ID=123 \
  RUNTRUE_GITHUB_APP_SLUG=runtrue \
  RUNTRUE_GITHUB_APP_CREDENTIAL_REFERENCE=provider://github-app/production \
  RUNTRUE_GITHUB_APP_JWT_PROVIDER_IMAGE=registry.example.com/github-app-jwt-provider@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  RUNTRUE_GITHUB_APP_PRIVATE_KEY_FILE="${TEMPORARY_ROOT}/github-app-private-key.pem" \
  RUNTRUE_GITHUB_OAUTH_CLIENT_ID=Iv1.validation \
  RUNTRUE_GITHUB_OAUTH_ADMIN_USER_IDS=123456 \
  "${common[@]}" \
    -f "${DEPLOY_DIR}/compose.github-app.yml" \
    -f "${DEPLOY_DIR}/compose.github-app-provider.yml" \
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
required = {"server", "traefik", "autoscaler", "github-app-jwt-provider"}
if set(services) != required:
    raise SystemExit(f"unexpected default services: {set(services)!r}")
for name, service in services.items():
    if service.get("privileged") is True or service.get("network_mode") == "host":
        raise SystemExit(f"{name} has unsafe host privileges")
    if name != "autoscaler" and "docker.sock" in json.dumps(service).lower():
        raise SystemExit(f"{name} received the Docker socket")
server = services["server"]
server_json = json.dumps(server)
if "github-app-private-key.pem" in server_json:
    raise SystemExit("Runtrue server received the GitHub App private key")
if "/run/runtrue-github-app-provider/provider.sock" not in server_json:
    raise SystemExit("Runtrue server is missing the external JWT provider socket")
provider_mounts = [
    mount for mount in server.get("volumes", [])
    if mount.get("target") == "/run/runtrue-github-app-provider"
]
if len(provider_mounts) != 1 or provider_mounts[0].get("read_only") is not True:
    raise SystemExit("external JWT provider socket directory must be mounted read-only")
provider = services["github-app-jwt-provider"]
if provider.get("image") != "registry.example.com/github-app-jwt-provider@sha256:" + "0123456789abcdef" * 4:
    raise SystemExit("external JWT provider image must retain its immutable digest")
if provider.get("network_mode") != "none":
    raise SystemExit("external JWT provider must have networking disabled")
if provider.get("read_only") is not True:
    raise SystemExit("external JWT provider root filesystem must be read-only")
if provider.get("cap_drop") != ["ALL"]:
    raise SystemExit("external JWT provider must drop every capability")
if "no-new-privileges:true" not in provider.get("security_opt", []):
    raise SystemExit("external JWT provider must enable no-new-privileges")
if provider.get("user") != "10001:10001":
    raise SystemExit("external JWT provider must use the deployment uid and gid")
if provider.get("restart") != "unless-stopped":
    raise SystemExit("external JWT provider must restart with the Compose stack")
if provider.get("pids_limit") != 64:
    raise SystemExit("external JWT provider PID limit changed")
provider_mounts = {mount["target"]: mount for mount in provider.get("volumes", [])}
if provider_mounts["/run/runtrue-github-app-private-key/private-key.pem"].get("read_only") is not True:
    raise SystemExit("external JWT provider private key must be mounted read-only")
if provider_mounts["/run/runtrue-github-app-provider"].get("read_only") is True:
    raise SystemExit("external JWT provider socket directory must be writable")
dependency = server.get("depends_on", {}).get("github-app-jwt-provider", {})
if dependency.get("condition") != "service_healthy":
    raise SystemExit("server must wait for a healthy external JWT provider")
if "/var/run/docker.sock" not in json.dumps(services["autoscaler"]):
    raise SystemExit("autoscaler is missing the Docker socket")
if services["server"].get("ports"):
    raise SystemExit("Traefik overlay retained direct application ports")
if "frontend" in services:
    raise SystemExit("Runtrue core must not define a product frontend service")
if "control" not in services["traefik"].get("networks", {}):
    raise SystemExit("Traefik must reach the control server over the internal network")
if services["traefik"].get("entrypoint") != ["/bin/sh", "/var/lib/traefik/entrypoint.sh"]:
    raise SystemExit("Traefik must execute its managed state entrypoint through /bin/sh")
published = {port["published"] for port in services["traefik"].get("ports", [])}
if published != {"80", "443"}:
    raise SystemExit(f"unexpected public ports: {published!r}")
PY

oci_rendered="${TEMPORARY_ROOT}/oci.json"
"${common[@]}" \
  -f "${DEPLOY_DIR}/compose.runner-tls.yml" \
  -f "${DEPLOY_DIR}/compose.runner-oci.yml" \
  config --format json >"$oci_rendered"

python3 - "$oci_rendered" <<'PY'
import json
import pathlib
import sys

model = json.loads(pathlib.Path(sys.argv[1]).read_text())
services = model["services"]
runner = services["runner-oci"]
if runner.get("image") != "local/runtrue-runner:0.1.0":
    raise SystemExit("OCI and Wasm deployments must use the same runner image")
if runner.get("privileged") is not True:
    raise SystemExit("OCI runner must be privileged for nested rootless Podman")
if runner.get("user") != "10001:10001":
    raise SystemExit("OCI runner must execute as the configured non-root identity")
if runner.get("restart") != "unless-stopped":
    raise SystemExit("OCI runner must restart with the Compose stack")
if int(runner.get("mem_limit", 0)) != 6 * 1024 * 1024 * 1024:
    raise SystemExit("OCI runner aggregate memory limit changed")
if runner.get("pids_limit") != 768:
    raise SystemExit("OCI runner aggregate PID limit changed")
if "/dev/fuse" not in json.dumps(runner.get("devices", [])):
    raise SystemExit("OCI runner is missing /dev/fuse")
if "systemd" in json.dumps(runner).lower():
    raise SystemExit("OCI runner configuration must not depend on systemd")
PY

combined_rendered="${TEMPORARY_ROOT}/combined.json"
"${common[@]}" \
  -f "${DEPLOY_DIR}/compose.runner-tls.yml" \
  -f "${DEPLOY_DIR}/compose.runner-wasm.yml" \
  -f "${DEPLOY_DIR}/compose.runner-combined.yml" \
  --profile runner-combined-eval \
  config --format json >"$combined_rendered"

python3 - "$combined_rendered" <<'PY'
import json
import pathlib
import sys

model = json.loads(pathlib.Path(sys.argv[1]).read_text())
runner = model["services"]["runner"]
environment = runner.get("environment", {})
if runner.get("image") != "local/runtrue-runner:0.1.0":
    raise SystemExit("combined deployment must use the single runner image")
if runner.get("privileged") is not True:
    raise SystemExit("combined Wasm/OCI runner must expose its OCI privilege boundary")
if "/dev/fuse" not in json.dumps(runner.get("devices", [])):
    raise SystemExit("combined Wasm/OCI runner is missing /dev/fuse")
required = {
    "RUNTRUE_RUNNER_WASM_COMPONENT_DIRECTORY",
    "RUNTRUE_RUNNER_WASM_MANIFEST_DIRECTORY",
    "RUNTRUE_RUNNER_WASM_COMPONENT_KEYRING",
    "RUNTRUE_RUNNER_WASM_AOT_CACHE",
    "RUNTRUE_RUNNER_WASM_RUNTIME_KEY",
    "RUNTRUE_RUNNER_OCI_STATE_DIRECTORY",
    "RUNTRUE_RUNNER_OCI_PODMAN",
    "RUNTRUE_RUNNER_OCI_SECCOMP_PROFILE",
    "RUNTRUE_RUNNER_OCI_IMAGE_STORE",
    "RUNTRUE_RUNNER_OCI_RUNTIME_ENVIRONMENT",
    "RUNTRUE_RUNNER_OCI_MANIFEST_DIRECTORY",
    "RUNTRUE_RUNNER_OCI_IMAGE_KEYRING",
}
missing = required - set(environment)
if missing:
    raise SystemExit(f"combined runner is missing backend configuration: {sorted(missing)!r}")
PY

grep -q 'RUNTRUE_RUNNER_WASM_MAX_CONCURRENT_JOBS: "${RUNTRUE_RUNNER_WASM_MAX_CONCURRENT_JOBS:-1}"' \
  "${DEPLOY_DIR}/compose.runner-wasm.yml" ||
  fail 'WASM runner overlay is missing its explicit concurrency ceiling'

printf 'Docker Compose deployment assets validated\n'
