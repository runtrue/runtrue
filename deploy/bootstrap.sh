#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly COMPOSE_FILE="${SCRIPT_DIR}/compose.yml"
readonly RUNNER_COMPOSE_FILE="${SCRIPT_DIR}/compose.runner-tls.yml"
readonly GITHUB_COMPOSE_FILE="${SCRIPT_DIR}/compose.github-app.yml"
readonly TRAEFIK_COMPOSE_FILE="${SCRIPT_DIR}/compose.traefik.yml"
readonly AUTOSCALER_COMPOSE_FILE="${SCRIPT_DIR}/compose.autoscaler.yml"
readonly TRAEFIK_ENTRYPOINT_SOURCE="${SCRIPT_DIR}/traefik-entrypoint.sh"

STATE_DIR="${SCRIPT_DIR}/state"
WITH_RUNNER_TLS=false
WITH_GITHUB_APP=false
WITH_TRAEFIK=false
WITH_AUTOSCALER=false
CHECK_ONLY=false
TEMP_PATHS=()

usage() {
  cat <<'EOF'
Usage: deploy/bootstrap.sh [--state-dir PATH] [--with-runner-tls]
                           [--with-github-app] [--with-traefik]
                           [--with-autoscaler] [--check-only]

Initializes private single-node evaluation state without replacing an existing
credential. --with-runner-tls also creates a short-lived, self-signed local
runner-control PKI. --with-github-app creates the webhook secret, browser
cookie key, and private mirror directory used by the Compose GitHub overlay.
--with-traefik creates private ACME state for the Compose HTTPS edge. It never
creates or reads a GitHub App private key. --check-only performs validation
without creating files.
--with-autoscaler enables the development-only Docker provider. It requires
runner TLS and a pre-issued, mode-0600 autoscaler API token at
STATE_DIR/runner-secrets/autoscaler.token.
EOF
}

die() {
  printf 'bootstrap: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local path
  for path in "${TEMP_PATHS[@]:-}"; do
    if [[ -n "$path" && -e "$path" && ! -L "$path" ]]; then
      rm -rf -- "$path"
    fi
  done
}
trap cleanup EXIT HUP INT TERM

while (($#)); do
  case "$1" in
    --state-dir)
      (($# >= 2)) || die '--state-dir requires a path'
      STATE_DIR=$2
      shift 2
      ;;
    --with-runner-tls)
      WITH_RUNNER_TLS=true
      shift
      ;;
    --with-github-app)
      WITH_GITHUB_APP=true
      shift
      ;;
    --with-traefik)
      WITH_TRAEFIK=true
      shift
      ;;
    --with-autoscaler)
      WITH_AUTOSCALER=true
      shift
      ;;
    --check-only)
      CHECK_ONLY=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

if "$WITH_AUTOSCALER" && ! "$WITH_RUNNER_TLS"; then
  die '--with-autoscaler requires --with-runner-tls'
fi

for command in docker openssl realpath stat find install mktemp ln cmp mv; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: ${command}"
done

if [[ "$STATE_DIR" != /* ]]; then
  STATE_DIR="$(realpath -ms -- "${PWD}/${STATE_DIR}")"
else
  STATE_DIR="$(realpath -ms -- "$STATE_DIR")"
fi
[[ "$STATE_DIR" =~ ^[A-Za-z0-9_./-]+$ ]] ||
  die 'state path may contain only letters, digits, underscore, dot, slash, and hyphen'
[[ "$STATE_DIR" != / ]] || die 'state directory cannot be the filesystem root'

if [[ -n "${RUNTRUE_RUNTIME_UID:-}" || -n "${RUNTRUE_RUNTIME_GID:-}" ]]; then
  [[ "${RUNTRUE_RUNTIME_UID:-}" =~ ^[0-9]+$ ]] || die 'RUNTRUE_RUNTIME_UID must be numeric'
  [[ "${RUNTRUE_RUNTIME_GID:-}" =~ ^[0-9]+$ ]] || die 'RUNTRUE_RUNTIME_GID must be numeric'
  RUNTIME_UID=$RUNTRUE_RUNTIME_UID
  RUNTIME_GID=$RUNTRUE_RUNTIME_GID
elif ((EUID == 0)); then
  RUNTIME_UID=10001
  RUNTIME_GID=10001
else
  RUNTIME_UID=$(id -u)
  RUNTIME_GID=$(id -g)
fi
readonly RUNTIME_UID RUNTIME_GID
((RUNTIME_UID > 0)) || die 'containers must not run as uid 0'
((RUNTIME_GID > 0)) || die 'containers must not run as gid 0'
if ((EUID != 0)) && { ((RUNTIME_UID != EUID)) || ((RUNTIME_GID != $(id -g))); }; then
  die 'a non-root bootstrap may only select its own uid and gid'
fi
DOCKER_GID=
AUTOSCALER_RESERVE_MEMORY_BYTES=
AUTOSCALER_RESERVE_NANO_CPUS=
if "$WITH_AUTOSCALER"; then
  DOCKER_GID=${RUNTRUE_DOCKER_GID:-$(stat -c '%g' -- /var/run/docker.sock 2>/dev/null || true)}
  [[ "$DOCKER_GID" =~ ^[0-9]+$ ]] || die 'RUNTRUE_DOCKER_GID must identify the docker.sock group'
  AUTOSCALER_RESERVE_MEMORY_BYTES=${RUNTRUE_AUTOSCALER_RESERVE_MEMORY_BYTES:-2147483648}
  AUTOSCALER_RESERVE_NANO_CPUS=${RUNTRUE_AUTOSCALER_RESERVE_NANO_CPUS:-2000000000}
  [[ "$AUTOSCALER_RESERVE_MEMORY_BYTES" =~ ^[0-9]+$ ]] ||
    die 'RUNTRUE_AUTOSCALER_RESERVE_MEMORY_BYTES must be a non-negative integer'
  [[ "$AUTOSCALER_RESERVE_NANO_CPUS" =~ ^[0-9]+$ ]] ||
    die 'RUNTRUE_AUTOSCALER_RESERVE_NANO_CPUS must be a non-negative integer'
fi
readonly DOCKER_GID AUTOSCALER_RESERVE_MEMORY_BYTES AUTOSCALER_RESERVE_NANO_CPUS

reject_symlink_components() {
  local path=$1 current=/ component
  local -a components
  IFS='/' read -r -a components <<<"${path#/}"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != '.' ]] || continue
    [[ "$component" != '..' ]] || die "parent traversal is not allowed: ${path}"
    current="${current%/}/${component}"
    [[ ! -L "$current" ]] || die "symbolic-link path component rejected: ${current}"
  done
}

owner_mode() {
  stat -c '%u:%g:%a' -- "$1"
}

validate_private_directory() {
  local path=$1
  reject_symlink_components "$path"
  [[ -d "$path" && ! -L "$path" ]] || die "private directory is missing or unsafe: ${path}"
  [[ "$(owner_mode "$path")" == "${RUNTIME_UID}:${RUNTIME_GID}:700" ]] ||
    die "private directory must be owned by ${RUNTIME_UID}:${RUNTIME_GID} with mode 0700: ${path}"
}

ensure_private_directory() {
  local path=$1
  if [[ -e "$path" || -L "$path" ]]; then
    validate_private_directory "$path"
    return
  fi
  reject_symlink_components "$(dirname -- "$path")"
  if ((EUID == 0)); then
    install -d -m 0700 -o "$RUNTIME_UID" -g "$RUNTIME_GID" -- "$path"
  else
    install -d -m 0700 -- "$path"
  fi
  validate_private_directory "$path"
}

validate_private_file() {
  local path=$1 expected_bytes=${2:-}
  reject_symlink_components "$path"
  [[ -f "$path" && ! -L "$path" ]] || die "private file is missing or unsafe: ${path}"
  [[ "$(owner_mode "$path")" == "${RUNTIME_UID}:${RUNTIME_GID}:600" ]] ||
    die "private file must be owned by ${RUNTIME_UID}:${RUNTIME_GID} with mode 0600: ${path}"
  [[ "$(stat -c '%h' -- "$path")" == 1 ]] || die "hard-linked private file rejected: ${path}"
  if [[ -n "$expected_bytes" ]]; then
    [[ "$(stat -c '%s' -- "$path")" == "$expected_bytes" ]] ||
      die "private file has an invalid byte length: ${path}"
  fi
}

publish_new_file() {
  local temporary=$1 destination=$2
  [[ ! -e "$destination" && ! -L "$destination" ]] ||
    die "refusing to replace existing file: ${destination}"
  chmod 0600 -- "$temporary"
  if ((EUID == 0)); then
    chown "${RUNTIME_UID}:${RUNTIME_GID}" -- "$temporary"
  fi
  ln -- "$temporary" "$destination" || die "could not atomically publish new file: ${destination}"
  rm -f -- "$temporary"
}

new_temporary_file() {
  local directory=$1 stem=$2 temporary
  temporary=$(mktemp -- "${directory}/.${stem}.tmp.XXXXXXXX")
  printf '%s\n' "$temporary"
}

create_random_file() {
  local destination=$1 encoding=$2 bytes=$3 temporary
  if [[ -e "$destination" || -L "$destination" ]]; then
    validate_private_file "$destination"
    return
  fi
  temporary=$(new_temporary_file "$(dirname -- "$destination")" "$(basename -- "$destination")")
  TEMP_PATHS+=("$temporary")
  case "$encoding" in
    raw) openssl rand "$bytes" >"$temporary" ;;
    hex) openssl rand -hex "$bytes" >"$temporary" ;;
    *) die "internal error: unsupported random encoding ${encoding}" ;;
  esac
  publish_new_file "$temporary" "$destination"
}

create_empty_file() {
  local destination=$1 temporary
  if [[ -e "$destination" || -L "$destination" ]]; then
    validate_private_file "$destination" 0
    return
  fi
  temporary=$(new_temporary_file "$(dirname -- "$destination")" "$(basename -- "$destination")")
  TEMP_PATHS+=("$temporary")
  : >"$temporary"
  publish_new_file "$temporary" "$destination"
}

sync_private_file() {
  local source=$1 destination=$2 temporary
  reject_symlink_components "$source"
  [[ -f "$source" && ! -L "$source" ]] || die "managed source file is missing or unsafe: ${source}"
  if [[ -e "$destination" || -L "$destination" ]]; then
    validate_private_file "$destination"
    cmp -s -- "$source" "$destination" && return
  fi
  temporary=$(new_temporary_file "$(dirname -- "$destination")" "$(basename -- "$destination")")
  TEMP_PATHS+=("$temporary")
  install -m 0600 -- "$source" "$temporary"
  if ((EUID == 0)); then
    chown "${RUNTIME_UID}:${RUNTIME_GID}" -- "$temporary"
  fi
  if [[ -e "$destination" ]]; then
    mv -fT -- "$temporary" "$destination"
  else
    publish_new_file "$temporary" "$destination"
  fi
}

create_autoscaler_template() {
  local destination="${STATE_DIR}/autoscaler/docker-template.json" temporary project_name
  if [[ -e "$destination" || -L "$destination" ]]; then
    validate_private_file "$destination"
    return
  fi
  project_name=${COMPOSE_PROJECT_NAME:-deploy}
  [[ "$project_name" =~ ^[A-Za-z0-9_-]+$ ]] || die 'COMPOSE_PROJECT_NAME is unsafe'
  temporary=$(new_temporary_file "${STATE_DIR}/autoscaler" docker-template.json)
  TEMP_PATHS+=("$temporary")
  sed \
    -e "s#/var/lib/runtrue#${STATE_DIR}#g" \
    -e "s#runtrue_control#${project_name}_control#g" \
    -e "s#__RUNTRUE_RUNTIME_UID__#${RUNTIME_UID}#g" \
    -e "s#__RUNTRUE_RUNTIME_GID__#${RUNTIME_GID}#g" \
    -e "s#__RUNTRUE_CAPACITY_RESERVE_MEMORY_BYTES__#${AUTOSCALER_RESERVE_MEMORY_BYTES}#g" \
    -e "s#__RUNTRUE_CAPACITY_RESERVE_NANO_CPUS__#${AUTOSCALER_RESERVE_NANO_CPUS}#g" \
    "${SCRIPT_DIR}/autoscaler-docker-template.json.example" >"$temporary"
  publish_new_file "$temporary" "$destination"
}

validate_bootstrap_material() {
  local token_file="${STATE_DIR}/secrets/bootstrap.token"
  local key_file="${STATE_DIR}/keys/security.key"
  local token
  validate_private_file "$token_file" 65
  token=$(<"$token_file")
  [[ "$token" =~ ^[0-9a-f]{64}$ ]] || die 'bootstrap token has invalid encoding'
  unset token
  validate_private_file "$key_file" 32
}

write_compose_environment() {
  local destination="${STATE_DIR}/compose.env" temporary expected
  temporary=$(new_temporary_file "$STATE_DIR" compose.env)
  TEMP_PATHS+=("$temporary")
  {
    printf 'RUNTRUE_RUNTIME_UID=%s\n' "$RUNTIME_UID"
    printf 'RUNTRUE_RUNTIME_GID=%s\n' "$RUNTIME_GID"
    if "$WITH_AUTOSCALER"; then
      printf 'RUNTRUE_DOCKER_GID=%s\n' "$DOCKER_GID"
    fi
    printf 'RUNTRUE_STATE_DIR=%s\n' "$STATE_DIR"
    printf 'RUNTRUE_HTTP_PORT=8080\n'
    printf 'RUNTRUE_INSTALLATION_ID=single-node-evaluation\n'
    printf 'RUNTRUE_IMAGE_REPOSITORY=local/runtrue\n'
    printf 'RUNTRUE_IMAGE_TAG=0.1.0\n'
    printf 'RUNTRUE_IMAGE_REVISION=unknown\n'
  } >"$temporary"
  chmod 0600 -- "$temporary"
  if ((EUID == 0)); then
    chown "${RUNTIME_UID}:${RUNTIME_GID}" -- "$temporary"
  fi
  if [[ -e "$destination" || -L "$destination" ]]; then
    validate_private_file "$destination"
    if ! cmp -s -- "$temporary" "$destination"; then
      die "existing compose environment differs; refusing to overwrite: ${destination}"
    fi
    rm -f -- "$temporary"
  else
    publish_new_file "$temporary" "$destination"
  fi
  expected="${RUNTIME_UID}:${RUNTIME_GID}:600"
  [[ "$(owner_mode "$destination")" == "$expected" ]] || die 'invalid compose environment permissions'
}

validate_tls_material() {
  local directory="${STATE_DIR}/tls"
  local ca_key="${directory}/runner-ca.key" ca_cert="${directory}/runner-ca.pem"
  local server_key="${directory}/runner-server.key" server_cert="${directory}/runner-server.pem"
  local public_key certificate_key
  validate_private_file "$ca_key"
  validate_private_file "$ca_cert"
  validate_private_file "$server_key"
  validate_private_file "$server_cert"
  openssl pkey -in "$ca_key" -noout >/dev/null 2>&1 || die 'runner CA private key is invalid'
  openssl x509 -in "$ca_cert" -noout >/dev/null 2>&1 || die 'runner CA certificate is invalid'
  openssl pkey -in "$server_key" -noout >/dev/null 2>&1 || die 'runner server private key is invalid'
  openssl x509 -in "$server_cert" -noout >/dev/null 2>&1 || die 'runner server certificate is invalid'
  openssl x509 -in "$ca_cert" -noout -text 2>/dev/null |
    grep -q 'CA:TRUE' || die 'runner CA certificate lacks CA constraints'
  openssl verify -CAfile "$ca_cert" "$server_cert" >/dev/null 2>&1 ||
    die 'runner server certificate does not verify under the local CA'
  openssl x509 -in "$server_cert" -checkhost server -noout >/dev/null 2>&1 ||
    die 'runner server certificate is not valid for the Compose service name'
  public_key=$(new_temporary_file "$directory" server-public)
  certificate_key=$(new_temporary_file "$directory" certificate-public)
  TEMP_PATHS+=("$public_key" "$certificate_key")
  openssl pkey -in "$server_key" -pubout -out "$public_key" 2>/dev/null
  openssl x509 -in "$server_cert" -pubkey -noout >"$certificate_key" 2>/dev/null
  cmp -s -- "$public_key" "$certificate_key" || die 'runner server certificate and private key do not match'
  rm -f -- "$public_key" "$certificate_key"
}

create_tls_material() {
  local directory="${STATE_DIR}/tls"
  local -a names=(runner-ca.key runner-ca.pem runner-server.key runner-server.pem)
  local present=0 name temporary_directory serial
  for name in "${names[@]}"; do
    [[ -e "${directory}/${name}" || -L "${directory}/${name}" ]] && ((present += 1))
  done
  if ((present == ${#names[@]})); then
    validate_tls_material
    return
  fi
  ((present == 0)) || die 'partial runner TLS state found; refusing to replace or complete credentials'

  temporary_directory=$(mktemp -d -- "${directory}/.bootstrap-tls.XXXXXXXX")
  TEMP_PATHS+=("$temporary_directory")
  chmod 0700 -- "$temporary_directory"
  openssl genpkey -algorithm ED25519 -out "${temporary_directory}/runner-ca.key" 2>/dev/null
  openssl req -new -x509 -key "${temporary_directory}/runner-ca.key" \
    -out "${temporary_directory}/runner-ca.pem" -days 3650 \
    -subj '/CN=Runtrue local evaluation runner CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' 2>/dev/null
  openssl genpkey -algorithm ED25519 -out "${temporary_directory}/runner-server.key" 2>/dev/null
  openssl req -new -key "${temporary_directory}/runner-server.key" \
    -out "${temporary_directory}/runner-server.csr" \
    -subj '/CN=server' \
    -addext 'subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1' 2>/dev/null
  cat >"${temporary_directory}/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1
EOF
  serial=$(openssl rand -hex 16)
  openssl x509 -req -in "${temporary_directory}/runner-server.csr" \
    -CA "${temporary_directory}/runner-ca.pem" \
    -CAkey "${temporary_directory}/runner-ca.key" \
    -set_serial "0x${serial}" -days 30 \
    -extfile "${temporary_directory}/server.ext" \
    -out "${temporary_directory}/runner-server.pem" 2>/dev/null
  unset serial
  for name in "${names[@]}"; do
    chmod 0600 -- "${temporary_directory}/${name}"
    if ((EUID == 0)); then
      chown "${RUNTIME_UID}:${RUNTIME_GID}" -- "${temporary_directory}/${name}"
    fi
    publish_new_file "${temporary_directory}/${name}" "${directory}/${name}"
  done
  rm -rf -- "$temporary_directory"
  validate_tls_material
}

validate_state_tree() {
  local unsafe
  reject_symlink_components "$STATE_DIR"
  unsafe=$(find -P "$STATE_DIR" -xdev -type l -print -quit)
  [[ -z "$unsafe" ]] || die "symbolic link in managed state rejected: ${unsafe}"
  unsafe=$(find -P "$STATE_DIR" -xdev -type d \! -perm 0700 -print -quit)
  [[ -z "$unsafe" ]] || die "managed directory does not have exact mode 0700: ${unsafe}"
  unsafe=$(find -P "$STATE_DIR" -xdev -type f \! -perm 0600 -print -quit)
  [[ -z "$unsafe" ]] || die "managed file does not have exact mode 0600: ${unsafe}"
  unsafe=$(find -P "$STATE_DIR" -xdev \! -uid "$RUNTIME_UID" -print -quit)
  [[ -z "$unsafe" ]] || die "managed path has an unexpected owner: ${unsafe}"
  unsafe=$(find -P "$STATE_DIR" -xdev \! -gid "$RUNTIME_GID" -print -quit)
  [[ -z "$unsafe" ]] || die "managed path has an unexpected group: ${unsafe}"
}

validate_compose() {
  local rendered
  local -a compose_files=(-f "$COMPOSE_FILE") compose_profiles=()
  docker compose version >/dev/null 2>&1 || die 'Docker Compose v2 is required'
  [[ "$(docker info --format '{{.OSType}}' 2>/dev/null)" == linux ]] ||
    die 'a reachable Linux Docker Engine is required'
  rendered=$(mktemp)
  TEMP_PATHS+=("$rendered")
  if "$WITH_RUNNER_TLS"; then
    compose_files+=(-f "$RUNNER_COMPOSE_FILE")
    compose_profiles+=(--profile runner-native-eval)
  fi
  if "$WITH_GITHUB_APP"; then
    compose_files+=(-f "$GITHUB_COMPOSE_FILE")
  fi
  if "$WITH_TRAEFIK"; then
    compose_files+=(-f "$TRAEFIK_COMPOSE_FILE")
  fi
  if "$WITH_AUTOSCALER"; then
    compose_files+=(-f "$AUTOSCALER_COMPOSE_FILE")
  fi
  if "$WITH_GITHUB_APP"; then
    env \
      GITHUB_TOKEN=deployment-validation-token \
      RUNTRUE_PUBLIC_ORIGIN=https://runtrue.example.com \
      RUNTRUE_GITHUB_APP_ID=123 \
      RUNTRUE_GITHUB_APP_SLUG=runtrue \
      RUNTRUE_GITHUB_WEB_ORIGIN=https://github.example.com \
      RUNTRUE_GITHUB_API_ORIGIN=https://github.example.com/api/v3 \
      RUNTRUE_GITHUB_APP_CREDENTIAL_REFERENCE=provider://github-app/production \
      RUNTRUE_GITHUB_OAUTH_CLIENT_ID=Iv1.test \
      RUNTRUE_GITHUB_OAUTH_ADMIN_USER_IDS=123456 \
      RUNTRUE_GITHUB_APP_PRIVATE_KEY_FILE=/run/runtrue/github-app-private-key.pem \
      RUNTRUE_ACME_EMAIL=operator@example.com \
      docker compose --env-file "${STATE_DIR}/compose.env" \
        "${compose_files[@]}" "${compose_profiles[@]}" config >"$rendered"
  elif "$WITH_TRAEFIK"; then
    env \
      RUNTRUE_PUBLIC_ORIGIN=https://runtrue.example.com \
      RUNTRUE_ACME_EMAIL=operator@example.com \
      docker compose --env-file "${STATE_DIR}/compose.env" \
        "${compose_files[@]}" "${compose_profiles[@]}" config >"$rendered"
  else
    docker compose --env-file "${STATE_DIR}/compose.env" \
      "${compose_files[@]}" "${compose_profiles[@]}" config >"$rendered"
  fi
  if "$WITH_TRAEFIK"; then
    grep -q 'published: "80"' "$rendered" || die 'Traefik does not publish HTTP port 80'
    grep -q 'published: "443"' "$rendered" || die 'Traefik does not publish HTTPS port 443'
    ! grep -q 'host_ip: 127.0.0.1' "$rendered" || die 'Traefik overlay retained an application loopback port'
  else
    grep -q 'host_ip: 127.0.0.1' "$rendered" || die 'Compose API publication is not loopback-only'
  fi
  if grep -Eq 'privileged:[[:space:]]*true|network_mode:[[:space:]]*host|podman\.sock' "$rendered"; then
    die 'Compose configuration contains a forbidden privilege escape'
  fi
  if ! awk '
    /^  [A-Za-z0-9_.-]+:$/ { service=$1; sub(":$", "", service) }
    /docker\.sock/ && service != "autoscaler" { exit 1 }
  ' "$rendered"; then
    die 'a container-runtime socket is mounted outside the autoscaler service'
  fi
  if "$WITH_AUTOSCALER"; then
    grep -q '/var/run/docker.sock' "$rendered" || die 'autoscaler Docker socket mount is missing'
  elif grep -q '/var/run/docker.sock' "$rendered"; then
    die 'Docker socket requires explicit --with-autoscaler opt-in'
  fi
  rm -f -- "$rendered"
}

declare -a STATE_DIRECTORIES=(
  "$STATE_DIR"
  "${STATE_DIR}/server"
  "${STATE_DIR}/secrets"
  "${STATE_DIR}/keys"
  "${STATE_DIR}/backups"
  "${STATE_DIR}/restores"
  "${STATE_DIR}/recovery-config"
  "${STATE_DIR}/runner"
  "${STATE_DIR}/runner/state"
  "${STATE_DIR}/runner/credentials"
  "${STATE_DIR}/workspaces"
  "${STATE_DIR}/tls"
  "${STATE_DIR}/runner-trust"
  "${STATE_DIR}/runner-trust/capsule-keys"
  "${STATE_DIR}/runner-secrets"
)

if "$WITH_GITHUB_APP"; then
  STATE_DIRECTORIES+=("${STATE_DIR}/server/git-mirrors" "${STATE_DIR}/github-app-provider")
fi
if "$WITH_TRAEFIK"; then
  STATE_DIRECTORIES+=("${STATE_DIR}/traefik")
fi
if "$WITH_AUTOSCALER"; then
  STATE_DIRECTORIES+=("${STATE_DIR}/autoscaler" "${STATE_DIR}/autoscaler/claims")
fi
readonly -a STATE_DIRECTORIES

if "$CHECK_ONLY"; then
  for directory in "${STATE_DIRECTORIES[@]}"; do
    validate_private_directory "$directory"
  done
else
  for directory in "${STATE_DIRECTORIES[@]}"; do
    ensure_private_directory "$directory"
  done
  create_random_file "${STATE_DIR}/secrets/bootstrap.token" hex 32
  create_random_file "${STATE_DIR}/keys/security.key" raw 32
  if "$WITH_GITHUB_APP"; then
    create_random_file "${STATE_DIR}/secrets/github-webhook.secret" hex 32
    create_random_file "${STATE_DIR}/secrets/browser-cookie.key" raw 32
  fi
  if "$WITH_TRAEFIK"; then
    create_empty_file "${STATE_DIR}/traefik/acme.json"
    sync_private_file "$TRAEFIK_ENTRYPOINT_SOURCE" "${STATE_DIR}/traefik/entrypoint.sh"
  fi
  write_compose_environment
  if "$WITH_RUNNER_TLS"; then
    create_tls_material
  fi
  if "$WITH_AUTOSCALER"; then
    create_autoscaler_template
  fi
fi

validate_bootstrap_material
validate_private_file "${STATE_DIR}/compose.env"
if "$WITH_GITHUB_APP"; then
  validate_private_file "${STATE_DIR}/secrets/github-webhook.secret" 65
  validate_private_file "${STATE_DIR}/secrets/browser-cookie.key" 32
fi
if "$WITH_TRAEFIK"; then
  validate_private_file "${STATE_DIR}/traefik/acme.json"
  validate_private_file "${STATE_DIR}/traefik/entrypoint.sh"
  cmp -s -- "$TRAEFIK_ENTRYPOINT_SOURCE" "${STATE_DIR}/traefik/entrypoint.sh" ||
    die 'managed Traefik entrypoint is stale; rerun bootstrap without --check-only'
fi
if "$WITH_RUNNER_TLS"; then
  validate_tls_material
fi
if "$WITH_AUTOSCALER"; then
  validate_private_file "${STATE_DIR}/runner-secrets/autoscaler.token"
  [[ -s "${STATE_DIR}/runner-secrets/autoscaler.token" ]] || die 'autoscaler API token is empty'
  validate_private_file "${STATE_DIR}/autoscaler/docker-template.json"
fi
validate_state_tree
validate_compose

printf 'Runtrue deployment preflight passed for %s (runtime uid:gid %s:%s).\n' \
  "$STATE_DIR" "$RUNTIME_UID" "$RUNTIME_GID"
printf 'No credential values were printed or replaced.\n'
