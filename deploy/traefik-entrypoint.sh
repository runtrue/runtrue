#!/bin/sh
set -eu

case "${RUNTRUE_PUBLIC_ORIGIN:-}" in
  https://*) host=${RUNTRUE_PUBLIC_ORIGIN#https://} ;;
  *) echo 'traefik: RUNTRUE_PUBLIC_ORIGIN must be an HTTPS origin' >&2; exit 1 ;;
esac
case "$host" in
  ''|*/*|*:*|*[!A-Za-z0-9.-]*)
    echo 'traefik: RUNTRUE_PUBLIC_ORIGIN must contain only a DNS hostname' >&2
    exit 1
    ;;
esac

upstream=${RUNTRUE_EDGE_UPSTREAM:-http://server:8080}
case "$upstream" in
  http://*) ;;
  *) echo 'traefik: RUNTRUE_EDGE_UPSTREAM must be an internal HTTP service origin' >&2; exit 1 ;;
esac
upstream_authority=${upstream#http://}
upstream_host=${upstream_authority%:*}
upstream_port=${upstream_authority##*:}
case "$upstream_host" in
  ''|.*|*.|*[!a-z0-9.-]*)
    echo 'traefik: RUNTRUE_EDGE_UPSTREAM has an invalid service name' >&2
    exit 1
    ;;
esac
case "$upstream_port" in
  ''|*[!0-9]*)
    echo 'traefik: RUNTRUE_EDGE_UPSTREAM has an invalid port' >&2
    exit 1
    ;;
esac

health_path=${RUNTRUE_EDGE_HEALTH_PATH:-/healthz}
case "$health_path" in
  /*) ;;
  *) echo 'traefik: RUNTRUE_EDGE_HEALTH_PATH must be an absolute path' >&2; exit 1 ;;
esac
case "$health_path" in
  *[!A-Za-z0-9._~/-]*)
    echo 'traefik: RUNTRUE_EDGE_HEALTH_PATH contains an unsafe character' >&2
    exit 1
    ;;
esac

cat > /run/runtrue-traefik/dynamic.yml <<EOF
http:
  routers:
    runtrue-http:
      rule: "Host(\`$host\`)"
      entryPoints: [web]
      middlewares: [redirect-https]
      service: noop@internal
    runtrue:
      rule: "Host(\`$host\`)"
      entryPoints: [websecure]
      middlewares: [security-headers]
      service: runtrue
      tls:
        certResolver: letsencrypt
  services:
    runtrue:
      loadBalancer:
        servers:
          - url: $upstream
        healthCheck:
          path: $health_path
          interval: 10s
          timeout: 3s
  middlewares:
    redirect-https:
      redirectScheme:
        scheme: https
        permanent: true
    security-headers:
      headers:
        contentTypeNosniff: true
        frameDeny: true
        referrerPolicy: no-referrer
        stsSeconds: 31536000
        stsIncludeSubdomains: true
EOF

exec /usr/local/bin/traefik "$@"
