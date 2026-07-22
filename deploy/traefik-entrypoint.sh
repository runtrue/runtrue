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
          - url: http://frontend:3000
        healthCheck:
          path: /frontend-healthz
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
