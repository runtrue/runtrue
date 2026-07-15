#!/usr/bin/env bash
set -Eeuo pipefail

exec 3<>/dev/tcp/127.0.0.1/8080
printf 'GET /healthz HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' >&3
IFS=$'\r' read -r status <&3
[[ "$status" == "HTTP/1.0 200 OK" || "$status" == "HTTP/1.1 200 OK" ]]
