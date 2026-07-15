FROM node:22.17.0-alpine3.22@sha256:fc3e945f920b7e3000cd1af86c4ae406ec70c72f328b667baf0f3a8910d69eed

ARG RUNTRUE_RUNNER_IMAGE_VERSION=0.1.0
LABEL org.opencontainers.image.title="Runtrue Node Runner Base" \
      org.opencontainers.image.version="${RUNTRUE_RUNNER_IMAGE_VERSION}" \
      org.opencontainers.image.description="Minimal Node, Bash, and Git filesystem for OCI workflow jobs"

RUN apk add --no-cache \
      bash=5.2.37-r0 \
      git=2.49.1-r0

WORKDIR /workspace

# The runner supplies an approval-bound command with --entrypoint for every
# step. Deliberately leave ENTRYPOINT and CMD unset.
