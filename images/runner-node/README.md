# Runtrue Node runner base

This image is the operator-configured OCI fallback for GitHub-hosted Linux jobs
when no microVM pool is configured. It contains Node.js, Bash, and Git, but no
workflow or action-specific entrypoint. Production configuration must reference
the published image by its immutable `sha256` digest.

The OCI runner overrides image metadata with the exact command from the signed
Capsule for every step.
