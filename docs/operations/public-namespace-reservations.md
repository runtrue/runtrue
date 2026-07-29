# Public namespace reservations

This runbook tracks the names that must be controlled before Runtrue publishes
into each distribution channel. A checked item means the name has been
verified live, reserved by an organization-owned account, and recorded in the
private ownership register. Repository documentation must not claim
availability based only on this list.

## Current source and runtime-image release

- [ ] GitHub organization `runtrue`
- [ ] GitHub Container Registry namespace under the Runtrue organization

The current release scope is the public source repository plus the
`runtrue-server` and `runtrue-runner` images in GHCR. These two reservations
must be verified immediately before the first public version tag.

## Deferred distribution channels

- [ ] Primary developer domain `runtrue.dev`
- [ ] CLI-oriented domain `runtrue.sh`
- [ ] Defensive domains selected by the project owners
- [ ] crates.io package `runtrue`
- [ ] crates.io package `runtrue-cli`
- [ ] Docker Hub organization or other canonical OCI namespace `runtrue`
- [ ] npm scope `@runtrue`
- [ ] Homebrew organization and tap `runtrue/homebrew-tap`
- [ ] Other package-manager names that correspond to an approved distribution
  roadmap

These names become release gates only when their distribution channel is added
to an approved release plan. Rust packages intentionally retain
`publish = false` while crates.io distribution is deferred.

Do not publish empty placeholder packages. Each registry reservation must ship
a legitimate minimal artifact, metadata that points to the canonical project,
and a security contact in accordance with that registry's policies.

## Ownership record

For every reservation, record outside this public repository:

- owning organization and administrative contacts;
- MFA and recovery-key custody;
- registrar or registry account;
- renewal and billing ownership where applicable;
- canonical verification URL;
- date last verified; and
- transfer and incident-recovery procedure.

Domain DNS, package publishing, image publishing, and GitHub administration
must use organization-controlled identities rather than a single maintainer's
personal account.

## Release gate

The release owner verifies every reservation in the approved channel set
immediately before a public tag. Names that are unavailable require a naming
decision; silently publishing into an unofficial or maintainer-owned namespace
is not an acceptable fallback.
