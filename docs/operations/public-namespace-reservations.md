# Public namespace reservations

This runbook tracks the names that must be controlled before Runtrue is
announced or its first public release is published. A checked item means the
name has been verified live, reserved by an organization-owned account, and
recorded in the private ownership register. Repository documentation must not
claim availability based only on this list.

## Required reservation set

- [ ] GitHub organization `runtrue`
- [ ] Primary developer domain `runtrue.dev`
- [ ] CLI-oriented domain `runtrue.sh`
- [ ] Defensive domains selected by the project owners
- [ ] crates.io package `runtrue`
- [ ] crates.io package `runtrue-cli`
- [ ] GitHub Container Registry namespace under the Runtrue organization
- [ ] Docker Hub organization or other canonical OCI namespace `runtrue`
- [ ] npm scope `@runtrue`
- [ ] Homebrew organization and tap `runtrue/homebrew-tap`
- [ ] Other package-manager names that correspond to an approved distribution
  roadmap

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

The release owner verifies this list immediately before the first public tag.
Names that are unavailable require a naming decision; silently publishing into
an unofficial or maintainer-owned namespace is not an acceptable fallback.
