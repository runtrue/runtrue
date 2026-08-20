# Changelog

All notable user-visible changes are documented here. This project follows
[Semantic Versioning](https://semver.org/) while it is pre-1.0: minor releases
may change APIs, but migrations and compatibility requirements remain explicit.

## Unreleased

### Added

- Private, durable supervisor-log archives for autoscaled Docker runners,
  captured before ephemeral containers are removed.
- A Runtrue-native container action for release-target synchronization.
- Browser-based GitHub App installation, repository onboarding, and human OIDC
  flows separated from the runner protocol.
- Durable SCM check revision journaling in database migrations 27 and 28.
- Multi-architecture OCI release evidence with embedded SBOM and provenance
  attestations for the published server and unified runner images.

### Changed

- Runners continue fenced lease heartbeats while hydrating source snapshots, so
  bounded source transfers cannot expire an otherwise healthy job assignment.
- Renamed the public project to **Runtrue** with the `runtrue` CLI, `.runtrue`
  configuration, `RUNTRUE_*` environment variables, `runtrue-*` packages and
  images, and the `@runtrue` JavaScript scope.
- Established Capsule, Seal, Bisim, and Replay Bundle as the canonical product
  vocabulary before the first public tag.
- Repository installation no longer implicitly authorizes every repository;
  an authorized user selects repositories during onboarding.
- The CSRF cookie uses `SameSite=Lax` so the OAuth navigation can return to the
  browser flow; state-changing requests still require an independent CSRF token.
- Core no longer ships a GitHub App private-key implementation or signer image.
  GitHub App deployments provide an independently reviewed, network-disabled
  JWT provider through the existing bounded Unix-socket protocol.
- Add an opt-in, hardened Compose lifecycle and provider-independent protocol
  probe for a separately built, digest-pinned GitHub App JWT provider image.
### Security

- Updated `h2` to 0.4.16 to bound processing of empty DATA frames.
- Runner and SCM operations continue to require current installation, lease,
  attempt, certificate, and repository authorization fences.

The first v0.x release will establish the supported single-node evaluation
profile described in [the upgrade guide](docs/operations/upgrading.md).
