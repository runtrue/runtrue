# Release and promotion runbook

Runtrue uses GitHub Actions to verify pull requests and pushes to `main`.
Release automation remains disabled: CI validates source, dependencies,
conformance, deployment configuration, and the runner image, but it does not
publish tags, packages, images, archives, or releases.

This document remains a manual, fail-closed operator checklist. Keep all
generated release artifacts private. Do not publish a tag, package, image,
archive, or release while any required step is manual unless the release
decision explicitly authorizes that process. Public source visibility does not
authorize a release.

## Source and verification gates

Start from a clean checkout of the exact proposed commit. Use Rust 1.94.0, the
locked dependency graph, and a controlled builder with no ambient publication
credentials.

```bash
cargo +1.94.0 fetch --locked
cargo +1.94.0 fmt --all -- --check
cargo +1.94.0 check --workspace --all-targets --locked
cargo +1.94.0 test --workspace --locked
cargo +1.94.0 clippy --workspace --all-targets --locked -- -D warnings
tests/check_brand.sh
tests/conformance/verify_workflow_frontend.sh
python3 tests/conformance/check_schema.py
python3 tests/conformance/check_openapi_routes.py
python3 tests/conformance/check_migrations.py
deploy/tests/validate.sh
cargo +1.94.0 audit
```

The exact GitHub Actions frontend commit and UI image selected by a product
distribution must also pass that repository's locked formatting, Rust and
browser tests, strict Clippy gates, and image build in a clean checkout. Retain
those results with the release evidence; core gates verify only the neutral
frontend contract and do not execute an external repository's test suite.

Also build every shipped container definition from its pinned base and rerun
the update trust and rollback acceptance suite:

```bash
docker build --tag runtrue/runner-node:verify images/runner-node
cargo +1.94.0 test --locked -p runtrue-update -p runtrue-update-cli
```

Any failure stops the release. Record the exact tool versions, source commit,
commands, builder identity, and results in the release evidence.

## Build and evidence

Build the six Rust binaries for `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu` from the locked graph:

- `runtrue`
- `runtrue-guest`
- `runtrue-image`
- `runtrue-runner`
- `runtrue-server`
- `runtrue-update`

Package deterministic per-binary archives with normalized timestamps,
ownership, ordering, and gzip headers. Generate a dependency-complete
CycloneDX SBOM and canonical provenance statement for every archive. Build the
runner-node multi-architecture OCI layout with embedded SBOM and provenance
attestations. Record the independently released GitHub Actions UI image digest
in `COMPONENTS.json` alongside every core component's exact source and tag.

The expected evidence set contains 40 build files before `SHA256SUMS` and 41
after it. Recompute checksums from the exact collected bytes under `LC_ALL=C`.
Missing, extra, hard-linked, symlinked, or mismatched content stops promotion.

## Signing and promotion

An independent signer must:

1. Verify the source commit, builder identity, complete evidence inventory, and
   every checksum.
2. Construct higher-versioned targets, snapshot, and timestamp envelopes, plus
   any required sequential dual-signed root rotation.
3. Use separated offline or non-exportable role authorities; private role keys
   must never enter a general-purpose build worker.
4. Verify the signed root through its independently recorded qualified SHA-256
   digest.
5. Build the verifier from the exact proposed source, bootstrap only from that
   root digest, and verify all 41 files before advancing trust state.
6. Record independent release-engineering and security approval with no
   self-approval.

Targets expiry must enclose snapshot expiry, which must enclose timestamp
expiry. Target names are normalized basenames. A repeated build produces new
bytes and therefore requires new checksums, metadata, signatures, and approval.
Never edit an archive, SBOM, provenance statement, checksum list, or bundle
after signing.

## Automation requirement

Any future Runtrue release workflow must preserve the same separation:
credential-free build jobs, immutable evidence transfer, exact-plan approval,
independent signing, and a distinct promotion job. Publication credentials may
exist only in that final approved boundary. Bisim must cover the local and
remote release plan before automated publication is enabled.

The checked-in GitHub Actions workflow is deployment-agnostic, runs without
repository secrets, and has read-only source permission. It is the current
source-verification path for both pull requests and `main`; it does not replace
Runtrue's runtime isolation or release trust boundaries.

## Consumer verification

Consumers establish the root digest through the ceremony in
[secure updates](secure-updates.md), verify the desired target, and apply the
same signed bundle to advance monotonic local state. A checksum file or hosting
provider attestation alone never replaces the pinned update root. Existing
installations must also follow the [v0.x upgrade runbook](upgrading.md).
