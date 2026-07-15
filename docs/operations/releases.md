# Release and promotion runbook

Runtrue does not currently ship a GitHub Actions CI or release workflow. That
is intentional: release automation remains disabled until the project can run
and validate this process on Runtrue itself. Do not add a temporary GitHub
Actions publisher as a shortcut.

Until the native workflow exists, this document is a manual, fail-closed
operator checklist. Keep repositories and all generated artifacts private. Do
not publish a tag, package, image, archive, or release while any required step
is manual unless the release decision explicitly authorizes that process.

## Source and verification gates

Start from a clean checkout of the exact proposed commit. Use Rust 1.88.0, Go
1.24 or newer, Node.js 22.17.0, the locked dependency graph, and a controlled
builder with no ambient publication credentials.

```bash
cargo +1.88.0 fetch --locked
cargo +1.88.0 fmt --all -- --check
cargo +1.88.0 check --workspace --all-targets --locked
cargo +1.88.0 test --workspace --locked
cargo +1.88.0 clippy --workspace --all-targets --locked -- -D warnings
tests/check_brand.sh
python3 tests/conformance/check_schema.py
python3 tests/conformance/check_openapi_routes.py
python3 tests/conformance/check_migrations.py
deploy/tests/validate.sh
npm --prefix web test
(cd components/github-signer && go test ./...)
cargo +1.88.0 audit
```

Also build every shipped container definition from its pinned base and rerun
the update trust and rollback acceptance suite:

```bash
docker build --file web/Containerfile --tag runtrue/web:verify web
docker build --tag runtrue/runner-node:verify images/runner-node
cargo +1.88.0 test --locked -p runtrue-update -p runtrue-update-cli
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
web and runner-node multi-architecture OCI layouts with embedded SBOM and
provenance attestations. Create `COMPONENTS.json` that binds every independently
versioned component to the exact source commit and proposed tag.

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

## Native automation requirement

The future Runtrue release workflow must preserve the same separation:
credential-free build jobs, immutable evidence transfer, exact-plan approval,
independent signing, and a distinct promotion job. Publication credentials may
exist only in that final approved boundary. Bisim must cover the local and
remote release plan before automated publication is enabled.

## Consumer verification

Consumers establish the root digest through the ceremony in
[secure updates](secure-updates.md), verify the desired target, and apply the
same signed bundle to advance monotonic local state. A checksum file or hosting
provider attestation alone never replaces the pinned update root. Existing
installations must also follow the [v0.x upgrade runbook](upgrading.md).
