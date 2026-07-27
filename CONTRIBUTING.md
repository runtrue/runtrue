# Contributing to Runtrue

Runtrue is a security-sensitive CI/CD system. Keep changes reviewable,
preserve fail-closed behavior, and include tests for altered trust boundaries.
Do not commit credentials, generated dependency directories, build output, or
production data.

## Development setup

Use the repository-pinned Rust 1.94 toolchain. The dependency graph is
lockfile-bound. Do not update a lockfile unless the change is intentional and
described in the pull request.

Run the relevant focused tests while developing. Before requesting review, run:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
tests/check_brand.sh
tests/conformance/verify_workflow_frontend.sh
python3 tests/conformance/check_schema.py
python3 tests/conformance/check_openapi_routes.py
python3 tests/conformance/check_migrations.py
deploy/tests/validate.sh
```

An update to the GitHub Actions frontend revision or UI image must include the
external repository's locked formatting, Rust and browser tests, strict Clippy
results, and image build for that exact source. Core integration gates validate
the selected artifacts but do not substitute for tests in the external
repository.

Container or build-input changes must retain immutable base-image references,
run without ambient credentials, and pass the image builds in CI. Changes to
protocols, schemas, durable records, release trust, authorization, isolation,
or credential handling need an adversarial regression test and an upgrade note.

## Pull requests

- Explain the user-visible behavior and the security invariant being preserved.
- Separate mechanical refactors from behavioral changes where practical.
- Document migrations, compatibility impact, rollback behavior, and operational
  actions.
- Keep generated fixtures deterministic and synthetic.
- Obtain CODEOWNERS review for release and trust-boundary changes.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
