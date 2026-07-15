# Workflow frontend extraction boundary

GitHub Actions is Runtrue's first workflow source frontend, but it is not part
of the execution kernel. The adapter currently lives at `crates/gha-import`
and is registered by the default `github-actions` feature in the server and
CLI. Both binaries must continue to compile with `--no-default-features`.

## Repository boundary

The future private repository should be `runtrue/github-actions-frontend`. It
owns the importer implementation, compatibility report, fixtures, adapter
security tests, and adapter release notes. Start it with a new root commit;
do not copy this repository's Git history.

The Runtrue repository continues to own:

- `runtrue-workflow-frontend` and its registry, integrity, ambiguity, and
  dishonest-frontend tests;
- Capsule, Seal, compiler, lockfile, and frontend provenance semantics;
- GitHub SCM authentication, source fetching, webhook normalization, checks,
  and installation lifecycle;
- the composition feature that selects the adapter for a server or CLI build.

Moving the workflow frontend does not move the GitHub SCM provider.

## Private dependency rule

While packages remain private and `publish = false`, the adapter repository
must consume its Runtrue packages from the private Runtrue Git repository. All
dependencies must use the same full 40-character `rev`; branches, floating
tags, and mixed Runtrue revisions are forbidden.

The adapter's current production dependency set is:

- `runtrue-compiler`
- `runtrue-lock`
- `runtrue-model`
- `runtrue-workflow-ast`
- `runtrue-workflow-frontend`

Its manifest should use entries of this form for every package:

```toml
runtrue-workflow-frontend = {
  git = "https://github.com/runtrue/runtrue.git",
  rev = "<full-reviewed-runtrue-commit>"
}
```

After extraction, Runtrue's workspace dependency for `runtrue-gha-import`
must point to one exact reviewed commit in the private adapter repository. The
server and CLI keep that dependency optional and enable it through their
default `github-actions` feature until another composition becomes the default.

## Compatibility identity

The adapter crate follows its own `0.x` version. `frontend_id` remains
`runtrue.github-actions`. Increment `frontend_generation` whenever translation,
lock generation, or report semantics can change for identical input. The
generation and exact input, native output, and report digests remain Capsule
and Seal material; a changed adapter cannot reuse an earlier approval.

## Test ownership and gates

Runtrue core must pass:

```text
cargo test -p runtrue-workflow-frontend -p runtrue-trusted-planner
cargo check -p runtrue-server --no-default-features --all-targets
cargo check -p runtrue-cli --no-default-features --all-targets
```

The adapter repository must run all importer fixtures and security tests
against its single pinned Runtrue revision. A private integration build must
then enable `github-actions` and prove discovery, planning, approval, replan,
and execution of a workflow under `.github/workflows/`.

The adapter revision may advance only when those core, adapter, and integrated
gates all pass against the same pair of commits. Record both commits in the
deployment evidence.

## Extraction sequence

1. Create the private adapter repository with a new root commit.
2. Copy `crates/gha-import`, preserving fixtures and tests but no Git history.
3. Replace workspace dependencies with one exact Runtrue `rev`.
4. Pass adapter tests and the integrated default-feature test.
5. Replace Runtrue's local adapter dependency with one exact adapter `rev`.
6. Remove `crates/gha-import` from this workspace only after the external
   default-feature and no-default-feature builds both pass.
7. Deploy the exact Runtrue and adapter commit pair before enabling repository
   workflow execution.
