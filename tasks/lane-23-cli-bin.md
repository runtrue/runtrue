# Lane 23: CLI binary

## Goal and ownership

Split `bins/cli/**` after lanes 08, 13, 18, and 19. This agent owns only the
CLI binary crate. Preserve the `runtrue` command name, flags, exit codes, output
schemas, and public behavior.

## Target layout

```text
src/main.rs
src/{cli,error,output,paths,strict_json}.rs
src/commands/{mod,init,import,validate,plan,run,replay,compare,doctor}.rs
src/admin/{mod,secrets,variables,secure_fs}.rs
src/remote/{mod,models,client,authentication,submit}.rs
src/{approve,reusable}.rs
tests/{cli,init,import,execution,remote,admin,security}.rs
```

## Steps

1. Move Clap argument structures and command dispatch to `cli.rs`; leave
   `main.rs` responsible only for parsing, calling dispatch, and returning an
   exit code.
2. Extract init and GitHub import workflows, keeping atomic multi-output
   publication and rollback together.
3. Extract validate, plan, run, replay, plan comparison, and doctor commands.
4. Move workflow discovery, bounded file reads, strict event JSON, local plan
   validation, and output rendering to specifically named modules.
5. Convert `admin.rs` to `admin/mod.rs`; separate secrets, variables, and
   private/no-follow filesystem operations. Keep secret-bearing values with
   zeroization and redacted debug behavior.
6. Convert `submit.rs` to `remote/mod.rs`; separate wire models, authenticated
   client, bearer-token loading, origin validation, idempotency, and submit
   orchestration.
7. Retain focused `approve.rs` and `reusable.rs` unless they independently
   exceed the production threshold.
8. Split the 2,000-line CLI test suite by command family while retaining common
   process/fixture support in `tests/support/mod.rs`.

## Safety constraints

Preserve exact JSON field names, human output, exit code classification,
idempotency keys, output-path confinement, atomic writes, secret permissions,
and CLI compatibility.

## Verification

```text
cargo fmt -p runtrue-cli -- --check
cargo check -p runtrue-cli --all-targets
cargo test -p runtrue-cli
cargo clippy -p runtrue-cli --all-targets
```
