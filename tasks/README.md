# Crate modularization task lanes

This directory turns the library- and binary-crate splitting plan into an
execution backlog for fast agents that should be given narrow, mechanical
tasks. The objective is to move code under both `crates/` and `bins/` into
domain-owned modules without changing behavior, public API paths, CLI or HTTP
contracts, serialization, SQL, or security checks.

## How to use these lanes

1. Complete `lane-00-baseline.md` first.
2. Run `lane-01-control-plane-foundation.md` through
   `lane-06-control-plane-identity-policy-deployment.md` in order. These lanes
   deliberately share control-plane files and must not run concurrently.
3. After lane 00, dependency-ready lanes 07-29 may run concurrently when each
   active agent has exclusive ownership of every crate named in its lane.
4. Complete `lane-30-final-audit.md` after all accepted lanes are merged.
5. Use `COORDINATOR_PROMPT.md` as the prompt for the main coordinating agent.

## Lane index

| Lane | Scope | Depends on | Parallel class |
|---|---|---|---|
| 00 | Baseline and API inventory | None | Gate |
| 01 | Control-plane foundation | 00 | CP sequential |
| 02 | Control-plane public types | 01 | CP sequential |
| 03 | Control-plane installation, repositories, SCM, runs | 02 | CP sequential |
| 04 | Control-plane runners and durable state | 03 | CP sequential |
| 05 | Control-plane artifacts, cache, lifecycle, workflow | 04 | CP sequential |
| 06 | Control-plane identity, policy, deployments | 05 | CP sequential |
| 07 | Compiler | 19 | Independent crate |
| 08 | GitHub Actions importer | 07 | Independent crate |
| 09 | OCI executor | 10 | Independent crate |
| 10 | Engine | 19 | Independent crate |
| 11 | Cache | 12 | Independent crate |
| 12 | Storage | 00 | Independent crate |
| 13 | Local runtime | 07, 10, 11, 12, 14 | Independent crate |
| 14 | Artifacts | 12 | Independent crate |
| 15 | Git | 00 | Independent crate |
| 16 | SCM | 15 | Independent crate |
| 17 | Wasm and Firecracker executors | 10, 21 | Exclusive to both crates |
| 18 | Auth, OIDC, signing, and secrets | 00 | Exclusive to four crates |
| 19 | Workflow AST, IR, expressions, and lock files | 00 | Exclusive to four crates |
| 20 | Logs, reports, update, and debug sessions | 00 | Exclusive to four crates |
| 21 | Guest, runner, scheduler, and trusted planner | 07, 15, 16, 19 | Exclusive to four crates |
| 22 | Remaining medium modules | 06, 11, 12, 14, 15, 18, 20 | Exclusive to listed crates |
| 23 | CLI binary | 08, 13, 18, 19 | Independent binary crate |
| 24 | Runner entrypoint and daemon | 09, 11, 12, 14, 15, 17, 19, 21 | Runner sequential |
| 25 | Runner backends, state, transport, and data plane | 24 | Runner sequential |
| 26 | Server HTTP application | 06-22, 25 | Server sequential |
| 27 | Server runner services | 26 | Server sequential |
| 28 | Server SCM worker, identity, and startup | 27 | Server sequential |
| 29 | Guest, image, and update binaries | 17, 20, 21, 22 | Exclusive to three binary crates |
| 30 | Workspace audit and enforcement | All accepted lanes | Final gate |

## Rules every agent must follow

- Read this file and the assigned lane completely before editing.
- Work only in the files and crates assigned to the lane.
- Treat existing changes as user-owned. Do not reset, revert, or overwrite them.
- Perform mechanical moves before cleanup. Do not redesign behavior while
  extracting modules.
- Preserve crate-root public imports using `pub use`.
- Do not change SQL, migrations, serialized field names, protocol values,
  cryptography, authorization logic, or state transitions.
- Do not create `utils.rs`, `helpers.rs`, or `common.rs`. Shared modules must be
  named for their responsibility.
- Keep atomic transactions and security-sensitive validation flows intact.
- Use the narrowest visibility that compiles. Never make fields public merely
  to cross a module boundary.
- Use `apply_patch` for edits and `rg` for searches.
- Do not edit files under `tasks/`; the coordinator owns task status.
- Do not commit. The coordinator owns integration and commits.
- Do not run workspace-wide formatting while other editing agents are active.
- Report every touched file, command run, test result, and remaining warning.
- If the baseline fails before edits, record it and stop rather than hiding it.
- If another active agent owns a needed file, stop and notify the coordinator.

## Standard verification

Unless a lane specifies more, run:

```text
cargo fmt --check
cargo check -p <package>
cargo test -p <package>
cargo clippy -p <package> --all-targets
```

At lane boundaries, the coordinator runs `cargo check --workspace`. Full
workspace tests and Clippy belong to lane 30.
