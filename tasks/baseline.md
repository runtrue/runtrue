# Modularization baseline

Recorded from the clean pre-modularization commit `8c1388b chore: checkpoint
pre-modularization baseline` on 2026-07-13. `git status --short` was empty.

## Toolchain blocker

The installed toolchain is `rustc/cargo 1.75.0`; the workspace declares
`rust-version = "1.88"`, and `Cargo.lock` is lockfile format 4. `rustup` is not
installed in this environment.

| Command | Result |
| --- | --- |
| `cargo fmt --check` | Passed |
| `cargo check --workspace` | Blocked: `lock file version 4 requires -Znext-lockfile-bump` |
| `cargo test --workspace` | Blocked: same lockfile parse error |
| `cargo clippy --workspace --all-targets` | Blocked: same lockfile parse error |

No source or manifest was changed to work around this pre-existing environment
failure. All implementation lanes remain gated on a Rust 1.88-or-newer Cargo.

## Source inventory

Format: `path | total lines | top-level tests start` (`-` means none). The
test boundary was identified only for a top-level `#[cfg(test)] mod tests`.

```text
bins/cli/src/admin.rs|1241|-
bins/cli/src/approve.rs|163|153
bins/cli/src/main.rs|2071|2011
bins/cli/src/reusable.rs|292|285
bins/cli/src/submit.rs|802|762
bins/cli/tests/cli.rs|2079|-
bins/guest/src/boot.rs|311|281
bins/guest/src/lib.rs|49|-
bins/guest/src/main.rs|38|-
bins/guest/src/process.rs|553|463
bins/guest/src/service.rs|372|-
bins/guest/src/wire.rs|211|184
bins/guest/tests/system.rs|189|-
bins/image/src/main.rs|794|672
bins/runner/src/broker.rs|980|609
bins/runner/src/credentials.rs|1585|1107
bins/runner/src/daemon.rs|2829|1834
bins/runner/src/data_plane.rs|942|869
bins/runner/src/enrollment.rs|243|-
bins/runner/src/firecracker.rs|1851|1574
bins/runner/src/inventory.rs|686|604
bins/runner/src/lib.rs|35|-
bins/runner/src/main.rs|962|853
bins/runner/src/oci.rs|1320|768
bins/runner/src/state.rs|1081|831
bins/runner/src/transport.rs|1051|949
bins/runner/src/wasm.rs|1140|648
bins/runner/tests/cli.rs|119|-
bins/server/src/app.rs|8399|8357
bins/server/src/github_install_ui.rs|963|777
bins/server/src/human_oidc.rs|1233|1013
bins/server/src/lib.rs|42|-
bins/server/src/main.rs|2139|1632
bins/server/src/runner_broker.rs|243|150
bins/server/src/runner_certificates.rs|436|331
bins/server/src/runner_service.rs|7693|5817
bins/server/src/scm_worker.rs|3527|3027
bins/server/tests/http.rs|3846|-
bins/server/tests/runner_e2e.rs|1127|-
bins/server/tests/scm_worker.rs|830|-
bins/update/src/main.rs|515|-
bins/update/tests/cli.rs|294|-
crates/artifacts/src/lib.rs|2502|1543
crates/attest/src/image.rs|711|567
crates/attest/src/lib.rs|507|387
crates/audit/src/lib.rs|508|419
crates/audit/src/signed.rs|221|165
crates/auth/src/lib.rs|1166|823
crates/auth/src/oidc.rs|631|347
crates/backup/src/database.rs|737|709
crates/backup/src/format.rs|94|-
crates/backup/src/lib.rs|751|-
crates/backup/src/main.rs|184|-
crates/backup/src/secure_fs.rs|799|-
crates/backup/tests/roundtrip.rs|661|-
crates/cache/src/lib.rs|3234|2225
crates/compiler/src/lib.rs|6147|-
crates/bisim/src/lib.rs|608|335
crates/control-plane/src/lib.rs|15|-
crates/control-plane/src/store.rs|35168|26958
crates/control-plane/src/types.rs|2547|-
crates/debug-session/src/lib.rs|1389|1049
crates/deploy/src/lib.rs|1074|688
crates/engine/src/lib.rs|4009|2797
crates/executor-dispatch/src/lib.rs|372|122
crates/executor-firecracker/src/config_state.rs|810|572
crates/executor-firecracker/src/image.rs|1255|829
crates/executor-firecracker/src/lib.rs|110|-
crates/executor-firecracker/src/platform.rs|396|334
crates/executor-firecracker/src/process.rs|351|286
crates/executor-firecracker/src/session.rs|457|-
crates/executor-firecracker/src/snapshot.rs|657|382
crates/executor-firecracker/src/transport.rs|273|221
crates/executor-oci/src/lib.rs|4351|3153
crates/executor-oci/src/process.rs|494|380
crates/executor-wasm/src/cache.rs|802|720
crates/executor-wasm/src/host.rs|1155|844
crates/executor-wasm/src/lib.rs|2297|1561
crates/executor-wasm/src/rooted_fs.rs|394|263
crates/expression/src/lib.rs|1969|-
frontends/github-actions/src/lib.rs|4296|3941
crates/git/src/benchmark.rs|167|117
crates/git/src/lib.rs|2539|1741
crates/git/src/mirror.rs|3027|2335
crates/git/src/origin.rs|247|197
crates/guest-core/src/lib.rs|1641|1288
crates/lifecycle/src/lib.rs|186|152
crates/lock/src/lib.rs|1277|1064
crates/logs/src/lib.rs|2257|1833
crates/model/src/lib.rs|244|213
crates/network/src/lib.rs|732|511
crates/oidc/src/lib.rs|2066|1381
crates/output-lifecycle/src/lib.rs|814|702
crates/policy/src/active_bundle.rs|1045|804
crates/policy/src/break_glass.rs|581|416
crates/policy/src/cedar.rs|765|614
crates/policy/src/lib.rs|473|332
crates/policy/src/lifecycle.rs|524|356
crates/protocol/build.rs|37|-
crates/protocol/src/lib.rs|391|255
crates/protocol/tests/contract.rs|875|-
crates/replay/src/lib.rs|390|250
crates/reports/src/lib.rs|1348|1160
crates/reports/src/main.rs|77|-
crates/runner-core/src/lib.rs|940|636
crates/runtime-local/src/lib.rs|3012|2161
crates/scheduler/src/lib.rs|904|701
crates/scm/src/github.rs|3308|-
crates/scm/src/lib.rs|1379|1076
crates/scm/src/workflow_source.rs|605|278
crates/secrets/src/key_file.rs|349|-
crates/secrets/src/lib.rs|21|-
crates/secrets/src/provider.rs|1985|1495
crates/secrets/src/runner_broker.rs|1071|642
crates/secrets/src/sensitive.rs|91|-
crates/secrets/src/vault.rs|1555|1152
crates/signing/src/lib.rs|1941|1358
crates/storage/src/lib.rs|2734|2210
crates/storage/tests/bounded_rss.rs|188|-
crates/storage/tests/object_transfer_chaos.rs|295|-
crates/trusted-planner/src/lib.rs|1112|606
crates/update/src/lib.rs|2367|1669
crates/update/src/secure_fs.rs|223|-
crates/update/src/strict_json.rs|156|-
crates/update/src/trust_store.rs|357|-
crates/workflow-ast/src/lib.rs|1209|1047
crates/workflow-ir/src/lib.rs|1222|922
```

## Public API and compatibility map

Library façade roots inspected: `bins/guest/src/lib.rs`, `bins/runner/src/lib.rs`,
`bins/server/src/lib.rs`, and every `crates/*/src/lib.rs` in the inventory.
These roots are the compatibility surfaces: every existing top-level `pub use`,
`pub mod`, and `pub` declaration must retain its crate-root path. In particular,
the glob façades are `runtrue_attest::image::*`, `runtrue_audit::signed::*`,
`runtrue_auth::oidc::*`, `runtrue_control_plane::store::*`,
`runtrue_control_plane::types::*`, `runtrue_policy::{active_bundle,break_glass,cedar,lifecycle}::*`,
`runtrue_scm::{github,workflow_source}::*`, and the multi-module façade roots in
the runner, server, executor-firecracker, executor-wasm, git, backup, secrets,
and update crates. The control-plane crate root is only `store`/`types`
re-exports, so both paths require special protection.

Workspace consumers use qualified `runtrue_*::...` imports throughout `crates/`
and `bins/`; later lanes must keep root re-exports rather than exposing new
module paths. The baseline search covered all Rust sources with
`rg -n 'runtrue_[a-z_]+::[A-Za-z_]' crates bins --glob '*.rs'`.

## Fixtures and explicit review items

Protocol fixtures are `crates/protocol/tests/fixtures/runner-v1.sha256` and
`runner-v2.sha256`; importer fixtures are under `frontends/github-actions/tests/fixtures/`.
Test/fixture-heavy files include the test files shown in the inventory. The
875-line `crates/protocol/tests/contract.rs` is an explicit extra review item.
The smaller explicit-review crates are `executor-dispatch`, `lifecycle`,
`model`, `protocol`, and `replay`.

## Oversized production targets

The production files at or above 800 total lines are covered by lanes 01-29;
the largest are `control-plane/src/store.rs` (35,168), server `app.rs` (8,399),
server `runner_service.rs` (7,693), and compiler `lib.rs` (6,147). Files whose
large portion is under the recorded top-level test boundary still require the
lane's production/responsibility review rather than automatic splitting.
