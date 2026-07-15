# WASI 0.3 hello action

This minimal component is Runtrue's executable WASI 0.3 compatibility fixture.
It imports the final `wasi:cli/environment@0.3.0` interface and exports the
Runtrue action entry point. The action intentionally performs no side effects;
success proves that the signed component was admitted, linked with the P3 host,
instantiated, and executed without inheriting the runner process environment.

The component is written in WebAssembly text so the fixture does not depend on
a guest-language toolchain shipping the low-tier `wasm32-wasip3` standard
library. The small pinned Rust builder only converts WAT to a component binary.

## Build and run locally

From this directory:

```sh
./scripts/test-local.sh
```

The script builds `dist/runtrue_wasi_0_3_hello.wasm`, executes that exact source
fixture through the signed Runtrue Wasm executor test, and validates the sample
workflow when a local `runtrue` binary is available.

## Prepare a managed E2E bundle

```sh
./scripts/prepare-managed.sh
```

This stages the component, workflow, and digest-pinned lockfile under `dist/`.
Before a managed run, sign and publish the component with an identity trusted by
the destination runner and replace `registry.example`. The machine-readable
`fixtures/e2e.json` records the expected terminal result and runtime contract.

The fixture is deliberately small. A later guest SDK example can add native
WASI 0.3 futures and streams once its toolchain is reproducibly distributable.
