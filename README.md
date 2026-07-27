# Runtrue

**Run local. Run remote. Run true.**

Runtrue is a Rust execution engine for reproducible, policy-controlled
workflows. It compiles an exact workflow and runtime contract into an immutable
execution capsule, binds approvals to that capsule, and produces replayable
evidence of what ran.

## Why Runtrue

- **Exact execution identity:** workflows, inputs, source, runtime, and policy
  are bound to a canonical digest.
- **Fail-closed security:** unsupported capabilities are rejected instead of
  silently falling back to a less isolated executor.
- **Portable execution:** the same workflow model can run locally or on remote
  Native, OCI, Wasm, and MicroVM runners.
- **Policy and evidence:** approvals, secrets, artifacts, audit records, and
  replay bundles remain tied to the admitted execution.

## Project status

Runtrue is pre-1.0 software. The supported evaluation profile is a single-node
control plane with local or remote runners; it is not yet a general
high-availability production recommendation.

See the [technical design](docs/technical-design.md) for the architecture,
threat model, and current boundaries.

## Try a local workflow

Runtrue requires Rust 1.94.0. From the repository root:

```sh
cargo run -p runtrue-cli -- validate \
  --workflow examples/workflows/secure-ci.yaml

cargo run -p runtrue-cli -- run smoke \
  --workflow examples/workflows/secure-ci.yaml \
  --allow-native \
  --replay-bundle runtrue.replay.json

cargo run -p runtrue-cli -- replay runtrue.replay.json --allow-native
```

Native execution is not a sandbox. Use `--allow-native` only for reviewed
workflows on a trusted or disposable host.

For a containerized control plane and runners, follow the
[Docker Compose evaluation guide](deploy/README.md).

## Documentation

- [Workflow semantics](docs/operations/workflow-semantics.md)
- [Architecture decisions](docs/adr)
- [HTTP API](api/openapi.yaml)
- [Single-node deployment](docs/operations/single-node-deployment.md)
- [Backup and recovery](docs/operations/single-node-backup-restore.md)
- [Security policy](SECURITY.md)

## Contributing

GitHub Actions runs the complete verification suite, including formatting,
Clippy, workspace tests, protocol conformance, dependency and secret scanning,
and Docker image builds. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a
change.

## License

Runtrue is licensed under the [Apache License 2.0](LICENSE).
