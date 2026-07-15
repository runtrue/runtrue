# Lane 29: guest, image, and update binaries

## Goal and ownership

Split remaining executable crates under `bins/guest`, `bins/image`, and
`bins/update` after lanes 17, 20, 21, and 22. One agent owns these three binary
crates and processes them sequentially.

## Guest target

Retain its existing module layout, splitting only oversized cohesive files:

```text
src/process/{mod,executor,command,capture,cleanup}.rs
src/service/{mod,session,job,steps,protocol}.rs
src/boot.rs
src/wire.rs
src/error.rs
```

Keep authenticated framing, guest session state, process cleanup, and one-job
service ordering unchanged.

## Image target

```text
src/main.rs
src/{cli,keys,digest,manifest,sign,verify,snapshot,secure_fs,output,error}.rs
```

Leave `main.rs` as parse/dispatch only. Preserve canonical manifest bytes,
signature domains, payload hashing, warm-snapshot sterility, path checks, key
permissions, and JSON output.

## Update target

```text
src/main.rs
src/{cli,root,bootstrap,verify,apply,keys,provenance,sbom,cargo_metadata,output,error}.rs
```

Preserve trust-state rollback protection, verification-before-publication,
canonical provenance/SBOM output, bounded reads, key secrecy, and CLI behavior.

Split each binary's tests by command or protocol family, preserve all flags and
exit behavior, and run standard checks for `runtrue-guest`, `runtrue-image`, and
`runtrue-update-cli`.
