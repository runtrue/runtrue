# Lane 16: SCM

## Goal and ownership

Split `crates/scm/src/lib.rs` and `src/github.rs`, retaining focused
`workflow_source.rs`. This lane exclusively owns `crates/scm/**`. Start after
lane 15.

## Target layout

```text
src/{lib,model,provider,error}.rs
src/github/{mod,client,installation,webhook,checks,pagination,validation}.rs
src/workflow_source.rs
```

## Steps

1. Move provider-neutral SCM models, traits, outcomes, and errors out of
   `lib.rs`; preserve root re-exports.
2. Convert `github.rs` to `github/mod.rs` and extract HTTP client/request
   construction separately from domain projection.
3. Move installation/repository discovery and selection.
4. Move webhook parsing, signature/event validation, and delivery identity.
5. Move check-run/check-suite publication and pagination behavior.
6. Keep GitHub-specific origin, identifier, permission, and payload validation
   in `github/validation.rs` when shared.
7. Split tests by client, installation, webhook, checks, pagination, and source
   selection.

Preserve request signing, bounded payloads, event identity, pagination,
permission checks, and provider-neutral exports. Run standard checks for
`runtrue-scm`.
