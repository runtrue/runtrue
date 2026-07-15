# ADR 0004: Capsule identity and compatibility versioning

- **Status:** Accepted
- **Compatibility scope:** v0.x
- **Date:** 2026-07-15

## Context

Capsules are compiled locally and remotely, persisted, signed, approved, sent to
runners, and retained in Replay Bundles. Their identity must therefore be
deterministic within a supported compiler generation, and incompatible encoding
changes must not reinterpret existing signatures or Seals.

Runtrue v0.x currently has one Rust implementation. It does not yet promise
cross-language canonical JSON compatibility or a permanently frozen wire
encoding.

## Decision

For v0.x, derive a Capsule identity as follows:

1. Strictly parse and validate the workflow into the typed Capsule model.
2. Materialize every execution-affecting default and resolved immutable
   dependency in that model.
3. Convert the Capsule to JSON, recursively sort object keys by bytewise UTF-8
   order, and preserve array order.
4. Serialize compact UTF-8 JSON with the repository-pinned Rust and
   `serde_json` generation.
5. Hash the exact bytes with SHA-256 and render the qualified digest as
   `sha256:` followed by lowercase hexadecimal characters.

The exact canonical bytes, not source YAML or a reparsed approximation, are the
signed and persisted Capsule representation. A receiver verifies the digest and
signature over those bytes before admission and must reject an unknown Capsule
schema or incompatible engine compatibility generation.

The approval subject is independently canonicalized under an explicit subject
version. It binds the Capsule digest plus authorization inputs that are
intentionally outside the Capsule. It is not interchangeable with the Capsule
digest.

Any incompatible change to Capsule fields, default materialization,
canonicalization, digest/signature domain, approval-subject encoding, or engine
semantics requires a new explicit compatibility generation. Existing bytes are
never silently reinterpreted under the same generation.

Cross-language implementations must not claim Capsule identity compatibility
until Runtrue adopts a language-independent canonical encoding and adds
cross-implementation conformance vectors.

## Consequences

- Local and remote Rust builds from the supported generation can compare exact
  Capsule identities.
- Signatures, Seals, stored Capsules, and Replay Bundles have an unambiguous byte
  representation.
- Dependency or serializer upgrades that affect canonical bytes are protocol
  changes, not routine refactors.
- v0.x can evolve without promising permanent compatibility, but every breaking
  generation is explicit and fail-closed.
- Stable cross-language support requires a future ADR and published vectors.

## Review triggers

- Runtrue commits to a stable v1 Capsule wire format.
- A non-Rust compiler or verifier needs interoperable identity.
- A canonicalization ambiguity or signature-validation incident is found.
- The digest algorithm or signing representation must change.
