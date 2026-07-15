# Runtrue OIDC signing-key lifecycle

`runtrue-oidc` mints short-lived, Ed25519-signed workload identity tokens that are
bound to an authorized grant, execution lease, fence, job, and step. The crate
also owns the public signing-key lifecycle used by discovery, JWKS publication,
verification, rotation, revocation, backup, and restore.

Runner-derived grants also carry the exact consumed/reusable approval subject
and Open-session posture digest; both become signed JWT claims. The durable
control-plane adapter, not the runner request, derives those values from the
run, signed capsule, accepted lease, and per-run authorization records.

## Rotation model

An `OidcIssuer` has one active private signing key and a bounded set of retired
public keys. `rotate_signing_key` performs a normal rotation: the old public key
remains in `jwks_at(now)` for an explicit overlap. The overlap must be at least
the issuer's maximum token TTL and no more than 24 hours, so every token minted
before the rotation can remain verifiable without retaining keys indefinitely.
At most eight retired keys may be live at once. A rotation fails without
changing state if that bound would be exceeded.

`emergency_rotate_signing_key` replaces and revokes the active key immediately.
`revoke_retired_signing_key` removes a selected overlap key immediately. Revoked
key IDs are retained as durable tombstones so issuer-level verification can
distinguish revocation from an unknown key. Tombstones are bounded at 64; an
operation fails closed instead of silently forgetting one.

All lifecycle timestamps supplied to an issuer must be monotonic. Minting,
verification, JWKS publication, rotation, revocation, and pruning reject a time
earlier than the last durable lifecycle transition.

## Persistence and recovery

`key_ring_snapshot_json` emits versioned, canonical JSON containing only public
lifecycle state:

- issuer and maximum mint TTL;
- generation and last transition time;
- the active public key and activation time;
- retired public keys, activation/retirement windows, overlap deadlines, and
  the mint TTL in effect at retirement; and
- revoked key-ID tombstones.

The active private key is deliberately absent. Persist it through a separate
secret or KMS boundary, and durably commit the new snapshot before exposing a
rotated issuer to token minting or JWKS requests. On recovery,
`from_key_ring_snapshot` validates every invariant and requires the separately
recovered private key to match the snapshot's active public key. A mismatch
fails with `SigningKeyContinuityMismatch`; it must be resolved as an intentional
emergency rotation, never by silently publishing an unrelated key.

Backups must include the public snapshot and a recoverable reference to the
active secret/KMS key. Restore drills should verify snapshot parsing, active-key
continuity, overlap-key publication, and intentional emergency-rotation
procedures.

## Publication and verification

Use `discovery_document` for the exact issuer metadata and `jwks_at(now)` for
HTTP JWKS responses. `JwkSet::from_json` validates every key, rejects duplicate
IDs and unsupported parameters, and enforces a size/key-count bound.
`verify_token_with_jwks` selects only the JWT's exact `kid` from such a set.

Use `OidcIssuer::verify` when local lifecycle state is available: it additionally
enforces activation, retirement, overlap, and revocation windows. The older
`verify_token` function remains available for callers that intentionally verify
against one already-selected key, but it cannot know whether that key has been
revoked.

The in-process `OidcSigningKey` implementation stores an Ed25519 seed in
zeroized memory. It never serializes or logs that seed, but it is not itself a
non-exportable HSM/KMS key. A production deployment that requires non-exportable
signing must place the active key behind its approved signing boundary while
preserving the snapshot and lifecycle semantics above.
