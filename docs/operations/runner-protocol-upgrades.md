# Runner protocol upgrades and generation-one drain

Runtrue servers support runner protocol generations 1 and 2 by default. Enrollment
selects the newest common generation on the server. The selection is bound into
the accepted inventory digest and stored beside the runner's enrolled
credentials, so reconnects and restarts do not renegotiate or silently
downgrade.

## Compatibility behavior

| Server | Runner | Enrollment and connection behavior |
| --- | --- | --- |
| old generation 1 | new 1–2 | The request's shipped inventory field remains `1`; the old server ignores the additive range, returns no selected field, and the runner persists `1`. |
| new 1–2 | old generation 1 | The absent `0/0` request range is decoded only as the singleton inventory version `1`; the server selects `1`, and the old runner ignores the additive response field. |
| new 1–2 | new 1–2 | The server selects and persists `2`. |

A partial-zero range, reversed range, inventory version outside the advertised
range, disjoint range, changed selected version, or Hello/inventory mismatch is
rejected. Enrollment negotiation finishes before the one-time token is
consumed. Generation-one sessions cannot use generation-two source/object RPCs.
There is no native executor, local-source, object-store credential, or ambient
credential fallback when a generation is unavailable.

The runner writes the selected number to the create-new
`protocol-version` file in its active credential generation. `metadata.json`
retains its generation-one shape so an older runner binary can read a credential
created by a newer binary during an intentional binary rollback. A credential
created before this sidecar existed has no inferred selection: start the new
runner once with an operator-reviewed `--protocol-version N` (or
`RUNTRUE_RUNNER_PROTOCOL_VERSION=N`). That atomically binds the current
generation; a conflicting replay fails.

Directly provisioned certificate/key credentials do not contain an enrollment
selection and therefore always require `--protocol-version N` or
`RUNTRUE_RUNNER_PROTOCOL_VERSION=N`. The runner never probes an endpoint and
guesses a compatible generation.

## Drain generation 1

1. Keep the server default `--runner-protocol-minimum 1` and deploy a server
   that supports both generations.
2. Upgrade and restart runners. Observe the non-sensitive protocol metrics
   `enrollment_selected_v1`, `enrollment_selected_v2`,
   `enrollment_rejected`, and `stream_version_rejected`. Inventory and
   credential inspection must show generation 2 for every pool that will
   remain active.
3. Drain generation-one runners through the normal runner-pool drain path. Wait
   for active leases to finish and verify no generation-one session remains.
   Do not revoke credentials merely to force a live job across generations.
4. Set `--runner-protocol-minimum 2` or
   `RUNTRUE_RUNNER_PROTOCOL_MINIMUM=2` and restart the server. Enrollment and
   Open now fail with `FAILED_PRECONDITION` for generation 1; rejected
   enrollment does not consume its one-time token.
5. Keep the minimum at 2 only after rollback readiness has been reviewed. To
   reopen generation 1 during a controlled rollback, restore the minimum to 1
   and restart the server; do not edit credential metadata or a shipped
   migration.

Malformed configuration fails startup. Raising the minimum changes admission,
not stored schema, credential authority, lease fences, or Capsule signatures. It
does not permit an in-place protocol switch for a connected runner.

## Verification and recovery

Run `runtrue-runner doctor` with the same credential mode used by the daemon. Its
`protocol_version` must equal the persisted or explicitly configured selection.
After a runner restart, verify its first Hello and inventory carry that exact
number. After a server restart, verify the durable inventory binding still
rejects a substituted generation.

Back up the credential directory as private runner identity state when local
operations require runner recovery. Restore the complete active generation,
including `protocol-version`; never reconstruct it from the endpoint. If the
sidecar is missing on a legacy backup, use the explicit one-time upgrade path
only after confirming the server generation that originally issued the
credential.
