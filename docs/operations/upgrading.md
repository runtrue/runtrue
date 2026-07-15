# Upgrading a v0.x Runtrue installation

Runtrue v0.x is a single-node evaluation release. Back up and verify the SQLite
database, content stores, signing state, configuration, and release root before
every upgrade. Do not attempt a rolling server upgrade unless the source and
target release notes explicitly authorize it.

## Pre-upgrade checklist

1. Read `CHANGELOG.md` for every skipped version and confirm the supported
   runner protocol range.
2. Drain runners and wait for active leases to complete or cancel them
   deliberately. Preserve their audit evidence.
3. Run the documented backup and restore verification. Retain the prior binary,
   container digests, configuration, and trusted update metadata.
4. Verify the new release against the configured update root before stopping
   the old service.
5. Stop the server, take a final offline database snapshot, and start the new
   server with the same durable paths. Migrations run in version order.

Database migrations are forward-only. A binary rollback after a migration is
not supported unless that release's notes provide an explicit, tested rollback
procedure. Restore the complete pre-upgrade snapshot instead; never manually
decrement the schema version.

## First v0.x migration notes

Migrations 27 and 28 add durable SCM check revisions and the corresponding
publication journal. They preserve existing check state but may create
reconciliation work for the SCM worker after restart. Keep outbound SCM access
available until that journal drains, and do not run an older server against the
migrated database.

The runner protocol maintains generation N and N-1 only where the release notes
say so. Upgrade the server before runners, then replace or re-enroll runners
outside the advertised range. Authentication or fencing changes may require a
fresh certificate even when the wire generation is otherwise compatible.

## Post-upgrade verification

- Confirm `/healthz` and `/readyz`, migration status, and audit-chain continuity.
- Confirm runner enrollment, session rotation, scheduling, log streaming, and
  completion with a disposable workflow.
- Confirm the installed GitHub App and selected repository bindings, then
  exercise webhook-to-check reconciliation.
- Confirm artifacts, caches, backup verification, and update trust state.
- Keep the old installation stopped and intact until these checks pass.
