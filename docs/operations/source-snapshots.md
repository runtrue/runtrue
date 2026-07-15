# Source snapshots

Remote execution must be bound to a ready source snapshot before source can be
hydrated. A snapshot identifies the tenant, repository, exact Git commit, and
deterministic tree-manifest digest. The same tree digest is part of the signed
Capsule and its approval subject; changing the tree requires a new Capsule
and approval.

Snapshot construction reads Git objects without a worktree, hooks, or network.
It rejects absolute or workspace-escaping symlinks, special entries, and
submodules without an exact nested-manifest lock. Entry count, aggregate bytes,
individual blob size, symlink size, Git output, and command duration are
bounded. Individual source blobs use the configured Git `max_blob_bytes` limit
(2 MiB by default) and are rejected from metadata size before `cat-file` can
allocate or publish their bytes. File bytes are digest-verified before
publication to CAS.

### Exact locked submodules

The Git primitive has two deliberately distinct entry points. The ordinary
`build_source_manifest` path rejects every Git link. The opt-in
`build_source_manifest_with_locked_submodules` path accepts only a canonical,
sorted tree of `GitSubmoduleLock` values paired with caller-supplied, already
opened `GitRepository` object databases. Each lock contains the mount path, an
administratively normalized HTTPS origin, and the full exact commit. It is not
a URL resolver or a request to fetch.

Before publishing any blob, the builder verifies all of the following across
the complete graph:

- every Git link has one lock and one unambiguous committed `.gitmodules`
  path/origin declaration;
- the Git-link object ID, lock commit, and supplied repository commit are
  identical full object IDs;
- the supplied repository's exact local `remote.origin.url` equals the locked
  normalized origin;
- every nested commit and blob already exists in the supplied local object
  database;
- mount paths are canonical and unique, repository/origin recursion is absent,
  and shared entry, aggregate-byte, path, and depth limits are respected; and
- no lock or `.gitmodules` declaration remains unused.

Nested entries are flattened deterministically beneath the mount directory in
the existing version-one `GitTreeManifest`, so existing manifest decoding and
create-new/no-follow materialization do not gain a new implicit behavior. The
builder separately returns the sorted lock identities and a domain-separated
submodule-lock digest. Production planning must bind that digest (or the
equivalent canonical `.runtrue.lock` digest) into the Capsule and approval subject.
The runner must receive only the resulting CAS graph; it never receives an SCM
origin or credential and never runs submodule update.

This is currently an L0 Git primitive, not an L2/L3 submodule claim. The
`.runtrue.lock` schema, authenticated SCM mirror acquisition for every locked
origin, durable snapshot construction, Capsule/approval binding, runner hydration,
clean-remote evidence, metrics, and recovery/operator drills still require
end-to-end wiring. Until those boundaries consume the opt-in type, production
SCM construction continues to use the ordinary fail-closed builder and rejects
all Git links. Operators must not work around that rejection with a checkout,
ambient credential helper, local path, direct clone, or runner-side fetch.

## Authenticated GitHub source refresh

Production GitHub events must resolve through an active, tenant-owned
`scm_installations` row and an active `scm_repository_links` row. The event's
installation ID, external repository ID, normalized owner, and repository name
must all match in one tenant-filtered database query. An absent, suspended,
cross-tenant, or partially matching link is reported only as an unavailable
authorization; it does not disclose which part exists.

The SCM worker reserves a durable `scm_source_fetches` identity before network
access. Exact event replay reuses that identity; a changed commit, base,
normalized event, repository, installation, or configured origin conflicts.
The journal stores only a token-scope digest. Installation tokens and GitHub App
private keys are never written to SQLite, CAS, mirror metadata, task payloads,
audit records, or logs.

The configured token provider must mint a repository-selected token containing
only Metadata read and Contents read for source refresh. The worker passes the
token directly to Git's child credential channel. Tokens must have between 30
seconds and one hour of remaining lifetime. Debug output is redacted, and any
credential observed in child output terminates and quarantines the fetch.

GitHub mirrors accept only the administratively allowlisted HTTPS origin.
`MirrorManager` rejects URL userinfo, alternate schemes, IP literals,
nonstandard ports, private/special DNS results, DNS rebinding, origin changes,
alternates, unsafe configuration, excess objects/packs/files/bytes, and a
missing authenticated event commit. There is no direct-clone, native, SSH, or
ambient-credential fallback. A bounded transient provider/fetch failure retries
the durable task; an origin, scope, repository, or content rejection is
terminal.

After the requested commit is verified, the worker publishes its file objects
and canonical manifest to the configured runner data-plane CAS, marks the
snapshot ready, signs the manifest digest into the Capsule, and atomically commits
the run-to-snapshot binding before jobs become visible as queued. On restart,
the same fetch, snapshot, Capsule, run, and binding identities converge. Operators
should alert on `reserved` or `snapshot-ready` fetch rows older than the task
lease/retry horizon, repeated fetch attempts, terminal origin/scope rejection,
and CAS publication failures. Provider credentials must be recovered through
the configured non-exportable provider; environment Git credential helpers and
operator home-directory configuration are unsupported.

The worker exposes bounded counters for `source_fetch_attempts`,
`source_fetch_rejections`, `source_snapshots_committed`,
`source_fetch_replays`, `task_retries`, and `task_terminal_failures`. Exporters
must label these only by installation/tenant policy-approved identifiers and
coarse reason; never use clone URLs, token values, credential references, or
repository-private paths as metric labels.

The durable lifecycle is `building`, `ready`, `failed`, or `retired`. Only a
`ready` snapshot whose tenant and repository match the run and whose manifest
digest matches the signed Capsule may be bound. Exact binding replay succeeds;
substitution and cross-tenant lookups are rejected without disclosing snapshot
existence.

## Direct API runs

`POST /api/v1/capsules/{capsule_id}/runs` requires `source_snapshot_id` whenever the
signed Capsule contains `context.source_tree_digest`; the field is rejected for a
Capsule without that binding. The server first creates the run idempotently in the
durable `created` state, then binds only the exact ready snapshot whose tenant,
repository, commit, tree digest, and signed-Capsule digest all match. Jobs cannot
become queued before that bind commits.

A crash or rejected snapshot can therefore leave a durable `created` run, but
never a runnable unbound job. Retry with the same idempotency key and the exact
snapshot converges on that run, commits the binding, and records one normalized
trigger. Replaying a changed snapshot conflicts; operators must not work around
that conflict by creating an unsigned Capsule, changing the signed digest, or
hydrating source outside the authorized ticket path.

Operators should alert on snapshot build failures by reason, time spent in
`building`, rejected binding attempts, source transfer integrity errors, and
snapshot/CAS bytes approaching configured quotas. Source integrity failures are
terminal correctness failures, never cache misses. Runners receive no SCM or
object-store credentials and must not fall back to `git clone` or local source.

The remote runner requests its generation-two source ticket only after lease
acceptance. It reports `preparing`, streams the canonical manifest and each
authorized file object into private bounded staging, verifies the signed-Capsule
root digest, and materializes with create-new/no-follow semantics before it
reports `running`. A malformed frame, changed digest or length, exhausted
ticket quota, missing object, disconnect, timeout, or unsafe manifest records a
durable terminal `source_integrity` completion and removes the lease workspace.
Restart cleanup removes both incomplete workspaces and private staging; a new
attempt must obtain a newly fenced ticket. Generation one blob RPCs are never
used for source transfer.

`CancelLease` is observed while hydration is in progress. The runner marks the
stream cancellation flag, stops at the next bounded frame boundary, removes
private staging and the lease workspace, persists a canceled completion, and
never starts executor execution for that accepted lease.

Tickets are bound to the mTLS certificate-owned live runner session, active
lease, fencing generation, durable job and attempt, tenant, and the run's ready
snapshot. Callers cannot select the source root. A ticket authorizes only its
canonical root manifest and file digests directly named by that manifest, and
its byte quota is aggregate across distinct object downloads. Authorization is
resolved before the requested object's existence is inspected, so cross-tenant
or guessed-digest requests receive no existence signal.
