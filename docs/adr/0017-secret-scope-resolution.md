# ADR 0017: Provider-neutral secret scopes and deterministic resolution

## Status

Accepted for implementation on `next`.

## Context

Runtrue currently stores built-in and external secret metadata under an opaque
scope string. The GitHub browser exposes workspace and repository secrets, but
teams also need secrets attached to an SCM account (a GitHub organization in
the GitHub frontend) and to a project that groups repositories and SCM
accounts.

Scope selection is part of the trusted execution input. A UI-only merge would
make the chosen value depend on presentation order and could silently select a
different secret when project membership changes.

## Decision

The control plane owns provider-neutral configuration projects, targets, and
secret resolution. Frontends translate provider vocabulary into these types;
only the GitHub frontend initially exposes the feature.

The supported secret scope kinds are:

- workspace (`tenant:<tenant-id>`, retaining the existing durable scope),
- SCM account (`scm-account:<account-id>`),
- project (`project:<project-id>`), and
- repository (`repository:<repository-id>`).

A project belongs to exactly one tenant and may target SCM accounts,
repositories, or both. A repository can match multiple projects.

For a requested secret name, resolution is:

1. repository,
2. project,
3. SCM account,
4. workspace.

Only active secret metadata is eligible. If more than one matching project
defines the same eligible name and no repository-scoped definition shadows
them, resolution fails closed. Project creation order, lexical order, and UI
order never break the tie.

The resolution result records the selected metadata ID and exact version, all
shadowed candidates, and a canonical digest. Trusted planning must bind this
result before a Capsule is sealed. Project target changes are versioned so a
planner can detect a membership change during planning.

Secret values remain write-only. Inventory, project, resolution, audit, and
browser payloads contain metadata only. Variables retain their current scope
behavior and are outside this decision.

Built-in secret values are not moved between vault snapshots. Changing a
scope requires writing a new value at the destination and tombstoning the old
metadata. Existing `tenant:<tenant-id>` secrets remain workspace defaults.

## Consequences

- The execution kernel does not contain GitHub organization terminology.
- GitHub account IDs, not mutable display names, identify SCM-account targets.
- Matching projects may overlap safely until they define the same name.
- Resolution can be audited and reproduced from metadata without exposing a
  value or ciphertext.
- Adding another SCM frontend requires only a vocabulary adapter and browser
  surface, not a new resolution algorithm.

## Rejected alternatives

- **Ordered projects:** a mutable priority silently changes which credential a
  workflow receives.
- **UI-side inheritance:** an API client or planner could resolve differently.
- **Copying plaintext while moving scope:** this adds a hidden secret release
  path and obscures operator intent.
- **GitHub-specific tables in core:** this couples trusted resolution to one
  presentation frontend.
