# Public repository launch checklist

This checklist covers publishing the source of `runtrue/runtrue`. Workflow
frontend repositories and deployment-specific configuration are independently
governed and do not need to change visibility at the same time.

The repository is pre-1.0 software, not a hosted service or a general
high-availability production recommendation. Making the source public does not
publish a release, support every roadmap item, or widen the documented runtime
and deployment guarantees.

## Before changing visibility

- [ ] Merge the community health files, native Runtrue CI workflow, and any
      security-boundary cleanup selected for launch.
- [ ] Require the full pinned validation suite to pass at the launch commit.
- [ ] Scan the complete Git history for credentials and private material, then
      rotate and remove anything real before making the repository public.
- [ ] Review Git history for large generated artifacts, production data, private
      repository content, and third-party material without compatible licensing.
- [ ] Confirm `LICENSE`, `README.md`, `CONTRIBUTING.md`, `SECURITY.md`,
      `SUPPORT.md`, issue forms, the pull request template, and `CODEOWNERS`
      render correctly.
- [ ] Confirm all examples and fixtures use synthetic identities and
      credentials.
- [ ] Confirm documentation does not promise unavailable releases, support
      channels, services, compatibility, or deployment profiles.
- [ ] Record the exact launch commit and an owner for the visibility change.
- [ ] Prepare branch protection or repository rules before accepting external
      changes. If the host cannot configure them while private, apply them
      immediately after the visibility change and keep merges paused until they
      are verified.

## Repository settings

Apply and verify these controls on `main`:

- [ ] Block force pushes and branch deletion.
- [ ] Require pull requests, at least one approving review, and dismissal of
      stale approvals after new commits.
- [ ] Require CODEOWNERS review for owned paths.
- [ ] Require the native Runtrue CI checks and require branches to be current
      before merge.
- [ ] Restrict bypass permissions and audit every exception.
- [ ] Enable dependency graph, Dependabot alerts, and security updates.
- [ ] Enable secret scanning and push protection.
- [ ] Enable private vulnerability reporting and verify the link in
      `SECURITY.md` and the issue chooser.
- [ ] Disable unused repository features or document who moderates them.
- [ ] Before enabling broader community features, assign a private conduct
      reporting channel and publish a code of conduct with an accountable
      enforcement owner.
- [ ] Review Actions permissions, fork pull-request permissions, workflow token
      defaults, and allowed actions. Default workflow tokens to read-only.

## Visibility change

- [ ] Pause merges and deployments while the repository setting is changed.
- [ ] Confirm the selected repository is exactly `runtrue/runtrue`.
- [ ] Change visibility through an authenticated repository-owner session.
- [ ] Verify the repository and its Git history are anonymously readable.
- [ ] Verify unrelated repositories remain at their intended visibility.
- [ ] Re-run the repository-settings checks above from a fresh session.
- [ ] Unpause merges only after required reviews and checks are enforced.

## After launch

- [ ] Test an anonymous clone and the documented build path on a clean machine.
- [ ] Open the issue chooser and confirm bugs, features, support, and private
      security reporting route to the intended destinations.
- [ ] Verify `LICENSE`, contribution, support, and security links from an
      unauthenticated browser.
- [ ] Confirm required CI runs for a pull request from a fork without exposing
      secrets or granting write permissions.
- [ ] Review the audit log for the visibility and rules changes.
- [ ] Monitor incoming issues, security reports, dependency alerts, and
      credential findings during the launch window.

## Release boundary

Source visibility and a Runtrue release are separate decisions. Do not create a
tag, publish binaries or images, or broaden the supported-version table merely
because the repository is public. Follow the
[release runbook](releases.md) for artifacts, signatures, metadata, SBOMs, and
promotion evidence.
