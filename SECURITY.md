# Security policy

Runtrue is security-sensitive pre-1.0 software. Do not treat the current
repository as a hosted CI service or expose its evaluation deployment directly
to untrusted networks.

## Supported versions

| Version | Supported |
| --- | --- |
| `main` before the first v0.x tag | Yes |
| Latest listed v0.x release line | Yes |
| Unlisted older tags | No |

Security fixes are made on `main` and on a release line only when it is
explicitly listed in a GitHub security advisory. Supporting runner protocol
generations N and N-1 during a rolling upgrade is a compatibility promise, not
a promise to maintain every older binary; an emergency policy may raise the
minimum runner version immediately.

## Report a vulnerability privately

Use the repository's **Security → Report a vulnerability** form (GitHub private
vulnerability reporting). Include affected versions, the violated security
invariant, a minimal reproduction, impact, and any known mitigations. If that
form is unavailable, contact the maintainers through a private channel provided
by the repository host before disclosing details. Do not open a public issue,
discussion, or pull request containing an exploit, credential, private key,
tenant data, or an unpatched bypass.

Reports about parser differentials, authorization or tenant isolation, secret
release, runner fencing, executor escape, artifact/cache trust, update signing,
rollback protection, audit integrity, backup recovery, or release-workflow
privilege are in scope. A dependency alert without a reachable impact is still
useful, but include the dependency path and relevant feature where possible.

## Response and disclosure

Maintainers should acknowledge a report privately, reproduce it in an isolated
environment, assign an incident owner, and preserve relevant audit evidence.
Remediation includes a regression test and review of adjacent trust boundaries.
The project publishes an advisory and fixed-version guidance after coordinated
disclosure; timing depends on exploitability and the safety of available
mitigations. Credit is given when requested and safe.

For active exploitation, signing-key compromise, a malicious release digest,
or an executor escape, operators should stop promotion and scheduling, revoke
affected identities and digests, quarantine derived state, and retain logs and
checkpoints. Update-key incidents additionally require the rotation or recovery
ceremony in [secure updates](docs/operations/secure-updates.md); never ship an
unsigned emergency binary or reset client trust state to make an update pass.

Public examples and test fixtures must contain synthetic credentials only.
Rotate any real credential accidentally submitted to the repository before
asking maintainers to remove it from history.
