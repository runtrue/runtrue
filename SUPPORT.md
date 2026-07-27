# Support

Runtrue is pre-1.0, security-sensitive software. The repository documents and
accepts issues for the supported evaluation profiles, but it does not provide a
hosted service, guaranteed response time, or production support agreement.

## Before opening an issue

1. Read the support boundaries in the [README](README.md) and the relevant
   document under [`docs/operations`](docs/operations/).
2. Search existing issues and the repository documentation.
3. Reproduce the problem with the current release, when one exists, or `main`,
   using synthetic data where possible.
4. Remove tokens, credentials, tenant data, private source, and sensitive logs.

Use the structured bug report for reproducible defects and the feature request
form for proposed behavior. Include a release tag or commit SHA and enough
environment detail to distinguish a Runtrue defect from an executor, container
runtime, database, network, or provider configuration problem.

Questions about custom deployments may be converted to documentation requests
when there is no reproducible product defect. Operational emergencies for
self-hosted installations remain the operator's responsibility.

## Security reports

Do not open a public issue, discussion, or pull request for suspected
vulnerabilities. Follow [SECURITY.md](SECURITY.md) and use GitHub private
vulnerability reporting. Do not attach exploit material, credentials, private
keys, tenant data, or details of an unpatched bypass to a public report.

## Contributions

Small, focused fixes and documentation improvements are welcome. For larger
behavior or trust-boundary changes, open a feature request before investing in
an implementation. See [CONTRIBUTING.md](CONTRIBUTING.md) for development and
validation requirements.
