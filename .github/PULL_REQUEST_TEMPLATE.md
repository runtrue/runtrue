## Summary

Describe what changed and why.

## User and operator impact

Describe externally visible behavior, deployment actions, compatibility, and rollback. Write "None" where a section does not apply.

## Trust and security

Identify the security invariant preserved or changed. Call out effects on authorization, credentials, isolation, execution identity, runner fencing, durable state, artifacts, updates, and release trust.

## Validation

List the exact commands and scenarios used to validate the change.

## Checklist

- [ ] The change is focused and includes tests or fixtures for altered behavior.
- [ ] Documentation and upgrade guidance reflect user-visible or operational changes.
- [ ] New fixtures and examples contain synthetic data only.
- [ ] Protocol, schema, migration, and compatibility changes fail closed when unsupported.
- [ ] I did not include credentials, private repository content, production data, or generated build output.
- [ ] I reviewed the relevant checks in the [contribution guide](https://github.com/runtrue/runtrue/blob/main/CONTRIBUTING.md).
