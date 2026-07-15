# ADR 0003: Capsule trust and exact Seal approval

- **Status:** Accepted
- **Date:** 2026-07-15

## Context

Workflow changes can alter code execution, secrets, network access, runner
privilege, caches, artifacts, workload identity, signing, and deployments. An
approval attached only to a pull request, branch, or YAML diff can become stale
or omit resolved dependencies and policy context.

The executable plan and the authority to execute it are distinct artifacts. A
Capsule identifies the immutable execution plan; an approval subject binds the
Capsule to the identities and policy inputs relevant to one authorization
decision; a Seal records that exact authorization.

## Decision

For an untrusted pull request, execute the target-branch workflow against the
proposed source by default. Compile a changed workflow separately for semantic
risk analysis, but do not execute it until the required workflow-definition
Seal exists.

Before execution, compile the selected workflow into a canonical Capsule. Build
an approval subject that includes the Capsule digest and every authorization
input that can change the decision, including source and base commits, workflow
and lock identities, resolved action and image digests, capabilities, secret
references, variables, network/cache/artifact policy, runner isolation,
environment, and policy versions. A Seal authorizes exactly that subject.

Use separate policy rules and approval subjects for:

1. admitting a changed workflow definition; and
2. granting privileged execution, such as secret, identity, signing, or
   deployment access.

Changing Capsule content changes the Capsule digest. Changing any other bound
authorization input changes the approval subject. Either change invalidates an
existing Seal. A Seal may be issued by an authorized human or by explicit
policy, but never inferred from contribution history or a prior approval of a
different subject.

## Consequences

- Reviewers approve the executable result and its authority, not only YAML
  text.
- Contributor history is not a root of trust.
- The compiler, resolver, canonical encoding, and approval-subject construction
  are security-critical.
- User interfaces must present semantic risk and distinguish definition
  approval from privileged execution approval.
- Policy-based Seals can reduce low-risk friction without weakening exact
  subject binding.

## Review triggers

- An incident or audit identifies a missing approval-subject field.
- Users cannot reliably distinguish Capsule identity, approval subject, and
  Seal.
- A new runtime, capability, credential type, or deployment surface changes the
  authorization boundary.
- Approval invalidation causes unacceptable false acceptance or rejection.
