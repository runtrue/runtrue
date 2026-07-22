# Workflow frontend extraction boundary

GitHub Actions is Runtrue's first workflow source frontend, but it is not part
of the execution kernel. The adapter now lives in the private
[`runtrue/github-actions-frontend`](https://github.com/runtrue/github-actions-frontend)
repository. Runtrue selects one exact reviewed frontend revision while the
contract, server composition, and integration gates remain owned by core.

## Repository boundary

Runtrue core owns:

- `runtrue-workflow-frontend`, including registry bounds, integrity validation,
  ambiguity rejection, and dishonest-frontend tests;
- Capsule, Seal, compiler, lockfile, and frontend provenance semantics;
- the trusted planner and public execution/provider contracts;
- GitHub SCM authentication, source fetching, webhook normalization, checks,
  and installation lifecycle; and
- server and CLI composition features that select installed frontends.

The GitHub Actions frontend owns:

- GitHub Actions parsing and compatibility analysis;
- translation to native Runtrue workflow YAML;
- generated lockfile material and compatibility reports;
- `.github/workflows` discovery metadata; and
- adapter fixtures, security tests, and release notes.

The trusted planner depends only on `runtrue-workflow-frontend`. It receives a
validated registry from the server composition root. The runtime engine,
executors, runner, guest, protocol, storage, and control plane never depend on
`runtrue-gha-import` or on the frontend contract.

The server and CLI enable the optional `github-actions` feature by default.
Both must continue to compile with `--no-default-features`, which is the
native-only composition and the proof that the adapter is replaceable.

Moving this frontend does not move the GitHub SCM provider or the standalone
browser application. Those are separate integration and presentation
boundaries.

## Compatibility and approval identity

The adapter identity is `runtrue.github-actions`. Its
`frontend_generation` must increase whenever translation, lock generation, or
report semantics can change for identical input.

Before compiling translated YAML, the trusted planner independently verifies:

- the frontend contract generation;
- the exact source digest;
- the digest of the exact adapter configuration;
- the frontend identity and nonzero generation;
- the emitted native workflow digest; and
- the media type, size, and digest of any compatibility report.

The contract generation, adapter identity and generation, input and
configuration digests, native digest, and report digest are bound into the
Capsule and approval subject. An adapter change therefore cannot reuse an
earlier Capsule identity or Seal accidentally.

Trusted SCM resolution may add bounded `ResolvedSourceAction` values to
`WorkflowFrontendOptions`. The keys are opaque source-language references and
the values contain only provider-neutral container or component program data
and declared inputs. Constructors enforce per-field, count, and aggregate byte
bounds; duplicate references and input names fail closed. Private storage and
read-only accessors prevent an adapter from manufacturing resolution metadata.
The exact sorted, length-prefixed representation is included in the existing
configuration digest before the adapter receives it.

This is an additive contract-generation-2 extension: when no resolved actions
are present, the canonical option bytes and digest are unchanged. Resolved
actions use the separately tagged `resolved-source-actions.v1` encoding. Any
incompatible change to that encoding, its interpretation, or the public data
model must increment `WORKFLOW_FRONTEND_CONTRACT_GENERATION` and the options
digest domain. Translation behavior that merely starts consuming the new input
increments the adapter's `frontend_generation` instead.

Resolution is a two-phase neutral preflight. The adapter discovers bounded
`SourceActionResolutionRequest` values containing an opaque source reference,
repository locator, revision, subpath, and descriptor candidates. Trusted SCM
authenticates the locator and fetches exact bounded descriptor bytes. The
adapter parses those bytes into a non-executable `SourceActionDeclaration`.
The declaration names the exact candidate descriptor it selected; core rejects
an unrequested or absent selection so SCM can digest precisely those bytes.
Trusted SCM then applies admission policy, builds repository containers or
validates components, supplies its configured API origin, and constructs the
final immutable `ResolvedSourceAction`. Only that final value enters frontend
options and their canonical configuration digest. No provider vocabulary or
adapter-authored executable identity crosses into the planner or runtime.
For component declarations, the adapter can only report the reference,
signature identity, and interface claimed by the authenticated descriptor; it
cannot supply the operator API origin. These claims are not executable identity.
Admission must independently verify the exact content digest, signature and
interface before trusted SCM constructs the resolved component program.

## Dependency rules

Across the repository boundary:

- only `runtrue-server` and `runtrue-cli` may depend on the GitHub adapter
  package;
- the trusted planner depends on `runtrue-workflow-frontend`, never on the
  GitHub adapter;
- the generic frontend contract depends only on `runtrue-model`; and
- the adapter may use compiler and workflow-model packages but no runtime,
  executor, runner, control-plane, protocol, or storage package.

`tests/conformance/check_frontend_boundary.py` enforces these dependency
directions.

## Required gates

Core and adapter changes must pass:

```text
python3 tests/conformance/check_frontend_boundary.py
cargo test -p runtrue-workflow-frontend -p runtrue-trusted-planner
cargo check -p runtrue-server -p runtrue-cli --no-default-features --all-targets
cargo check -p runtrue-server -p runtrue-cli --all-targets
```

The selected external frontend revision must independently pass its locked
format, test, and clippy gates before the core dependency revision advances.

The default-feature integration suite must also prove discovery, planning,
approval, re-planning, and execution of a workflow under `.github/workflows/`.

## Extraction readiness

The repository was extracted only after all of the following became true:

1. The generic frontend API has a reviewed compatibility generation and all
   inputs that affect translation are covered by its configuration digest.
2. Frontend provenance is present in every Capsule, approval, Evidence, and
   replay path that consumes translated input.
3. The native-only server and CLI compositions are release gates.
4. Adapter security and integration tests do not require private kernel APIs.
5. Advancing an adapter revision is an explicit, auditable dependency update.

## Extracted revisions and Cargo identity

The private frontend repository started with a new root history. Its reviewed
root commit `95494b229d14dec027d092f4a65053bfb28d9bf4` contains the adapter
implementation, fixtures, security tests, lockfile, and release notes. It pins
all Runtrue packages to the one reviewed core anchor
`0ff23cf70485260741473993156fca2d5a0c7a40`.

Contract generation 2 uses core anchor
`bcaba397cc04095ac7dd45fbf177339e5efb6846` and reviewed frontend revision
`1be5f0fedc3e6d6b8dcfa956939d832de062dd46`. In this generation the adapter
returns only translated bytes and diagnostics; trusted core derives all signed
identity and integrity metadata.

Repository-action translation keeps contract generation 2's compatible
encoding and advances the adapter to frontend generation 3. Reviewed frontend
revision `1064f9efe2e5b3a4229a4aee2454b2b07e3294e6` pins every Runtrue package to
core contract anchor `73a08bb9338503118baac57181ab2cb576b5489b`. The adapter emits
only bounded resolution requests and non-executable declarations; trusted SCM
constructs the immutable resolved program included in the configuration digest.

Until packages are published with a stable compatibility promise, the adapter
repository must consume all Runtrue packages from one full reviewed 40-character
Git revision. Branches, floating tags, and mixed Runtrue revisions are
forbidden. The Runtrue workspace must likewise select one exact reviewed
frontend revision.

An immutable frontend commit cannot name the hash of a core commit that already
names that frontend commit: each Git commit hash covers the manifest containing
the other hash, so mutual exact pins would require an infeasible hash fixed
point. Extraction therefore follows an explicit three-revision sequence:

1. Review and publish the core anchor `C0`.
2. Create frontend revision `F`, with every Runtrue dependency pinned to `C0`.
3. Create core integration revision `C1`, pinned to `F`.

For the integrated `C1` build, the root manifest patches the five Runtrue
packages named directly by `F` back to the reviewed local core paths. Cargo's
top-level transitive patching gives the adapter and server one Rust package and
trait identity while the frontend's standalone build remains reproducibly
pinned to `C0`. The integration gate must verify that no duplicate Runtrue
packages remain in the resolved graph.

External adapter tests run at `F` against `C0`; native-only and integrated
default-feature builds run at `C1`, with the integrated build selecting `F`.
Deployment Evidence records `C0`, `F`, and `C1` before repository workflow
execution is enabled. Removing the former monorepo copy is therefore a
dependency-source change, not a redesign of the trusted planner or runtime
engine.
