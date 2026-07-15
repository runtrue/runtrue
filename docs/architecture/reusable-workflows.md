# Reusable workflow compilation

Native workflow v1 supports immutable, recursively expanded workflow calls. A
call is a job with `uses` and optional static `with` arguments:

```yaml
version: 1
jobs:
  shared-ci:
    needs: [prepare]
    uses: git+https://example.test/platform/workflows.git//ci.yaml@v3
    with:
      profile: release
      run-tests: true
  publish-report:
    needs: [shared-ci]
    if: needs.shared-ci.outputs.report == needs.shared-ci.outputs.report
    steps:
      - run: { command: ["true"] }
```

A call may contain only `name`, `needs`, `if`, `uses`, and `with`. It cannot
also request a runner, permissions, services, a matrix, outputs, or executable
steps. Call arguments are finite scalar values; dynamic context-to-context
argument forwarding is intentionally not part of v1.

The called source declares typed inputs and artifact-output aliases:

```yaml
version: 1
inputs:
  profile: { type: choice, options: [debug, release], default: debug }
  run-tests: { type: boolean, required: true }
outputs:
  report: { from: needs.test.outputs.report }
jobs:
  test:
    if: inputs.run-tests == true
    steps:
      - run:
          command: ["./ci"]
          args: [{ from: inputs.profile }]
    outputs:
      report: { path: reports/results.json }
```

Reusable sources cannot declare event triggers. Public outputs can reference
only declared job artifact outputs through
`needs.<job>.outputs.<output>`; secret, event, arbitrary expression, and
undeclared output contexts are rejected.

## Authenticated source contract

Compilation performs no filesystem or network access. Before invoking the
compiler, a trusted SCM layer must provide both:

1. a validated `.runtrue.lock` `[[workflow]]` entry containing the human
   reference, immutable commit, and SHA-256 digest; and
2. a `ReusableWorkflowSources` bundle in `CompileContext`, keyed by that exact
   human reference and containing the authenticated commit plus exact source
   bytes.

The compiler compares the bundle commit and byte digest with the lock entry
before UTF-8 decoding or YAML parsing. Missing, extra, malformed, mutable,
mismatched, and unused entries fail closed. The source provider is private and
immutable after bounded construction: at most 256 entries, 1 MiB per source,
and 8 MiB total.

### Local and submitted Capsules

The CLI hydrates each locked digest from this exact workspace path:

```text
.runtrue/reusable-workflows/sha256/<64-lowercase-hex>.yaml
```

The `sha256` directory is enumerated through a held descriptor, and each file
is opened relative to it with Linux `openat2`, `BENEATH`, `NO_SYMLINKS`, and
`NO_MAGICLINKS`. The directory and files cannot be group/world writable;
sources must be regular single-link files. Missing, unexpected, symlinked,
oversized, insecure, or digest-mismatched content is rejected. This hydration
is shared by `validate`, `capsule`, `run`, `compare-capsule`, and `submit`.

`submit` sends the same exact bytes as bounded lowercase hex alongside the
lockfile. The server accepts at most 256 unique entries, 1 MiB each and 8 MiB
decoded in total, requires the references and commits to exactly match every
`[[workflow]]` lock entry, reconstructs `ReusableWorkflowSources`, and compiles
again. A run is created only after the existing canonical local/remote Capsule
comparison succeeds.

### Trusted SCM Capsules

The SCM worker never uses the content store, a checkout fallback, or a network
fetch. GitHub reusable references must use one of these canonical forms:

```text
git+https://github.com/<owner>/<repository>.git//<path>.yaml@<selector>
git+ssh://git@github.com/<owner>/<repository>.git//<path>.yaml@<selector>
```

Same-repository calls use the already authenticated event mirror. Cross-
repository calls require an exact private mirror at
`<mirror-root>/<owner>/<repository>`. Before reading the locked commit and
path as a regular Git blob, the worker verifies that the mirror has exactly
one local `remote.origin.url` authenticating the same GitHub owner and
repository. Foreign origins, traversal, symlinked/changed mirrors, missing
objects, and ambiguous origins fail or retry closed; no operation fetches or
executes repository content.

## Expansion semantics and limits

The compiler recursively expands calls before matrix expansion. Concrete IDs
are deterministically namespaced with `__`, for example
`shared-ci__test`. Caller dependencies are attached to the child entry jobs;
downstream dependencies are attached to all child terminal jobs. Internal
`needs` references and public output aliases are rewritten to the concrete
namespaced producer. Any collision or overlong identifier is rejected.

Typed input literals are substituted only inside the called workflow's typed
bindings and conditions. String literals in expressions are never searched or
rewritten. Ordinary root-workflow runtime `inputs.*` contexts remain runtime
contexts. Workflow and job permission ceilings are intersected at every call
boundary, and called workflow variables are copied into their concrete jobs.

Default limits are eight nested calls, 256 concrete jobs per call, 1,024 jobs
for the complete expanded workflow, and the existing matrix limits. Reference
cycles, dependency cycles, excessive depth, excessive fan-out, and namespace
collisions are compilation errors. Selecting a call job selects all of its
terminal jobs and their complete dependency closure.

The canonical workflow identity includes the expanded semantics and the
sorted locked source/commit/digest identities. The lock digest remains in the
Capsule, and sorted reusable source digests are included in the
`ApprovalSubject`, so any authenticated source or resolution change
invalidates prior Capsule and approval identities.
