# runtrue-executor-wasm

This crate is Runtrue's embedded WebAssembly Component backend. It accepts only
digest-pinned components implementing `runtrue:action/run@1.0.0`, verifies their
exact signed image manifest and expected image-signing key, and then compiles
them with the security-patched Wasmtime 36.0.12 runtime.

The guest receives no WASI linker and therefore has no ambient filesystem,
network, environment, clock, random, process, or secret access. The only host
imports are those in [`wit/action.wit`](wit/action.wit). Filesystem, network,
secret, and OIDC access must be both declared in the step capability set and
backed by an explicitly installed adapter. Grants are represented by
invocation-local authenticated handles; unknown or forged handles fail closed.
OIDC minting accepts only an audience handle, never an arbitrary audience
string. Other workflow capabilities are rejected until this ABI has a
corresponding adapter.

Execution is bounded by Wasmtime store memory/table/instance limits, fuel, an
epoch watchdog, a wall timeout, and size limits for component bytes, inputs,
outputs, logs, adapter traffic, secret values, and OIDC tokens. Output must be
a duplicate-free canonical JSON object. Delivered secret and OIDC values are
kept in redacting, zeroizing wrappers, masked from host logs, and rejected if a
component attempts to publish them as structured output. No command or native
fallback exists.

The executor runs only the current host's baseline target: Linux or macOS on
`x86_64` or `aarch64`. Cross-target execution and Windows are rejected. This
keeps native AOT bytes bound to the machine-code target and lets the cache
enforce Unix owner-only directory/file modes and no-follow opens; platforms
without those checks fail closed during cache setup.

The AOT key binds the component and WIT digests, Wasmtime version, target
triple, CPU feature floor, compiler settings, mitigation profile, and
Wasmtime's engine compatibility hash. Cache metadata and serialized component
artifacts are HMAC-authenticated, size-bounded, and checked as component AOT
objects before Wasmtime's safe source-loading/cache path is used. Cold source
compilation uses a separate engine with Wasmtime's internal cache disabled;
the cache-enabled engine is used only after Runtrue authenticates an AOT entry,
and its serialized result must exactly equal that authenticated entry before
guest initialization. Corrupt entries are quarantined and rebuilt as misses.
The cache authentication key and capability-handle key are installation
secrets and are zeroized on drop.

Remote runners call `preflight_components` before advertising Wasm. This
verifies and compiles every registered signed component. Normal cold-cache
publication does not create an integrity event; corrupt or unauthenticated AOT
state is quarantined and recorded so a runner can fail that startup instead of
silently advertising from repaired state. Atomic cache publication and rooted
filesystem temporary names treat operating-system entropy failure as a typed,
fail-closed error.

On Linux, `RootedFilesystemAdapter` provides the concrete workspace adapter. It
walks from a retained root descriptor with kernel `openat2` resolution using
`RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, and `RESOLVE_NO_XDEV`; kernels without
that boundary fail closed. It rejects non-regular and hard-linked files and
writes through an unpredictable private in-directory temporary file followed
by an atomic rename. The workspace tree must be exclusively owned by the
executor while a step runs: no filesystem API can preserve write integrity
against an unrelated same-UID process that can concurrently mutate the same
directory. macOS execution remains available with custom capability adapters,
but the concrete rooted filesystem adapter is intentionally not exported there.
