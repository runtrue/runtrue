# Bisim executor parity and enforcement

Runtrue admits an executor only for capabilities it can enforce. An
unsupported capability is a preflight error; it never selects another backend
and never falls back to Native execution.

This matrix defines part of Bisim's provider contract. Bisim compares the
normalized lifecycle and declared effects of supported fixtures; it does not
reinterpret a rejected capability as a successful parity result.

## Current enforcement matrix

| Backend | Hydrated workspace | Network | Process services | Cleanup evidence |
| --- | --- | --- | --- | --- |
| Wasm | Filesystem handles are rooted at the verified per-lease workspace; host paths never cross WIT | Denied until a host-mediated adapter is configured | Rejected | Invocation limits and cancellation are enforced by Wasmtime |
| OCI | Mounted from the verified per-lease workspace with pull disabled | Deny-only; allow policies are rejected without an external enforcement provider | Private internal Podman network with bounded health checks | Containers, networks, and volumes must be absent before state removal |
| Firecracker | Guest-image path only; host source sharing is not advertised | Denied until the common provider and signed policy are wired | Rejected in the current guest generation | VM/process teardown is required by the host driver |
| Native | Direct trusted-host workspace | `allow` is rejected without a cgroup-bound external provider; a deny declaration is not host firewall isolation | Rejected by the current image-only service model | Ordinary descendants in each step process group are terminated and absence is verified before finalization |

Host-mediated connection tickets are bound to the exact run, job, positive job
attempt, step, execution lease, and fencing generation. A retry cannot reuse a
prior attempt's DNS pins even while the lease identifier is unchanged.

Native remains a high-trust boundary, not a sandbox. Operators must use a
dedicated or disposable pool and must not describe Native runs as network- or
filesystem-isolated. A deliberately daemonized process can leave its original
process group; host reimaging remains the isolation proof for privileged Native
pools.

## Wasm workspace adapter

Lease preflight validates the signed filesystem scopes without accessing a
workspace. After source hydration, execution opens the actual workspace root
as a directory file descriptor. Reads and writes use beneath/no-symlink/
no-magic-link/no-cross-device resolution, enforce invocation cancellation and
deadlines, and cap each file at 64 MiB in addition to the smaller per-call WIT
request/response bounds. Failure to open the hydrated root is terminal; no Git,
registry, host-path, or ambient filesystem fallback exists.

`$RUNTRUE_TOOLS` is not exposed by this runtime generation. A Capsule that requires
a tools-root handle must remain unsupported until the runner has a separately
configured, verified tools root and the Capsule can distinguish its namespace
from workspace-relative paths.

## Admission and incident signals

The following errors are expected security decisions, not retryable workload
failures:

- `network allow ... without an external enforcement provider`;
- `filesystem adapter is unavailable` or an unsafe hydrated workspace root;
- process-group cleanup could not be proved;
- process services on Wasm, Firecracker, or Native; and
- secret/OIDC capabilities on a backend without an exact broker adapter.

Drain the affected runner when cleanup cannot be proved. Inspect the host for
escaped processes before returning it to service. Repeated workspace-root or
capability-adapter failures should be treated as runner-integrity incidents.

## Remaining parity gates

This slice is not M3/L2 or release-complete. Grade-A claims remain blocked on a
real external network-enforcement helper and isolation tests, Native process
service semantics from R7, the attempt-aware Firecracker guest protocol
generation, common remote lifecycle/artifact/report tests, and KVM/rootless
Podman cleanup evidence on production-equivalent hosts.
