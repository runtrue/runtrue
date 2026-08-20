# ADR 0018: Runner fleet autoscaling and bound automatic enrollment

- Status: Accepted
- Date: 2026-07-17

## Context

Runtrue fences stale runners and expires their leases, but an operator must
currently provision replacement capacity and copy a reusable enrollment input.
That leaves a fleet offline after host loss and gives a bootstrap credential a
larger blast radius than one instance needs.

Scheduling is exact. A queued job is constrained by operating system,
architecture, isolation backend, resources, region, verified capabilities, and
allowed pools. Scaling on queue length alone can therefore create runners that
cannot execute the waiting work.

Provisioner credentials (for example a Docker socket, Kubernetes credentials,
or cloud instance authority) are also too powerful for the control plane or a
runner. They must not be combined with access to Capsules, workload data, or
tenant secrets.

## Decision

Runtrue introduces an isolated `runtrue-autoscaler` service and a durable,
provider-neutral fleet model.

The control plane owns runner-pool scaling policy, exact demand snapshots,
fleet request lifecycle, autoscaler fencing leases, and one-time launch claims.
The autoscaler accesses those operations through a narrowly scoped HTTP API; it
never opens the Runtrue database. Only the autoscaler process receives provider
authority. `runtrue-server` and `runtrue-runner` never receive a Docker socket,
cloud credential, or Kubernetes management credential.

Fleet requests use this lifecycle:

```text
requested -> provisioning -> bootstrapping -> enrolled -> online
                                                     |
                                                     v
                              terminated <- terminating <- draining
```

Provisioning ambiguity enters `failed` or `quarantined`. A failed or
quarantined instance may only transition toward termination. An online runner
cannot transition directly to termination: scale-down first asks the control
plane to drain it, waits for its leases to close, and only then destroys the
provider instance.

Each demand class is the versioned digest of the complete
`SchedulingRequirements` value. A pool template explicitly maps that digest to
an immutable provider template and runner image/binary digest. Unknown demand
classes fail closed; the autoscaler does not substitute a similar runner.

Every pool has a short autoscaler ownership lease with a monotonically
increasing fencing generation. Mutating API requests carry that generation so
a delayed former owner cannot provision or terminate capacity.

### Launch claims

After a provider returns an immutable instance identity, the autoscaler asks
the control plane for a launch claim. Creation is atomic with a normal
single-use enrollment token and binds:

- pool and fleet request;
- provider and provider instance identity;
- immutable runner template digest;
- digest of the exact provider identity evidence;
- creation and expiration times (at most fifteen minutes).

The autoscaler injects the claim into only that instance as a mode-0600 file.
The runner generates its private key locally, presents the claim and the bound
identity evidence, sends its verified inventory and CSR, and atomically installs
the returned mTLS credentials. The control plane consumes the enrollment token,
marks the launch claim consumed, binds the runner ID, and moves the fleet
request to `enrolled` in one transaction. A replay, expired claim, mismatched
identity proof, or mismatched runner image digest is rejected.

Real providers must supply an identity document authenticated by their native
identity system. The development Docker provider uses exact evidence injected
by the autoscaler and the one-time claim binding; it is not a host-attestation
mechanism and is not sufficient for a hostile Docker host.

The runner command `enroll-if-needed` is idempotent: it enrolls only when its
atomically versioned credential store is empty and then starts the daemon. It
never replaces an existing identity. Claim cleanup is performed by the
autoscaler after observing enrollment because the file is mounted read-only.

### Replacement and scale-down

The existing heartbeat timeout fences a lost runner and expires its work. The
autoscaler observes the durable capacity deficit after the policy's offline
grace period and creates replacement requests. A stale runner that returns
cannot reclaim a fenced lease and is drained or quarantined during
reconciliation.

Desired capacity is bounded by minimum workers, minimum idle workers, maximum
workers, scale-up batch, cooldown, and the exact unsatisfied demand classes.
Scale-down applies only after the idle timeout and never destroys below the
minimums. The default policy keeps at least one idle worker; scale-to-zero is an
explicit operator choice.

## Development provider

The first provider targets one Docker Engine for Compose development. The
autoscaler alone mounts `/var/run/docker.sock`; server and runner services do
not. Launch claim files live under an autoscaler-owned mode-0700 directory and
are mounted read-only into runner containers.

Docker does not automatically remove ephemeral runner containers. During
termination the autoscaler first archives the runner supervisor's timestamped
stdout and stderr into the request's private provider-state directory, then
removes the container. Failure to archive prevents removal, preserving the
container as the fallback diagnostic source. Guest step logs remain governed
by the control plane's separate durable log protocol.

This provider repairs runner-container failure only. It cannot repair failure
of the Docker host, its disk, its socket, or the autoscaler container on that
host. Host-level availability requires a Kubernetes or cloud/VM provider on an
independent failure domain.

## Consequences

- Runner replacement no longer depends on a human copying a pool-wide token.
- Provider compromise does not directly grant Runtrue workload or secret
  access, and Runtrue server compromise does not directly grant provider
  management authority.
- The control-plane API and schema become the provider-neutral contract.
- Exact demand may remain queued until an operator registers an exact template;
  this is intentional and observable.
- Provider reconcilers must be idempotent and tolerate ambiguous create/delete
  outcomes.
- Multi-host availability is not claimed by the Compose provider.

## Required verification

- Two autoscalers racing for one pool cannot both mutate under one fencing
  generation.
- A launch claim can enroll one runner exactly once and token consumption,
  runner creation, claim consumption, and fleet transition are atomic.
- Mismatched provider evidence or image digest fails before certificate issue.
- Offline replacement does not permit late logs, artifacts, secrets, or
  completion from the fenced runner.
- Normal termination is impossible before drain completion.
- The autoscaler API token cannot read Capsules, tenant secrets, job payloads,
  or runner broker endpoints.
