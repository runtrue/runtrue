# Lane 21: guest, runner, scheduler, and trusted planner

## Goal and ownership

Split `crates/guest-core/**`, `crates/runner-core/**`, `crates/scheduler/**`, and
`crates/trusted-planner/**`. Start after lanes 07, 15, 16, and 19.

## Target layouts

```text
guest-core/src/{lib,bootstrap,protocol,codec,commands,events,trust,session,authorization,error}.rs
runner-core/src/{lib,profile,trust_store,admission,lease,completion,validation,error}.rs
scheduler/src/{lib,model,quota,matching,resources,scheduler,validation,error}.rs
trusted-planner/src/{lib,provider,limits,planner,analysis,locks,source_trust,error}.rs
```

## Steps

1. Guest core: move bootstrap/key/config, authenticated envelope codec, command
   and event models, trust store, session state machine, authorization, and
   canonical HMAC helpers.
2. Runner core: move verified profile/trust store, lease admission, admitted
   lease, execution guard/state, completion, and validation.
3. Scheduler: move records/state models, tenant quota, matching, resource
   reservation/release, scheduler orchestration, and validation.
4. Trusted planner: move reusable source provider, limits/results, proposed
   analysis, main planning orchestration, lock parsing, and source trust.
5. Keep state-machine and atomic reservation/release flows in cohesive files.
6. Preserve all root exports and split tests after production checks pass.

Preserve HMAC domains, protocol bounds, admission checks, lease transitions,
scheduling determinism, resource accounting, plan identities, and trust
derivation. Run standard checks for each package.
