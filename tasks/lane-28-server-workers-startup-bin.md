# Lane 28: server SCM worker, human identity, and startup

## Goal and ownership

Complete `bins/server/**` after lane 27. This agent owns all remaining server
source and test files.

## Target layout

```text
src/scm_worker/{mod,config,tokens,checks,source_fetch,worker,continuations,reusable,mirror,validation,error}.rs
src/human_oidc/{mod,model,github,client,jwt,claims,cookies,network,metrics,error}.rs
src/github_install_ui/{mod,model,render,escape}.rs
src/startup/{mod,args,config,github,runner_grpc,servers,workers,secure_fs,secrets,error}.rs
src/main.rs
```

## Steps

1. Split SCM worker configuration/token provider/check publisher/source fetcher,
   task loop, continuations, reusable workflow provider, secure mirror paths,
   validation, and errors. Preserve private token redaction.
2. Split human OIDC/GitHub OAuth models and adapters, hardened HTTP client,
   ID-token/JWK verification, claims/MFA, cookie sealing, public-network policy,
   metrics, and errors.
3. Split GitHub installation UI model/enums from rendering and HTML escaping;
   preserve exact CSS and cache-control exports.
4. Move server arguments/config/environment parsing, GitHub signer/provider,
   runner gRPC setup, HTTP/gRPC task supervision, background workers, shutdown,
   database path preparation, seed/secret reads, systemd credential handling,
   and startup errors under `startup/`.
5. Leave `main.rs` as a thin async entrypoint.
6. Split remaining `http`, `scm_worker`, and startup tests by subsystem.
7. Audit `server/src/lib.rs` as declarations and compatibility re-exports only.

## Safety constraints

Preserve GitHub token lifetime and permissions, mirror confinement, workflow
approval evidence, OIDC/JWT validation, SSRF protections, cookie secrecy,
startup file permissions, service supervision, shutdown, and public exports.

Run all `runtrue-server` checks and its complete integration test suite.
