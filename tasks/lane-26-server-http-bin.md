# Lane 26: server HTTP application

## Goal and ownership

Split `bins/server/src/app.rs` after lanes 06-22 and 25. This is the first
server lane; server lanes 26-28 are strictly sequential.

## Target layout

```text
src/app/mod.rs
src/app/{state,router,middleware,problem,authorization,audit}.rs
src/app/routes/{health,repositories,capsules,runs,approvals,runners,secrets,variables,artifacts,cache,policy,api_tokens}.rs
src/app/browser/{mod,login,sessions,cookies,csrf,status}.rs
src/app/github/{mod,setup,installations,webhooks,lifecycle,ui}.rs
```

## Steps

1. Convert `app.rs` to `app/mod.rs` unchanged and verify all server tests still
   compile.
2. Extract `AppState`, bootstrap authentication, provider state, security-seed
   derivation, metrics, and builder methods.
3. Move router construction separately, preserving route order and middleware.
4. Move request IDs, bearer authentication, writable-mode guards, framework
   error normalization, problem responses, authorization resources, and audit
   principal conversion.
5. Extract REST models and handlers by route family in the order listed above.
6. Move browser login/session refresh/logout, sealed cookies, CSRF, callback
   terminalization, and status pages under `browser/`.
7. Move GitHub setup, installation catalog/reconciliation, UI, provider
   callbacks, webhooks, and lifecycle projection under `github/`.
8. Keep each handler transaction and its validation helpers together. Do not
   create a generic route helper dumping ground.
9. Split `tests/http.rs` by route family with shared application/token fixtures
   in `tests/http/support.rs`.

## Safety constraints

Preserve route paths, middleware order, RFC 7807 responses, authorization,
tenant scoping, idempotency, cookie attributes, callback one-use behavior,
webhook verification, lifecycle deduplication, and sensitive response headers.

Run all `runtrue-server` tests and Clippy before lane 27.
