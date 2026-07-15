# Lane 18: auth, OIDC, signing, and secrets

## Goal and ownership

Split the security and identity crates. This lane exclusively owns
`crates/auth/**`, `crates/oidc/**`, `crates/signing/**`, and `crates/secrets/**`.

## Target layouts

```text
auth/src/{lib,principal,token,authentication,authorization,error}.rs
auth/src/oidc/{mod,config,claims,verification}.rs

oidc/src/{lib,keys,jwk,discovery,key_ring,grant,issuer,claims,token,verification,validation,error}.rs

signing/src/{lib,model,authorization,signer,local,envelope,audit,broker,validation,canonical,error}.rs
signing/src/ledger/{mod,memory,sqlite,validation}.rs

secrets/src/provider/{mod,model,registry,validation}.rs
secrets/src/provider/vault/{mod,token,transport,reference,kv}.rs
secrets/src/vault/{mod,model,crypto,lease,snapshot,store,validation,error}.rs
secrets/src/runner_broker/{mod,model,authorization,delivery,audit}.rs
```

## Steps

1. Process one crate at a time in this order: OIDC, auth, signing, secrets.
2. For OIDC, keep signing key material with `Drop`/redacted `Debug`; split JWK
   discovery, key-ring rotation/revocation, grants, issuer/minting, claims, and
   verification.
3. For auth, separate principal/token models, authentication, authorization,
   and OIDC claim verification while retaining root exports.
4. For signing, separate request/grant/approval models, authorizer/signer
   traits, local signer, envelope/audit, memory and SQLite ledgers, broker, and
   validation. Keep ledger state transition and validation together.
5. For secrets provider, separate registry from hardened Vault transport,
   token source, strict reference parsing, and KV-v2 behavior.
6. For secret vault, separate public model, encryption/wrapping, lease state,
   snapshot representation, store operations, and validation.
7. For runner broker, separate authorization, one-shot delivery, and audit.
8. Move tests after each crate compiles.

## Safety constraints

Never separate secret-bearing values from zeroization/drop behavior. Preserve
canonical signing bytes, key identifiers, token validation order, lease state
transitions, hardened DNS/address policy, redacted diagnostics, and SQL ledger
semantics.

Run standard checks for each package before proceeding to the next.
