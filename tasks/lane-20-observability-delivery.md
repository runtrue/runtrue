# Lane 20: logs, reports, update, and debug sessions

## Goal and ownership

Split `crates/logs/**`, `crates/reports/**`, `crates/update/**`, and
`crates/debug-session/**`.

## Target layouts

```text
logs/src/{lib,model,secrets,redaction,limits,pipeline,journal,quota,validation,secure_io,error}.rs
reports/src/{lib,model,limits,strict_json,coverage,custom,sarif,junit,html,error}.rs
update/src/{lib,limits,roles,keys,trusted_state,release,sbom,canonical,verification,error}.rs
update/src/metadata/{mod,root,targets,snapshot,timestamp,envelope}.rs
debug-session/src/{lib,model,policy,token,identity,secret_gate,relay,broker,audit,validation,error}.rs
```

## Steps

1. Logs: separate models/secret patterns, streaming redaction, line/quota
   limiting, pipeline orchestration, journal hashing/verification, validation,
   and hardened filesystem access. Keep streaming redactor state intact.
2. Reports: separate strict JSON and each report format parser. Preserve parser
   tolerance, limits, annotation order, and normalized output.
3. Update: separate role/key/metadata envelope types, trusted-state rotation,
   release provenance, CycloneDX SBOM, canonical encoding, threshold
   verification, and errors. Reuse existing secure filesystem/trust-store files.
4. Debug sessions: separate request/record models, policy, one-use token,
   ephemeral identity, secret gate, relay, broker state machine, audit, and
   validation.
5. Split tests after each crate compiles and preserve root exports.

Preserve secret redaction, journal hashes, update signature bytes and role
thresholds, debug token one-use behavior, broker transitions, and audit order.
Run standard checks for each package.
