# Conformance checks

`check_schema.py` performs offline structural validation of both the exact
reference schema shipped with the design and the executable workflow-v1 schema.
It rejects duplicate JSON keys, unresolved or remote references, open typed
objects, malformed bounds, and missing root workflow requirements.

`check_openapi_routes.py` compares the Axum router's static HTTP path/verb
inventory with `api/openapi.yaml`. It normalizes parameter names while rejecting
undocumented implementations and stale specification entries.

`check_migrations.py` requires a contiguous migration sequence, matching
`user_version` declarations, exact registration order in the control plane,
and a backup verifier schema head that advances in the same change. It also
checks the immutable SHA-256 inventory for migrations already shipped through
schema 20; corrections must use a new migration rather than rewrite history.

Run it from any directory with:

```bash
python3 tests/conformance/check_schema.py
python3 tests/conformance/check_openapi_routes.py
python3 tests/conformance/check_migrations.py
```

The Rust workspace tests remain the authoritative parser, compiler, engine,
protocol, storage, and security conformance suite.
