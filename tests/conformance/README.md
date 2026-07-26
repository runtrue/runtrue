# Conformance checks

`check_schema.py` performs offline structural validation of both the exact
reference schema shipped with the design and the executable workflow-v1 schema.
It rejects duplicate JSON keys, unresolved or remote references, open typed
objects, malformed bounds, and missing root workflow requirements.

`check_openapi_routes.py` compares the Axum router's static HTTP path/verb
inventory with `api/openapi.yaml`. It normalizes parameter names while rejecting
undocumented implementations and stale specification entries.

`check_migrations.py` freezes and validates the complete legacy SQLite and
PostgreSQL histories, their exact adapter registration order, and SQLite's
backup-verifier head. It also validates the ordered unified catalog, unique
logical migration IDs, backend payloads, and the history digest bound by the
cutover baseline. Corrections to a shipped history or logical migration must
use a new forward migration rather than rewriting accepted files.

`verify_workflow_frontend.sh` is the mandatory fail-fast gate for the neutral
workflow-frontend boundary. It verifies that core has no concrete frontend
dependency or lockfile source, runs the focused generic-contract and
trusted-planner tests, and checks the server/CLI compositions against
`Cargo.lock`. Concrete adapter repositories own their own formatting, tests,
and strict Clippy gates.

Run it from any directory with:

```bash
tests/conformance/verify_workflow_frontend.sh
python3 tests/conformance/check_schema.py
python3 tests/conformance/check_openapi_routes.py
python3 tests/conformance/check_migrations.py
```

The Rust workspace tests remain the authoritative parser, compiler, engine,
protocol, storage, and security conformance suite.
