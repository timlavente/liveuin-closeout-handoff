# AUTH02 Ops restart source review — bounded evidence

The current API candidate introduces no new import-time execution. Its non-function module statements and existing function declarations (decorators, defaults and annotations) are AST-identical to the deployed baseline. The sole new helper has no declaration-time call. Exact candidate SHA-256: `a0834b412c06263d1ca593de67cc2514471cf4fdd7a83c860608be998fc65fcb`.

The reviewed20-file Ops source subtree contains no startup/lifespan/scheduler registration or import-time mail/payment/tenancy job invocation. `autopilot_executor.apply_staged_actions` is inside the exact `if __name__ == "__main__"` guard at706–709, so importing that module does not call it. Auth modules declare routers/functions. SQLAlchemy `create_engine`/`sessionmaker` calls in the generated router construct engine/session factories; the shown import-time calls contain no connection/query call. Router/manifest/env-cache setup still executes.

The selected systemd metadata shows four ExecStartPre operations: ensure_venv, cache-directory creation, and py_compile of app.py/main.py. ExecStartPost is empty. ExecStart wrapper reads systemd credential files into its own process environment and starts uvicorn app.main:app on127.0.0.1:9095. No secret values were read or emitted by this review.

**Remaining prestart condition:** ensure_venv is not a passive check. Its existing rebuild path can remove/recreate the virtual environment, upgrade pip/tools and install requirements. It also runs import probes. The current mode/hash/executable classifier is pending; no product import or restart has been run by this reviewer. A requirements hash match alone cannot guarantee no rebuild in automatic mode if imports fail.

**Scope limit:** the20-file traversal covers static imports resolvable within the Ops directory. Main also imports31 unique deploy modules and a function-scoped app.connect_admin router. Their exact paths and lines are in outside-import-scope.json. Thus this review is not a platform-wide assertion that all current startup effects are absent. No existing mail queues, customer records, transactions or imported-tenancy records were read.

Files: unit-selected-metadata.json, candidate-startup-delta.json, outside-import-scope.json; root-generated AST evidence is backend/evidence/auth02-startup-declarations.json (SHA-256 `8a905e5a7c84cef38fa402bb02fee767757df931f90c3a3622b73ab18f63f123`).

Ecosystem boundary check: reviewed service is LiveUIN Ops/Identity routing and canonical Core adapters. No sibling website or imported-tenancy workflow was changed. Public access and public live charging were not enabled.

Helper correction: prestart-mode-readonly.py SHA94603d438a37d78938916c146bff155c9a85c88bb5d1632a3d5e21ae41f4f7c4 is withdrawn after a source-redaction regex stalled. Root interrupted it before any service mutation; the helper contained no product execution or writes. Its replacement prestart-mode-readonly-v2.py SHA219f9a2fb314e64ad85e691c7a3c09c08704c0cb0598bdd2663cc6cfb59ceb7c uses a linear quote scanner, condition-first split/isidentifier literal checks and an8-second alarm. Only the replacement result may be used for readiness.

Current prestart metadata (replacement helper result): running PID1298408 has no ENSURE_VENV overrides, so source defaults are rebuild=auto and app-import=auto. Expected venv Python exists/executable; requirements hash equals its stored marker. Default third-party probes are fastapi, httpx, psycopg, psycopg2, pydantic, uvicorn and email_validator. The script's eval is only indirect lookup over LIVEUIN_DB_DSN, OPS_DB_DSN and DATABASE_URL. No probe was executed by this review.

This supports a narrow next check: compare the actual loaded next-start prestart environment (before the wrapper adds DSNs), prove the app import is skipped, and run only the seven existing library probes under the same interpreter/working-directory binding. Seven passes plus unchanged pins prove the present fast-path condition at187–189; they do not make auto mode structurally incapable of later rebuilding. Any changed pin or failed probe must stop before ensure_venv. Source/flags cannot by themselves certify the fast path.

Replacement result SHA-256: `2120f3ea47b29fb7febb899aa2dbc035f99bdbcb6d590d88031ff4a723088883`.
