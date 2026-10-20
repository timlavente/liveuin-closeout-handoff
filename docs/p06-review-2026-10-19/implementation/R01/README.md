# R01 staged private-operation guard

**Staged fix ready for review; R01 has not passed on production. Nothing has been deployed or restarted.** This package changes exactly two deployed application files and guards the 21 operations in the frozen R01 inventory. It contains no credentials, case records, customer documents, database exports or account changes.

In the isolated staged tests, a stranger receives a sign-in refusal before a protected handler reads or writes. A failed identity service closes the operation with an unavailable response. A verified existing platform administrator reaches the same handler with the signed LiveUIN workspace explicitly passed to it. Private CMS handlers target only `www`. The existing fixed 404 pages route and public published-content handlers retain their behavior.

## Files and exact baseline

- `before/`: exact fresh copies of `/opt/liveuin/deploy/home_api.py` and `/opt/liveuin/deploy/public_home_gateway.py`. These are forensic inputs, not a safe rollback to reopen private routes.
- `candidate/`: the guarded replacement files, built from those copies. The differing local `deploy/` files are not used or overwritten.
- `fallback/`: the same gateway with its 21 private operations closed before identity or data calls. Public paths and the existing fixed 404 remain available.
- `evidence/`: per-file unified diffs, exact route inventory, source provenance, framework versions and the test output.
- `tests/`: isolated tests which import the actual candidate/fallback gateway applications with in-memory service spies. Exact deployed identity verifier functions are tested separately against a synthetic memory store.
- `build_candidate.py` and `guard-fragment.py`: reproducible package assembly from the pinned input copies. They do not connect to the server.

`manifest.json` records each file's digest, the frozen plan digest and hydrated/readable local inputs. There is no product Git commit: this is a versioned, reviewable file package. Initial partial test runs are not proof and are excluded from the package. The final test log is the result for the final source hashes.

## Authorization behavior

The existing canonical authority is fixed to `http://127.0.0.1:9095/api/ops/auth/whoami`. Requests force `X-LiveUIN-Require-Signed-Session: 1`. The guard does not call the legacy path, invent a session, read the credential store itself, or add a second authority. Requests have a 2.5-second transport timeout, a 64 KiB response limit, strict JSON/object checks, no redirects and no process proxy use. Unavailable or malformed authority replies fail closed.

Exactly one supported credential form is forwarded, using deliberate precedence: a complete signed-header bundle, otherwise a session bearer, otherwise the complete canonical cookie bundle. Other cookies, API/connector keys, requested-profile fields and forwarded hosts cannot affect this selection. A partial signed bundle is refused even when another credential is present. Empty scope fields are permitted only as part of a complete signed bundle; the authority must verify them. Duplicate credential headers/canonical cookies are refused. Higher-priority valid credentials are verified independently; discarded credentials cannot supplement their workspace, role or signature.

This matters because the existing whoami adapter calls `resolve_access_context(require_identity=False)`: forwarding an unsigned workspace alongside a bearer could otherwise influence its workspace projection. The guard forwards no unsigned identity selectors with a bearer/cookie. It requires `auth is True`, `canonical_session_verified is True`, `credential_kind == liveuin_session`, a nonempty actor, valid claim shapes, the exact signed workspace `liveuin_first_party`, and the existing platform role `ops_manager` or `super_admin`. No generic owner/host, connector-admin, parent, agent or test-workspace role can open these aggregate operations.

The earlier entry report's generalized theme/CMS scope statement is corrected by `R01-POLICY-CORRECTION-01.md`. The correction narrows the candidate to the exact existing effective role policy. No production grants have been proved or created for Ern. The positive fixture is explicitly synthetic; it is not proof that his account already has a particular role/workspace. R05 later proves his actual login. Test staff's own-case access belongs in later scoped desk/case routes, not these platform controls.

Query and body workspace/site/host selectors are checked before service/preview loading. Duplicate query selectors and JSON keys are refused; conflicting aliases and sibling sites are refused. The authorized workspace is passed explicitly to admin/developer handlers; the inherited `laijuzhu` default is never used. CMS uses `www` after those checks and never authorizes from `Host` or `X-Forwarded-Host`.

Cookie-authenticated CMS writes require an approved HTTPS Origin and JSON; hostile/missing cookie Origins, cross-site Fetch Metadata and form submissions are refused. Explicit signed-header/bearer writes still refuse a hostile supplied Origin. Allowed origins are the existing LiveUIN public, API and Ops hosts; no sibling or arbitrary localhost browser origin is granted. Existing CORS policy is not widened. Every protected response, including refusal, validation error and service failure, receives `Cache-Control: no-store`; Cookie/Authorization are added to Vary without dropping Origin. Business failures are sanitized without recovering the database.

## Isolated proof and limits

The final tests cover all 21 actual mounted operations: anonymous refusal before service/body validation, a synthetic verified platform allow path, test/sibling/cross-workspace refusal, forbidden roles, malformed/unverified identity, authority denial/outage, CMS selector conflicts and browser-write protection, body replay through the actual middleware, cache headers and sanitized failures. Both variants construct the actual gateway application. The closed fallback denies every private operation before identity/data calls. Public handler ASTs and the fixed 404 function match the exact deployed baseline.

The identity tests run exact deployed verifier functions without importing the product module. Synthetic signatures are checked against a synthetic memory store; modified claims, expired signatures, revoked/expired/rotated/inactive/missing records and store-workspace mismatch are refused. No real credential is used. This confirms the existing verifier behavior used by the adapter; it does not establish the active production account/store configuration.

Tests use Python 3.13 locally with the production FastAPI 0.116.1, Starlette 0.47.3 and Pydantic 1.10.24 versions. Production is Python 3.10.12. The final candidate and fallback both passed independent stdin-only Python 3.10.12 compilation on the server, without source writes, imports or product execution; see `evidence/root-python310-compile-final.json`. Isolated HTTP tests are not production browser/account proof.

## Production entry and recovery gate

This package deliberately includes no executable upload/restart script. Authenticated activation/recovery access is unproved. The narrow passwordless command list does not include the public API restart; general sudo entitlement still requires authentication. Copy permission alone is not permission or ability to activate and recover. No rsync/helper/kill workaround is allowed.

Before any mutation, the engineer must recheck the pinned on-disk source hashes, retain an exact pre-change copy, verify the actual service restart/recovery method and its authorization, and prove the selected identity allow/refuse path using permitted synthetic/owner scope. No database recovery or R02 work is included. The known active unit is `liveuin-public-api.service`, running the public gateway on loopback 9080.

The safe recovery candidate is `fallback/`: stage its two pinned files with the authorized deployment method and activate through the verified service mechanism if the guarded candidate fails its private/public smoke. It returns 503 for all 21 private operations without touching their data handlers. The original unguarded source is retained for investigation; restoring it to serve traffic is not an acceptable recovery. Recovery has been proved only in isolation, not executed or verified on production. If restart/recovery cannot be established, stop before deployment.

The separate `PUBLIC-CHARGE-LOCK-INVENTORY-01.md` found no exposed live-charge operation on the bounded inspected paths, but effective protected runtime settings were unreadable. A universal public-live-charge-off claim remains unproved. That production invariant and safe scoped allow/refuse evidence remain deployment/freeze-note gates. **Do not issue FREEZE-ISSUE-001 from these isolated tests. Do not begin R02.**

## Boundary and data record

This row touches the private API boundary on LiveUIN's existing public gateway. LiveUIN Core/Trust/Ops and signed Identity remain authoritative. Persona, workspace and data restrictions are enforced at that boundary; no UI/shortcode, commercial plan/quota, listing, commission or case entitlement is changed. The ecosystem boundary and persona audit were checked against the global LiveUIN documents and sibling blueprints. No connector or sibling site/theme was modified. No rent/deposit custody, payment keys, payment mode, publish switch, legal document or signature behavior was changed. Imported tenancies were not used and were not emailed. No public access was opened.
