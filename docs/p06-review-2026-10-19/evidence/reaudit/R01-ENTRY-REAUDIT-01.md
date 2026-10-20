# R01 entry re-audit — 19 October 2026

Status: read-only preparation against Review06. No freeze, patch, deployment, restart, database access, credentials inspection or account action occurred.

**A small guard repair is technically feasible without restoring the broken search/status database connection. R01's scope must first be corrected to cover the adjacent private routes in the same deployed gateway. Its code boundary is now concrete; live deployment is not yet cleared.** The outstanding execution conditions are the exact restart/reload mechanism, a verified scoped staff fixture for the allow path, and a tested closed fallback. These are engineering dependencies, not decisions Ern must debug.

## Fresh baseline and concrete scope

Fresh copies from the server and SHA256 evidence are in `source/` and `r01-source-baseline.json`. Deployed `home_api.py`, `public_home_gateway.py`, Ops `app.py`, API nginx and Ops nginx are unchanged from the earlier baseline. Deployed home routes still differ from the working local source. Do not upload the local file wholesale.

The primary candidate source is `/opt/liveuin/deploy/home_api.py`, SHA256 `cab022b1055df93e27328fa74813d8ae043bb1cc387562255eed0d9b68471172`. The second candidate file is `/opt/liveuin/deploy/public_home_gateway.py` (SHA256 `67f4befdd7dbccc34bcaa79050b6c990cd3df33349ee4369f7da9838810f6fac`) for its existing rollout-status operation. A shared guard before handler execution protects every hostname routing to this application; an nginx-only `/admin/` check does not.

The exact 21 existing operations are recorded with source line numbers in `r01-proposed-protected-routes.json`:

| Group | Existing operations requiring a private boundary |
|---|---|
| Control centre, seven GETs | `/api/core/admin/control-center`; suffixes `/users`, `/roles`, `/audit`, `/retention`, `/settings`, `/developers` (`home_api.py:729–775`) |
| Developer control, five GETs | `/api/core/developers/portal`; suffixes `/docs`, `/webhooks`, `/sandbox`, `/limits` (`779–810`) |
| Private draft blog, two GETs | `/api/core/public-cms/blog/posts`, `/api/core/public-cms/blog/posts/{slug}` (`342–374`); these default to draft and read history/data. |
| Private rollout evidence, one GET | `/api/core/ops/liveuintest-rollout-status` (`public_home_gateway.py:347–349`); private role policy exists in the preview authority but was not applied to this mounted handler. |
| Private CMS writes, six POSTs | `/api/core/public-cms/blog/posts/{draft,publish,restore}` and `/api/core/public-cms/pages/{draft,publish,restore}` (`393–498`) |

`GET /api/core/public-cms/pages` already returns a fixed404 (`379–389`); preserve that lock. Public `/api/public/blog...`, honest public pages/search/status/intake and Sierra marketing remain outside this private guard. No CMS content or sibling site is edited. No private endpoint was requested or mutated to establish these findings.

The public gateway mounts `home_api.router` at `public_home_gateway.py:264` with only CORS middleware at257. API nginx's default location sends requests to9080, while its `/admin/` deny does not match `/api/core/admin/...`. These facts remain unchanged.

The developer service is **not made safe merely by replacing a workspace query**: it selects its first-party snapshot and returns workspace/endpoint summaries (`deploy/developer_portal_service.py:114–118,194–210,250–262`). The proposed guard must require the existing platform-admin/first-party entitlement for this family, not any staff member of any workspace. CMS needs explicit authorized LiveUIN site scope; do not grant a signed caller arbitrary `site` or `host` selection. Read-only role/site entitlements must be fixed in the R01 tests before deployment, without creating a new identity store or expanding connector permissions.

## The actual existing sign-in authority

Production `ops-authgate.service` is active on9097, working directory `/opt/ops-authgate`, entry `app:app`; its actual source is `source/ops-authgate-app.py`. It sends `X-LiveUIN-Require-Signed-Session: 1` to the loopback canonical whoami at9095. It requires both `auth=true` and `canonical_session_verified=true` before its route-role check. Its response does not provide a workspace, so calling `/gate` alone cannot bind an API query to a workspace.

The active Ops assembly loads `/opt/liveuin/ops_backend/app.py`, which includes `auth_api.router` before its later duplicate whoami handler. `/opt/liveuin/ops_backend/auth_api.py:895–930` requires credential kind `liveuin_session`, verified true, a recognized staff role and a nonempty actor. Lines1044–1048 return the signed projection, or a denied result on the strict path **before** the legacy cookie decoder/DB user-row path. Its signed claims include workspace, actor, role and scopes at941–947. `auth_api.py:22–27` explicitly imports Identity from `/opt/liveuin/deploy`.

This is the least disruptive authority to reuse: a bounded trusted-loopback call from the gateway's private guard, forwarding only its supported credentials and forcing the strict header. Require the returned canonical verification and role/site policy; derive scope from returned claims; reject a conflicting query/header. Never accept a caller-provided whoami URL, role projection or workspace as authorization. A timeout/malformed response must close the private operation with a clear unavailable/sign-in response before its data handler.

A generic `resolve_access_context(...require_identity=True)` call alone is insufficient. In the deployed Identity source, `connector_api_key` can produce an unverified connector-admin context (`core_identity_session.py:787–881`). R01 must explicitly reject unverified/connector/bridge credentials. The existing strict whoami already rejects them. Likewise, a literal role `owner` is not an automatic platform-admin entitlement. Today's source inspection does not prove Ern's actual role/workspace mapping; R05 still proves his real identity.

The known signed identity verification depends on its existing session registry, not the failed public search/replay PostgreSQL connection. Reusing the9095 strict projection avoids guessing the separate9080 Identity store/configuration. This proves a viable design, not that every production account presently authenticates.

## Required checks and safe return path

The existing AST-only `ops_authgate_canonical_session_smoke.py` passed seven checks against the exact deployed gate, app and auth_api copies: legacy-cookie denial, signed-host refusal, allowed signed Ops roles, and strict whoami before legacy decoding. This used fixtures and did not import the product runtime or touch a database. It is not the real-owner browser proof.

Before deploying R01, its own bounded tests must prove:

- anonymous, forged role/workspace, unsigned connector/bridge, malformed/expired/revoked session, wrong role and wrong workspace/site cannot invoke a protected service function;
- a verified authorized session retains the allowed path and authenticated workspace/site; backend spies establish scope without reading real records;
- identity unavailable/malformed replies remain closed; every protected response is private/no-store and exposes no credential;
- the full21-operation set is protected, including CMS writes, and the already-closed pages GET stays404;
- public blog/display/search/status behavior and the separate Sierra routes are not inadvertently restricted; search/status's existing failure is not falsely reported repaired;
- after release, safe denial checks pass on actual routing; a scoped positive check uses the authorized synthetic/owner identity, not a fabricated production credential.

The exact current source copy is available for forensic comparison and backup. The R01 package must include both the guarded candidate and a tested **closed fallback** that disables the affected private operations cleanly while preserving public routes. Restoring the old unguarded source alone is not an acceptable security rollback. No database migration or credential change belongs in R01, so this row must not create a database restore exercise as a prerequisite for code-only denial work. Existing production stores remain untouched.

## Deployment access: exact remaining dependency

`r01-service-access-metadata.json` records the active service and path ownership. The SSH user can read deployed source, and sudo lists passwordless rsync. It does **not** list passwordless restart of `liveuin-public-api.service`, restart of Ops or authgate, or nginx reload. General passwordless sudo previously required a password. Named promotion helpers exist, but the readable helper references do not establish a9080 restart mechanism; one canary helper is unreadable. None was executed.

Therefore code transport capability is known; the intended service restart/rollback mechanism remains **unverified**. Resolve an authorized mechanism before deployment. Do not work around it by modifying privileged scripts, killing processes, changing sudo or using rsync to create an execution path. This access dependency does not prevent frozen-row implementation and isolated testing; it prevents claiming live release clearance.

## Runtime route-registration check and contract-router resolution

The final finite read-only check retrieved only OpenAPI path/method/operation metadata from loopback9080 and9095. Both schema endpoints returned200;9080 reports69 operations and9095 reports613. The full sanitized path inventory is `r01-runtime-openapi-metadata.json`; no business endpoint, database or customer record was read.

All20 home_api operations above are mounted on9080, alongside the fixed404 pages GET. The runtime schema additionally confirms the unguarded rollout-status GET described above, bringing R01 to **21 operations across two source files**. It reads `outputs/ops-liveuintest-rollout-status/ops-liveuintest-rollout-status-report.json` or falls back to a readiness projection (`public_home_gateway.py:97–140,347–349`). Existing deployed `route_group_allowed` classifies this endpoint for Ops/finance roles. Reuse that policy only after canonical signed-session verification; preserve its current permitted role intersection rather than accepting a role header. Do not read the report until authorization succeeds. Keep it private/no-store, avoid any new raw report fields, credentials, customer IDs or path exposure, and do not turn its page-readiness claims into P6 completion. This is boundary hardening, not a rollout dashboard redesign.

The actual OpenAPI inventories contain **zero `/api/core/contracts/*` operations on both services**. Combined with the absent contract-router imports in the active assembly and the contract module's default schema-visible decorators, this resolves the suspected current mount: the inspected contract GET source is not an active advertised route family on these two services. Do not add contract implementation or change signing in R01. No claim is made about a future/different deployment.

The only other non-public9080 data paths in the schema are `/api/pass/status` and `/api/pass/{case_id}`. Their router uses injected API-key dependencies; the public gateway supplies that verifier. Their scoped-family proof remains in the existing auth rows; schema visibility alone does not establish another R01 defect. `/v1/health` is intentionally public. No exhaustive609+ private-service hardening programme was added.

## Boundary and hydration check

Rechecked global/project AGENTS, README, sitemap/domain/P6 definitions, current tracker, persona/entitlement rules, Laijuzhu blueprint and both ownership/protocol sections of the ecosystem audit. All fingerprinted local inputs have positive local blocks and readable bytes. No placeholder was reconstructed. This row affects LiveUIN's private API boundary on a public gateway; Core/Trust/Ops and signed Identity remain authoritative. No connector, sibling theme, imported tenancy or unrelated operator record was touched.

## Exact existing policy names to retain

A fresh source-only read of deployed `/opt/liveuin/public-home-preview.py` is recorded in `r01-existing-policy-source.json`. Its SHA256 is `e523924bac421433ad34ea6587353b0448bd42aeba950e27029d654ffb063099`, different from local. Do not import or copy the local policy wholesale.

Its `route_group_allowed` at932 declares privileged roles **admin, super_admin, ops_manager**. Control-centre and developer families allow ops_manager/connector_admin/super_admin with existing prefixes **ops., connect., identity., finance.**, while privileged roles bypass the prefix check. CMS uses **ops.theme** or **identity.admin** with its privileged/Ops/connector role table. These are existing role/scope names, not production grants proven for Ern. The stricter canonical whoami's staff-role set excludes `admin` and `connector_admin`; the effective intersection for privileged admin/developer access is therefore **ops_manager or super_admin**. Do not “repair” this difference by adding grants in R01. Verified `ops` with the existing CMS scope can remain a candidate CMS path only with explicit LiveUIN site authorization. No `administrator` alias should be imported from the different local file.

The deployed frontend gate is broader than some API families: its execution role includes operator/finance, while admin control is narrower. R01 must not treat opening the staff shell as permission to read platform-wide developer settings. `owner` as a persona also does not supply that grant by itself.

Safe staging for R01 means an isolated local test app assembled from the verified source copies in this non-cloud temporary directory, with a stubbed signed authority and service spies. This is available without service/data writes. An authorized production restart/reload path is still not established; the existing named production helpers are not evidence that they operate this9080 service.

## Public live-charging invariant: evidence that can honestly be reused

Known LiveUIN publication route: `GET https://www.liveuin.com/api/core/inventory/marketing-publications/listing_ef55a13993724d8e8d1201cb` maps to9095 via the established nginx route and `core_marketing_offer_api.py:39–41` → `MarketingWorkflow.get_public`. Prior public evidence returns **payment_enabled=false, hold_enabled=false, instant_booking_enabled=false**. `marketing_publication.js:49` submits a rental request and reports no payment; it does not invoke Stripe checkout. This supports the Sierra request path being non-charging. R01 must not change this route or those flags.

Known sample path: `GET https://liveuin.com/checkout/cozy-studio-orchard`; the inspected public checkout source states no agreement/payment record or charge is created (`www-lovable/src/pages/Checkout.tsx:57,75`). The release/browser observation must be rechecked rather than trusting that local file alone.

Known Core adapter: deployed `core_stripe_sandbox_api.py` matches the earlier payment fingerprint and accepts only test keys at30; the existing pay-door health independently reports live off/refund executor off. These are separate supporting facts, not a universal live-lock proof.

Safe before/after R01 checks are GETs of the public Sierra projection (assert the three false flags), public Sierra/sample checkout pages (assert no live checkout handoff), and anonymous GET of an already documented private payment-status endpoint (expect401/403 without reading records). The last check proves an anonymous auth lock, **not** card-mode configuration. Do not submit a real or valid synthetic checkout, card, amount, case or refund to establish R01 invariance.

**Exact remaining coverage limit:** this audit has not proven a complete inventory of every deployed payment-creation URL and its effective live flag. Therefore “all public live charging is off” cannot be derived solely from pay health, a sandbox adapter or a single listing. Until that inventory is established, the first issue note should state the specific observed public paths stayed non-charging and that R01 changed no payment flags; it must not quietly convert that into worldwide/merchant-wide charging readiness. No unrelated IGEMA transaction is a proof candidate.

## Final freeze input status

The inventory is stable at **21 guarded operations, two application files**, with the existing closed pages route retained. Contract mount uncertainty is resolved for9080/9095 by runtime schema metadata. The source hash, role/scope, test and closed-fallback requirements above are the implementation boundary. Production restart/rollback authority and complete no-live-charge path coverage remain explicitly unproved mutation-entry conditions; only isolated R01 staging/tests may start after freeze until those conditions pass. No unrelated promotion helper was executed and no permission workaround was attempted.
