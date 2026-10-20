# LiveUIN source, runtime and boundary audit — 19 October 2026

Status: READ-ONLY FINDINGS FOR PLAN REFINEMENT. This is not FREEZE-PLAN-01, an implementation, a release or a P6 claim. Checked in the evening Singapore time. No accounts, listings, cases, payments, switches, code or server configuration were changed. No imported tenancy records or private family documents were opened or emailed.

## What changes the proposed plan

1. **The three API failures have an observed common cause.** The existing public API service reaches PostgreSQL, but the database rejects its authentication. The deployed service log shows `password authentication failed for user "liveuin_ops"`. Search fails while checking its rate limit; status and the admin summary fail while reading replay-store statistics. These are not missing endpoints. Preserve separate acceptance checks but treat their shared dependency as one controlled repair.
2. **A private guard must precede that credential repair.** The deployed admin summary endpoint directly calls its service using caller-supplied `workspace_id`, without a signed-session dependency. The public gateway mounts it without global auth; nginx sends it to that gateway. An anonymous request therefore reaches private-summary data work. Its current database crash is not a security lock. Restoring the database before adding a deny boundary could expose the summary. This is confirmed missing boundary, not a claim that a real family's document was retrieved.
3. **“Core does not exist” is too broad and contradicted by direct evidence.** The configured LiveUIN server answers SSH and runs the public gateway, private backend, production identity service, staging backend and PostgreSQL. Substantial Core source is on the server and locally. The narrower claim is that a complete, reproducible, production-approved case journey and release source lineage have not been proven. Do not build a second Core or replace the existing server because one proposed DNS name fails.
4. **The GitHub default branch is README-only; the repository is not.** There are 74 branches. At least three recent M2 branches contain source fragments and contracts. Also the supposed “33 open issues” is **1 issue plus 32 pull requests**, not 33 issues.
5. **The Sierra pilot has its own real runtime, different from showroom search.** The public and Host marketing paths proxy to the private backend on port 9095. The API/showroom service is on 9080. Marketing runtime code binds existing Core Inventory and Demand stores and real Identity. This explains how a real Sierra listing and broken sample search can coexist. The historical listing proof does not close applicant-to-case, agreement, payment or P6.
6. **Source drift is real.** Three failing service files and the Sierra assembly match local hashes, but deployed gateway, home routes and case files differ from local versions. A bulk local upload would risk a downgrade.

## Evidence and precise fault paths

Evidence captured in `server-readonly-evidence.txt`; local file fingerprints in `local-source-fingerprints.json`; GitHub metadata, branch trees and issue/PR counts in `github-source-evidence.json` in this directory.

Public process: `liveuin-public-api.service`, working directory `/opt/liveuin`, command `python3 -m uvicorn deploy.public_home_gateway:app --host 127.0.0.1 --port 9080 --proxy-headers --app-dir /opt/liveuin`, observed active/running.

| Observed request | Deployed trace / source | What it proves |
|---|---|---|
| POST `/api/public/search` → 500 | `/opt/liveuin/deploy/home_api.py:844` → `public_home_service.py:2301` → `public_home_store.py:250` → `public_home_postgres_store.py:79,54` → PostgreSQL authentication failure | Existing route fails on rate-limit persistence, before returning search results. |
| GET `/api/public/status` → 500 | `home_api.py:602` → `public_status_service.py:357,213` → `core_access_service.py:2959` → `core_adapter_replay_store.py:169` → `core_adapter_replay_postgres_store.py:322,72` → same failure | Public status incorrectly depends on the failing internal read without a usable degraded response. |
| GET `/api/core/admin/control-center` → 500 | `home_api.py:732` → `admin_control_service.py:585` → audit/access/replay statistics → same failure | The route performs work before authenticating a visitor. |

The deployed route is `/opt/liveuin/deploy/home_api.py:728–732`: decorator, optional `workspace_id=Query(...)`, direct `admin_svc.admin_control_summary(...)`. Its users and roles siblings at 735–746 use the same unguarded pattern; those siblings were not requested. `/opt/liveuin/deploy/public_home_gateway.py:252–265` creates FastAPI, adds CORS, then includes the public home router; there is no global auth dependency there. `/etc/nginx/conf.d/api.liveuin.com.conf:80–85` blocks `/admin/`, but sends the default location to 9080; `/api/core/admin/...` does not match `/admin/`. Current anonymous request logs corroborate the path.

The summary service, byte-identical locally and on the server, is `/Users/Vivian/Documents/Liveuin/deploy/admin_control_service.py:582–641`. It gathers workspace access, audit, retention, API-key workspace, webhook workspace, CMS, contract-template/execution, payment and ledger summaries, then calls itself a private admin control center. CORS is not authentication. Freeze acceptance should require anonymous 401/403 before private reads, signed-role and signed-workspace enforcement, and refusal of forged workspace/role inputs. Do not merely catch the database error and return a plausible dashboard.

`public_home_service.py:2300–2327` searches the `LISTINGS` collection, areas, tools and deals and records the search. Even after its crash is repaired, that is not proof of real Inventory-backed room search. These must remain separate checks.

## Existing runtime and actual access

Observed service metadata (not just a document):

| Service | State | Runtime / role |
|---|---|---|
| `liveuin-public-api.service` | active/running | `/opt/liveuin`, public gateway on 9080 |
| `ops-backend@liveuin.service` | active/running | `/opt/liveuin/ops_backend`; DSN-credential wrapper; backend target 9095 is proven by nginx |
| `liveuin-ops-command.service` | active/running | `/opt/liveuin`, private Ops gateway on 9083 |
| `liveuin-identity-public-prod.service` | active/running | `/opt/liveuin-identity-public/current`, `prod_app:app` on 9098 |
| `liveuin-ops-backend-staging.service` | active/running | `/opt/liveuin-live-staging/run_backend.py`, staging workspace |
| `postgresql@14-main.service` | active/running | Existing PostgreSQL cluster; its presence does not prove every service's credentials/data model are correct |

The configured `liveuin-hk` SSH alias works as `liveuin`. GitHub API access reports admin/pull/push permissions for the three named repositories. General `sudo -n true` fails because a password is required. Read-only `sudo -n -l` reports command-specific passwordless permissions, including rsync and named release/model scripts. They were not executed. Thus read access is available, some privileged deployment mechanisms exist, and unrestricted administration has not been proven. Do not say all deployment access is missing; do not claim unrestricted deploy/restart readiness either.

Several guard/backup-related units show failed states, including `lu-offsite-rsync.service`, `lu-ops-watchdog.service`, `ops-guard.service` and `ops-nginx-guard.service`. Their present names/states are a P6 evidence gap, not proof that all backups are bad. No restart, repair, timer activation or log containing customer records was requested.

Core files exist, but `/opt/liveuin/ops_backend/app/` is not readable to this SSH account. The final executing backend assembly and its configured canonical case-store location remain unverified. No process environment or secret registry was read. The case store source is SQLite (`core_case_store.py:12–25,47–55,67–108`), with `core_cases` and `core_case_events`; opening its helper would create/migrate schema, so it was not executed. This is source evidence, not a read of production case rows or a durability/restore test.

The server's case API already contains signed Identity checks (`core_case_api.py:81–95`) and participant authorization helpers. Deployed `core_case_service.py:792–825` reads the case in the requested workspace and grants operational roles (`admin`, `ops`, `ops_manager`, `super_admin`, `support_reviewer`, `trust_reviewer`) access at 811–812; families require bound participant IDs and an `operator` requires assigned-operator binding. Thus a generic staff role in a mixed real/test workspace does not enforce “test cases only”, and the owner's requested refusal of another family's documents needs explicit case assignment/document policy. This is code evidence only; no private case was opened. The source supports preserving signed Identity, but cannot substitute for the five-account test matrix. See `runtime-routing-and-scope-evidence.txt`.

## Domain and Sierra lineage

| Surface | Current nginx evidence | Interpretation |
|---|---|---|
| `api.liveuin.com` | `/etc/nginx/conf.d/api.liveuin.com.conf:84–85` → 9080 | Public API gateway is not the full private Core API inventory. |
| apex and www | `liveuin.com.conf:68–70` marketing API → 9095; `92–94` `/stays/listing_` → 9095; `130` public static root | Real marketing pilot can coexist with a separate public showroom. |
| `host.liveuin.com` | `host.liveuin.com.conf:60–86` marketing APIs, rental offers and listing-publication → 9095; `98` separate Host release root | Preserve real owner publication and inbox rather than replacing it with the public sample app. |
| `app.liveuin.com` | app config has selected production identity locations, general Identity → 9095, public API → 9080 and static `/var/www/liveuin` | Existing identity infrastructure is present; complete family case workflow remains unproven. |
| `ops.liveuin.com` | Ops configuration has auth-gate routes and private backend routes | Browser login lock and public admin API are different boundaries; one cannot prove the other. |

Sierra source: `/Users/Vivian/Documents/Liveuin/deploy/core_marketing_offer_api.py:32–65` distinguishes owner publication, public read, applicant request and private inbox. `/Users/Vivian/Documents/Liveuin/deploy/core_marketing_publication_runtime.py:125–139` binds existing Inventory, Demand, media and signed Identity; 104–110 binds owner actor/workspace; 155–173 checks a separate applicant cookie through signed Identity; 178–184 checks verified email binding. The runtime's local and deployed SHA256 is `0383e287e3e925b1ce8d2366ed348ef29b2ccc8cab6224b1834e9d49803e6026`.

Historical Oct 1 proof is `/Users/Vivian/Documents/Liveuin/outputs/host-marketing-offers-20261001/publication-release-proof.json:2–52`. It records a real owner publication, S$6,400/month, availability 16 September 2027, actual images, anonymous refusals, zero real applications/payments/bookings, and no programme gates closed. Marketing approval review is due 30 December 2026. Oct 2 source is `outputs/host-inventory-link-20261002/checkpoint.json:13–57`: actual inventory link exists, but `needs_review`, `parent_ready=false`, whole-premises hierarchy incomplete, holds/payments disabled, production legal-rule evidence missing, applicant-to-case handoff unimplemented/unproven. The tracker says the same at `docs/LIVEUIN-MODULE-FEATURE-TRACKER.md:7–17` and explicitly refuses a P06 claim at line 11.

Therefore retain Sierra if the live auditor confirms it, label its marketing/request-only state accurately, and do not describe its rent as the platform fee or its future availability as an immediate available room. An authenticated owner success from 2 October is historical evidence, not today's required owner sign-in/denial/sign-out proof.

## GitHub and local source truth

Checked authenticated GitHub API on 19 October; complete default tree responses have `truncated=false`.

| Repository | Default branch result | Last push (UTC) |
|---|---|---|
| `timlavente/liveuin-platform` | main `0edb58d9f8ab111bc71bb99944aea16a87e1d2d9`, one 36-byte README; 74 branches | 13 Oct 09:52:18 |
| `timlavente/liveuin-resident-app` | main `16bafa745c9b6821796a7ed45e742699669f838e`, 959 blobs; React/native projects and marketing build | 18 Oct 14:07:57 |
| `timlavente/liveuin-visual-playground` | main `987579d5b680fc779162799d42b93a16bfba5e0a`, 286 blobs; visual source | 2 Oct 04:56:57 |

`liveuin-platform` has one actual open issue (#93, “P0 external runtime closure: staging, identity, backup and rollback”) and 32 open PRs. Sample non-default branches: `chatgpt/m2-canonical-canary-20261001` (120 blobs), `chatgpt/m2-real-core-integration-20260930` (53), `chatgpt/m2-source-export-20260929` (36), including case source fragments. This does not establish that any branch is a complete deployable Core export.

`/Users/Vivian/Documents/Liveuin` itself is not a Git repository. `www-lovable` is a Git repository with a different configured origin (not one of the named GitHub remotes), HEAD `e389b10a1809df380e181ff91415e7f7ccf075ca`, many working-tree changes and 720 files under src. Preserve those changes. The full local deploy directory includes Core source and safety/runbook machinery. Before implementation, freeze a **specific source-to-live baseline** and scoped file hashes, not a filename count or a blanket “use GitHub main”.

The deployed hashes match local for public_home_service, public_status_service, admin_control_service and core_marketing_publication_runtime. They differ for public_home_gateway, home_api, core_case_api, core_case_store and core_case_service. Full hashes are in the evidence files. This is an explicit downgrade risk for a whole-directory upload.

## Boundary laws and P0–P6 ladder

Read first: `/private/tmp/liveuin-p06-audit-20261019/city-audit.txt`. Also read parent/project AGENTS.md, required README, sitemap, tracker, Laijuzhu blueprint, ecosystem audit twice, IGEMA section 21, persona/entitlement audit and demand lane register. All required local files were fully readable with positive local blocks; no placeholder was treated as empty/corrupt. `local-source-fingerprints.json` records sizes, blocks and hashes.

Exactly one primary planning lane for the request/share part: **Demand Core / LeadPassport** (`docs/LIVEUIN-DEMAND-VIRAL-AI-LANE-REGISTER-2026-06-17.md:28–39,61–77`). No AI implementation/review task is selected; excluded AI features remain excluded.

The actual ladder from `docs/LIVEUIN-SITEMAP-DOMAIN-HANDOFF.md:233–243` is:

| Phase | Existing definition / exit |
|---|---|
| P0 | Basic skeleton; safe public/app/host/ops/partner/vendor/connect starting routes and correct truth ownership. |
| P1 | Understandable funnel; conversion paths and clear calls to action. |
| P2 | Safe editable public CMS/trust/legal/support; API/CMS-backed reviewed, visually checked and promoted public pages. |
| P3 | Coherent member/host/wallet/finance/Pass; persona- and scope-separated dashboards. |
| P4 | Canonical Ops; command, control tower, payments, rollout review, moderation and private role language. |
| P5 | Operational ecosystem split; controlled role-aware partner/vendor/CN/Connect/Pass roots. |
| P6 | Production-serious scale/governance; hardened auth, RBAC, analytics, automation, observability, server evidence and rollout gates. |

The explicit P6 exit at line 231 requires real production auth, RBAC, observability, server routing, TLS, browser smoke, backup/restore, rollout evidence and governance. Line 224 says rendering pages is insufficient. “Promoted” UI routes at 46–56 and 188–198 are historical route evidence, not proof of an operating case desk today.

Promotion arithmetic needs correction in the refinement notes: 20 P2 + 12 P3 + 5 P4 + 9 P5 = **46 distinct routes**; P6 lists two routes already counted under P4, yielding 48 phase-route entries. Thus 9 promoted + 37 not live = 46 unique routes. The heading “48 routes” conflates entries and distinct routes. Do not turn either count into a production completion percentage.

Domain ownership: sitemap 60–77; public www is presentation, app/Host/Partner are scoped private views, Ops is private workflow, Core/Trust/Ops/TrustPay/LiveLedger own durable truth. Laijuzhu blueprint 121–156 and ecosystem audit 38–54, 130–177 confirm Laijuzhu is corridor demand/trust, WeChat identity/OAuth/callback/delivery plus temporary bridge, connector setup/widgets/SSO/handoff, IGEMA assigned fulfilment. IGEMA Rental Operations may be evidence; it must not become this release's canonical Core. No tenancy import/migration is needed or authorized by this audit.

Persona controls: `docs/LIVEUIN-PERSONA-ENTITLEMENT-UI-CONSISTENCY-AUDIT-2026-05-28.md:11–33,35–73,126–147,194–212`. For each frozen screen record persona, surface, identity, workspace role, commercial entitlement, record scope, state lock, prohibited exposure and canonical owner. Parent/family in this release uses app.liveuin.com per the user's explicit scope; historical Laijuzhu Pass presentation is not a reason to expand into that sibling. No connector/shortcode changes are proposed; parity is not applicable to changed output, but any retained launcher must agree on scope and handoff.

Money law: `/Users/Vivian/Documents/igema/IGEMA-Blueprint.md:857–886` requires correct payee/custody, invoice/receipt, milestone agreement for commission, proof-before-operator-payment, refund reason/approver/amount/payee and licensed remittance provider. Section 22, 920–934 requires partner tier approval before case access. The text is an internal boundary law, not independent evidence of legal permission for a particular live merchant charge. Signed price-card discovery and legal/processor research are separate audit workstreams. Do not promote old plan/tier numbers in persona docs to accepted public prices.

## Freeze implications

Keep the owner's queue categories. Within its first “crashes and locks” category, explicitly protect the private admin surface before repairing shared DB access. Require source hashes and rollback evidence for that bounded row. Then separately prove real catalogue/request-to-case, named-account isolation, honest examples/pricing, approved test-and-real-payment sequence, only blocking screens, accepted commercial card, P6 evidence and publish sheet. A full rollback/restore exercise, real owner auth and each test role remain unproven.

The plan must preserve existing source and data; it should not create new Core infrastructure merely to match a missing `core-staging` hostname. A viable production baseline may reuse this runtime, but that decision requires completed source/mount/store/deployment reconciliation and a safe isolated rehearsal. Neither today's server presence nor a July “promoted” label grants public access approval.

Ecosystem boundary checked: audited surfaces are LiveUIN public UI, private app and canonical Core/Trust/Ops services. No sibling theme, bridge or connector was edited or made the product source of truth.
