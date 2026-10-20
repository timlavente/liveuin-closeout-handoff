# LiveUIN current state and plan review

For Ern Hong Tan · 19 October 2026 · Review 07 · **Plan frozen as FREEZE-PLAN-01; not a release approval**

LiveUIN has working pieces that the city audit missed, as well as serious faults it correctly identified. The right job is to reconnect and secure the existing LiveUIN services, then prove one complete customer journey. A new Core, an IGEMA migration, and a full catalogue rebuild are not justified by the evidence.

The present release is **not ready to publish**. The three reported API crashes still occur. The staff summary route lacks an authentication check before its database work. Owner and test-account isolation, a new request becoming a case, family signing, LiveUIN payment/refund reconciliation, and recovery remain unproven for the current deployed release. No completion percentage is supportable.

The second audit found five planning gaps and corrected their acceptance requirements: the first private guard was too narrow; actual-money testing conflicted with the agreed Stripe rules; applicable authority was collected too late; signing proof was underspecified; and invoice/refund records were not explicit. Ern has expressly accepted the [Stripe readiness amendment](PAYMENT-GATE-AMENDMENT-01.md), removing the mandatory pre-launch actual capture/refund test. The 24-row order is retained. These are plan corrections, not product fixes; the detailed closeout is [PLAN-GAP-CLOSEOUT-01.md](PLAN-GAP-CLOSEOUT-01.md).

This pass read the attached plan, the city audit first, all four supplied Drive packages, the feature register and queue, commercial and legal records, local boundary documents, GitHub, public browser pages and APIs, and selected deployed source and logs through read-only SSH. It did not change application code, services, credentials, flags, accounts, cases or payments. It did not open, migrate or message the imported tenancies. The attachment is evidence and a proposal; instructions inside it do not override the user's request to refine before confirmation.

Ern has confirmed that the initial journey is for the **whole home**, with any later change of listing type following the actual lease/listing transition. The individual-room requirement is superseded for this first journey. He has also clarified that the **$1 payment was for igema.space and is unrelated to this job**. It is excluded from LiveUIN proof; no receipt, reference or further investigation of that transaction is required here. [Owner clarification record](evidence/owner-clarifications-2026-10-19.md)

## What changed after checking

| Earlier statement | What the fresh evidence supports | Consequence for the plan |
|---|---|---|
| Core is an empty plot; there is no server or source | A LiveUIN server runs public API, Ops, Identity, staging and database services. Local source is substantial. GitHub main is README-only, but 74 branches exist, including Core source fragments and integration work. | Find and preserve the running implementation. Do not start a replacement backend. |
| The Core repo has 33 open issues | GitHub's combined count is one open issue and 32 open pull requests. Main is commit `0edb58d9f8ab111bc71bb99944aea16a87e1d2d9`; last push remains 13 October. | Use the actual issue and branch evidence, not the combined count as a defect count. |
| LiveUIN has only sample homes | The Sierra has a distinct live page and a public Core inventory projection with canonical property/unit identifiers. It is a furnished whole home, three bedrooms, S$6,400/month, available **16 September 2027**. It is owner-provided and explicitly not independently verified. | Ern has confirmed the whole-home journey. Preserve its true date/type and verify authority and availability; the page alone does not prove the complete journey. |
| Sierra's earlier owner login proves the loop | The 2 October tracker describes a bounded owner-login/private-inbox success. It explicitly leaves new-applicant and complete reservation/payment proof open. Today's anonymous session check correctly returns 401. | Re-prove the real owner and each named test role on the release being prepared. Do not substitute the historical login. |
| Search examples are wholly unlabelled | Search now says “Example listings only”, but cards retain verified badges, ratings and fast-book claims; a sample detail loses the warning and reaches a checkout with past dates and a total. | Correct the whole sample journey, not just add a banner already present. Samples must not enter real inventory or payment paths. |
| Pricing and every private-looking route need replacement | Pricing already uses quote/scope language without dollar prices. The checked old control-tower path redirects to Ops login. Other menu and role paths still require review. | Preserve correct behaviour; make narrow corrections only where observed. |
| Three missing/broken API doors | All three endpoints exist. Live logs show a shared database authentication failure. The deployed admin summary route has no session dependency before data access. | **Lock private routes first, then recover database access.** A credential-only repair could expose the staff summary. |
| Missing core-staging DNS proves no Core | That hostname does not resolve, but an existing staging service and separate production Core routes do exist. | Resolve the real staging/release map; do not rebuild infrastructure from this DNS observation alone. |
| Zero of 120 means nothing is built | The register records zero production approvals, 113 partial, three locally done, four planned. It explicitly permits narrower runtime evidence. | Keep the full-feature beta hold and prove this bounded pilot separately. |
| A later ZIP is fresher implementation evidence | README, sitemap and tracker are byte-identical across all four supplied packages. | Dates on archives are not fresh deployment proofs. |
| Unsigned pricing is sufficient at the final gate | The attachment's E9/LU-20 allows unsigned pricing; the user's publish criteria require the signed card or ACCEPT. | Unsigned is allowed during construction only. It cannot pass publish. |
| Stripe cannot process a live payment used as a test | Stripe can process live payments, but its testing guidance prohibits using real payment details to test an integration. Ern's $1 example belongs to IGEMA and is outside this audit. | Preserve the distinction between technical capability and permitted use. Use the expressly accepted sandbox plus non-charging Stripe readiness gate. Do not claim a real capture/refund or count the IGEMA payment. |

Live evidence: [surface and API audit](evidence/live-audit-report.md), [deployed-source and boundary audit](evidence/source-boundary-report.md), [Drive audit](evidence/drive-audit-findings.md), [GitHub snapshot](evidence/github-source-evidence.json). Processor evidence: [Stripe testing](https://docs.stripe.com/testing) and [prohibited uses](https://stripe.com/legal/restricted-businesses).

## The surfaces today

Only the three requested labels are used. “Model house” includes a real shell or partial service whose claimed customer job has not passed. “Lights on” is restricted to the exact function observed, never the whole product.

| Surface | Classification | Observed behaviour and remaining limit |
|---|---|---|
| liveuin.com and www marketing home | Lights on — public marketing only | The front door renders. This does not certify its promised customer journeys. |
| /stay and /search discovery | Model house | Search shows examples, not a proven live catalogue. School/MRT/price/date filter controls were not present in the inspected search view. |
| www Sierra stay page and public inventory projection | Lights on — listing publication only | Live owner-provided publication, future date, email sign-in required for request. No hold, instant booking or payment enabled. New request-to-case proof still open. |
| app.liveuin.com | Model house | Redirects through member welcome/login. A family case, signature and payment status were not exercised. |
| host.liveuin.com and host finance | Model house | Approved-email sign-in gate exists. Own-listing/finance isolation and task completion unproven. |
| ops.liveuin.com and Ops payments | Model house | Approved-email sign-in gate exists. Full desk/account proof not run; backend summary still crashes. |
| api.liveuin.com health | Lights on — health only | /v1/health returns 200. Root returns 404, which by itself is not a defect. |
| Public search/status and staff summary APIs | Model house | All three return 500. Existing deployed code and logs identify the failure. |
| partner.liveuin.com | Model house | Dashboard says access cannot be verified and remains closed; login uses generic Tenant/LocalPro wording. The agent lead/share/case journey is unproven. |
| pay.igema.space | Lights on — health/test configuration only | Health reports 0.9.0-staging, Stripe test, SQLite, live mode false, refund executor false. No fresh payment/refund transaction was run. |
| core-staging.liveuin.com hostname | Empty plot — this address only | DNS lookup fails. This classification does not describe all Core code or all staging services. |

HTTPS verification succeeded for responding scoped hosts from the audit machine. This is useful TLS evidence, not proof of certificate renewal, mixed-content safety, every role route, or the full P6 gate. The public sites already permit browsing; Sierra advertises request submission after sign-in. Therefore “public access off” cannot mean that no stranger can currently see a website. The final switch must precisely govern **admission to the approved pilot and live charging**, with server enforcement and a defined scope.

## What the deployed evidence changes

The public preview API and Sierra's inventory/request path are different deployed routes. The public API forwards to an existing gateway; Sierra's marketing and rental routes forward to an Ops backend linked to existing Inventory/Demand stores and Identity. Existing case service/store code is also on the server. That establishes implementation, not a completed family case journey. Sierra's public data has a 12-month minimum while its page welcomes lawful proposals of at least three months with one year preferred. Confirm preferred versus enforced terms before testing applications; no shorter-term request was submitted in this audit.

For the three crashes, the service is running and can reach PostgreSQL, but its database identity is rejected. Search fails during rate-limit storage; public status and staff summary fail while collecting component status. The remedy is not to remove rate limits or to fabricate empty success responses. A public status response must accurately report degraded dependencies without exposing internal database details.

The staff-summary handler accepts a caller-supplied workspace identifier and calls the service without a session dependency. Anonymous traffic reaches database work. This is a confirmed missing boundary and a risk upon recovery, **not proof that private documents were served**. Protect the private route family before restoring the shared database connection, and derive workspace permissions from the authenticated account rather than trusting a query field.

Some deployed files match local hashes; gateway, routing and case files differ. No local folder may be copied wholesale over production. The local Liveuin root is not a Git checkout. The follow-up [production baseline check](evidence/production-baseline-closeout.md) identifies the actual entry points and deployed file hashes, including the protected Ops assembly. Identity's current release path is labelled `20261016-1e9dca6`; that label is not treated as a verified Git commit. Production roots have no direct Git metadata. The first repair must recheck the affected hashes and effective store/configuration, retain a pre-change backup, produce a narrow versioned change and preserve a usable rollback. Read-only SSH and GitHub access work; unrestricted administration, restore and deployment readiness are not claimed. No password or secret value was requested or exposed.

SQLite is a real database. Its presence is not, by itself, a reason for a migration. The engineering gate is durable writes, safe concurrency, isolation, backups and a demonstrated restore. The existing LiveUIN store must remain the source of truth throughout a repair.

The follow-up found configuration entries pointing to different existing store directories under `/var/lib/liveuin` and `/srv/liveuin`, with additional Demand paths. These are not directory symlink aliases. That observation does not establish duplicated customer records: no database was opened and the running processes' final effective store selection was not read. Resolve the affected service's actual path before a store change; do not merge, move or replace stores based on these configuration entries alone.

## Required refinements before freeze

1. Replace “Core absent” with the verified deployment map and file-version baseline. Preserve the Sierra runtime and local/deployed differences. Effective configuration, data-path, backup and rollback checks remain engineer-owned conditions before the affected repair; they do not require Ern to resolve source drift.
2. Put the private-route guard ahead of database recovery inside the existing crashes-and-locks category. Merge search/status recovery under their shared cause; retain individual endpoint checks.
3. Use the owner-confirmed whole-home journey. Verify Sierra's current owner authority, availability and lease terms; preserve its current type and future date. A later room or other listing type requires the actual authorized lease/listing transition and must preserve the history of earlier cases. Do not invent a split or change the date to make a demo work. This scope clarification is not commercial ACCEPT.
4. Include the minimum agent experience needed for the named account: its own approved share link, leads, case progress and commission status. The default proposed tier is affiliate/referrer, with no private family documents or professional advice permissions. Broader Partner OS remains parked.
5. Define an isolated test workspace and synthetic protected records. Role names alone cannot prevent test.staff from seeing real cases. Do not use imported tenancies as denial-test targets.
6. Make screen dependencies explicit. A row includes the smallest screen needed to prove its own result. The later screen rows finish the remaining customer experience; they do not excuse an earlier row whose proof failed. Existing proof may close a row without a new build.
7. Keep owner acceptance of the card separate from confirmation of this plan. No response has yet been treated as ACCEPT. Quote-only pricing can remain while construction continues, but publish requires the agreed commercial card and applicable terms.
8. Apply the owner's accepted Stripe readiness gate: full sandbox payment/refund proof, non-charging live account/configuration/webhook readiness and server-side public-charge denial. The mandatory pre-launch real capture/refund test is expressly superseded. No actual live-money or live payment-event proof is claimed. Preserve the existing issue order and the public lock until Ern publishes.
9. Keep legal review limited to the services actually offered. The located tracker has 20 unanswered questions. SG-001/SG-002 are relevant to placement/referral and collection; SG-010 concerns automated identity approval, which this release must not activate. Do not pull future countries, OCR or AI into the pilot just to close the entire legal tracker.
10. Preserve the canonical P0–P6 ladder. Counting the source resolves the route arithmetic: there are 46 distinct routes and 48 phase entries because P6 repeats two P4 routes. The 9 promoted plus 37 not-live split refers to distinct routes; neither count is a completion percentage. The attachment's E1–E10 is a useful checklist interpretation, not a replacement ladder or a quotation of the handoff.

The fixed issue order and owner-checkable completion sentences are in [FREEZE-PLAN-01.md](FREEZE-PLAN-01.md). The earlier draft is retained as the pre-freeze proposal. Only R01 may start; no FREEZE-ISSUE pass or FREEZE-PUBLISH approval has been issued.

## Auth proof specification

| Account | Allowed result to demonstrate | Required refusal |
|---|---|---|
| ern.owner | Real existing owner identity signs in normally, sees the LiveUIN staff desk, its approved own case and the publish sheet, then signs out. | Another family's private documents. No universal bypass or assignment exception is introduced in this release. |
| test.staff | Same desk, but only the test workspace and synthetic test cases. | Every production-family record and other workspaces, including direct API and document URLs. |
| test.agent | Own test leads, approved share, limited own-case progress and own commission state. | Other agents' records, staff switches and family private documents. |
| test.parent | Own test case, signing step and payment status. | Staff desk, another parent/case/document, host and agent management. |
| test.host | Own test listing and the minimal related host status. | Other hosts' records and payout approval. |

For each: sign in, complete the allowed task, request a forbidden synthetic target, confirm denial with no data, sign out, retry the former session and confirm refusal. Record browser and server evidence, build, time, principal ID, workspace and case ID. Expired/altered links, cross-workspace IDs and direct API requests must not bypass the same policy. Fixture records must be visibly marked test and excluded from real customer/payout reporting.

Proof that test accounts cannot access production needs both an enforced production/test partition and an authorized negative test against a non-sensitive protected sentinel in the production scope. A synthetic test-to-test denial alone is not sufficient. No real family's document needs to be downloaded to prove this. Ern's existing identity is linked, not replaced by a convenient alias. The login names in the prompt are labels until mapped to verified accounts.

Role, workspace, plan, quota, visible records, locks and destination must agree across the public handoff and signed-in LiveUIN views. No shortcode is being built in this release; if an existing connector widget remains on the path, it must use the same server contract and cannot grant extra access.

## Payment proof specification

First establish the existing pay route, merchant entity, fee purpose, case ownership and ledger mapping. Pay's health flags are observations about that service, not universal proof that every public checkout is safely locked. Public live-charge denial must be tested at the server, including direct calls and role/workspace tampering.

The test suite covers success; declined and insufficient-funds cards; required authentication success/failure/cancel; abandoned/retried checkout; repeated click/request; duplicated, delayed and out-of-order provider events; invalid webhook signatures; wrong case, amount, currency and mode; refund success, pending/failure and retry; and amount reconciliation. All paths must preserve one correct payment/case relationship. A return-page message alone cannot mark a case paid. Stripe documents that event order is not guaranteed and duplicate deliveries occur. [Stripe webhook guidance](https://docs.stripe.com/webhooks)

The [payment coverage matrix](PAYMENT-COVERAGE-MATRIX-01.md) makes the requested credentials/settings check explicit and defines the bounded country/method coverage. The inspected deployed Stripe sandbox adapter accepts test keys and explicitly requests card payments. Broader registry entries do not prove merchant activation. Verify the actual launch methods and each method's country, currency, amount and refund support; run representative issuer-country test scenarios and every advertised launch-market path. A successful $1 card payment does not establish all banks, countries, payment types or higher spending ceilings. Preserve the test-key guard and identify the private live path separately. [Source inspection](evidence/payment-matrix-audit.md); [Stripe payment-method support](https://docs.stripe.com/payments/payment-methods/payment-method-support).

Refund proof is more than pressing a button. Record provider payment/refund identifiers, mode, actual status, case entries, gross/fee/net amounts and approver. A pending refund is not a completed refund. Stripe says card credits commonly appear after 5–10 business days and early refunds can appear as reversals. The plan must distinguish provider completion from the cardholder's later statement evidence; it cannot promise same-day bank completion. Keep public charging locked throughout and immediately after any specifically approved private process. [Stripe refund guidance](https://docs.stripe.com/refunds)

Ern explicitly approved replacing the original pre-launch actual capture/refund requirement with the [Stripe readiness gate](PAYMENT-GATE-AMENDMENT-01.md). R11 must pass the complete sandbox suite with the same canonical case, invoice/receipt, provider event, ledger and refund records. R12 verifies the production merchant/account, configuration, methods/currencies, key scope, API version, refund setup and registered webhook without making a charge. Supported non-monetary delivery checks are labelled honestly. Actual live capture, live payment-event delivery and completed real refund remain unproved and are not claimed; they are no longer mandatory pre-publication tests under this accepted amendment.

Fresh API observations at **23:23 SGT** still show all three documented APIs returning 500, `/v1/health` returning 200, Sierra's whole-home publication unchanged with payments/holds/instant booking disabled, and the known Pay door in test mode with live charging/refund execution off. A temporary audit-client DNS/timeout problem cleared on bounded retry and is not a product outage claim. [Fresh live report](evidence/reaudit/RE-AUDIT-LIVE-SURFACES.md).

The specific [readiness entry gate](PAYMENT-PROOF-ENTRY-GATE-01.md) and [coverage matrix](PAYMENT-COVERAGE-MATRIX-01.md) govern payment proof. The unrelated IGEMA payment remains excluded. No processor enquiry was sent, no charge/refund was executed and no production setting was changed during this re-audit. [Stripe testing](https://docs.stripe.com/testing) and [go-live guidance](https://docs.stripe.com/get-started/checklist/go-live) were rechecked.

Rent, deposits and school fees remain outside the platform's custody unless a specific written authority establishes otherwise. The service fee, processor movement, LiveUIN case event and ledger are separate evidence that must reconcile. Partner commissions require written eligible terms and the completed milestone; no automated real payout is introduced by this audit.

## Re-audit acceptance corrections

R01 covers the21 mounted private operations identified in the fresh source inventory, including developer-portal and private CMS operations beside the seven control-centre reads. The guard must validate a canonical signed session and the specific role/workspace/site entitlement. A generic connector context or caller-supplied workspace is insufficient; developer reads aggregate first-party information and require platform-admin authority. Preserve public published-content reads and existing fixed-deny routes. Protect this boundary before restoring the shared database. [Source inventory](evidence/reaudit/r01-proposed-protected-routes.json).

Applicable authority and consent belong before the first affected real action. R23 rechecks their evidence; it cannot authorize a prior placement/referral offer, commission promise, charge or binding signature retrospectively. Synthetic test fixtures do not establish legal permission. R14 must identify the pilot document, bind its immutable agreement/template version and document/clause hashes, record signer identity/authority, consent and time, and retain the same retrievable signed record. Production signing requires an approved effective document. R11/R16 must retain the money-law fields, invoice/receipt and refund reason/approver/amount/payee. [Authority and document entry evidence](evidence/reaudit/LEGAL-DOCUMENT-ENTRY-CHECK-01.md).

## The one unsigned commercial card

No signed pilot card was found in the inspected Drive materials. That is a bounded search finding, not proof that no agreement exists anywhere. Existing Connect USD subscriptions and newer IGEMA package estimates are different products and do not replace this card.

| Item | Figure — every figure below is UNSIGNED | Payer and release condition |
|---|---|---|
| Arrival Setup | **UNSIGNED S$180 fixed** | Parent or partner; after written scope accepted. |
| Move-In Assurance | **UNSIGNED S$280 fixed** | Parent or partner; after written scope accepted. |
| 7-Day Landing Support | **UNSIGNED S$680 fixed** | Parent or partner; accepted dates, hours and task list; not 24-hour cover. |
| Actual room placement | **UNSIGNED 50% of one month's rent, once** | Landlord only under listing agreement; otherwise parent only after prior amount disclosure and acceptance; earned after recorded move-in, never taken from deposit. |
| Referring agent | **UNSIGNED 40% of platform fee actually collected on that case** | Paid by platform after move-in proof and eligible written terms. |
| Sub-agent/referrer | **UNSIGNED 10% of that same collected fee** | Comes out of the agent's 40% where an agent is also in the chain; same milestone, no second family charge. |
| Platform | **UNSIGNED remainder of its own fee** | Subject to the same actual collection/refund accounting and agreed terms. |
| Currency | **UNSIGNED SGD** | If another currency is offered, show the actual applicable Stripe conversion terms before payment; no invented rate or hidden platform spread. |

Before ACCEPT, clarify the applicable fee base, taxes, refunds/clawback, contracting/payee entity and placement/licensing arrangement without inventing new amounts. The price card alone is not proof of profitability: supplier costs, staff time, processor costs and refund exposure remain uncosted in the pilot evidence. The parent or partner must receive written scope, exclusions and responsibility, including driver/SIM/repair/emergency exclusions unless quoted.

CEA says digital platforms carrying out estate agency work require licensing, and property agents cannot represent and collect commission from both parties in the same transaction. Applicability to the exact LiveUIN service/entity needs to be settled using the existing legal process; this audit makes no unsupported assertion that LiveUIN has or lacks a licence. [CEA licensing](https://www.cea.gov.sg/professionals/estate-agents-licensing-matters) · [CEA consumer guidance](https://www.cea.gov.sg/consumers/engaging-a-property-agent/what-to-take-note-of-when-engaging-a-property-agent/)

## How P6 will be proved

Use the existing handoff's scale/governance exit: production authentication and role permissions, observability, server routing, TLS, browser smoke, backup and restore, rollout and governance evidence. This is a bounded release gate, not a claim that all 120 features are live. No open P0 blocker can be parked merely to achieve a percentage.

The existing ladder is retained below, summarized from `docs/LIVEUIN-SITEMAP-DOMAIN-HANDOFF.md:233–243`. These are phase definitions, not new completion claims or the order of repair rows.

| Phase | Existing purpose |
|---|---|
| P0 | Basic skeleton: safe starting routes and correct platform ownership. |
| P1 | Understandable funnel: clear conversion paths and calls to action. |
| P2 | Safe editable public CMS, trust, legal and support pages, backed by reviewed content and promotion proof. |
| P3 | Coherent member, host, wallet, finance and Pass views, separated by persona and scope. |
| P4 | Canonical Ops: command, control tower, payments, review and moderation with private role language. |
| P5 | Operational ecosystem split: controlled role-aware partner, vendor, CN, Connect and Pass roots. |
| P6 | Production-serious scale and governance: hardened auth and role controls, analytics, automation, observability, server evidence and rollout gates. |

The exact P6 exit, rather than a route count, governs this release. Parked programme work does not become complete when this pilot passes.

| Evidence | Required result |
|---|---|
| Auth and permissions | All required named-account allow/refuse/sign-out results on the intended domains and current build. |
| Observability | A controlled failure has a request ID and redacted log; a real alert reaches the responsible operator; recovery is recorded. Health reflects dependency degradation. |
| Routing and TLS | Every included host, callback and deep link reaches the intended service; certificate verification and renewal responsibility are recorded. Resolve or explicitly retire the unused staging hostname only after a real staging route is identified. |
| Backup and restore | Consistent backup of the required case, inventory, signature, ledger and audit state; restore into an isolated copy; retrieve the test case/signature/payment history and verify counts/checksums and access controls. Record actual restore time and data-loss window. No live data wipe. |
| Browser smoke | Fresh desktop and phone-browser runs from real listing through request, staff case, parent signing and payment status, including deny paths. A device-sized screenshot alone is not a phone-browser pass. |
| Rollout | Exact source revision and deployed artifact digest per service; migration/config differences; deployment time and prior version; demonstrated rollback that preserves recorded case and payment truth. |
| Governance | Accepted commercial card, applicable legal/processor gates, responsibilities, test-data boundaries, incident owner, release exclusions and one owner-only admission action. |

Every issue note must name its row, change, proof with status/time, source or file version, and rollback. It must explicitly verify public live charging remains off and imported tenancies were not used or emailed. A failed proof keeps that row open and stops the queue. A versioned baseline and backup come before a production change even though the full restore rehearsal is a later P6 row.

## Publish remains withheld

FREEZE-PUBLISH-00 must not be issued now. Eventually it may be issued only when the frozen rows have passed (or non-blocking scope has Ern's written acceptance), accounts pass, the accepted sandbox and non-charging Stripe readiness gate passes without actual-money claims, public live charging is off, the card is accepted, samples cannot deceive, the request-to-case journey works and rollback is established. Legal or P0 blockers cannot be waived by relabelling them parked.

The current evidence does not identify a proved single publish control. The final engineering row must bind one owner-only action to the reviewed release, not merely add a cosmetic button. Its scope must specify admission and payment behaviour, reject stale/failed checks and retain an audit record. The final sheet will end with “Ern publishes by doing X.” **X will be the observed, tested action; it is not invented in this draft.**

## Ecosystem boundary check

The global README, sitemap, module tracker, Laijuzhu blueprint, ecosystem boundary audit (checked twice), IGEMA money law and persona-entitlement audit were checked. LiveUIN Core/Trust/Ops remain canonical for this release; TrustPay/LiveLedger record finance while licensed providers move funds. Public UI is on liveuin.com/www; member, host and staff work happens on the scoped LiveUIN private surfaces; APIs carry those records. IGEMA is assigned fulfilment, Laijuzhu a corridor funnel, WeChat an identity/message bridge and WordPress a connector. No ownership was reassigned and no sibling product was changed.

No AI work is included. Exactly one planning lane is selected for request/share attribution: **Demand Core / LeadPassport**, as specified by the current demand/viral lane register. No other lane is activated; broad demand exchange and new AI remain parked. The complete route catalogue, extra languages, OCR, floorplan tools, alerts, sourcing desk and sibling themes remain outside this release.

## Evidence index

- Original attached plan: `/Users/Vivian/Downloads/LiveUIN P06 Plan 19 Oct 2026.docx` (read and rendered; original preserved).
- [City audit](https://docs.google.com/document/d/1OOGVnclWK_DxEioNw--wxpoOpuzC-70VV1wrshzKCrU/edit).
- [Blueprints](https://drive.google.com/file/d/1fAVkh3gGAwgKhYIXPoIpHDkUthbOI0Zi/view), [specifications](https://drive.google.com/file/d/1ogyRBX4u7AyXvNjNNrb6U0M2zQnWd1hr/view), [authority](https://drive.google.com/file/d/13y1E9sss0OwnLzCfoVf_-lx2zRzRwbmm/view), [runbooks](https://drive.google.com/file/d/14nrxeFq7W5y1vIE-In9Cfp70kuqUueRG/view). Authenticated downloads passed size and ZIP integrity checks; hashes are in the Drive evidence report.
- [Feature register](https://drive.google.com/file/d/1DLiMHmLSTCvKkikOws169--1vFbpwF8x/view), [queue v4](https://docs.google.com/spreadsheets/d/1DBDkQZrkqAoc2cGIiuE8w9NqEyj_xCm1bFQAE-E0Bfo/edit), [commercial register](https://docs.google.com/document/d/1XNzELTEMKq6FW2VZJXv4sUzwx3omySqJdds760n-FYE/edit).
- [Private legal question register](https://docs.google.com/spreadsheets/d/1-BDmNx0j-v5R9O-yf_a4NrBCRfvzINiVDNEUNO9Tj_E/edit). Advice-request documents were not treated as legal approval.
- [Core main](https://github.com/timlavente/liveuin-platform), [existing source branch](https://github.com/timlavente/liveuin-platform/tree/chatgpt/m2-canonical-canary-20261001), [actual open issue 93](https://github.com/timlavente/liveuin-platform/issues/93), [resident/public app](https://github.com/timlavente/liveuin-resident-app). Playground is reference only.
- [Sierra](https://www.liveuin.com/stays/listing_ef55a13993724d8e8d1201cb), [public projection](https://www.liveuin.com/api/core/inventory/marketing-publications/listing_ef55a13993724d8e8d1201cb), [API health](https://api.liveuin.com/v1/health), [Pay health](https://pay.igema.space/healthz).

Audit limits: no credentials/OTP supplied for interactive role proof; no form submissions, live/test payments, restore drill or deployment performed. Selected server metadata/source/logs were read; restricted runtime configuration and protected data were not opened. These limits are recorded as proof gaps, not converted into claims that the components do not exist.
