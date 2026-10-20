# LiveUIN live audit — 19 October 2026, Singapore

Status: research evidence for a draft plan, not FREEZE-PLAN-01 and not a launch approval.

The City Audit was read first. The checks below used fresh unauthenticated HTTP requests, a browser, and fresh Firecrawl page reads. No account was created, no sign-in code requested, no form submitted, no booking completed, no payment made, and no switch changed. No imported tenancy or private family document was opened or emailed.

## The important correction

There is a working owner-provided Sierra publication on the exact address supplied. A live Core-named inventory route returns that publication and canonical unit/property identifiers. Its request form has an email-verification gate. This contradicts the City Audit's broad conclusion that all of LiveUIN is sample inventory and that no Core service exists anywhere. It does **not** prove request-to-case, staff operations, production identity, family signing, or ledger completion.

The public search and this publication are different paths. Search still shows example homes. The Sierra is not among the six cards shown by the unfiltered public search page. Preserve the published Sierra and trace the service already serving it before proposing a replacement backend or a second truth store.

## Live surface classification

These labels apply to the capability named in each row. A working login gate does not certify the desk behind it.

| Surface / capability | Label | What the live check actually established |
|---|---|---|
| `https://liveuin.com/` and `https://www.liveuin.com/` public marketing | Lights on | Both return 200 and render the Stay/Grow/Earn front door. They are public marketing pages. Header/footer observed no Ops, payment-review, private-case, or finance-desk links. This is not proof every public route is clean. |
| `https://liveuin.com/search` discovery | Model house | 200; explicitly says “Example listings only”; six sample cards still carry verification/booking badges and review counts. No school, MRT, price, date, map, sort or query input appeared in the rendered page. Sierra is not a displayed card. |
| `https://liveuin.com/stay` promised living journey | Model house | 200; promises search by city, school, commute, budget and stay type, and a continuous booking/payment/move-in journey. This exceeds what the observed search delivers. |
| The Sierra publication at the supplied `www` URL | Lights on | A published owner-provided whole-home listing can be read: S$6,400/month, three bedrooms, two bathrooms, available **16 September 2027**. The page says it is not independently verified. This label covers the public publication only. |
| Sierra request-to-case completion | Model house | Form exists, requires email verification, says no charge and no reservation. Submission, durable case creation, staff visibility and owner processing were not exercised. Do not call this missing or complete yet. |
| `https://app.liveuin.com` family/member product | Model house | HTTP sends the visitor to `/app/member`; browser then reaches a welcome page for member with tenant-home return path. Its sign-in page says “One login for Tenant and LocalPro”. No family case or signing workflow was proven. |
| Host approved-email sign-in gate | Lights on | `https://host.liveuin.com` routes through `/host/onboarding` to a Host-specific approved-email verification screen. No code requested. |
| Host finance product | Model house | `https://host.liveuin.com/host/finance` requires Host login. The old `https://app.liveuin.com/host/finance` hands off to the Host domain. Records, entitlements and finance operations behind the gate remain unproven. |
| Ops sign-in gate | Lights on | `https://ops.liveuin.com` reaches `/ops/login`; approved Ops email, challenge ID and one-time code fields are shown. It states role choice does not grant access. No code requested. |
| Ops desk/control tower/payments | Model house | `/ops/payments` returns to Ops login with its destination preserved. The old public `/ops/control-tower` also hands off to Ops login. No staff case, today list, audit event or payment review was proven. The separately documented control-center API still crashes. |
| Partner/agent entry and product | Model house | Root redirects to `/partner/dashboard`, whose fresh rendered read says access could not be verified and remains closed. Its offered sign-in link leads to a generic Tenant/LocalPro password/Google login. Own leads, share link, case progress, commission status and record isolation remain unproven. |
| Public API health | Lights on | `https://api.liveuin.com/v1/health` returns 200 with `liveuin-public-home-v4`. API root returns 404, which is not a service-outage finding. |
| Public search/status and admin control API | Model house | Three documented operations return 500. Health success does not override these failed operations. |
| Pay health/test-mode guard | Lights on | `https://pay.igema.space/healthz` returns 200, test keys, live disabled, refund executor disabled, SQLite healthy, schema 18. This proves the published health state only. |
| Payment + refund + case ledger journey | Model house | No payment or refund was executed. The refund executor reports off. Test success, controlled real-money test and reconciled case ledger all remain unproven. |
| `https://core-staging.liveuin.com` hostname | Empty plot | Does not resolve from this client. This finding is limited to that hostname; it cannot establish that Core is absent on other routes/servers. |

Partner was included in a narrow follow-up because the draft release requires the minimum `test.agent` journey. Only its root, observed dashboard handoff and offered login link were read. The public Partner explainer is not proof of an agent workspace.

## HTTP and API evidence

| Method and URL | Result | Saved raw evidence |
|---|---:|---|
| GET `https://api.liveuin.com/v1/health` | 200 | `live-09.body`, `.headers`, `.meta.json` |
| GET `https://api.liveuin.com/openapi.json` | 200, 69 paths | `live-10.body` |
| GET `https://api.liveuin.com/api/public/status` | 500, Internal Server Error | `live-api-0.*` |
| GET `https://api.liveuin.com/api/public/status?workspace_id=liveuin` | 500, Internal Server Error | `live-api-status-liveuin.*` |
| POST `https://api.liveuin.com/api/public/search`, body `{}` | 500, Internal Server Error | `live-api-2.*` |
| GET `https://api.liveuin.com/api/core/admin/control-center`, no credentials | 500, Internal Server Error | `live-api-1.*` |
| GET `https://api.liveuin.com/api/public/listings` | 200, six entries marked `Public preview` | `live-api-3.*` |
| GET `https://www.liveuin.com/api/core/inventory/marketing-publications/listing_ef55a13993724d8e8d1201cb` | 200, publication version 1, accepting offers | `live-sierra-publication.*` |
| GET `https://www.liveuin.com/api/core/demand/rental-auth/session`, no credentials | 401, `rental_sign_in_required` | `live-sierra-auth.*` |
| GET `https://pay.igema.space/healthz` | 200, live and refunds disabled | `live-11.*` |

The one POST was the OpenAPI-described **Public Search** operation, with the documented default empty-object payload. It did not submit a request, lead, account or payment. No mutation endpoint was called. The OpenAPI advertises `laijuzhu` as the default workspace for status and control-center. The explicit public-status query for `liveuin` also failed. Before fixing, the implementation audit should establish the intended workspace routing, rather than taking the schema default as a product-boundary decision.

The public inventory API's six previews differ from the six public search cards. This is another reason not to assume a page and an API are using the same inventory merely because both are on LiveUIN domains.

## Sierra details worth preserving and reconciling

Sources: [live publication](https://www.liveuin.com/stays/listing_ef55a13993724d8e8d1201cb) and [public publication JSON](https://www.liveuin.com/api/core/inventory/marketing-publications/listing_ef55a13993724d8e8d1201cb).

- Owner-provided photos from a video tour; explicit “not independently verified” label.
- S$6,400 is monthly rent, not the platform service fee.
- Availability is 16 September **2027**, not immediate October 2026 inventory.
- Whole premises, three bedrooms, two bathrooms. Do not silently reclassify it as an individually rentable room.
- Public JSON: `state=accepting_offers`, `offer_submission_enabled=true`, `instant_booking_enabled=false`, `payment_enabled=false`, `hold_enabled=false`, `independently_verified=false`.
- Public JSON includes canonical property and unit IDs, which is evidence of a canonical inventory reference, not independently verified persistence or ownership.
- JSON says `minimum_lease_months=12`; the visible page says one year is preferred, other lawful proposals welcome, and “at least three consecutive months”. This is a **preferred-versus-enforced term uncertainty**, not a proved rejection bug or a conclusion about legal permission. Confirm which value controls submitted offers and how the owner may accept alternative terms before freezing the request-row acceptance criteria. No shorter-term request was submitted.
- The public JavaScript bundle, downloaded from the exact asset linked by the page, refers to same-origin rental-auth, rental-self, rental-offers, and owner review routes. It refers to a lead passport ID. These are implementation clues; they do not prove a signed family case or complete downstream workflow.

Evidence: `live-sierra-scrape.md`, `live-sierra-publication.body`, `live-sierra-api-summary.json`, `live-sierra-bundle-endpoints.txt`, `live-sierra.jpg`. The live bundle is `https://www.liveuin.com/__liveuin_marketing__/design-v3/assets/marketing-DORh8JK3.js`; a default Python fetch was refused with 403, ordinary curl fetched 200. Nothing was bypassed or authenticated.

## Public honesty findings

The example warning is present on [search](https://liveuin.com/search), so the plan should not state that the page has no example label. The incomplete part is the rest of the journey:

1. Sample cards still show `VERIFIED OPERATOR`, `VERIFIED LANDLORD`, `FAST BOOK`, and specific review counts.
2. [Cozy Studio detail](https://liveuin.com/stays/cozy-studio-orchard) loses the example warning and offers “Continue to checkout”.
3. [Its checkout](https://liveuin.com/checkout/cozy-studio-orchard) shows populated contact fields, card/PayPal/Apple Pay choices, dates in July 2026, and “Complete booking $791.17”. It also says no payment is collected at this step and that it only stores booking state. No completion control was pressed. The public display is still liable to make an example look actionable.
4. The current [pricing page](https://liveuin.com/pricing) is already scope-first and contains no dollar package amounts in the fresh read. Preserve that behavior until an approved price card exists. Do not list “remove public package dollars” as an observed defect without another cited page.
5. Public header/footer on the inspected pages showed public product explainers and general links, not private finance/case/Ops menus. The old control-tower URL now transfers to a private-domain login. Broader route exposure still needs its own inventory and access test; it is not proven clean site-wide.

Evidence: `live-search-ax.txt`, `live-search-scrape.md`, `live-search.jpg`, `live-sample-detail-ax.txt`, `live-sample-checkout-ax.txt` (name and phone redacted), `live-pricing-scrape.md`, `live-control-tower-lock-ax.txt`.

## Conflicts to amend before freeze

| Earlier statement | Current evidence | Plan correction |
|---|---|---|
| All LiveUIN homes are examples | Search is examples, but the exact Sierra publication and its public Core-named projection work | Separate brochure/sample discovery from the owner-provided Sierra publication; preserve the real publication while proving its case path |
| Core does not exist | Staging hostname fails, but the `www` Core-named inventory and rental-auth routes answer | Find the deployed runtime/source/database behind these routes; do not infer global absence or build a second truth store |
| Public control-tower URL merely exposes a shell | It now transfers to Ops sign-in | Keep this existing handoff; test the protected desk and backend separately |
| Member/host screens merely answer with shells | Browser execution produces distinct welcome and Host verification gates | Record working gate behavior while withholding role/session/data-isolation approval |
| Search lacks example labelling | Page-wide example warning exists; detail/checkout and badges still mislead | Fix the complete sample journey, not just add another banner |
| Public pricing needs dollar amounts removed | Inspected pricing has no dollar amounts | Preserve quote/scope-only state; verify signed card and controlled publication later |
| Healthy API means product works | Health 200 coexists with three 500 responses | Keep the three crash rows first in the prescribed order |
| Test branch proves payments | Health still reports refunds off, live off | Require actual test and controlled live/refund/case reconciliation evidence |

## Transport and routing facts

All scoped answering hosts verified using the host trust store and negotiated TLS 1.3. No certificate warning was bypassed. HTTP redirects to HTTPS were checked for apex, www, app, host, ops, API and Pay. See `live-tls-dns.json` and `live-http-redirect-summary.json`.

- Apex and www resolve through Cloudflare; their certificate expires 24 November 2026.
- App, Host, Ops and API resolve to the same public IP in this check. Their separate certificates expire 28 November, 28 November, 21 December and 26 November 2026 respectively.
- Pay resolves to a different public IP; its certificate expires 6 January 2027.
- Sierra returns a separate 638-byte HTML entry document with an October 2 last-modified value. Most public/member/host entries return the 2,284-byte application shell. Public headers label both the generic page and the Core-named projection `public_static_site`, which is not sufficient to identify the underlying system of record.
- Public root, app, host and Sierra responses have security headers, but a TLS pass is only one P6 check. Backup restoration, log access, release rollback, monitoring alerts, authorization and end-to-end browser smoke remain unproven.

## Limits and consequences for the draft plan

No owner or named test account has passed sign-in → correct screen → refused wrong screen → sign-out. The existence of gates cannot satisfy that table. No request became a case in this audit; no family signed; no live or test card was used; no refund or ledger reconciliation passed. No backup or rollback was attempted. Public health reports live charging locked, and Sierra reports payment disabled; this does not independently prove every possible payment entry is locked.

The next plan revision should preserve proven gates and Sierra, list the three API crashes as reproduced defects, and turn untested downstream work into explicit proof rows rather than asserting it is absent. The runtime/source/deployment map behind the working Sierra projection is required to scope fixes safely before implementation. Demand/LeadPassport ownership and lane selection must be checked against the global register before any implementation in that path.

This audit touched public UI, private-app entry gates, public API projections and the existing payment edge's health endpoint only. It did not change canonical ownership, Laijuzhu, PrimeStay, IGEMA themes, imported tenancies, or public access. Global ecosystem boundaries must be reconciled by the main audit against the required platform and sibling documents; live endpoint names alone do not establish ownership law.

No P6, disruption-ready, public-ready or freeze-complete claim is supported by this read-only pass.

## Conditional Partner follow-up

Sources: [Partner entry](https://partner.liveuin.com), its observed [dashboard handoff](https://partner.liveuin.com/partner/dashboard), and offered [sign-in link](https://partner.liveuin.com/login).

Fresh HTTP reads show both HTTP and HTTPS roots redirecting to `https://partner.liveuin.com/partner/dashboard`, which returns 200. The rendered response is not a usable dashboard: “We couldn’t verify your access” and “This area stays closed until access can be confirmed.” It offers “Open LiveUIN sign-in”. No private lead/case data was shown.

The linked login returns 200 and presents email/password, Google sign-in, approved-account copy and “One login for Tenant and LocalPro.” It does not present an agent-specific explanation in this read. This supports a login/route clarity issue to examine during the frozen auth row; it does not prove that a named agent account will fail, or that a real signed-in session existed in the unauthenticated fetch.

Classification: **Model house** for the Partner/agent journey. The closed access state is visible, but sign-in, own lead/share/case/payout access, denial of other agents and staff switches, and sign-out have not been tested. No identity input, OTP request or form submission occurred.

TLS 1.3 verifies for `partner.liveuin.com`, certificate expiry **5 December 2026**. It resolves to the same public IP observed for App/Host/Ops/API. HTTP root redirects into HTTPS. These are transport facts, not permission proof.

The earlier in-app browser was unavailable during this follow-up. Fresh Firecrawl rendering (`maxAge=0`) and direct HTTP/TLS checks provided the evidence; no independent CUA browser result is claimed for Partner. Evidence: `live-partner-http-summary.json`, `live-partner-tls-dns.json`, `live-partner-0.headers`, `live-partner-1.headers`, `live-partner-scrape.json`, `live-partner-login-scrape.json`.
