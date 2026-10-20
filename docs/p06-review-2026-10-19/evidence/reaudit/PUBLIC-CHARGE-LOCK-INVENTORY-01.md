# PUBLIC-CHARGE-LOCK-INVENTORY-01

Read-only evidence, 19 October 2026, Singapore time. Source capture 23:34:17; routing 23:37:10; public probes 23:37:59–23:39:02; configuration classification 23:40:46. This is a bounded inventory for the R01 freeze, not payment acceptance or a publish approval.

**Result: no reachable live-charge operation was established in the inspected LiveUIN paths. The universal statement “public live charging is off” remains UNPROVED.** Pay health and Sierra supply positive evidence for their own doors. Core's concrete Stripe adapter is test-only in the deployed source. A separate live-capable legacy Connect checkout implementation exists, but the inspected public-domain routing does not map its exact route to that implementation. Effective running Core/Connect mode flags were not obtainable from anonymous status or the normally readable configuration sources. Defaults and a GET result are not substitutes for that missing evidence.

The owner’s latest accepted Stripe readiness gate applies: this investigation creates no real payment and does not require a real charge or refund. Nothing here reinstates that superseded requirement.

## Payment entry inventory

| Entry / route | What the deployed code does | Guard / live-mode finding | Evidence and limit |
| --- | --- | --- | --- |
| Sierra public publication, `/api/core/inventory/marketing-publications/listing_ef55a13993724d8e8d1201cb` | Publishes the real listing projection and permitted actions. | Latest public response says `payment_enabled=false`, `hold_enabled=false`, `instant_booking_enabled=false`; offers remain enabled. Runtime source also sets the public payment flag false. | Latest 23:23 public re-audit plus `core_marketing_publication_runtime.py:204`. This is a listing-specific signal, not a platform-wide payment lock. |
| Public example checkout, `/checkout/cozy-studio-orchard` | Earlier browser evidence showed an example checkout and “no payment collected” wording. The apex/www `/checkout/*` route proxies to the preview UI on 9081. | The deployed preview server rejects POST paths beginning `/checkout/` before dispatch because its POST allowlist includes API/Connect prefixes only. | `public-home-preview.py:11267–11273`; nginx apex configuration line318. This is server-route evidence. The complete deployed browser JS network behavior was not re-proven in this inventory, and example-page honesty remains a separate issue. |
| `POST /api/core/payments/bills` and `POST /api/core/payments/intents` | Create canonical bill/intent records and case events. The generic intent method does not itself make an external provider charge request. | Both are behind `access_gateway.guarded_mutation`. The intent may resolve a selected rail; live rail readiness depends on separate nonsecret flags. | `core_payment_api.py:290–341`, `core_payment_service.py:2278` onwards. Ops `/api/*` maps to9095. No bill or intent was created. The source guard is not the required role test. |
| `POST /api/core/payments/intents/{intent_id}/stripe/sandbox-payment-intent` | Calls Stripe to create a sandbox PaymentIntent for an existing Core intent. | Guarded mutation; service requires provider `stripe` and `validation_environment=sandbox`. Adapter accepts a credential only when it begins `sk_test_`; otherwise it returns503 before provider access. | `core_payment_api.py:362`, `core_payment_service.py:2818–2840`, `core_stripe_sandbox_api.py:18–30,45–75`. No key was read and no provider call was made. Concrete test-only adapter behavior is established from deployed source, not a successful payment test. |
| `POST /api/core/booking/bookings/{booking_id}/deposit` | Records a deposit-intent state, amount, supplied provider reference, and case timeline. | Guarded mutation. Reviewed implementation writes records; it does not make a provider charge. | `core_booking_api.py:125–140`, `core_booking_service.py:625–692`. Its existence does not authorize platform custody of rent/deposit. No booking/customer store was opened. |
| Payment provider webhooks, provider-event, refund request/transition | Receive evidence or change Core payment/refund state. | They are not alternate card checkout creation operations in the reviewed source. Provider webhooks have transport verification; Core state mutations use guarded paths. | Deployed `core_payment_api.py`, `core_payment_provider_edge.py`, route inventory. No webhook, event or refund was submitted. Full refund execution proof belongs to the payment row. |
| Legacy `POST /connect/checkout/sessions` | Creates a Connect subscription checkout using configured `stripe`, `hitpay` or `airwallex`, or returns a sandbox/reference result. | Static function validates public input, not a staff session. Stripe function does not reject live keys; it labels test/live after provider response. **However**, this exact route is not proxied to legacy Ops by the six inspected vhost files and relevant snippets. | `app.py:5916,6014–6065,6145–6387,6661`; nginx evidence and seven public GET probes. GET returned SPA HTML200 on apex/www/app/host/ops/partner and API404; none returned method405 from this FastAPI route. This supports “not exposed by inspected routing”; it does not prove a POST denial or establish the internal provider setting. No checkout created. |
| Public Pass gateway | Exposes read-only Pass projections on public API. | Mounted router explicitly has no mutation routes; payment arrays in its public projection are empty. | `public_pass_gateway.py:358–359,566–609`. No real case/Pass URL opened. |
| `https://pay.igema.space/healthz` | Reports the separate current Pay branch status. | Latest public health: Stripe `test`, `live_enabled=false`, `refund_executor_enabled=false`, version `0.9.0-staging`. | `pay-health-retry.body.json`, captured23:23. The LiveUIN-to-Pay creation-route mapping was not established by this finite source inventory. Health does not prove every payment route is gated. No IGEMA transactions inspected. |

## Mode evidence and the remaining uncertainty

| Control | Established fact | Not established |
| --- | --- | --- |
| Pay live switch | Public health reports false. | Whole payment-router enforcement; any different branch or external checkout path. |
| Sierra payment switch | Public projection reports false. | Other listings/cases/payment routes. |
| Core concrete Stripe adapter | Source is sandbox-only and refuses non-test credentials. | Credential presence, successful test payments, deployed in-memory function identity. |
| Core live-rail readiness | Source reads `LIVEUIN_STRIPE_LIVE_VALIDATION_READY`, `LIVEUIN_HITPAY_LIVE_VALIDATION_READY`, `LIVEUIN_WECHAT_PAY_LIVE_VALIDATION_READY`, and `LIVEUIN_SALTEDGE_PAYMENT_INITIATION_APPROVED`. Absent values default false. These choose a rail; they do not themselves execute a charge. | Effective running booleans. Anonymous Ops `/api/core/payments/rails` and `/status` both correctly returned401 `identity_session_required`; API `/api/core/payments/rails` returned404. No authenticated read attempted. |
| Connect mode | Source selects provider via `LIVEUIN_CONNECT_BILLING_PROVIDER`; sandbox flag influences its default and fallback. An explicit external provider can still dispatch. | Effective configured provider/sandbox/strict modes. Sandbox flag alone would not prove all external dispatch off. |

A targeted, read-only configuration pass classified only an allowlist of nonsecret mode names. It found no matching assignments in the normally readable unit/drop-in files. The Ops `90-listing-media-engine-rc3-dark-runtime.conf`, its referenced production environment file, and the preview identity environment file were permission-denied. The report therefore does **not** turn “no assignment observed” into “false”. No process environment, credential contents, keys, customer database or application imports were used. Source configuration also cannot by itself prove the running process inherited the same values.

Ops process was active, PID1298408, started16 October23:24:39SGT. Preview UI was active, PID1041, started12 September11:53:01SGT. These facts bind the inventory to the observed services, but do not prove the loaded module bytes or effective mode values. No restart/reload was performed.

## R01 consequence

The honest freeze wording at this point is: **“The checked Pay and Sierra doors remain off, and no live-charge operation was exercised. Platform-wide public live-charge-off enforcement remains unproved.”** Do not replace it with an unconditional off/pass line while the proof is missing. This inventory does not authorize changing payment flags, adding a payment feature, jumping the frozen queue, or opening public access. There is no observed live-charge incident asserted here.

The smallest remaining proof is a safe, current classification of the nonsecret running mode controls for the actual deployed payment path, coupled to its ingress/guard evidence. It must not expose keys or require making a payment. If that cannot be obtained under the available read-only access, retain the proof gap and stop closure; do not infer success from source defaults.

## Evidence files

All new raw evidence is in `payment-lock-source/` beside this report:

- `fingerprints.json` — original deployed source hashes for eight named files. Payment API SHA256 `160343272ba1a1f31b6d22bd1355b685abe3f70b3d978638f79d11d76853ed63`; sandbox adapter `2eb20cb1dd95e48ce25df0844e838c458a218f0290518657bd8f2c66099f30c6`; legacy Ops app `fcecabe419ce5aa080155f0e29e34eee79596d05f3838a6180dad2ce9795bbf2`.
- `payment-routes.json` — static payment-related route decorators, without loading the application.
- `nginx-routing.json` and `routing-supplement.json` — safe routing directives from the six domain configs and relevant snippets; no header credentials emitted.
- `connect-route-get-probes.json` — seven anonymous GET results. These are method/reachability observations, not payment or auth tests.
- `core-mode-anonymous-probes.json` — two Ops401 responses and API404.
- `nonsecret-config-mode-classifications.json` — allowlisted mode classification, source paths, process metadata, and access limitations.
- `gateway-supplement.json`, `preview-source.json`, and extracted source copies — public Pass/preview routing and provider-edge context. Preview source hash `e523924bac421433ad34ea6587353b0448bd42aeba950e27029d654ffb063099`.

The ecosystem boundary was rechecked against LiveUIN README, sitemap/domain handoff, module tracker, Laijuzhu blueprint and cross-project boundary audit, and IGEMA blueprint. This work touches LiveUIN public/private routing and its payment edge only. Core/Trust/Ops remains the durable product owner. No Laijuzhu, PrimeStay or IGEMA theme changes; no imported tenancies read, used or emailed; no forms, accounts, messages, charges, refunds, webhooks, checkout sessions or switches changed.
