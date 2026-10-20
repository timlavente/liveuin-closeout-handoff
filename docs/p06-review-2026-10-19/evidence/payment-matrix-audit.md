# LiveUIN payment-method evidence and bounded pilot matrix

Read-only audit, 19 October 2026, 22:48 Singapore. No payment, refund, key/configuration change, account change, provider call using credentials, or database/customer/IGEMA-transaction inspection was performed. This is a refinement proposal, not a freeze or passed test report.

**One successful $1 card payment would prove that particular payment on that merchant account and route. It would not prove every country, currency, wallet, bank method, webhook outcome or refund.** The requested live proof still needs an explicitly identified merchant, permitted process, amount/currency, owner-controlled case, completed refund and public charging lock. A dollar sign alone does not establish SGD. No newly reported transaction was inspected in this work.

## What is actually present

| Evidence | Proven statement | Limit |
|---|---|---|
| `/opt/liveuin/deploy/core_stripe_sandbox_api.py`, identical to local `deploy/core_stripe_sandbox_api.py:18–30,45–81` | Concrete Stripe PaymentIntent adapter accepts only test keys; it explicitly sends `payment_method_types[]=card` at64. Default currency is SGD; currency-format validation alone is not eligibility validation. | No live-key adapter or wallet/bank activation is proven by this file. |
| Same file84–96 | Sandbox connected-account creation requests `country=SG`. | This does not prove the production platform merchant is a Singapore company, its capabilities, or its settlement currency. It is not permission to create an IGEMA account in this release. |
| `deploy/core_payment_rail.py:26–38,88–145`, identical to deployed bytes | Registry declares Stripe SG/GLOBAL; SGD/USD/EUR/GBP/CNY; card/wallet/bank-transfer; separate live-ready flag. | The file explicitly says it is a selection registry, not a provider action. `GLOBAL` and `supports_stripe_presented_wechat_pay` are declarations, not account-level availability or tested coverage. |
| `deploy/core_payment_provider_edge.py`, identical to deployed bytes | Implements Stripe raw-body signature and timestamp checks; parsers/adapters for other providers also exist. | Receiving/parsing a simulated provider event does not prove a working checkout method. |
| `www-lovable/src/pages/Checkout.tsx:57,75` | Local public checkout says agreements/payments occur later and creates no payment record or charge. | This local source is not a signed production source mapping or a live Stripe Checkout session. No public enabled-method list is established. |
| Fresh GET `https://pay.igema.space/healthz`, 22:48 SGT; `pay-public-health.json` | HTTP200; version0.9.0-staging, Stripe test, live disabled, refund executor disabled; Airwallex demo/routing disabled/live disabled. | Health exposes neither merchant country nor enabled payment methods. It cannot identify or disprove a separate owner-reported live charge. |

Five payment source fingerprints are in `deployed-payment-fingerprints.json`. The sandbox adapter, rail registry and provider edge match local files. Deployed payment service/API differ from local; do not deploy or claim current behavior from those local files wholesale. The earlier exact Ops assembly shows Core payment router registration at `ops-main.py:412,553–554`, conditional on its status route not already existing.

The Payments Hub spec is explicitly **planning handoff**, `docs/LIVEUIN-PAYMENTS-HUB-SG-FIRST-SPEC.md:3–5`. Its PayNow/HitPay/Airwallex/bank-feed roadmap is not proof of enabled methods. Its broader money purposes also do not override this release's rule: platform fee only; rent and security deposits go to the proper landlord/licensed recipient.

## Existing tests that can be reused

These are identified test programs; they were not run or credited as fresh passes during this audit.

- `deploy/core_stripe_sandbox_payment_flow_smoke.py:3,94–130`: explicitly no-network; mocks Stripe intent creation and injects success/reconciliation evidence. Useful Core bookkeeping coverage, not a real Stripe test-card transaction.
- `deploy/core_payment_provider_edge_smoke.py:151–175`: synthetic valid signature, tampered payload and stale timestamp checks.
- `deploy/core_payment_provider_handoff_smoke.py:170–194,216–231`: signed handoff and replay refusal; explicitly reports `provider_truth_used=false`.
- `deploy/core_payment_api_auth_smoke.py:171–204`: local TestClient anonymous denial and role visibility. Does not prove real owner/test-account browser isolation.
- `deploy/core_g39_refund_lifecycle_http_smoke.py:243–504`: local TestClient full/partial refund, pending/delayed/failure/recovery, replay and restored local state. Does not prove Stripe executed a refund.

A bounded search of current `deploy/*.py` found no dedicated Stripe card decline, insufficient-funds, 3DS or international-card scenario suite. That is a gap in the searched source, not proof no historical test exists elsewhere. The old `docs/FOUNDER-CONTROLLED-SGD10-RELEASE-RUNBOOK.md:1–6` actually describes S$0.10 despite its filename; it is a procedure, not completed proof and not the new $1 instruction.

## Proposed finite Singapore pilot matrix

| Row | What to prove | Mode / scope |
|---|---|---|
| M1 | Merchant account reference, legal entity/business country, capabilities, accepted presentment currency, settlement currency, enabled methods and intended payment page agree. Record safe metadata, never keys. | Read-only account/configuration inspection. Merchant/currency assertions currently unverified. |
| M2 | Card success reaches the owned test case, staff payment line, receipt and ledger; duplicate submission creates one charge. | Stripe test; proposed SGD pilot presentment, subject to the accepted card and merchant eligibility. |
| M3 | Decline/insufficient funds; required authentication succeeds, fails or is abandoned; user cancellation/retry; unsupported method/currency is safely refused. | Stripe test fixtures through the actual released UI/API. |
| M4 | Valid event, bad signature, stale signature, duplicate/retried event and delayed/out-of-order event; unmatched payment stays reviewable without crediting the wrong case. | Stripe test webhook delivery plus bounded negative tests. Success redirect alone never marks paid. |
| M5 | Full refund and duplicate-refund safety; asynchronous/pending/failure states; provider and case/ledger agree. | Stripe test, no imported cases. |
| M6 | Representative Singapore-issued and foreign-issued test cards while keeping the selected presentment currency fixed. Separately label issuer country, customer location and merchant country. | Stripe test. Covers those representative paths, never “all countries”. |
| M7 | Any additional method actually enabled and eligible for this merchant: show/hide correctly, complete its own flow, process asynchronous result and refund. | Conditional per-method tests only. Apple Pay/Google Pay require their browser/device path; PayNow/GrabPay/Alipay/WeChat Pay must not be inferred enabled from registry strings. Park or visibly disable unproven methods. |
| M8 | The explicitly permitted small live charge: correct credentials/account, actual capture, signed live webhook, owned case, ledger, completed refund, final public live lock. | One designated owner/card/case and expressly confirmed currency, after test suite and existing payment entry gate. Does not make all M7 methods live-proven. |

Stripe publishes different business-country, customer-country, currency and integration restrictions for each method; therefore “all countries and all types” is not an honest universal acceptance criterion. For example its table lists PayNow for SG/SGD and GrabPay for SG/MY with SGD/MYR. The matrix must use the actual merchant's eligible enabled subset. Source checked: [Stripe payment-method support](https://docs.stripe.com/payments/payment-methods/payment-method-support).

M8 remains subject to the already documented processor-permitted process in `docs/p06-review-2026-10-19/PAYMENT-PROOF-ENTRY-GATE-01.md`; this inventory supplies no new authorization or workaround. Existing live credential validity by itself does not settle that condition.

Ecosystem boundary checked: LiveUIN public/private payment surfaces, Core/TrustPay/LiveLedger and the existing pay door only. No sibling product work, custody change, imported tenancy or IGEMA transaction inspection.
