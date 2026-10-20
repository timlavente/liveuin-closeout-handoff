# LiveUIN Stripe payment coverage matrix

19 October 2026 · Review 07 · **Planned coverage, not passed tests or permission to open checkout**

Ern has now instructed: “ok just follow stripe...” Integration testing follows Stripe's official sandbox/test guidance; do not perform the previously proposed real-card $1 live integration test. Verify production credentials, account settings and webhook registration without making a test charge. The policy choice is settled and does not need another permission question.

Ern has explicitly approved the [Stripe readiness gate](PAYMENT-GATE-AMENDMENT-01.md): the mandatory pre-launch real capture/refund test is replaced by complete sandbox proof plus non-charging production configuration and public-lock proof. No real-money pass is claimed. The commercial card and owner-only publish action retain their separate gates. No charge, refund, key change or payment setting was performed during this planning pass.

## What the inspected integration establishes

The concrete LiveUIN sandbox adapter requests card payments and accepts only test secret keys. Do not insert live keys into that adapter or remove its test-key protection to make a check pass. Identify and prove the intended private live path separately, bound to the same canonical LiveUIN bill, case and ledger.

A general capability entry listing global coverage, wallets or bank transfers is not evidence that those methods are enabled on the merchant account or work in the checkout. Card-funded wallets also need device/domain/checkout eligibility proof; a card-only API parameter does not by itself establish whether a wallet will appear. The actual method list must come from the configured checkout and account capabilities.

## Required coverage within R11 and R12

| Check | Mode and scope | Pass evidence |
|---|---|---|
| Correct merchant and credentials | Separate test and live configuration checks; no key values in evidence | Correct account reference, environment, permissions and API version; test objects cannot be used as live objects. |
| Live webhook setup | Inspect the registered live destination and its own signing-secret reference | Correct HTTPS endpoint and event subscriptions; live and test secrets are separate; real events are authenticated and tied to the intended mode. |
| Advertised payment methods | Every method actually offered by the launch checkout | Account eligibility, country/currency/amount support and the actual customer flow are recorded. Unsupported or unproven methods remain unavailable or unadvertised. |
| Card-country coverage | Stripe test mode, representative issuer countries plus every payer market claimed for launch | Start with SG, CN, MY, IN, GB and US test scenarios where supported; record these as simulated issuer-country checks, not real-bank or worldwide acceptance. This does not launch new destination markets. |
| Authentication and failure | Test mode | Required authentication success, failure and cancellation; declined and insufficient-funds outcomes; useful customer messages with no false paid state. |
| Amounts and limits | Method-specific test cases and configuration checks | Sandbox small amounts, expected service-fee amounts, configured minimum/maximum boundaries and currency minor units behave correctly. An individual bank's real spending ceiling is not proved by a low-value success. |
| Pending and asynchronous methods | Each such method actually offered | Pending, eventual success, failure, expiry and abandonment leave the correct case state; browser return alone cannot mark a case paid. |
| Webhook delivery | Sandbox delivery plus supported non-monetary production-endpoint verification | Invalid signatures rejected; duplicated, delayed and out-of-order events do not duplicate money or case records; wrong case/amount/currency/mode rejected. |
| Refund coverage | Sandbox/test mode for offered methods | Test provider status, case line, invoice/receipt and ledger reversal reconcile; refund reason, approver, amount and payee are recorded. Pending is not completed. No actual bank refund is claimed. |
| Production readiness without a charge | After R11 passes; no real-card integration transaction | Correct live merchant, readiness, credentials/key scope, API version, methods/currencies and webhook registration; supported non-monetary verification; canonical case/bill/ledger binding; public live charging denied. No actual live capture/refund claimed. |

Every result records the release version, merchant account reference, mode, method, issuer/customer country as applicable, charge currency, amount, case ID, expected outcome and actual evidence. No result is labelled passed merely because a request returns HTTP 200.

## Coverage limits

Sandbox proof establishes the recorded test scenarios, and configuration checks establish the inspected production settings. Neither proves real money moved, every bank will accept a card or a higher spending ceiling will succeed. The release claim must match the recorded method/country/currency coverage. The original proposed $1 live integration test is superseded by the accepted readiness gate.

## Sources and boundaries

- [Stripe test scenarios and country simulations](https://docs.stripe.com/testing)
- [Payment method country and currency support](https://docs.stripe.com/payments/payment-methods/payment-method-support)
- [Minimum and maximum charge amounts](https://docs.stripe.com/currencies#minimum-and-maximum-charge-amounts)
- [Separate test and live API keys](https://docs.stripe.com/keys)
- [Webhook signing and delivery](https://docs.stripe.com/webhooks)
- [Production checklist](https://docs.stripe.com/get-started/checklist/go-live)
- [LiveUIN payment execution gate](PAYMENT-PROOF-ENTRY-GATE-01.md)

This adds precision to R11/R12; it does not reorder the 24 issues, authorize every global payment rail, start a new country rollout or open public checkout. LiveUIN Core/Trust/Ops and TrustPay/LiveLedger remain canonical. The IGEMA $1 transaction remains excluded.
