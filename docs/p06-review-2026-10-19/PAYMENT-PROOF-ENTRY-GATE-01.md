# LiveUIN Stripe readiness entry gate

19 October 2026 · Review 07 · **Accepted criteria, execution proof still open**

Ern explicitly approved “Use the Stripe readiness gate (Recommended)” in this chat. The [accepted amendment](PAYMENT-GATE-AMENDMENT-01.md) replaces the mandatory pre-launch real charge/refund requirement. Do not ask again, carry the old requirement as an unresolved blocker, or claim that real money moved.

## Required outcome

R11 passes the complete Stripe sandbox suite through the actual LiveUIN test case and payment journey. R12 then proves production configuration and refusal of public live charges without creating a real-card integration charge. No real capture or completed live refund is required or claimed for this pre-publication gate.

| Required item | Proof required before R12 closes |
|---|---|
| Sandbox suite | R11 results identify release, merchant test account, methods, country/currency scenarios, case, invoice, receipt, webhook, ledger and refund outcomes. |
| Correct production merchant | Verified legal entity/account reference, account readiness and eligible capabilities; never secret values in evidence. |
| Credentials and API version | Correct live/test separation, permitted key scope and API-version agreement, verified by safe supported non-charging checks. |
| Live webhook | Actual HTTPS endpoint registration, event subscriptions, API version and separate signing-secret reference. Verify supported non-monetary delivery/negative checks and label simulation honestly. |
| Payment methods and limits | Every offered launch method is eligible for the account, charge/settlement currencies and method limits. Unproven methods remain unavailable. |
| Public live-charge lock | Server refuses strangers, test accounts and altered role/case inputs; direct calls cannot bypass the lock. Client-hidden buttons alone do not pass. |
| Production flow binding | The prepared live configuration targets the existing canonical LiveUIN case, bill and ledger path; no second money store or sandbox object reused as live. |
| Evidence claim | Record “sandbox payment/refund passed; live configuration verified; no actual live capture/refund performed”. |

## Boundaries retained

Public charging remains denied until Ern's separately proved publish action. The unsigned commercial card still requires ACCEPT. Platform money remains its own authorized service fee; rent and deposits remain outside platform custody by default. The earlier IGEMA payment is excluded. No imported tenancies are used or contacted.

The full test matrix is in [PAYMENT-COVERAGE-MATRIX-01.md](PAYMENT-COVERAGE-MATRIX-01.md). No test result or account capability is treated as passed merely because a health page answers.

The previously drafted processor enquiry was never sent and is no longer a dependency of this accepted gate. Do not send it without an explicit request.

Sources: [Stripe testing](https://docs.stripe.com/testing) and [Stripe go-live checklist](https://docs.stripe.com/get-started/checklist/go-live). LiveUIN Core/Trust/Ops and TrustPay/LiveLedger remain canonical.
