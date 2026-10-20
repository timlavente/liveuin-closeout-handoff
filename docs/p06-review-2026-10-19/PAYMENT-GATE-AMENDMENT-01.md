# Accepted correction to the payment publish gate

19 October 2026 · **Accepted by Ern in this chat**

Owner response: “Use the Stripe readiness gate (Recommended)”. This explicitly replaces the mandatory pre-publication real-money capture/refund test with the readiness gate below. It does not claim a real capture/refund occurred or authorize publication.

Ern has already decided to follow Stripe. This accepted amendment does not reopen that decision. It corrects the remaining conflict between that instruction and the original requirement for an actual captured payment and completed refund before publication.

## Exact accepted replacement

Replace only the mandatory pre-publication real-money test in R12 and the payment line of R24 / FREEZE-PUBLISH-00 with:

> Stripe sandbox payment, authentication, failure, webhook, case/ledger reconciliation and refund tests have passed for the launch payment methods and documented country/currency coverage. The intended live merchant account, account readiness, key permissions, API version, eligible payment methods, live webhook registration and signing-secret reference have been checked without creating a charge. Test/live separation and the server's refusal of public live charges have been proved. No actual live capture or refund is claimed. Public live charging remains disabled until Ern's tested publish action.

R11 retains the complete sandbox test suite. R12 becomes **Prove Stripe production configuration and keep live charging locked**. Its pass evidence includes the correct merchant/account reference, enabled capabilities, charge and settlement currencies, key/configuration references (never secret values), real HTTPS webhook destination, event subscriptions, API-version agreement, test/live separation and server-side public-charge denial. Use processor-supported non-monetary checks where available, label every simulated delivery, and never label it an actual live transaction.

R24 uses this exact amended payment gate. The acceptance change removes the requirement to manufacture a pre-launch real-card integration transaction. It does not change the fee card, scope, role permissions, case/signature journey, backup/restore, P6 evidence, public-access control or row order. The build must still implement payment and refund handling; sandbox proof cannot establish that real money has moved.

## Alternative not selected

Keeping the original real-money-before-publication requirement was offered as the alternative. Ern selected the readiness gate instead. Do not carry the old mandatory test forward as an unresolved release blocker, and do not mislabel its removal as a completed real-money test.

## Why this acceptance was recorded

The original user request explicitly made both test payments and a real captured/refunded payment part of “done” and the publish sheet. The later instruction settled compliance with Stripe, but did not expressly remove that original acceptance line. The exact release-criterion change has now been expressly approved. No further approval of the same change is needed.

Sources checked: [Stripe testing](https://docs.stripe.com/testing) and [Stripe go-live checklist](https://docs.stripe.com/get-started/checklist/go-live). This document records an accepted criterion change. It is not completed payment evidence or permission to publish.
