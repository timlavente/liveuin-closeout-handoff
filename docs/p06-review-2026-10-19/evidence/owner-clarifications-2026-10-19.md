# Owner clarifications received during the audit

19 October 2026. These statements came directly from Ern in the current chat. They refine the draft; they are not plan freeze, commercial ACCEPT or publish approval.

## Inventory scope — confirmed

In response to individual room versus Sierra whole home, Ern wrote:

> it is a whole home journey unless end of lease, and change of listing to other list types...

The initial journey is therefore the whole home. Preserve the current listing type, real availability and lease terms. Any later change to rooms or another type follows an actual authorized lease/listing transition and preserves existing case history. This does not establish an earlier availability date, authorize a speculative split or accept a commercial fee.

## Existing payment — confirmed as IGEMA, excluded from this job

In response to the proposed Stripe proof constraint, Ern wrote:

> who said so.. i just did real card funds using grok bot and paid 1 dollar

Ern subsequently clarified:

> that was for igema.space... nothing to do with u.. but are u sure stripe cannot do live testing?

This closes the earlier identification question. The transaction belongs to IGEMA and is excluded from LiveUIN proof and investigation. No reference, receipt or further information about it is required. It is not counted as a LiveUIN pass or failure. Currency and refund details are immaterial to this job and remain uninspected.

Recheck of [Stripe's testing documentation](https://docs.stripe.com/testing) on this audit date confirms its stated restriction on live-mode integration testing using real payment details. This does not mean a real-card charge cannot technically succeed, and this audit does not assess the unrelated transaction. Preserve the user's separate LiveUIN real-money requirement until fulfilled through a permitted method or explicitly changed.

Before this clarification, a local engineering-note search found no matching $1 record and located [the older founder payment runbook](../../FOUNDER-CONTROLLED-SGD10-RELEASE-RUNBOOK.md), which specifies **S$0.10**, despite its filename. It is a procedural reference, not a receipt or processor approval. Its example includes a Laijuzhu workspace and out-of-scope financial legs, and it must not be executed wholesale for this release. No further search for the IGEMA transaction will be performed.

No application, payment, refund, account or public-access switch was changed by this clarification.

## LiveUIN payment validation — technical approach specified

Ern subsequently instructed: “the testing is on the credentials and the payment settings, hooks etc.” He requested Stripe test coverage and a $1 live payment, and raised payment-type, country and bank-ceiling coverage.

Record this as authorization for the requested technical approach, not an unresolved choice between real money and simulation. The proposed Singapore pilot amount is SGD 1.00; the dollar sign alone does not establish currency, so bind it to the exact owned case and authorized payer before execution. The required completed refund remains part of the same proof. No repeat general approval request is needed.

A single low-value success proves that specific route; it cannot prove all banks, countries, methods or higher limits. The [coverage matrix](../PAYMENT-COVERAGE-MATRIX-01.md) therefore covers every actual launch method, representative issuer countries, amount boundaries, authentication, failures, webhooks and refunds. Stripe's published restriction remains a separate processor-permission condition; this instruction does not establish an exemption. No charge or setting change has occurred.

## Stripe guidance — policy choice settled

Ern's latest instruction, after the distinction between technical capability and Stripe's testing restriction was explained, is:

> ok just follow stripe...

Follow Stripe's official sandbox/test guidance. Do not perform the earlier proposed $1 real-card live integration test. Production credentials/account settings/webhook registration can be checked without creating a test charge. This settles the policy choice; do not ask the same general permission question again.

The original actual captured-payment and completed-refund requirement is retained as uncompleted, conditional on a documented processor-permitted route. No route is currently established, no substitute is counted and no original requirement is silently waived. This instruction is not full-plan freeze, commercial ACCEPT, permission to send a processor enquiry or public-publish approval. No charge, refund or production change was performed.

Official guidance rechecked: [Stripe testing](https://docs.stripe.com/testing).

## Payment publish criterion explicitly replaced

During the re-audit, Ern was shown the exact choice between the original actual charge/refund requirement and a Stripe readiness gate comprising passed sandbox tests plus verified live account, credentials, webhook and public-charge lock, with no actual-money claim. He selected:

> Use the Stripe readiness gate (Recommended)

This expressly accepts [PAYMENT-GATE-AMENDMENT-01.md](../PAYMENT-GATE-AMENDMENT-01.md). The mandatory pre-publication actual capture/refund test is superseded. Do not leave it as a hidden blocker, count it as performed or ask for the same approval again. This does not accept the commercial card or authorize public access. The user also authorized freezing and starting in the original issue order once the re-audit's planning gaps are closed; product defects still require their individual proofs.
