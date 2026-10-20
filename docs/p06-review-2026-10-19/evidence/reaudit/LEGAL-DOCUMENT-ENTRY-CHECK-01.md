# Authority and document prerequisites for this release

19 October 2026 · Planning re-audit · No transaction or legal approval claimed

The retained legal register contains unanswered Singapore questions about estate-agency/referral work and collecting or splitting money. These are requests for advice, not evidence that the company is licensed, exempt or prohibited. Current CEA guidance confirms that entities carrying out estate-agency work through a digital platform require the applicable licence. The actual LiveUIN entity and service arrangement must be verified before the affected real activity; the audit does not invent their status.

The planning correction is precise: applicable authority must be present before the first real placement/referral offer, commission promise, charge or binding signature. R23 collects and rechecks that evidence; it cannot authorize an earlier action retrospectively. R03 checks listing authority and terms, R07 keeps the referrer within its permitted role, R11 uses clearly marked test bills and receipts, R14 separates synthetic signature fixtures from approved production documents, and R18 retains the exact unsigned card until ACCEPT. There is no new legal programme or extra country rollout.

The existing LiveUIN ContractOps specification requires immutable agreement/template versions, clause/document hashes, a signer snapshot and approval state. Its IGEMA tenancy reference is explicitly a test fixture. R14 must preserve what the parent actually reviewed and signed, record identity/authority, consent and time, and let the authorized parent and staff retrieve the same signed record. A changed template cannot silently replace a signed version. The production-effective document and its authority must be established before a real signature; technical fixture proof is labelled accordingly. Reuse Core/Agreements rather than building a new template studio or copying IGEMA records.

IGEMA Blueprint section21, expressly adopted by this release, requires payer, payee, currency, amount, fee type, processor, custody model, invoice number, receipt, refund policy, dispute/reconciliation state and manual-change approver. Refund proof additionally requires reason, approver, amount and payee. R11/R16 must retain these in the same LiveUIN case/ledger and show the correct scoped invoice/receipt. Test receipts cannot claim real money was received.

Sources:

- [CEA licence guidance](https://www.cea.gov.sg/real-estate-professionals/for-estate-agents/apply-for-an-estate-agent-licence/), refreshed19October2026.
- [IMDA electronic-transactions guidance](https://www.imda.gov.sg/regulations-and-licensing-listing/electronic-transactions-act-and-regulations), context only; not legal approval of this template.
- `/Users/Vivian/Documents/Liveuin/docs/LIVEUIN-CANONICAL-CONTRACTOPS-TEMPLATE-STUDIO-2026-09-17.md`, especially immutable versions, signing and production approval.
- `/Users/Vivian/Documents/igema/IGEMA-Blueprint.md`, section21.
- Retained private legal question register, LQ-SG-001 and LQ-SG-002, still unanswered in the inspected snapshot.

Ecosystem boundaries remain LiveUIN Core/Trust/Ops/Agreements and TrustPay/LiveLedger. No sibling implementation or imported-tenancy action is included.
