# Drive evidence audit — 19 October 2026

Status: read-only research for plan refinement. This is not FREEZE-PLAN-01 and not release approval.

Audit performed approximately 19:17–19:24 Singapore time on 19 October 2026. The city audit was read first from the parent task’s authenticated copy. Google Drive metadata was read before downloading stored files. All four mandatory ZIPs were materialized using the connector’s authenticated top-level file_uri, matched their declared byte sizes and passed ZIP CRC validation. No local cloud placeholders were used as archive substitutes. No Drive files, code, production flags, accounts, cases, payments or messages were changed. No imported-tenancy record was opened, copied, emailed or used.

## Principal findings

1. **The documents do not establish that Core is an empty plot everywhere.** The 8 October queue says the named staging host/source import was missing. The 1–2 October module tracker separately records a narrowly deployed Core Inventory/Demand marketing runtime for The Sierra, a real owner sign-in, a private Host inbox, and a Core inventory link. The tracker carefully leaves the new-applicant request, complete reservation and payments journey open. The audit must distinguish the missing named staging environment, a README-only GitHub default branch, and the existence or absence of a particular deployed runtime. A live recheck and deployed-source mapping must settle this; a repo tree alone cannot do so.

2. **The four mandatory packages repeat the same authority snapshots.** LiveUIN README (85,539 bytes), sitemap (21,748 bytes), and module tracker (516,423 bytes) have identical SHA-256 across the blueprints, specifications, authority and runbooks archives. The later upload dates are not additional independent production confirmations. The ecosystem boundary audit is also identical. The two IGEMA blueprint variants differ only in redaction of two public/staging contact email addresses; section 21 money-flow rules are the same.

3. **P6 is explicit and demanding, not a page count.** The sitemap’s P6 section, lines 220–243, requires real production auth, RBAC, observability, routing, TLS, browser smoke, backup/restore, rollout and governance evidence. Earlier promoted-route labels do not prove current persona journeys. The documented route arithmetic is inconsistent: 9 promoted + 37 not-live = 46, while the reported preview total is 48. The feature register itself calls for reconciliation; do not convert these route totals into percent complete.

4. **Zero of 120 is an approval count, not a claim that no code exists.** The fetched 6 October feature register contains exactly 120 F rows: 113 backend partial, 3 done locally, 4 planned; 0 production evidence and 0 explicit production approvals in that register. External beta is HOLD_BETA_ONBOARDING. It expressly says absent approval does not mean zero implementation or no narrowly live runtime. Eighteen cross-cutting workstreams overlap these features and are not 18 extra approvals. Full-catalogue external beta remains held; the refined plan must define the exact constrained LiveUIN pilot and preserve exclusions instead of declaring the whole roadmap finished.

5. **No signed pilot price card was found in the inspected materials.** The 6 October commercial register says actual take rates, referral percentages, fee caps, refund rules, holdbacks, attempt fees and service prices were not finalized by its inspected sources. Its May Connect USD subscription rules concern a different product. July persona prices and v28/v29 economics are recommendations/illustrations, not a signed Singapore landing/placement price card. The 16 October IGEMA Arrival Packs plan has different package names and estimated working prices, expressly awaiting three supplier quotes per service. None authorizes replacing the user’s single UNSIGNED card or publishing its amounts. Searches for price/pricing/commercial names, “signed”, “LiveUIN Stripe” and “LiveUIN ACCEPT” found no signed pilot card. This is a bounded search result, not proof that no agreement exists anywhere.

6. **Legal questions remain unanswered in the located register.** The current confidential legal tracker has 20 rows, all OPEN, with blank answered-by/date/summary fields. Relevant rows include SG-001 estate agency/overseas referral work, SG-002 collecting for others and splitting commissions, and SG-010 automated identity checking/staff approval (marked blocking). The accompanying briefing is a request for legal advice with blank lawyer answer boxes, not counsel’s opinion. Its entity statement is based on a third-party company listing, explicitly not an ACRA extract. Neither establishes the Stripe merchant identity, licensing permission, or authority to collect rent/deposits.

7. **Historical Pay proofs are materially narrower than release readiness.** Queue v4 claims test checkout on an IGEMA case, paid state/room win in six seconds, and replay idempotency on 8 October. The same row says the Core record remains missing. It records live mode off, refund executor off and SQLite. A computed commission is not a payout. Those facts require fresh LiveUIN-scoped proof and cannot be reused as proof that the required family case, real-money charge, refund and ledger reconciliation are complete.

8. **The current prompt removes old queue work from this release.** N057 concerns an IGEMA theme inbox, and N051b proposes an IGEMA RO export/migration. Those are not permission to modify IGEMA or move imported tenancies. Translate the useful acceptance concept into LiveUIN request → canonical LiveUIN case with fictional/explicitly approved test records. No RO migration is needed merely to satisfy this release.

## Mandatory archive provenance

| Package | Drive source | Bytes | SHA-256 |
|---|---|---:|---|
| Blueprints and boundaries | https://drive.google.com/file/d/1fAVkh3gGAwgKhYIXPoIpHDkUthbOI0Zi/view | 712837 | fbe742f25e0c746d78264382aa71d00e7ce221d452bcc1089282af031b4684bb |
| Specifications and design | https://drive.google.com/file/d/1ogyRBX4u7AyXvNjNNrb6U0M2zQnWd1hr/view | 8831102 | 6b88ac0f40056b1e26b78e9432671dcd413438d373c4edbcb07789295ec02807 |
| Authority snapshots | https://drive.google.com/file/d/13y1E9sss0OwnLzCfoVf_-lx2zRzRwbmm/view | 225030 | 966c973559dd70a7faa499adfdbdfd80d579542cf6c6f8a3a96c28da0290efa6 |
| Architecture and runbooks | https://drive.google.com/file/d/14nrxeFq7W5y1vIE-In9Cfp70kuqUueRG/view | 747685 | 6db83a08174b28fc479679341af8a07f25a38cead4f4073f256111a4b48ead72 |

Metadata modified times: 13 October 22:11 SGT (blueprints), 13 October 23:44 SGT (specifications), 12 October 14:39 SGT (authority), 6 October 23:04 SGT (runbooks). Downloaded bytes and ZIP CRCs were checked on 19 October. These are our download hashes, not a separately signed publisher attestation.

Evidence root: /private/tmp/liveuin-p06-audit-20261019/
- drive-download-provenance.json — authenticated retrieval, sizes and SHA-256.
- drive-archive-metadata.json — source IDs, MIME, title, modified times.
- drive-*-members.txt and drive-*-extracted/ — complete mandatory archive contents.
- drive-feature-register.json and drive-feature-count-verification.json — independently parsed 120-row count.
- drive-queue-v4.csv and drive-queue-v4-relevant-rows.json — 246 queue rows, 19 relevant extracted rows.
- drive-commercial-decisions.txt, drive-commercial-register.json, drive-commercial-search-index.json — pricing search and source boundaries.
- drive-legal-questions.txt, drive-legal-briefing.txt — confidential advice-request records. Keep these private.
- drive-arrival-plan.txt — later IGEMA working-price comparison, not adopted.
- drive-pay-blueprint-15oct.txt — later accounting proposal, expressly research/design only.

## Sierra and auth: exact source statements and limits

In 02_Blueprints_and_Boundaries/Liveuin/docs/LIVEUIN-MODULE-FEATURE-TRACKER.md:

- Line 15, 1 October: The Sierra at https://www.liveuin.com/stays/listing_ef55a13993724d8e8d1201cb is described as published, existing Core Inventory-backed, eight real walkthrough images, signed owner publication, public application/private inbox routes. S$6,400/month is a room request amount. It is explicitly not a reservation, confirmed tenancy or payment. A genuine new-applicant OTP/application was not observed.
- Line 11, 2 October: normal owner sign-in and private inbox were verified then. Genuine applicant and complete bookable-unit/hold/agreement/payment journey remain open; no G1/G2/F01–F120/beta/P06 claim.
- Line 9: applicant-to-owner rehearsal uses fictional identity/mail/media and isolated canonical stores. It proves a local path, not actual applicant delivery.
- Line 7: listing linked to Core unit unit_743083f741e8a925904a172b and property reference property_d7ec630f707adb4039836fdd, with state needs_review. Holds/payments remain disabled; whole-premises hierarchy and production legal approval evidence remain missing. Tests/races prove locking primitives, not the complete production reservation journey.

These identities are public inventory references; no private applicant/case contents were accessed. Fresh checks should preserve The Sierra if still genuine and available, while isolating it from samples. Owner-auth evidence dated 2 October must be rerun for this build. Named test accounts need distinct fixture-only record scopes; granting generic staff/host roles alone does not meet the user’s denial requirements.

## Canonical money-flow law

The downloaded blueprints ZIP, igema/IGEMA-Blueprint.md §21, lines 857–915:
- Split money by economic purpose.
- Service fee goes to the contracted service company through a licensed processor with invoice/receipt.
- School fees go to school absent documented collection authority.
- Housing rent/deposit goes directly to landlord/licensed agency client account/approved housing provider; no unreviewed platform custody.
- Commission/referral payout needs written terms, milestone, case linkage and eligibility under corridor/local rules.
- Operator earnings follow approved proof.
- Refund records reason, approver, amount and correct payee.
- Cross-border remittance uses a licensed provider.
- Payment records retain payer, payee, currency, amount, fee type, processor, custody model, invoice, receipt, refund policy, dispute and reconciliation states, manual-change approver.
- Origin-market payment instructions require approved payee, purpose, template, refund/FX disclosure and owner approval.

§22 separates affiliate/referrer, counsellor/agency and licensed/approved destination operator access. Giving a test account the word “agent” cannot substitute for mapping the permitted tier and record scope.

The lawyer briefing’s statements about own-brand rents, 4/7/12% of term rent, and planned third-party collection do not override this law or the current user’s service-fee-only release boundary. They are facts/questions presented for advice, not a signed change to the pilot’s commercial rules. The 15 October accounting blueprint says “Research and design document only. No server, database or provider was touched”; its deposit ledger and future entity plans are not implementation evidence or collection permission.

## Recommended plan corrections before freeze

- Add source/deployment reconciliation as evidence needed inside the first relevant issue; do not discard an existing runtime because the named GitHub main branch is sparse.
- Keep current live failures above dated “promoted” claims, but retain the original narrow claim with date and evidence path.
- Use fresh browser+API+record proof per account and per journey, with denied reads of another synthetic case to establish isolation. Do not probe real family documents.
- Require a persisted LiveUIN case ID and one audit trail shared by parent/staff/payment views; no website-only inbox or IGEMA-only record can pass.
- Keep unsigned commercial data internal, quote-only public pricing, and specify tax/fee/refund/FX disclosure and processor account identity as unresolved evidence before charging.
- Keep legal and processor-policy validation as explicit payment prerequisites; an unanswered counsel question and a payment-service health endpoint do not satisfy them.
- Treat the old all-feature beta hold separately from the explicitly bounded pilot. Any release claim must name included/excluded capabilities and fresh P6 evidence; no “100%” while a required gate is open.
- Preserve the user’s queue and scope; older multi-brand migration, new AI/accounting automation, new countries, or IGEMA theme work remain parked.
- The publish sheet must reference one exact deployed version, retained backup/restore evidence and an owner-only publish action. No document in the inspected set proves that single publish switch already exists.

## Ecosystem boundary check

This audit touched private documentation and derived evidence only. Public UI belongs to liveuin.com/www; family, host and staff workflows remain role-scoped LiveUIN app surfaces; API is transport to LiveUIN Core/Trust/Ops/TrustPay/LiveLedger canonical truth. Laijuzhu, WeChat and WordPress remain funnel/bridge/connector layers. IGEMA is assigned local fulfilment, not the canonical owner of LiveUIN cases or payments. The global README, sitemap, tracker, Laijuzhu blueprint, ecosystem boundary audit and IGEMA §21 were checked against the downloaded authoritative snapshots. The persona audit was read from its hydrated local file. The ecosystem audit was double-checked. No boundary was reassigned.

## Key live source links

- Feature register: https://drive.google.com/file/d/1DLiMHmLSTCvKkikOws169--1vFbpwF8x/view
- Work queue v4: https://docs.google.com/spreadsheets/d/1DBDkQZrkqAoc2cGIiuE8w9NqEyj_xCm1bFQAE-E0Bfo/edit
- Commercial decisions: https://docs.google.com/document/d/1XNzELTEMKq6FW2VZJXv4sUzwx3omySqJdds760n-FYE/edit
- Current legal questions (private): https://docs.google.com/spreadsheets/d/1-BDmNx0j-v5R9O-yf_a4NrBCRfvzINiVDNEUNO9Tj_E/edit
- Lawyer briefing (private): https://docs.google.com/document/d/12Zg_n_nEtdpUvDTOSR2cYhXAMBbD1u-SboTv8I-Ducs/edit
- Arrival Packs working plan (reference only): https://docs.google.com/document/d/1ZiBlKOTO_hEe2QyJCGEYtOhmcdPeAK2AdmeNKgCrF18/edit
- Accounting proposal (reference only): https://docs.google.com/document/d/1YnZH7l03XOwKz08PR6Mk2riGSsXeEGk67PeT7FX5fvw/edit

