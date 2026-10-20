# LiveUIN fresh public-surface re-audit

19 October 2026, Singapore. Initial HTTP requests began at **23:15:48 SGT**; the bounded retry established the final API/configuration observations at **23:23:01–02 SGT**. Fresh rendered page retrievals used `maxAge=0` within this audit window.

This is a finite, read-only recheck against Review 06. It does not freeze the plan, pass a repair, prove the full product, or approve publication. No form, account, OTP, payment, refund, checkout-session, service/configuration or credential mutation was performed. The only POST was the previously documented read-only Public Search operation with its default `{}` body. The public sample checkout link was observed but not opened.

## Result

**The inspected live state remains consistent with Review 06. No new public-surface scope conflict was found. Existing faults and execution proofs remain open.**

| Exact surface / operation | Fresh result | Meaning and existing work |
|---|---|---|
| `https://liveuin.com/search` | HTTP 200 and fresh rendered examples | **Model house.** The “Example listings only” banner remains. Six sample cards still display `VERIFIED OPERATOR`, `VERIFIED LANDLORD`, `FAST BOOK` and review counts. Sierra is not among the displayed cards. R10 and real discovery remain necessary. |
| `https://liveuin.com/pricing` | HTTP 200 and scope/quote language | **Lights on for the current public price explanation only.** No dollar package prices appeared in the fresh rendering. Preserve that state until the accepted commercial card is ready. This is not proof of card acceptance. |
| `https://liveuin.com/stays/cozy-studio-orchard` | Fresh rendered HTTP 200 | **Model house.** The detail still lacks an example warning and presents “Continue to checkout” pointing to `/checkout/cozy-studio-orchard`. The target was not opened, and no session was created. |
| `https://www.liveuin.com/stays/listing_ef55a13993724d8e8d1201cb` | HTTP 200, owner-provided whole-home publication | **Lights on for publication only.** S$6,400/month; three bedrooms; available 16 September 2027; not independently verified; email verification is shown as necessary to send a request. No request was sent. |
| `https://www.liveuin.com/api/core/inventory/marketing-publications/listing_ef55a13993724d8e8d1201cb` | HTTP 200 on bounded retry | Version 1, `accepting_offers`, `whole_premises`, asking rent 6400 SGD, availability 2027-09-16, minimum lease 12 months. Offer submission true; instant booking, payment and hold false. Canonical inventory IDs remain present. No case or storage-completion claim follows from this public projection. |
| `https://app.liveuin.com` | HTTP 200 after `/app/member` redirect; fresh rendering reaches member welcome | **Model house for the family product.** Welcome offers sign-in links. Own-case, signing, payment status and isolation were not exercised. |
| `https://host.liveuin.com` | HTTP 200 after `/host/onboarding`; rendering reaches Host-specific approved-email sign-in | **Model house for the host product.** The gate is visible; no code requested and no listing/finance permissions proved. |
| `https://ops.liveuin.com` | HTTP 200 after `/ops/login`; fresh rendering shows approved Ops sign-in | **Model house for the staff product.** The gate is visible; no desk, account isolation, case action or payment review proved. |
| GET `https://api.liveuin.com/v1/health` | **200** at 23:23:02 | **Lights on for health only:** `ok=true`, `liveuin-public-home-v4`. |
| POST `https://api.liveuin.com/api/public/search`, `{}` | **500**, `Internal Server Error`, at 23:23:02 | Existing R02 failure remains reproduced. |
| GET `https://api.liveuin.com/api/public/status` | **500**, `Internal Server Error`, at 23:23:02 | Existing R02 failure remains reproduced. |
| GET `https://api.liveuin.com/api/core/admin/control-center`, no credentials | **500**, `Internal Server Error`, at 23:23:02 | Existing R01/R02 work remains necessary. This is not the required sign-in denial. No private response data was received. Source-level missing-guard findings belong to the earlier deployed-source audit, not a newly performed source inspection. |
| GET `https://pay.igema.space/healthz` | **200** at 23:23:02 | **Lights on for the published health/configuration report only.** Version 0.9.0-staging; Stripe test; live false; refund executor false; SQLite healthy; schema 18. No transaction proof. |

Sierra's visible “at least three consecutive months” and one-year preference still coexist with JSON `minimum_lease_months=12`. This remains the existing preferred-versus-enforced term uncertainty for R03. No shorter-term offer was submitted, so a validation bug is not asserted.

## Public navigation and payment indications

The inspected search, pricing and sample-detail header/footer contain public product explainers, help, company and legal links. No staff desk, case-document or host-finance destination appeared in those inspected menus. This limited result does not certify every route or menu on the site.

The sample detail still offers a checkout destination. No direct live Stripe payment link was visible on the inspected pages. Sierra says no payment now and its public projection reports payment disabled; the known Pay health report also says live disabled. These observations **do not prove every possible public payment entry is server-locked** and do not satisfy payment or refund evidence. Existing R11/R12/R23 proof obligations remain unchanged.

## Review 06 comparison and freeze implications

- No observed change invalidates the existing first repair order: protect the staff boundary before shared database recovery, then individually prove the three endpoints.
- Example honesty, real discovery and public-to-case completion remain assigned to existing rows. Do not replace the Sierra, invent a different home, or treat the sample catalogue as live inventory.
- Existing correct quote-only pricing and role-entry gates should be preserved.
- This pass does not reopen the settled instruction to follow Stripe guidance. It performed no live-card integration test and supplies no alternative real-money proof.
- No new public-surface planning decision was identified. **That does not mean the product has no gaps.** The planned faults are still faults, and owner/test-account allow/refuse/sign-out, request-to-case, signing, payment/refund reconciliation, backup/restore, rollout and publish-control proofs have not been executed here.
- Whether R01 may begin depends on the main audit's freeze decision and its pre-change source/configuration/store/backup/rollback evidence. This public read cannot certify those execution-entry conditions.

## Retrieval limitation retained honestly

The first local HTTP batch had transient resolution failures for Host/Ops/API/Pay and a timeout for the Sierra JSON. Fresh remote rendering succeeded for the corresponding pages. One bounded normal retry then returned Host/Ops/Sierra/health successfully and reproduced all three API 500s. Both batches are retained. The initial retrieval errors are **not classified as a site-wide outage or a DNS change**. No DNS override, access-control bypass or new guessed endpoint was used.

## Evidence

- `http-summary.json`: original observation times, raw result codes, TLS verifier result where a connection occurred, body sizes and digests.
- `http-retry-summary.json`: final successful/reproduced observations, including exact Pay configuration and Sierra public fields.
- Individual `*.headers.txt`, `*.body` and sanitized Pay `*.body.json` files: status/body evidence; headers limited to safe operational fields.
- `search-rendered.md`, `pricing-rendered.md`, `sample-detail-rendered.md`, `sierra-rendered.md`, `app-rendered.md`, `host-rendered.md`, `ops-rendered.md`: fresh rendered text and the corresponding JSON provider metadata.
- `rendered-summary.json`: narrow label, link and routing observations.

Surface/layer scope stayed public UI, private-app entry pages, public projections and the existing payment edge's health report. No ecosystem ownership changed; no Laijuzhu, PrimeStay or IGEMA theme work occurred. Imported tenancies were not opened, used or contacted.
