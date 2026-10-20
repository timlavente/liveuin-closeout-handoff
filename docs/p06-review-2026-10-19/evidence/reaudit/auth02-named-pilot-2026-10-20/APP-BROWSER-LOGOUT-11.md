# Both App logout controls passed; AUTH02 return destination remains open

20 October 2026, Singapore. The coordinating agent completed both normal browser sign-out controls for the named synthetic parent. Each returned to Welcome; reopening `/tenant/account` also returned to Welcome. The screenshots were independently viewed during evidence retention.

| Browser action | Canonical observation window, SGT | Active sessions and refresh credentials | Timestamped revoked records | Total records |
|---|---|---|---|---|
| Account page's Sign out button | 15:50:49 → 15:51:25 | Each 1 → 0 | Each 3 → 4 | Each stayed 4 |
| Profile-switch menu's Sign out | 15:54:43 → 15:55:17 | Each 1 → 0 | Each 4 → 5 | Each stayed 5 |

The positive active-session baseline, visible sign-out action, matching session/refresh revocation increase, unchanged total and closed private route support both logout results. This is not a zero-to-zero inference. The read-only helper queries only the fixed synthetic parent's bound account/person in `liveuin-public`, returns counts, and reads no token, password, session hash, metadata body or customer record.

Evidence:

- [Before account-button logout](parent-browser-before-logout1-02.json) and [after](parent-browser-after-logout1.json).
- [Before menu logout](parent-browser-before-logout2.json) and [after](parent-browser-after-logout2.json).
- [Account-button result](app-parent-body-logout-passed.png), [menu result](app-parent-menu-logout-passed.png), and [private-page reopening refused](app-parent-private-reopen-refused.png).

The count snapshots were stable within each read and bound to the reviewed member process/source/store paths. Counts alone cannot attribute a particular session when multiple active sessions or concurrent activity exist; the retained observations show one active session and refresh credential before each tested control.

## First metadata probe stopped safely

The [first probe result](parent-browser-before-logout1.json) reported `synthetic_parent_not_verified_active`. Its helper incorrectly required the public account status `active`. Canonical completed onboarding writes `tenant_active`. This was a **probe assumption error**, not a failed product login, account corruption or missing verification.

The original helper, SHA-256 `b6e35f35b63b5dbb77e63dd07d3c79f4ee9df323eb56673999393df8ce503ced`, is retained as `parent-session-counts-readonly-01.py`. The corrected helper, SHA-256 `16408ac30682cd72b04e621da15c2f60b4262b3a92b501c57e979cf2163a3d42`, changes only the expected status to `tenant_active` and its failure label. Read-only source/store/process and column restrictions remain unchanged. Ten corrected isolated tests passed; both source versions and their fixtures/results are retained.

## Remaining AUTH02 defect

The Welcome page received the allowed absolute App return destination for `/tenant/account`, but its sign-in links dropped the query. The next normal successful sign-in therefore landed at `/tenant/home` instead. That screen remained safely closed with NEEDS REVIEW, as shown in [the wrong-destination screenshot](app-return-destination-lost.png); it is not evidence of a working home or family-case page.

Preserving an allowed return destination is already part of AUTH02's frozen acceptance rule. The correction was being prepared locally in `frontend-return-11`; it had not been deployed or passed in this record. See [the precise gap](AUTH02-RETURN-DESTINATION-GAP-11.md). **AUTH02 remains open. Do not freeze it or activate the public frontend while this return-path proof is missing.**

The earlier API proof, password rejection, canonical Tenant reload, LocalPro refusal and these two logout results remain valid evidence within their recorded scope. The Tenant navigation mismatch stays assigned to the existing AUTH06 row. Other accounts, family-case isolation, broader release completion and publishing remain separate.

Core Identity owns the account, entitlement and session authority. Core/Trust/Ops retain durable product truth. No imported tenancy, real family case or sibling product was used, and no payment or public-access switch was changed in this evidence-retention step.
