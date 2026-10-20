# R01 sign-in dependency amendment — proposed, not accepted

20 October 2026 · This file does not alter FREEZE-PLAN-01 or authorise a deployment.

## Why an amendment is needed

R01's guard and closed fallback passed 678 isolated checks. Administrator access is now verified. The remaining required live admission check needs an existing canonical, correctly scoped LiveUIN session. The normal Ops Request code attempt for the owner-supplied email returned `email_code_delivery_unavailable`; no session was obtained. The full owner journey remains R05, but the current sign-in failure prevents R01's own positive check.

The frozen process says to stop on failed proof and not stack another fix. The engineer therefore has not deployed R01, created a privileged test identity, or started an unrecorded email repair. An existing eligible signed-in owner session would avoid changing the sequence. Without one, the following narrow exception requires Ern's acceptance.

## Proposed exception

Insert one dependency row immediately before completing R01. Keep all existing R01–R24 rows, acceptance criteria and their relative order unchanged. Record acceptance in a separate decision note; preserve the original freeze and its hashes.

| ID | Plain name | Type | Evidence | What fixed looks like | What will not be touched |
| --- | --- | --- | --- | --- | --- |
| R01-D1 | Restore the existing owner sign-in delivery path | Broken pipe | [Administrator and sign-in check](evidence/reaudit/R01-ADMIN-ACCESS-CHECK-01.md); `https://ops.liveuin.com/ops/login` | The existing authorised owner can request and receive a code through the normal approved delivery service, complete the canonical sign-in and pass the guard's validation-only access check without opening family records. | No new identity store, credentials invented from server access, role/workspace expansion, imported tenancy contacts, customer campaigns, public access, commercial acceptance or sibling-site/theme changes. Do not assume the observed error proves a missing SMTP setting. |

First identify the exact deployed handler, existing provider binding and cause through narrowly scoped nonsecret diagnostics. Capture the current configuration and a recovery method. Repair only that identified cause using the existing service and ownership model. If the cause needs an unavailable owner-held credential or a new provider/permission, leave that item explicit; acceptance of this amendment does not invent access or approve broader permissions.

Prove owner-only delivery and canonical sign-in, expired/reused code refusal and correct role/workspace enforcement without reading other people's data. Record the dependency's own change, version, recovery and payment-lock evidence in its freeze note before returning to R01. Preserve the user's separate later full-account checks; this does not pass R05 or create the named test accounts early.

Then deploy and prove R01 under its unchanged 21-operation boundary, including anonymous refusal and an eligible signed-in validation-only request. Only after R01 passes may R02 begin.

## Decision

**Awaiting Ern's explicit acceptance of this narrow sequence exception, or an existing eligible LiveUIN owner session.** Administrator access is already solved and no administrator password/key is requested.

The accepted Stripe readiness amendment remains in force. No real-card test or public charging is enabled. LiveUIN Core/Trust/Ops and canonical Identity retain ownership; imported tenancies will not be used or emailed.
