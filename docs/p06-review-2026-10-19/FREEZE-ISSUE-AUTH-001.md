# FREEZE-ISSUE-AUTH-001

20 October 2026, Singapore · **AUTH-01 passed: existing owner code delivery and sign-in restored.**

Authority: Ern's “ok resolve them”, recorded in [FREEZE-AUTH-REPAIR-01](FREEZE-AUTH-REPAIR-01.md). This closes only AUTH-01. It does not close R01, the other login repairs, the full account table, or public-release readiness.

## What changed

The existing private code-delivery service was stopped. After checking its exact source, startup behaviour, running Ops configuration and recovery, the engineer started `otp-gateway.service` at 00:34:49 Singapore. It remains bound to the server's private loopback address. Its existing configuration, already-enabled boot setting and application files were not changed. No queue was flushed and no new mail provider was added.

The normal Ops request then delivered a new LiveUIN verification email to Ern's supplied owner account, `timlavente@gmail.com`. The delivered code completed sign-in at 00:35:25 and the browser opened [Ops Command](https://ops.liveuin.com/ops/command). A reload retained access. No broadcast or other Ops command was sent. The sample content on that page is not proof of a working case desk.

## Proof

| Check | Result |
| --- | --- |
| Delivery service health and database connection | `/healthz` 200; `/readyz` 200 using only `SELECT 1`. |
| Private sending gate | Anonymous empty request 401. The existing Ops internal credential reached field validation and received 400; neither check sent mail. |
| Actual delivery | New `LiveUIN verification code` email from `noreply@liveuin.com` arrived at the named owner's mailbox at 00:34:59 Singapore; mail authentication reported SPF and DKIM passes. No code is retained in the evidence files. |
| Normal owner sign-in | Browser reported authentication complete and opened the protected Ops destination using that delivered factor. [Screenshot](evidence/auth-01-restoration-2026-10-20/owner-ops-signed-in.jpg). |
| Existing owner authority | A read-only query restricted to this exact owner/challenge/session found a verified challenge, active session, unchanged existing role `ops`, workspace `liveuin`, and scopes matching the existing role. No credential or hash was output; no unrelated account or family record was selected. |
| Invalid, expired and reused codes | 14/14 isolated checks passed against checksum-matched deployed canonical verification code. Wrong code 403, expired code 410 and reused code 409; no new session was issued on refusal. |
| Role and workspace tampering | The isolated checks refused unapproved membership, retained server-approved role/workspace/scopes, refused a forged role signature and denied membership revoked after code request. |

The isolated tests used synthetic identities, three temporary databases and no network or email. They ran on Python 3.13.3. The actual delivered-factor proof ran through the existing production service. Full named-test-account access to cases, wrong-case refusal, signing and sign-out remains in the original account rows; it is not claimed here.

## Versions and recovery

The controller and all proof files are pinned in [AUTH-01 manifest](evidence/auth-01-restoration-2026-10-20/manifest.json). The controller SHA256 is `885062ee08ce7707b735fbe7090c954730ce3f6121012601d1b806af8add278b`. The unchanged OTP application SHA256 is `24542a1052dda9723591e1e068c0a446183b643768cf6ccda134a4f2f8e7fe87`; unchanged unit SHA256 is `d2ecd65e7581c6aa019a56e637fdded337ffd4f720c826479371a85ff80bc272`. The exact deployed identity sources used for the proof are separately pinned in the retained test manifest. This is a service-state repair, with file versions rather than a fabricated Git commit.

A root-only backup of the existing application, unit, Ops delivery binding and private configuration is retained at `/var/backups/liveuin-p06/auth-01-20261020-attempt-01` on the verified LiveUIN server. Recovery for this change is to stop only this delivery service, restoring its previous inactive state; no application or data restore is needed. The controller contains that failure recovery and did not need to invoke it. Stopping it would make code delivery unavailable again. The historical reason it stopped on 9 October remains unknown.

## Unchanged release limits

**Public live charging is still off for the reviewed LiveUIN paths.** The 00:37 repeat check found the four Core live-rail flags off, the Core Stripe adapter using a test key, and legacy Connect selecting no external provider dispatch. No checkout, charge or refund was created. The accepted Stripe readiness gate remains the payment requirement.

**Imported tenancies were not used and were not emailed.** The only product email requested was the named owner's normal sign-in code. No account grant, case, public-admission switch, sibling theme or commercial price changed.

The real owner's existing `ops`/`liveuin` session does not match the staged R01 guard's narrower `ops_manager`/`super_admin` and `liveuin_first_party` admission rule. This is recorded for R01's required authority alignment; no role was silently expanded and R01 is not declared deployable or closed by this note. Continue with AUTH-02 in the frozen dependency order.

Ecosystem and persona boundary check: these are LiveUIN private Ops and Core Identity delivery/session surfaces. Core Identity remains the authority for accounts, membership and sessions; Core/Trust/Ops retain product truth. Public access remains closed pending the full release and Ern's publication action.
