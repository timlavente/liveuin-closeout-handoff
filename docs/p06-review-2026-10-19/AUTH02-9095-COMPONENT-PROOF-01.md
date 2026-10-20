# AUTH02-9095 component proof — legacy sign-in boundary repaired

20 October 2026, Singapore · **This backend component passed. AUTH02 remains open.**

The older Identity API now closes its raw preview sign-in routes and refuses unsupported browser sign-in paths before creating a challenge or sending mail. The owner's existing membership-based Ops sign-in still works. This is one component of the authorized authentication repair, not completion of AUTH02, R01, the five-account role table or P6.

## What changed and its exact version

One production application file changed: `/opt/liveuin/deploy/core_identity_api.py`, served by the existing `ops-backend@liveuin.service` on port 9095. Candidate08 is SHA256 `a0834b412c06263d1ca593de67cc2514471cf4fdd7a83c860608be998fc65fcb`; its final running PID is 3427360. No member frontend or 9098 member Identity release was activated by this component.

The exact [candidate source](evidence/reaudit/auth02-final-verification/final08-component/package08/candidate-9095/deploy/core_identity_api.py), [package manifest](evidence/reaudit/auth02-final-verification/final08-component/package08/deployment/package-manifest-9095.json) and [version receipt](evidence/reaudit/auth02-final-verification/final08-component/package08/deployment/PACKAGE-08-HASHES.json) are retained. This is a file-version proof; it is not presented as a reproducible Git release. The separate mobile task's resident adapters, app/main and customer-card follow-up were reconciled before restart and preserved. They are not counted as work delivered by this component.

## Deployed checks

Activation began at 04:21:15 Singapore. Configuration/source checks, private backup and all seven guarded startup-library imports passed before the final restart. The final service answered health 200. Eight public denial checks passed at 04:21:38; the safe requests contained only an empty object and, on verify routes, a clearly nonexistent diagnostic marker. No customer or account identity was sent.

| Public door checked | Result | What the result proves |
|---|---|---|
| [Ops raw challenge door](https://ops.liveuin.com/api/core/identity/login/challenges), create and verify | 404; no-store | The two raw preview handlers cannot issue or verify a public preview credential. |
| [App raw challenge door](https://app.liveuin.com/api/core/identity/login/challenges), create and verify | 404; no-store | The same older handlers are closed through App routing. |
| [Host raw challenge door](https://host.liveuin.com/api/core/identity/login/challenges), create and verify | 404; no-store | The same older handlers are closed through Host routing. |
| [Ops request-code door](https://ops.liveuin.com/api/ops/auth/request_code), empty request | 403 | An unsupported empty request is refused before challenge creation or email. |
| [Ops verify-code door](https://ops.liveuin.com/api/ops/auth/verify-code), empty request | 400 | Missing challenge input is refused. |

The two Ops adapter checks did not return no-store; that header is claimed only for the six raw-route denials. These results establish the tested boundary, not every role or case permission. Full [activation evidence](evidence/reaudit/auth02-final-verification/final08-component/runtime/activation-9095-result-08.json), [public results](evidence/reaudit/auth02-final-verification/final08-component/runtime/public-denial-after-08.json) and [startup result](evidence/reaudit/auth02-final-verification/final08-component/runtime/prestart-summary-08.json) are retained. The activation JSON accurately says owner proof was pending at its creation; the subsequent evidence below closes that component gate without rewriting history.

## Real owner proof

The existing owner session reloaded successfully. A fresh normal browser sign-in then requested a code at 04:21:53 Singapore, received its email at 04:21:55 and verified the delivered code at 04:22:40. The protected Ops Command screen opened. No command or broadcast was submitted.

The independent read-only [canonical proof](evidence/reaudit/auth02-final-verification/final08-component/runtime/owner-canonical-proof-after-08.json) at 04:22:59 matched the same normal owner flow and running source. Membership and session were active, role remained `ops`, workspace remained `liveuin`, and the existing 19 scopes were unchanged. No role or access grant was added. The helper read only the selected owner's Identity records; it did not create a challenge or session.

The [fresh sign-in screenshot](evidence/reaudit/auth02-final-verification/final08-component/runtime/owner-fresh-signin-after-08.jpg) shows the sample Command shell and a sample broadcast placeholder. It proves authenticated/session access only. It does not prove a completed staff desk, real resident count, command execution, case access, another-family refusal or logout. The sanitized [browser observation](evidence/reaudit/auth02-final-verification/final08-component/owner-proof/OWNER-BROWSER-OBSERVATION-08.md) contains no delivered code, real challenge identifier, token, cookie or raw email.

## Incident, recovery and the way back

The first activation failed an immediate post-restart command-line check. Review found that the check could inspect the normal startup wrapper before Python took over; the bounded wait corrected the check and full runtime proof then passed. It installed the reviewed closed fallback, encountered the same timing check and stopped the service. The explicit recovery then restored the closed fallback as a healthy service with new sign-in held. Candidate08 corrected only the bounded startup wait: a mismatch still cannot pass, and all final process/source/configuration checks remain required. The unchanged application candidate subsequently passed. The [failed attempt](evidence/reaudit/auth02-final-verification/activation07-incident/activation-9095-result-07.json) and [closed recovery](evidence/reaudit/auth02-final-verification/closed-recovery01/closed-recovery-result-01.json) remain separate, immutable evidence.

The final prechange backup is `/root/liveuin-closeout-backups/AUTH02-20261019T202116Z-3427110`. It remains root-private. The supported way back is the reviewed closed fallback SHA256 `aee0ce11a4ffe48242b18dbde4a67463409765d80f43f15a68c6d40facc6e143`, using the same checked controller and deployment lock. It holds new sign-in while preserving a recoverable service; it does not restore the original unsafe preview API or overwrite customer records. Root confirmed the cooperative deployment lock was released after final proof.

## Release limits retained

**Public live charging remains OFF.** The post-activation [payment-lock check](evidence/reaudit/auth02-final-verification/final08-component/runtime/payment-lock-after-08.json) matched PID 3427360 and all 13 reviewed source pins: checked live-rail flags were false, the concrete Core Stripe adapter had a test key, legacy Connect selected no external dispatch and the additional card sandbox flag was false. No payment or payment setting was changed. This is the bounded route/configuration evidence already used by this release; it is not a payment-suite pass or a new inspection of the separate Pay service.

**Imported tenancies were NOT used and were NOT emailed.** The owner's requested verification email was the only normal email action in this component proof. No family case, imported account or payment record was used. No public-admission switch was opened.

AUTH02 remains open for the approved pilot cohort, member-service/frontend deployment, named test-account isolation and real sign-out/revocation proofs. AUTH03–AUTH06 also remain open. R01's staged private-operation guard still needs its owner authority mismatch resolved and its own deployment proofs. No full FREEZE-ISSUE-AUTH-002, FREEZE-ISSUE-001, P6 completion or publish readiness is claimed.

The ecosystem and persona boundaries were checked against the LiveUIN README, domain/P0–P6 handoff, module tracker, persona-entitlement audit and sibling boundary blueprints. The touched layer is the canonical Core Identity API used by private Ops and routed through App and Host. Identity and durable authorization remain canonical in LiveUIN; no Laijuzhu, PrimeStay, IGEMA theme, connector or channel became a truth store. The owner kept only the already established role and scope, and no unrelated private case was opened.
