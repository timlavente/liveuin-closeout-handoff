# FREEZE-ISSUE-AUTH-002

**AUTH-02 passed — real public/member sign-in.** 20 October 2026, Singapore.

The public form previously used a preview identity exchange instead of checking the entered password. It now hands approved members to canonical LiveUIN Identity, preserves an allowed destination and signs out through server invalidation. Pilot admission remains closed to unapproved accounts; admission itself grants no role. This closes only AUTH02 in [the frozen auth sequence](FREEZE-AUTH-REPAIR-01.md).

## Proof

- **Unsafe preview paths closed; owner's access preserved.** The older Identity API refused the preview exchanges, and fresh normal owner sign-in retained the existing Ops role, workspace and scopes. [Component proof](AUTH02-9095-COMPONENT-PROOF-01.md).
- **Closed pilot admission enforced.** Member activation refused outside-cohort registration/password and unsigned session requests. Exact executed versions and closed-recovery history are retained. [Member proof](evidence/reaudit/auth02-named-pilot-2026-10-20/NAMED-PILOT-WORKING-EVIDENCE-02.md).
- **Real parent verification completed.** The synthetic parent completed normal verification, profile and onboarding. Correcting the local test interpreter's certificate trust preserved strict TLS and form protections. [Verification evidence](evidence/reaudit/auth02-named-pilot-2026-10-20/BROWSER-HANDOFF-07.md).
- **Seven actual API checks passed.** Wrong password refused; correct password resolved the exact parent; existing Ops boundary refused the parent; server logout revoked session and refresh; both stale credentials were refused. The Ops response was 401, not a proven 403 role-policy decision or an R01 pass. [API proof](evidence/reaudit/auth02-named-pilot-2026-10-20/PARENT-API-PROOF-08.md).
- **App password and role checks passed.** Actual wrong-password refusal, correct account, canonical reload and locked LocalPro were observed. [Browser evidence](evidence/reaudit/auth02-named-pilot-2026-10-20/APP-ACTIVATION-BROWSER-10.md).
- **Allowed return and both logout controls passed.** Each sign-out control reduced active canonical sessions and refresh credentials from one to zero, with matching revocation and private reopening refused. Return11 preserved `/tenant/account` through Welcome and sign-in. Earlier unchanged-code checks are explicitly carried forward. [Both controls](evidence/reaudit/auth02-named-pilot-2026-10-20/APP-BROWSER-LOGOUT-11.md), [return proof](evidence/reaudit/auth02-named-pilot-2026-10-20/APP-RETURN-CONTINUATION-11.md).
- **Public handoffs passed on both domains.** Normal apex and www header login links reached App sign-in. The parent signed in, opened and reloaded the Tenant account, signed out, and was refused when reopening it. The default home remained NEEDS REVIEW with no active case. Strict origin checks and normal public-browser proof are separately retained. [Final browser proof](evidence/reaudit/auth02-named-pilot-2026-10-20/auth02-closeout-12/PUBLIC-BROWSER-PROOF-12.md), [actual activation](evidence/reaudit/auth02-named-pilot-2026-10-20/frontend-public-activation-12.json).

## File versions

| File or release | SHA-256 / version |
|---|---|
| Older Identity API | `a0834b412c06263d1ca593de67cc2514471cf4fdd7a83c860608be998fc65fcb` |
| Member API | `30f6d81466d15fad9451445449682f359969b405e21a641a7cd4523ab863b5fd` |
| Member public authentication | `8340f026f68f5048bbe2e5fc4744f17366dcf134730d4349213c549319630019` |
| Member social authentication | `44680d3685415ec4ce209851f2ffa52cbe207f72e487e80543000ef0d920b709` |
| Member session handling | `a3f4cedfc79003abebbdaacc12e59eb82086b0b6e5534ed08eb817a54989585c` |
| Member pilot admission | `fefc124fb49131510b5daa801d810608ff09e6c1bdccef54ea72bdf07a9b8c62` |
| App/public namespace and entry | `auth02-34c8511dd5a2a5ad` / `d64151e0728796b61d396cb8c38d00f7bd8dc9c563975b42aa5caad86b02e268` |
| App nginx configuration | `949256d02fa4e26ba69e013cb717551c2e0fac7b16d9c80151632962b3f39a0b` |
| Public12 activation runner | `bc562d1910a6db000f7b6645bb62ae9565ff75640e6d921923c52830158ce932` |

The [version index](evidence/reaudit/auth02-named-pilot-2026-10-20/auth02-closeout-12/AUTH02-ACTIVE-VERSIONS-12.json), [installed source/continuity gate](evidence/reaudit/auth02-named-pilot-2026-10-20/auth02-closeout-12/app-browser-pass-11.json) and [candidate manifest](evidence/reaudit/auth02-named-pilot-2026-10-20/auth02-closeout-12/candidate-manifest-return-11.json) bind these files to the passing activation. No Git commit is invented. The actual member runner was `00ba41…`; later unexecuted recovery changes are not credited.

## Recovery and limits

Protected activation backups preserve the exact files and configuration. Public recovery uses `/root/liveuin-closeout-backups/AUTH02-FRONTEND-20261020T080803Z-3752686/state.json` to restore the preceding pointer; App can restore the prior working AUTH02 alias. Backend recovery uses reviewed closed fallbacks while preserving canonical stores and signer, never the unsafe preview implementation. Earlier stopped attempts and successful recoveries remain recorded. Public11's automated Cloudflare 1010 refusal was diagnosed without changing edge policy; public12 separately proved exact origin bytes and the normal browser journey. [Recovery and diagnosis](evidence/reaudit/auth02-named-pilot-2026-10-20/public-diagnosis-12/PUBLIC-EDGE-DIAGNOSIS-12.md).

**Public live charging is still off for the reviewed LiveUIN routes.** [Runtime evidence](evidence/reaudit/auth02-named-pilot-2026-10-20/payment-lock-auth02-1531.json) and its [provider-version reconciliation](evidence/reaudit/auth02-named-pilot-2026-10-20/provider-review-15/PROVIDER-CHANGE-REVIEW-15.md) retain their limits; sandbox setup is not live charging or payment readiness. AUTH02 created no charge or refund and did not change the accepted Stripe gate.

**Imported tenancies were not used and were not emailed.** Ecosystem boundaries were checked: LiveUIN public/private UI uses canonical Identity; Core/Trust/Ops retain durable product truth. No sibling theme or second truth store was introduced.

Google, recovery navigation, Partner and role UI remain AUTH03–AUTH06 in order. The Tenant footer's LocalPro labels remain AUTH06. Full named-role/case isolation, the staged R01 guard, a usable family case, signing, payments, commercial ACCEPT and P6 remain separate. This freeze does not open pilot admission to strangers or authorize publication. Only Ern publishes after the full release passes.
