# AUTH03 App proof — truthful Google notice; public proof pending

20 October 2026, Singapore. **AUTH03 is not yet frozen as passed.** The frozen row explicitly allows an unavailable browser option without an active Google button when browser OAuth is not configured. This is the selected alternative; no Google provider round trip is claimed.

The App now says: “Google sign-in is not available on this website yet. Use your email and password.” The active Google button and its dead handler are removed, with the same truthful defensive message. Native Google, provider services/settings, accounts and grants are unchanged. The [exact delta](active-delta-results.json) changes two JavaScript files and their two entry references; 360 files are unchanged. Password, return handling, canonical hydration and logout bytes remain unchanged.

## Actual activation

The [actual App activation](frontend-auth03-app-activation-01.json) passed locked backend pins, full nginx tests and reload. Its readiness check first received the exact previous AUTH02 entry `d64151e0…` and then the exact AUTH03 entry `62ac4fcabd7e99e942fad05fec241d89e2c0654383f4afe3a83fd09ace1c8b95`, both HTTP 200 with no-store. The App nginx configuration is SHA-256 `2a1a3edcada383615ad0bc082567519315e7788a682bee822e6fd79750676c4d`; release namespace is `auth03-d542aefd993107da`. The public pointer did not change.

## Actual App browser checks

The coordinating agent completed these normal checks before 09:14:49UTC (17:14:49 Singapore). Its earlier 17:16 estimate was corrected; no exact action minute is invented.

- Welcome→sign-in preserved the allowed `/tenant/account` return; direct `/login` also showed the truthful notice with no Google button.
- The named synthetic parent's correct password opened the account; full reload retained Tenant with one profile.
- The body Sign out button returned to Welcome, and private account reopening was refused.

The [root observation](APP-BROWSER-ROOT-OBSERVATION-01.json) is the hash-bound source used by the public gate. The [separate retention observation](AUTH03-APP-BROWSER-PROOF-01.json) agrees with it. Three screenshots were independently viewed: [notice](app-google-unavailable-01.png), [account/reload](app-parent-return-reload-01.png), [logout/refusal](app-logout-refused-01.png). None exposes an entered password, factor or token.

Actual sign-out navigation is not relabelled as newly measured server revocation. AUTH02's wrong-password/wrong-role refusals, both logout controls, canonical revocation and stale-session/refresh denials are explicitly carried forward because their code is unchanged. No new provider, case or entitlement proof is claimed.

## Versions and next gate

Candidate manifest SHA-256: `785bfec58a76aeeea01484814285d6a43a1d7783a0c4a5c0d2156f1d25b57793`. Package manifest: `3d20846d5c80e253cf6f60b6a499b12dfeb30a60bfedd8b2a1ea11282b5d3ce3`. The [backend readiness gate](backend-ready-gate-auth03-01.json) retains current process/source continuity and the fresh bounded payment classification; it does not claim universal payment readiness.

Recovery state: `/root/liveuin-closeout-backups/AUTH03-FRONTEND-20261020T091023Z-3784001/state.json`. App failure restores the working AUTH02 alias; public failure restores the exact AUTH02 public pointer. No unsafe preview implementation is the recovery target.

**Public activation and normal apex/www browser handoffs remain pending in this observation.** AUTH03 cannot freeze until those checks pass. AUTH04 implementation has not begun.

Public live charging stays off for the reviewed LiveUIN routes; no charge/refund or admission switch changed. Imported tenancies were not used or emailed. Ecosystem and persona boundaries remain canonical LiveUIN Identity/Core/Trust/Ops; this repair changes only browser public/private login UI, with no sibling or native Google work.
