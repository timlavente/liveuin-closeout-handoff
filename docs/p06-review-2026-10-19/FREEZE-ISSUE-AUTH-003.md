# FREEZE-ISSUE-AUTH-003

**AUTH-03 passed — truthful Google availability.** 20 October 2026, Singapore.

The browser offered a Google button although its web OAuth flow was not configured. The form now says **“Google sign-in is not available on this website yet. Use your email and password.”** The active button and dead handler are removed. This fulfills the explicit unavailable/no-active-control alternative in [the frozen AUTH03 row](FREEZE-AUTH-REPAIR-01.md); it does not claim successful Google authentication.

## Proof

- The retained provider configuration identifies native Google mode, with browser redirect/secret inputs absent. No Google provider call, new OAuth app or native change was made. [Configuration evidence](evidence/reaudit/auth03-google-2026-10-20/google-web-presence-13.json).
- Normal App sign-in and direct `/login` showed the truthful notice with no active Google control. The named parent signed in with its existing password and allowed account return; full reload retained Tenant and one profile. Body sign-out returned to Welcome and private reopening was refused. [Actual App evidence](evidence/reaudit/auth03-google-2026-10-20/AUTH03-APP-PROOF-01.md).
- Exact App activation passed nginx configuration tests, backend/source continuity and candidate hash/no-store checks. [App activation](evidence/reaudit/auth03-google-2026-10-20/frontend-auth03-app-activation-01.json).
- Public activation passed both hostnames' strict-TLS origin checks, serving the exact candidate entry. These checks remain labelled origin-only. [Public activation](evidence/reaudit/auth03-google-2026-10-20/frontend-auth03-public-activation-01.json).
- Normal public browsers on **liveuin.com and www.liveuin.com** followed the visible header login link into App and showed the correct unavailable notice without a Google button. [Final browser proof and screenshots](evidence/reaudit/auth03-google-2026-10-20/AUTH03-PUBLIC-BROWSER-PROOF-01.md).
- Password, return handling, session/profile authority and logout code are unchanged; 360 files are identical. AUTH02 wrong-password/wrong-role, both logout controls, server revocation and stale-session/refresh results are carried forward, not claimed as rerun. [Exact delta](evidence/reaudit/auth03-google-2026-10-20/active-delta-results.json), [AUTH02 freeze](FREEZE-ISSUE-AUTH-002.md).

## File versions

| File or release | SHA-256 / version |
|---|---|
| Namespace | `auth03-d542aefd993107da` |
| App/public entry | `62ac4fcabd7e99e942fad05fec241d89e2c0654383f4afe3a83fd09ace1c8b95` |
| Sign-in JavaScript | `d94b4421e9da3c895abed9dd38be69f4a9bede3665ce9308589c072e45760734` |
| Shared runtime JavaScript | `7b39821d5cd7077115261838e63bbd63a120b4c001ba621f248549d1163013d3` |
| App nginx configuration | `2a1a3edcada383615ad0bc082567519315e7788a682bee822e6fd79750676c4d` |
| Candidate manifest | `785bfec58a76aeeea01484814285d6a43a1d7783a0c4a5c0d2156f1d25b57793` |
| Package manifest | `3d20846d5c80e253cf6f60b6a499b12dfeb30a60bfedd8b2a1ea11282b5d3ce3` |

The retained [candidate manifest](evidence/reaudit/auth03-google-2026-10-20/candidate-manifest.json), [package manifest](evidence/reaudit/auth03-google-2026-10-20/package-manifest.json) and [public gate](evidence/reaudit/auth03-google-2026-10-20/app-browser-pass-auth03-01.json) preserve exact files and continuity. No Git commit is invented.

## Recovery and limits

Protected recovery state is `/root/liveuin-closeout-backups/AUTH03-FRONTEND-20261020T091023Z-3784001/state.json`. The reviewed controller restores the exact working AUTH02 App alias or public pointer on failure, preserving unrelated routes. It retains both cooperative locks: `/var/lock/liveuin-resident-core-api.lock` and `/var/lock/liveuin-auth02-frontend.lock`. No backend restart, provider change or unsafe-preview restoration is part of this release. [Release/recovery record](evidence/reaudit/auth03-google-2026-10-20/RELEASE-README.md).

**Public live charging remains off for the reviewed LiveUIN routes.** The [fresh bounded classification](evidence/reaudit/auth03-google-2026-10-20/auth03-payment-lock-01.json) retains test-only Core credentials, disabled live rails and no legacy external dispatch; customer-card sandbox setup is not live charging. This is not universal payment-readiness proof. No charge, refund or public-admission/access switch changed.

**Imported tenancies were not used and were not emailed.** Ecosystem and persona boundaries were checked: this changes LiveUIN browser public/private login UI only. Canonical Identity owns accounts and entitlements; Core/Trust/Ops retain durable product truth. Native Google and sibling products remain unchanged.

AUTH04 recovery, AUTH05 Partner and AUTH06 role UI remain in order. Full role/case proofs, R01, family signing, payments, commercial ACCEPT and P6 are not passed by this note. Public access remains held for Ern's final publish action.
