# AUTH03 — truthful browser Google availability

Local deployment candidate only. AUTH02 is passed in `FREEZE-ISSUE-AUTH-002.md`, SHA256 `0891b096bc3bf94a14f42ef219ebf243657d78b3b2fc269a8758b44bd23dfe28`. This package implements only the next frozen row, AUTH03.

The browser sign-in page says: “Google sign-in is not available on this website yet. Use your email and password.” The Google action and its dead handler are removed. The defensive provider interface uses the same truthful message. Password, selected-profile authority, return handling, session hydration, logout and all other current browser modules remain byte-for-byte unchanged apart from namespace references. Native Google, provider services, flags, accounts and grants are untouched.

## Baseline and recovery

The current App nginx configuration is `949256d02fa4e26ba69e013cb717551c2e0fac7b16d9c80151632962b3f39a0b`. Replace only its current AUTH02 index alias with the AUTH03 alias. The full nginx comparison preserves every other route. Failure restores that working AUTH02 alias, never the older preview login. The current public target is `/var/www/liveuin-public-releases/liveuin-auth02-34c8511dd5a2a5ad`; public failure restores that exact target. Shared Partner HTML, Host, Ops and the association file remain pinned.

## Ordered execution by the close-out engineer

1. Verify and unpack the hash-pinned archive with `stage-private.py`. Run the pinned release controller's `stage` phase. This writes only immutable static files and a private recoverable state; it changes no active alias or pointer.
2. Create a fresh root-private backend gate bound to this candidate. Required phase: `backend_ready_for_app`; flags: `backend_candidate_verified`, `pilot_admission_closed`, `logout_revocation_proven`, `approved_named_account_ready`, `public_live_charging_off`, `auth02_frozen`, `google_browser_unavailable_approved`. Its `continuity_services` and `continuity_sources` must reflect verified current processes and files. The separately observed Ops restart requires a fresh bounded payment-lock classification; do not relabel old PID evidence as current.
3. Run `activate-app.py --state STATE --gate GATE --gate-sha256 SHA256`. It holds the original cooperative locks and preserves the tested eight-second readiness check: only the exact previous entry can be transient; the new entry must match its hash and carry no-store. Other failures trigger original exact-alias recovery.
4. Prove App browser routes `/login` and `/auth/sign-in`, including normal SPA navigation, truthful notice with no Google button or handler, allowed return continuation, password sign-in, canonical reload and sign-out/refusal. Record actual versus carried-forward evidence explicitly. Do not claim a Google provider round trip.
5. Create a separate root-private `app_browser_pass` gate bound to this candidate. Preserve the existing required auth flags and add `google_notice_visible` and `no_active_google_control`. Run `activate-public.py --state STATE --gate GATE --gate-sha256 SHA256`. The unchanged pointer controller validates the candidate and source boundaries; the strict TLS origin-only verifier requires exact host/SNI/certificate, loopback destination, status200 and exact entry bytes. It does not prove Cloudflare or the public browser journey.
6. Prove normal public browser handoffs from both `liveuin.com` and `www.liveuin.com` to App and the truthful Google notice. Freeze AUTH03 only after its actual proof passes. A failed proof stops this row.

The two existing cooperative locks remain `/var/lock/liveuin-resident-core-api.lock` and `/var/lock/liveuin-auth02-frontend.lock`. No backend restart or account/provider/payment request is performed by this package. It does not enable public admission or public live charging.

The touched layer is the LiveUIN browser public/private member UI. Core Identity stays authoritative; Core/Trust/Ops retain product truth. The ecosystem and persona boundary was checked. No sibling product, connector, imported tenancy, rent/deposit custody, AUTH04 recovery, AUTH05 Partner or AUTH06 role-screen work is included.
