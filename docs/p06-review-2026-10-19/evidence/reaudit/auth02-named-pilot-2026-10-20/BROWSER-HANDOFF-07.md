# BROWSER-HANDOFF-07 — real parent email verified and onboarding completed

20 October 2026, Singapore time. This additive record succeeds the pending-factor status in BROWSER-HANDOFF-06. It is **not an AUTH02 pass**, proof of every role, a completed case journey or permission to publish.

The coordinating agent reported that the owner's normal browser submission completed the synthetic parent's real canonical email verification at **15:29:32**. The existing user-entered field was retained by the browser; the agent did not retrieve the factor or ask the owner for another code. The canonical response returned HTTP 200, `authenticated`, and the next action `complete_profile`.

The normal profile update then returned HTTP 200 at **15:29:47**, with the next action `complete_onboarding`. Normal onboarding returned HTTP 200 at **15:29:52**, status `tenant_active`, next action `tenant_home`, and the authorized profile `tenant`. These responses are retained in [the sanitized lifecycle snapshot](parent-lifecycle-through-onboarding-07.jsonl). No manual account verification or direct database grant was used.

The [browser screenshot](parent-email-verification-passed.png) shows the real local handoff's successful verification message. It includes the already approved mailbox instructions but no factor, password, registration identifier, session header or token. Caption: **“Real synthetic-parent email verification succeeded through canonical LiveUIN Identity; full password, permission, logout and App-browser proof remains pending.”**

## Local runtime correction

The earlier generic failure did not establish that the owner entered a wrong code. The local helper was running under Frameworks Python 3.13, whose certificate trust store could not verify the service issuer. A data-free HTTPS OPTIONS comparison reported `URLError` caused by `SSLCertVerificationError`, verification code 20, under that interpreter. Homebrew Python verified TLS and received the expected HTTP 405 JSON response. These comparison results were reported by the coordinating agent; this evidence-retention step made no network request.

The coordinating agent stopped only the identified old local helper process and launched the same handoff explicitly with `/opt/homebrew/opt/python@3.13/bin/python3.13 -u`. The handoff version used was SHA-256 `982ba742c52a226949b3952b1c4b2750cbb0621cdd35d2ca9304b23167638d2e`. Its added failure logging records only the exception class. Certificate verification, HTTPS, Host/Origin/CSRF/expiry checks, the single-verification lock and canonical verification contract remain in force. No production service or TLS policy was changed, and certificate checks were not disabled.

The earlier separate dummy-browser result remains retained as BROWSER-HANDOFF-06; it is not credited as this real verification. The [transport diagnosis](VERIFICATION-TRANSPORT-DIAGNOSIS-07.md) explains the distinction.

## Remaining proof

Actual password rejection and success, exact canonical account/profile/session resolution, staff-access refusal, secure logout, stale-session and refresh refusal, and the real App browser's reload/role/sign-out behaviour remain to be completed. The prepared API proof and App frontend activation are not claimed as passed here. Family-case isolation, remaining named roles, R01 and the broader release remain open.

Core Identity remains the account, entitlement and session authority. This work concerns the LiveUIN private-app authentication flow and its temporary local verification handoff. No imported tenancy or sibling product was used; no payment or public-access switch was changed.
