# PARENT-API-PROOF-08 — parent API and server logout passed

20 October 2026, Singapore time. The actual synthetic-parent API run completed at **15:32:10**. Its [safe result](PARENT-API-PROOF-08.json), SHA-256 `0fe24bd01adb3e6483df13b946907fdc9f11beac086d399966ab41507ede31e2`, records seven passed checks:

| Actual check | HTTP result |
|---|---|
| Wrong password refused | 401 |
| Correct password authenticated | 200 |
| Exact parent account, profile and workspace resolved through canonical Identity | 200 |
| Signed parent request refused by the existing Ops boundary | 401 |
| Proof session logged out and its refresh credential revoked | 200 |
| Logged-out session refused | 403 |
| Logged-out refresh credential refused | 401 |

All seven responses had `no-store`. The run reports zero test sessions left unconfirmed. No credential, account identifier, session header, factor or refresh token is included in this retained result.

The Ops probe used the separately checked existing staff-protected `OPTIONS https://ops.liveuin.com/api/core/ai/` boundary, without a request body, redirect following or response-body reading. Its actual result was **401**, not 403. This proves refusal at that checked boundary; it does not establish a 403 role-policy response, cross-service principal recognition, family-case isolation, or completion of R01's separate staged private-operation guard. The earlier invalid-limit audit route was not the proof route.

The separate onboarding session was then logged out at **15:32:17**: canonical logout returned 200 with `revoked: true`; attempting to resolve that same session returned 403, `identity_session_revoked`. The two allowlisted events are retained in [the onboarding logout snapshot](parent-onboarding-logout-08.jsonl). They are distinct from the session created and revoked inside the seven-check API proof.

Actual App-browser password entry, reload, the correct screen, wrong-role navigation and sign-out remain pending, as do case isolation and the other named-account proofs. App activation is a separate controlled step. This note does not pass AUTH02, R01, P6 or publication.

Core Identity remains authoritative for accounts, entitlements and sessions. No imported tenancy, real family case or sibling product was used. No payment or public-access switch was changed by this proof.
