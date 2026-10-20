# R01 identity probe and delivery trace — 01

Date: 20 October 2026 (Singapore). Additive read-only evidence; no frozen document, staged source, permission, account, service, payment flag or production application file was changed. No additional login attempt, email, credential inspection or customer-record read was performed by this source audit.

## R01 proof boundary

`FREEZE-PLAN-01.md:48` separates R01's API denial boundary from the completed staff desk and later real-account proofs. R05 retains Ern's real owner sign-in, approved own-case access, unrelated-document refusal and sign-out proof (`FREEZE-PLAN-01.md:25`).

The R01 entry report allows pre-release positive testing with backend spies (`evidence/reaudit/R01-ENTRY-REAUDIT-01.md:45–50`). It separately requires, after release, a scoped positive using an authorized synthetic/owner identity rather than a fabricated production credential (`:52`). Freeze line 11 and the staged package README lines 44/48 retain guarded allow/refuse and production-entry conditions. Isolated permit tests plus anonymous authority replies alone are not a completed live positive.

The owner declined an order amendment and offered an existing signed-in LiveUIN owner session. This preserves the frozen order. Server root/Tailscale access and possession of an email address are not LiveUIN platform authorization. Do not create a first-party test administrator, change a workspace/role grant, manufacture a signed credential or repair email delivery within R01.

## Validation-only live positive

Once an existing legitimate session has been supplied through its normal browser context, verify its actual canonical identity/role/workspace without exposing its credential. The current candidate permits the existing effective platform roles `ops_manager` / `super_admin` in `liveuin_first_party`; a client-supplied workspace or role is not a grant.

Use this bounded request on the actual guarded service:

`GET /api/core/admin/control-center/audit?limit=0`

With a qualifying verified session, the expected result is HTTP 422 with `Cache-Control: no-store`. The guard runs before FastAPI validation (`implementation/R01/candidate/home_api.py:243–270`); the existing audit parameter requires `limit >= 1` (`:1005–1008`), so validation rejects the request before `admin_control_audit` invokes its data service. The same request without a session or with forged credentials should return HTTP 401. Wrong canonical role/workspace should return HTTP 403. Record the exact deployed source and safe response status/detail, not the cookie/token.

This proves admission through the identity boundary and rejection at harmless input validation. It does not prove that the audit data service, staff desk or family case works. The staged test at `implementation/R01/tests/test_r01.py:311` already verifies that invalid audit input does not call the business service. The full staged tests cover the 21 routes; the live validation probe must not be presented as 21 functional data reads.

Avoid using the developer `/docs` route as a supposedly static positive: `deploy/developer_portal_service.py:173–175` calls `_developer_workspace_snapshot()`, which reads API/webhook workspace metadata. No real family or other private records are needed for the validation probe.

## Exact browser delivery trace

The parent observed one normal Request code attempt for the owner-provided email on `https://ops.liveuin.com/ops/login`; the page returned `email_code_delivery_unavailable`. No code/session was obtained. This source audit did not repeat the attempt.

Fresh public HTML names `/ops/login/assets/index-BAq4vWNL.js`. Its SHA-256 is:

`cf52d5eac5bc895d94972c56552cb7d72c40e292d1f16b40e87356d5424e15ef`

That main module lazily imports `./OpsLogin-BLxReVVn.js`. The exact deployed chunk is:

`https://ops.liveuin.com/ops/login/assets/OpsLogin-BLxReVVn.js`

SHA-256:

`270243cc0f6badd5b9943ffa751f6a4284a4e2163342d9e2a3f483be54ca75a7`

The 5,907-byte chunk contains the visible labels “Approved Ops email” and “Request code”, and submits POST `/api/ops/auth/request_code` with browser credentials. Its verification route is `/api/ops/auth/verify-code`. The client supplies workspace `liveuin` and a selected role; these inputs do not establish the canonical session's effective entitlement. Initial absence of these strings from the main module is explained by the lazy import; there is no established cache-mismatch finding.

The pinned deployed Ops nginx configuration (`reaudit/source/ops.liveuin.com.conf:301–306`) maps `/api/ops/auth/request_code` to `http://127.0.0.1:9095/api/ops/auth/request_code`. The actual Ops assembly copy (`baseline-closeout/ops-main.py:449–466`, source `/opt/liveuin/ops_backend/app/main.py`) removes the earlier request/verify aliases and selects the Core identity router for them.

Read-only source inspection of `/opt/liveuin/deploy/core_identity_api.py` returned SHA-256:

`fcf8c612f2442ab05a8950523890806af7b89f88e9cbf801fcc5561ec1d6acc4`

Its `_otp_gateway_deliver` starts at line 121. It returns the same unavailable detail when:

- `OTP_GATEWAY_URL` or the internal-token setting is absent (line 126);
- transport/HTTP or JSON processing fails (line 148); or
- the gateway reply is not an object with both `ok is True` and `sent is True` (line 151).

`browser_auth_request_code` returns the controlled unavailable response at line 306. These branches were read as source; no setting or secret value was read, no `/send` request was made and no delivery/customer log was inspected.

The separate 9098 Identity release is different: `/opt/liveuin-identity-public/current/deploy/core_identity_api.py` resolves to `/opt/liveuin-identity-public/releases/20261016-1e9dca6/deploy/core_identity_api.py`, SHA-256 `35cb1b2ed434eec9bce941eb0f4a6642d28a88ffb005cbec8cd4d4662f436132`. It has neither this error literal nor `_otp_gateway_deliver`. Do not attribute the observed Ops error to that separate source or to the differing local working file.

## Causal limit and stop

The visible error proves that delivery was not confirmed through the normal Ops request. It does not identify which helper branch failed, prove SMTP alone failed, or show that the email address lacks an account. The exact effective gateway configuration, gateway response and underlying delivery cause remain unconfirmed. No account/permission conclusion should be inferred from this failure.

The owner-provided existing session is the current R01 path. Email investigation is stopped; no R05 repair or order change is included. Root will independently establish deployment/recovery access, the production charging invariant and the legitimate session proof. No FREEZE-ISSUE is issued by this note.

Ecosystem boundary retained: LiveUIN Identity is the authentication authority, Core/Trust/Ops own product truth, and no sibling, connector or imported-tenancy workflow was touched.
