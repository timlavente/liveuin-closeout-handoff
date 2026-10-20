# AUTH03–AUTH06 — read-only preparation

20 October 2026, Singapore. No later-row implementation, provider call, account read or production mutation was performed. AUTH02 remains active. Account existence and membership are being audited separately; the [approved account decision](AUTH-PILOT-ACCOUNT-DECISION-02.md) does not grant permissions.

## Evidence freshness and limits

Four exact nonsecret files were reread from the existing host at 12:37 Singapore: the two deployed Google OAuth modules and App/Partner nginx configurations. [Fresh metadata](evidence/reaudit/auth03-06-preparation-2026-10-20/fresh-source-metadata.json) records paths, time, sizes and hashes. Partner still matches the earlier 51cae8f2 routing baseline; App is now a98bf4fe and must not be overwritten with the earlier dd2a557b copy. Root owns the current App merge for AUTH02. Both Google OAuth modules match b708f7e2. No product module was imported.

The served UI findings remain the explicitly dated 00:13–00:15 audit in [AUTH-CONSISTENCY-AUDIT-01](evidence/reaudit/AUTH-CONSISTENCY-AUDIT-01.md). The nonsecret provider configuration classification is the 00:45 snapshot in [auth02-runtime-compatibility.json](evidence/reaudit/auth-repair-map/auth02-runtime-compatibility.json), not a fresh 12:37 process read. Reclassify only the selected provider's configured-presence booleans at AUTH03 entry. No broad provider-status request was made: the inspected handler also evaluates Apple JWKS/secret readiness and identity-graph integrity, so it is not a side-effect-free Google-only configuration probe.

## AUTH03 — truthful Google option

The published web handler throws the linked-account message immediately without checking linkage or opening Google. The existing 9098 source supports native provider credentials, but the last bounded runtime classification has native-ID-token readiness true and public Google enabled while web redirect URI, client-secret reference and exchange/callback readiness are absent. These native settings do not establish a configured browser OAuth journey. The resident native helper's web implementation itself reports provider unavailable.

A separate existing browser OAuth flow is present in [the deployed Google module](evidence/reaudit/auth03-06-preparation-2026-10-20/ops-google-oauth.py): `_google_config` at 534, `google_authorization_start` at 762 and `_link_identity_and_issue_session` at 1075. It creates server state/nonce, uses the approved OAuth app and checks workspace membership before issuing a session. It serves the existing Ops/connector path; its presence and App nginx mapping do not prove compatibility with 9098 member account/profile projection. Do not relabel its operator default as a public member grant or reuse an Ops cookie as member proof.

Smallest supported fix when this row begins: if the selected public web provider still has no configured, approved flow, replace the active fake Google control with an explicit unavailable state, as AUTH03 already permits. If the exact approved web flow is configured, wire only that flow and prove callback/state/nonce refusal, canonical account/profile mapping and safe return. No new OAuth app, new provider, expanded scopes or account grant is needed or authorized. Existing native Google capability must not be disabled merely to correct the website button.

## AUTH04 — existing password recovery, missing reachable page

App's current nginx already routes password-reset paths to the member Identity service. Retained `core_identity_api.py` exposes the request handler (202) at 842, verify at 851 and complete at 861. Retained `core_identity_public.py` implements request at 1413, verify at 1475 and complete at 1503; the exact source is in [the retained map](evidence/reaudit/auth-repair-map/core_identity_public.py). The reference resident auth context has matching client methods at 393–451; it is contract evidence, not permission to replace the deployed application wholesale.

The supported sequence is email request with an idempotency key; delivered code verification using the returned reset identifier; then a one-time reset token and new password. Request acknowledgements are deliberately the same for eligible and ineligible accounts. The completion path changes the password and attempts session/refresh revocation. Those operations are mutations and were not invoked in this preparation.

Smallest supported fix: mount the missing `/auth/forgot-password` route around those existing calls, keep reset identifiers/tokens internal and show one generic acknowledgement. Use the current signed-session/revocation contract from AUTH02, preserve safe return and fail honestly if delivery or completion fails. Prove unknown-account parity, invalid/expired/reused code/token refusal and old-session rejection in isolated tests; perform an actual reset only on a specifically authorized synthetic account when the row is active. Ops/Host email-code users should return to their existing code journey instead of being told to reset a nonexistent password. No new credential store or owner password reset is implied.

## AUTH05 — Partner routing and agent authority

The [fresh Partner vhost](evidence/reaudit/auth03-06-preparation-2026-10-20/partner-current.conf) still sends root to `/partner/dashboard`, serves the shared original HTML and has no Identity proxy. It blocks `/api/ops/` and otherwise falls through to static SPA routing. The retained UI audit shows the Partner guard's error/forbidden links use plain `/login`, losing role and return destination; its normal unauthenticated branch preserves them.

The existing `WorkspaceSignIn` agent branch requests `agent`/`connect_admin`/`partner_workspace`. That branch is not proof of a supported server path. The now-proven 9095 component intentionally allows only existing membership-bound Ops/Host compatibility paths; merely proxying the old Partner request would still be refused. Do not undo this closure or accept a client role to make the page advance.

Smallest supported fix: preserve an allowlisted Partner destination in every login/error path, connect the exact canonical Identity/session door, and gate the destination on a server-approved agent profile/membership. Establish the existing account/workspace mapping for `test.agent` before selecting the adapter; use a narrowly membership-bound path if required, not a generic challenge issuer. A Tenant or Host sign-in must not become agent authority. Only the own-leads/share/commission-status slice required by this release is in scope. No general Partner OS, other-agent records, staff switch or new privilege is opened.

## AUTH06 — clear steps, verified destinations

| Persona/account purpose | Existing surface/target | Required authority and locked state |
|---|---|---|
| Real owner / Ops operator / Ops admin | `ops.liveuin.com/ops/login` → permitted `/ops/command` or existing approved destination | Existing trusted role/workspace; internal challenge ID stays hidden. A requested role is not a grant. No unrelated private documents. |
| Owner acting as Host; separate synthetic Host | `host.liveuin.com` → own Host onboarding/listing journey | Approved Host membership and own listing only. Preserve the real owner's other established access. Other hosts and payout approval remain refused. |
| Synthetic parent/member | App's real sign-in → permitted member account/case destination | Server-approved profile and test-case scope only. Staff/agent/other-case screens remain closed. |
| Synthetic agent | `partner.liveuin.com/partner/dashboard` with preserved return | Own approved agent membership and own lead/case/commission status. No other agents or staff switches. |

Keep the existing design. Hide challenge IDs in component state; show clear request-code, enter-code, resend/error and sign-out steps. Reconcile footer/menu destinations with the canonical selected profile. The local AUTH02 fixture showed Tenant account footer links to LocalPro-only pages; those pages remained locked, but the misleading links belong in AUTH06 rather than weakening the guard. Recheck delivered-factor failures, allowed/blocked returns, reload and both visible logout controls in actual role browsers after their earlier rows pass.

## Boundary and next action

The LiveUIN README, sitemap/P0–P6 handoff, tracker, persona-entitlement audit, Laijuzhu blueprint, cross-project boundary audit and IGEMA blueprint were checked. This work concerns public/private UI entry and the canonical Core Identity API. No shortcode changes are proposed; any existing handoff must preserve the same workspace, plan/quota, record scope and lock state. The current release's family journey remains on App as required by Ern, despite older sibling-brand family examples. No sibling or channel becomes an identity/case/payment owner.

Finish AUTH02 and its named-account/logout proof first. Then take AUTH03, AUTH04, AUTH05 and AUTH06 in their frozen order, refreshing only their relevant exact runtime baseline before mutation. This preparation is neither a passed row nor a new feature register. Public live charging remains off; imported tenancies were not used or emailed.
