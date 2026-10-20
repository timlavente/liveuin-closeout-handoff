# AUTH02 browser fixture: home review screen

The review screen is the expected existing case/runtime guard for this deliberately case-free fixture. It is not a failed password or failed canonical identity projection. No candidate, role or fixture permission was loosened.

The first recorded sequence was: resolve 401 before sign-in; incorrect password 401; correct password 200; canonical resolve 200 twice. No home, case or runtime API request occurred. The fixture projects one approved synthetic Tenant profile but `access.case_ids: []`, with no active case. Exact counters are retained in [browser-fixture-home-guard-status.json](browser-fixture-home-guard-status.json).

In the unchanged shared index, `Tj` enables its resident-runtime query only when a case, booking or stay ID exists. Without one, `Nu` returns `activeState: pending_review`, empty `allowedActions`, and hidden finance/support behavior. This deliberately does not manufacture a home or case.

In unchanged `ResidentAppShell-CQOxnRFw.js`:
- `ze` maps `/tenant/home` to the required action `home`.
- `K` returns `review` when a required action is neither allowed, hidden nor locked.
- `He` supplies “Home needs a quick review first” and the closed-home explanation.
- The same `ze` explicitly maps `/tenant/account` to `actions: []`; `K` allows an empty action list. The earlier `authRequired` check still rejects unauthenticated visitors.

## Existing logout controls

Use the same signed-in browser at `http://127.0.0.1:52541/tenant/account`. No extra fixture API response or case is required for this route. The unchanged account component reads the verified profile context and includes the existing “Sign out” button. Its original handler `W` was the small AUTH02 splice that now calls `auth02LogoutFromControl`.

The same account page has the existing account/profile-menu entry. Its menu “Sign out” callback is the other patched control in ResidentAppShell. A second fixture sign-in can exercise that separate control. Both must issue the signed logout POST, receive the fixture acknowledgment, clear the bridge, and reach welcome. Returning to the protected account route must fail canonical resolution after logout.

This verifies React routing and auth controls only. It does not prove the MVP home/case loop, production account approval, downstream Identity/Core mapping or production logout. Those proofs remain separate.

Evidence: baseline shared index SHA `2db8bfcb0aeecd9a975dde8192ca612f0d3f056d6c70e04173f5b4d27f4102fa`; shell SHA `32c543067b2dc28bb4b3346315fe490c1483f0a3a850ebce3fdc77c5942f89cd`; active candidate manifest SHA `c37ffe59eb8baae4915ff4203b42068007e1fc7cacd9e0f549607521b0a4fea3`. The fixture is a distinct non-deployable copy; its two host substitutions are documented in `browser-fixture/NOT-DEPLOYABLE.json`.
