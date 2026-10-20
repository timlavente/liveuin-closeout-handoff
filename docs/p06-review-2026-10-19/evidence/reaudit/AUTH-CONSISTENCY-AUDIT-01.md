# AUTH-CONSISTENCY-AUDIT-01

20 October 2026, Singapore time. Fresh public HTML:00:13:42; entry bundles:00:14:04; successful public-bundle retry and routed login chunks:00:14:36; nginx routing:00:15:52. Bounded read-only audit of the release's apex/www, App, Host, Ops and Partner entry paths. Root performed the accompanying browser checks. No login code, account, password reset, credential, private case or customer record was submitted/read in this audit.

**Finding: the login inconsistency is real. Public/member login is wired to a preview handler, while Host and Ops use their role-specific Core Identity email-code adapters. Partner's failed-access handoff drops its role and destination and lands on the generic member login.** These findings do not prove a successful login, an account bypass, email delivery, or role isolation.

## Observed doors and intended differences

| Surface | Published/observed entry | Current login component and method | Assessment |
| --- | --- | --- | --- |
| `liveuin.com` / `www.liveuin.com` | Same current HTML/bundle. Root opened the public home menu and followed **Log in** to `https://liveuin.com/login`. | “Welcome back”, “One login for Tenant and LocalPro”, Email, Password, Sign in, Continue with Google, Forgot? | The public link really reaches the defective generic component below. It is not merely unused code sitting in a bundle. The www homepage serves the identical bundle; www menu click was not separately rehearsed. |
| `app.liveuin.com` | HTTP root redirects to `/app/member`; client route maps that to tenant home. Earlier browser gate reaches member welcome and `/auth/sign-in`. Fresh route source confirms the same sign-in component/provider. | Generic Tenant/LocalPro email/password and Google interface. | The current served provider uses the preview challenge exchange, not the production password endpoint already routed on App. Own-family/case return and successful sign-in remain unproved. |
| `host.liveuin.com` | HTTP root redirects to `/host/onboarding`; existing gate supplies `/login?returnTo=…&role=host&surface=host`. Fresh route/bundle still map this to `WorkspaceSignIn`. | “Sign in to your Host workspace”; approved email; request and enter a six-digit code. | Role-specific wording/method is intentional. Backend binds the Host origin and its configured isolated workspace, then checks the approved owner membership. This is currently a single-owner pilot gate; it is not multi-host/test-host readiness proof. |
| `ops.liveuin.com` | HTTP root redirects to `/ops/login`. Root browser confirms current Ops screen. | “LiveUIN Core Identity”, approved Ops email, Challenge ID, one-time code; requested access defaults to Ops. | A dedicated staff gate is intentional. Role choice is a request, not an entitlement. Backend resolves existing workspace membership. Exposing Challenge ID is an owner-usability concern; it does not establish broken auth by itself. |
| `partner.liveuin.com` | HTTP root redirects to `/partner/dashboard`. Its current routed workspace guard checks same-origin session resolution and offers plain `/login` on an error. Prior rendered check observed exactly that closed/error state. | Plain `/login` has no agent role query, so it selects generic Tenant/LocalPro login. | Actual handoff inconsistency. Agent context and the intended destination are dropped. Current Partner nginx also lacks the Identity proxy routes used by this UI. No private agent data was displayed or opened. |

Different labels, destinations and access rules for staff, parent, agent and host are required. They need one coherent Core Identity and scope contract, not an identical-looking screen or automatic cross-role access. The persona/entitlement UI audit was read and applied. Existing shortcode/connector flows were not changed or expanded into this audit.

## Confirmed faults

1. **The reachable public/member password screen is not wired as a production password login.** In the served bundle, `/login` selects `ZR`; with no role query, it selects lazy `Login-Mh8o3oad.js`. That wrapper mounts `auth.sign-in-CQBkq3x9.js` under `Rj`, exported as `aq` (the Auth provider). `/auth/sign-in` mounts the same provider directly. `Rj.signIn` only checks that a password is nonempty, then sends an Identity challenge request with fixed `workspace_id="laijuzhu"`, `role="member"`. It expects the verification code to be returned with `local_preview_only`, and automatically verifies it. The entered password is not submitted for verification. This is an observed code contract, **not** a tested login bypass. On App, nginx already has a production `/api/core/identity/sessions/password` route to9098; this served UI instead calls `/login/challenges`, routed to9095.

2. **The displayed Google sign-in control has no functioning Google continuation in this component.** Its bound handler throws “Google sign-in is available only for Google accounts already connected to LiveUIN.” Root clicked it on the published public login and observed that message immediately, with no OAuth navigation. Account linkage is not checked by this handler before the error.

3. **The published password-recovery link is broken.** Root followed the public login's `Forgot?` link to `/auth/forgot-password`; after settling, the page showed404, “Oops! Page not found”, and Return to Home. No reset was requested.

4. **Partner loses the agent journey and lacks its needed identity routing.** `/partner/dashboard` mounts a workspace guard with `expectedRole="partner"`. Its normal unauthenticated branch preserves role and return path, but its error/forbidden links are plain `/login`. The latter selects member login rather than the existing agent-capable `WorkspaceSignIn` branch. Fresh Partner nginx has a static fallback, no `/api/core/identity/` proxy, and explicitly returns404 for `/api/ops/`. Both its session check and the existing agent email-code component therefore lack the mapped backend doors they require. These are routing/source findings, not invented endpoint POST tests.

5. **The public origin does not hand generic login to App's identity service.** The served request helper resolves browser API paths relative to the current origin. Apex/www nginx has no Identity prefix mapping for the generic member challenge path, and `/api/ops/` is blocked. Public login therefore lacks the production identity handoff already available on App. A page rendering200 cannot establish that its form works.

The native provider's sign-out handler also only clears its client-held session state and navigates to welcome; no server logout call appears in that handler. Server revocation/sign-out remains an explicit proof item, not a claimed completed test.

## Challenge, role and return-path contract

| Active component | Request / verify paths | Role/workspace inputs | Return behaviour |
| --- | --- | --- | --- |
| Generic public/member login | `/api/core/identity/login/challenges`; `/api/core/identity/login/challenges/{id}/verify` | Fixed member role and legacy `laijuzhu` workspace string; preview code required. | After its synthetic-style exchange, chooses tenant or LocalPro home. It does not implement an agent/family-case continuation contract. |
| Host `WorkspaceSignIn` | `/api/ops/auth/request_code`; `/api/ops/auth/verify-code` | Host maps to `landlord`, `operator_portal`, `host_workspace`. UI sends legacy `laijuzhu`; **backend overrides this from configured Host context and existing owner membership**, so the string alone is not evidence of cross-brand data leakage. | Preserves `returnTo` or `return_to`; only accepts a relative slash path and rejects protocol-relative `//`. Backend applies its own safe return logic. |
| Ops `OpsLogin` | Same browser-safe code adapters | UI requests workspace `liveuin`, one of `ops/ops_manager/super_admin`, surface `ops_command`. Backend resolves trusted existing role/scopes again at request and verification. | Defaults `/ops/command`; restricts destination to the same origin and `/ops/` or `/studio/`; rejects backslashes and foreign origins. |
| Agent-capable branch, not selected by Partner's plain error link | Same browser-safe code adapters | Partner maps to `agent`, `connect_admin`, `partner_workspace`; fixed legacy workspace in current component. | Can preserve role and destination when correctly selected. Its mere presence in the bundle is not proof that the published Partner handoff selects it or its backend is reachable. |

Host's request/verify exceptions reach9095 despite its general `/api/ops/` block. Ops API routing also reaches9095. The deployed Ops entry point removes legacy request/verify implementations and mounts the Core Identity compatibility routes. Do not treat the older `auth_api.py` implementation as the active owner merely because that file still exists. App's exact password/provider/session routes go to the separate production identity service9098; its remaining Identity prefix goes to9095. Partner has neither arrangement in the inspected vhost.

The deployed direct Core challenge-create/verify routes still call the local-preview challenge service. The service's returned-code contract matches the incorrect member UI expectation. This requires review in the existing auth work before any production-auth claim. We did not invoke these routes or establish exploitability against real accounts, and did not inspect identity/customer stores.

## Evidence and release boundary

Fresh evidence is in `reaudit/auth-audit/`:

- `entry-summary.json` and `entry-*.html`: exact redirects, timestamps, public entry HTML hashes.
- `bundle-summary.json`, `chunk-summary.json`: public asset URLs/status/hashes. Initial apex/www asset requests had an HTTP error; one bounded retry succeeded200 with the same bytes as App/Partner. **No missing-bundle fault is claimed.**
- `routed-auth-evidence.json`, `workspace-guard-excerpts.json`: component binding, actual handler, route selectors and offsets into the retained deployed bundles.
- `nginx-auth-routing.json`: six vhosts and named identity/login snippets, timestamps and source hashes.
- `identity-route-source.json`, `core_identity_api.py`, `core_identity_login.py`: deployed Core Identity route/adapter source and hashes. Baseline Ops entry point is `baseline-closeout/ops-main.py`.

Key served-source SHA256 values: shared apex/www/App/Partner index `2db8bfcb0aeecd9a975dde8192ca612f0d3f056d6c70e04173f5b4d27f4102fa`; Host index `095faa1491b4f1861fecc10ac46e98fad1df3ac69da8ef98dc4574d38dce57ac`; Ops index `cf52d5eac5bc895d94972c56552cb7d72c40e292d1f16b40e87356d5424e15ef`; active member sign-in chunk `064b97ed8469f57975c884c5306d457917ce906128a88d4ac630d3895a21a1f7`; Ops login chunk `270243cc0f6badd5b9943ffa751f6a4284a4e2163342d9e2a3f483be54ca75a7`; deployed Identity API `fcf8c612f2442ab05a8950523890806af7b89f88e9cbf801fcc5561ec1d6acc4`.

Use these findings to refine acceptance in the existing frozen auth/login work; they do not authorize reordering the queue or adding unrelated surfaces. Owner/test-account sign-in, allowed screen, refused screen and sign-out are still mandatory execution proofs. No auth method or account is marked passed by this audit.

Ecosystem boundary checked: LiveUIN public/private entry surfaces and canonical Core Identity only. No sibling theme, WeChat, connector or imported-tenancy work; no imported tenancy was read or contacted. No public-access switch, payment mode or production code/configuration was changed.
