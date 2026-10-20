# LiveUIN sign-in check — 20 October 2026

**The reported problems are confirmed. Authentication remains a release blocker. No repair or deployment is claimed by this check.**

| What a person encounters | What the fresh check established | Existing release work |
| --- | --- | --- |
| Owner cannot receive an Ops sign-in code | The running Ops service points to its code-delivery gateway, but that gateway is stopped and refuses connections. Both required connection settings are present. This explains the observed error; why the service stopped and whether downstream email delivery is healthy remain unproved. | R05 owner authentication; currently blocks R01's legitimate signed-in proof |
| Public/member form asks for a password | The actual served form only checks that the password box is nonempty. Its bound handler uses a preview challenge exchange instead of submitting the password for verification. It expects a returned preview code and uses a fixed legacy workspace. No successful login or account bypass was attempted or established. | R08 and R16; production authentication must be proved before publication |
| Continue with Google appears available | The current handler immediately displays a message instead of starting Google sign-in. It does not first verify whether the account is connected. Browser behaviour and served code agree. | R16 |
| Forgot? should recover access | Following the published link reaches “404 — Oops! Page not found”. No reset was requested. | R16 |
| Agent tries to open the Partner workspace | Its failed-access link sends the agent to the generic Tenant/LocalPro login and drops the intended destination. The inspected Partner server routing also lacks the identity routes those screens need. | R07 and R16 |
| Host and staff see different code-entry forms | Host uses an email-first workspace form. Ops exposes Challenge ID, code entry, technical language and an internal error. Different role destinations are valid; delivery, session checks, recovery and explanations still need to agree. | R05–R09 and R16 |

The public login also makes same-origin identity calls without the required public-to-App handoff. App has production identity endpoints, but the displayed generic form does not use the production password endpoint. This is a connection and implementation problem, not something solved by making the pages look alike.

The required result is one verified LiveUIN account/session system, with the appropriate owner, staff, parent, agent and host destinations and server-enforced record access. Each supported sign-in method must work; unavailable methods must not present themselves as usable. Technical challenge IDs stay inside the product. Failed delivery must give a clear recovery path. Sign-out must invalidate access, not merely change the displayed page. None of that is marked passed by this audit.

## Browser observations

- Public home → menu → Log in → `https://liveuin.com/login`: Email/Password, Google button and Forgot? link.
- Google button: immediate fixed message; no Google continuation.
- Forgot? → `https://liveuin.com/auth/forgot-password`: rendered 404.
- App root → member welcome → I already have an account → `/auth/sign-in`: same generic password/Google form; the welcome link drops the visible role/return parameters.
- Host root → `/login?returnTo=%2Fhost%2Fonboarding&role=host&surface=host`: approved workspace email and Send verification code. No code was requested.
- Partner root → `/partner/dashboard`: closed access-error screen → `/login`: generic Tenant/LocalPro form. No agent records were opened.
- Ops owner page: existing `email_code_delivery_unavailable` remains visible. No additional request was sent during this check.

Source hashes, exact active handlers, routing and limits are in the [detailed consistency audit](evidence/reaudit/AUTH-CONSISTENCY-AUDIT-01.md). The [confirmed delivery cause](evidence/auth-check-2026-10-20/OTP-CAUSE-CONFIRMED-01.md) is backed by a nonsecret classification of the actual process and a no-payload connection check. Credential values and customer records were not recorded.

## Frozen-order consequence

Ern's latest decision remains to keep the frozen order and use an existing legitimate owner session. The sign-in dependency amendment is still unaccepted. This request authorised checking the reported failure and inconsistencies; this read-only audit has not been treated as permission to reorder the frozen repairs or turn on the stopped service.

R01 remains staged and unpassed. Its 678 isolated checks do not replace a legitimate live signed-in check. No FREEZE-ISSUE-001 or publish sheet is issued. The original frozen files remain unchanged; these findings are evidence against the existing auth/login rows, not completed fixes.

Ecosystem boundary checked: the inspected surfaces are LiveUIN public UI/private apps and the Core Identity delivery boundary. Core/Trust/Ops retain product ownership. No sibling theme, connector, WeChat, imported tenancy, payment setting or public-access switch was changed. Imported tenancies were not used or emailed. The accepted Stripe readiness gate remains unchanged.
