# AUTH06 observation — Tenant sees LocalPro navigation

20 October 2026. This is additional evidence for the **existing AUTH06 row**, not a new issue that jumps the frozen queue. No UI or entitlement change was made.

The actual named synthetic parent's `/tenant/account` page shows Tenant and one ready profile, but its footer includes EARN, TASKS and PAYOUTS. Opening `/localpro/home` displays ACCESS NEEDED and says LocalPro access is required. See [the Tenant account](app-parent-reload-passed.png) and [the locked LocalPro destination](app-parent-localpro-refused.png).

The observed problem is misleading navigation for the selected persona. The checked LocalPro workflow remained locked. Do not “fix” the navigation by granting another role or removing its guard.

| Persona/entitlement check | Recorded boundary |
|---|---|
| Persona | Named synthetic parent using the Tenant member profile |
| Surface | Private App at `app.liveuin.com` |
| Role and workspace | Verified Tenant profile; canonical public Identity workspace `liveuin-public` in the separate API proof |
| Entitlement | Tenant access only; LocalPro was not granted |
| Plan and quota | Not changed or inferred by this observation |
| Data scope | The synthetic account screen and locked route only; no family-case data opened |
| Shortcode parity | No shortcode or connector output changed |
| LiveUIN parity | Menus and destinations should agree with the canonical selected profile |
| Locked state | LocalPro remains ACCESS NEEDED until properly authorized |
| Prohibited exposure | Other personas' tasks/payouts, unrelated cases and staff controls |
| Canonical owner | Core Identity for profile/session authority; Core/Trust/Ops for durable product records |

Apply the existing persona-entitlement audit and AUTH06 scope when that row becomes active: reconcile footer/menu destinations with the verified selected profile while preserving locked states. The family journey remains on App for this release under Ern's explicit scope. No sibling product becomes the account, case or payment owner.
