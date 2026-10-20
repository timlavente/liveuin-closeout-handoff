# Actual public-browser handoff12 passed

20 October 2026, Singapore. The coordinating agent completed the normal browser checks after public12 activated. These are actual browser observations through the public edge, separate from the origin-only automated readiness result.

On `https://liveuin.com/`, a normal reload and header **Log in** opened `https://app.liveuin.com/auth/sign-in`. The named synthetic parent's existing password was accepted. The default `/tenant/home` remained safely at NEEDS REVIEW because it has no active case; no working family home or case is claimed. Opening the known `/tenant/account` showed Tenant and one profile; a full reload retained them. The [completed account screenshot](public-parent-account-12.png) was independently reviewed.

The account profile-menu **Sign out** returned to Welcome. Normal navigation to `https://www.liveuin.com/` then loaded the homepage, and its header **Log in** opened the App sign-in form. The [www handoff screenshot](public-www-app-handoff-12.png) was independently reviewed. Reopening App `/tenant/account` after sign-out was refused to Welcome with a validated return destination.

The screenshots show the resulting screens; the coordinating agent's browser observation supplies the URL/navigation sequence. No plaintext credential, factor, browser session header, case record or customer document was retained. No additional OTP was requested. The [final cleanup snapshot](parent-public-after-logout-12.json) at 16:46:49 Singapore shows each canonical/refresh store at total 7, active 0, revoked 7. This confirms cleanup, not a new standalone positive-before/after logout proof. Canonical revocation is already proven by the earlier actual API denials and both browser-control positive before/after counts, with unchanged auth/session/logout code. The [private reopening refusal screenshot](public-parent-logout-refused-12.png) was also independently reviewed.

Public12's [actual activation](../frontend-public-activation-12.json) had first matched exact candidate bytes on both apex/www origins with strict TLS, preserved backend continuity and changed no admission/payment switch. This actual browser sequence supplies the separate normal-edge handoff proof that its automated result deliberately required. The earlier public11 failure, original-pointer recovery and Cloudflare 1010 diagnosis remain retained; no security rule was changed.

This completes the bounded AUTH02 acceptance evidence. It does not pass Google, password-recovery navigation, Partner, role-navigation cleanup, all named-role/case isolation, family-case completion, payments, R01, P6 or publication. The visible LocalPro footer on Tenant remains with AUTH06.

Ecosystem boundary checked: LiveUIN public/private UI uses canonical Identity accounts, roles and entitlements; Core/Trust/Ops retain durable truth. Imported tenancies were not used or emailed. No charge, refund or public-admission opening occurred in this final proof.
