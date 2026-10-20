# AUTH-02 local browser smoke, corrected candidate

20 October 2026, Singapore. **Local browser proof only; not deployed.**

Candidate manifest `ab0eabe75d33b8218792eaa247ea2da6be1bd28d7776125d6928850a7bda9bcf`, namespace `auth02-2c3dd7ac316e7cbe`. This successor includes the reviewed permission-projection correction. The separate loopback fixture at `http://127.0.0.1:53821` has a visible fixture-only notice and two explicitly documented host substitutions. It is not a deployable artifact.

In a separate in-app browser context, the synthetic test parent completed these checks through the visible controls:

- Wrong password: remained on sign-in with the plain rejection message.
- Correct password: reached the requested `/tenant/account` page with one approved Tenant profile.
- Reload: canonical resolution retained that account page.
- Ungranted LocalPro link: displayed ACCESS NEEDED and the locked-profile message.
- Account-page Sign out: returned to Welcome; reopening the account required sign-in and retained the safe return address.
- Welcome sign-in: retained the account return address; successful sign-in reached it.
- Account-menu Sign out: returned to Welcome; reopening the account again required sign-in.

`fixture-status-final-browser.json` records wrong-password 401, valid password/resolve 200, two logout 200 responses and subsequent resolve 401. Final state: **zero active sessions; two revoked sessions**. `signed-out-final-local.jpg` shows the closed private-route entry with its fixture notice.

The independent cross-contract test additionally passed the real canonical backend Tenant projection and rejected 16 mismatched binding, role, scope, entitlement and continuation cases. That source-level test is separate from these browser observations. The first candidate and its superseded browser result remain in `BROWSER-SMOKE-01.md`.

No production identity, email, family case, payment, imported tenancy or sibling product was used. The owner’s real Chrome Ops session remained separate. This does not pass the family case, signature or payment journey, production admission, or production named-account proof. The existing confusing Tenant/LocalPro navigation stays recorded for AUTH-06; locked navigation did not grant access.
