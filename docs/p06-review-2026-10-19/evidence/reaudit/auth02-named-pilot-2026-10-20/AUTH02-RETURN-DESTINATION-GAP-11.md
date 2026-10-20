# AUTH02 — preserve the requested account destination through Welcome

Observed 20 October 2026 in the actual App browser. This is an unresolved acceptance condition within the current AUTH02 row; it does not add a row or change the freeze order.

After sign-out, reopening `/tenant/account` correctly reached Welcome with the allowed absolute App destination in `returnTo`. The Welcome sign-in links omitted that query. A normal subsequent sign-in consequently opened `/tenant/home`, not the account page the person had requested. The [observed destination](app-return-destination-lost.png) displayed NEEDS REVIEW and remained closed; no family/home data was accessed.

The required result is straightforward: preserve the allowed App return destination through Welcome and the existing sign-in entry, then let canonical profile/role checks decide access. The same browser sequence must finish at `/tenant/account` after a valid sign-in. Untrusted external destinations and destinations outside the verified role must remain refused; the repair must not grant a role, bypass the locked home state or create another identity store.

The `frontend-return-11` candidate was local only at this observation. No deployment or passed return-path test is credited here. AUTH02 must not be frozen, and the public frontend must not be activated, until the remaining repair and its actual proof pass.

Both browser logout controls have separate positive canonical revocation evidence in [APP-BROWSER-LOGOUT-11.md](APP-BROWSER-LOGOUT-11.md). The previously observed Tenant/LocalPro navigation mismatch remains in the later AUTH06 row; it is not folded into this fix.
