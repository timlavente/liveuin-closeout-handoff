# AUTH-02 local browser smoke, first candidate

20 October 2026, Singapore. This is an isolated synthetic fixture, not a production account or a deployment pass.

Candidate manifest tested: `c37ffe59eb8baae4915ff4203b42068007e1fc7cacd9e0f549607521b0a4fea3`, namespace `auth02-262471dd6d78da5f`. The fixture runs at `http://127.0.0.1:52541` and carries a visible LOCAL AUTH02 FIXTURE ONLY notice. Its separate non-deployable manifest records two loopback/host-classification substitutions. The deployed candidate does not contain those substitutions.

The CUA-controlled in-app browser used only `test.parent@auth02.invalid`, with a synthetic fixture password. It was separate from the real owner's Chrome Ops session. No production request, account, code delivery, case, family record or payment was involved.

Observed steps:

1. A wrong password stayed on sign-in and displayed a plain failure message; fixture recorded password 401.
2. The correct password navigated to the preserved `/tenant/home` destination. Canonical resolve returned 200. Reload resolved again.
3. Home displayed its existing review state because this fixture has no case or permitted home action. No home/case API was called; this does not prove a usable home or case journey.
4. `/tenant/account` opened with one approved Tenant profile and the existing account controls.
5. The visible EARN link led to `/localpro/home`, which showed ACCESS NEEDED and said the profile was locked. It did not grant LocalPro access.
6. The account page's Sign out button returned to Welcome. Reopening `/tenant/account` required sign-in and preserved that allowed return destination. Fixture recorded logout 200 and subsequent resolve 401.
7. The Welcome sign-in link preserved `/tenant/account`; successful sign-in returned there.
8. The account/profile menu's separate Sign out button also returned to Welcome. Reopening the private account again required sign-in; fixture recorded the second logout 200 and resolve 401.

Final fixture counters: two revoked sessions, zero active sessions. See `fixture-status-after-browser.json`. Screenshot: `signed-out-local.jpg`.

The account footer showed LocalPro navigation while Tenant was the only granted profile; the destination refused access correctly. This observed UI inconsistency belongs to the already frozen AUTH-06 consistency row. The default Home review state and empty case links are not passed as the MVP case journey. Google and recovery remain their own uncompleted rows.

An independent review subsequently found permission-projection mismatches in this candidate. Its successor requires a fresh browser smoke; this record is retained as history and must not be cited as proof of untested successor bytes.

Ecosystem boundary checked: public/private LiveUIN UI with canonical Identity authority. No sibling product, imported tenancy or live-charge setting was changed.
