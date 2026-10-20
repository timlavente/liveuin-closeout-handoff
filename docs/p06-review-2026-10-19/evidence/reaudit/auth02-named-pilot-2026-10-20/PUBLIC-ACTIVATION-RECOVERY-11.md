# Public activation 11 stopped; original pointer recovered

20 October 2026, Singapore. **AUTH02 remains open.** The public login activation stopped with HTTP403; its recovery restored the original public pointer. The App return11 deployment and its earlier actual browser proof remain in place. No successful public-to-App handoff or AUTH02 freeze is claimed.

The [public gate installation result](public-gate-install-result-11.json) passed before activation: 18 reviewed source versions and four service-continuity checks matched, and the App browser gate SHA-256 was `92b0ed0380b87ca59bb2443c8aa73c1e24d0a6a176dda077738d87c5ea35fed8`. Installing that proof gate changed no production configuration or service.

The [actual activation result](frontend-public-activation-11.json), SHA-256 `36f4d5f2809957d6b92bacdd19b92bb7c5f55d65138ebb5783b30ef275593958`, reports:

- Locked backend continuity passed.
- The attempt stopped with `public_activation_failed_old_pointer_restored` and `HTTPError`403.
- `original_public_pointer_recovery` entered and passed.
- No authentication or product completion was claimed.

This retained output does not identify the exact failing response URL or establish the cause of the403. Diagnosis remains read-only; no presumed permission, route or cache fix is credited.

The coordinating agent also reported an administrator-console connection loss before the installer initially ran. The result was confirmed absent, then the existing Tailscale/Google session was reauthenticated through its normal flow. No grant change was made. The subsequent successful gate installation is the recorded operation; the connection interruption is not a failed product login or a reason to bypass an access control.

The prior [App continuation and logout proof](APP-RETURN-CONTINUATION-11.md) remains valid within its recorded scope. The public frontend is on its restored original pointer, so this failed attempt does not fulfill the frozen requirement for the published public login. The issue must stay open until the cause is resolved within AUTH02 and actual public activation/handoff evidence passes. AUTH03–AUTH06 retain their existing order.

The ecosystem boundary remains unchanged: LiveUIN public/member UI consumes canonical Identity; Core/Trust/Ops retain product truth. No imported tenancies were used or emailed. This retention changed no service, admission, payment or public-access switch, and makes no P6/publication claim.
