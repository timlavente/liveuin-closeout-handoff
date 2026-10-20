# App login source reconciliation — 21 October 2026

The owner's correction is confirmed. The browser page at `https://app.liveuin.com/auth/sign-in` is not the latest accepted App login implementation. The current native App already has a recovery screen. Neither a working native screen nor a source file proves that the browser route works.

## What was checked

- Current App source: `/Users/Vivian/liveuin-resident-app`, branch `gb/liveuin-finish-publish-2026-10`. Observed HEAD: `ebf37a3` (the payment-route recovery commit). This checkout has other work in progress and was not changed.
- Accepted authentication source: `47f648baa35af2c8e320b4677f0a25ad69117cbd`, recorded in `docs/LIVEUIN-RESIDENT-AUTH-FREEZE-20261019.json`. The acceptance records Ern's email recovery/password, Apple and Google journeys on the native App.
- All 34 full-file hashes in that freeze match current source. The repository's own `auth:freeze:check` also returns `AUTH FREEZE: PRESERVED`, including its protected source/contract checks. Generated payload and installed-binary parity are outside that check.
- The current browser entry imports `src/native-lovable/routes/auth.sign-in.tsx`. It does not mount the existing `/auth/forgot-password` component. The separate native entry does mount it.
- `src/native-lovable/routes/auth.forgot-password.tsx` implements the existing Core request → code verification → password completion contract. A second recovery product is unnecessary.
- `src/lib/residentSocialAuth.ts` uses native provider bridges. Its browser bridge throws `provider_unavailable`. Native Apple/Google acceptance therefore does not prove browser OAuth readiness. AUTH03's browser-only unavailable notice remains truthful.
- On 21 October the actual browser followed **Forgot?** from the sign-in form and displayed **404 / Oops! Page not found**. [Screenshot](evidence/shared-handoff-2026-10-21/recovery-still-404.png).
- The server's retained AUTH03 App entry still hashes to `62ac4fcabd7e99e942fad05fec241d89e2c0654383f4afe3a83fd09ace1c8b95`; the public pointer still selects `liveuin-auth03-d542aefd993107da`. This is a bounded read, not a fresh complete runtime/payment audit.

## Coordination and availability

The owner explicitly requested confirmation with **Complete LiveUIN iPhone app**. The previous coordination requests were sent to that chat. Although the chat read tool was unavailable on this pass, the other work subsequently produced `docs/APP-LOGIN-COORDINATION-20261021.md` in the current App repository. A copy is retained in this handoff. It confirms the accepted native source, the separate browser contract, the existing recovery component and preservation of the AUTH03 entry. It also records that its five payment routes changed the nginx configuration to `e9a65aeccfaf1387f5ae05dc0923559aaf97e5ca6ae268efcdc4cb4a85a9d3b0`; the earlier AUTH03 proxy hash must not be treated as the latest complete configuration.

The App checkout subsequently advanced to `76f1e88` for test-case admission handling. That does not change the accepted native authentication baseline. The source freeze passed, and the existing recovery component's five isolated tests passed. These are source/component checks, not a production browser recovery pass.

GitHub's commit endpoint returned 422 for the accepted source commit in `timlavente/liveuin-resident-app`. It is present locally but was not retrievable from that remote at this check. The shared handoff therefore contains a checksum-verified snapshot of the accepted auth files and the relevant current browser/native route files, labelled as a reference snapshot rather than a new canonical repository or deployed release.

## AUTH04 remains the next repair

Reuse the existing accepted recovery component and its canonical Core contract through a browser-only route binding. Preserve AUTH02's real credential validation, safe return handling, canonical session/profile authority and server sign-out. Preserve AUTH03's truthful browser provider state. Do not deploy the entire native build over the public website, rewrite the native acceptance manifest, restore the preview exchange, or replace the newer shared server/payment routes with an old configuration.

Before activation, reconcile the exact active source/configuration, verify recovery expiry/reuse and revocation behaviour in isolated tests, retain an exact backup and prove restoration. Then prove the visible browser link and safe, non-enumerating response on the deployed route. This note does not pass AUTH04 and does not start AUTH05.

## Boundary check

Persona: approved member/family, with the existing verified profile and scope. Surface/layer: LiveUIN private browser App and its public login handoff. Canonical owner: Core Identity for identity/session and Core/Trust/Ops for case/product truth. No role, workspace, plan, quota or record entitlement is granted by the screen. No shortcode is changed; any handoff must retain the same authority and locked states. No unrelated family's documents, staff controls or host records may be exposed.

The global LiveUIN documents, persona audit and sibling boundary audit were checked. No native accepted-auth source, Laijuzhu, IGEMA, WeChat, imported tenancy, payment setting or public-admission switch was changed by this reconciliation.
