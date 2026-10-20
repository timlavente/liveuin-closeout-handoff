# Native and browser login coordination

21 October 2026, Singapore. This note identifies the accepted native contract and the independently deployed browser contract. It authorizes no website release.

## Authoritative native source and installed version

- Repository: `https://github.com/timlavente/liveuin-resident-app`
- Current checkout: `/Users/Vivian/liveuin-resident-app`
- Branch: `gb/liveuin-finish-publish-2026-10`
- Last recorded installed iPhone source: `29f2468f4f04305023386e5e870f92c99c5f9b6d`, bundle `com.liveuin.resident`, version 1.0 (4). Later commits prepare server integration and documentation; they do not establish a newer phone installation.
- Accepted auth baseline: `47f648baa35af2c8e320b4677f0a25ad69117cbd`. The fresh `npm run auth:freeze:check` reports `AUTH FREEZE: PRESERVED`.
- This is the source/contract freeze. Generated payload parity and signing are separate build/install checks.

The iPhone entry is `src/main.native.tsx` / `src/NativeApp.tsx`. Its sign-in implementation is `src/native-lovable/routes/auth.sign-in.tsx`; `/auth/sign-in` and the legacy login alias use the shared implementation. Keep email, password, Continue with Apple and Continue with Google. The native bridge is `ResidentSocialAuth` registered on `LiveUINBridgeViewController`; the existing iOS project contains Apple capability and Google client configuration.

Ern confirmed production email reset/sign-in, Apple sign-in and Google sign-in opened his account/home. This is historical physical acceptance, not a fresh phone test on 21 October.

## Recovery contract

`src/native-lovable/routes/auth.forgot-password.tsx` implements `/auth/forgot-password`. It requests a recovery code through `POST /api/core/identity/password-resets/request`, verifies the returned reset with `/{reset_id}/verify`, and completes the reset through `/complete`. Identity owns account eligibility, reset delivery, verification and completion. The phone must display the real result, expiry/error and retry state; a visible code field alone is not proof an email arrived.

Do not collect or publish any password, reset code, token or signed customer session.

## Independent browser release

The website closeout records `FREEZE-ISSUE-AUTH-002.md` and `FREEZE-ISSUE-AUTH-003.md` under `Documents/Liveuin/docs/p06-review-2026-10-19` describe the browser release. AUTH02 added canonical Identity authentication, safe returns, pilot admission and durable logout. AUTH03 truthfully removed the nonfunctional **browser** Google control because that browser OAuth flow is unconfigured. That is not a request to hide the accepted native Google button.

The website entry alias is `auth03-d542aefd993107da`. The payment mount preserved that alias while adding its five guarded routes. The fresh nginx hash is `e9a65aeccfaf1387f5ae05dc0923559aaf97e5ca6ae268efcdc4cb4a85a9d3b0`; the older AUTH03 document's proxy hash predates those additive payment routes. No app-entry file was replaced by this work.

The pending administrator test-case helper now reads the current owning Identity admission policy. It must not restore earlier Identity sources, bypass admission, invent a customer session or alter authentication to provision a case.

## Shared boundary

Surface: private native customer app and the canonical Core administrator maintenance layer. Persona: the currently eligible tenant/member only. Entitlement: literal `payment.intent.write`, current account/person/workspace binding and own TEST-customer mapping. Scope: one synthetic case with no real housing obligation. Invalid admission or missing authority remains locked.

No family, host, partner, unrelated tenant, Ops, Studio or founder access is implied. No shortcode changed; any connector view must retain the same role, workspace, record scope and handoff restrictions. Core/Identity/TrustPay/LiveLedger own durable truth; the app is a consumer. Global LiveUIN and sibling ecosystem/persona documents were checked.
