# AUTH02 local frontend candidate

Local candidate only. Nothing here was uploaded or activated. No account, role, registration, provider, payment, inventory, public-access or Partner switch was changed. Owner Ops and named member test sessions must remain separate.

## What changed

The existing public/member design is preserved. The sign-in form submits email and password to the existing App Identity password endpoint. Only a server-issued signed session is kept in the existing browser bridge; the returned refresh token is not copied into storage or a URL. The canonical resolver must confirm the session and matching account, person, workspace and approved profile before the UI can continue.

The richer session entitlement list and the public account list must agree. Permissions are their intersection; the selected actor's role, scopes and active workspace/profile must match its own approved entitlement. Other separately approved profiles remain intact. Account continuation is checked separately from active profile selection, so a valid LocalPro selection is not forced into Tenant. Empty, cross-account, expired, future, revoked or missing grants stay closed. No profile, permission or Laijuzhu workspace is inferred. An incomplete account remains closed rather than entering self-service registration/onboarding.

Public sign-in entry hands off to App before password entry. The welcome page preserves only a safe, permitted member return destination. The existing real sign-out button and profile-menu sign-out now use the server logout operation. In-flight sign-in/bootstrap responses cannot reopen the UI after sign-out begins. Failed or ambiguous logout closes private cached views and retains a local retry-only lock; the existing sign-in error area offers Retry sign out. Success is claimed only after HTTP 200, JSON, `ok: true`, and `identity_session_logged_out`.

When a browser already holds another session, that session must be revoked and acknowledged before a new password is sent. Bootstrap remains closed during the exchange, and a failed new password cannot revive the old account. If storing a newly issued credential fails, cleanup uses that credential's explicit server-issued headers rather than assuming it reached browser storage.

Google and password-recovery components remain unchanged and unproven in this row. No new registration or provider path was added. The actual session mapping from Identity to downstream Core remains a required deployment proof.

## Files and reproducibility

- `source/`: readable authored replacements and exact UI splice descriptions.
- `generate.py`: deterministic local-only generator. It rejects wrong manifest/baseline/boundary hashes, missing/duplicate anchors, overlaps and an unexpected changed-JavaScript set before output creation.
- `baseline/`: exact materialized deployed HTML/assets. This is a distribution baseline, not a claim that the original source/build has been recovered.
- `baseline-manifest.json`: 363 pinned files, 12,252,309 bytes; hash `3a72d117bbcf597dbc0087ce23c060ed14f99fbd1f9839a82a8b769e1800bc1d`.
- `candidate/`: new namespaced assets and two separate proposed entry HTML files; no replacement of shared App/Partner `index.html` is included.
- `candidate-manifest.json`: every output/source hash and splice range, including unchanged-byte checks.
- `tests/`: synthetic contract, parser/import graph, deterministic replay and rejection tests plus results.

Exactly five JavaScript files have semantic edits: shared index, sign-in, welcome, AppAccount and ResidentAppShell. The other 357 candidate asset files are byte-identical to the deployed baseline. The unchanged Login wrapper still uses the same module graph. Old immutable asset URLs are untouched. The release namespace is content-derived and must not be reused for different bytes.

## Local checks completed

Twenty synthetic contract test groups passed: approved/rejected profiles, expiry, selected-actor permission consistency, legitimate dual-profile selection, malicious returns, real password request shape, malformed responses/credentials, prior-account switch and wrong-password isolation, storage-failure cleanup, cleanup after an incomplete profile, strict logout acknowledgment, failed-logout retry, pending-password/logout serialization, stale bootstrap rejection and public-origin refusal. An independent 17-case cross-contract check passed using an actual local canonical backend projection. These are isolated fixtures, not production account proof.

All 301 JavaScript modules parse. All 3,094 static imports and 146 dynamic imports resolve within the new namespace; all shared-index imports stay in that graph. Repeat generation is byte-identical. Tampered manifest, baseline or splice anchor is rejected before output creation. No service-worker/Workbox/precache reference was found in the deployed JS/HTML/JSON scan.

## Proposed activation boundary — not executed

Public: introduce the complete new namespace and a pinned entry HTML using the existing public release mechanism. Preserve all original non-auth assets, current public route overrides and domain association files. Some public nginx routes directly use `/index.html`; they must select the same intended new public entry.

App: add the immutable namespace to the shared assets root, but leave `/var/www/liveuin/index.html` unchanged. Use an App-vhost-only exact `/index.html` alias to a separately pinned new App HTML. The current App SPA fallback reaches that location; the existing `/` redirect and `.well-known` locations stay unchanged. Partner therefore continues receiving its original HTML and old graph. Mere availability of an unreferenced namespace is not Partner activation.

Before any activation: independent source review, admission controls, Identity/Core session mapping, exact source/config baseline and rollback checks, then separate named-account browser proof must pass. Health alone cannot prove authentication. The live sequence is password → canonical resolution → reload → correct permitted screen → wrong scope refused → server logout → stale session refused. Public and App browser smoke must also check actual lazy loading and preserved public behavior; these have not been proven by the local parser tests.

Ecosystem boundary checked: the touched layer is LiveUIN public/private client UI. Identity/Core retain durable account, grant, case and payment authority. No sibling product or imported tenancy was touched or messaged.
