# AUTH02 backend — staged repair, not deployed

This package is a local candidate based on the exact retained production files. It closes the public Identity admission door to an explicit approved pilot cohort, preserves normal authentication and canonical permissions, makes logout honest, and closes two raw preview challenge routes in production. No production source, service, setting, account, email, case, payment or customer record has been changed by this package.

`candidate/deploy/` targets the9098 public Identity release only. `candidate-9095/deploy/core_identity_api.py` is a separate exact9095 copy containing only the two raw HTTP preview route guards. Do not interchange these two APIs. The9095 approved Ops/Host adapter functions are unchanged. Baselines, separate diffs and manifests identify every byte. The generator refuses a baseline hash mismatch and checks Python3.10 syntax before writing output.

## Admission behavior

A new deployment setting, `LIVEUIN_PUBLIC_ADMISSION_COHORT_JSON`, is a release ACL containing schema_version1, the exact configured workspace, and exact SHA256 hashes of the approved canonical email identifiers. It is not an identity database and grants no role, scope, profile, case or workspace membership. Missing, empty, malformed, duplicated or mismatched configuration refuses admission. No production configuration has been set.

Registration and password entry check the exact normalized email hash before store writes, password work or mail. Pending registration verification/resend check the stored canonical hash before mutation. Every public session issuance, refresh, onboarding/profile continuation and signed public account bootstrap also checks the canonical account and workspace. Session admission requires a verified email and canonical account/person IDs. Social exchange uses actual verified provider claims for new accounts and the linked canonical account for existing identities; a caller-provided email or workspace cannot grant access. Existing provider switches, factor verification, terms, account-state checks and canonical role/grant checks remain in place.

Email normalization matches the existing deployed implementation: trim, lowercase and length bound. Gmail plus aliases and dots are not merged. The proposed owner and test.parent addresses remain distinct identities. No other named role is created here.

`PROPOSED-COHORT-NOT-ACTIVATED.json` contains only the owner and the named test.parent alias supplied by the parent. It is a review candidate, not a confirmed complete production pilot list. Root has asked Ern whether other approved private/native pilot identities exist. Activation must wait for that factual answer; absence of an answer is not agreement to remove their access. A public Tenant entitlement that the old onboarding flow issued itself is not evidence of owner approval.

Privacy/account-deletion lookup and recovery are not blanket-disabled by this admission helper. Password recovery cannot issue a session or bypass the later admission check. Logout remains available even for a removed cohort member or invalid cohort configuration. Google/recovery UI completion remains in its separate authorized row; this package enables no provider.

## Logout behavior

Both explicit signed headers and their existing canonical cookie representation select the same current session. After attempting revocation, the session store must confirm that exact credential is inactive. Refresh revocation also reads back only active rows for that exact session hash before acknowledging success. Unknown/already inactive logout remains idempotent. A durable revocation failure raises an error and leaves the browser able to retry; it cannot return a successful logout acknowledgement. These queries are product implementation, tested only against isolated fixtures; no production database was inspected.

The API's existing public-session projection-denial branch lacked the required error-message argument. The candidate supplies it so a deliberate denied account returns403 instead of raising500. No role or grant is added to make a positive test pass.

## Raw preview routes

Both assemblies guard only POST `/api/core/identity/login/challenges` and POST `/api/core/identity/login/challenges/{challenge_id}/verify`. Default, unknown or production environment refuses404 with no-store before either challenge service runs. Only explicitly nonproduction configuration plus loopback client and loopback request host reaches the old local preview operation. Forwarded headers, payload fields and trusted-preview-host settings cannot enable this route. Production9095 currently has no explicit environment, which is closed by this rule;9098 is production, also closed.

Retained nginx evidence maps these routes on App (lines133–134), Host (119–120), and Ops (588–589) to9095. The raw9098 route is guarded too even though normal App routing uses9095 for this prefix. Canonical Ops/Host adapters call the service functions directly with their established membership flow and remain unchanged. Existing list/cancel endpoints are not redesigned here. This is source/configuration evidence; no public challenge exploit or credential was created.

## Validation and remaining gates

The local24 policy/side-effect groups pass with zero network or database access. Independent exact-source contract tests exercise registration with a synthetic sink, real code verification, password, canonical resolve, ordinary onboarding, cohort rejection, refresh and logout using only temporary databases. Their results are recorded separately and pinned to candidate hashes. No isolated result establishes owner production proof. Dependency versions in that harness differ from production; production Python3.10 syntax checks and framework-matched verification are separate evidence.

Existing `/ready` synthetic account projection checks now use one configured ACL identifier in the existing mocked record. They neither mutate the ACL nor create an account, grant or persisted session. Missing/invalid ACL makes this readiness contract false. The real application still consults actual canonical records.

Before activation: root must confirm the full approved cohort; recheck all baseline hashes and actual service bindings; independently review the final diffs/tests; compile on the production Python version; back up the exact targeted files and protected effective configuration; and establish bounded restart/rollback for both affected services. Configure the approved ACL before exposing the corrected App flow. An unchanged public registration flag is not a release decision—the ACL is the closed-pilot control. Public launch remains Ern's later action.

Rollback restores the exact previous files and protected setting through the verified service-specific backup, then restarts only the affected assembly. Because the old public flow contains preview/auth defects, a functional rollback must also hold the corrected public/member entry closed; never roll back a guard alone while leaving a new working entry exposed. Do not combine these candidate files with another assembly or silently replace the whole application release.

This package does not prove all downstream private APIs accept the member session correctly. Runtime evidence shows9098/9095 share a direct signer and session store but use different Identity stores. Do not merge those stores or add permissions as a workaround. Cross-case/role proof and R01 owner-role alignment remain their existing rows. The actual owner Ops grant is `ops` in `liveuin`, not the synthetic privileged role used by the earlier R01 isolated test.

Ecosystem/persona boundary checked: public UI and private App use canonical LiveUIN Identity/Core/Trust/Ops. The ACL is only release admission, never a new canonical account/case store. No Laijuzhu, IGEMA, WordPress, WeChat, imported tenancy, payment or public-launch work is included. Inputs were fully readable/hash-matched and staged outside the cloud-managed Documents folder.
