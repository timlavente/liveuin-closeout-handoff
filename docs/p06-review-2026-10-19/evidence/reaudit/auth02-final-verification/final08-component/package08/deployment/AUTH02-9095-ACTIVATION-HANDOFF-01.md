# AUTH02 component:9095 unsafe issuance closure

Local candidate only. Root performs activation separately. This component can close the unapproved new-session paths before the member cohort is settled; it cannot close AUTH02 as a whole or establish platform-wide public admission control.

Target exactly `/opt/liveuin/deploy/core_identity_api.py`, loaded by `ops-backend@liveuin.service`. Baseline SHA256 `fcf8c612f2442ab05a8950523890806af7b89f88e9cbf801fcc5561ec1d6acc4`. Candidate SHA256 `a0834b412c06263d1ca593de67cc2514471cf4fdd7a83c860608be998fc65fcb`. Closed fallback SHA256 `aee0ce11a4ffe48242b18dbde4a67463409765d80f43f15a68c6d40facc6e143`. Do not install the separate9098 API into this path.

The candidate stops raw generic challenge create/verify in production, rejects browser compatibility request/verify branches without existing Ops/Host membership authority, and refuses raw preview-code echo unless the environment is explicitly nonproduction. Known Ops/Host membership checks, delivered code verification and their existing permissions remain authoritative. Empty or unknown surface can no longer fall through to a caller-selected role. Pending challenges with unknown/Connect/Partner metadata are refused. This work does not inspect or revoke previously issued credentials; session resolution is intentionally preserved. Full account, permission and cross-case proof remain pending.

All replacements, restart and recovery actions below are performed through the reviewed `activate-9095.py`, using the evidence gates in `RESTART-REVIEW-PROCEDURE-01.md`. The prose is not permission to bypass a failed controller gate. If reviewed stop actions themselves change, stop automatically attempting service actions and require root reconciliation.

## Entry and protected recovery

1. Recheck the full current package manifests, source baseline, running unit, process arguments, source root, PID and effective nonsecret bindings. Another active task can change the same server. Any drift stops activation; do not overwrite its work or silently regenerate the baseline.
2. Stage the reviewed package beneath a root-owned0700 directory on the same server. Run `deployment/preflight-backup.py --component 9095` for metadata-only classification. Run the same with `--backup` only after review. It makes a new root0700 backup containing the exact9095 source, unit/drop-in/environment configuration and consistent SQLite backups of the actual Ops identity, login and shared session files. No record values are selected or exported. Backups are protected by permissions; encryption is not claimed. Each SQLite backup is consistent individually, not an atomic snapshot across databases.
3. Keep original owner/group/mode in the root-private restore manifest. Backups stay on the server. Code rollback does not restore databases, which could reinstate revoked sessions or lose concurrent work.
4. Compile both candidate and fallback using `/usr/bin/python3` with `compile(source, ..., 'exec')` in a separate process receiving source through stdin. Do not import the product for this check. Confirm the service's runtime interpreter/installed framework and all source hashes still match.
5. Complete the bounded startup-source review described below. Then atomically replace only the one API file, preserving its recorded owner/group/mode, and restart only `ops-backend@liveuin.service`. Do not change9098, nginx, a role, a database, an environment flag, the OTP service, or the public/member application in this component.

## No-side-effect post-restart checks

Confirm a new service PID, the exact expected executable/arguments/cwd, listener ownership on127.0.0.1:9095, active/running state and candidate file hash. A response from a different process is not proof.

- GET loopback `/healthz`: baseline is200 with `ok:true`; exact current `app.py:1529–1531` returns that literal and does not call the database, mail or autopilot. `/health` is currently404 and is not the success endpoint. Do not call any autopilot dispatch or feature status as a health check.
- POST loopback generic challenge create with `{}` and generic verify with an empty body and a fixed nonexistent diagnostic path: require404 plus `Cache-Control:no-store`. Neither path reaches the challenge service under the production/default environment. Use no email, workspace, role, amount, card or real case.
- POST loopback `/api/ops/auth/request_code` with `{}`: candidate requires403 `browser_sign_in_unavailable` before email validation, membership lookup, challenge creation or delivery. This distinguishes the candidate from baseline400 without supplying an identifier. Empty `/api/ops/auth/verify-code` remains400 `challenge_id_required`; it is validation-only evidence. The historical malformed-metadata denial is proved against isolated stores, not by manufacturing a live challenge.
- Repeat the safe generic404 and empty request403 through the known Ops/App/Host routing where that alias is actually exposed. App and Host generic Identity prefixes and Ops Identity prefix reach9095. Do not invent a missing alias on a domain.
- Root then reloads the existing legitimate owner Ops session and completes one normal owner-requested code sign-in, preserving actual `ops`/`liveuin` membership. Only that explicit owner proof may send mail. Isolated tests are not the owner proof. No other account is contacted.

The source gate can be installed without a new member cohort, but no AUTH02 completion freeze or public access claim is allowed until its remaining member/browser/cohort proofs pass.

## Recovery stays closed

If startup, negative proof or legitimate owner access fails, stop this component and install the precompiled closed fallback in the same one-file slot, preserving metadata; restart only the same unit. The fallback returns503 `browser_sign_in_temporarily_locked` before either browser email-code adapter runs. Generic production challenge routes remain404/no-store. Existing session resolve, logout and administrative route code are otherwise the baseline code. Test fallback health and denial; report new sign-in temporarily held if used.

Do not automatically restore the original API: that would reopen the identified unsafe issuance paths. If the closed fallback cannot start safely, leave the service stopped while root establishes an independently reviewed route hold/recovery; do not claim success or resume the member rollout. Never restore a shared Identity/session database as a routine code fallback. The protected original backup is forensic/recovery material, not permission to reopen an unsafe route.

## Startup review and limits

Exact entry assembly `app/main.py` SHA256 `b8f00791b71b11e93c72980ad31fa0eac3d18d0b03a0e4e4dd5f172620c85c2a` loads the existing root app and includes router modules. Exact root `app.py` SHA256 `fcecabe419ce5aa080155f0e29e34eee79596d05f3838a6180dad2ce9795bbf2` has no startup/lifespan/background scheduling hook in the inspected source. Its import-time calls construct the app, attach routers, read config and wire generated/alias router packages; the modified API adds no startup hook, migration, queue drain, imported tenancy action or mail call. Mail remains inside the request function after canonical membership and a normal request.

The root-only source review now covers20 Ops entry/local modules and31 direct deployed modules, with exact hashes. Named Connect dependency-loading and concrete marketing/rental workflow constructors and storage path getters were separately inspected; the constructors retain configuration/callbacks and the getters select paths. No automatic mail, queue drain or customer-record mutation was found in those reviewed startup paths. See `evidence/AUTH02-BOUNDED-STARTUP-REVIEW-01.md` and its exact source evidence. The candidate's module-level startup is unchanged. This finite review does not claim exhaustive recursive inspection of every transitive import. A separate current seven-library fast-path proof is still mandatory because the existing prestart script can otherwise rebuild/install dependencies.

Ecosystem boundary checked. This is the canonical LiveUIN Identity adapter only; it does not change Laijuzhu, IGEMA, WordPress, WeChat, imported tenancies, custody of funds or the publish switch.

## Revision05 reconciliation and serialization

The current Ops PID baseline is3403267 after the separately authorized resident API deployment. See evidence/RECONCILIATION-SOURCE-REVIEW-05.md and locked metadata. The new main and14 actual resident source pins are preserved; they are not overwritten by this one-file Identity change. Package04 remains stopped and retained. Run activation and recovery only while holding the existing cooperative /var/lock/liveuin-resident-core-api.lock (flock -n); the authenticated operator already holding that lock must invoke the controller inside that held shell. Do not acquire the same lock again in a child if its inherited lock is already held. Exact source/config gates remain required because this cooperative lock cannot constrain unknown writers.
