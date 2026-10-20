# R01 deployment and closed recovery — review procedure

**Local preparation only. Do not execute, upload, restart or activate from this document. R01 is still staged and open.** The normal owner sign-in request currently returns `email_code_delivery_unavailable`, so the required permitted production identity proof is unavailable. Authorized root Tailscale SSH establishes a possible activation/recovery channel; it does not satisfy application identity or public-payment-lock evidence. The closed fallback must not be activated as a way to bypass these entry conditions.

This is an engineering review addendum, not a new freeze note or an owner debugging guide. No executable deployment script or passing entry-proof file is supplied. The original package, manifest, frozen plan and deployed files remain unchanged.

## Exact scope and pinned material

Only these application files may be replaced, using bytes from the matching final package. Do not substitute local workspace source, rebuild the release, change credentials/configuration, alter permissions or copy any other product file.

| File | Exact deployed baseline | Guarded candidate | Closed fallback |
|---|---|---|---|
| `/opt/liveuin/deploy/home_api.py` | `cab022b1055df93e27328fa74813d8ae043bb1cc387562255eed0d9b68471172` | `d1f0f44278302caf328c623052f4cd0f8c236776c2112098cca0df261873adc2` | `e3f08013e3baf977818fc8033472f823b3874c47ea67816d90054241a3c8fad4` |
| `/opt/liveuin/deploy/public_home_gateway.py` | `67f4befdd7dbccc34bcaa79050b6c990cd3df33349ee4369f7da9838810f6fac` | `49a57731d9df60e95b67eb3ac578d67f2bd861e1befff5bba7afcdfdeab42c60` | `49a57731d9df60e95b67eb3ac578d67f2bd861e1befff5bba7afcdfdeab42c60` |

- Package: `/private/tmp/liveuin-p06-r01-stage-20261019`; manifest SHA256 `79153e64cf76d086b47b7cc4db202c3ef426bff85b89026074671ed4d73f9abc`.
- Frozen plan SHA256: `0923c859996ba0a43e67c495111b89e6a1d4ad70c61c3fbefc0540226d05267b`.
- Exact 21-operation inventory: `evidence/protected-routes.json`, SHA256 `fa772759b9f018c4b807c1134bb97ae22ce8e3f483ec4e9f6f6d6ec398273818`.
- The package's policy correction is part of the reviewed candidate: all 21 operations require verified canonical first-party identity and the existing `ops_manager` / `super_admin` intersection. No role is granted by this procedure.
- Only service mutation permitted: `systemctl restart liveuin-public-api.service`. No other restart, stop, kill, reload, daemon reload, service edit, sudo/auth change, promotion helper or permission workaround.

The known service is the public gateway on loopback 9080, user `liveuin`, working directory `/opt/liveuin`, loading `deploy.public_home_gateway:app` through `/usr/bin/python3 -m uvicorn`. Freshly recheck those facts and the unit/drop-in/config fingerprints; they are not approval to assume the current process is unchanged. The last source metadata was regular file mode `0644`, UID 501, GID 50 for both files. Record and retain the freshly verified metadata. If it differs, stop for review instead of restoring or changing ownership to an old value.

## Entry gate — before any deployment mutation

The release operator must supply a real, reviewed entry-proof file **and its separately supplied SHA256**. A filename, file existence, placeholder digest or a boolean without supporting evidence is insufficient. The deployment mechanism must read and verify this file and all bound evidence before creating staging/backup files on the host, replacing application bytes or restarting a service. Missing, mismatched, stale or failed proof is a hard exit before mutation.

The entry proof must bind all of the following to one identified attempt:

1. Exact host identity, the authorized root recovery channel and the named service. Identify the actual host from the authenticated session; this document does not invent a hostname, IP or machine ID. Verify the recovery connection remains usable independently of the public API.
2. Frozen-plan, manifest, route-inventory and all six application-file digests above; fresh deployed baseline and metadata; relevant service/config fingerprints; the final isolated tests, independent review and Python 3.10 compile result.
3. A permitted canonical production identity allow/refuse proof, with exact role/workspace/site and a safe fixture or authorized owner scope. Do not create a synthetic signed production credential, grant a role, reuse another person's session or read real-family records to make this pass. **This condition is currently false because owner sign-in could not obtain its code.**
4. Effective public-live-charge denial evidence and its actual deployed coverage. The bounded public listing flags and pay health observations alone are not this proof. No payment keys, modes, charges, refunds or case/payment records are changed in R01.
5. The exact reviewed private/public smoke requests, allowed safe scope, expected outcomes and comparison baseline; no valid CMS content write or payment action. Record which existing public endpoints are already degraded so their unrelated database fault is neither hidden nor mislabelled a regression.
6. A reviewed closed-recovery procedure and an operator able to perform it, with both fallback files preverified. Define a bounded smoke deadline and an interruption/re-entry route. A green health response never substitutes for this gate or for smoke results.

Do not write a fabricated passing example of this file. Its evidence must be collected through permitted working access. A future executable controller must enforce this gate in code, not rely solely on an operator remembering the paragraph.

## Preparation after the entry gate passes

1. Recheck the exact target paths, regular-file status and parent directories; reject symlinks, unexpected paths, drift or an unreviewed reload/watch mechanism. Confirm the active interpreter is Python 3.10 and the service still loads these files. Do not import the product merely to compile it.
2. Retain exact pre-change copies of both sources in a protected attempt directory, with the source digest, size, UID/GID and mode recorded. Verify the copies against the deployed bytes and flush them to disk. These originals are forensic evidence only; they are **not** an allowed serving rollback because they reopen the private routes.
3. Verify all candidate and fallback bytes against the pinned digests. Under the actual Python 3.10 interpreter, compile all four byte sequences using `compile(source_bytes, expected_filename, 'exec')`. This checks syntax without executing imports or writing bytecode. Compile failure stops before application replacement.
4. Prepare all four replacement files on the target filesystem, under unique attempt names; retain each destination's verified UID/GID and mode on its replacement. Verify contents and metadata after staging. This preserves existing ownership/mode; it does not grant new access. Record a durable intent journal naming only these two targets and the candidate/fallback digests.
5. Immediately before replacement, check the deployed baseline digests and metadata again. Any mismatch stops the attempt. Do not overwrite another change or update the pinned manifest to make drift disappear.

## Activation and immediate smoke

Replace `home_api.py` first, then `public_home_gateway.py`, using same-filesystem atomic rename/replace for each fully written file, and flush the parent directory. Verify both candidate digests and preserved metadata before the one permitted service restart. Never restart deliberately with a mixed pair.

**Each file replacement is atomic; the two-file pair is not one atomic filesystem transaction.** The reviewed service has no autoreload, but that must be rechecked. An interruption, process crash or host failure between replacements can leave a mixed on-disk pair. The journal and closed recovery below handle that state; this procedure does not claim zero downtime or immunity to power loss.

After `systemctl restart liveuin-public-api.service`, verify service state and the expected active process/version. Then run the separately reviewed smoke, with an explicit timeout:

- All 21 mounted operations refuse anonymous callers before handlers, with the intended sign-in response and private/no-store behavior. Include the exact route/method variants in the inventory and safe invalid/empty CMS requests only as approved in the entry proof. Verify wrong role/workspace/site and malformed or forged identity refusal without real-family data.
- A permitted scoped positive check proves the canonical authorization path on the deployed service. Record the authorized scope and expected response. Neither a public 200 nor the local synthetic fixture is this proof. An unrelated existing backend degradation must be described accurately, not counted as full handler success.
- The fixed pages route remains closed, public published-content and Sierra request/display paths preserve their reviewed baseline, and existing search/status degradation has not been represented as fixed. Confirm the existing public payment-lock evidence still applies and no payment setting changed.
- A process/health check is one separate check. It cannot mark the private, public or payment rows passed. Missing, inconclusive, timed-out or failed mandatory smoke triggers closed recovery; it does not authorize moving to R02.

Persist only redacted status, timestamps, route names, version/digest references and result evidence. Never put cookies, tokens, secrets, customer response bodies or unrelated records in logs or the freeze note.

## Closed recovery on replacement, restart or smoke failure

1. Stop the candidate attempt. Verify the pre-staged fallback digests and the current target state against the journal. If interrupted state is recognized as the baseline/candidate/fallback mix from this same attempt, install **both** fallback files using atomic per-file replacement and retained original metadata. Unknown third-party changes stop for investigation; do not blindly overwrite them.
2. Verify both fallback digests, then restart only `liveuin-public-api.service`. Do not recover by serving the original unguarded copies, changing auth permissions, recovering the database, restarting Ops/authgate/nginx, or enabling any switch.
3. Verify the fallback on actual routing: all 21 private operations return the intended closed 503 before identity/data handlers, and the reviewed public behavior remains at its baseline. Health alone does not prove this. If fallback activation or smoke fails, retain the incident and journal, keep R01 failed/open, and use the already authorized recovery channel. Do not improvise a broader service/permission change.
4. R01 remains open after any fallback. A successful fallback is containment, not a passed fix. No `FREEZE-ISSUE-001` and no R02 follow from it.

The eventual executable implementation should trap normal interruption and perform the closed recovery, but SIGKILL, lost power and lost host access cannot be made catchable. Before re-entry, inspect the durable journal and exact target hashes; do not rerun a baseline-only deployment blindly. If the reviewed recovery capability is unavailable, do not begin activation.

## What a completed attempt may claim

Only after separate deployed proof passes may the engineer prepare the R01 freeze note with exact file versions, safe allow/refuse proof, public-regression evidence and the properly scoped public-live-charge-off evidence. The operator still has to verify every required statement. A script exit code, 678 isolated checks, successful restart or a health 200 is not R01 completion.

This addendum touches only LiveUIN's private API boundary and its operational release procedure. Core/Trust/Ops and canonical Identity remain the owners; the global/sibling ecosystem boundary and persona requirements were checked. No sibling theme, imported tenancy, customer document, application data, payment setting or production permission was used or changed. Imported tenancies were not emailed. Public access was not opened.
