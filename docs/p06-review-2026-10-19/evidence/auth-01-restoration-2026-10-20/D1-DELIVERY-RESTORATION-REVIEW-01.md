# D1 delivery restoration — independent source review

20 October 2026, Singapore. Read-only review; no service, code, configuration, database or permission was changed. This is an engineering procedure for the authorized D1 amendment, not a completed fix or an instruction sheet for Ern.

## Conclusion

The existing production `otp-gateway.service` is the narrow restoration target. Its exact source does not send mail, read delivery rows, flush a queue, migrate a database, or start a background worker during startup. It sends one message synchronously only after an authenticated `/send` request passes required-field validation. The live Ops process points to this service's loopback port, and that service is stopped.

Restoring this service can repair the confirmed transport failure without changing the login's roles, identity authority, website bundle, payment flags or public-access controls. Delivery and owner sign-in still need their own proof after restoration. The old staging gateway is not the target: it uses port 9098, where the current dedicated Identity service exists.

## Exact deployed baseline

The copies under `source/` were freshly fetched from `liveuin-hk` using read-only SSH. `source-fingerprints.json` records the source paths and hashes.

| Source | SHA-256 |
|---|---|
| `/opt/liveuin/otp_service/app.py` | `24542a1052dda9723591e1e068c0a446183b643768cf6ccda134a4f2f8e7fe87` |
| `/etc/systemd/system/otp-gateway.service` | `d2ecd65e7581c6aa019a56e637fdded337ffd4f720c826479371a85ff80bc272` |
| `/etc/systemd/system/ops-backend@liveuin.service.d/82-identity-otp-gateway.conf` | `6746a5b8da9cf9965ae1730ee67ba3fc5cbdd1fe4d32af5ccfc962534a9a9609` |
| `/etc/systemd/system/otp-gateway-staging.service` — do not start | `d94f471fa88c70e3752bada2f38398a0f69fe7af2029868b58d3dcd118eb791f` |

The production unit's lines 10–14 select user/group `liveuin`, `/opt/liveuin/otp_service`, `/etc/liveuin/otp-prod.env`, and `/opt/liveuin/otp_service/venv/bin/python -m uvicorn app:APP --host 127.0.0.1 --port 9094`. There are no drop-ins, startup/stop hooks, timer triggers or PartOf binding in the selected unit metadata. It is already enabled; the proposed repair does not enable another service or change the boot policy. Runtime package metadata: Python 3.10.12, FastAPI 0.128.0, Starlette 0.50.0, Pydantic 2.12.5, Uvicorn 0.30.6, psycopg 3.3.2. These differ from the Ops/API framework versions used for R01; do not reuse those versions as gateway runtime proof.

The existing Ops drop-in line 3 references `/etc/liveuin/authcore-prod.env`. The earlier root classifier examined only allowlisted information from the actual running Ops process: its gateway URL is `http://127.0.0.1:9094`, both URL/token settings are present, and a TCP connection is refused. See `../otp-runtime-classification.json`. The shared token's equality with the gateway setting is not yet proven.

## Startup and request safety

All following line numbers refer to the exact `source/app.py` copy.

- Lines 14–27 read configuration and validate the schema name. Line 29 constructs FastAPI; line 187 aliases `app = APP`. There is no startup/lifespan handler, scheduler, queue consumer or import-time database/SMTP call.
- Lines 32–33 define database connection creation; they do not call it at import. Lines 48–68 define SMTP delivery; they do not call it at import.
- Lines 95–104 check the internal header using constant-time comparison before accepting any `/send` fields. Missing/wrong token is 401; an authenticated empty JSON object is 400, before any database or SMTP work.
- Lines 106–130 validate an optionally supplied six-digit code, create one delivery ID, insert one delivery row and send one email to the recipient in that request. There is no read or resend of old deliveries. The email is sent inside the database context; a later commit failure could mean a message was sent despite an error, so do not automatically retry a full delivery request.
- Lines 131–134 collapse storage/delivery failures into bounded errors. Liveness cannot prove those dependencies.
- `/verify` lines 139–184 can read and update delivery records after token/field checks. Do not use it for this no-mail entry check or treat it as canonical identity authority.
- The service has no per-request rate limit in this source. Its existing protection is the loopback binding plus internal token. Keep that binding, token requirement and the Core client boundary unchanged.

Starting the service makes it available to new valid requests from its existing callers. The source gives no evidence of queued requests being replayed; it does not promise that no new user will request a code while the service is running.

## Required configuration, without exposing values

Startup requires the keys `OTP_DATABASE_URL`, `OTP_INTERNAL_TOKEN`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, and `SMTP_FROM`. The last two credential fields and the database URL must never be printed. `SMTP_USER` and `SMTP_PASS` must exist as keys but the implementation permits an empty user for a relay that does not authenticate; do not infer that a non-empty value is universally required. A non-empty internal token is required for useful authorization.

`SMTP_PORT` and optional `OTP_CODE_TTL_SECONDS` must parse as integers. Optional `OTP_DATABASE_SCHEMA` defaults to `p3_auth` and must satisfy the source's identifier check. Optional `SMTP_STARTTLS` defaults true; `SMTP_SSL` defaults false. TLS is used only if those selected settings require it. Root's bounded preflight should report required-key presence, valid scalar parsing, TLS mode and token presence/agreement as booleans or non-secret classifications; never environment dumps, token hashes, credentials, database URLs or mailbox contents. No configuration repair is authorized by this review merely because a later check fails: stop and report the exact failure within D1.

Actual mail delivery requires a reachable PostgreSQL database with the existing `otp_deliveries` schema/table and insert permission, plus the configured SMTP connection/TLS/authentication and sender. Startup and `/healthz` test none of these. `/readyz` performs only `SELECT 1`, not a table read or delivery write. It proves connectivity, not table permissions or SMTP readiness.

## Was the stop an intentional hold?

`service-restoration-metadata.json` records inactive/dead, MainPID 0, Result success, signal 15, and exit at 9 October 2026 00:06:05 Singapore. The unit remains enabled. This is consistent with an orderly termination; it does not establish who stopped it or why.

A bounded journal query selected only systemd manager records (`_PID=1`, exact `UNIT=otp-gateway.service`, 9 October 00:04–00:08 Singapore). It returned no records and no access warning. No application, mail or customer log was read. A bounded search of existing readable local `docs/` and `deploy/` Markdown (excluding this audit's own evidence) found no matching OTP stop/disable/hold note. These checks do not prove that no hold ever existed. The historical reason remains unconfirmed; do not label the stop a crash or an intentional security hold. The current owner's explicit repair instruction is the authority for a new bounded restoration, once the root amendment and preflight are recorded.

## Minimal restoration and rollback procedure

1. Root records the D1 amendment and preserves the current service state, source/unit hashes and boolean-only preflight evidence. Recheck those hashes, the existing loopback binding, absence of a conflicting listener and the current inactive state immediately before the action. Stop on drift or a failed required setting; do not substitute the staging unit, a new branch, new keys, a database recovery or a promotion helper.
2. The only proposed mutation is `systemctl start otp-gateway.service`, using the existing authenticated root session. No code deployment, environment edit, daemon reload, enable operation, Ops restart or Identity restart is needed for this target as currently recorded.
3. Prove the actual process executable/working directory/port and active/running state; use the bounded no-mail checks below. Do not retry restarts indefinitely or inspect broad application logs if it fails. Capture only selected manager state and bounded error classifications.
4. After those checks, one normal owner code request may establish real delivery to the already supplied owner address. Do not send a synthetic email to an unrelated address, replay an old challenge or auto-retry an uncertain mail result. Owner session/role checks remain separate from transport proof; no account or entitlement is created by this procedure.
5. If activation or entry proof fails, `systemctl stop otp-gateway.service` returns the service to the recorded inactive state. Recheck inactive/dead and closed port. Files and flags remain unchanged, so no file restore or database rollback is part of this repair. Any email already sent cannot be undone; record it and never claim stopping the service retracts it.

## No-mail production proof sequence

| Check | Expected result | What it proves and does not prove |
|---|---|---|
| Actual unit/process and loopback listener metadata | Expected exact executable, directory, module and 127.0.0.1:9094 | Correct service was restored; does not prove delivery. |
| `GET http://127.0.0.1:9094/healthz` | 200 and exact `liveuin-otp-smtp-pg` projection | Liveness only. Source returns `ready: true` without a dependency check. |
| `POST /send`, JSON `{}`, no internal token | 401 `internal_authentication_required` | Caller protection before DB/SMTP. No email/challenge fields supplied. |
| `POST /send`, JSON `{}`, using the existing effective Ops internal token locally | 400 `email_and_challenge_id_required` | Actual client/gateway token agreement and header handling. Source returns before DB/SMTP. Never print the token or HTTP request headers. |
| Optional `GET /readyz` within the approved non-customer connectivity check | 200, or bounded 503 `not_ready` | Only `SELECT 1`. No family/delivery rows read, but not SMTP/schema/write proof. |

Do not use a valid email, challenge, amount, card or case in these entry checks. Do not call the full `/send` flow except the separately recorded normal owner delivery proof. A stopped gateway restored to liveness is not yet a completed authentication journey, R01, P6 or public release.

## Boundary and remaining proof

The touched layer is the existing LiveUIN internal email-delivery adapter used by the Ops login. Core remains the owner of login challenge and signed session truth; no role or workspace entitlement changes. The global README, sitemap/tracker, persona audit and Laijuzhu ecosystem boundaries were checked; no sibling surface becomes canonical. No imported tenancies were read, used or emailed. This review did not inspect or change payment paths, so it makes no new claim that public live charging is universally off.

Remaining before D1 completion: actual allowed activation; process/route and no-mail auth proof; dependency readiness as needed; and a recorded successful owner delivery/session proof. Historical stop attribution remains unknown and is not replaced by inference. R01 remains staged and its own production proof conditions remain in force.
