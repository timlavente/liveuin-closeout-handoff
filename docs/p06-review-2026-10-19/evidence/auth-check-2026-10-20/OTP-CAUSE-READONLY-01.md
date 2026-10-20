# OTP cause audit — read only

The strongest current lead is a stopped email-code gateway, rather than evidence that the owner's address or password is wrong. This is not yet an unconditional root-cause statement: the effective Ops gateway URL must first be matched to the stopped listener.

The known Ops request trace is unchanged: deployed `OpsLogin-BLxReVVn.js` POSTs `/api/ops/auth/request_code`, nginx sends that alias to the active 9095 Ops service, and its Core adapter `_otp_gateway_deliver` calls the configured gateway `/send`. Exact source/routing references and hashes are retained in `../reaudit/R01-IDENTITY-PROBE-AND-DELIVERY-TRACE-01.md`.

Fresh read-only service evidence in `otp-service-metadata.json` shows:

- `otp-gateway.service` is loaded but inactive/dead, with MainPID 0.
- Its executable/module is `/opt/liveuin/otp_service/venv/bin/python`, `app:APP`, port 9094; its environment-file reference is `/etc/liveuin/otp-prod.env`.
- A TCP connection to `127.0.0.1:9094` was refused. No payload was sent.
- Systemd records Result `success`, ExecMainCode `2`, ExecMainStatus `15`, exit `2026-10-09 00:06:05 +08`. This is not proof of a current crash, nor permission to restart a service deliberately left off.
- The active Ops service has the existing `82-identity-otp-gateway.conf` drop-in, which references `/etc/liveuin/authcore-prod.env`. No contents of that environment file were read by this collector.

## Finite root-read classifier

`classify-otp-runtime-readonly.py` is prepared for the already authenticated root session. It does not change files, services, flags or permissions. It checks the current process identity before selecting only `OTP_GATEWAY_URL` and the presence of `OTP_INTERNAL_TOKEN` from that process's environment. It emits URL scheme/host/port and root-path/userinfo/query presence bits, never token values, userinfo, query values or arbitrary environment fields. It does not read email/customer logs or databases, send email, call `/send`, or try a login.

Its classifications distinguish:

| Observed condition | Evidence-based conclusion |
|---|---|
| Gateway URL or internal-token setting absent from the effective Ops process | Missing runtime configuration triggers the helper's early unavailable branch. |
| Both are present; URL is the known loopback 9094 gateway; TCP is refused | The configured delivery service is unreachable. This is enough to explain the generic delivery error without testing SMTP. |
| Known gateway is listening | Reachability alone does not prove internal authorization, storage or SMTP. The prior failed reply remains unclassified. |
| Effective URL is another destination | This stopped 9094 unit cannot yet be assigned as the cause; the classifier makes no request to that other destination. |

The deployed OTP source's `GET /healthz` at line 81 is a fixed service response, so it could confirm listener identity without sending mail if needed. It does not prove SMTP. `GET /readyz` at line 86 runs a database `SELECT 1`; it was not called. No `/send` probe is required for the current bounded classification.

The adapter collapses missing settings, HTTP/transport/JSON errors and replies lacking both `ok:true` and `sent:true` to `email_code_delivery_unavailable`. Without a new send or appropriate redacted per-request evidence, a reachable service's failed-reply category cannot be distinguished further. Do not infer a specific SMTP credential, provider, database or recipient problem from the generic browser error.

## Scope and stop

This is a cause check requested after the repeated login failure. R01 remains staged. No order amendment, email repair, gateway start, credential change, new account or production deployment has occurred. The owner/session positive gate and the separate whole-site consistency check are not claimed resolved. Any repair of email delivery must respect the frozen order; the read-only finding is not an instruction to reactivate an old service.

LiveUIN Identity retains authentication ownership. No sibling theme, connector truth, customer record, imported tenancy or payment path was changed.
