# OTP immediate cause confirmed — 01

20 October 2026, 00:15:59 Singapore. Additive conclusion following `OTP-CAUSE-READONLY-01.md`; no frozen plan or production state changed.

**The Ops code request points to a stopped gateway.** The authenticated root classifier verified the actual running `ops-backend@liveuin.service` process, not merely an environment file. Both `OTP_GATEWAY_URL` and `OTP_INTERNAL_TOKEN` are present. The effective gateway destination is `http://127.0.0.1:9094`, with a root path and no URL userinfo/query/fragment. The connection is refused.

`otp-gateway.service` is inactive/dead with MainPID 0. Systemd records Result `success`, termination signal 15 and its last exit at 9 October 2026, 00:06:05 Singapore. These observations explain the deployed helper's transport-error branch and the browser's `email_code_delivery_unavailable` response. No email request was sent during this classification.

This is a confirmed delivery-service availability failure. Missing URL/token settings are ruled out for the effective Ops process. It is not evidence of an incorrect owner email, bad SMTP password, wrong Stripe key or account permission problem. SMTP delivery, token agreement and account entitlement have not been positively tested; additional downstream defects cannot be ruled out until the intended delivery path is restored through the authorized plan.

Why the gateway was stopped remains unconfirmed. The recorded stop is not permission to restart it or proof that reactivating this older service is the intended repair. No restart, log inspection, credential change, account grant, email retry or repair was performed. R01 remains staged; its required legitimate positive proof and the frozen order are unchanged.

Evidence: `otp-runtime-classification.json`, produced by `classify-otp-runtime-readonly.py`, plus the already traced browser module, nginx alias and exact deployed helper in `../reaudit/R01-IDENTITY-PROBE-AND-DELIVERY-TRACE-01.md`. The classifier reports presence and sanitized connection metadata only; no secret values or customer records are included.
