# PAYMENT-LOCK-RUNTIME-CHECK-01

Additive evidence, 20 October 2026, Singapore time. This note does not modify the frozen inputs or the earlier inventory. Runtime classification: **00:04:03 SGT**. Bounded static source follow-up: **00:05:31 SGT**.

**Decision: PASS for the bounded R01 invariant on the deployed LiveUIN payment entry paths identified in PUBLIC-CHARGE-LOCK-INVENTORY-01.** The current process classifications, unchanged reviewed source and domain routing together support that these paths cannot offer a stranger a live card charge. The earlier inventory's unresolved runtime-mode condition is now closed for this scope. This is not a successful-payment result, a global claim about every unknown endpoint, or permission to publish.

Suggested freeze line: **“Public live charging remains off on the reviewed LiveUIN routes. No payment or checkout session was created. Payment readiness remains to be proved in its frozen row.”**

## What the root-session check establishes

The exact classifier was run by the root agent in the authorized browser SSH session. It made no application imports, network/provider calls, writes or customer-store reads. It returned only mode classifications, selected credential kinds/presence, source-match booleans, service identity and timing. No raw environment, credential values or credential hashes were emitted.

| Running service | Runtime result | Consequence for this invariant |
| --- | --- | --- |
| `ops-backend@liveuin.service`, PID1298408 | Active; unchanged PID/start identity during read; no child process. All four Core live-rail flags absent and therefore false under the matching source. Core Stripe credential classified `secret_test`. | The concrete Core Stripe adapter accepts only test credentials. The generic bill/intent methods record Core state; they do not themselves execute an external live card charge. Live rail selection is also off. |
| Same Ops service, legacy Connect checkout | Sandbox flag false, provider `reference`, strict true. Stripe key absent/empty; HitPay key absent; Airwallex token absent. Derived dispatch: `no_external_provider_dispatch`. | “Sandbox false” is not “live on”. With `reference`, the dispatcher returns a reference result and calls no external processor. Independently, the exact legacy checkout route is not mapped to this implementation by the inspected LiveUIN vhosts. |
| `liveuin-public-preview-ui.service`, PID1041 | Active, same process, no children. All four live-rail flags false. Core Stripe credential absent/empty. Internal preview authentication required. | No live processor credential was established for this preview path. The reviewed `/checkout/*` POST prefix is rejected before dispatch; its generic Core payment record routes are not live-card execution. |
| `liveuin-public-api.service`, PID296370 | Active, same process, no children. All four live-rail flags false. | Consistent with its reviewed public Home/marketplace/Pass route mapping; the public Pass gateway adds no payment creation route. |

The four flags are Stripe live validation, HitPay live validation, WeChat Pay live validation and Salt Edge payment initiation approval. This is a classification of readiness switches under the reviewed code; it does not validate any country's payment methods, amounts, ceilings, webhooks, refunds or ledger reconciliation.

The classifier confirms exact source matches for `core_payment_rail.py`, `core_stripe_sandbox_api.py`, legacy Ops `app.py`, and `public-home-preview.py`. Root's existing service/source evidence supplies the wider entry-point binding. Together with the prior routing inventory, this closes a concrete configuration uncertainty rather than relying on missing environment-file assignments.

## Could application code override the startup environment?

Linux `/proc/PID/environ` is startup-environment evidence; it is not in-process introspection. That technical limit remains true. The bounded source review found **no evidence of a payment-related override or dotenv loader** in the actual reviewed payment rail, sandbox adapter, payment service, legacy Ops app, Ops entry point, preview server or public gateway.

The legacy Ops source contains a separate `/etc/ops-backend.env` parser for its UI scanner. It caches values in a dictionary; the only referenced cached setting is `OPS_UI_ROOT`. It does not update `os.environ`, and the Connect payment functions read `os.getenv` directly. Its existence is therefore not a reason to treat the payment classification as stale.

The public Home API sets `LIVEUIN_PUBLIC_CMS_SQLITE_PATH` when loading its preview module. This is an unrelated CMS storage path, not a payment mode or credential override.

A further static scan of normally readable direct helpers found no dotenv loader/environment mutation in `auth_api.py`, payment/runtime stores, service-secret resolver, identity session, or payment provider adapter. Four additional legacy imports (`db.py`, `auth_email_otp.py`, `ui_nav_api.py`, `autopilot_executor.py`) were permission-denied to the ordinary SSH reader; their contents are not claimed reviewed. No customer data or environment file was opened for this source check.

**These residual limits do not identify a realistic bypass of the bounded R01 lock.** Even a hypothetical change to a live-rail boolean cannot make the matching Core sandbox adapter accept a live key. Legacy Connect is independently absent from the reviewed public proxy routing and currently selects reference mode with no provider credentials. Treating an unobserved arbitrary in-process change as an ongoing blocker would demand an unbounded audit beyond the known routes. It is retained as an evidence limit, not promoted into a new frozen issue.

## Scope of the pass and retained limits

This pass combines static enforcement, process-mode classification and public ingress observations. It does **not** claim an anonymous payment POST was executed. No charge, checkout session, refund, webhook, bill or payment intent was created during this check. No real or test customer case was opened.

The earlier Sierra projection (`payment_enabled=false`) and Pay health (`stripe_mode=test`, `live_enabled=false`, `refund_executor_enabled=false`, last captured19 October23:23SGT) remain supporting evidence for those individual doors. This check did not inspect the separate Pay process or unrelated IGEMA transactions. It does not certify every unknown direct Pay route or externally created payment link. Any new LiveUIN checkout route or configuration change invalidates this bounded conclusion until it is checked.

The Stripe test suite, case binding, refunds, payment-country/type/amount coverage, real owner and named-role proof, commercial acceptance, P6 evidence and publish sheet remain separate requirements. No real charge/refund requirement is reintroduced: the owner's latest accepted Stripe readiness gate remains in force. The owner alone publishes.

## Evidence

- `payment-lock-classification.json` — sanitized root runtime output,20 October00:04:03SGT.
- `payment-lock-classify.py` — exact read-only classifier; locally checked for syntax, mode parity and synthetic-secret redaction before execution by root.
- `payment-lock-source/startup-env-source-scan.json` — bounded static follow-up,20 October00:05:31SGT; source hashes, matching node names/line numbers, explicit permission limits.
- `PUBLIC-CHARGE-LOCK-INVENTORY-01.md` and its `payment-lock-source/` evidence — routes, guards, exact source copies, domain mappings, anonymous401/404/static-shell observations and initial limits. Preserved unchanged.

Ecosystem boundary retained: LiveUIN public/private routing and payment edge only; durable truth remains in LiveUIN Core/Trust/Ops. No sibling theme work. Imported tenancies were not read, used, billed or emailed. No production state or public-access switch was changed by this check.
