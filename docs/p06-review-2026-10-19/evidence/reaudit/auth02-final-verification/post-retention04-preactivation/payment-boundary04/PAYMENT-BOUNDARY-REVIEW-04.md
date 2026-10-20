# New resident payment paths — bounded review

The earlier public-live-charge-off evidence is **not sufficient by itself for the new deployment**. Its four source pins and earlier process snapshot cover the old payment routes, but not the newly mounted customer-card router or the current Ops process. The exact new source does not introduce a live charge operation: it has a separate test-only card setup boundary. Refresh the process/source evidence and append this boundary; do not describe the old snapshot as a current universal pass.

This review used immutable commit `87ff864a9b0ba8680abe3f0ecfe5be8aff3b6d1a` from `/Users/Vivian/liveuin-resident-app`. The parent reported deployment archive SHA-256 `1836d96839dc1fb22ff1304c82e5821ddeb3d96f32cc6b0d04db4302595a81ff`. Fresh server equality belongs to the parallel source reconciliation. All eight selected payload hashes match the manifest at that commit. The working-tree manifest and card API differ, so they were excluded as deployment evidence. Exact selected bytes and hashes are retained in `source-provenance.json` and the adjacent payload directory.

## Relevant new operations

| Operation | Source behavior |
| --- | --- |
| POST `/api/core/payments/customer/sandbox/setup-intents` | Creates test customer/setup objects after canonical customer scope and configuration checks. Exact consent payload; no amount or currency input. |
| GET `/api/core/payments/customer/sandbox/setup-intents/{setup_id}` | Reconciles an owned test setup against Stripe; this is not a harmless provider-free smoke request. |
| GET `/api/core/payments/customer/sandbox/payment-methods` | Reads/verifies owned test methods against Stripe. |
| DELETE `/api/core/payments/customer/sandbox/payment-methods/{method_id}` | Detaches an owned test method. |
| POST `/api/core/payments/provider-webhooks/stripe/customer-sandbox` | Requires configured signature verification; accepts only test-mode setup events and reconciles the current provider object. |
| GET `/api/core/resident/cases/{case_id}/bills` | Canonical case-scoped bill projection; no provider call or charge action in this adapter. |

The gateway mounts these routers in Core; the package prepares App nginx routes for them. Mounting a route does not prove the configuration or authorizations pass.

## Why the added card adapter cannot select live charging

`core_customer_card_provider.py` calls the unchanged sandbox `_secret()` loader and independently accepts only a secret beginning `sk_test_`. Its fixed provider methods cover account/customer/setup-intent/payment-method lookup and detach. There is no charge, PaymentIntent, refund, transfer, payout or mandate endpoint in this adapter. Setup requests use card and on-session usage. API configuration requires a `pk_test_` publishable key. The service requires returned objects and accepted webhook events to have `livemode` exactly false. These checks are distinct from the old four live-rail flags and do not rely on those flags.

The new API's complete enable flag is `LIVEUIN_CUSTOMER_CARDS_SANDBOX_ENABLED`. Its test is **exactly** `value == "true"`; whitespace/case variants and `1` do not enable it. Absent or any other value rejects setup/provider operations with 503. There is no new live-charge enable switch in these reviewed files.

## Smallest fresh runtime classification

Add only `{present, enabled_exact_true}` for `LIVEUIN_CUSTOMER_CARDS_SANDBOX_ENABLED` to the existing read-only running-process classifier. Do not reuse its generic truthy normalizer for this flag. Recheck the current service PID/start identity and the old live-rail/Connect classifications; retain current hashes for the new API, provider, service, bill projection and gateway plus the unchanged `_secret()` loader. Do not print values or credential hashes.

If configuration readiness is also needed, these are additional names, not enable switches. Reduce them only to the indicated booleans:

- `LIVEUIN_CUSTOMER_CARDS_STRIPE_ACCOUNT_ID`: present and matches the source's account-ID syntax.
- `LIVEUIN_CUSTOMER_CARDS_WORKSPACE_ID`: present and matches the source's workspace syntax.
- `LIVEUIN_CUSTOMER_CARDS_STRIPE_PUBLISHABLE_KEY`: matches the source's exact test-publishable-key syntax.
- `LIVEUIN_CUSTOMER_CARDS_WEBHOOK_SECRET_REF`: nonempty only. Presence does not prove the registry reference resolves or is approved.
- Existing systemd credential `STRIPE_SECRET_KEY`: reuse the existing key-kind/accepted-test-key classification. Never print or hash its value.

An enabled sandbox flag would mean the sandbox feature is enabled, not that live charging is enabled. Conversely, old live-rail flags off do not prove this sandbox flag is off. None of this is a passing payment journey, refund, browser or owner-role proof.

## Provenance caveat

Deployed-commit card API SHA-256 is `82f3e57356ee4a32f3979262279d7fb75c3efeba54d38efd7a023489a3743953`. It uses the existing `stripe_webhook_signature` registry purpose. The later working-tree API has a dedicated customer setup purpose and additional context checks; those later checks must not be credited to the deployed commit. This review does not broaden into callback or registry repair.

No module was imported or executed. No endpoint/provider request, customer store, secret, payment setting, service or grant was accessed or changed. LiveUIN Core/TrustPay remains the canonical owner; sibling products and imported tenancies are outside this review.
