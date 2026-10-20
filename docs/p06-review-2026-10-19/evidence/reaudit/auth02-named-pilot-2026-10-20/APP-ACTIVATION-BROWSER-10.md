# App activation 10 passed; remaining browser logout proof is open

20 October 2026, Singapore. The [actual activation result](frontend-app-readiness-10.json) records `app_alias_active_browser_proof_required`. The exact App nginx configuration is now SHA-256 `4a5f86ae39b5c8c25525a442674f58a4a55c78a9fa160c7567f3ede6ad41601d`. The public frontend pointer did not change.

## Exact readiness transition

After the reviewed configuration test and nginx reload passed, the first App entry check received HTTP 200, 2,284 bytes, SHA-256 `415bfcdbd60ef8124e8a2fb480669324fb89b90752d4f0f458be5f8fb0eea15e`, with `no_store: false`. This matched the exact reviewed old baseline, so the bounded readiness check waited.

Attempt two received HTTP 200, 2,332 bytes, SHA-256 `431419843f2f8696ef55426613a6e2aa8848e0fe6d613244ca9c36ec547716a8`, with `no_store: true`. This matched the exact candidate entry and passed.

This retry directly demonstrates the old-to-new response transition during reload. Activation 08's earlier length/timing observation remains preserved as its original limited evidence; its response body was not retrospectively hashed. The successful retry is separate proof and does not rewrite that stopped attempt.

The retained result hash is `5ae5cb51a8fbabd3b548f9502e2145712ef496412516dafefc67769428aa1e36`. The local reviewed readiness-wrapper source at retention is SHA-256 `c437323294045cad9cf9c3153dd79c8714500a38295fae7427025fadb3670a4e`.

## Actual browser observations

The coordinating agent reported the following normal browser checks for the named synthetic parent:

| Check | Observed result | Retained screenshot |
|---|---|---|
| Wrong password | Sign-in refused with a user-visible error | [Wrong password refused](app-wrong-password-refused.png) |
| Correct password | Arrived at `/tenant/account` | Subsequent account/reload screenshot below |
| Reload | Tenant selected; one profile ready | [Tenant account after reload](app-parent-reload-passed.png) |
| Open `/localpro/home` | “ACCESS NEEDED”; LocalPro use remains locked | [LocalPro refusal](app-parent-localpro-refused.png) |

The screenshots were independently viewed during retention. They expose no plaintext password, factor, session header or token. The login image contains the already approved synthetic mailbox and a masked password field. Account labels and the locked screen do not prove that a family case, payment or other product screen is complete.

Both visible browser logout controls still require their own normal browser and canonical revocation evidence. The earlier actual parent API and server-logout proof remains passed. Public frontend activation/handoff, remaining AUTH02 evidence and the issue freeze remain pending. No AUTH02 pass, family-case completion, P6 or public opening is claimed.

## Existing persona-navigation gap

The Tenant account screen also displays LocalPro-oriented bottom links **EARN, TASKS and PAYOUTS**. Opening LocalPro remains refused, but those navigation labels mislead the Tenant about its available workflow. This confirms in the actual App the gap already recorded from the local fixture in AUTH03–AUTH06 preparation.

The precise follow-up is recorded in [AUTH06-TENANT-NAVIGATION-OBSERVATION-10.md](AUTH06-TENANT-NAVIGATION-OBSERVATION-10.md), assigned to the existing AUTH06 row. It is not fixed here and does not change the frozen row order or grant LocalPro access.

Core Identity owns accounts and entitlements; Core/Trust/Ops own durable case, payment and operational truth. This is LiveUIN private App UI evidence. No sibling product, imported tenancy or unrelated family record was used.
