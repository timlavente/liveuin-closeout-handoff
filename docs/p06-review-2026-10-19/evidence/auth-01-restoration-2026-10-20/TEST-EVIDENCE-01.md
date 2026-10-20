# AUTH-01 isolated verification evidence

**PASS: all14 checks passed against the captured deployed9095 Identity code.** This is isolated verification evidence for AUTH-01. The parent's actual owner browser sign-in and delivery evidence remain separate; this suite does not mark AUTH-01 or the staff desk complete by itself.

The suite executes the actual canonical login verifier, login/identity/session stores, session signer/resolver and Ops membership code. The small browser request/verify adapter and cookie helpers are unchanged AST function nodes compiled from the pinned deployed files. Their line spans and AST hashes are recorded. They are not reimplemented test substitutes. The unrelated FastAPI/guest-projection routes are not imported, and no HTTP protocol mock is presented as a live endpoint test.

| Required check | Result |
| --- | --- |
| Wrong code | Refused403, `identity_login_challenge_invalid_code`; attempts recorded; no session created. |
| Expired code | Refused410, `identity_login_challenge_expired`; expiry state recorded; no session created. |
| Reused code | Refused409, `identity_login_challenge_not_pending`; no additional session created. |
| Valid control after one wrong attempt | Issued a canonical session with the fixture's approved `ops_manager` role, original workspace and exact existing role scopes. Requested `super_admin` and foreign workspace did not override membership. |
| Canonical session validation | Actual signed cookies resolve as `signed_session_verified_store_active`. Forged role header is refused; hostile workspace/role body cannot grant access. |
| Membership controls | Unapproved fixture email/workspace refused. Revoking the fixture membership after requesting a code prevents verification. |

The wrong value is guaranteed to differ from the generated fixture code. Expiry is represented by setting the isolated challenge's persisted expiry to the past; the verifier and its clock functions are unchanged. Successful issuance is the positive control for the reused-code test. No raw code, session credential, signature or cookie is written into the result.

Before imports, the harness assigns all relevant Identity stores to fresh directories under this non-cloud evidence folder. Python runs with `-I` and bytecode writing disabled. An audit hook refuses nonfixture SQLite connections, production/cloud paths, nonfixture writes, network activity and child-process execution. The successful run opened only three temporary SQLite files (identity, login, session); network attempts and forbidden file attempts were both zero. Source reads over SSH copied source text only: no product imports, application endpoint requests, database reads or email took place on the server.

Existing `core_identity_login_smoke.py`, `core_identity_ops_browser_auth_smoke.py`, `core_identity_host_browser_auth_smoke.py` and `core_identity_otp_gateway_smoke.py` were reviewed first. Their wrong/reuse/membership assertions were useful, but they import before fixture setup; the login smoke has no expiry assertion. The new harness places isolation first and covers expiry. It does not run unrelated WeChat/Host tests or fake a successful delivery gateway.

During harness construction, a broad `/opt/` read guard also blocked the local Homebrew Python standard library; it was narrowed to production `/opt/liveuin` paths. A constant parser and the fixture store connection call were corrected. The initial session assertion assumed a foreign-workspace payload should be ignored; actual deployed code correctly refused it. The retained `harness-initial-resolve-expectation.json` records that test expectation failure. The final suite separates the valid empty-body resolve control from the hostile request and accepts refusal or correctly scoped resolution. No deployed product code was changed to make a test pass.

Evidence files:

- `result.json`: all14 named checks, exact UTC run time, Python version, safety counters and unchanged extracted-function identities.
- `source-manifest.json`: exact deployed `/opt/liveuin/deploy` paths, capture times and15 source-file SHA256 values; every local input is checksum-verified again before execution.
- `run_tests.py`: complete reproducible isolated harness; its SHA256 is embedded in the result.
- `source/`: checksum-matched source inputs used by that run. Do not copy these wholesale back to production.
- `owner-proof-readonly.py`: separate, unexecuted helper for the parent's exact delivered-factor owner proof. It has fixed account/challenge/window bounds and emits only approved role/workspace/status metadata. It cannot replace the browser factor evidence.

Only synthetic local fixtures were created or altered. No production account or record was created, no imported tenancy was read or contacted, no payment setting changed, and no public access opened. Ecosystem boundary checked: canonical LiveUIN Identity/Core session and role authority only. No sibling or connector work.
