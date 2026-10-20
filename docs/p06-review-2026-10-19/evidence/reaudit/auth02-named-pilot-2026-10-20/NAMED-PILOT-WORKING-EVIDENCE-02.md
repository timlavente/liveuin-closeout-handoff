# AUTH02 named-pilot work — member candidate active; normal proof pending

20 October 2026, Singapore. This succeeds the working status in [note 01](NAMED-PILOT-WORKING-EVIDENCE-01.md) without changing its historical evidence. It is not an AUTH02 issue pass or permission to publish.

## Actual member activation

[Retry 13](member-retry-13.json) activated the intended member candidate, replacing closed-fallback PID 3662305 with **PID 3675726**. The checked Ops process remained PID 3669871. Raw challenge create and verify returned 404; outside-cohort registration and password returned 403; unsigned resolution returned 403. All five responses had `no-store`. The result remains `candidate_active_normal_browser_proof_pending` with `recovery_required: true`.

The runner actually executed was SHA-256 `00ba41f14120b99b07c2658663f2c27d418f42137c80167e336094ec1c07002d`. The [actual-execution note](activation-13/MEMBER-ACTIVATION-13-ACTUAL.md) and [exact executed source](activation-13/evidence/actual-executed-retry-member-admission-13.py) preserve that fact. Its successful run did not enter recovery. The later emergency-lock correction, SHA-256 `f39fb816bed0cc8904ce46916c3beaf027d1f53cd356d3a56d25ae98d540f8d2`, was not executed and is not credited as the activation. The separately reviewed current recovery contingency also remains unexecuted.

## Concurrent mobile configuration and payment hold

The [bounded classification](mobile-addition-classification-13.json) identified exactly the separate mobile task's test-card configuration addition. Existing environment-file order and credential bindings were preserved; the new file contains no identity-store or signer keys. It enables customer-card **sandbox setup**, uses a test publishable key and the reviewed webhook reference, and remains scoped to the public LiveUIN workspace. These are the other task's changes, not extra work delivered by AUTH02.

At 13:30:32 Singapore, the [fresh payment classification](payment-lock-after-member-13.json) matched the 13 reviewed source files. Checked Core live-rail flags remained disabled, Core Stripe remained on a test secret key, and legacy Connect selected no external-provider dispatch. The customer-card sandbox flag is now true. It must not be confused with live charging or described as still false using the earlier 04:22 snapshot. This read-only startup-environment check made no provider request or payment and does not claim universal payment readiness; its routing/source and separate Pay-service limits remain explicit.

## Google readiness is evidence for the next row only

At 13:30:25 Singapore, [the selected Google configuration check](google-web-presence-13.json) bound the observation to member PID 3675726 and the exact source versions. Native ID-token readiness and public Google enablement are true. Browser redirect URI, client-secret/state-secret references, and exchange/callback readiness are absent or false. The source therefore selects its native path, while `member_web_inputs_present` is false.

No product module, provider-status endpoint, credential resolver, Google API or identity/customer record was used by this check. It does not prove native login works, authorize a provider change or start AUTH03. AUTH02 retains the queue position.

## Remaining normal proof

The [sanitized lifecycle snapshot](parent-lifecycle-evidence-through-registration-13.jsonl) records the named synthetic parent's normal registration returning 201. The [13:32 handoff evidence](parent-factor-handoff-evidence-13.json) records delivered email and the mailbox connector deliberately withholding the one-time factor. No factor was retrieved or bypassed. A temporary user-entry handoff at `http://127.0.0.1:56383` was opened so the owner can enter the delivered factor directly; verification was still pending in that observation. Its form returned 200 with `no-store`, and a cross-origin POST was refused with 403. Those are local-form checks, not a product authentication pass. That local address is a temporary test handoff, not a new production product URL. No file from `private-parent` is included in this retention.

Registration and delivery are not completed sign-in, approved-profile or logout proof. The normal parent lifecycle must finish, then the actual App browser must prove password rejection, the permitted account, canonical reload, the wrong-role refusal, both sign-out controls and stale-session rejection.

The existing [frontend stage result](frontend-stage-09.json) remains inert: no App alias or public pointer activation is evidenced here. App activation still requires genuine completed parent lifecycle evidence. The public pointer is a later separate phase requiring actual App browser proof. The earlier local fixture cannot replace those production checks.

All retained files and their provenance are listed in [RETENTION-MEMBER-13-MANIFEST.json](RETENTION-MEMBER-13-MANIFEST.json). Previous retention manifests and freeze artifacts are untouched. No AUTH02 issue pass, family-case proof, payment proof, P6 completion or public opening is claimed. Imported tenancies were not used or emailed. Core Identity/Core/Trust/Ops remain authoritative; sibling products remain outside the repair.
