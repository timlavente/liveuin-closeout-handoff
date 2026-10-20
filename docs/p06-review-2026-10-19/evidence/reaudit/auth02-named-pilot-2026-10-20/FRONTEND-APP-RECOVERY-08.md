# Frontend App activation 08 stopped and recovered

20 October 2026, Singapore time. The [actual activation result](frontend-app-activation-08.json) is `stopped`, reason `app_activation_failed_exact_alias_recovered`. It makes no authentication or product-completion claim.

The coordinating agent confirmed that recovery restored the exact App nginx configuration baseline SHA-256 `a98bf4fedbc22a77313f5dadc004afa193795c5d66a77f9540473896d3824b50`, nginx was active, and App `/index.html` returned HTTP 200. The App candidate is not left activated by this attempt. No public frontend pointer activation or completed App-browser journey is claimed.

## What the timing evidence does and does not show

The [sanitized access-log summary](frontend-activation-08-log-summary.json) records `/index.html` returning 200 with 2,284 bytes at 15:36:49, and again at 15:37:51 and 15:38:52. The coordinating agent reported the activation-result file time as 15:36:49.905 and the recovered nginx configuration time as 15:36:49.785. The old shared index is 2,284 bytes; the proposed App entry is 2,332 bytes.

Those observations support a readiness timing race as a hypothesis: the immediate check may have seen an old worker's response while nginx reloaded. **Byte length and timestamps do not prove the exact old response hash.** No full old-body-hash result was captured in this evidence. The unrelated earlier error categories in the log summary are not attributed to this activation.

A bounded retry wrapper that waits only when the exact reviewed old response hash is observed was being prepared and independently reviewed. It had not been executed or credited as a successful activation at the time of this note. Unknown content, errors or other drift must not be treated as the known readiness transition.

## Separate payment-source reconciliation

The [15:31 runtime classification](payment-lock-auth02-1531.json) retains its original `false` match for the customer-card provider's old source pin. It is not rewritten as an all-source-match result. The other twelve checked source matches are true. The observed live-rail flags were absent/false; Core's Stripe key was classified as test; legacy Connect selected no external-provider dispatch; customer-card sandbox setup was enabled.

The separate [provider review 15](provider-review-15/PROVIDER-CHANGE-REVIEW-15.md) and [classification](provider-review-15/provider-change-classification-15.json) reconcile that source delta: the SetupIntent request field changed from `payment_method_types[]` to `allowed_payment_method_types[]`; normalizing that one constant leaves the rest of the source AST identical. Test-key enforcement, fixed provider endpoints, `livemode: false` and exact returned card-type checks remain. The review does not prove provider acceptance, card setup, payment or refund.

This combines bounded source and startup-configuration evidence only. It does not claim universal payment readiness or a complete public-charge lock beyond the separately reviewed routes. The separate Pay service was not inspected by that classification. No payment or provider API call occurred in this retention task.

The actual parent API and server logout proof remains passed in PARENT-API-PROOF-08. Actual App-browser proof and case isolation remain pending, and AUTH02 remains active. Core Identity/Core/Trust/Ops retain canonical ownership; no imported tenancy or sibling product was used.
