# AUTH02 named-pilot work — recovery, held retries and inert frontend stage

20 October 2026, Singapore. This is an additive working record, not an issue freeze or a passed member journey. The frozen plan, AUTH01 pass and earlier 9095 component proof remain unchanged.

The first member activation stopped on `protected_file_type_invalid` and left the member service stopped. That result is already retained in [member-activation-09.json](member-activation-09.json). The explicit closed recovery then restored the service with PID **3662305**, using the reviewed closed fallback. [Recovery evidence](member-closed-recovery-09.json) records raw challenge create/verify as 404 and outsider registration/password and unsigned session resolution as 403, all with `no-store`. It does not prove an approved member can sign in; further recovery/activation work remains required.

The next three bounded attempts stopped before completing member activation:

| Attempt | Recorded stop | Evidence |
|---|---|---|
| Retry 10 | Existing baseline PID changed; reconciliation required | [member-retry-10.json](member-retry-10.json) |
| Retry 11 | Fresh Ops reconciliation failed | [member-retry-11.json](member-retry-11.json) |
| Retry 12 | Fresh Ops reconciliation failed | [member-retry-12.json](member-retry-12.json) |

The [read-only diagnostic after retry 12](member-reconcile-diagnostic-12.json) found Ops active with PID **3669871** before and after the check, started at 13:15:24 Singapore. The reconciler reported `unit_configuration_drift`; its list of changed protected configuration files was empty. This result does not identify or authorize a particular configuration change. The diagnostic made no service/configuration change, auth request or customer-row read. The separate concurrent mobile work and its process changes must be reconciled as deployment inputs, not claimed as this auth repair.

At 13:17:53 Singapore, the [frontend stage](frontend-stage-09.json) completed with `inert_static_stage_complete` and `active_configuration_or_pointer_changed: false`. The stage state is retained on the server at:

`/root/liveuin-closeout-backups/AUTH02-FRONTEND-20261020T051753Z-3671134/state.json`

The immutable frontend files are present, but neither the App alias nor the public root pointer was activated by staging. Partner's shared entry remains selected. Genuine approved-parent lifecycle evidence must precede App activation; actual App browser evidence must precede the separate public pointer phase. Neither gate is passed by this stage result.

The six new JSON files in this note were copied byte-for-byte from the verified host's sanitized `/tmp/liveuin-r01-access-check-20261020` exchange directory. Their source checksums were verified during retrieval, and retained copies are enumerated in [RETENTION-STAGE-09-MANIFEST.json](RETENTION-STAGE-09-MANIFEST.json). Earlier files in this directory were preserved.

AUTH02 remains active. R01's 21-operation repair remains staged; AUTH03–AUTH06 and later frozen rows have not been advanced by this retention. These results contain no live payment, provider enablement, account/grant creation or database restore. Public access is not opened. Public live charging remains held; this retention does not replace the separately dated payment-lock evidence. Imported tenancies were not used or emailed.

Ecosystem boundary: existing LiveUIN public/private entry and canonical Core Identity only. No sibling site, connector or channel becomes the owner of cases, identity, payments or permissions.
