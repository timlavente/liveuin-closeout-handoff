# Public verifier diagnosis12 — edge refusal separated from origin readiness

20 October 2026, Singapore. This adds evidence to the [failed public activation11](../PUBLIC-ACTIVATION-RECOVERY-11.md); it does not erase that failure or pass AUTH02.

The default Python client received403 for apex/www, both `/` and `/index.html`, from laptop and server at16:32 Singapore. All eight retained responses have Cloudflare headers and the same17-byte body hash. The coordinating agent separately inspected the exact body `error code: 1010` followed by a newline; hashing that fixed public error text matches the retained hash. This statement is attributed to the coordinator's inspection, rather than claiming the metadata-only probes saved body text.

[Cloudflare's official error1010 documentation](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1010/) describes denial based on the client's browser signature. This supports classifying the automated403 as a Cloudflare client-signature refusal. **The configured site rule was not inspected**; no specific enabled setting, event match or reason for that configuration is claimed. No security setting, user-agent or access grant was changed.

The coordinating agent reloaded the restored public homepage through the normal in-app browser and observed it working. This is an observation of the old restored public release, not proof that the new public login is active.

At16:34:34 Singapore, the separately authorized [strict local-origin checks](origin-tls-metadata.json) returned200 for all four existing public URLs. Each retained hostname/SNI, normal certificate validation (`ssl_verify_result: 0`), no redirect following, loopback destination and exact original entry SHA-256 `415bfcdbd60ef8124e8a2fb480669324fb89b90752d4f0f458be5f8fb0eea15e`. This demonstrates that the restored origin serves the reviewed original bytes; it is not public-edge browser proof.

The [source diagnosis](PUBLIC-403-DIAGNOSIS-01.md) and [independent static recovery check](PUBLIC-STATIC-RECOVERY-12.md) found the original pointer restored, App return11 unchanged, expected file hashes and readable owner/modes, with no demonstrated artifact-permission defect. Historical earlier wording in the source diagnosis is preserved; the later origin check and coordinator's1010 observation narrow the cause evidence.

The same-row public12 verifier correction can therefore check exact static bytes at the authorized origin while retaining **mandatory normal public browser proof through Cloudflare on both apex and www**. Origin200 alone cannot pass AUTH02. The public handoff, final version and issue freeze remain pending. No payment, imported tenancy, account privilege or sibling product was touched by these read-only checks.
