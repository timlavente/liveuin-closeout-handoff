# D1 activation controller — independent review

Reviewed `/private/tmp/liveuin-p06-auth01-20261020/restore-delivery.py` on 20 October 2026 before upload or execution. This note concerns the initially reviewed 129-line version; a later version needs the affected checks rechecked.

The exact production source/unit hashes, stopped/enabled precondition, existing Ops URL/token selection, root-private backup, single-unit start and empty-body authentication probes agree with the deployed-source review. An authenticated `{}` reaches the required-fields error before database or SMTP. `/readyz` is only `SELECT 1`. The controller correctly does not call this an owner login or a row pass.

Concrete corrections requested before execution:

1. **Disable HTTP redirects.** The opener at line 37 disables proxies but retains redirects. A redirect from an unexpected listener could forward the internal-token header. Fixed loopback URL plus source hashes do not guarantee which listener receives it. Treat every redirect as failure.
2. **Check the effective unit and actual listener.** The source-unit hash does not cover drop-ins or prove the running command. Require empty `DropInPaths` and the expected effective command/environment-file binding; require no existing listener on 9094 before start. After activation and before the authenticated probe, verify the exact unit MainPID, process command/working directory/executable resolution and ownership of the loopback listener. This closes the wrong-process/wrong-branch case without reading customer records or arbitrary environment fields.
3. **Preserve recovery evidence if recovery fails.** The stop and state calls in lines 123–125 can throw outside the original try block. Catch recovery errors, always emit a sanitized result, and explicitly record whether the unit is inactive with MainPID 0 and the port closed. A failed stop must remain a visible unresolved recovery failure, never an implied return to baseline.
4. **Scope the mail assertion.** `message_sent: false` should describe this controller's requests. Once the service is active another caller may request a code. The reviewed source has no queue flush; that is narrower than proving no message was sent by any concurrent caller.

No secret values were read or printed for this review. No server mutation, request, mail, customer lookup or payment operation was performed by the reviewer. The ecosystem boundary remains the existing LiveUIN delivery adapter; Core identity and entitlements remain canonical.
