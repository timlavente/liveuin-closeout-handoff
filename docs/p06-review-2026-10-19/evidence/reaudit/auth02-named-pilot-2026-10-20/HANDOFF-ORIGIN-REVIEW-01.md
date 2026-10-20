# Local handoff browser compatibility review

Reviewed 20 October 2026. This is a localhost verification handoff only; Core Identity remains the canonical account and session authority. No production code, identity, grant, mailbox or factor was read or changed in this review.

The earlier handoff sent `Referrer-Policy: no-referrer` while requiring the exact local `Origin` on a normal HTML form POST. The Fetch standard's Origin-header algorithm sets the serialized origin to `null` for this non-CORS POST under that policy. MDN explicitly documents HTML form submissions as affected. This establishes a concrete compatibility defect; a safe local failure-reason classification is still needed to attribute the user's specific submission. A stale CSRF token after a local process restart is another possible refusal branch.

Sources:
- https://fetch.spec.whatwg.org/#append-a-request-origin-header
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy#effect_on_the_origin_header

Bounded correction: use `Referrer-Policy: same-origin`, keep exact local Host and Origin matching, keep null Origin refused, and reload the form. Persist a random CSRF token in the existing private directory at mode0600, tied to this same registration ID; compare in constant time and reuse only for the same registration. A previous unpersisted process token cannot be recovered; the current browser must reload once. Retain expiry checks before submission and canonical verification. Use fixed refusal labels without printing request body, code, CSRF value or other header values. Never replay a submitted code automatically.

No browser or production verification was performed by the reviewer. The submitted factor stays with the owner and normal canonical verify route.
