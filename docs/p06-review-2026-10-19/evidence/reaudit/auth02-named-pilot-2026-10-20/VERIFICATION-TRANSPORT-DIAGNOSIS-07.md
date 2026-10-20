# Parent verification transport diagnosis

The local helper sends the correct deployed route and JSON field. `core_identity_api.py:801` accepts POST `/api/core/identity/registrations/{registration_id}/verify`; `core_identity_public.py:1148` reads `verification_code`, and its successful response includes `status: authenticated` and a session credential. The local handoff's expectations match that contract.

The lifecycle evidence contains no verification response. A normal JSON API rejection would be written before the helper raises its stop exception; the generic browser message also covers transport, response parsing and local persistence errors. It was not proof that the user entered the wrong code.

Root diagnosed the running local helper under Frameworks Python3.13, while successful lifecycle calls used Homebrew Python3.13. Root's safe, data-free HTTPS OPTIONS comparison reported Frameworks URLError caused by SSLCertVerificationError, verify code20 (missing local issuer), while Homebrew verified TLS and received the expected405 JSON response. These runtime results were reported by root; this reviewer did not repeat the request or inspect a code, credential, registration record or account document. Use the working interpreter with normal strict TLS verification; do not disable certificate checks.

Independent staff-denial probe source/schema checks are recorded in `OPS-DENIAL-PROBE-REVIEW-07.json`. No signed parent probe or production mutation was performed by this reviewer.

Boundary check: this is LiveUIN private-app Identity verification and existing Ops admission proof. Canonical Identity/session ownership is unchanged; no imported tenancy or sibling product was used.
