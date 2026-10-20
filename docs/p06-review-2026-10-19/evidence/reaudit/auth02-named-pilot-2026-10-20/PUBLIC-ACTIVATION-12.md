# Public activation12 passed origin checks; browser journey still in progress

20 October 2026, Singapore. The [actual public12 activation result](frontend-public-activation-12.json), SHA-256 `0b4c21a6f5c48d0e21116023f539df4634bfb5a79fbb4301b2fff9b3abc7c9fb`, reports `public_entry_active_browser_smoke_required`. This is a successful bounded activation with **origin-only verification**, not an AUTH02 freeze.

Locked backend continuity passed. Both existing apex and www `/index.html` origin checks returned 200, verified the certificate, used loopback 127.0.0.1 with the real hostname, and returned the exact 2,332-byte candidate SHA-256 `d64151e0728796b61d396cb8c38d00f7bd8dc9c563975b42aa5caad86b02e268`. The result explicitly requires normal browser handoffs through the public edge on both hostnames. No public-access or payment switch changed.

The coordinating agent reported a browser-tool timeout after the server command had executed. Before retrying any action, it confirmed the saved success result over the existing SSH connection. A fresh browser inventory then identified the original in-app tab under its new tab ID. No duplicate activation is credited.

The actual normal browser reloaded the apex homepage and followed its header **Log in** link to `https://app.liveuin.com/auth/sign-in`, where the sign-in form rendered. The [apex-to-App screenshot](public-apex-app-handoff-12.png) was independently viewed during retention and contains no entered credentials. URL/navigation observation is attributed to the coordinating agent; the screenshot shows the resulting form rather than a browser address bar.

At this record, normal parent sign-in, reload and sign-out from that public entry, and the www handoff, were still being completed. **AUTH02 remains open; no full public journey or issue freeze is claimed.** Google and recovery buttons visible in the form remain separate later rows, not evidence that those options work.

The earlier [stopped activation11 and original-pointer recovery](PUBLIC-ACTIVATION-RECOVERY-11.md) remain retained. The [Cloudflare 1010 and strict-origin diagnosis](public-diagnosis-12/PUBLIC-EDGE-DIAGNOSIS-12.md) explains why origin readiness and normal public-browser proof are separate; no Cloudflare setting was changed or claimed as inspected.

Ecosystem boundaries remain unchanged: LiveUIN public/member UI uses canonical Identity, with Core/Trust/Ops retaining durable truth. No imported tenancies were used or emailed. No charge, refund, public-admission opening or sibling work occurred in this evidence-retention step.
