# AUTH03 public browser proof passed

20 October 2026, Singapore. After the public activation, the coordinating agent used the normal in-app browser on both domains:

| Entry | Actual normal browser result |
|---|---|
| `https://liveuin.com/` | Homepage loaded; visible header Log in led to `https://app.liveuin.com/auth/sign-in`; truthful unavailable notice appeared with no Google button. |
| `https://www.liveuin.com/` | Homepage loaded; visible header Log in led to the same App sign-in page; the same notice appeared with no Google button. |

The [apex screenshot](public-apex-google-notice-01.png) and [www screenshot](public-www-google-notice-01.png) were independently viewed. Both show “Google sign-in is not available on this website yet. Use your email and password.” Neither exposes an entered credential. The navigation sequence is the coordinating agent's actual observation; screenshots show the resulting form.

The [public activation result](frontend-auth03-public-activation-01.json), SHA-256 `36a74ad42c3ff49b9d501c830d1a2a5d288630cbec6ef51416bfc5ba6e28adb2`, passed backend continuity and strict-TLS origin checks for both hosts. Each origin returned HTTP 200, 2,332 bytes and exact entry SHA-256 `62ac4fcabd7e99e942fad05fec241d89e2c0654383f4afe3a83fd09ace1c8b95`. Its deliberate “browser smoke required” flag is satisfied by the separate normal-browser observations above, not rewritten in that historical output.

The earlier [actual App checks](AUTH03-APP-PROOF-01.md) also passed named-parent password, allowed return, full canonical reload, body sign-out navigation and private reopening refusal. AUTH02's server-revocation and negative results remain explicitly carried forward under the unchanged-code delta. No Google provider round trip, new native configuration, new account grant or later-row proof is claimed.

The [temporary verification handoff cleanup](temporary-verification-retired-01.json) records that its already-completed success page was replaced by the official App sign-in page and its local helper was stopped. No further code was requested and no credential or account grant changed.

The unchanged cooperative locks and preserved source/service gates remained part of activation. No public-admission or live-charging switch changed. Imported tenancies were not used or emailed. This completes AUTH03's frozen **explicit-unavailability/no-active-control** alternative, while Core Identity/Core/Trust/Ops retain their ecosystem responsibilities.
