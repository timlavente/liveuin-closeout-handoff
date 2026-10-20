# Public activation11 HTTP403 — bounded read-only diagnosis

The failure is not specific to `/index.html` or the newly staged release. After the controller restored the original public pointer, the same default Python verifier received HTTP403 for all four ordinary public URLs from both laptop and server: apex/www, each `/` and `/index.html`.

All eight responses had `Server: cloudflare`, `Content-Type: text/plain`, no-store/private cache headers, 17 bytes and body SHA256 `2938e9f1284180959e33ab1718d0793a72ff6e4cdb8108c34dcd14e69446de5c`. Bodies were hashed only; no body text, cookies or credentials were retained. No proxy, redirect follow, alternate user-agent, origin bypass or access-rule change was used.

The controller's retained result says locked backend continuity passed, external request returned403, and original public pointer recovery passed. Fresh filesystem read confirms `.liveuin-public-root` points to `liveuin-lovable-20260915-01fe27bb`.

Fresh public nginx source SHA256 is `fd56cd248bfc7354b0d86c6dbe2f76a181e27e80090dd96b1822cda603eb1d34`. Its HTTPS vhost serves both names; root is the existing pointer, index is index.html, and generic location uses `try_files $uri $uri/ /index.html`. Its two included public snippets add security headers/asset/legal semantics, with no root/index denial or authentication gate. Both old/new release directories are755 and both index files644. Old index SHA415bfcdb… and new index SHAd64151e0… match the reviewed baselines.

This rules out a path-only unsupported-index explanation and an obvious file-permission/hash defect. It does **not** prove the exact Cloudflare rule, prove origin processing, or prove that the new release serves successfully through the public browser. The external403 could reflect an edge/client policy; that remains an inference until ordinary browser observation or existing edge-event evidence identifies it.

Smallest next check: use the ordinary browser on the unchanged original public URLs, and if required inspect the existing Cloudflare event for the retained Ray IDs. Preserve all access controls. Do not declare the403 a candidate pass or bypass the edge. No AUTH02 freeze or later-row implementation follows this failed public proof.

Evidence: laptop-http.json, server-http.json, liveuin.com.conf.txt and routing-and-file-metadata.txt in this directory. No production state was changed by this investigation. Ecosystem boundary remains public static UI only; Core identity, payments and imported tenancies were untouched.

## Additional authorized origin check

After the coordinating agent observed the restored homepage succeed through the normal browser, it explicitly requested a strict local-origin diagnostic. At08:34:34UTC, `curl --resolve <existing-host>:443:127.0.0.1` returned200 for all four ordinary public URLs, with certificate verification result0 and exact original2284-byte entry hash415bfcdb…. TLS verification, hostname/SNI and no-redirect behaviour were retained. No access-control settings, user-agent spoofing or provider/account operation was used.

This is origin readiness evidence only. A deployment verifier may use the exacthash local-origin check to decide whether the pointer change correctly serves the reviewed files, while preserving the separate mandatory normal-browser check through the public edge. It must not label local-origin success as Cloudflare/public-client success. Actual public login handoff on apex/www remains required before AUTH02 closes; the earlier external403 and recovery remain retained as failed verifier evidence.
