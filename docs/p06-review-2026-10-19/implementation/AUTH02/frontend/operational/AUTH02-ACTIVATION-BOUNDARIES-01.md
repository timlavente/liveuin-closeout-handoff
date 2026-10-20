# AUTH02 proposed activation and recovery boundary

Prepared locally from read-only checks. No upload, nginx reload, pointer switch, service restart or account change was performed. This is a reviewable plan, not deployment permission or a proof pass.

Candidate: `auth02-2c3dd7ac316e7cbe`; manifest SHA-256 `ab0eabe75d33b8218792eaa247ea2da6be1bd28d7776125d6928850a7bda9bcf`.

## Exact App change

[APP-ENTRY-ALIAS-01.diff](APP-ENTRY-ALIAS-01.diff) adds one exact `/index.html` location to the App HTTPS vhost. It aliases the pinned `app-entry.html` at `/var/www/liveuin-auth02-releases/auth02-2c3dd7ac316e7cbe/app-entry.html`. The proposed HTML SHA is `431419843f2f8696ef55426613a6e2aa8848e0fe6d613244ca9c36ec547716a8`.

App's existing `/` redirect remains `/app/member`. The SPA fallback remains `try_files $uri $uri/ /index.html`; the final internal redirect reaches the exact alias. No App API route, provider, registration, identity proxy, TLS, .well-known location, document root or asset route is changed.

The new location repeats the existing three App headers and existing security-header include, then adds `Cache-Control: no-store`. This is necessary because adding a location-level header otherwise suppresses inherited nginx headers. No security-header value is relaxed.

Verified current App config SHA: `dd2a557bd58adc7dc2bb823fa083f748a608039d9c7077d517e1283c9bf4013b`. Proposed config SHA: `d6e7afe4f451639ef28499774ff939bec9ddcb048ffaa4548e42c23027ad8637`. The proposal is not nginx syntax-tested on the host. A changed baseline requires a fresh bounded diff; never overwrite later admission-control changes using this full-file proposal.

## Preserve Partner and other surfaces

Add only the new immutable namespace at `/var/www/liveuin/assets/auth02-2c3dd7ac316e7cbe/`. Leave `/var/www/liveuin/index.html` byte-for-byte unchanged: SHA `415bfcdbd60ef8124e8a2fb480669324fb89b90752d4f0f458be5f8fb0eea15e`. Partner keeps its existing vhost and shared original HTML, so normal Partner navigation remains on the original graph. Do not replace the shared index or activate a Partner alias.

Partner vhost SHA: `51cae8f2eea512ff8d68ff5df8364309da717bcb6ac951234f5d8afb4dbf9ced`. App's Apple association file remains `f884f7b17617971746b0ce84392702f860f5ab7a0d135e127a63e67202041915`. Host and Ops files/configuration remain outside this frontend change.

## Public release boundary

The public vhost serves both `liveuin.com` and `www.liveuin.com`. Its root pointer is `/var/www/liveuin-public-releases/.liveuin-public-root`, currently targeting `/var/www/liveuin-public-releases/liveuin-lovable-20260915-01fe27bb`. A fresh read-only verification matched all 381 existing public files to the previously retained manifest, with no extra or missing paths. See [public-release-baseline-verification.json](public-release-baseline-verification.json).

Prepare a new complete public release from that pinned 381-file baseline. Keep all existing files except the mutable `index.html`; replace that entry with candidate `public-entry.html` and add the 362 new namespace assets. The expected complete release has 743 files. Old immutable URLs must continue returning their original bytes. Preserve all .well-known, policy, legal-link, social, sitemap and robots assets. The public Apple association is different from App's and must remain its existing public version.

No public nginx change is proposed. Its vhost SHA is `fd56cd248bfc7354b0d86c6dbe2f76a181e27e80090dd96b1822cda603eb1d34`. Existing Sierra/listing and marketing paths retain their specific Core proxy/alias routing; legal, preview, private-route denials and marketplace routes retain their existing behavior. Generic SPA routes and the two `/pass` exact routes that directly read `/index.html` will see the new public entry through the root pointer. The public assets location retains one-year immutable caching, which is why the new namespace is mandatory.

## Order and evidence before activation

1. Close the independently identified backend logout acknowledgment defect and admission/mapping conditions. A front-end acknowledgment check cannot repair a backend false acknowledgment. Preserve named test/owner separation and the held public launch/payment gates.
2. Verify current source, nginx and root hashes again; preserve exact pre-change copies, ownership/mode and the root pointer target. Install only inert, hashed artifacts first. Confirm App's alias target and both asset graphs are readable and complete.
3. Validate the complete proposed nginx configuration before any reload. Activate App alone and prove the approved named-account sequence on the real App domain: wrong password refused; correct password; canonical profile; reload; permitted account screen; wrong role refused; both actual logout controls; stale session rejected. No case or payment completion is implied by the account screen.
4. Only after App passes, switch the public root pointer atomically to the prepared complete release and smoke both public hostnames, public-to-App handoff, lazy imports and representative existing public pages. Confirm the unchanged Partner entry/graph and Host/Ops entry versions. Check actual response hashes and browser behavior; a health response is insufficient.
5. Record activation versions, browser evidence, held public access and held live charging in the AUTH02 freeze note. A failed proof stops this row.

## Recovery

Keep the old public release and old immutable graph intact. If App proof fails, stop before changing the public pointer and undo only the exact App alias block against the verified current config; preserve any independently approved admission/security changes. If public smoke fails after the pointer switch, restore the recorded previous public pointer atomically. Keep admission/public-live holds in place and retain the backend security/logout fixes; restoring old frontend bytes does not count as a successful auth proof. Do not remove the new namespace while any browser may still reference it. Recovery must itself be checked on App/public/Partner, then recorded as a failed row rather than bypassed.

The only proposed mutations are new static artifact directories, one App-only entry alias, and the public root pointer. There is no database migration, identity grant, payment action, imported-tenancy use or public-access opening in this frontend plan.

## Separate finding retained for AUTH06

Root's browser smoke observed LocalPro-only footer links on a Tenant account without that grant. Their destination stayed locked. This is an AUTH06 presentation finding and was not changed in AUTH02. Earlier full-graph fixture smoke passed wrong password, correct sign-in/reload, Tenant account, LocalPro refusal, both logout controls and protected reopening to welcome with return preserved; the final permission-consistency candidate requires the requested repeat smoke.
