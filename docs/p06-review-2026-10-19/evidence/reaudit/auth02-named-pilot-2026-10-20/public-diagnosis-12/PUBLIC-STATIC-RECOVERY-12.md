# Public entry recovery and static permissions

Checked read-only on 20 October 2026, about 16:32–16:35 Singapore time, using the existing `liveuin-hk` SSH alias. No application, nginx, pointer, account, payment or security setting changed by this check.

The failed public activation11 restored `/var/www/liveuin-public-releases/.liveuin-public-root` to `/var/www/liveuin-public-releases/liveuin-lovable-20260915-01fe27bb`. A fresh `readlink` independently confirmed that target. The current App nginx configuration still hashes to `949256d02fa4e26ba69e013cb717551c2e0fac7b16d9c80151632962b3f39a0b`.

The original public tree contains 381 files and four directories. The new `liveuin-auth02-34c8511dd5a2a5ad` clone contains 743 files and five directories. Every directory in each tree is root:root mode0755; every file is root:root mode0644. Neither tree contains a symlink. All ancestors of the release directories are traversable. The pointer itself is a normal root-owned symlink.

Original entry SHA256: `415bfcdbd60ef8124e8a2fb480669324fb89b90752d4f0f458be5f8fb0eea15e`.

New entry SHA256: `d64151e0728796b61d396cb8c38d00f7bd8dc9c563975b42aa5caad86b02e268`.

The public nginx vhost uses that pointer as its root and the existing `try_files $uri $uri/ /index.html` fallback. Its static-route include has no rule denying `/index.html`. No artifact permission defect was established. The safe activation11 result records HTTP403 and successful original-pointer recovery; it does not identify the cause itself.

Separate root/source-review observations established that the unchanged baseline also receives the external automated403 while ordinary public browsing works, and that a strict TLS loopback origin check returns the exact old entry. Root identified Cloudflare error1010. Those network observations belong to their separate retained evidence; they are not inferred from the filesystem check above.

Runner12 changes only the public static verification transport to the existing origin with normal hostname/SNI/certificate verification. It retains the reviewed source gates, both locks and original pointer recovery. Its automated result is explicitly origin-only. The normal public browser handoff through Cloudflare remains required on both `liveuin.com` and `www.liveuin.com` before AUTH02 can pass. No public-access or live-charging switch is part of this repair.
