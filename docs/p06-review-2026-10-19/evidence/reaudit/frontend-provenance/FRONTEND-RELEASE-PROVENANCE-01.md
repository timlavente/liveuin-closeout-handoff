# Frontend release provenance — 20 October 2026

Read-only audit, approximately 00:27–00:31 Singapore time. No install, build, checkout, source edit, upload, production change or customer-record read. Only new local evidence/report files were written.

**Neither the local working tree nor GitHub main is proved to be the source of the served frontend. A full rebuild would introduce unrelated changes. D1 delivery can remain backend-only: the deployed Ops component already calls the affected request-code adapter.**

## Exact production map

Fresh SSH metadata/hashes agree with the retained HTTP asset and nginx routing audit:

| Surface | Actual webroot / entry | Entry asset and SHA256 |
|---|---|---|
| Apex/www | `/var/www/liveuin-public-releases/.liveuin-public-root` → `/var/www/liveuin-public-releases/liveuin-lovable-20260915-01fe27bb` | `index-DPZwxwE9.js` — `2db8bfcb0aeecd9a975dde8192ca612f0d3f056d6c70e04173f5b4d27f4102fa` |
| App/Partner | `/var/www/liveuin`, a separate ordinary directory | Same DPZ bytes |
| Host | `/opt/liveuin/releases/liveuin-host-20260928T052333Z-before` | `index-Cxfe6mRB.js` — `095faa1491b4f1861fecc10ac46e98fad1df3ac69da8ef98dc4574d38dce57ac` |
| Ops login | HTML `/opt/liveuin/production-ui-auth/ops-auth-shell.html`; assets `/opt/liveuin/releases/liveuin-auth-20260917T052635Z-ops-gate/auth-ui/assets/` | `index-BAq4vWNL.js` — `cf52d5eac5bc895d94972c56552cb7d72c40e292d1f16b40e87356d5424e15ef` |

The complete current public distribution has **381 files, all paths and hashes exactly matching the retained September 15 manifest**. This is a fresh full comparison, not just an entry-file match. On-disk public/App/Partner index SHA256 is `415bfcdbd60ef8124e8a2fb480669324fb89b90752d4f0f458be5f8fb0eea15e`. The HTTP apex/www HTML includes the previously observed Cloudflare beacon, so its different transport hash alone is not source drift.

No source maps were found in the four asset roots. Their top-level entries contain distribution files, not Git metadata, package/lockfiles or a source-build manifest. The Ops release parent contains only `auth-ui`. `/opt/liveuin/www-lovable` contains partial `src` and `dist`; `src` has App.tsx, assets and pages, without the checked auth provider/project inputs. It is not a reproducible source project.

A public symlink change would not update App/Partner, Host or Ops. The separate Sierra marketing aliases and Host listing-entry override must also remain outside an unrelated shell replacement.

Evidence: [fresh webroot metadata/full manifest](production-webroot-provenance.json), [381-file comparison](active-manifest-comparison.json), [served-route audit](/Users/Vivian/Documents/Liveuin/docs/p06-review-2026-10-19/evidence/reaudit/AUTH-CONSISTENCY-AUDIT-01.md).

## Local source and distributions

`www-lovable` is its own Git repo. HEAD/main is `e389b10a1809df380e181ff91415e7f7ccf075ca`, 10 September, “Release claims-safe LiveUIN public remediation.” Status has **141 modified tracked files and 1,103 untracked entries**, including generated distributions and native work. Preserve them.

Its only configured origin is a private `git.chatgpt-team.site` repository, not the named GitHub resident repository. A read-only remote-head query failed for missing authentication. Cached `origin/main` is `2c2aacb69c8e2b0de8987a426f1f7ebb3d5ef598`; this is not a fresh remote-head claim. The registered September promotion worktree directories no longer exist, though their branch objects remain. `01fe27bb` is not a local commit object.

Current local entry assets are `dist/index-DofG-jLY.js`, `dist-ops-login/index-DyL0kSSc.js` and `dist-studio/index-BdVJYwN4.js` (each under its `assets/` directory). None matches the three served entry assets. The former checkout-only commit `a684abdd3647c80724319c8cdfebfa86b63b0f6c` is genuine, but its retained build comparison explicitly differed from the active release; it is not a safe substitute.

Inputs read here have positive local blocks and readable bytes. No cloud placeholder was called empty/corrupt. See [local hashes/status](local-source-provenance.json) and [retained source-lineage audit](/Users/Vivian/Documents/Liveuin/outputs/liveuin-public-checkout-handoff-2026-09-16/SOURCE-LINEAGE-AUDIT-2026-09-16.md). Historical approval instructions in that audit are evidence, not a new instruction to ask Ern again.

## GitHub is useful source, not a production-build match

Fresh GitHub API checks confirm [resident main `16bafa745c9b6821796a7ed45e742699669f838e`](https://github.com/timlavente/liveuin-resident-app/tree/16bafa745c9b6821796a7ed45e742699669f838e), dated 16 October. It includes account-deletion/error-handling changes. The repository was created on 7 October; its latest push is 18 October. Other current branches are `gb/liveuin-finish-publish-2026-10` (`14dfd11445f8560f9dc6f50ffc7203ca18290c37`) and `publish-readiness-2026-10-17` (`3cb6f04bc8f67f5c25f5aa539cd7de4cecfa07c8`). Direct `01fe27bb` lookup returns “No commit found.” No GitHub release or retained Actions artifact exists. All seven returned workflow runs are TestFlight, not evidence linking these served web assets to source.

The pinned GitHub auth provider submits passwords to `/api/core/identity/sessions/password`, and includes recovery/server logout integration. The served DPZ provider instead uses the preview challenge exchange. This is useful existing implementation material, **not** evidence the website runs it.

| GitHub file at pinned main | SHA256 | Local comparison |
|---|---|---|
| `src/lib/auth-context.tsx` | `296a61fb02180be8e2604252fee55a7fba071969eef8bad2ab7dac67c038a21b` | Different |
| `src/native-lovable/routes/auth.sign-in.tsx` | `fbe4feb865033c016b52656979ddf03a054ef91f6a18ddd394444e760a86ce15` | Different |
| `src/pages/OpsLogin.tsx` | `486bfbdee984ce6276811482c68c4b3e5cdac0a14b9e5bcc2d6586576b198a8c` | Exact |
| `src/pages/WorkspaceSignIn.tsx` | `4d922648a4468367ae3e2097e8afe94677b094abe4af0b1678602f327fa33757` | Exact |
| `package-lock.json` | `74ea5b3dad7dede5f7f1092c7584b84ba68bf9c29582ef08cd483233885aaad1` | Exact |

`package.json` differs even though the lockfile matches; Vite config matches. The package prebuild generates resident link manifests and Vite has native-only/preview modes. Exact component equality does not establish full-build equality or authorize promoting unrelated registration/deletion/mobile/content changes.

## Smallest safe implementation direction

- **For D1 now: no frontend patch.** Keep every webroot/asset hash unchanged while fixing the existing permitted delivery adapter and proving normal sign-in.
- **For later frontend faults: no verified full-build baseline is available.** Do not promote dirty `www-lovable`, the old checkout candidate or resident main wholesale, or label a release-directory suffix a commit.
- A bounded auth-only build from pinned existing auth source is the narrow packaging option to investigate if original full source remains unavailable. It must keep unrelated deployed assets unchanged, use an explicit isolated entry/build configuration, and handle the actual SPA transitions as well as direct URLs. This is an engineering option, **not a built or cleared candidate**. A direct nginx redirect alone cannot repair client-side React Router transitions.
- Bind the session storage/headers, downstream hydration, safe return and server logout contract before choosing that boundary. A new login that the existing shell cannot use or revoke is not a repair. Relevant existing components are `Login.tsx`, the resident provider/sign-in/bridge and `WorkspaceIdentityGate.tsx` for Partner's error handoff. Preserve Host/Ops email-code behavior unless its actual fault requires change. Partner's missing adapter routing is an explicit separate affected configuration, not fixed by shared JS alone.
- Later release proof must enumerate every changed asset/reference/route, preserve unrelated hashes in each separate root, and prove allowed/refused/sign-out paths. No new brand, broad frontend update, mobile/account-deletion work, fake active provider or new identity authority is implied.

The implementation baseline gap belongs to engineering; it does not require Ern to debug history. D1 backend progress is independent. No frontend repair or production-auth pass is claimed here.

Boundary/persona check: global README, sitemap/P0–P6, tracker, persona/entitlement audit, auth-provider policy, Laijuzhu blueprint and ecosystem audit were checked. This is public handoff/private App–Host–Ops–Partner entry work. Canonical Identity owns role/workspace/entitlement decisions; Core/Trust/Ops own durable truth. Parent, agent, host and staff scopes/locks remain separate; URL role selectors do not grant access. No shortcode, sibling theme, WeChat, imported tenancy or AI/demand implementation changed.
