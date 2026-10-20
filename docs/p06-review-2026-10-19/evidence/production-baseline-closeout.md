# LiveUIN production baseline closeout — 19 October 2026

**The bounded source-identification planning gap can close. Production readiness cannot.** The existing services, executing entrypoints, on-disk source versions and Sierra mounting/routing are identified. A full reproducible Git release, effective store selection, backups and authority to perform each future write remain execution checks owned by the engineer. They are not commercial decisions for Ern and do not justify building another Core.

Read-only observation: 19 October 2026, approximately 20:00–20:08 Singapore. No code, service, configuration, account, payment or flag changed. No database opened, customer/imported-tenancy record read, or secret value printed. Boundary rules and cloud-placeholder safety from the initial audit remain applied.

## The existing release baseline

`production-baseline-manifest.json` records actual process arguments, systemd service metadata, resolved paths, SHA256 values and local comparisons. It contains 67 hashed files after the protected Ops entry was obtained by a read-only remote rsync sender. Three other requested files remain unreadable in this bounded check. Additional Identity candidate-module hashes are in `store-bindings-and-identity.json`; these are candidate on-disk dependencies, not a verified complete Python import graph.

| Service / route | Executing entry and source | File SHA256 |
|---|---|---|
| Public API, 9080 | `liveuin-public-api.service`; `/usr/bin/python3 -m uvicorn deploy.public_home_gateway:app`; working directory `/opt/liveuin` | `67f4befdd7dbccc34bcaa79050b6c990cd3df33349ee4369f7da9838810f6fac` |
| Core/Ops backend, 9095 | `ops-backend@liveuin.service`; credential wrapper starts `/opt/liveuin/ops_backend/.venv/bin/python -m uvicorn app.main:app`; working directory `/opt/liveuin/ops_backend` | `app/main.py`: `e843d45640ddfc58e8a2957ea50726c17fe8be4056b9023f2c887648493423da` |
| Legacy application loaded by that entry | `/opt/liveuin/ops_backend/app.py`; `app/main.py:18–20` establishes its path | `fcecabe419ce5aa080155f0e29e34eee79596d05f3838a6180dad2ce9795bbf2` |
| Ops command, 9083 | `liveuin-ops-command.service`; same virtualenv Python, `deploy.ops_command_gateway:app`; working directory `/opt/liveuin` | `de48662bcc1be71ee822519b67c2f3a7235264af4028e75628353e639cdb4b44` |
| Public production Identity, 9098 | `liveuin-identity-public-prod.service`; `prod_app:app`; `/opt/liveuin-identity-public/current` resolves to `/opt/liveuin-identity-public/releases/20261016-1e9dca6` | `6311c28a8b20d2a30423a9e299d97f114670f6a106d6aa9f1888617a9a157f11` |
| Sierra marketing | 9095 mounts `/opt/liveuin/deploy/core_marketing_publication_runtime.py` via `app/main.py:598–599`; apex/www/Host nginx marketing locations route to9095 | `0383e287e3e925b1ce8d2366ed348ef29b2ccc8cab6224b1834e9d49803e6026` |

All four services were active/running. This is an **on-disk file-version baseline associated with the observed executing entrypoints**, not a claim that every loaded Python object has the same bytes as disk or that a future restart is safe. The exact protected entry copy is retained privately in the audit working directory as `ops-main.py`; it is not included in this evidence bundle. It imports the safe case router at line401 and mounts it at448, replacing specified legacy case routes at435–447. This supersedes the initial report's statement that the Ops assembly could not be read. No whole-directory export or replacement is proposed.

No `.git` exists at the three inspected production roots. The Identity directory suffix `1e9dca6` is a release label; it is not independently verified Git provenance. `prod_app.py:25` reads `LIVEUIN_DEPLOYED_COMMIT` from the environment; its value was not inspected. Exact file hashes supply a valid bounded version baseline even where a commit is unavailable.

Authenticated GitHub evidence from the same audit remains separate: Core main `0edb58d9f8ab111bc71bb99944aea16a87e1d2d9` is README-only, with source in other branches; resident main `16bafa745c9b6821796a7ed45e742699669f838e`; visual playground main `987579d5b680fc779162799d42b93a16bfba5e0a`. These SHAs are not represented as the deployed server commit. Selected Core branch SHAs and metadata are in `github-source-evidence.json` and the original source report.

## Stores: ownership established; effective binding still a pre-change gate

The canonical product stores remain existing LiveUIN Core/Trust/Ops, not IGEMA WordPress, the public showroom or a new store. Exact deployed source uses SQLite for Core case, inventory, demand and Identity; public search/replay also support PostgreSQL and the earlier production traces show their current PostgreSQL authentication failure. No store helper was imported or run because that could create/migrate schema.

Selected non-secret configuration fields were read and saved with filename and line in `store-bindings-and-identity.json`. They establish **configured paths, not the running process's final effective store**:

- `/etc/liveuin/liveuin-pass-core.env:1–3` names `/var/lib/liveuin/core-case-data`, `core-identity-data`, and `core-inventory-data`. Both the public and Ops service declarations include this file.
- Ops also includes `/etc/liveuin/l0-internal-operating-spine.env`; lines2–4 name corresponding `/srv/liveuin/...` directories. Line31 explicitly names `/srv/liveuin/core-inventory-data/liveuin-core-inventory.sqlite3`. `/etc/liveuin/finance-ledger.env:4` also names `/srv/liveuin/core-case-data`.
- Demand has `/srv/liveuin/core-demand-data` in those environment files, while Ops drop-in73 line4 names `/var/lib/liveuin-ops-backend/core-demand-data`.

A metadata-only realpath/stat check found these pairs are distinct existing directories, not directory symlink aliases (`store-path-metadata.json`). This is **not evidence of duplicated or inconsistent customer records**: database files and contents were not inspected, nor was effective process configuration. Do not migrate, merge or delete anything on the strength of these path differences. Before a case/inventory/auth repair, establish the effective relevant path and its backup/restore route with safe selected-field access.

## Exact access limits and next mutation gate

The ordinary read failed for `/opt/liveuin/ops_backend/app/main.py`, but the specific passwordless rsync sender could read that source into local evidence; its fingerprint is now complete. Remaining ordinary-read limits in this bounded manifest are:

- `/opt/liveuin/ops_backend/db.py`;
- `/etc/systemd/system/liveuin-identity-public-prod.service.d/zzzz-production-provider-consolidation.conf`;
- `/etc/systemd/system/ops-backend@liveuin.service.d/90-listing-media-engine-rc3-dark-runtime.conf`.

Selected-config read limits and intentional credential/provider exclusions are listed individually in `store-bindings-and-identity.json`. Public-home, Ops main, Host workspace, media, Ops command and Identity environment files were not all readable; secret files were deliberately excluded. There was no process-environment dump. These limits do **not** make the known code hashes invalid, and do **not** prove that relevant privileged access is unavailable: general passwordless sudo is unavailable, while named passwordless commands exist. Permission to restart/reload/deploy and perform backup/restore has not been exercised in this audit.

Before R01 mutation, the engineer must pin the exact affected file hashes, recheck drift, retain a rollback copy and prove the required read/deploy/restart or reload permissions. Protect private routes before shared database credential recovery. Before a store-affecting row, resolve that row's effective store and recovery evidence. Stop that row if either gate fails. This keeps the ordered frozen issue scope; it is not a new owner approval item, new platform build or P6 claim.

Ecosystem boundary checked: LiveUIN public UI, private app and canonical Core/Trust/Ops only. No sibling theme, connector, channel bridge, imported tenancy or IGEMA transaction was inspected or changed in this closeout.
