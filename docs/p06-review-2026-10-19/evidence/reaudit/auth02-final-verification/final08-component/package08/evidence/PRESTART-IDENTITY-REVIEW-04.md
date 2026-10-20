# AUTH02 bounded prestart identity review

The local probe is ready for the root-controlled runtime check. Its SHA-256 is `f6318de6719959db2d224ea2485da11e6e46a2968fa5b2fb4cef33dcc7dbc601`. No service was restarted and no product, database, or third-party module was imported during these local tests.

The first server probe stopped before imports because the loaded unit has `PermissionsStartOnly=true`. The corrected probe supports that actual systemd 249 control-process behavior: root UID/GID, the configured `liveuin_ops` user's NSS supplementary groups, and the configured user's generated login environment. The observed configured UID/GID is 998/998; NSS groups are 998 and 1005; the explicit `liveuin_pass` group is already in that list. A differing explicit group is rejected in this branch. The ordinary `PermissionsStartOnly=false` branch retains the configured service UID/GID.

The probe requires the loaded four `ExecStartPreEx` commands to match the reviewed commands with no privilege-prefix flags, DynamicUser false, no alternate root, and systemd major version 249. HOME and SHELL defaults follow systemd's cleaned-user rules for the supported simple paths. Declared unit/file values retain precedence; any competing manager or UnsetEnvironment login names stop the check. Identity, groups, command metadata, source and configured environment are checked again afterwards.

Local evidence: `prestart-probe-identity-tests-04.json` reports 24/24 tests. The guarded child is byte-for-byte unchanged from reviewed03, whose existing 35/35 guard tests remain at `prestart-probe-local-guard-tests.json`. The test script selects only pure helper functions from the AST; it does not import or execute the probe's main function.

The source interpretation is limited to the installed systemd 249 behavior: [service.c](https://raw.githubusercontent.com/systemd/systemd/v249/src/core/service.c), [execute.c](https://raw.githubusercontent.com/systemd/systemd/v249/src/core/execute.c), and [user-util.c](https://raw.githubusercontent.com/systemd/systemd/v249/src/basic/user-util.c). This remains an instrumented check of the current seven-library fast path, not a structural ban on future automatic rebuilds and not evidence that auth or the entire application has passed.

The helper concerns the existing LiveUIN Ops service only. Core remains the canonical identity owner. No sibling-site changes, customer records, imported tenancy actions, payment actions, public-access changes, or new truth store are involved.
