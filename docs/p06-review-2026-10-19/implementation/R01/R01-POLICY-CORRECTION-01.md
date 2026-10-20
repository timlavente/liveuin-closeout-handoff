# R01-POLICY-CORRECTION-01

Staged implementation addendum. The frozen register, its 21 operations, two source files and issue order are unchanged. The copied re-audit report and freeze input manifest remain untouched.

The earlier R01 entry report generalized the theme administration policy to the private CMS paths. The exact deployed source does not support that generalization. Read-only AST inspection of `/opt/liveuin/public-home-preview.py` (SHA-256 `e523924bac421433ad34ea6587353b0448bd42aeba950e27029d654ffb063099`) confirms:

- `THEME_ADMIN_API_PREFIXES = ("/api/core/public-theme",)`.
- `public_theme_admin_route_requires_auth` tests only its theme UI paths or those prefixes.
- The frozen `/api/core/public-cms/blog/posts...` and `/api/core/public-cms/pages...` paths do not match that prefix or another CMS grant in `route_group_allowed`.
- Its final rule permits privileged roles only: `admin`, `super_admin`, `ops_manager`.
- The active canonical signed staff authority does not accept `admin` or `connector_admin`; the effective existing intersection is `super_admin` or `ops_manager`.

Therefore the final candidate refuses `ops` CMS access even when a signed actor has `ops.theme`, `ops.theme.write` or `identity.admin`. Those scope names cannot create a grant for a different route family. All 21 operations require an existing verified platform role in `liveuin_first_party`; private CMS additionally targets only `www`. Empty canonical scope lists remain valid for these privileged roles because the existing privileged policy bypasses scope-prefix checks. This adds no account, entitlement or role.

The rollout read is restricted to platform administrators because its output is a platform governance aggregate, as required by the frozen R01 scope clarification. It is not made a test-staff or finance entitlement. Later scoped case/desk routes can satisfy test.staff's own-case requirements without opening these aggregate controls.

The initial candidate's proposed CMS `ops` allowance and associated preliminary hashes are superseded. Final source hashes and the passing test run are in this package's manifest. This correction was made before any production change.
