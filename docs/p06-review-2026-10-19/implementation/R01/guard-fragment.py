# R01: protect only the 21 frozen private operations on the public gateway.
# This is a build-time recovery variant, never an environment/public switch.
R01_CLOSED_FALLBACK = False
R01_WORKSPACE_ID = "liveuin_first_party"
R01_WHOAMI_URL = "http://127.0.0.1:9095/api/ops/auth/whoami"
R01_WHOAMI_TIMEOUT = 2.5
R01_PLATFORM_ROLES = frozenset({"ops_manager", "super_admin"})
R01_SIGNED_HEADERS = (
    "X-LiveUIN-Workspace-Id", "X-LiveUIN-Actor-Id", "X-LiveUIN-Role",
    "X-LiveUIN-Scopes", "X-LiveUIN-Session-Id", "X-LiveUIN-Session-Issued-At",
    "X-LiveUIN-Auth-Method", "X-LiveUIN-Session-Signature",
)
R01_COOKIE_NAMES = (
    "LIVEUIN_WORKSPACE_ID", "LIVEUIN_ACTOR_ID", "LIVEUIN_ROLE", "LIVEUIN_SCOPES",
    "LIVEUIN_SESSION_ID", "LIVEUIN_SESSION_ISSUED_AT", "LIVEUIN_AUTH_METHOD",
    "LIVEUIN_SESSION_SIGNATURE",
)
R01_WRITE_ORIGINS = frozenset({
    "https://ops.liveuin.com", "https://api.liveuin.com",
    "https://liveuin.com", "https://www.liveuin.com",
})
R01_PRIVATE_OPERATIONS = {
    **{("GET", "/api/core/admin/control-center" + suffix): "admin"
       for suffix in ("", "/users", "/roles", "/audit", "/retention", "/settings", "/developers")},
    **{("GET", "/api/core/developers/portal" + suffix): "developer"
       for suffix in ("", "/docs", "/webhooks", "/sandbox", "/limits")},
    ("GET", "/api/core/public-cms/blog/posts"): "cms",
    **{("POST", "/api/core/public-cms/" + resource + "/" + action): "cms"
       for resource in ("blog/posts", "pages") for action in ("draft", "publish", "restore")},
    ("GET", "/api/core/ops/liveuintest-rollout-status"): "rollout",
}


def r01_private_family(method: str, path: str) -> str:
    path = path.rstrip("/")
    family = R01_PRIVATE_OPERATIONS.get((method, path), "")
    if family:
        return family
    prefix = "/api/core/public-cms/blog/posts/"
    if method == "GET" and path.startswith(prefix) and "/" not in path[len(prefix):]:
        return "cms"
    return ""


def _r01_error(status: int, detail: str):
    raise HTTPException(status_code=status, detail=detail)


def _r01_forward_credentials(request: Request) -> tuple[Dict[str, str], bool]:
    """Forward one canonical credential form, never unsigned identity selectors.

    whoami's legacy resolver uses require_identity=False. A bearer plus an
    unsigned workspace header must not reach it. Complete signed bundles are
    cryptographically verified there; bearer-only derives its claims from the
    existing credential store. No new credentials or grants are created here.
    """
    forwarded = {"X-LiveUIN-Require-Signed-Session": "1"}
    for name in (*R01_SIGNED_HEADERS, "Authorization", "Cookie"):
        if len(request.headers.getlist(name)) > 1:
            _r01_error(401, "sign_in_required")
    values = [request.headers.get(name, "") for name in R01_SIGNED_HEADERS]
    if any(name in request.headers for name in R01_SIGNED_HEADERS):
        if not all(name in request.headers and (request.headers[name] or name == "X-LiveUIN-Scopes") for name in R01_SIGNED_HEADERS):
            _r01_error(401, "sign_in_required")
        forwarded.update(zip(R01_SIGNED_HEADERS, values))
        return forwarded, False
    authorization = request.headers.get("Authorization", "")
    if authorization:
        if not authorization.lower().startswith("bearer "):
            _r01_error(401, "sign_in_required")
        token = authorization.split(" ", 1)[1]
        if not token.startswith(("sess_", "lus_")) or any(c.isspace() for c in token):
            _r01_error(401, "sign_in_required")
        forwarded["Authorization"] = authorization
        return forwarded, False
    # Cookie-only: omit legacy cookies and reject duplicate canonical cookies.
    raw_cookie = request.headers.get("cookie", "")
    cookie_names = [part.split("=", 1)[0].strip() for part in raw_cookie.split(";") if "=" in part]
    if any(cookie_names.count(name) > 1 for name in R01_COOKIE_NAMES):
        _r01_error(401, "sign_in_required")
    try:
        jar = SimpleCookie()
        jar.load(raw_cookie)
        if not all(name in jar and (jar[name].value or name == "LIVEUIN_SCOPES") for name in R01_COOKIE_NAMES):
            _r01_error(401, "sign_in_required")
        forwarded["Cookie"] = "; ".join(jar[name].OutputString() for name in R01_COOKIE_NAMES)
    except (CookieError, ValueError):
        _r01_error(401, "sign_in_required")
    return forwarded, True


class _R01NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _r01_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _r01_load_authority(headers: Dict[str, str]) -> Dict[str, Any]:
    # Fixed loopback authority; never follow a redirect or a process proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _R01NoRedirect())
    req = urllib.request.Request(R01_WHOAMI_URL, headers=headers, method="GET")
    try:
        with opener.open(req, timeout=R01_WHOAMI_TIMEOUT) as response:
            if response.status != 200:
                _r01_error(503, "sign_in_service_unavailable")
            if response.headers.get_content_type() != "application/json":
                _r01_error(503, "sign_in_service_unavailable")
            raw = response.read(65537)
            if len(raw) > 65536:
                _r01_error(503, "sign_in_service_unavailable")
            data = json.loads(raw, object_pairs_hook=_r01_json_object)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            _r01_error(401, "sign_in_required")
        _r01_error(503, "sign_in_service_unavailable")
    except (OSError, ValueError, TypeError):
        _r01_error(503, "sign_in_service_unavailable")
    if not isinstance(data, dict):
        _r01_error(503, "sign_in_service_unavailable")
    return data


def _r01_authorize(request: Request, family: str) -> Dict[str, Any]:
    if R01_CLOSED_FALLBACK:
        _r01_error(503, "private_operations_temporarily_closed")
    headers, cookie_auth = _r01_forward_credentials(request)
    if request.method == "POST":
        origin_values = request.headers.getlist("origin")
        origin = request.headers.get("origin", "")
        if len(origin_values) > 1 or (origin and origin not in R01_WRITE_ORIGINS) or (cookie_auth and not origin):
            _r01_error(403, "request_origin_denied")
        if request.headers.get("sec-fetch-site", "") == "cross-site":
            _r01_error(403, "request_origin_denied")
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            _r01_error(415, "json_required")
    data = _r01_load_authority(headers)
    if data.get("auth") is not True or data.get("canonical_session_verified") is not True:
        _r01_error(401, "sign_in_required")
    claims = data.get("claims")
    if not isinstance(claims, dict) or claims.get("credential_kind") != "liveuin_session":
        _r01_error(401, "sign_in_required")
    actor_id, role, workspace = (claims.get(key) for key in ("actor_id", "role", "workspace_id"))
    scopes = claims.get("scopes")
    if (not isinstance(actor_id, str) or not actor_id.strip()
            or not isinstance(role, str) or not isinstance(workspace, str)
            or not isinstance(scopes, list)
            or not all(isinstance(scope, str) and scope and len(scope) <= 120 for scope in scopes)):
        _r01_error(401, "sign_in_required")
    if workspace != R01_WORKSPACE_ID:
        _r01_error(403, "workspace_access_denied")
    # Existing privileged role policy, intersected with canonical staff roles.
    # Aggregated developer/rollout data is never a tenant-staff entitlement.
    allowed = role in R01_PLATFORM_ROLES
    if not allowed:
        _r01_error(403, "operation_access_denied")
    return {"workspace_id": workspace, "actor_id": actor_id, "role": role, "scopes": list(scopes), "site_slug": "www"}


def _r01_check_selectors(values: Dict[str, Any], workspace: str) -> None:
    # The public API may serve several sites, but these private operations are
    # confined to LiveUIN www. No Host/Forwarded-Host header grants a site.
    for key in ("site", "site_slug"):
        if key in values and (not isinstance(values[key], str) or values[key].strip().lower() != "www"):
            _r01_error(403, "site_access_denied")
    if "host" in values:
        host = values["host"]
        if not isinstance(host, str) or host.strip().lower() not in {"liveuin.com", "www.liveuin.com", "liveuin.com:443", "www.liveuin.com:443"}:
            _r01_error(403, "site_access_denied")
    for key in ("workspace", "workspace_id"):
        if key in values and values[key] != workspace:
            _r01_error(403, "workspace_access_denied")
    # These handlers have no caller-defined access-context contract.
    if any(key in values for key in ("access", "access_context", "actor")):
        _r01_error(403, "operation_access_denied")


def r01_private_context(request: Request) -> Dict[str, Any]:
    context = getattr(request.state, "r01_private_context", None)
    if not isinstance(context, dict) or context.get("workspace_id") != R01_WORKSPACE_ID:
        _r01_error(401, "sign_in_required")
    return context


def r01_private_site(request: Request, payload: Dict[str, Any] | None = None) -> str:
    context = r01_private_context(request)
    if payload is not None:
        _r01_check_selectors(payload, context["workspace_id"])
        for key in ("post", "page"):
            if isinstance(payload.get(key), dict):
                _r01_check_selectors(payload[key], context["workspace_id"])
    return context["site_slug"]


def install_r01_private_guard(app) -> None:
    @app.middleware("http")
    async def r01_private_guard(request: Request, call_next):
        family = r01_private_family(request.method, request.url.path)
        if not family:
            return await call_next(request)
        try:
            context = await run_in_threadpool(_r01_authorize, request, family)
            selectors = {}
            for key in ("site", "site_slug", "host", "workspace", "workspace_id", "access", "access_context", "actor"):
                values = request.query_params.getlist(key)
                if len(values) > 1:
                    _r01_error(400, "ambiguous_request_scope")
                if values:
                    selectors[key] = values[0]
            _r01_check_selectors(selectors, context["workspace_id"])
            if request.method == "POST":
                # Reject duplicate JSON selectors before FastAPI or CMS reads.
                try:
                    payload = json.loads(await request.body(), object_pairs_hook=_r01_json_object)
                except (ValueError, TypeError):
                    _r01_error(400, "invalid_json")
                if not isinstance(payload, dict):
                    _r01_error(400, "object_required")
                _r01_check_selectors(payload, context["workspace_id"])
                for key in ("post", "page"):
                    if isinstance(payload.get(key), dict):
                        _r01_check_selectors(payload[key], context["workspace_id"])
            request.state.r01_private_context = context
            response = await call_next(request)
        except HTTPException as exc:
            response = JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        except Exception:
            # A protected business-service failure must not leak its traceback,
            # DB address, credentials or private response into a public cache.
            response = JSONResponse({"detail": "private_operation_unavailable"}, status_code=503)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        vary = [value.strip() for value in response.headers.get("Vary", "").split(",") if value.strip()]
        for name in ("Cookie", "Authorization"):
            if name.lower() not in {value.lower() for value in vary}:
                vary.append(name)
        response.headers["Vary"] = ", ".join(vary)
        return response


