from __future__ import annotations

import importlib.util
import json
import urllib.error
import urllib.request
from http.cookies import CookieError, SimpleCookie
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

try:
    from . import admin_control_service as admin_svc
    from . import public_china_service as public_china_svc
    from . import developer_portal_service as developer_svc
    from . import public_help_service as public_help_svc
    from . import public_trust_service as public_trust_svc
    from . import public_home_service as svc
    from . import public_status_service as status_svc
except ImportError:  # pragma: no cover - supports direct app-folder deployment.
    import admin_control_service as admin_svc
    import public_china_service as public_china_svc
    import developer_portal_service as developer_svc
    import public_help_service as public_help_svc
    import public_trust_service as public_trust_svc
    import public_home_service as svc
    import public_status_service as status_svc


router = APIRouter()
ROOT = Path(__file__).resolve().parent.parent
PREVIEW_MODULE_PATH = ROOT / "public-home-preview.py"


# R01: protect only the 21 frozen private operations on the public gateway.
# This is a build-time recovery variant, never an environment/public switch.
R01_CLOSED_FALLBACK = True
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


@lru_cache(maxsize=1)
def _load_preview_module():
    default_data_dir = Path(os.getenv("LIVEUIN_PUBLIC_API_DATA_DIR", str(ROOT / "outputs" / "home-api-data")))
    os.environ.setdefault(
        "LIVEUIN_PUBLIC_CMS_SQLITE_PATH",
        str(default_data_dir / "public-theme-cms.sqlite3"),
    )
    spec = importlib.util.spec_from_file_location("liveuin_public_home_preview_gateway", PREVIEW_MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"preview_module_unavailable:{PREVIEW_MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _request_meta(request: Request) -> Dict[str, str]:
    return {
        "ip": request.client.host if request.client else "",
        "user_agent": str(request.headers.get("user-agent") or "")[:500],
        "referer": str(request.headers.get("referer") or "")[:500],
        "path": str(request.url.path),
    }


def _raise_if_error(response: Dict[str, Any]) -> Dict[str, Any]:
    if response.get("ok") is not False:
        return response

    raise HTTPException(
        status_code=int(response.get("status_code") or 400),
        detail=str(response.get("detail") or "public_home_error"),
    )


def _site_slug(request: Request, site: str = "", host: str = "") -> str:
    preview = _load_preview_module()
    if site:
        return preview.public_theme_normalize_site_slug(site)
    return preview.public_theme_site_slug_from_host(host or request.headers.get("host"))


def _site_slug_from_payload(preview: Any, payload: Dict[str, Any], request: Request) -> str:
    raw_site = str(payload.get("site") or payload.get("site_slug") or "").strip()
    if raw_site:
        return preview.public_theme_normalize_site_slug(raw_site)
    return preview.public_theme_site_slug_from_host(request.headers.get("host"))



# P2_PUBLIC_CMS_PROJECTION_V1
_P2_PUBLIC_DROP = object()
_P2_PRIVATE_KEY_PARTS = (
    "workspace",
    "case_id",
    "operator",
    "private",
    "internal",
    "payment",
)


def _p2_public_clean(value):
    if isinstance(value, dict):
        result = {}

        for key, child in value.items():
            key_text = str(key).lower()

            if any(part in key_text for part in _P2_PRIVATE_KEY_PARTS):
                continue

            cleaned = _p2_public_clean(child)

            if cleaned is not _P2_PUBLIC_DROP:
                result[key] = cleaned

        return result

    if isinstance(value, list):
        result = []

        for child in value:
            cleaned = _p2_public_clean(child)

            if cleaned is not _P2_PUBLIC_DROP:
                result.append(cleaned)

        return result

    if isinstance(value, str):
        lowered = value.lower()

        if (
            "laijuzhu" in lowered
            or "/api/core/" in lowered
            or "/api/pass/" in lowered
        ):
            return _P2_PUBLIC_DROP

    return value


def _p2_safe_site_slug(site):
    value = str(site or "").strip().lower()
    return value or "www"


def _p2_public_site_value(value, site_slug):
    if not isinstance(value, dict):
        return {"slug": site_slug}

    result = {"slug": str(value.get("slug") or site_slug)}

    for key in ("host", "name"):
        if value.get(key):
            result[key] = str(value[key])

    return _p2_public_clean(result)


def _p2_public_site_theme_response(record, site_slug):
    theme = record.get("theme")
    return {
        "ok": True,
        "source": str(record.get("source") or "sqlite"),
        "theme": _p2_public_clean(theme if isinstance(theme, dict) else {}),
        "site": _p2_public_site_value(record.get("site"), site_slug),
    }


def _p2_public_page_response(response, site_slug):
    page = response.get("page")
    history = response.get("history")

    return {
        "ok": True,
        "source": str(response.get("source") or "sqlite"),
        "site": _p2_public_site_value(response.get("site"), site_slug),
        "status": str(response.get("status") or "published"),
        "page": _p2_public_clean(page),
        "history": _p2_public_clean(history if isinstance(history, list) else []),
    }


def _p2_public_blog_list_response(response, site_slug):
    if response.get("ok") is False:
        return _p2_public_error_response(response)

    posts = response.get("posts")
    categories = response.get("categories")

    return {
        "ok": True,
        "posts": _p2_public_clean(posts if isinstance(posts, list) else []),
        "categories": _p2_public_clean(
            categories if isinstance(categories, list) else []
        ),
        "count": int(response.get("count") or 0),
        "site": _p2_public_site_value(response.get("site"), site_slug),
        "status": str(response.get("status") or "published"),
    }


def _p2_public_blog_detail_response(response):
    if response.get("ok") is False:
        return _p2_public_error_response(response)

    return {
        "ok": True,
        "post": _p2_public_clean(response.get("post")),
    }


def _p2_public_error_response(response):
    status_code = int(response.get("status_code") or 502)
    detail = str(response.get("detail") or "")

    if status_code == 404 or detail == "blog_post_not_found":
        return JSONResponse(
            {"ok": False, "error": "not_found"},
            status_code=404,
        )

    return JSONResponse(
        {"ok": False, "error": "public_cms_unavailable"},
        status_code=502,
    )


@router.get("/api/public/site-theme")
def public_site_theme(
    request: Request,
    site: str = Query("", max_length=80),
    host: str = Query("", max_length=255),
) -> Dict[str, Any]:
    site_slug = _p2_safe_site_slug(site)

    try:
        preview = _load_preview_module()
        site_slug = _site_slug(request, site=site, host=host)
        record = preview.load_public_theme_cms_record(site_slug, "published")

        if isinstance(record, dict) and record.get("ok"):
            return _p2_public_site_theme_response(record, site_slug)

        fallback_theme = preview.fallback_public_theme_payload()
    except Exception:
        fallback_theme = {}

    return {
        "ok": True,
        "source": "fallback",
        "theme": _p2_public_clean(
            fallback_theme if isinstance(fallback_theme, dict) else {}
        ),
        "site": {"slug": site_slug},
    }

@router.get("/api/public/page")
def public_page(
    request: Request,
    path: str = Query("/", max_length=255),
    site: str = Query("", max_length=80),
    host: str = Query("", max_length=255),
) -> Dict[str, Any]:
    site_slug = _p2_safe_site_slug(site)

    try:
        preview = _load_preview_module()
        site_slug = _site_slug(request, site=site, host=host)
        response = preview.load_public_cms_page(
            site_slug=site_slug,
            route=path,
            status="published",
        )

        if isinstance(response, dict) and response.get("ok") is not False:
            return _p2_public_page_response(response, site_slug)
    except Exception:
        pass

    return {
        "ok": True,
        "source": "fallback",
        "site": {"slug": site_slug},
        "status": "published",
        "page": None,
        "history": [],
    }

@router.get("/api/public/blog")
def public_blog(
    request: Request,
    site: str = Query("", max_length=80),
    host: str = Query("", max_length=255),
    category: str = Query("", max_length=80),
    q: str = Query("", max_length=120),
    limit: int = Query(24, ge=1, le=200),
) -> Dict[str, Any]:
    site_slug = _p2_safe_site_slug(site)

    try:
        preview = _load_preview_module()
        site_slug = _site_slug(request, site=site, host=host)
        response = preview.load_public_blog_posts(
            site_slug=site_slug,
            status="published",
            category=category,
            query=q,
            limit=limit,
        )
    except Exception:
        response = {
            "ok": False,
            "status_code": 502,
            "detail": "public_blog_unavailable",
        }

    return _p2_public_blog_list_response(response, site_slug)

@router.get("/api/public/blog/{slug}")
def public_blog_post(
    request: Request,
    slug: str,
    site: str = Query("", max_length=80),
    host: str = Query("", max_length=255),
) -> Dict[str, Any]:
    site_slug = _p2_safe_site_slug(site)

    try:
        preview = _load_preview_module()
        site_slug = _site_slug(request, site=site, host=host)
        response = preview.get_public_blog_post(
            site_slug=site_slug,
            slug=slug,
            status="published",
        )
    except Exception:
        response = {
            "ok": False,
            "status_code": 502,
            "detail": "public_blog_unavailable",
        }

    return _p2_public_blog_detail_response(response)

@router.get("/api/core/public-cms/blog/posts")
def core_public_cms_blog_posts(
    request: Request,
    site: str = Query("", max_length=80),
    host: str = Query("", max_length=255),
    status: str = Query("draft", max_length=20),
    category: str = Query("", max_length=80),
    q: str = Query("", max_length=120),
    limit: int = Query(50, ge=1, le=200),
) -> Dict[str, Any]:
    site_slug = r01_private_site(request)
    preview = _load_preview_module()
    return _raise_if_error(
        preview.load_public_blog_posts(
            site_slug=site_slug,
            status=status,
            category=category,
            query=q,
            limit=limit,
        )
    )


@router.get("/api/core/public-cms/blog/posts/{slug}")
def core_public_cms_blog_post(
    request: Request,
    slug: str,
    site: str = Query("", max_length=80),
    host: str = Query("", max_length=255),
    status: str = Query("draft", max_length=20),
) -> Dict[str, Any]:
    site_slug = r01_private_site(request)
    preview = _load_preview_module()
    return _raise_if_error(preview.get_public_blog_post(site_slug=site_slug, slug=slug, status=status))


# P2_PUBLIC_CMS_PRIVATE_404_V1
@router.get("/api/core/public-cms/pages")
def core_public_cms_pages(
    request: Request,
    site: str = Query("", max_length=80),
    host: str = Query("", max_length=255),
    status: str = Query("draft", max_length=20),
    route: str = Query("", max_length=255),
) -> Dict[str, Any]:
    return JSONResponse(
        {"ok": False, "error": "not_found"},
        status_code=404,
    )


@router.post("/api/core/public-cms/blog/posts/draft")
def core_public_cms_blog_post_draft(
    request: Request,
    payload: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    site_slug = r01_private_site(request, payload)
    preview = _load_preview_module()
    post = payload.get("post") if isinstance(payload.get("post"), dict) else {}
    if not post:
        raise HTTPException(status_code=400, detail="blog_post_required")
    return _raise_if_error(preview.upsert_public_blog_post(site_slug, post, publish=False, meta=_request_meta(request)))


@router.post("/api/core/public-cms/blog/posts/publish")
def core_public_cms_blog_post_publish(
    request: Request,
    payload: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    site_slug = r01_private_site(request, payload)
    preview = _load_preview_module()
    post = payload.get("post") if isinstance(payload.get("post"), dict) else {}
    if not post:
        raise HTTPException(status_code=400, detail="blog_post_required")
    return _raise_if_error(preview.upsert_public_blog_post(site_slug, post, publish=True, meta=_request_meta(request)))


@router.post("/api/core/public-cms/blog/posts/restore")
def core_public_cms_blog_post_restore(
    request: Request,
    payload: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    site_slug = r01_private_site(request, payload)
    preview = _load_preview_module()
    post_slug = preview.public_theme_normalize_site_slug(payload.get("slug") or payload.get("post_slug") or "")
    if not post_slug:
        raise HTTPException(status_code=400, detail="blog_post_slug_required")
    try:
        restore_index = int(payload.get("index", 0))
    except Exception:
        restore_index = 0
    try:
        revision_id = int(payload.get("revision_id", 0) or 0)
    except Exception:
        revision_id = 0
    return _raise_if_error(
        preview.restore_public_blog_post_revision(
            site_slug=site_slug,
            post_slug=post_slug,
            revision_id=revision_id or None,
            index=restore_index,
            meta=_request_meta(request),
        )
    )


@router.post("/api/core/public-cms/pages/draft")
def core_public_cms_page_draft(
    request: Request,
    payload: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    site_slug = r01_private_site(request, payload)
    preview = _load_preview_module()
    page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
    if not page:
        raise HTTPException(status_code=400, detail="public_page_required")
    return _raise_if_error(preview.upsert_public_cms_page(site_slug, page, publish=False, meta=_request_meta(request)))


@router.post("/api/core/public-cms/pages/publish")
def core_public_cms_page_publish(
    request: Request,
    payload: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    site_slug = r01_private_site(request, payload)
    preview = _load_preview_module()
    page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
    if not page:
        raise HTTPException(status_code=400, detail="public_page_required")
    return _raise_if_error(preview.upsert_public_cms_page(site_slug, page, publish=True, meta=_request_meta(request)))


@router.post("/api/core/public-cms/pages/restore")
def core_public_cms_page_restore(
    request: Request,
    payload: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    site_slug = r01_private_site(request, payload)
    preview = _load_preview_module()
    route = preview.normalize_path_for_public_router(str(payload.get("route") or payload.get("path") or "/"))
    try:
        restore_index = int(payload.get("index", 0))
    except Exception:
        restore_index = 0
    try:
        revision_id = int(payload.get("revision_id", 0) or 0)
    except Exception:
        revision_id = 0
    return _raise_if_error(
        preview.restore_public_cms_page_revision(
            site_slug=site_slug,
            route=route,
            revision_id=revision_id or None,
            index=restore_index,
            meta=_request_meta(request),
        )
    )


@router.get("/api/public/home/bootstrap")
def public_home_bootstrap(
    market: str = Query("singapore", max_length=40),
    locale: str = Query("en-SG", max_length=20),
) -> Dict[str, Any]:
    return svc.public_home_bootstrap(market=market, locale=locale)


@router.get("/api/public/listings")
def public_listings(
    q: str = Query("", max_length=120),
    market: str = Query("singapore", max_length=40),
    stay_type: str = Query("", max_length=80),
    limit: int = Query(12, ge=1, le=100),
) -> Dict[str, Any]:
    return svc.public_listings(q=q, market=market, stay_type=stay_type, limit=limit)


@router.get("/api/public/deals")
def public_deals(
    q: str = Query("", max_length=120),
    lat: str = Query("", max_length=40),
    lng: str = Query("", max_length=40),
    district: str = Query("", max_length=80),
    stay_context: str = Query("", max_length=80),
    school_context: str = Query("", max_length=80),
    category: str = Query("", max_length=80),
    limit: int = Query(12, ge=1, le=100),
) -> Dict[str, Any]:
    return svc.public_deals(
        q=q,
        lat=lat,
        lng=lng,
        district=district,
        stay_context=stay_context,
        school_context=school_context,
        category=category,
        limit=limit,
    )


@router.get("/api/public/deals/report")
def public_deal_report(
    action: str = Query("", max_length=40),
    route: str = Query("", max_length=120),
    source_route: str = Query("", max_length=120),
    partner_id: str = Query("", max_length=120),
    anchor_used: str = Query("", max_length=80),
    status: str = Query("", max_length=80),
    freshness_state: str = Query("", max_length=80),
    evidence_state: str = Query("", max_length=80),
    include_private: str = Query("", max_length=8),
    since: str = Query("", max_length=40),
    until: str = Query("", max_length=40),
    limit: int = Query(200, ge=1, le=500),
) -> Dict[str, Any]:
    return _raise_if_error(
        svc.public_deal_action_report(
            {
                "action": action,
                "route": route or source_route,
                "partner_id": partner_id,
                "anchor_used": anchor_used,
                "status": status,
                "freshness_state": freshness_state,
                "evidence_state": evidence_state,
                "include_private": include_private,
                "since": since,
                "until": until,
                "limit": limit,
            }
        )
    )


@router.get("/api/public/areas")
def public_areas(
    q: str = Query("", max_length=120),
    region: str = Query("", max_length=80),
    limit: int = Query(12, ge=1, le=100),
) -> Dict[str, Any]:
    return svc.public_areas(q=q, region=region, limit=limit)


@router.get("/api/public/tools")
def public_tools(
    q: str = Query("", max_length=120),
    category: str = Query("", max_length=80),
    limit: int = Query(12, ge=1, le=100),
) -> Dict[str, Any]:
    return svc.public_tools(q=q, category=category, limit=limit)


@router.get("/api/public/growth/status")
def public_growth_status() -> Dict[str, Any]:
    return svc.public_growth_status()


@router.get("/api/public/status")
def public_status_summary(
    workspace_id: str = Query(status_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return status_svc.public_status_summary(workspace_id=workspace_id)


@router.get("/api/public/status/components")
def public_status_components(
    workspace_id: str = Query(status_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return status_svc.public_status_components(workspace_id=workspace_id)


@router.get("/api/public/status/incidents")
def public_status_incidents(
    workspace_id: str = Query(status_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return status_svc.public_status_incidents(workspace_id=workspace_id)


@router.get("/api/public/status/maintenance")
def public_status_maintenance(
    workspace_id: str = Query(status_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return status_svc.public_status_maintenance(workspace_id=workspace_id)


@router.get("/api/public/status/postmortems")
def public_status_postmortems(
    workspace_id: str = Query(status_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return status_svc.public_status_postmortems(workspace_id=workspace_id)


@router.get("/api/public/trust")
def public_trust_summary(
    workspace_id: str = Query(public_trust_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return public_trust_svc.public_trust_summary(workspace_id=workspace_id)


@router.get("/api/public/trust/safety")
def public_trust_safety(
    workspace_id: str = Query(public_trust_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return public_trust_svc.public_trust_safety(workspace_id=workspace_id)


@router.get("/api/public/trust/verification")
def public_trust_verification(
    workspace_id: str = Query(public_trust_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return public_trust_svc.public_trust_verification(workspace_id=workspace_id)


@router.get("/api/public/trust/refunds")
def public_trust_refunds(
    workspace_id: str = Query(public_trust_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return public_trust_svc.public_trust_refunds(workspace_id=workspace_id)


@router.get("/api/public/trust/policies")
def public_trust_policies(
    workspace_id: str = Query(public_trust_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return public_trust_svc.public_trust_policies(workspace_id=workspace_id)


@router.get("/api/public/help")
def public_help_summary(
    workspace_id: str = Query(public_help_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> JSONResponse:
    try:
        payload = public_help_svc.public_help_summary(workspace_id=workspace_id)
    except Exception:  # Public help must degrade to documented JSON, never text/HTML.
        payload = public_help_svc.public_help_fallback()
    return JSONResponse(status_code=200, content=payload)


@router.get("/api/public/help/routing")
def public_help_routing(
    workspace_id: str = Query(public_help_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return public_help_svc.public_help_routing(workspace_id=workspace_id)


@router.get("/api/public/help/billing")
def public_help_billing(
    workspace_id: str = Query(public_help_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return public_help_svc.public_help_billing(workspace_id=workspace_id)


@router.get("/api/public/help/emergency")
def public_help_emergency(
    workspace_id: str = Query(public_help_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return public_help_svc.public_help_emergency(workspace_id=workspace_id)


@router.get("/api/public/cn")
def public_china_summary(
    workspace_id: str = Query(public_china_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return public_china_svc.public_china_summary(workspace_id=workspace_id)


@router.get("/api/public/cn/share-cards")
def public_china_share_cards(
    workspace_id: str = Query(public_china_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return public_china_svc.public_china_share_cards(workspace_id=workspace_id)


@router.get("/api/public/cn/agents")
def public_china_agents(
    workspace_id: str = Query(public_china_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return public_china_svc.public_china_agents(workspace_id=workspace_id)


@router.get("/api/public/cn/auth")
def public_china_auth(
    workspace_id: str = Query(public_china_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return public_china_svc.public_china_auth(workspace_id=workspace_id)


@router.get("/api/core/admin/control-center")
def admin_control_summary(
    request: Request,
    workspace_id: str = Query("", max_length=96),
) -> Dict[str, Any]:
    return admin_svc.admin_control_summary(workspace_id=r01_private_context(request)["workspace_id"])


@router.get("/api/core/admin/control-center/users")
def admin_control_users(
    request: Request,
    workspace_id: str = Query("", max_length=96),
) -> Dict[str, Any]:
    return admin_svc.admin_control_users(workspace_id=r01_private_context(request)["workspace_id"])


@router.get("/api/core/admin/control-center/roles")
def admin_control_roles(
    request: Request,
    workspace_id: str = Query("", max_length=96),
) -> Dict[str, Any]:
    return admin_svc.admin_control_roles(workspace_id=r01_private_context(request)["workspace_id"])


@router.get("/api/core/admin/control-center/audit")
def admin_control_audit(
    request: Request,
    workspace_id: str = Query("", max_length=96),
    limit: int = Query(20, ge=1, le=100),
) -> Dict[str, Any]:
    return admin_svc.admin_control_audit(workspace_id=r01_private_context(request)["workspace_id"], limit=limit)


@router.get("/api/core/admin/control-center/retention")
def admin_control_retention(
    request: Request,
    workspace_id: str = Query("", max_length=96),
) -> Dict[str, Any]:
    return admin_svc.admin_control_retention(workspace_id=r01_private_context(request)["workspace_id"])


@router.get("/api/core/admin/control-center/settings")
def admin_control_settings(
    request: Request,
    workspace_id: str = Query("", max_length=96),
) -> Dict[str, Any]:
    return admin_svc.admin_control_settings(workspace_id=r01_private_context(request)["workspace_id"])


@router.get("/api/core/admin/control-center/developers")
def admin_control_developers(
    request: Request,
    workspace_id: str = Query("", max_length=96),
) -> Dict[str, Any]:
    return admin_svc.admin_control_developers(workspace_id=r01_private_context(request)["workspace_id"])


@router.get("/api/core/developers/portal")
def developer_portal_summary(
    request: Request,
    workspace_id: str = Query("", max_length=96),
) -> Dict[str, Any]:
    return developer_svc.developer_portal_summary(workspace_id=r01_private_context(request)["workspace_id"])


@router.get("/api/core/developers/portal/docs")
def developer_portal_docs(
    request: Request,
    workspace_id: str = Query("", max_length=96),
) -> Dict[str, Any]:
    return developer_svc.developer_portal_docs(workspace_id=r01_private_context(request)["workspace_id"])


@router.get("/api/core/developers/portal/webhooks")
def developer_portal_webhooks(
    request: Request,
    workspace_id: str = Query("", max_length=96),
) -> Dict[str, Any]:
    return developer_svc.developer_portal_webhooks(workspace_id=r01_private_context(request)["workspace_id"])


@router.get("/api/core/developers/portal/sandbox")
def developer_portal_sandbox(
    request: Request,
    workspace_id: str = Query("", max_length=96),
) -> Dict[str, Any]:
    return developer_svc.developer_portal_sandbox(workspace_id=r01_private_context(request)["workspace_id"])


@router.get("/api/core/developers/portal/limits")
def developer_portal_limits(
    request: Request,
    workspace_id: str = Query("", max_length=96),
) -> Dict[str, Any]:
    return developer_svc.developer_portal_limits(workspace_id=r01_private_context(request)["workspace_id"])


@router.get("/api/public/partners/{partner_slug}/stays")
def public_partner_stays(
    partner_slug: str,
    limit: int = Query(12, ge=1, le=100),
    display_mode: str = Query("", max_length=80),
    user_requested_alternatives: bool = Query(False),
) -> Dict[str, Any]:
    return _raise_if_error(
        svc.public_partner_stays(
            partner_slug,
            limit=limit,
            display_mode=display_mode,
            user_requested_alternatives=user_requested_alternatives,
        )
    )


@router.post("/api/public/partners/{partner_slug}/match-intake")
def public_partner_match_intake(
    request: Request,
    partner_slug: str,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(svc.public_partner_match_intake(partner_slug, payload, _request_meta(request)))


@router.post("/api/public/search")
def public_search(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(svc.public_search(payload, _request_meta(request)))


@router.post("/api/public/events")
def public_events(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(svc.public_event(payload, _request_meta(request)))


@router.post("/api/public/deals/{deal_id}/claim")
def public_deal_claim(
    request: Request,
    deal_id: str,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(svc.public_deal_claim(deal_id, payload, _request_meta(request)))


@router.post("/api/public/deals/{deal_id}/contact")
def public_deal_contact(
    request: Request,
    deal_id: str,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(svc.public_deal_contact(deal_id, payload, _request_meta(request)))


@router.post("/api/public/deals/{deal_id}/share")
def public_deal_share(
    request: Request,
    deal_id: str,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(svc.public_deal_share(deal_id, payload, _request_meta(request)))


@router.post("/api/public/reservations/quote")
def public_reservation_quote(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(svc.public_reservation_quote(payload, _request_meta(request)))


@router.post("/api/public/igema/consultations")
def public_igema_consultations(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(svc.public_igema_consultation(payload, _request_meta(request)))


@router.post("/api/public/landlords/watchlist")
def public_landlord_watchlist(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(svc.public_future_landlord_watchlist(payload, _request_meta(request)))


@router.post("/api/public/tools/yield-calculator")
def public_yield_calculator(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(svc.public_yield_calculator(payload, _request_meta(request)))


@router.post("/api/public/invite/stakeholders")
def public_stakeholder_invite(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(svc.public_stakeholder_invite(payload, _request_meta(request)))
