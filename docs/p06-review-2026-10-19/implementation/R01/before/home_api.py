from __future__ import annotations

import importlib.util
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import JSONResponse

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
    preview = _load_preview_module()
    site_slug = _site_slug(request, site=site, host=host)
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
    preview = _load_preview_module()
    site_slug = _site_slug(request, site=site, host=host)
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
    preview = _load_preview_module()
    site_slug = _site_slug_from_payload(preview, payload, request)
    post = payload.get("post") if isinstance(payload.get("post"), dict) else {}
    if not post:
        raise HTTPException(status_code=400, detail="blog_post_required")
    return _raise_if_error(preview.upsert_public_blog_post(site_slug, post, publish=False, meta=_request_meta(request)))


@router.post("/api/core/public-cms/blog/posts/publish")
def core_public_cms_blog_post_publish(
    request: Request,
    payload: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    preview = _load_preview_module()
    site_slug = _site_slug_from_payload(preview, payload, request)
    post = payload.get("post") if isinstance(payload.get("post"), dict) else {}
    if not post:
        raise HTTPException(status_code=400, detail="blog_post_required")
    return _raise_if_error(preview.upsert_public_blog_post(site_slug, post, publish=True, meta=_request_meta(request)))


@router.post("/api/core/public-cms/blog/posts/restore")
def core_public_cms_blog_post_restore(
    request: Request,
    payload: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    preview = _load_preview_module()
    site_slug = _site_slug_from_payload(preview, payload, request)
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
    preview = _load_preview_module()
    site_slug = _site_slug_from_payload(preview, payload, request)
    page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
    if not page:
        raise HTTPException(status_code=400, detail="public_page_required")
    return _raise_if_error(preview.upsert_public_cms_page(site_slug, page, publish=False, meta=_request_meta(request)))


@router.post("/api/core/public-cms/pages/publish")
def core_public_cms_page_publish(
    request: Request,
    payload: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    preview = _load_preview_module()
    site_slug = _site_slug_from_payload(preview, payload, request)
    page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
    if not page:
        raise HTTPException(status_code=400, detail="public_page_required")
    return _raise_if_error(preview.upsert_public_cms_page(site_slug, page, publish=True, meta=_request_meta(request)))


@router.post("/api/core/public-cms/pages/restore")
def core_public_cms_page_restore(
    request: Request,
    payload: Dict[str, Any] = Body(...),
) -> Dict[str, Any]:
    preview = _load_preview_module()
    site_slug = _site_slug_from_payload(preview, payload, request)
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
    workspace_id: str = Query(admin_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return admin_svc.admin_control_summary(workspace_id=workspace_id)


@router.get("/api/core/admin/control-center/users")
def admin_control_users(
    workspace_id: str = Query(admin_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return admin_svc.admin_control_users(workspace_id=workspace_id)


@router.get("/api/core/admin/control-center/roles")
def admin_control_roles(
    workspace_id: str = Query(admin_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return admin_svc.admin_control_roles(workspace_id=workspace_id)


@router.get("/api/core/admin/control-center/audit")
def admin_control_audit(
    workspace_id: str = Query(admin_svc.DEFAULT_WORKSPACE_ID, max_length=96),
    limit: int = Query(20, ge=1, le=100),
) -> Dict[str, Any]:
    return admin_svc.admin_control_audit(workspace_id=workspace_id, limit=limit)


@router.get("/api/core/admin/control-center/retention")
def admin_control_retention(
    workspace_id: str = Query(admin_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return admin_svc.admin_control_retention(workspace_id=workspace_id)


@router.get("/api/core/admin/control-center/settings")
def admin_control_settings(
    workspace_id: str = Query(admin_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return admin_svc.admin_control_settings(workspace_id=workspace_id)


@router.get("/api/core/admin/control-center/developers")
def admin_control_developers(
    workspace_id: str = Query(admin_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return admin_svc.admin_control_developers(workspace_id=workspace_id)


@router.get("/api/core/developers/portal")
def developer_portal_summary(
    workspace_id: str = Query(developer_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return developer_svc.developer_portal_summary(workspace_id=workspace_id)


@router.get("/api/core/developers/portal/docs")
def developer_portal_docs(
    workspace_id: str = Query(developer_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return developer_svc.developer_portal_docs(workspace_id=workspace_id)


@router.get("/api/core/developers/portal/webhooks")
def developer_portal_webhooks(
    workspace_id: str = Query(developer_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return developer_svc.developer_portal_webhooks(workspace_id=workspace_id)


@router.get("/api/core/developers/portal/sandbox")
def developer_portal_sandbox(
    workspace_id: str = Query(developer_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return developer_svc.developer_portal_sandbox(workspace_id=workspace_id)


@router.get("/api/core/developers/portal/limits")
def developer_portal_limits(
    workspace_id: str = Query(developer_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return developer_svc.developer_portal_limits(workspace_id=workspace_id)


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
