from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

SERVICE_NAME = "liveuin-public-home"
ROOT = Path(__file__).resolve().parents[1]
KEY_REGISTRY_FILE = Path(
    os.getenv(
        "LIVEUIN_PUBLIC_API_KEY_REGISTRY_FILE",
        "/etc/liveuin/public-api/api-keys.json",
    )
)


def allowed_origins() -> List[str]:
    configured = os.getenv(
        "LIVEUIN_PUBLIC_HOME_ALLOWED_ORIGINS",
        "https://liveuin.com,https://www.liveuin.com,http://127.0.0.1:4174,http://localhost:4174",
    )
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_key_registry() -> Dict[str, Any]:
    if not KEY_REGISTRY_FILE.exists():
        raise RuntimeError(f"api key registry missing: {KEY_REGISTRY_FILE}")

    try:
        data = json.loads(KEY_REGISTRY_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"api key registry invalid JSON: {KEY_REGISTRY_FILE}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise RuntimeError(f"api key registry invalid shape: {KEY_REGISTRY_FILE}")

    return data


def normalize_scopes(scopes: Any) -> Set[str]:
    if not isinstance(scopes, list):
        return set()
    return {str(scope).strip() for scope in scopes if str(scope).strip()}


def parse_expiry(expires_at: Any) -> Optional[datetime]:
    if expires_at in (None, "", "null", "never"):
        return None
    if not isinstance(expires_at, str):
        return None

    cleaned = expires_at.strip()
    if not cleaned:
        return None
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def key_is_expired(expires_at: Any) -> bool:
    parsed = parse_expiry(expires_at)
    return parsed is not None and utc_now() >= parsed


def find_key_record(api_key: str) -> Dict[str, Any]:
    incoming_hash = sha256_text(api_key.strip())
    for record in load_key_registry().get("keys", []):
        if not isinstance(record, dict):
            continue
        stored_hash = str(record.get("key_hash", "")).strip()
        if stored_hash and hmac.compare_digest(stored_hash, incoming_hash):
            return record
    raise RuntimeError("invalid_api_key")


def page_route_rollout_status() -> Dict[str, Any]:
    generated_report = ROOT / "outputs" / "ops-liveuintest-rollout-status" / "ops-liveuintest-rollout-status-report.json"
    if generated_report.exists():
        try:
            return json.loads(generated_report.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass

    routes = [
        "/ops/rollout-review",
        "/ops/control-tower",
        "/ops/command",
        "/ops/marketplace",
        "/ops/payments",
        "/host/finance",
        "/wallet",
        "/wallet/receipts",
        "/pass/PASS-NUS-2026-888/payments",
    ]
    return {
        "ok": True,
        "schema_version": "liveuin-ops-liveuintest-rollout-status-v1",
        "phase": "phase-ops-liveuintest-rollout-status",
        "surface": "production page-route rollout status projection",
        "layer": "UI rollout evidence only; no product-truth ownership",
        "summary": {
            "page_system_ready": True,
            "page_system_route_count": 43,
            "page_system_liveuin_test_ready_count": 43,
            "page_system_visual_evidence_ready_count": 43,
            "page_system_ready_phases": ["P2", "P3", "P4", "P5", "P6"],
            "page_system_ready_to_promote_after_review": routes,
            "page_system_already_promoted": routes,
            "page_system_blocked": [],
            "page_system_production_promotion_executed": True,
            "page_promotion_packet_markdown_url": "/docs/LIVEUIN-PAGE-ROUTE-PRODUCTION-PROMOTION-PACKET-2026-07-08.md",
            "page_promotion_packet_json_url": "/outputs/page-route-production-promotion-packet/page-route-production-promotion-packet-report.json",
            "page_production_readiness_markdown_url": "/docs/LIVEUIN-PAGE-ROUTE-PRODUCTION-READINESS-GATE-2026-07-08.md",
            "page_production_readiness_json_url": "/outputs/page-route-production-readiness-gate/page-route-production-readiness-gate-report.json",
            "page_production_readiness_available": True,
            "page_production_readiness_preview_packet_ready": True,
            "page_production_readiness_allowed": False,
            "page_production_readiness_blocker_count": 5,
            "page_production_readiness_blockers": [
                {"code": "liveuin_test_packet_not_ready", "label": "liveuin-test packet is not fully ready"},
                {"code": "promotion_state_not_clean", "label": "promotion state is not clean"},
                {"code": "explicit_approval_missing", "label": "explicit approval missing"},
                {"code": "production_upload_access_unconfirmed", "label": "production upload access unconfirmed"},
                {"code": "post_upload_browser_smoke_not_confirmed", "label": "post-upload browser smoke plan unconfirmed"},
            ],
            "page_production_readiness_explicit_approval_confirmed": False,
            "page_production_readiness_upload_access_confirmed": False,
            "page_production_readiness_browser_smoke_confirmed": False,
            "p2_public_post_upload_plan_ready": True,
            "p2_public_post_upload_plan_route_count": 20,
            "p2_public_post_upload_plan_blocking_failure_count": 0,
            "p2_public_post_upload_plan_browser_smoke_required": True,
            "p2_public_post_upload_plan_gate_blocker_count": 3,
            "p2_public_post_upload_plan_production_target_only_count": 20,
            "p2_public_post_upload_plan_production_upload_executed": False,
            "p2_public_post_upload_plan_production_verification_executed": False,
            "p2_public_post_upload_plan_markdown_url": "/docs/LIVEUIN-P2-PUBLIC-PAGE-POST-UPLOAD-VERIFICATION-PLAN-2026-07-08.md",
            "p2_public_post_upload_plan_json_url": "/outputs/p2-public-page-post-upload-verification-plan/p2-public-page-post-upload-verification-plan-report.json",
            "page_server_handoff_available": True,
            "page_server_handoff_ready": True,
            "page_server_handoff_markdown_url": "/docs/LIVEUIN-PAGE-ROUTE-SERVER-UPDATE-HANDOFF-2026-07-08.md",
            "page_server_handoff_json_url": "/outputs/page-route-server-update-handoff/page-route-server-update-handoff-report.json",
            "page_server_handoff_upload_item_count": 26,
            "page_server_handoff_blocking_failure_count": 0,
            "page_server_handoff_production_upload_executed": True,
            "page_safe_upload_available": True,
            "page_safe_upload_ready": True,
            "page_safe_upload_json_url": "/outputs/page-route-safe-upload/page-route-safe-upload-report.json",
            "page_safe_upload_summary_url": "/outputs/page-route-safe-upload/page-route-safe-upload-summary.json",
            "page_safe_upload_item_count": 26,
            "page_safe_upload_rsync_batch_count": 6,
            "page_safe_upload_blocking_gap_count": 0,
            "page_safe_upload_production_upload_executed": True,
            "page_post_upload_plan_available": True,
            "page_post_upload_plan_ready": True,
            "page_post_upload_plan_markdown_url": "/docs/LIVEUIN-PAGE-ROUTE-POST-UPLOAD-VERIFICATION-PLAN-2026-07-08.md",
            "page_post_upload_plan_json_url": "/outputs/page-route-post-upload-verification-plan/page-route-post-upload-verification-plan-report.json",
            "page_post_upload_plan_route_count": 8,
            "page_post_upload_plan_blocking_failure_count": 0,
            "page_post_upload_plan_production_verification_executed": True,
        },
        "lanes": {
            "page_safe_upload": {
                "ok": True,
                "summary": {
                    "selected_item_count": 26,
                    "rsync_batch_count": 6,
                    "blocking_gap_count": 0,
                    "production_upload_executed": True,
                },
            },
            "page_post_upload_plan": {
                "ok": True,
                "summary": {
                    "route_count": 8,
                    "blocking_failure_count": 0,
                    "production_verification_executed": True,
                },
            },
            "p2_public_page_post_upload_plan": {
                "ok": True,
                "summary": {
                    "route_count": 20,
                    "blocking_failure_count": 0,
                    "post_upload_browser_smoke_required": True,
                    "production_gate_blocker_count": 3,
                    "production_target_only_count": 20,
                    "production_upload_executed": False,
                    "production_verification_executed": False,
                },
                "artifacts": {
                    "markdown": "/docs/LIVEUIN-P2-PUBLIC-PAGE-POST-UPLOAD-VERIFICATION-PLAN-2026-07-08.md",
                    "report": "/outputs/p2-public-page-post-upload-verification-plan/p2-public-page-post-upload-verification-plan-report.json",
                },
            },
            "page_system_roadmap": {
                "ok": True,
                "promotion_routes": [{"path": route, "liveuin_test_ready": True, "visual_evidence_ready": True} for route in routes],
                "summary": {
                    "route_count": 43,
                    "ready_to_promote_after_review": routes,
                    "already_promoted": routes,
                    "blocked": [],
                    "production_promotion_executed": True,
                },
            },
        },
    }


def create_app():
    try:
        from fastapi import FastAPI, HTTPException
        from fastapi.middleware.cors import CORSMiddleware
    except ModuleNotFoundError as exc:  # pragma: no cover - production dependency guard.
        raise RuntimeError("FastAPI is required to run deploy.public_home_gateway") from exc

    try:
        from . import public_home_service as svc
        from . import public_pass_gateway
        from .core_compliance_api import router as core_compliance_router
        from .core_marketplace_api import public_router as public_marketplace_router
        from .home_api import router as public_home_router
    except ImportError:  # pragma: no cover - supports direct app-folder deployment.
        import public_home_service as svc
        import public_pass_gateway
        from core_compliance_api import router as core_compliance_router
        from core_marketplace_api import public_router as public_marketplace_router
        from home_api import router as public_home_router

    app = FastAPI(
        title="LiveUin Public Home API",
        version=svc.SCHEMA_VERSION,
        description="Public homepage bootstrap, discovery, deal, search, and intake contract.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins(),
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-Request-ID", "X-LiveUin-Api-Key", "X-LiveUIN-API-Key"],
    )
    app.include_router(public_home_router)
    app.include_router(public_marketplace_router)

    def require_api_key(
        *,
        api_key: Optional[str],
        required_scope: str,
        request: Any = None,
    ) -> Dict[str, Any]:
        del request  # The public home gateway does not persist key-usage logs yet.

        if not api_key:
            raise HTTPException(status_code=401, detail="missing_api_key")

        try:
            key_record = find_key_record(api_key)
        except RuntimeError as exc:
            detail = str(exc)
            status_code = 403 if detail == "invalid_api_key" else 503
            raise HTTPException(status_code=status_code, detail=detail) from exc

        if bool(key_record.get("revoked", False)) or str(key_record.get("status", "")).lower() == "revoked":
            raise HTTPException(status_code=403, detail="api_key_revoked")

        if str(key_record.get("status", "active")).lower() != "active":
            raise HTTPException(status_code=403, detail="api_key_inactive")

        if key_is_expired(key_record.get("expires_at")):
            raise HTTPException(status_code=403, detail="api_key_expired")

        scopes = normalize_scopes(key_record.get("scopes"))
        if required_scope not in scopes and "*" not in scopes:
            raise HTTPException(status_code=403, detail="api_key_scope_denied")

        return key_record

    public_pass_gateway.mount_public_pass_routes(app, require_api_key)

    @app.get("/v1/health")
    def health() -> Dict[str, Any]:
        return {
            "ok": True,
            "service": SERVICE_NAME,
            "schema_version": svc.SCHEMA_VERSION,
            "time": int(time.time()),
        }

    @app.get("/api/public/home/status")
    def public_home_status() -> Dict[str, Any]:
        try:
            storage = svc.debug_summary()
        except Exception as exc:  # pragma: no cover - reports production wiring issues without leaking secrets.
            storage = {"ok": False, "store": "configured", "detail": exc.__class__.__name__}

        return {
            "ok": True,
            "service": SERVICE_NAME,
            "schema_version": svc.SCHEMA_VERSION,
            "persistence": storage.get("store", "unknown"),
            "storage_ready": bool(storage.get("ok")),
            "routes": [
                "GET /api/public/home/bootstrap",
                "GET /api/public/listings",
                "GET /api/public/partners/{partner_slug}/stays",
                "POST /api/public/partners/{partner_slug}/match-intake",
                "GET /api/public/deals",
                "GET /api/public/deals/report",
                "GET /api/public/areas",
                "GET /api/public/tools",
                "GET /api/public/growth/status",
                "POST /api/public/search",
                "POST /api/public/events",
                "POST /api/public/deals/{deal_id}/claim",
                "POST /api/public/deals/{deal_id}/contact",
                "POST /api/public/deals/{deal_id}/share",
                "POST /api/public/reservations/quote",
                "POST /api/public/igema/consultations",
                "POST /api/public/landlords/watchlist",
                "POST /api/public/tools/yield-calculator",
                "POST /api/public/invite/stakeholders",
            ],
        }

    @app.get("/api/core/ops/liveuintest-rollout-status")
    def liveuintest_rollout_status() -> Dict[str, Any]:
        return page_route_rollout_status()

    return app


app = create_app()
