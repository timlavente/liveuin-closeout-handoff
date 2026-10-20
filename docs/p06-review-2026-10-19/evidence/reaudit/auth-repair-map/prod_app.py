"""LiveUIN Identity public app routes - PRODUCTION entrypoint (step 30, 2026-10-16).

Derived from the staging_app.py of commit 1e9dca6 with these deliberate differences:
  * no CORS middleware (the iOS app uses native HTTP; no browser origins)
  * only the identity router and the token-gated internal notification router are mounted (no inventory router)
  * service name / health identify production
nginx on app.liveuin.com routes only the specific app paths to this service.
"""
from __future__ import annotations

import os
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from core_identity_api import router as identity_router
from core_notification_api import router as notification_router
import core_identity_social as identity_social
import core_identity_account_deletion as account_deletion
import core_identity_public as public_identity
from p2a1_identity_route_contract import route_contract_status

COMMIT = os.environ.get("LIVEUIN_DEPLOYED_COMMIT", "unknown")
SERVICE = "liveuin-identity-public-prod"

app = FastAPI(title="LiveUIN Identity public (production)", version=COMMIT, docs_url=None, redoc_url=None, openapi_url=None)


def _error_response(request: Request, status_code: int, code: str, message: str) -> JSONResponse:
    request_id = str(request.headers.get("x-request-id") or "req_" + uuid.uuid4().hex[:20])
    return JSONResponse(
        status_code=status_code,
        content={
            "ok": False,
            "error": {"code": code, "message": message, "field": None, "recoverable": status_code < 500, "next_action": "retry_or_contact_support"},
            "request_id": request_id,
        },
        headers={"X-Request-ID": request_id},
    )


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or "req_" + uuid.uuid4().hex[:20]
    if not request.headers.get("x-request-id"):
        scope_headers = list(request.scope.get("headers") or [])
        scope_headers.append((b"x-request-id", request_id.encode("ascii")))
        request.scope["headers"] = scope_headers
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    detail = str(exc.detail or "identity_request_failed")
    return _error_response(request, int(exc.status_code), detail, "LiveUIN identity request could not be completed.")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return _error_response(request, 422, "request_validation_error", "The request could not be validated.")


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return _error_response(request, 500, "identity_internal_error", "LiveUIN identity is temporarily unavailable.")


@app.get("/health")
def health() -> dict[str, object]:
    return {"ok": True, "service": SERVICE, "environment": os.environ.get("LIVEUIN_ENVIRONMENT", "")}


@app.get("/version")
def version() -> dict[str, object]:
    return {"ok": True, "service": SERVICE, "commit": COMMIT, "environment": os.environ.get("LIVEUIN_ENVIRONMENT", "")}


@app.get("/ready")
def ready() -> dict[str, object]:
    contract_status = route_contract_status(app)
    route_contract_ready = bool(contract_status["ok"])
    provider_status = identity_social.provider_status()
    deletion_status = account_deletion.readiness()
    registration_enabled = os.environ.get("LIVEUIN_PUBLIC_REGISTRATION_ENABLED", "false").lower() == "true"
    workspace_configured = bool(os.environ.get("LIVEUIN_PUBLIC_WORKSPACE_ID", "").strip())
    return {
        "ok": route_contract_ready,
        "ready": route_contract_ready,
        "service": SERVICE,
        "commit": COMMIT,
        "route_contract_ready": route_contract_ready,
        "public_workspace_configured": workspace_configured,
        "registration_enabled": registration_enabled,
        "identity_email_delivery_mode": os.environ.get("LIVEUIN_IDENTITY_EMAIL_DELIVERY_MODE", "disabled"),
        "identity_email_ready": os.environ.get("LIVEUIN_IDENTITY_EMAIL_READY", "false").lower() == "true",
        "google_public_identity_ready": bool(provider_status.get("google_public_identity_ready")),
        "apple_public_identity_ready": bool(provider_status.get("apple_public_identity_ready")),
        "account_deletion_public_enabled": bool(deletion_status.get("account_deletion_public_enabled")),
    }


app.include_router(identity_router)
app.include_router(notification_router)  # internal identity-email delivery route; token-gated, not exposed by nginx
