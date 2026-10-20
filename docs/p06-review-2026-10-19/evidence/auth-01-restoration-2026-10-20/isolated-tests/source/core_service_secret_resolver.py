from __future__ import annotations

import hmac
import os
import sqlite3
from typing import Any, Dict, Mapping

try:
    from . import core_adapter_secret_registry as secret_registry
except ImportError:  # pragma: no cover - supports direct script execution.
    import core_adapter_secret_registry as secret_registry


SCHEMA_VERSION = "liveuin-core-service-secret-resolver-v1"
PHASE = "phase-l0-g2-service-api-key-protection"
CANONICAL_OWNER = "LiveUIN Core/Ops"

SERVICE_PROVIDER = "liveuin_service"
WORKSPACE_ENV_KEYS = ("LIVEUIN_OPS_AUTH_WORKSPACE_ID", "LIVEUIN_WORKSPACE_ID")

OPS_COMMAND_REF_ENV = "LIVEUIN_SERVICE_API_KEY_REF"
OPS_COMMAND_RAW_ENV = "LIVEUIN_OPS_COMMAND_API_KEY"
OPS_COMMAND_CREDENTIAL = "LIVEUIN_SERVICE_SECRET_OPS_COMMAND_API_KEY"
OPS_COMMAND_PURPOSE = "ops_command_api_key"

IDENTITY_ADMIN_REF_ENV = "LIVEUIN_ADMIN_BOOTSTRAP_TOKEN_REF"
IDENTITY_ADMIN_RAW_ENV = "LIVEUIN_IDENTITY_ADMIN_TOKEN"
IDENTITY_ADMIN_CREDENTIAL = "LIVEUIN_SERVICE_SECRET_IDENTITY_ADMIN_BOOTSTRAP_TOKEN"
IDENTITY_ADMIN_PURPOSE = "identity_admin_bootstrap_token"
IDENTITY_ADMIN_HEADER = "X-LiveUIN-Admin-Token"

IDENTITY_ADMIN_EXACT_ROUTES = {
    "/api/core/identity/workspaces/host-pilot",
}

IDENTITY_ADMIN_ROUTE_PREFIXES = (
    "/api/core/identity/workspace-memberships",
    "/api/core/identity/workspace-invites",
    "/api/core/identity/credentials",
    "/api/core/identity/session/issue",
    "/api/core/identity/session/revoke",
    "/api/core/identity/api-keys",
)


def _workspace_id() -> str:
    for key in WORKSPACE_ENV_KEYS:
        value = str(os.getenv(key) or "").strip()
        if value:
            return value
    return "laijuzhu"


def _error(detail: str, status_code: int = 503, **extra: Any) -> Dict[str, Any]:
    return {
        "ok": False,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "detail": detail,
        "status_code": status_code,
        "canonical_owner": CANONICAL_OWNER,
        "raw_secret_echoed": False,
        **extra,
    }


def _resolve(*, ref_env: str, raw_env: str, purpose: str, credential_name: str) -> Dict[str, Any]:
    if str(os.getenv(raw_env) or "").strip():
        return _error(
            "raw_service_secret_environment_forbidden",
            500,
            raw_env=raw_env,
            ref_env=ref_env,
        )

    secret_ref_id = str(os.getenv(ref_env) or "").strip()
    if not secret_ref_id:
        return _error("service_secret_reference_required", 503, ref_env=ref_env)

    try:
        resolved = secret_registry.resolve_secret_reference(
            workspace_id=_workspace_id(),
            provider=SERVICE_PROVIDER,
            purpose=purpose,
            secret_ref_id=secret_ref_id,
            request_meta={"source": "core_service_secret_resolver", "purpose": purpose},
            read_only=True,
        )
    except (OSError, RuntimeError, ValueError, sqlite3.Error):
        return _error(
            "service_secret_reference_unavailable",
            503,
            ref_env=ref_env,
            registry_detail="secret_registry_unavailable",
        )
    if resolved.get("ok") is not True:
        return _error(
            "service_secret_reference_unavailable",
            int(resolved.get("status_code") or 503),
            ref_env=ref_env,
            registry_detail=str(resolved.get("detail") or "secret_reference_resolution_failed"),
        )

    secret = str(resolved.get("secret") or "").strip()
    context = resolved.get("secret_context") if isinstance(resolved.get("secret_context"), dict) else {}
    if (
        len(secret) < 32
        or context.get("secret_source") != "registered_systemd_credential"
        or context.get("provider") != SERVICE_PROVIDER
        or context.get("purpose") != purpose
        or context.get("secret_env_var") != credential_name
    ):
        return _error(
            "service_secret_reference_policy_mismatch",
            500,
            ref_env=ref_env,
            secret_context={
                "secret_source": context.get("secret_source", ""),
                "secret_ref_id": context.get("secret_ref_id", ""),
                "provider": context.get("provider", ""),
                "purpose": context.get("purpose", ""),
                "secret_credential_name": context.get("secret_credential_name", ""),
                "raw_secret_echoed": False,
            },
        )

    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "canonical_owner": CANONICAL_OWNER,
        "secret": secret,
        "secret_context": {
            "secret_source": context.get("secret_source", ""),
            "secret_ref_id": context.get("secret_ref_id", ""),
            "provider": context.get("provider", ""),
            "purpose": context.get("purpose", ""),
            "secret_credential_name": context.get("secret_credential_name", ""),
            "secret_hash_prefix": context.get("secret_hash_prefix", ""),
            "raw_secret_echoed": False,
        },
    }


def resolve_ops_command_api_key() -> Dict[str, Any]:
    return _resolve(
        ref_env=OPS_COMMAND_REF_ENV,
        raw_env=OPS_COMMAND_RAW_ENV,
        purpose=OPS_COMMAND_PURPOSE,
        credential_name=OPS_COMMAND_CREDENTIAL,
    )


def resolve_identity_admin_bootstrap_token() -> Dict[str, Any]:
    return _resolve(
        ref_env=IDENTITY_ADMIN_REF_ENV,
        raw_env=IDENTITY_ADMIN_RAW_ENV,
        purpose=IDENTITY_ADMIN_PURPOSE,
        credential_name=IDENTITY_ADMIN_CREDENTIAL,
    )


def identity_admin_route(path: str) -> bool:
    normalized = "/" + str(path or "").strip().lstrip("/")
    return normalized in IDENTITY_ADMIN_EXACT_ROUTES or normalized.startswith(IDENTITY_ADMIN_ROUTE_PREFIXES)


def authorize_identity_admin_bootstrap(headers: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    normalized_headers = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    provided = normalized_headers.get(IDENTITY_ADMIN_HEADER.lower(), "").strip()
    resolved = resolve_identity_admin_bootstrap_token()
    if resolved.get("ok") is not True:
        return resolved
    if not provided or not hmac.compare_digest(provided, str(resolved.get("secret") or "")):
        return _error("identity_admin_bootstrap_token_required", 401)
    context = resolved.get("secret_context") if isinstance(resolved.get("secret_context"), dict) else {}
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "canonical_owner": CANONICAL_OWNER,
        "auth_mode": "protected_admin_bootstrap_token",
        "secret_context": context,
        "raw_secret_echoed": False,
    }


def public_status() -> Dict[str, Any]:
    ops = resolve_ops_command_api_key()
    identity = resolve_identity_admin_bootstrap_token()
    return {
        "ok": ops.get("ok") is True and identity.get("ok") is True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "canonical_owner": CANONICAL_OWNER,
        "ops_command": {
            "ready": ops.get("ok") is True,
            "detail": "ready" if ops.get("ok") is True else str(ops.get("detail") or "unavailable"),
            "secret_context": ops.get("secret_context", {}),
        },
        "identity_admin_bootstrap": {
            "ready": identity.get("ok") is True,
            "detail": "ready" if identity.get("ok") is True else str(identity.get("detail") or "unavailable"),
            "secret_context": identity.get("secret_context", {}),
        },
        "raw_secret_echoed": False,
    }
