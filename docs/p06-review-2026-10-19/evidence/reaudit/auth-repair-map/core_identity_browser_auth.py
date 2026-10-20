from __future__ import annotations

import hashlib
from typing import Any, Dict

try:
    from . import core_identity_google_oauth as google_oauth
    from . import core_identity_login as identity_login
except ImportError:  # pragma: no cover
    import core_identity_google_oauth as google_oauth
    import core_identity_login as identity_login


LOCAL_PREVIEW_HOSTS = {"127.0.0.1", "localhost", "host.docker.internal"}


def _clean_email(value: Any) -> str:
    return str(value or "").strip().lower()


def _looks_like_email(value: str) -> bool:
    return "@" in value and "." in value.rsplit("@", 1)[-1]


def _local_preview_request(request_context: Dict[str, Any] | None = None) -> bool:
    context = request_context if isinstance(request_context, dict) else {}
    host = str(context.get("host") or "").split(":", 1)[0].strip().lower()
    return host in LOCAL_PREVIEW_HOSTS


def browser_auth_request_code(
    payload: Dict[str, Any] | None = None,
    request_meta: Dict[str, str] | None = None,
    request_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    raw_identifier = (
        payload.get("email")
        or payload.get("identifier")
        or payload.get("username")
        or payload.get("phone")
        or ""
    )
    email = _clean_email(raw_identifier)
    if not email:
        return {"ok": False, "status_code": 400, "detail": "email_required"}
    if not _looks_like_email(email):
        return {"ok": False, "status_code": 400, "detail": "valid_email_required"}

    surface = str(payload.get("surface") or "").strip().lower()
    requested_role = str(payload.get("liveuin_role") or payload.get("role") or "").strip().lower()
    purpose = str(payload.get("purpose") or "").strip().lower()
    if not purpose:
        if requested_role in {"agent", "connector_admin"} or surface.startswith("connect") or surface.startswith("partner"):
            purpose = "connect_admin"
        else:
            purpose = "operator_portal"

    created = identity_login.create_login_challenge(
        {
            "workspace_id": payload.get("workspace_id") or identity_login.DEFAULT_WORKSPACE_ID,
            "channel": "email",
            "purpose": purpose,
            "surface": payload.get("surface") or "ops_command",
            "target_hash": hashlib.sha256(email.encode("utf-8")).hexdigest(),
            "role": requested_role or ("agent" if purpose == "connect_admin" else "operator"),
            "source": payload.get("source") or "ops_auth_shell_email_code",
            "metadata": {
                "browser_safe_email_code": True,
                "raw_email_stored": False,
            },
        },
        request_meta,
    )
    if created.get("ok") is not True:
        return created

    challenge = created.get("challenge") if isinstance(created.get("challenge"), dict) else {}
    one_time = created.get("one_time_challenge") if isinstance(created.get("one_time_challenge"), dict) else {}
    response = {
        "ok": True,
        "challenge_id": str(challenge.get("challenge_id") or one_time.get("challenge_id") or ""),
        "expires_at": int(one_time.get("expires_at") or 0),
        "expires_at_iso": str(one_time.get("expires_at_iso") or ""),
        "local_preview_only": False,
        "raw_secret_echoed": False,
    }
    if _local_preview_request(request_context):
        response["local_preview_only"] = True
        response["preview_code"] = str(one_time.get("verification_code") or "")
    return response


def browser_auth_verify_code(
    payload: Dict[str, Any] | None = None,
    request_meta: Dict[str, str] | None = None,
    request_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    challenge_id = str(payload.get("challenge_id") or "").strip()
    if not challenge_id:
        return {"ok": False, "status_code": 400, "detail": "challenge_id_required"}

    return_to = google_oauth._safe_return_to(payload.get("return_to") or "/ops/command")
    verified = identity_login.verify_login_challenge(
        challenge_id,
        {
            "workspace_id": payload.get("workspace_id") or identity_login.DEFAULT_WORKSPACE_ID,
            "verification_code": payload.get("verification_code") or payload.get("code") or "",
            "session_ttl_seconds": payload.get("session_ttl_seconds") or payload.get("ttl_seconds"),
        },
        request_meta,
    )
    if verified.get("ok") is not True:
        return verified

    return {
        "ok": True,
        "redirect": return_to,
        "challenge": verified.get("challenge", {}),
        "session": verified.get("session", {}),
        "set_cookie_headers": google_oauth._session_cookie_headers(
            verified,
            request_context=request_context,
            return_to=return_to,
        ),
        "raw_secret_echoed": False,
    }
