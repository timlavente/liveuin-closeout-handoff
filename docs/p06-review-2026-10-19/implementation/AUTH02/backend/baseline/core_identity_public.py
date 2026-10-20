from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import string
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import ipaddress
from typing import Any, Dict, Mapping

try:
    import bcrypt
except ImportError:  # pragma: no cover - staging dependency gate
    bcrypt = None

try:
    from . import core_identity_service as identity_svc
    from . import core_identity_session as identity_session
    from . import core_identity_store as identity_store
    from . import core_identity_public_store as store
    from . import core_service_secret_resolver as service_secrets
except ImportError:  # pragma: no cover - direct app-folder deployment
    import core_identity_service as identity_svc
    import core_identity_session as identity_session
    import core_identity_store as identity_store
    import core_identity_public_store as store
    import core_service_secret_resolver as service_secrets


SCHEMA_VERSION = "liveuin-core-identity-public-v2"
PHASE = "p2a1r-independent-hardening-corrections"
PUBLIC_WORKSPACE_ENV = "LIVEUIN_PUBLIC_WORKSPACE_ID"
PUBLIC_TERMS_ENV = "LIVEUIN_PUBLIC_TERMS_VERSION"
DEFAULT_REGISTRATION_TTL_SECONDS = 15 * 60
DEFAULT_REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60
MAX_REGISTRATION_TTL_SECONDS = 60 * 60
MAX_REFRESH_TTL_SECONDS = 90 * 24 * 60 * 60
PASSWORD_HASH_VERSION = "bcrypt-12"
PUBLIC_PROFILE_KEY = "tenant"
TENANT_SCOPES = ["identity.session", "tenant"]
MAX_RESENDS = 5
RESEND_WINDOW_SECONDS = 3600
DEFAULT_RECOVERY_TTL_SECONDS = 15 * 60
FOUNDER_QA_ACCESS_ENABLED_ENV = "LIVEUIN_FOUNDER_QA_ACCESS_ENABLED"
FOUNDER_QA_ACCESS_CODE_HASH_ENV = "LIVEUIN_FOUNDER_QA_ACCESS_CODE_HASH"
FOUNDER_QA_ACCOUNT_ID_ENV = "LIVEUIN_FOUNDER_QA_ACCOUNT_ID"
FOUNDER_QA_PERSON_ID_ENV = "LIVEUIN_FOUNDER_QA_PERSON_ID"
FOUNDER_QA_DISPLAY_NAME_ENV = "LIVEUIN_FOUNDER_QA_DISPLAY_NAME"
FOUNDER_QA_DEFAULT_ACCOUNT_ID = "acct_founder_qa_resident"
FOUNDER_QA_DEFAULT_PERSON_ID = "per_founder_qa_resident"

PROFILE_CONTINUATION_ROUTES = {
    "complete_profile": "/auth/complete-profile",
    "complete_onboarding": "/auth/continue-tenant",
    "tenant_home": "/tenant/home",
    "localpro_home": "/localpro/home",
    "localpro_review": "/localpro/apply",
    "contact_support": "/support",
    "sign_in": "/welcome",
    "wait_for_deletion": "/auth/deletion-pending",
    "link_required": "/auth/link-required",
}


def _now() -> int:
    return int(time.time())


def _iso(epoch: Any) -> str:
    try:
        value = int(epoch)
    except (TypeError, ValueError):
        value = 0
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(value)) if value else ""


def _clean(value: Any, max_length: int = 240) -> str:
    return str(value or "").strip()[:max_length]


def _clean_id(value: Any, max_length: int = 160) -> str:
    return "".join(ch for ch in str(value or "").strip() if ch.isalnum() or ch in "_.:-")[:max_length]


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _is_production() -> bool:
    return str(os.getenv("LIVEUIN_ENVIRONMENT") or os.getenv("ENVIRONMENT") or "").strip().lower() in {"prod", "production"}


def _feature_enabled() -> bool:
    return _bool_env("LIVEUIN_PUBLIC_REGISTRATION_ENABLED", False)


def _configured_workspace(request_meta: Mapping[str, Any] | None = None) -> tuple[str, Dict[str, Any]]:
    workspace_id = _clean_id(os.getenv(PUBLIC_WORKSPACE_ENV), 96)
    if not workspace_id:
        return "", error(
            "public_workspace_not_configured",
            503,
            "Public identity workspace configuration requires a LiveUIN governance decision.",
            request_meta=request_meta,
            recoverable=False,
            next_action="configure_approved_public_workspace",
        )
    return workspace_id, {}


def _approved_terms_version(request_meta: Mapping[str, Any] | None = None) -> tuple[str, Dict[str, Any]]:
    version = _clean(os.getenv(PUBLIC_TERMS_ENV), 80)
    if not version:
        return "", error(
            "public_terms_not_configured",
            503,
            "The current LiveUIN terms version is not configured.",
            request_meta=request_meta,
            recoverable=False,
            next_action="configure_current_terms_version",
        )
    return version, {}


def _request_is_trusted_local(request_meta: Mapping[str, Any] | None) -> bool:
    meta = _as_dict(request_meta)
    host = str(meta.get("host") or "").split(":", 1)[0].strip().strip("[]").lower()
    client_ip = str(meta.get("ip") or "").strip()
    if host not in {"localhost", "127.0.0.1", "::1", "host.docker.internal"}:
        return False
    try:
        return ipaddress.ip_address(client_ip).is_loopback
    except ValueError:
        return False


def _synthetic_test_mode(request_meta: Mapping[str, Any] | None = None) -> bool:
    return not _is_production() and _bool_env("LIVEUIN_IDENTITY_TEST_MODE", False) and _request_is_trusted_local(request_meta)


def _email_subject_identifier(email: str) -> str:
    pepper = os.getenv("LIVEUIN_IDENTITY_EMAIL_PROVIDER_PEPPER") or os.getenv("LIVEUIN_IDENTITY_VERIFICATION_PEPPER")
    if not pepper or len(pepper) < 16:
        raise RuntimeError("email_provider_pepper_missing")
    return hmac.new(pepper.encode("utf-8"), email.encode("utf-8"), hashlib.sha256).hexdigest()


def _idempotency_key(payload: Mapping[str, Any], request_meta: Mapping[str, Any] | None = None) -> str:
    raw = _clean(payload.get("idempotency_key") or _as_dict(request_meta).get("idempotency_key"), 200)
    return raw or ("implicit:" + _email_hash(_email(payload.get("email"))))


def _request_id(request_meta: Mapping[str, Any] | None) -> str:
    provided = _clean(_as_dict(request_meta).get("request_id"), 80)
    if provided and all(char.isalnum() or char in "._:-" for char in provided):
        return provided
    return "req_" + uuid.uuid4().hex[:20]


def error(
    code: str,
    status_code: int,
    message: str,
    *,
    request_meta: Mapping[str, Any] | None = None,
    field: str | None = None,
    recoverable: bool = True,
    next_action: str = "contact_support",
    **extra: Any,
) -> Dict[str, Any]:
    return {
        "ok": False,
        "status_code": status_code,
        "request_id": _request_id(request_meta),
        "error": {
            "code": code,
            "message": message,
            "field": field,
            "recoverable": recoverable,
            "next_action": next_action,
            **extra,
        },
    }


def internal_error(request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    return error(
        "server_error",
        500,
        "LiveUIN could not complete that request.",
        request_meta=request_meta,
        recoverable=True,
        next_action="retry_or_contact_support",
    )


def _feature_error(request_meta: Mapping[str, Any] | None) -> Dict[str, Any]:
    return error(
        "public_registration_disabled",
        503,
        "Public account creation is not available yet.",
        request_meta=request_meta,
        recoverable=True,
        next_action="try_again_later",
    )


def _email(value: Any) -> str:
    return _clean(value, 320).lower()


def _valid_email(email: str) -> bool:
    if len(email) < 5 or len(email) > 320 or email.count("@") != 1:
        return False
    local, domain = email.rsplit("@", 1)
    return bool(local and domain and "." in domain and " " not in email)


def _email_hash(email: str) -> str:
    return hashlib.sha256(email.encode("utf-8")).hexdigest()


def _email_hint(email: str) -> str:
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        local_hint = "*"
    else:
        local_hint = local[:1] + "***" + local[-1:]
    return local_hint + "@" + domain


def _password_valid(password: str) -> bool:
    if len(password) < 12 or len(password) > 128:
        return False
    has_alpha = any(char.isalpha() for char in password)
    has_digit = any(char.isdigit() for char in password)
    return has_alpha and has_digit


def _password_hash(password: str) -> str:
    if bcrypt is None:
        raise RuntimeError("bcrypt_dependency_missing")
    rounds = int(os.getenv("LIVEUIN_IDENTITY_BCRYPT_ROUNDS", "12"))
    rounds = max(10, min(14, rounds))
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds)).decode("ascii")


def _password_matches(password: str, stored: str) -> bool:
    if bcrypt is None or not stored:
        return False
    try:
        return bool(bcrypt.checkpw(password.encode("utf-8"), stored.encode("ascii")))
    except (ValueError, TypeError):
        return False


def _verification_pepper() -> bytes:
    value = os.getenv("LIVEUIN_IDENTITY_VERIFICATION_PEPPER") or os.getenv("LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET")
    if not value or len(value) < 16:
        raise RuntimeError("verification_pepper_missing")
    return value.encode("utf-8")


def _code_hash(code: str) -> str:
    return hmac.new(_verification_pepper(), code.encode("utf-8"), hashlib.sha256).hexdigest()


def _random_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _random_token(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def _random_reset_id() -> str:
    """Return a path-safe reset correlation identifier with 128 bits of entropy."""
    return "pwr_" + secrets.token_hex(16)


def _valid_reset_id(reset_id: Any) -> bool:
    value = str(reset_id or "").strip()
    return len(value) == 36 and value.startswith("pwr_") and all(char in string.hexdigits for char in value[4:])


def _recovery_request_response(reset: Mapping[str, Any], request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    expires_at = int(reset.get("expires_at") or 0)
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "recovery_requested",
        "message": "If the account is eligible, recovery instructions will be delivered.",
        "reset_id": _clean_id(reset.get("reset_id"), 96),
        "next_action": "verify_code",
        "expires_in_seconds": max(0, expires_at - _now()),
        "verification_expiry": expires_at,
        "request_id": _request_id(request_meta),
        "enumeration_safe": True,
    }


def _recovery_failure(request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    return error(
        "recovery_code_invalid_or_expired",
        403,
        "That recovery code is invalid or expired.",
        request_meta=request_meta,
        next_action="request_password_reset",
    )


def _bounded(value: Any, default: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if parsed <= 0:
        return default
    return min(parsed, maximum)


def _verification_ttl(payload: Mapping[str, Any], request_meta: Mapping[str, Any] | None) -> int:
    if not _synthetic_test_mode(request_meta):
        return DEFAULT_REGISTRATION_TTL_SECONDS
    return _bounded(payload.get("verification_ttl_seconds"), DEFAULT_REGISTRATION_TTL_SECONDS, MAX_REGISTRATION_TTL_SECONDS)


def _deliver_verification_code(
    *,
    email: str,
    code: str,
    registration_id: str,
    expires_at: int,
    locale: str,
    request_meta: Mapping[str, Any] | None,
    idempotency_key: str,
    template: str = "liveuin_identity_verification",
) -> Dict[str, Any]:
    mode = _clean(os.getenv("LIVEUIN_IDENTITY_EMAIL_DELIVERY_MODE") or "disabled", 40).lower()
    if mode in {"test_sink", "synthetic"}:
        if _is_production() or not _bool_env("LIVEUIN_IDENTITY_TEST_MODE", False):
            return error("email_delivery_unavailable", 503, "Email delivery is not available.", request_meta=request_meta, next_action="try_again_later")
        sink = _clean(os.getenv("LIVEUIN_IDENTITY_TEST_SINK_PATH"), 500)
        if not sink:
            return error("email_delivery_unavailable", 503, "Email delivery is not available.", request_meta=request_meta, next_action="try_again_later")
        try:
            path = os.path.abspath(os.path.expanduser(sink))
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({
                    "registration_id": registration_id,
                    "code": code,
                    "expires_at": expires_at,
                    "locale": locale,
                    "template": template,
                    "email_hash": _email_hash(email),
                }, sort_keys=True) + "\n")
            return {"ok": True, "mode": "test_sink"}
        except OSError:
            return error("email_delivery_unavailable", 503, "Email delivery is not available.", request_meta=request_meta, next_action="try_again_later")

    if mode not in {"http", "approved_http"}:
        return error("email_delivery_unavailable", 503, "Email delivery is not available.", request_meta=request_meta, next_action="try_again_later")

    endpoint = _clean(os.getenv("LIVEUIN_IDENTITY_EMAIL_DELIVERY_URL"), 500)
    parsed_endpoint = urllib.parse.urlparse(endpoint)
    if (
        not endpoint
        or parsed_endpoint.scheme != "http"
        or parsed_endpoint.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed_endpoint.path != "/internal/notifications/identity-email"
        or not _bool_env("LIVEUIN_IDENTITY_EMAIL_READY", False)
    ):
        return error("email_delivery_unavailable", 503, "Email delivery is not available.", request_meta=request_meta, next_action="try_again_later")
    resolved_token = service_secrets.resolve_identity_email_delivery_token()
    if resolved_token.get("ok") is not True:
        return error("email_delivery_unavailable", 503, "Email delivery is not available.", request_meta=request_meta, next_action="try_again_later")
    correlation_id = _clean_id(registration_id, 160)
    notification_key = f"identity-email:{template}:{correlation_id}:{idempotency_key}"
    notification_id = "notif_" + correlation_id + "_" + store.hash_value(notification_key)[:16]
    payload = json.dumps({
        "notification_id": notification_id,
        "template": "password_reset" if template == "liveuin_identity_password_reset" else "identity_verification",
        "recipient": email,
        "correlation_id": correlation_id,
        "verification_code": code,
        "expires_at": expires_at,
        "locale": locale or "en",
        "request_id": _request_id(request_meta),
        "idempotency_key": notification_key,
    }, separators=(",", ":"), sort_keys=True).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Request-ID": _request_id(request_meta),
        "X-LiveUIN-Notification-Token": str(resolved_token.get("secret") or ""),
    }
    try:
        request = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=5) as response:
            if int(response.status) not in range(200, 300):
                raise urllib.error.HTTPError(endpoint, int(response.status), "delivery_failed", response.headers, None)
            response_body = response.read(8192).decode("utf-8", "replace")
        try:
            response_payload = json.loads(response_body or "{}")
        except json.JSONDecodeError:
            response_payload = {}
        if response_payload.get("ok") is not True:
            response_error = response_payload.get("error") if isinstance(response_payload.get("error"), dict) else {}
            response_code = str(response_error.get("code") or "email_delivery_unavailable")
            if response_code not in {"email_delivery_unavailable", "email_delivery_timeout", "email_provider_rate_limited", "email_sender_not_ready", "email_recipient_rejected", "email_message_rejected", "email_provider_auth_failed", "email_delivery_internal_error"}:
                response_code = "email_delivery_unavailable"
            return error(response_code, 503, "Email delivery is not available.", request_meta=request_meta, next_action="try_again_later")
        return {"ok": True, "mode": "approved_http"}
    except urllib.error.HTTPError:
        return error("email_delivery_unavailable", 503, "Email delivery is not available.", request_meta=request_meta, next_action="try_again_later")
    except (OSError, urllib.error.URLError, TimeoutError):
        return error("email_delivery_unavailable", 503, "Email delivery is not available.", request_meta=request_meta, next_action="try_again_later")


def _public_profile_entitlements(account: Dict[str, Any]) -> list[Dict[str, Any]]:
    """Return only canonical, active profile entitlements for this account.

    This is the single public authorized-profile projection used by password,
    verification, refresh, onboarding, and provider flows.  The store query
    is scoped, but the relationship checks below are intentionally repeated at
    the projection boundary so a malformed or cross-account row fails closed
    instead of being repaired with a client/default workspace.
    """
    account_id = _clean_id(account.get("account_id"), 160)
    person_id = _clean_id(account.get("person_id"), 160)
    workspace_id = _clean_id(account.get("workspace_id"), 96)
    if not account_id or not person_id or not workspace_id:
        return []

    rows = identity_store.list_profile_entitlements(
        person_id=account.get("person_id", ""),
        account_id=account.get("account_id", ""),
        workspace_id=account.get("workspace_id", ""),
    )
    result: list[Dict[str, Any]] = []
    for row in rows:
        entitlement_id = _clean_id(row.get("entitlement_id"), 160)
        row_workspace_id = _clean_id(row.get("workspace_id"), 96)
        row_account_id = _clean_id(row.get("account_id"), 160)
        row_person_id = _clean_id(row.get("person_id"), 160)
        profile_key = _clean(row.get("profile_key"), 80).lower()
        status = _clean(row.get("status"), 40).lower()
        if not entitlement_id or not profile_key or status not in {"active", "authorized"}:
            continue
        if (
            row_workspace_id != workspace_id
            or row_account_id != account_id
            or row_person_id != person_id
        ):
            # Do not substitute a default workspace or disclose an internal
            # scope conflict in customer-facing data.
            continue
        permissions = row.get("permissions")
        route_restrictions = row.get("route_restrictions")
        result.append({
            "entitlement_id": entitlement_id,
            "workspace_id": row_workspace_id,
            "account_id": row_account_id,
            "person_id": row_person_id,
            "profile_key": profile_key,
            "subject_id": _clean_id(row.get("subject_id"), 160),
            "subject_role": _clean(row.get("subject_role"), 80).lower(),
            "status": status,
            "is_default": bool(row.get("is_default")),
            "permissions": list(permissions) if isinstance(permissions, list) else [],
            "route_restrictions": list(route_restrictions) if isinstance(route_restrictions, list) else [],
        })
    return result


def _mobile_scope_profile_compatible(profile: Mapping[str, Any], account: Mapping[str, Any]) -> bool:
    """Mirror the non-negotiable mobile scope boundary for readiness tests."""
    required = {
        "entitlement_id",
        "workspace_id",
        "account_id",
        "person_id",
        "profile_key",
        "status",
        "is_default",
        "permissions",
        "route_restrictions",
    }
    if not required.issubset(profile):
        return False
    return bool(
        profile.get("workspace_id")
        and profile.get("workspace_id") == account.get("workspace_id")
        and profile.get("account_id") == account.get("account_id")
        and profile.get("person_id") == account.get("person_id")
        and profile.get("profile_key")
        and str(profile.get("status") or "").lower() in {"active", "authorized"}
    )


def _has_active_profile(authorized_profiles: list[Dict[str, Any]], profile_key: str) -> bool:
    normalized_key = str(profile_key or "").strip().lower()
    return any(
        str(profile.get("profile_key") or "").strip().lower() == normalized_key
        and str(profile.get("status") or "").strip().lower() in {"active", "authorized"}
        for profile in authorized_profiles
    )


def _state(account: Dict[str, Any], authorized_profiles: list[Dict[str, Any]] | None = None) -> str:
    deletion = account.get("deletion_status")
    if deletion == "deleted":
        return "account_deleted"
    if deletion == "pending":
        return "deletion_pending"
    if account.get("status") == "account_disabled":
        return "account_disabled"
    if not account.get("email_verified_at"):
        return "email_verification_pending"
    profiles = _public_profile_entitlements(account) if authorized_profiles is None else authorized_profiles
    if account.get("tenant_entitlement_state") == "active" and _has_active_profile(profiles, PUBLIC_PROFILE_KEY):
        return "tenant_active"
    if account.get("localpro_authorization_state") in {"active", "authorized", "issued", "approved"} and _has_active_profile(profiles, "localpro"):
        return "localpro_approved"
    if account.get("profile_completion_state") == "complete":
        return "authenticated"
    if account.get("status") in {"authenticated", "profile_incomplete", "tenant_active", "localpro_pending", "localpro_approved"}:
        return "profile_incomplete" if account.get("profile_completion_state") != "complete" else "authenticated"
    return str(account.get("status") or "anonymous")


def _next_action(account: Dict[str, Any], authorized_profiles: list[Dict[str, Any]] | None = None) -> str:
    state = _state(account, authorized_profiles)
    return {
        "email_verification_pending": "verify_email",
        "authenticated": "complete_onboarding",
        "profile_incomplete": "complete_profile" if account.get("profile_completion_state") != "complete" else "complete_onboarding",
        "tenant_active": "tenant_home",
        "localpro_pending": "localpro_review",
        "localpro_approved": "localpro_home",
        "localpro_suspended": "contact_support",
        "account_disabled": "contact_support",
        "deletion_pending": "wait_for_deletion",
        "account_deleted": "contact_support",
    }.get(state, "sign_in")


def _account_payload(account: Dict[str, Any], authorized_profiles: list[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    profiles = _public_profile_entitlements(account) if authorized_profiles is None else list(authorized_profiles)
    state = _state(account, profiles)
    next_action = _next_action(account, profiles)
    return {
        "profile_state": state,
        "account_state": state,
        "email_verification_state": "verified" if account.get("email_verified_at") else "pending",
        "profile_completion_state": account.get("profile_completion_state", "incomplete"),
        "tenant_entitlement_state": account.get("tenant_entitlement_state", "not_issued"),
        "localpro_application_state": account.get("localpro_application_state", "not_started"),
        "localpro_authorization_state": account.get("localpro_authorization_state", "not_issued"),
        "authorized_profiles": profiles,
        "next_action": next_action,
        "continuation": {
            "state": state,
            "next_action": next_action,
            "route": PROFILE_CONTINUATION_ROUTES.get(next_action, "/welcome"),
            "label": "Complete your LiveUIN profile" if next_action in {"complete_profile", "complete_onboarding"} else "Continue to LiveUIN",
        },
    }


def session_bootstrap_projection_result(account_id: Any, person_id: Any, workspace_id: Any) -> Dict[str, Any]:
    """Resolve a server-owned session reference into a strict public projection."""
    account_id = _clean_id(account_id, 160)
    person_id = _clean_id(person_id, 160)
    workspace_id = _clean_id(workspace_id, 96)
    if not account_id or not person_id or not workspace_id:
        return {"ok": False, "detail": "session_public_account_projection_unavailable", "status_code": 403}
    account = store.get_account(account_id)
    if not account:
        return {"ok": False, "detail": "session_public_account_projection_unavailable", "status_code": 403}
    if (
        _clean_id(account.get("account_id"), 160) != account_id
        or _clean_id(account.get("person_id"), 160) != person_id
        or _clean_id(account.get("workspace_id"), 96) != workspace_id
    ):
        return {"ok": False, "detail": "session_public_account_projection_unavailable", "status_code": 403}
    person = identity_store.get_person(person_id, workspace_id)
    if (
        not person
        or _clean_id(person.get("person_id"), 160) != person_id
        or _clean_id(person.get("workspace_id"), 96) != workspace_id
    ):
        return {"ok": False, "detail": "session_public_account_projection_unavailable", "status_code": 403}
    return {
        "ok": True,
        "projection": {
            "account_id": account_id,
            "person_id": person_id,
            "workspace_id": workspace_id,
            **_account_payload(account),
        },
    }


def session_bootstrap_projection(account_id: Any, person_id: Any, workspace_id: Any) -> Dict[str, Any]:
    """Return the public, non-secret Identity/Core continuation projection for a resolved session."""
    result = session_bootstrap_projection_result(account_id, person_id, workspace_id)
    return result.get("projection") if result.get("ok") is True else {}


def session_public_account_projection_ready() -> bool:
    """Run the non-mutating session/public-account contract gate used by /ready."""
    from unittest.mock import patch

    account = {
        "account_id": "acct_contract",
        "person_id": "per_contract",
        "workspace_id": "workspace_contract",
        "status": "profile_incomplete",
        "email_verified_at": 1,
        "profile_completion_state": "incomplete",
        "tenant_entitlement_state": "not_issued",
        "localpro_application_state": "not_started",
        "localpro_authorization_state": "not_issued",
    }
    person = {"person_id": account["person_id"], "workspace_id": account["workspace_id"]}
    public_record = identity_session._session_identity_record(
        {
            "auth_method": "public_google",
            "metadata": {"public_account_id": account["account_id"]},
        },
        {"actor_id": account["person_id"]},
    )
    if not (
        public_record.get("ok") is True
        and public_record.get("account_id") == account["account_id"]
        and public_record.get("public_account_id") == account["account_id"]
        and public_record.get("person_id") == account["person_id"]
    ):
        return False
    if identity_session._session_identity_record(
        {
            "auth_method": "public_google",
            "metadata": {"public_account_id": "acct_a", "account_id": "acct_b"},
        },
        {"actor_id": account["person_id"]},
    ).get("detail") != "session_account_reference_conflict":
        return False
    with patch.object(store, "get_account", return_value=account), patch.object(identity_store, "get_person", return_value=person):
        projection_result = session_bootstrap_projection_result(
            account["account_id"], account["person_id"], account["workspace_id"]
        )
    projection = projection_result.get("projection") if projection_result.get("ok") is True else {}
    if not (
        projection_result.get("ok") is True
        and projection.get("account_id") == account["account_id"]
        and projection.get("person_id") == account["person_id"]
        and projection.get("workspace_id") == account["workspace_id"]
        and projection.get("profile_completion_state") == "incomplete"
        and projection.get("tenant_entitlement_state") == "not_issued"
        and projection.get("authorized_profiles") == []
        and projection.get("next_action") == "complete_profile"
        and _as_dict(projection.get("continuation")).get("route") == "/auth/complete-profile"
    ):
        return False

    captured: Dict[str, Any] = {}

    def fake_issue(payload: Dict[str, Any], request_meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
        captured.update(payload)
        return {
            "ok": True,
            "one_time_credential": {
                "session_id": "session-contract-only",
                "session_headers": {"X-LiveUIN-Session-Id": "session-contract-only"},
                "expires_at": 1,
            },
        }

    with patch.object(identity_session, "issue_session", side_effect=fake_issue):
        issued = _issue_session(account, {}, "public_google", persist_refresh=False)
    issued_metadata = _as_dict(captured.get("metadata"))
    return bool(
        issued.get("ok") is not False
        and issued_metadata.get("public_account_id") == account["account_id"]
        and identity_session._session_identity_record(
            {"auth_method": "public_session_refresh", "metadata": issued_metadata},
            {"actor_id": account["person_id"]},
        ).get("public_account_id")
        == account["account_id"]
    )


def profile_continuation_contract_ready() -> bool:
    """Keep the mobile bootstrap contract executable without touching customer data."""
    incomplete = {
        "account_id": "acct_contract",
        "person_id": "per_contract",
        "workspace_id": "workspace_contract",
        "status": "profile_incomplete",
        "email_verified_at": 1,
        "profile_completion_state": "incomplete",
        "tenant_entitlement_state": "not_issued",
        "localpro_application_state": "not_started",
        "localpro_authorization_state": "not_issued",
    }
    incomplete_projection = _account_payload(incomplete, [])
    if not (
        incomplete_projection.get("profile_state") == "profile_incomplete"
        and incomplete_projection.get("profile_completion_state") == "incomplete"
        and incomplete_projection.get("tenant_entitlement_state") == "not_issued"
        and incomplete_projection.get("authorized_profiles") == []
        and incomplete_projection.get("next_action") == "complete_profile"
        and _as_dict(incomplete_projection.get("continuation")).get("route") == "/auth/complete-profile"
    ):
        return False

    complete = {**incomplete, "profile_completion_state": "complete"}
    complete_projection = _account_payload(complete, [])
    if complete_projection.get("next_action") != "complete_onboarding":
        return False

    tenant = {**complete, "status": "tenant_active", "tenant_entitlement_state": "active"}
    tenant_profile = [{"profile_key": PUBLIC_PROFILE_KEY, "status": "active", "is_default": True}]
    tenant_projection = _account_payload(tenant, tenant_profile)
    if tenant_projection.get("next_action") != "tenant_home" or tenant_projection.get("profile_state") != "tenant_active":
        return False

    # An entitlement flag without an active Tenant profile must remain fail-closed.
    if _account_payload(tenant, []).get("next_action") != "complete_onboarding":
        return False

    localpro = {**complete, "localpro_authorization_state": "active"}
    localpro_profile = [{"profile_key": "localpro", "status": "authorized", "is_default": True}]
    localpro_projection = _account_payload(localpro, localpro_profile)
    if localpro_projection.get("next_action") != "localpro_home":
        return False
    return True


def auth_journey_contract_ready() -> bool:
    """Prove every bounded public auth state has an explicit continuation route."""
    cases = [
        ({"status": "profile_incomplete", "profile_completion_state": "incomplete"}, "complete_profile", "/auth/complete-profile"),
        ({"status": "authenticated", "profile_completion_state": "complete"}, "complete_onboarding", "/auth/continue-tenant"),
        ({"status": "tenant_active", "profile_completion_state": "complete", "tenant_entitlement_state": "active"}, "tenant_home", "/tenant/home"),
        ({"status": "localpro_approved", "profile_completion_state": "complete", "localpro_authorization_state": "active"}, "localpro_home", "/localpro/home"),
        ({"status": "deletion_pending", "deletion_status": "pending"}, "wait_for_deletion", "/auth/deletion-pending"),
    ]
    common = {
        "account_id": "acct_auth_contract",
        "person_id": "per_auth_contract",
        "workspace_id": "workspace_auth_contract",
        "email_verified_at": 1,
        "tenant_entitlement_state": "not_issued",
        "localpro_application_state": "not_started",
        "localpro_authorization_state": "not_issued",
    }
    for overrides, expected_action, expected_route in cases:
        account = {**common, **overrides}
        profiles = []
        if expected_action == "tenant_home":
            profiles = [{"profile_key": "tenant", "status": "active", "is_default": True}]
        if expected_action == "localpro_home":
            profiles = [{"profile_key": "localpro", "status": "authorized", "is_default": True}]
        projection = _account_payload(account, profiles)
        continuation = _as_dict(projection.get("continuation"))
        if projection.get("next_action") != expected_action or continuation.get("route") != expected_route:
            return False
    return all(route.startswith("/") for route in PROFILE_CONTINUATION_ROUTES.values())


def profile_workspace_projection_ready() -> bool:
    """Prove the canonical scoped profile contract without touching customer data."""
    from unittest.mock import patch

    account = {
        "account_id": "acct_workspace_contract",
        "person_id": "per_workspace_contract",
        "workspace_id": "liveuin-public-staging",
        "status": "tenant_active",
        "email_verified_at": 1,
        "profile_completion_state": "complete",
        "tenant_entitlement_state": "active",
        "localpro_application_state": "not_started",
        "localpro_authorization_state": "not_issued",
    }
    valid = {
        "entitlement_id": "ent_workspace_contract",
        "workspace_id": account["workspace_id"],
        "account_id": account["account_id"],
        "person_id": account["person_id"],
        "profile_key": "tenant",
        "subject_id": account["person_id"],
        "subject_role": "tenant",
        "status": "active",
        "is_default": True,
        "permissions": ["tenant"],
        "route_restrictions": [],
    }

    with patch.object(identity_store, "list_profile_entitlements", return_value=[valid]):
        profiles_by_method = {
            method: _public_profile_entitlements(account)
            for method in ("email_password", "google", "apple", "session_refresh", "onboarding")
        }
    profiles = profiles_by_method["email_password"]
    if len(profiles) != 1 or not _mobile_scope_profile_compatible(profiles[0], account):
        return False
    if any(output != profiles for output in profiles_by_method.values()):
        return False
    if _account_payload(account, profiles).get("next_action") != "tenant_home":
        return False
    if _as_dict(_account_payload(account, profiles).get("continuation")).get("route") != "/tenant/home":
        return False

    missing_workspace = {**valid, "workspace_id": ""}
    conflicting_workspace = {**valid, "workspace_id": "laijuzhu"}
    wrong_account = {**valid, "account_id": "acct_other"}
    inactive = {**valid, "status": "revoked"}
    for invalid in (missing_workspace, conflicting_workspace, wrong_account, inactive):
        with patch.object(identity_store, "list_profile_entitlements", return_value=[invalid]):
            if _public_profile_entitlements(account):
                return False
            if _account_payload(account).get("next_action") == "tenant_home":
                return False

    # A client/request workspace is never read by this projection; the
    # account's canonical relationship is the only source of scope.
    client_workspace = "client-requested-workspace"
    with patch.object(identity_store, "list_profile_entitlements", return_value=[valid]) as listed:
        _public_profile_entitlements({**account, "requested_workspace_id": client_workspace})
    call = listed.call_args.kwargs
    if call.get("workspace_id") != account["workspace_id"]:
        return False
    return True


def _issue_session(
    account: Dict[str, Any],
    request_meta: Mapping[str, Any] | None,
    auth_method: str,
    *,
    persist_refresh: bool = True,
) -> Dict[str, Any]:
    scopes = ["identity.session"]
    if account.get("tenant_entitlement_state") == "active" and _has_active_profile(_public_profile_entitlements(account), PUBLIC_PROFILE_KEY):
        scopes.append("tenant")
    issued = identity_session.issue_session(
        {
            "workspace_id": account.get("workspace_id") or "",
            "actor_id": account.get("person_id"),
            "role": "member",
            "scopes": scopes,
            "ttl_seconds": _bounded(os.getenv("LIVEUIN_PUBLIC_SESSION_TTL_SECONDS"), 60 * 60 * 24, identity_session.MAX_SESSION_TTL_SECONDS),
            "auth_method": auth_method,
            "metadata": {"public_account_id": account.get("account_id"), "identity_state": _state(account)},
        },
        dict(request_meta or {}),
    )
    if issued.get("ok") is not True:
        return internal_error(request_meta)
    one_time = _as_dict(issued.get("one_time_credential"))
    raw_session_id = _clean(one_time.get("session_id"), 240)
    raw_refresh = _random_token("lur_")
    session_hash = store.hash_value(raw_session_id)
    refresh_hash = store.hash_value(raw_refresh)
    refresh_expires = _now() + _bounded(os.getenv("LIVEUIN_PUBLIC_REFRESH_TTL_SECONDS"), DEFAULT_REFRESH_TTL_SECONDS, MAX_REFRESH_TTL_SECONDS)
    if persist_refresh:
        store.create_refresh_credential(
            refresh_token_hash=refresh_hash,
            account_id=account.get("account_id", ""),
            workspace_id=account.get("workspace_id", ""),
            session_id_hash=session_hash,
            issued_at=_now(),
            expires_at=refresh_expires,
        )
    return {
        "session": {
            "credential_kind": "liveuin_session",
            "session_headers": _as_dict(one_time.get("session_headers")),
            "expires_at": int(one_time.get("expires_at") or 0),
            "expires_at_iso": _iso(one_time.get("expires_at")),
            "raw_secret_returned_once": True,
            "raw_secret_stored": False,
        },
        "one_time_credential": {
            "credential_kind": "liveuin_session",
            "session_id": raw_session_id,
            "session_headers": _as_dict(one_time.get("session_headers")),
            "expires_at": int(one_time.get("expires_at") or 0),
            "raw_secret_returned_once": True,
            "raw_secret_stored": False,
        },
        "refresh_token": raw_refresh,
        "refresh_expires_at": refresh_expires,
        "refresh_expires_at_iso": _iso(refresh_expires),
    }


def _session_account(headers: Mapping[str, str] | None, request_meta: Mapping[str, Any] | None) -> tuple[Dict[str, Any], Dict[str, Any]]:
    configured_workspace, workspace_failure = _configured_workspace(request_meta)
    if workspace_failure:
        return {}, workspace_failure
    resolved = identity_session.resolve_access_context(
        {}, headers or {}, method="POST", path="/api/core/identity/public", request_meta=dict(request_meta or {}), require_identity=True,
    )
    if resolved.get("ok") is not True:
        return {}, error("session_required", 401, "Sign in to continue.", request_meta=request_meta, next_action="sign_in")
    actor = _as_dict(resolved.get("actor"))
    person_id = _clean_id(actor.get("actor_id"))
    resolved_workspace = _clean_id(resolved.get("workspace_id"), 96)
    if resolved_workspace != configured_workspace:
        return {}, error("session_workspace_mismatch", 403, "This session is not valid for the public identity workspace.", request_meta=request_meta, next_action="sign_in")
    account = store.get_account_by_person_id(person_id, configured_workspace)
    if not account:
        return {}, error("session_account_not_found", 401, "Sign in to continue.", request_meta=request_meta, next_action="sign_in")
    if _state(account) in {"account_disabled", "deletion_pending", "account_deleted"}:
        return {}, error("account_unavailable", 403, "This account is not available.", request_meta=request_meta, next_action="contact_support")
    return account, {}


def _registration_response(registration: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "registration_started",
        "canonical_owner": "LiveUIN Identity",
        "registration_id": registration.get("registration_id", ""),
        "verification_required": True,
        "verification_expiry": registration.get("expires_at", 0),
        "verification_expiry_iso": _iso(registration.get("expires_at")),
        "next_action": "verify_email",
        "profile_state": "email_verification_pending",
        "requested_default_profile": PUBLIC_PROFILE_KEY,
        "raw_verification_code_returned": False,
        "raw_password_stored": False,
        "workspace_authority": "server_configured",
    }


def _registration_delivery(
    registration: Dict[str, Any],
    *,
    email: str,
    locale: str,
    code: str,
    request_meta: Mapping[str, Any] | None,
    idempotency_key: str,
) -> Dict[str, Any]:
    delivered = _deliver_verification_code(
        email=email,
        code=code,
        registration_id=registration["registration_id"],
        expires_at=registration["expires_at"],
        locale=locale,
        request_meta=request_meta,
        idempotency_key=idempotency_key,
    )
    if delivered.get("ok") is not True:
        store.mark_delivery_failed(registration["registration_id"], dict(request_meta or {}))
        return delivered
    store.mark_delivery_succeeded(registration["registration_id"], dict(request_meta or {}))
    return {"ok": True}


def start_registration(payload: Dict[str, Any] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    request_meta = request_meta or {}
    if not _feature_enabled():
        return _feature_error(request_meta)
    payload = _as_dict(payload)
    workspace_id, workspace_failure = _configured_workspace(request_meta)
    if workspace_failure:
        return workspace_failure
    approved_terms, terms_failure = _approved_terms_version(request_meta)
    if terms_failure:
        return terms_failure
    email = _email(payload.get("email"))
    if not _valid_email(email):
        return error("invalid_email", 400, "Enter a valid email address.", request_meta=request_meta, field="email", next_action="edit_email")
    password = _clean(payload.get("password"), 128)
    if not _password_valid(password):
        return error("weak_password", 400, "Choose a password with at least 12 characters, including a letter and a number.", request_meta=request_meta, field="password", next_action="edit_password")
    terms = _clean(payload.get("accepted_terms_version"), 80)
    if not terms:
        return error("terms_required", 400, "Accept the current LiveUIN terms to continue.", request_meta=request_meta, field="accepted_terms_version", next_action="accept_terms")
    if terms != approved_terms:
        return error("terms_version_not_current", 400, "Accept the current LiveUIN terms to continue.", request_meta=request_meta, field="accepted_terms_version", next_action="accept_terms", approved_terms_version=approved_terms)
    if _clean(payload.get("requested_default_profile") or PUBLIC_PROFILE_KEY, 40).lower() != PUBLIC_PROFILE_KEY:
        return error("default_profile_invalid", 400, "New public accounts start with the Tenant profile.", request_meta=request_meta, field="requested_default_profile", next_action="use_tenant_profile")
    email_hash = _email_hash(email)
    idempotency_hash = store.hash_value(_idempotency_key(payload, request_meta))
    ip = _clean(request_meta.get("ip"), 120)
    existing_by_key = store.get_registration_by_idempotency(idempotency_hash)
    if existing_by_key and existing_by_key.get("workspace_id") == workspace_id:
        if existing_by_key.get("status") == "email_verification_pending":
            return _registration_response(existing_by_key)
    if not store.allow_rate("registration_ip", ip or "unknown", limit=10, window_seconds=3600) or not store.allow_rate("registration_email", email_hash, limit=MAX_RESENDS, window_seconds=RESEND_WINDOW_SECONDS):
        return error("rate_limited", 429, "Too many account attempts. Try again later.", request_meta=request_meta, next_action="try_again_later")
    existing = store.get_account_by_email_hash(email_hash, workspace_id)
    if existing:
        if existing.get("email_verified_at"):
            return error("duplicate_email", 409, "An account already exists for this email.", request_meta=request_meta, field="email", next_action="sign_in")
        registration = store.get_latest_registration_by_email_hash(email_hash, workspace_id)
        if not registration:
            return error("registration_resume_unavailable", 503, "Account creation is temporarily unavailable.", request_meta=request_meta, next_action="try_again_later")
        code = _random_code()
        try:
            password_hash = _password_hash(password)
            registration = store.prepare_registration_delivery(
                registration["registration_id"],
                code_hash=_code_hash(code),
                expires_at=_now() + _verification_ttl(payload, request_meta),
                delivery_mode=_clean(os.getenv("LIVEUIN_IDENTITY_EMAIL_DELIVERY_MODE") or "disabled", 40),
                idempotency_key_hash=idempotency_hash,
                password_hash=password_hash,
                password_hash_version=PASSWORD_HASH_VERSION,
                accepted_terms_version=terms,
            )
            delivered = _registration_delivery(
                registration,
                email=email,
                locale=existing.get("locale", ""),
                code=code,
                request_meta=request_meta,
                idempotency_key=_idempotency_key(payload, request_meta),
            )
            return _registration_response(registration) if delivered.get("ok") is True else delivered
        except RuntimeError as exc:
            if str(exc) in {"bcrypt_dependency_missing", "verification_pepper_missing"}:
                return error("identity_security_not_ready", 503, "Account creation is temporarily unavailable.", request_meta=request_meta, next_action="try_again_later")
            return internal_error(request_meta)
    if bcrypt is None:
        return error("password_hasher_unavailable", 503, "Account creation is temporarily unavailable.", request_meta=request_meta, next_action="try_again_later")
    try:
        password_hash = _password_hash(password)
        email_provider_subject_hash = _email_subject_identifier(email)
        code = _random_code()
        registration_id = "reg_" + uuid.uuid4().hex[:20]
        account_id = "acct_" + uuid.uuid4().hex[:20]
        now = _now()
        account = store.create_account_registration(
            account={
                "account_id": account_id, "workspace_id": workspace_id, "email_hash": email_hash,
                "email_provider_subject_hash": email_provider_subject_hash, "email_hint": _email_hint(email),
                "person_id": "", "status": "email_verification_pending", "profile_completion_state": "incomplete",
                "tenant_entitlement_state": "not_issued", "localpro_application_state": "not_started", "localpro_authorization_state": "not_issued",
                "accepted_terms_version": terms, "locale": _clean(payload.get("locale"), 20), "display_name": "",
                "password_hash": password_hash, "password_hash_version": PASSWORD_HASH_VERSION, "created_at": now, "updated_at": now,
            },
            registration={
                "registration_id": registration_id, "account_id": account_id, "workspace_id": workspace_id, "email_hash": email_hash,
                "verification_code_hash": _code_hash(code), "status": "email_verification_pending", "max_attempts": 5,
                "issued_at": now, "expires_at": now + _verification_ttl(payload, request_meta),
                "delivery_mode": _clean(os.getenv("LIVEUIN_IDENTITY_EMAIL_DELIVERY_MODE") or "disabled", 40),
                "idempotency_key_hash": idempotency_hash, "created_at": now, "updated_at": now,
            },
            request_meta=dict(request_meta),
        )
        registration = store.get_registration(registration_id)
        delivered = _registration_delivery(
            registration,
            email=email,
            locale=account.get("locale", ""),
            code=code,
            request_meta=request_meta,
            idempotency_key=_idempotency_key(payload, request_meta),
        )
        return _registration_response(registration) if delivered.get("ok") is True else delivered
    except RuntimeError as exc:
        if str(exc) in {"bcrypt_dependency_missing", "verification_pepper_missing", "email_provider_pepper_missing"}:
            return error("identity_security_not_ready", 503, "Account creation is temporarily unavailable.", request_meta=request_meta, next_action="try_again_later")
        return internal_error(request_meta)
    except Exception:
        return internal_error(request_meta)


def verify_registration(registration_id: str, payload: Dict[str, Any] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    request_meta = request_meta or {}
    if not _feature_enabled():
        return _feature_error(request_meta)
    workspace_id, workspace_failure = _configured_workspace(request_meta)
    if workspace_failure:
        return workspace_failure
    registration = store.get_registration(registration_id)
    if not registration:
        return error("registration_not_found", 404, "That registration could not be found.", request_meta=request_meta, next_action="start_registration")
    if registration.get("workspace_id") != workspace_id:
        return error("registration_not_found", 404, "That registration could not be found.", request_meta=request_meta, next_action="start_registration")
    if registration.get("status") == "locked":
        return error("verification_locked", 423, "Too many verification attempts. Start again.", request_meta=request_meta, next_action="start_registration")
    if registration.get("status") != "email_verification_pending":
        return error("verification_not_pending", 409, "That verification is no longer pending.", request_meta=request_meta, next_action="sign_in")
    if registration.get("expires_at", 0) <= _now():
        store.mark_verification_attempt(registration_id, success=False, lock=True, request_meta=dict(request_meta))
        return error("verification_expired", 410, "That verification code has expired. Start again.", request_meta=request_meta, next_action="start_registration")
    code = _clean(_as_dict(payload).get("verification_code") or _as_dict(payload).get("code"), 32)
    if not code or not hmac.compare_digest(_code_hash(code), registration.get("verification_code_hash", "")):
        next_attempts = int(registration.get("attempts") or 0) + 1
        locked = next_attempts >= int(registration.get("max_attempts") or 5)
        store.mark_verification_attempt(registration_id, success=False, lock=locked, request_meta=dict(request_meta))
        return error("invalid_verification_code", 403, "That verification code is not valid.", request_meta=request_meta, next_action="enter_verification_code")
    verified = store.mark_verification_attempt(registration_id, success=True, request_meta=dict(request_meta))
    account = store.get_account(verified.get("account_id"))
    if not account:
        return internal_error(request_meta)
    provider_subject = _clean(account.get("email_provider_subject_hash"), 128)
    if not provider_subject:
        store.rollback_verified_registration(registration_id, dict(request_meta))
        return error("identity_security_not_ready", 503, "Account verification is temporarily unavailable.", request_meta=request_meta, next_action="try_again_later")
    link = identity_svc.link_identity(
        {
            "workspace_id": workspace_id,
            "provider": "email_hash",
            "provider_user_id": provider_subject,
            "verified_state": "verified",
            "person": {"display_name": account.get("display_name", ""), "locale": account.get("locale", ""), "role_flags": ["tenant"], "contacts": {"email_hash": account.get("email_hash", "")}},
            "consent": {"accepted": True, "status": "accepted", "scope": "public_registration_terms", "version": account.get("accepted_terms_version", ""), "source": "liveuin_public_registration"},
            "metadata": {"source": "public_registration", "raw_email_stored": False, "email_delivery_storage": "approved_delivery_service_or_ephemeral_test_sink"},
        },
        dict(request_meta),
    )
    if link.get("ok") is not True:
        store.rollback_verified_registration(registration_id, dict(request_meta))
        return error("identity_unavailable", 503, "Account verification is temporarily unavailable.", request_meta=request_meta, next_action="try_again_later")
    person_id = _clean_id(link.get("person_id"))
    identity_link = _as_dict(link.get("identity_link"))
    try:
        bound = store.bind_verified_person(account["account_id"], person_id, dict(request_meta))
        if not bound or bound.get("person_id") != person_id:
            raise RuntimeError("public_account_bind_failed")
        session = _issue_session(bound, request_meta, "public_email_registration")
        if session.get("ok") is False:
            raise RuntimeError("public_session_issue_failed")
    except Exception:
        if identity_link.get("identity_link_id"):
            identity_store.delete_link(identity_link["identity_link_id"], workspace_id)
            identity_store.delete_person_if_unreferenced(person_id, workspace_id)
        store.rollback_verified_registration(registration_id, dict(request_meta))
        return internal_error(request_meta)
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "authenticated",
        "canonical_owner": "LiveUIN Identity",
        "profile_state": "incomplete",
        "next_action": "complete_profile",
        "authorized_profiles": [],
        **session,
        "raw_verification_code_returned": False,
    }


def resend_registration(registration_id: str, payload: Dict[str, Any] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    request_meta = request_meta or {}
    if not _feature_enabled():
        return _feature_error(request_meta)
    workspace_id, workspace_failure = _configured_workspace(request_meta)
    if workspace_failure:
        return workspace_failure
    payload = _as_dict(payload)
    registration = store.get_registration(registration_id)
    if not registration or registration.get("workspace_id") != workspace_id:
        return error("registration_not_found", 404, "That registration could not be found.", request_meta=request_meta, next_action="start_registration")
    if registration.get("status") not in {"email_verification_pending", "delivery_failed"}:
        return error("verification_not_pending", 409, "That verification is no longer pending.", request_meta=request_meta, next_action="sign_in")
    if not store.allow_rate("verification_resend", registration_id, limit=MAX_RESENDS, window_seconds=RESEND_WINDOW_SECONDS):
        return error("rate_limited", 429, "Too many verification attempts. Try again later.", request_meta=request_meta, next_action="try_again_later")
    email = _email(payload.get("email"))
    if not _valid_email(email) or _email_hash(email) != registration.get("email_hash"):
        return error("registration_not_found", 404, "That registration could not be found.", request_meta=request_meta, next_action="start_registration")
    code = _random_code()
    updated = store.prepare_registration_delivery(
        registration_id,
        code_hash=_code_hash(code),
        expires_at=_now() + DEFAULT_REGISTRATION_TTL_SECONDS,
        delivery_mode=_clean(os.getenv("LIVEUIN_IDENTITY_EMAIL_DELIVERY_MODE") or "disabled", 40),
        idempotency_key_hash=store.hash_value(_idempotency_key(payload, request_meta)),
    )
    delivered = _registration_delivery(
        updated,
        email=email,
        locale="",
        code=code,
        request_meta=request_meta,
        idempotency_key=_idempotency_key(payload, request_meta),
    )
    return _registration_response(updated) if delivered.get("ok") is True else delivered


def password_sign_in(payload: Dict[str, Any] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    request_meta = request_meta or {}
    payload = _as_dict(payload)
    workspace_id, workspace_failure = _configured_workspace(request_meta)
    if workspace_failure:
        return workspace_failure
    email = _email(payload.get("email"))
    password = _clean(payload.get("password"), 128)
    if not _valid_email(email):
        return error("invalid_email", 400, "Enter a valid email address.", request_meta=request_meta, field="email", next_action="edit_email")
    if not password:
        return error("credentials_required", 400, "Enter your email and password.", request_meta=request_meta, field="password", next_action="edit_password")
    email_hash = _email_hash(email)
    ip = _clean(request_meta.get("ip"), 120)
    if not store.allow_rate("sign_in_ip", ip or "unknown", limit=30, window_seconds=900) or not store.allow_rate("sign_in_email", email_hash, limit=12, window_seconds=900):
        return error("rate_limited", 429, "Too many sign-in attempts. Try again later.", request_meta=request_meta, next_action="try_again_later")
    account = store.get_account_by_email_hash(email_hash, workspace_id)
    if not account or not _password_matches(password, account.get("password_hash", "")):
        return error("invalid_credentials", 401, "We could not verify those credentials.", request_meta=request_meta, recoverable=True, next_action="check_credentials_or_recover")
    state = _state(account)
    if state == "email_verification_pending":
        return error("email_unverified", 403, "Verify your email before signing in.", request_meta=request_meta, next_action="verify_email")
    if state in {"account_disabled", "deletion_pending", "account_deleted"}:
        return error("account_unavailable", 403, "This account is not available.", request_meta=request_meta, next_action="contact_support")
    session = _issue_session(account, request_meta, "public_password")
    if session.get("ok") is False:
        return session
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "authenticated",
        "canonical_owner": "LiveUIN Identity",
        "profile_state": _state(account),
        "next_action": _next_action(account),
        "authorized_profiles": _public_profile_entitlements(account),
        **session,
    }


def founder_qa_access(payload: Dict[str, Any] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    """Issue a real Tenant session for the server-controlled staging QA lane."""
    request_meta = request_meta or {}
    payload = _as_dict(payload)
    environment = str(os.getenv("LIVEUIN_ENVIRONMENT") or os.getenv("ENVIRONMENT") or "").strip().lower()
    if environment != "staging" or not _bool_env(FOUNDER_QA_ACCESS_ENABLED_ENV, False):
        return error("founder_qa_unavailable", 404, "Founder QA access is not available.", request_meta=request_meta, next_action="sign_in")
    if _clean(payload.get("lane"), 40) != "resident-app" or _clean(payload.get("build_profile"), 40) != "staging_e2e":
        return error("founder_qa_lane_invalid", 403, "This QA access lane is not valid for this build.", request_meta=request_meta, next_action="sign_in")

    configured_hash = _clean(os.getenv(FOUNDER_QA_ACCESS_CODE_HASH_ENV), 128).lower()
    access_code = _clean(payload.get("access_code"), 240)
    ip = _clean(request_meta.get("ip"), 120) or "unknown"
    if not store.allow_rate("founder_qa_access_ip", ip, limit=12, window_seconds=900):
        return error("founder_qa_rate_limited", 429, "Too many QA access attempts. Try again later.", request_meta=request_meta, next_action="try_again_later")
    if not configured_hash or not access_code or not hmac.compare_digest(store.hash_value(access_code), configured_hash):
        return error("founder_qa_access_denied", 403, "Founder QA access could not be verified.", request_meta=request_meta, next_action="sign_in")

    workspace_id, workspace_failure = _configured_workspace(request_meta)
    if workspace_failure:
        return workspace_failure
    terms_version, terms_failure = _approved_terms_version(request_meta)
    if terms_failure:
        return terms_failure
    account_id = _clean_id(os.getenv(FOUNDER_QA_ACCOUNT_ID_ENV) or FOUNDER_QA_DEFAULT_ACCOUNT_ID, 96)
    person_id = _clean_id(os.getenv(FOUNDER_QA_PERSON_ID_ENV) or FOUNDER_QA_DEFAULT_PERSON_ID, 96)
    if not account_id.startswith("acct_founder_qa_") or not person_id.startswith("per_founder_qa_"):
        return error("founder_qa_identity_misconfigured", 503, "Founder QA access is temporarily unavailable.", request_meta=request_meta, recoverable=False, next_action="contact_support")

    display_name = _clean(os.getenv(FOUNDER_QA_DISPLAY_NAME_ENV) or "LiveUIN QA Tenant", 160)
    synthetic_key = f"founder-qa:{workspace_id}:{account_id}"
    subject_hash = store.hash_value(f"founder-qa-provider:{workspace_id}:{account_id}")
    account = store.ensure_founder_qa_account(
        {
            "account_id": account_id,
            "workspace_id": workspace_id,
            "person_id": person_id,
            "email_hash": store.hash_value(synthetic_key),
            "email_provider_subject_hash": subject_hash,
            "email_hint": "founder-qa@staging.invalid",
            "accepted_terms_version": terms_version,
            "locale": "en",
            "display_name": display_name,
        },
        {
            "provider_identity_id": "pvid_founder_qa_resident",
            "workspace_id": workspace_id,
            "provider": "founder_qa",
            "subject_hash": subject_hash,
            "subject_hint": "founder-qa",
            "account_id": account_id,
            "person_id": person_id,
            "verified_email_hash": "",
        },
        dict(request_meta),
    )
    if not account:
        return error("founder_qa_identity_conflict", 409, "The staging QA identity is not in a safe state.", request_meta=request_meta, recoverable=False, next_action="contact_support")

    existing_link = identity_store.find_link(
        workspace_id=workspace_id,
        provider="liveuin_user",
        provider_subject_hash=hashlib.sha256(account_id.encode("utf-8")).hexdigest(),
    )
    if existing_link and existing_link.get("person_id") != person_id:
        return error("founder_qa_identity_conflict", 409, "The staging QA identity is not in a safe state.", request_meta=request_meta, recoverable=False, next_action="contact_support")
    with identity_store.connection() as conn:
        cross_workspace_person = conn.execute(
            "SELECT workspace_id FROM identity_persons WHERE person_id = ? LIMIT 1",
            (person_id,),
        ).fetchone()
    if cross_workspace_person and str(cross_workspace_person[0]) != workspace_id:
        return error("founder_qa_identity_conflict", 409, "The staging QA identity is not in a safe state.", request_meta=request_meta, recoverable=False, next_action="contact_support")

    person = identity_store.get_person(person_id, workspace_id)
    if not person or not existing_link:
        linked = identity_svc.link_identity(
            {
                "workspace_id": workspace_id,
                "provider": "liveuin_user",
                "provider_user_id": account_id,
                "person_id": person_id,
                "verified_state": "verified",
                "person": {"display_name": display_name, "locale": "en", "role_flags": ["tenant"], "contacts": {}},
                "consent": {"accepted": True, "status": "accepted", "scope": "founder_qa_staging", "version": terms_version, "source": "liveuin_founder_qa"},
                "metadata": {"source": "founder_qa_access", "staging_only": True, "raw_identifier_stored": False},
                "surface": "resident_app_founder_qa",
                "channel": "resident_app",
            },
            dict(request_meta),
        )
        if linked.get("ok") is not True or _clean_id(linked.get("person_id")) != person_id:
            return error("founder_qa_identity_unavailable", 503, "Founder QA access is temporarily unavailable.", request_meta=request_meta, next_action="try_again_later")
        person = identity_store.get_person(person_id, workspace_id)
    else:
        roles = list(dict.fromkeys([str(role) for role in (person.get("role_flags") or [])] + ["tenant"]))
        person = identity_store.upsert_person({
            **person,
            "display_name": display_name,
            "locale": "en",
            "role_flags": roles,
            "consent_state": "accepted",
            "metadata": {**_as_dict(person.get("metadata")), "founder_qa_staging": True},
        })
    if not person:
        return error("founder_qa_identity_unavailable", 503, "Founder QA access is temporarily unavailable.", request_meta=request_meta, next_action="try_again_later")

    identity_store.upsert_profile_entitlement(
        {
            "entitlement_id": "ent_founder_qa_tenant_" + account_id,
            "workspace_id": workspace_id,
            "account_id": account_id,
            "person_id": person_id,
            "profile_key": PUBLIC_PROFILE_KEY,
            "subject_id": person_id,
            "subject_role": "tenant",
            "status": "active",
            "permissions": ["tenant"],
            "route_restrictions": [],
            "is_default": True,
            "metadata": {"source": "founder_qa_access", "staging_only": True, "localpro_authorization_issued": False},
        }
    )
    revoked = identity_session.revoke_active_workspace_sessions(
        workspace_id,
        actor_ids=[person_id],
        reason="founder_qa_reauthentication",
        request_meta=dict(request_meta),
    )
    if revoked.get("ok") is False:
        return error("founder_qa_identity_unavailable", 503, "Founder QA access is temporarily unavailable.", request_meta=request_meta, next_action="try_again_later")
    store.revoke_refresh_for_account(account_id, "founder_qa_reauthentication")
    current = store.get_account(account_id)
    profiles = _public_profile_entitlements(current)
    if len(profiles) != 1 or profiles[0].get("profile_key") != PUBLIC_PROFILE_KEY or profiles[0].get("workspace_id") != workspace_id:
        return error("founder_qa_identity_unavailable", 503, "Founder QA access is temporarily unavailable.", request_meta=request_meta, next_action="try_again_later")
    session = _issue_session(current, request_meta, "founder_qa_access")
    if session.get("ok") is False:
        return session
    store.append_audit_event(
        account_id=account_id,
        workspace_id=workspace_id,
        event_type="identity.public.founder_qa_session_issued",
        payload={"staging_only": True, "lane": "resident-app", "localpro_authorization_issued": False},
        request_meta=dict(request_meta),
    )
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "authenticated",
        "canonical_owner": "LiveUIN Identity",
        "profile_state": "tenant_active",
        "next_action": "tenant_home",
        "display_name": display_name,
        "provider": "liveuin_user",
        "provider_linked": True,
        "founder_qa": True,
        "founder_qa_lane": "resident-app",
        "founder_qa_account_id": account_id,
        "authorized_profiles": profiles,
        **session,
    }


def password_reset_request(payload: Dict[str, Any] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    request_meta = request_meta or {}
    workspace_id, workspace_failure = _configured_workspace(request_meta)
    if workspace_failure:
        return workspace_failure
    payload = _as_dict(payload)
    ip = _clean(request_meta.get("ip"), 120)
    email = _email(payload.get("email"))
    idempotency_key = _idempotency_key(payload, request_meta)
    idempotency_hash = store.hash_value(idempotency_key)
    existing = store.get_password_reset_by_idempotency(idempotency_hash, workspace_id)
    if existing:
        return _recovery_request_response(existing, request_meta)

    valid_email = _valid_email(email)
    email_hash = _email_hash(email)
    account = store.get_account_by_email_hash(email_hash, workspace_id) if valid_email else {}
    account_eligible = bool(
        account
        and account.get("email_verified_at")
        and _state(account) not in {"account_disabled", "deletion_pending", "account_deleted"}
    )
    rate_allowed = (
        store.allow_rate("password_reset_ip", ip or "unknown", limit=12, window_seconds=3600)
        and store.allow_rate("password_reset_recipient", email_hash, limit=6, window_seconds=3600)
    )
    reset_id = _random_reset_id()
    expires_at = _now() + DEFAULT_RECOVERY_TTL_SECONDS
    code = _random_code()
    reset = store.create_password_reset(
        {
            "reset_id": reset_id,
            "account_id": account["account_id"] if account_eligible and rate_allowed else None,
            "workspace_id": workspace_id,
            "email_hash": account.get("email_hash") if account_eligible else email_hash,
            "verification_code_hash": _code_hash(code),
            "expires_at": expires_at,
            "idempotency_key_hash": idempotency_hash,
            "delivery_mode": _clean(os.getenv("LIVEUIN_IDENTITY_EMAIL_DELIVERY_MODE") or "disabled", 40),
        },
        dict(request_meta),
    )
    if reset.get("reset_id") != reset_id:
        return _recovery_request_response(reset, request_meta)

    if account_eligible and rate_allowed:
        store.supersede_password_resets_for_account(account["account_id"], workspace_id, reset_id, dict(request_meta))
        delivered = _deliver_verification_code(
            email=email,
            code=code,
            registration_id=reset_id,
            expires_at=reset["expires_at"],
            locale=account.get("locale", ""),
            request_meta=request_meta,
            idempotency_key=idempotency_key,
            template="liveuin_identity_password_reset",
        )
        if delivered.get("ok") is not True:
            store.mark_password_reset_delivery_failed(reset_id, dict(request_meta))
    return _recovery_request_response(store.get_password_reset(reset_id, workspace_id), request_meta)


def password_reset_verify(reset_id: str, payload: Dict[str, Any] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    request_meta = request_meta or {}
    workspace_id, workspace_failure = _configured_workspace(request_meta)
    if workspace_failure or not _valid_reset_id(reset_id):
        return _recovery_failure(request_meta) if not workspace_failure else workspace_failure
    reset = store.get_password_reset(reset_id, workspace_id)
    if not reset or reset.get("status") != "verification_pending" or reset.get("expires_at", 0) <= _now():
        return _recovery_failure(request_meta)
    code = _clean(_as_dict(payload).get("verification_code") or _as_dict(payload).get("code"), 32)
    if not code or not hmac.compare_digest(_code_hash(code), reset.get("verification_code_hash", "")):
        store.mark_password_reset_attempt(reset_id, success=False, workspace_id=workspace_id, request_meta=dict(request_meta))
        return _recovery_failure(request_meta)
    token = _random_token("lurp_")
    verified = store.mark_password_reset_attempt(reset_id, success=True, reset_token_hash=store.hash_value(token), workspace_id=workspace_id, request_meta=dict(request_meta))
    if verified.get("status") != "verified" or verified.get("claim_won") is not True:
        return _recovery_failure(request_meta)
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "recovery_verified",
        "reset_token": token,
        "raw_secret_returned_once": True,
        "raw_secret_stored": False,
        "request_id": _request_id(request_meta),
    }


def password_reset_complete(payload: Dict[str, Any] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    request_meta = request_meta or {}
    workspace_id, workspace_failure = _configured_workspace(request_meta)
    if workspace_failure:
        return workspace_failure
    payload = _as_dict(payload)
    token = _clean(payload.get("reset_token"), 400)
    password = _clean(payload.get("new_password"), 128)
    if not _password_valid(password):
        return error("weak_password", 400, "Choose a password with at least 12 characters, including a letter and a number.", request_meta=request_meta, field="new_password", next_action="edit_password")
    reset = store.get_password_reset_by_token_hash(store.hash_value(token), workspace_id)
    if not token or not reset:
        return _recovery_failure(request_meta)
    account = store.get_account(reset.get("account_id", ""))
    if not account:
        return _recovery_failure(request_meta)
    completed = store.complete_password_reset(store.hash_value(token), _password_hash(password), PASSWORD_HASH_VERSION, workspace_id, dict(request_meta))
    if not completed:
        return _recovery_failure(request_meta)
    store.revoke_refresh_for_account(account["account_id"], "password_reset")
    if account.get("person_id"):
        identity_session.revoke_active_workspace_sessions(account.get("workspace_id", ""), actor_ids=[account["person_id"]], reason="password_reset", request_meta=dict(request_meta))
    return {"ok": True, "schema_version": SCHEMA_VERSION, "phase": PHASE, "status": "password_reset_completed", "next_action": "sign_in", "request_id": _request_id(request_meta)}


def onboarding_status(headers: Mapping[str, str] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    account, failure = _session_account(headers, request_meta)
    if failure:
        return failure
    return {"ok": True, "schema_version": SCHEMA_VERSION, "phase": PHASE, "status": "onboarding_status", "canonical_owner": "LiveUIN Identity", **_account_payload(account)}


def update_profile(headers: Mapping[str, str] | None, payload: Dict[str, Any] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    account, failure = _session_account(headers, request_meta)
    if failure:
        return failure
    payload = _as_dict(payload)
    allowed = {"display_name", "locale"}
    unexpected = sorted(set(payload) - allowed)
    if unexpected:
        return error("invalid_profile_fields", 400, "Only approved profile fields may be updated.", request_meta=request_meta, next_action="edit_profile", fields=unexpected)
    display_name = _clean(payload.get("display_name") or account.get("display_name"), 160)
    locale = _clean(payload.get("locale") or account.get("locale") or "en", 20)
    if len(display_name) < 2:
        return error("profile_incomplete", 409, "Add your name to continue.", request_meta=request_meta, field="display_name", next_action="complete_profile")
    updated = store.update_account(account["account_id"], {"display_name": display_name, "locale": locale, "profile_completion_state": "complete", "status": "profile_incomplete"}, dict(request_meta or {}))
    person = identity_store.get_person(account.get("person_id", ""), account.get("workspace_id", ""))
    if person:
        roles = list(dict.fromkeys([str(role) for role in (person.get("role_flags") or [])] + ["tenant"]))
        identity_store.upsert_person({**person, "display_name": display_name, "locale": locale, "role_flags": roles, "metadata": {**_as_dict(person.get("metadata")), "public_profile_complete": True}})
    return {"ok": True, "schema_version": SCHEMA_VERSION, "phase": PHASE, "status": "profile_incomplete", "profile_state": "complete", "next_action": "complete_onboarding", "display_name": updated.get("display_name", ""), "locale": updated.get("locale", "")}


def complete_onboarding(headers: Mapping[str, str] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    account, failure = _session_account(headers, request_meta)
    if failure:
        return failure
    if account.get("profile_completion_state") != "complete":
        return error("profile_incomplete", 409, "Complete your profile before continuing.", request_meta=request_meta, next_action="complete_profile")
    if account.get("tenant_entitlement_state") != "active":
        store.update_account(account["account_id"], {"status": "tenant_active", "tenant_entitlement_state": "active", "localpro_application_state": "not_started", "localpro_authorization_state": "not_issued"}, dict(request_meta or {}))
        identity_store.upsert_profile_entitlement(
            {
                "entitlement_id": "ent_tenant_" + account["account_id"],
                "workspace_id": account.get("workspace_id") or "",
                "account_id": account.get("account_id"),
                "person_id": account.get("person_id"),
                "profile_key": "tenant",
                "subject_id": account.get("person_id"),
                "subject_role": "tenant",
                "status": "active",
                "permissions": ["tenant"],
                "route_restrictions": [],
                "is_default": True,
                "metadata": {"source": "public_onboarding", "localpro_authorization_issued": False},
            }
        )
        person = identity_store.get_person(account.get("person_id", ""), account.get("workspace_id", ""))
        if person:
            roles = list(dict.fromkeys([str(role) for role in (person.get("role_flags") or [])] + ["tenant"]))
            identity_store.upsert_person({**person, "role_flags": roles, "consent_state": "accepted", "metadata": {**_as_dict(person.get("metadata")), "public_onboarding_completed": True}})
        store.append_audit_event(account_id=account["account_id"], workspace_id=account.get("workspace_id") or "", event_type="identity.public.tenant_onboarding_completed", payload={"default_profile": "tenant", "localpro_authorization": "not_issued"}, request_meta=dict(request_meta or {}))
    current = store.get_account(account["account_id"])
    old_session_id = _clean((headers or {}).get("X-LiveUIN-Session-Id") or (headers or {}).get("x-liveuin-session-id"), 240)
    session = _issue_session(current, request_meta, "public_tenant_onboarding")
    if session.get("ok") is False:
        return session
    if old_session_id:
        identity_session.revoke_session({"session_id": old_session_id, "reason": "onboarding_session_rotation"}, dict(request_meta or {}))
        store.revoke_refresh_for_session(store.hash_value(old_session_id), "onboarding_session_rotation")
    return {"ok": True, "schema_version": SCHEMA_VERSION, "phase": PHASE, "status": "tenant_active", "profile_state": "tenant_active", "next_action": "tenant_home", "authorized_profiles": _public_profile_entitlements(current), **session, "localpro_authorization_issued": False}


def refresh_session(payload: Dict[str, Any] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    request_meta = request_meta or {}
    configured_workspace, workspace_failure = _configured_workspace(request_meta)
    if workspace_failure:
        return workspace_failure
    refresh_token = _clean(_as_dict(payload).get("refresh_token"), 400)
    if not refresh_token:
        return error("refresh_token_required", 400, "A refresh credential is required.", request_meta=request_meta, next_action="sign_in")
    old_hash = store.hash_value(refresh_token)
    old = store.get_refresh_by_hash(old_hash)
    if not old or old.get("status") != "active":
        return error("session_refresh_invalid", 401, "Your session has expired. Sign in again.", request_meta=request_meta, next_action="sign_in")
    if old.get("expires_at", 0) <= _now():
        return error("session_refresh_expired", 401, "Your session has expired. Sign in again.", request_meta=request_meta, next_action="sign_in")
    account = store.get_account(old.get("account_id", ""))
    if not account or _state(account) in {"account_disabled", "deletion_pending", "account_deleted"}:
        return error("account_unavailable", 403, "This account is not available.", request_meta=request_meta, next_action="contact_support")
    if account.get("workspace_id") != configured_workspace or old.get("workspace_id") != configured_workspace:
        return error("session_workspace_mismatch", 403, "This session is not valid for the public identity workspace.", request_meta=request_meta, next_action="sign_in")
    session = _issue_session(account, request_meta, "public_session_refresh", persist_refresh=False)
    if session.get("ok") is False:
        return session
    new_hash = store.hash_value(session.get("refresh_token"))
    new_session_headers = _as_dict(session.get("one_time_credential")).get("session_headers") or {}
    new_session_id = _clean(new_session_headers.get("X-LiveUIN-Session-Id") or new_session_headers.get("x-liveuin-session-id"), 240)
    rotation = store.rotate_refresh_atomic(
        old_hash,
        new_hash,
        session_id_hash=store.hash_value(new_session_id),
        issued_at=_now(),
        expires_at=int(session.get("refresh_expires_at") or (_now() + DEFAULT_REFRESH_TTL_SECONDS)),
        request_meta=dict(request_meta),
    )
    if not rotation.get("ok"):
        if new_session_id:
            identity_session.revoke_session({"session_id": new_session_id, "reason": "refresh_race_lost"}, dict(request_meta))
        return error("session_refresh_replay", 401, "Your session has expired. Sign in again.", request_meta=request_meta, next_action="sign_in")
    identity_session.revoke_session({"session_id_hash": old.get("session_id_hash"), "reason": "refresh_rotation"}, dict(request_meta))
    return {"ok": True, "schema_version": SCHEMA_VERSION, "phase": PHASE, "status": "session_refreshed", "profile_state": _state(account), "next_action": _next_action(account), "authorized_profiles": _public_profile_entitlements(account), **session}


def revoke_current_session(headers: Mapping[str, str] | None) -> int:
    values = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    session_id = values.get("x-liveuin-session-id", "")
    return store.revoke_refresh_for_session(store.hash_value(session_id), "logout") if session_id else 0
