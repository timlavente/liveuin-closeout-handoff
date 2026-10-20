from __future__ import annotations

import os
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

try:
    from . import core_identity_google_oauth as google_oauth
    from . import core_adapter_secret_registry as secret_registry
except ImportError:  # pragma: no cover - supports direct script execution.
    import core_identity_google_oauth as google_oauth
    import core_adapter_secret_registry as secret_registry


SCHEMA_VERSION = "liveuin-core-identity-auth-policy-v1"
PHASE = "phase31-identity-auth-policy-preview"
DEFAULT_WORKSPACE_ID = "laijuzhu"
CANONICAL_OWNER = "LiveUIN Identity"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "ready", "enabled"}


_PLACEHOLDER_FRAGMENTS = {
    "change_me",
    "changeme",
    "dummy",
    "example",
    "fake",
    "placeholder",
    "replace",
    "sample",
    "test_secret",
    "todo",
    "your_",
}


def _env_any(names: List[str]) -> str:
    for name in names:
        value = str(os.getenv(name) or "").strip()

        if value:
            return value

    return ""


def _env_bool_any(names: List[str], default: bool = False) -> bool:
    saw_value = False

    for name in names:
        raw = str(os.getenv(name) or "").strip()

        if raw:
            saw_value = True

        if _env_bool(name, False):
            return True

    return default if not saw_value else False


def _placeholder(value: Any) -> bool:
    text = str(value or "").strip().lower()

    if not text:
        return False

    normalized = re.sub(r"[^a-z0-9]+", "_", text)
    return any(fragment in normalized for fragment in _PLACEHOLDER_FRAGMENTS)


def _real_value(value: Any, min_length: int = 1) -> bool:
    text = str(value or "").strip()
    return bool(len(text) >= min_length and not _placeholder(text))


def _website_qr_redirect_ready(value: Any) -> bool:
    parsed = urlparse(str(value or "").strip())
    return bool(
        parsed.scheme == "https"
        and parsed.netloc
        and parsed.path.rstrip("/") == "/api/ops/auth/wechat/website-qr/callback"
    )


def _website_qr_secret_ready(secret_ref: str, purpose: str, workspace_id: str) -> bool:
    if not _real_value(secret_ref, 8):
        return False
    resolved = secret_registry.resolve_secret_reference(
        workspace_id=workspace_id,
        provider="wechat_identity",
        purpose=purpose,
        secret_ref_id=secret_ref,
        request_meta={"source": "identity_auth_policy_status"},
    )
    return bool(
        resolved.get("ok") is True
        and _real_value(resolved.get("secret"), 24)
        and resolved.get("secret_context", {}).get("secret_source") == "registered_systemd_credential"
    )


def _website_qr_runtime_status(workspace_id: str = DEFAULT_WORKSPACE_ID) -> Dict[str, Any]:
    workspace_id = _clean_workspace(workspace_id)
    enabled_requested = _env_bool_any(["LIVEUIN_WECHAT_WEBSITE_QR_READY", "WECHAT_WEBSITE_QR_ENABLED"], False)
    configured_requested = _env_bool_any(["LIVEUIN_WECHAT_WEBSITE_QR_CONFIGURED", "WECHAT_WEBSITE_QR_ENABLED"], False)
    app_id = _env_any(["WECHAT_WEBSITE_APP_ID", "LIVEUIN_WECHAT_WEBSITE_APP_ID"])
    raw_app_secret = _env_any(["WECHAT_WEBSITE_APP_SECRET", "LIVEUIN_WECHAT_WEBSITE_APP_SECRET"])
    app_secret_ref = _env_any(["WECHAT_WEBSITE_APP_SECRET_REF", "LIVEUIN_WECHAT_WEBSITE_APP_SECRET_REF"])
    redirect_uri = _env_any(["WECHAT_WEBSITE_REDIRECT_URI", "LIVEUIN_WECHAT_WEBSITE_REDIRECT_URI"])
    raw_state_secret = _env_any(["WECHAT_WEBSITE_STATE_SECRET", "LIVEUIN_WECHAT_WEBSITE_STATE_SECRET"])
    state_secret_ref = _env_any(["WECHAT_WEBSITE_STATE_SECRET_REF", "LIVEUIN_WECHAT_WEBSITE_STATE_SECRET_REF"])
    app_id_ready = bool(_real_value(app_id, 10) and re.fullmatch(r"wx[A-Za-z0-9]{10,64}", app_id))
    app_secret_ready = _website_qr_secret_ready(
        app_secret_ref,
        "wechat_website_app_secret",
        workspace_id,
    )
    redirect_ready = _website_qr_redirect_ready(redirect_uri)
    state_secret_ready = _website_qr_secret_ready(
        state_secret_ref,
        "wechat_website_state_secret",
        workspace_id,
    )
    configured = bool(
        enabled_requested
        and configured_requested
        and app_id_ready
        and redirect_ready
        and _real_value(app_secret_ref, 8)
        and _real_value(state_secret_ref, 8)
    )
    ready = bool(
        enabled_requested
        and configured_requested
        and app_id_ready
        and app_secret_ready
        and redirect_ready
        and state_secret_ready
        and not raw_app_secret
        and not raw_state_secret
    )
    gaps = []

    if not ready:
        if not enabled_requested:
            gaps.append("website_qr_disabled")
        if not configured_requested:
            gaps.append("website_qr_not_marked_configured")
        if not app_id_ready:
            gaps.append("website_app_id_missing_or_placeholder")
        if not app_secret_ready:
            gaps.append("website_app_secret_reference_unresolved")
        if raw_app_secret:
            gaps.append("website_app_secret_raw_env_forbidden")
        if not redirect_ready:
            gaps.append("website_redirect_uri_invalid")
        if not state_secret_ready:
            gaps.append("website_state_secret_reference_unresolved")
        if raw_state_secret:
            gaps.append("website_state_secret_raw_env_forbidden")

    return {
        "ready": ready,
        "configured": configured,
        "gaps": gaps,
    }


def _clean_workspace(value: Any) -> str:
    text = str(value or "").strip()
    cleaned = "".join(ch for ch in text if ch.isalnum() or ch in {"_", "-", ".", ":"})
    return cleaned[:96] or DEFAULT_WORKSPACE_ID


def provider_readiness(workspace_id: str = DEFAULT_WORKSPACE_ID) -> Dict[str, Any]:
    workspace_id = _clean_workspace(workspace_id)
    website_qr = _website_qr_runtime_status(workspace_id)
    google = google_oauth.google_oauth_status(workspace_id=workspace_id)
    google_provider = google.get("provider_readiness", {})
    return {
        "workspace_id": workspace_id,
        "google_ready": bool(google.get("ready")),
        "google_enabled": bool(google_provider.get("google_enabled")),
        "google_configured": bool(google_provider.get("google_configured")),
        "google_token_exchange_ready": bool(google_provider.get("token_exchange_ready")),
        "google_callback_validation_ready": bool(google_provider.get("callback_validation_ready")),
        "google_session_signing_ready": bool(google_provider.get("session_signing_ready")),
        "google_account_policy_ready": bool(google_provider.get("account_policy_ready")),
        "google_workspace_access_ready": bool(google_provider.get("workspace_access_ready")),
        "google_secret_runtime_ready": bool(google.get("secret_runtime", {}).get("ok")),
        "google_scopes": google.get("oauth", {}).get("scopes", ["openid", "email", "profile"]),
        "email_ready": _env_bool("LIVEUIN_AUTH_EMAIL_READY", True),
        "phone_otp_ready": _env_bool("LIVEUIN_AUTH_PHONE_OTP_READY", False),
        "apple_ready": _env_bool("LIVEUIN_AUTH_APPLE_READY", False),
        "official_account_oauth_ready": _env_bool("LIVEUIN_WECHAT_OFFICIAL_ACCOUNT_READY", True),
        "website_qr_connect_ready": bool(website_qr["ready"]),
        "miniprogram_ready": _env_bool("LIVEUIN_WECHAT_MINIPROGRAM_READY", True),
        "identity_exchange_ready": _env_bool("LIVEUIN_WECHAT_IDENTITY_EXCHANGE_READY", True),
        "website_qr_connect_configured": bool(website_qr["configured"]),
        "website_qr_connect_config_gaps": website_qr["gaps"],
        "google_owner": "LiveUIN Identity + Core Access",
        "official_account_oauth_owner": "Laijuzhu/brand channel route + LiveUIN broker",
        "website_qr_owner": "LiveUIN Identity + Connect",
    }


def _context_matrix(readiness: Dict[str, Any]) -> List[Dict[str, Any]]:
    email_google = [
        "google" if readiness.get("google_ready") else "",
        "email" if readiness.get("email_ready") else "",
        "phone" if readiness.get("phone_otp_ready") else "",
        "apple" if readiness.get("apple_ready") else "",
    ]
    fallback = [item for item in email_google if item]
    official_account_ready = bool(readiness.get("official_account_oauth_ready") and readiness.get("identity_exchange_ready"))
    website_qr_ready = bool(readiness.get("website_qr_connect_ready") and readiness.get("website_qr_connect_configured"))
    return [
        {
            "context": "desktop_browser",
            "label": "Desktop browser",
            "primary_wechat_method": "website_qr_connect_snsapi_login",
            "show_wechat": website_qr_ready,
            "status": "ready" if website_qr_ready else "locked",
            "reason": "Website QR Connect requires real Open Platform Website App credentials.",
            "fallback_providers": fallback,
            "canonical_owner": "LiveUIN Identity + Connect",
        },
        {
            "context": "mobile_external_browser",
            "label": "Mobile Safari or Chrome",
            "primary_wechat_method": "none",
            "show_wechat": False,
            "status": "fallback_only",
            "reason": "Official Account OAuth is an in-WeChat browser flow, not an external-browser workaround.",
            "fallback_providers": fallback,
            "canonical_owner": "LiveUIN Identity policy",
        },
        {
            "context": "wechat_webview",
            "label": "WeChat WebView",
            "primary_wechat_method": "official_account_oauth",
            "show_wechat": official_account_ready,
            "status": "ready" if official_account_ready else "locked",
            "reason": "Official Account OAuth is channel-owned and exchanges into LiveUIN Identity.",
            "fallback_providers": [item for item in ["email" if readiness.get("email_ready") else "", "phone" if readiness.get("phone_otp_ready") else ""] if item],
            "canonical_owner": "Laijuzhu/brand channel route + LiveUIN Identity broker",
        },
        {
            "context": "mini_program",
            "label": "Mini Program",
            "primary_wechat_method": "wx.login_server_exchange",
            "show_wechat": False,
            "status": "channel_only" if readiness.get("miniprogram_ready") else "locked",
            "reason": "Mini Program login is a channel adapter, not a connector shortcode provider.",
            "fallback_providers": [],
            "canonical_owner": "Mini Program channel + LiveUIN Identity",
        },
        {
            "context": "operator_portal",
            "label": "Operator portal",
            "primary_wechat_method": "policy_routed_by_device",
            "show_wechat": website_qr_ready or official_account_ready,
            "status": "role_gated",
            "reason": "Approved operator role and workspace scope are required before private Ops opens.",
            "fallback_providers": fallback,
            "canonical_owner": "LiveUIN Identity + Core Access",
        },
    ]


def auth_policy_status(workspace_id: str = DEFAULT_WORKSPACE_ID, locale_mode: str = "auto") -> Dict[str, Any]:
    workspace_id = _clean_workspace(workspace_id)
    locale_mode = str(locale_mode or "auto").strip().lower()
    if locale_mode not in {"auto", "en", "zh"}:
        locale_mode = "auto"
    readiness = provider_readiness(workspace_id)
    return {
        "ok": True,
        "service": "liveuin-core-identity-auth-policy",
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "workspace_id": workspace_id,
        "source": "liveuin_identity",
        "canonical_owner": CANONICAL_OWNER,
        "provider_readiness": readiness,
        "contexts": _context_matrix(readiness),
        "locale_policy": {
            "mode": locale_mode,
            "allowed_modes": ["auto", "en", "zh"],
            "auto_order": ["explicit_url", "profile_or_session", "accept_language", "workspace_default"],
            "connector_rule": "Connector auth labels stay operator-neutral; Laijuzhu page language is a brand/page wrapper decision.",
        },
        "operator_auth_shell": {
            "persona": "internal operator / wife tester",
            "surface": "private app auth shell",
            "required_role": "operator",
            "workspace_scope": workspace_id,
            "locked_state": "Unapproved identities stay in access pending until LiveUIN Identity and Core Access grant role/workspace scope.",
            "handoff_destination": "/ops/command",
        },
        "production_requirements": [
            "Mount real IdP/provider adapters before production login is considered complete.",
            "Enable Google sign-in only after the server-side Google OIDC authorization-code callback validates state, nonce, issuer, audience, expiry, and email_verified, then mints a LiveUIN-owned session.",
            "Request only Google login identity scopes openid, email, and profile unless a later feature uses incremental authorization for a specific Google API.",
            "Configure LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET and production credential persistence.",
            "Use the production vault backend for provider/client secrets and adapter secret references.",
            "Enable Website QR Connect only after real WeChat Open Platform Website App credentials exist.",
            "Keep Official Account OAuth inside WeChat WebView/channel routes and exchange into LiveUIN Identity.",
        ],
        "boundary": {
            "surface": "ops/auth shell, connector auth shortcodes, Laijuzhu channel login wrappers, and operator portal entry",
            "layer": "provider/device/locale policy plus role-gated identity handoff",
            "owner": CANONICAL_OWNER,
            "core_access_owner": "LiveUIN Core/Admin Access Governance",
            "wechat_role": "identity/OAuth/callback/message delivery only; not canonical case, proof, inventory, payments, tickets, SLA, finance, or operator truth.",
            "connector_role": "auth shell renderer and SSO/API handoff only; connector setup does not own identity truth.",
            "laijuzhu_role": "public customer language and channel wrapper only; LiveUIN Identity owns auth/session/RBAC truth.",
            "igema_operator_role": "assigned execution only when selected; not mandatory owner of LiveUIN operator identity.",
        },
    }


def wechat_auth_status(workspace_id: str = DEFAULT_WORKSPACE_ID) -> Dict[str, Any]:
    readiness = provider_readiness(workspace_id)
    return {
        "ok": True,
        "service": "liveuin-ops-wechat-identity-status-preview",
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "canonical_owner": CANONICAL_OWNER,
        "workspace_id": readiness["workspace_id"],
        "official_account_oauth_ready": readiness["official_account_oauth_ready"],
        "website_qr_connect_ready": readiness["website_qr_connect_ready"],
        "website_qr_connect_configured": readiness["website_qr_connect_configured"],
        "identity_exchange_ready": readiness["identity_exchange_ready"],
        "miniprogram_ready": readiness["miniprogram_ready"],
        "ready": bool(
            readiness["identity_exchange_ready"]
            and (readiness["official_account_oauth_ready"] or readiness["website_qr_connect_ready"])
        ),
        "boundary": auth_policy_status(readiness["workspace_id"])["boundary"],
    }
