from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from http.cookies import SimpleCookie
from typing import Any, Dict, Iterable, List
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

try:
    from . import core_adapter_secret_registry as secret_registry
    from . import core_identity_service as identity_svc
    from . import core_identity_session as identity_session
    from . import core_identity_workspace_access as workspace_access
except ImportError:  # pragma: no cover - supports direct script execution.
    import core_adapter_secret_registry as secret_registry
    import core_identity_service as identity_svc
    import core_identity_session as identity_session
    import core_identity_workspace_access as workspace_access


SCHEMA_VERSION = "liveuin-core-identity-google-oauth-v1"
PHASE = "phase35-google-oidc-provider-guard"
DEFAULT_WORKSPACE_ID = "laijuzhu"
CANONICAL_OWNER = "LiveUIN Identity"

GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_ENDPOINT = "https://openidconnect.googleapis.com/v1/userinfo"
GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUER = "https://accounts.google.com"
GOOGLE_ISSUER_ALT = "accounts.google.com"
DEFAULT_SCOPES = ["openid", "email", "profile"]
ALLOWED_LOGIN_SCOPES = {"openid", "email", "profile"}
ALLOWED_NATIVE_RETURN_TO_SCHEMES = {"liveuinresident", "com.liveuin.resident"}
ALLOWED_NATIVE_RETURN_TO_HOSTS = {
    "app",
    "bookings",
    "claims",
    "documents",
    "help",
    "insurance",
    "login",
    "member",
    "move-in",
    "notifications",
    "pass",
    "renewal",
    "saved",
    "support",
    "utilities",
    "verification",
    "wallet",
}
DEFAULT_STATE_TTL_SECONDS = 600
DEFAULT_HTTP_TIMEOUT_SECONDS = 8
DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 24
JWT_TIME_SKEW_SECONDS = 300
RS256_SHA256_DER_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

SENSITIVE_KEYS = {
    "access_token",
    "authorization",
    "client_secret",
    "code",
    "id_token",
    "nonce",
    "raw_secret",
    "refresh_token",
    "state",
    "token",
}


def _now() -> int:
    return int(time.time())


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _iso_from_epoch(value: Any) -> str:
    try:
        epoch = int(value)
    except (TypeError, ValueError):
        return ""
    if epoch <= 0:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "ready", "enabled", "required", "enforced"}


def _first_env(names: Iterable[str]) -> tuple[str, str]:
    for name in names:
        value = str(os.getenv(name) or "").strip()
        if value:
            return value, name
    return "", next(iter(names), "")


def _clean_workspace(value: Any) -> str:
    text = str(value or "").strip()
    cleaned = "".join(ch for ch in text if ch.isalnum() or ch in {"_", "-", ".", ":"})
    return cleaned[:96] or DEFAULT_WORKSPACE_ID


def _clean_text(value: Any, max_length: int = 240) -> str:
    return str(value or "").strip()[:max_length]


def _clean_slug(value: Any, default: str = "", max_length: int = 120) -> str:
    cleaned = re.sub(r"[^a-z0-9_.:-]+", "_", str(value or "").strip().lower()).strip("_")
    return (cleaned or default)[:max_length]


def _hash(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _hint(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 12:
        return text[:3] + "..." + text[-3:]
    return text[:6] + "..." + text[-6:]


def _redact(value: Any) -> Any:
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if not isinstance(value, dict):
        return value
    cleaned: Dict[str, Any] = {}
    for key, item in value.items():
        if str(key).lower() in SENSITIVE_KEYS:
            cleaned[str(key)] = "[redacted]"
        else:
            cleaned[str(key)] = _redact(item)
    return cleaned


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


def _json_loads(value: Any, fallback: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        parsed = json.loads(str(value or ""))
    except (TypeError, ValueError):
        return fallback
    return parsed if parsed is not None else fallback


def _b64url_decode(value: Any) -> bytes:
    text = str(value or "").strip()
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode((text + padding).encode("ascii"))


def _env_json(name: str) -> Dict[str, Any]:
    raw = str(os.getenv(name) or "").strip()
    if not raw:
        return {}
    parsed = _json_loads(raw, {})
    return parsed if isinstance(parsed, dict) else {}


def _http_timeout() -> int:
    try:
        return max(2, min(int(os.getenv("LIVEUIN_GOOGLE_OIDC_HTTP_TIMEOUT_SECONDS") or DEFAULT_HTTP_TIMEOUT_SECONDS), 30))
    except ValueError:
        return DEFAULT_HTTP_TIMEOUT_SECONDS


def _http_json(
    url: str,
    *,
    form: Dict[str, str] | None = None,
    headers: Dict[str, str] | None = None,
    timeout: int | None = None,
) -> Dict[str, Any]:
    payload = urlencode(form or {}).encode("utf-8") if form is not None else None
    request_headers = {
        "Accept": "application/json",
        **(headers or {}),
    }
    if form is not None:
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = Request(url, data=payload, headers=request_headers, method="POST" if form is not None else "GET")
    try:
        with urlopen(request, timeout=timeout or _http_timeout()) as response:
            raw = response.read(2_000_000)
            parsed = json.loads(raw.decode("utf-8"))
            return parsed if isinstance(parsed, dict) else {}
    except HTTPError as exc:
        raw_body = exc.read(20_000).decode("utf-8", errors="replace")
        parsed = _json_loads(raw_body, {})
        return error(
            "google_oidc_http_error",
            int(getattr(exc, "code", 502) or 502),
            upstream_status=int(getattr(exc, "code", 0) or 0),
            upstream_detail=_clean_text(_as_dict(parsed).get("error") or raw_body, 180),
            upstream_description=_clean_text(_as_dict(parsed).get("error_description"), 240),
            raw_secret_echoed=False,
        )
    except (TimeoutError, URLError, OSError) as exc:
        return error(
            "google_oidc_http_unavailable",
            502,
            upstream_error=_clean_text(type(exc).__name__, 80),
            upstream_detail=_clean_text(str(exc), 180),
            raw_secret_echoed=False,
        )


def _hash_email(value: Any) -> str:
    text = str(value or "").strip().lower()
    return _hash(text) if text else ""


def _csv_env(name: str) -> List[str]:
    raw = str(os.getenv(name) or "").strip()
    if not raw:
        return []
    cleaned: List[str] = []
    for item in re.split(r"[\s,]+", raw):
        text = item.strip().lower()
        if text and text not in cleaned:
            cleaned.append(text)
    return cleaned


def _account_policy_status() -> Dict[str, Any]:
    allowed_emails = _csv_env("LIVEUIN_GOOGLE_ALLOWED_EMAILS")
    allowed_domains = [item.lstrip("@") for item in _csv_env("LIVEUIN_GOOGLE_ALLOWED_EMAIL_DOMAINS")]
    allow_any_verified = _env_bool("LIVEUIN_GOOGLE_ALLOW_ANY_VERIFIED_EMAIL_FOR_LOGIN", False)
    policy_ready = _env_bool("LIVEUIN_GOOGLE_ACCOUNT_POLICY_READY", False)
    return {
        "ok": policy_ready and (allow_any_verified or bool(allowed_emails) or bool(allowed_domains)),
        "policy_ready": policy_ready,
        "allow_any_verified_email": allow_any_verified,
        "allowed_email_count": len(allowed_emails),
        "allowed_email_hashes": [_hash_email(email) for email in allowed_emails],
        "allowed_domains": allowed_domains,
        "raw_email_list_echoed": False,
    }


def _validate_account_policy(claims: Dict[str, Any]) -> Dict[str, Any]:
    policy = _account_policy_status()
    email = str(claims.get("email") or "").strip().lower()
    domain = email.rsplit("@", 1)[1] if "@" in email else ""
    if not policy["policy_ready"]:
        return error("google_account_policy_not_ready", 403, account_policy=policy, raw_secret_echoed=False)
    if policy["allow_any_verified_email"]:
        return {"ok": True, "account_policy": policy, "email_hash": _hash_email(email), "email_domain": domain}
    allowed_emails = set(_csv_env("LIVEUIN_GOOGLE_ALLOWED_EMAILS"))
    allowed_domains = {item.lstrip("@") for item in _csv_env("LIVEUIN_GOOGLE_ALLOWED_EMAIL_DOMAINS")}
    if email and email in allowed_emails:
        return {"ok": True, "account_policy": policy, "email_hash": _hash_email(email), "email_domain": domain}
    if domain and domain in allowed_domains:
        return {"ok": True, "account_policy": policy, "email_hash": _hash_email(email), "email_domain": domain}
    return error(
        "google_account_not_allowed",
        403,
        account_policy=policy,
        email_hash=_hash_email(email),
        email_domain=domain,
        raw_secret_echoed=False,
    )


def _sqlite_path() -> Path:
    explicit = str(os.getenv("LIVEUIN_CORE_IDENTITY_GOOGLE_OAUTH_SQLITE_PATH") or "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()
    login_path = str(os.getenv("LIVEUIN_CORE_IDENTITY_LOGIN_SQLITE_PATH") or "").strip()
    if login_path:
        return Path(login_path).expanduser().resolve()
    data_dir = Path(
        os.getenv("LIVEUIN_CORE_IDENTITY_LOGIN_DATA_DIR")
        or os.getenv("LIVEUIN_CORE_IDENTITY_DATA_DIR")
        or Path.cwd() / ".liveuin-data"
    ).expanduser()
    return (data_dir / "liveuin-core-identity-login.sqlite3").resolve()


def _connect() -> sqlite3.Connection:
    path = _sqlite_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS identity_google_oauth_states (
            state_hash TEXT PRIMARY KEY,
            nonce_hash TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            return_to TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            consumed_at INTEGER NOT NULL DEFAULT 0,
            request_meta_json TEXT NOT NULL DEFAULT '{}'
        )
        """
    )
    conn.commit()
    return conn


def _create_state(
    *,
    workspace_id: str,
    return_to: str,
    redirect_uri: str,
    ttl_seconds: int = DEFAULT_STATE_TTL_SECONDS,
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    state = "lug_" + secrets.token_urlsafe(32)
    nonce = "lun_" + secrets.token_urlsafe(32)
    now = _now()
    expires_at = now + max(60, min(int(ttl_seconds or DEFAULT_STATE_TTL_SECONDS), 1800))
    with _connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO identity_google_oauth_states (
                state_hash, nonce_hash, workspace_id, return_to, redirect_uri,
                status, issued_at, expires_at, consumed_at, request_meta_json
            ) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, 0, ?)
            """,
            (
                _hash(state),
                _hash(nonce),
                workspace_id,
                return_to,
                redirect_uri,
                now,
                expires_at,
                json.dumps(_redact(request_meta or {}), sort_keys=True),
            ),
        )
        conn.commit()
    return {
        "state": state,
        "nonce": nonce,
        "state_hash": _hash(state),
        "nonce_hash": _hash(nonce),
        "state_hint": _hint(state),
        "nonce_hint": _hint(nonce),
        "issued_at": now,
        "expires_at": expires_at,
        "expires_at_iso": _iso_from_epoch(expires_at),
        "raw_secret_stored": False,
    }


def _consume_state(state: str) -> Dict[str, Any]:
    state_hash = _hash(state)
    now = _now()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM identity_google_oauth_states WHERE state_hash = ?",
            (state_hash,),
        ).fetchone()
        if row is None:
            return error("google_oauth_state_not_found", 403)
        record = dict(row)
        if record.get("status") != "pending" or int(record.get("consumed_at") or 0) > 0:
            return error("google_oauth_state_reused", 409, state_hint=_hint(state))
        if int(record.get("expires_at") or 0) <= now:
            conn.execute(
                "UPDATE identity_google_oauth_states SET status = 'expired' WHERE state_hash = ?",
                (state_hash,),
            )
            conn.commit()
            return error("google_oauth_state_expired", 410, state_hint=_hint(state))
        conn.execute(
            "UPDATE identity_google_oauth_states SET status = 'consumed', consumed_at = ? WHERE state_hash = ?",
            (now, state_hash),
        )
        conn.commit()
    return {
        "ok": True,
        "state_hash": state_hash,
        "state_hint": _hint(state),
        "nonce_hash": record.get("nonce_hash", ""),
        "workspace_id": record.get("workspace_id", DEFAULT_WORKSPACE_ID),
        "return_to": record.get("return_to", "/ops/auth-pending"),
        "redirect_uri": record.get("redirect_uri", ""),
        "request_context": _json_loads(record.get("request_meta_json"), {}),
        "issued_at": record.get("issued_at", 0),
        "expires_at": record.get("expires_at", 0),
        "consumed_at": now,
        "consumed_at_iso": _iso_from_epoch(now),
        "raw_secret_echoed": False,
    }


def _scope_list() -> List[str]:
    raw = str(os.getenv("LIVEUIN_GOOGLE_SCOPES") or os.getenv("GOOGLE_OAUTH_SCOPES") or "").strip()
    values = [item for item in re.split(r"[\s,]+", raw) if item] if raw else list(DEFAULT_SCOPES)
    cleaned: List[str] = []
    for value in values:
        scope = value.strip()
        if scope and scope not in cleaned:
            cleaned.append(scope)
    return cleaned


def _safe_return_to(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "/ops/auth-pending"
    parsed = urlparse(text)
    scheme = str(parsed.scheme or "").strip().lower()
    host = str(parsed.hostname or "").strip().lower()
    if scheme in ALLOWED_NATIVE_RETURN_TO_SCHEMES:
        if host and host not in ALLOWED_NATIVE_RETURN_TO_HOSTS:
            return "/ops/auth-pending"
        path = parsed.path or "/"
        if not path.startswith("/"):
            path = f"/{path}"
        if path.startswith("//"):
            return "/ops/auth-pending"
        sanitized = f"{scheme}://{host}{path[:300]}"
        if parsed.query:
            sanitized = f"{sanitized}?{parsed.query[:800]}"
        if parsed.fragment:
            sanitized = f"{sanitized}#{parsed.fragment[:200]}"
        return sanitized
    if parsed.scheme or parsed.netloc:
        if parsed.scheme == "https" and host and (host == "liveuin.com" or host.endswith(".liveuin.com")):
            path = parsed.path or "/"
            if not path.startswith("/") or path.startswith("//"):
                return "/ops/auth-pending"
            sanitized = path[:300]
            if parsed.query:
                sanitized = f"{sanitized}?{parsed.query[:200]}"
            return f"https://{host}{sanitized}"
        return "/ops/auth-pending"
    if not text.startswith("/") or text.startswith("//"):
        return "/ops/auth-pending"
    return text[:300]


def _safe_https_base_url(value: Any) -> str:
    text = str(value or "").strip()
    parsed = urlparse(text)
    if parsed.scheme != "https" or not parsed.netloc:
        return ""
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _final_return_url(return_to: str, request_context: Dict[str, Any] | None = None) -> str:
    sanitized = _safe_return_to(return_to)
    parsed = urlparse(sanitized)
    if parsed.scheme in ALLOWED_NATIVE_RETURN_TO_SCHEMES:
        return sanitized
    if parsed.scheme == "https" and parsed.netloc:
        return sanitized

    context = _as_dict(request_context)
    host = str(context.get("host") or "").split(":", 1)[0].strip().lower()
    if not host or not sanitized.startswith("/"):
        return sanitized
    if host in {"ops.liveuin.com", "connect.liveuin.com"}:
        return sanitized
    if host == "liveuin.com" or host.endswith(".liveuin.com"):
        return f"https://{host}{sanitized}"
    return sanitized


def _connect_google_redirect_uri(default_redirect_uri: str, request_context: Dict[str, Any] | None = None, return_to: str = "") -> str:
    context = _as_dict(request_context)
    surface = _clean_slug(context.get("surface"), "", 80)
    host = str(context.get("host") or "").split(":", 1)[0].strip().lower()
    connect_base = _safe_https_base_url(
        os.getenv("LIVEUIN_GOOGLE_CONNECT_REDIRECT_URI_BASE")
        or os.getenv("LIVEUIN_CONNECT_BASE_URL")
        or ""
    )
    connect_host = str(urlparse(connect_base).hostname or "").strip().lower()
    wants_connect_surface = surface == "connect_control_plane" or str(return_to or "").startswith("/connect/")
    local_hosts = {"localhost", "127.0.0.1", "host.docker.internal"}
    request_is_connect_host = bool(connect_host and host and host == connect_host)
    request_can_define_connect_base = bool(
        host
        and (
            host == "connect.liveuin.com"
            or host in local_hosts
        )
    )
    effective_connect_base = connect_base
    if request_can_define_connect_base:
        effective_connect_base = f"https://{host}"

    if not effective_connect_base or not (wants_connect_surface or request_is_connect_host or request_can_define_connect_base):
        return default_redirect_uri
    return effective_connect_base + "/api/ops/auth/google/callback"


def _google_config(workspace_id: str = DEFAULT_WORKSPACE_ID) -> Dict[str, Any]:
    workspace_id = _clean_workspace(workspace_id)
    client_id, client_id_key = _first_env(["LIVEUIN_GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_ID"])
    redirect_uri, redirect_uri_key = _first_env(["LIVEUIN_GOOGLE_REDIRECT_URI", "GOOGLE_REDIRECT_URI"])
    client_secret_ref, client_secret_ref_key = _first_env(["LIVEUIN_GOOGLE_CLIENT_SECRET_REF", "GOOGLE_CLIENT_SECRET_REF"])
    state_secret_ref, state_secret_ref_key = _first_env(["LIVEUIN_GOOGLE_STATE_SECRET_REF", "GOOGLE_STATE_SECRET_REF"])
    raw_client_secret, raw_client_secret_key = _first_env(["LIVEUIN_GOOGLE_CLIENT_SECRET", "GOOGLE_CLIENT_SECRET"])
    scopes = _scope_list()
    parsed_redirect = urlparse(redirect_uri)
    scope_set = set(scopes)
    prompt = str(os.getenv("LIVEUIN_GOOGLE_PROMPT") or "select_account").strip()
    if prompt and prompt not in {"none", "consent", "select_account"}:
        prompt = "select_account"
    hosted_domain = str(os.getenv("LIVEUIN_GOOGLE_HOSTED_DOMAIN") or os.getenv("GOOGLE_HOSTED_DOMAIN") or "").strip().lower()

    return {
        "workspace_id": workspace_id,
        "client_id": client_id,
        "client_id_configured": bool(client_id) and client_id.endswith(".apps.googleusercontent.com"),
        "client_id_hint": _hint(client_id),
        "client_id_key": client_id_key,
        "redirect_uri": redirect_uri,
        "redirect_uri_key": redirect_uri_key,
        "redirect_uri_configured": bool(redirect_uri),
        "redirect_uri_https": parsed_redirect.scheme == "https" and bool(parsed_redirect.netloc),
        "redirect_uri_path": parsed_redirect.path,
        "client_secret_ref": client_secret_ref,
        "client_secret_ref_configured": bool(client_secret_ref),
        "client_secret_ref_key": client_secret_ref_key,
        "state_secret_ref_configured": bool(state_secret_ref),
        "state_secret_ref_key": state_secret_ref_key,
        "raw_client_secret_present": bool(raw_client_secret),
        "raw_client_secret_key": raw_client_secret_key if raw_client_secret else "",
        "scopes": scopes,
        "scope_policy_ok": "openid" in scope_set and scope_set.issubset(ALLOWED_LOGIN_SCOPES),
        "scope_policy": "login_only_openid_email_profile",
        "prompt": prompt,
        "hosted_domain": hosted_domain,
        "access_type": "online",
        "include_granted_scopes": True,
        "authorization_endpoint": GOOGLE_AUTHORIZATION_ENDPOINT,
        "token_endpoint": GOOGLE_TOKEN_ENDPOINT,
        "userinfo_endpoint": GOOGLE_USERINFO_ENDPOINT,
        "jwks_uri": GOOGLE_JWKS_URI,
        "issuer": GOOGLE_ISSUER,
        "accepted_issuers": [GOOGLE_ISSUER, GOOGLE_ISSUER_ALT],
    }


def _resolve_client_secret(workspace_id: str, request_meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    config = _google_config(workspace_id)
    if not config["client_secret_ref_configured"]:
        return error("google_client_secret_ref_required", 500, raw_secret_echoed=False)
    resolved = secret_registry.resolve_secret_reference(
        workspace_id=config["workspace_id"],
        provider="google",
        purpose="google_oauth_client_secret",
        secret_ref_id=str(config["client_secret_ref"] or ""),
        request_meta=request_meta,
    )
    if resolved.get("ok") is not True:
        return error(
            str(resolved.get("detail") or "google_client_secret_unavailable"),
            int(resolved.get("status_code") or 500),
            secret_context=_as_dict(resolved.get("secret_context")),
            raw_secret_echoed=False,
        )
    secret = str(resolved.get("secret") or "").strip()
    if not secret:
        return error("google_client_secret_empty", 500, raw_secret_echoed=False)
    return {
        "ok": True,
        "secret": secret,
        "secret_context": _as_dict(resolved.get("secret_context")),
        "raw_secret_echoed": False,
    }


def _client_secret_runtime_status(workspace_id: str) -> Dict[str, Any]:
    resolved = _resolve_client_secret(workspace_id, {"source": "google_oauth_status"})
    context = _as_dict(resolved.get("secret_context"))
    return {
        "ok": resolved.get("ok") is True,
        "detail": "" if resolved.get("ok") is True else str(resolved.get("detail") or "google_client_secret_unavailable"),
        "secret_context": context,
        "raw_secret_echoed": False,
    }


def _requirement(name: str, ok: bool, detail: str) -> Dict[str, Any]:
    return {"name": name, "ok": bool(ok), "detail": detail}


def error(detail: str, status_code: int = 400, **extra: Any) -> Dict[str, Any]:
    return {
        "ok": False,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "detail": detail,
        "status_code": status_code,
        "canonical_owner": CANONICAL_OWNER,
        **extra,
    }


def google_oauth_status(workspace_id: str = DEFAULT_WORKSPACE_ID) -> Dict[str, Any]:
    config = _google_config(workspace_id)
    real_idp_ready = _env_bool("LIVEUIN_AUTH_REAL_IDP_ADAPTERS_READY", False)
    google_enabled = _env_bool("LIVEUIN_AUTH_GOOGLE_READY", False)
    callback_validation_ready = _env_bool("LIVEUIN_GOOGLE_OIDC_CALLBACK_VALIDATION_READY", False)
    token_exchange_ready = _env_bool("LIVEUIN_GOOGLE_OIDC_TOKEN_EXCHANGE_READY", False)
    client_secret_runtime = _client_secret_runtime_status(config["workspace_id"]) if config["client_secret_ref_configured"] else {
        "ok": False,
        "detail": "google_client_secret_ref_required",
        "secret_context": {},
        "raw_secret_echoed": False,
    }
    account_policy = _account_policy_status()
    workspace_access_policy = workspace_access.workspace_access_status(config["workspace_id"])
    redirect_path_ok = config["redirect_uri_path"].rstrip("/") == "/api/ops/auth/google/callback"
    session_signing_ready = bool(str(os.getenv("LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET") or "").strip())
    requirements = [
        _requirement("google_enabled", google_enabled, "LIVEUIN_AUTH_GOOGLE_READY is explicitly enabled"),
        _requirement("real_idp_adapters_ready", real_idp_ready, "real provider/IdP adapter set is mounted"),
        _requirement("client_id", config["client_id_configured"], "Google OAuth Web client ID is configured"),
        _requirement("redirect_uri_https", config["redirect_uri_https"], "Google redirect URI is HTTPS and exact-match ready"),
        _requirement("redirect_uri_path", redirect_path_ok, "Google redirect URI uses /api/ops/auth/google/callback"),
        _requirement("client_secret_ref", config["client_secret_ref_configured"], "Google client secret is referenced through the server secret store"),
        _requirement("client_secret_runtime", client_secret_runtime["ok"], "Google client secret reference resolves through the LiveUIN secret registry at runtime"),
        _requirement("state_secret_ref", config["state_secret_ref_configured"], "Google state/nonce secret is referenced through the server secret store"),
        _requirement("scope_policy", config["scope_policy_ok"], "Google login scopes are limited to openid email profile"),
        _requirement("no_raw_client_secret_env", not config["raw_client_secret_present"], "raw Google client secret is not present in process env"),
        _requirement("token_exchange_ready", token_exchange_ready, "server-side authorization-code token exchange is mounted"),
        _requirement("callback_validation_ready", callback_validation_ready, "ID token issuer/audience/expiry/nonce/email validation is mounted"),
        _requirement("session_signing_secret", session_signing_ready, "LiveUIN session signing secret is configured before Google can issue a first-party session"),
        _requirement("account_policy_ready", account_policy["ok"], "Google account admission policy has allowed emails/domains or an explicit verified-email policy"),
        _requirement("workspace_access_policy", workspace_access_policy.get("ready") is True, "LiveUIN workspace membership/admission policy is mounted"),
    ]
    ready = all(item["ok"] for item in requirements)
    return _redact(
        {
            "ok": True,
            "ready": ready,
            "service": "liveuin-core-identity-google-oauth",
            "schema_version": SCHEMA_VERSION,
            "phase": PHASE,
            "workspace_id": config["workspace_id"],
            "source": "liveuin_identity",
            "canonical_owner": CANONICAL_OWNER,
            "provider": "google",
            "configured": all(
                [
                        config["client_id_configured"],
                        config["redirect_uri_https"],
                        redirect_path_ok,
                        config["client_secret_ref_configured"],
                        config["state_secret_ref_configured"],
                        config["scope_policy_ok"],
                    not config["raw_client_secret_present"],
                ]
            ),
            "authorization_start_ready": ready,
            "provider_readiness": {
                "google_ready": ready,
                "google_enabled": google_enabled,
                "google_configured": all(
                    [
                        config["client_id_configured"],
                        config["redirect_uri_https"],
                        redirect_path_ok,
                        config["client_secret_ref_configured"],
                        client_secret_runtime["ok"],
                        config["state_secret_ref_configured"],
                    ]
                ),
                "real_idp_adapters_ready": real_idp_ready,
                "token_exchange_ready": token_exchange_ready,
                "callback_validation_ready": callback_validation_ready,
                "session_signing_ready": session_signing_ready,
                "account_policy_ready": account_policy["ok"],
                "workspace_access_ready": workspace_access_policy.get("ready") is True,
            },
            "oauth": {
                "authorization_endpoint": config["authorization_endpoint"],
                "token_endpoint": config["token_endpoint"],
                "userinfo_endpoint": config["userinfo_endpoint"],
                "jwks_uri": config["jwks_uri"],
                "issuer": config["issuer"],
                "accepted_issuers": config["accepted_issuers"],
                "response_type": "code",
                "scopes": config["scopes"],
                "scope_policy": config["scope_policy"],
                "prompt": config["prompt"],
                "access_type": config["access_type"],
                "include_granted_scopes": config["include_granted_scopes"],
                "redirect_uri_path": config["redirect_uri_path"],
                "client_id_hint": config["client_id_hint"],
                "hosted_domain": config["hosted_domain"],
            },
            "secret_runtime": _redact(client_secret_runtime),
            "account_policy": account_policy,
            "workspace_access": workspace_access_policy,
            "requirements": requirements,
            "consent_behavior": {
                "expected_google_screen": "Google authenticates the selected account and may show a consent screen for the requested login scopes.",
                "requested_permissions": "Only OpenID Connect login identity scopes are requested: openid, email, profile.",
                "offline_access": False,
                "no_drive_calendar_or_payment_scopes": True,
            },
            "frontend": {
                "show_button": ready,
                "disabled_reason": "" if ready else "Google sign-in is not available right now. Use your email code for now.",
                "start_path": "/api/ops/auth/google",
                "status_path": "/api/ops/auth/google/status",
                "callback_path": "/api/ops/auth/google/callback",
            },
            "boundary": {
                "surface": "ops auth shell and connector/operator auth widgets",
                "layer": "Google OIDC provider adapter guard",
                "owner": CANONICAL_OWNER,
                "core_access_owner": "LiveUIN Core/Admin Access Governance",
                "google_role": "authentication provider and consent screen only; LiveUIN Identity owns identity link, session issuance, role, workspace, and RBAC truth.",
                "secret_policy": "Raw Google client secrets, authorization codes, access tokens, refresh tokens, ID tokens, state, and nonce values are not exposed in status output or stored as raw durable truth.",
            },
        }
    )


def google_authorization_start(
    query: Dict[str, List[str]] | None = None,
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    query = query if isinstance(query, dict) else {}
    workspace_id = _clean_workspace((query.get("workspace_id") or [DEFAULT_WORKSPACE_ID])[0])
    status = google_oauth_status(workspace_id=workspace_id)
    if status.get("ready") is not True:
        return error(
            "google_oidc_not_ready",
            409,
            status="locked",
            google=status,
            raw_secret_echoed=False,
        )

    config = _google_config(workspace_id)
    return_to = _safe_return_to((query.get("return_to") or ["/ops/auth-pending"])[0])
    request_context = {
        **_as_dict(request_meta),
        "audience": _clean_slug((query.get("audience") or ["operator"])[0], "operator", 80),
        "surface": _clean_slug((query.get("surface") or ["ops_auth_shell"])[0], "ops_auth_shell", 80),
        "workspace_id": workspace_id,
        "role_requested": _clean_slug((query.get("liveuin_role") or query.get("role") or ["operator"])[0], "operator", 80),
        "brand": _clean_slug((query.get("brand") or ["liveuin"])[0], "liveuin", 80),
        "source": _clean_slug((query.get("source") or ["ops_auth_shell"])[0], "ops_auth_shell", 120),
    }
    redirect_uri = _connect_google_redirect_uri(config["redirect_uri"], request_context, return_to)
    state = _create_state(
        workspace_id=workspace_id,
        return_to=return_to,
        redirect_uri=redirect_uri,
        request_meta=request_context,
    )
    params = {
        "client_id": _clean_text(os.getenv("LIVEUIN_GOOGLE_CLIENT_ID") or os.getenv("GOOGLE_CLIENT_ID"), 200),
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(config["scopes"]),
        "state": state["state"],
        "nonce": state["nonce"],
        "include_granted_scopes": "true",
        "access_type": "online",
    }
    if config["hosted_domain"]:
        params["hd"] = config["hosted_domain"]
    if config["prompt"]:
        params["prompt"] = config["prompt"]
    authorization_url = GOOGLE_AUTHORIZATION_ENDPOINT + "?" + urlencode(params)
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "google_oauth_redirect_ready",
        "status_code": 302,
        "redirect_url": authorization_url,
        "canonical_owner": CANONICAL_OWNER,
        "workspace_id": workspace_id,
        "state": {
            "state_hash": state["state_hash"],
            "state_hint": state["state_hint"],
            "nonce_hash": state["nonce_hash"],
            "nonce_hint": state["nonce_hint"],
            "expires_at_iso": state["expires_at_iso"],
            "raw_secret_stored": False,
        },
        "raw_secret_echoed": False,
    }


def _exchange_authorization_code(
    *,
    code: str,
    workspace_id: str,
    redirect_uri: str,
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    config = _google_config(workspace_id)
    fixture = _env_json("LIVEUIN_GOOGLE_OIDC_TOKEN_RESPONSE_JSON")
    if fixture:
        return {
            "ok": True,
            "token_response": _redact(fixture),
            "id_token": str(fixture.get("id_token") or ""),
            "token_source": "local_test_fixture",
            "raw_secret_echoed": False,
        }

    secret = _resolve_client_secret(workspace_id, request_meta)
    if secret.get("ok") is not True:
        return secret
    form = {
        "code": code,
        "client_id": config["client_id"],
        "client_secret": str(secret.get("secret") or ""),
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    response = _http_json(GOOGLE_TOKEN_ENDPOINT, form=form)
    if response.get("ok") is False:
        return response
    if response.get("error"):
        return error(
            "google_oidc_token_exchange_failed",
            502,
            upstream_detail=_clean_text(response.get("error"), 120),
            upstream_description=_clean_text(response.get("error_description"), 240),
            raw_secret_echoed=False,
        )
    id_token = str(response.get("id_token") or "").strip()
    if not id_token:
        return error("google_oidc_id_token_missing", 502, raw_secret_echoed=False)
    return {
        "ok": True,
        "token_response": _redact(response),
        "id_token": id_token,
        "token_source": "google_token_endpoint",
        "secret_context": _as_dict(secret.get("secret_context")),
        "raw_secret_echoed": False,
    }


def _load_jwks() -> Dict[str, Any]:
    fixture = _env_json("LIVEUIN_GOOGLE_OIDC_JWKS_JSON")
    if fixture:
        return {"ok": True, "jwks": fixture, "jwks_source": "local_test_fixture"}
    response = _http_json(GOOGLE_JWKS_URI)
    if response.get("ok") is False:
        return response
    keys = response.get("keys")
    if not isinstance(keys, list):
        return error("google_jwks_keys_missing", 502, raw_secret_echoed=False)
    return {"ok": True, "jwks": response, "jwks_source": GOOGLE_JWKS_URI}


def _jwt_parts(id_token: str) -> Dict[str, Any]:
    parts = str(id_token or "").split(".")
    if len(parts) != 3:
        return error("google_oidc_jwt_shape_invalid", 401, raw_secret_echoed=False)
    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
        claims = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
        signature = _b64url_decode(parts[2])
    except Exception:
        return error("google_oidc_jwt_decode_failed", 401, raw_secret_echoed=False)
    if not isinstance(header, dict) or not isinstance(claims, dict):
        return error("google_oidc_jwt_payload_invalid", 401, raw_secret_echoed=False)
    return {
        "ok": True,
        "header": header,
        "claims": claims,
        "signature": signature,
        "signing_input": (parts[0] + "." + parts[1]).encode("ascii"),
    }


def _jwk_int(jwk: Dict[str, Any], key: str) -> int:
    return int.from_bytes(_b64url_decode(jwk.get(key)), "big")


def _verify_rs256_signature(signing_input: bytes, signature: bytes, jwk: Dict[str, Any]) -> bool:
    try:
        modulus = _jwk_int(jwk, "n")
        exponent = _jwk_int(jwk, "e")
    except Exception:
        return False
    key_bytes = (modulus.bit_length() + 7) // 8
    if key_bytes < len(RS256_SHA256_DER_PREFIX) + 32 + 11 or len(signature) != key_bytes:
        return False
    decrypted = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(key_bytes, "big")
    digest_info = RS256_SHA256_DER_PREFIX + hashlib.sha256(signing_input).digest()
    separator_index = key_bytes - len(digest_info) - 1
    if separator_index < 10:
        return False
    return (
        decrypted[0:2] == b"\x00\x01"
        and all(item == 0xFF for item in decrypted[2:separator_index])
        and decrypted[separator_index] == 0
        and hmac.compare_digest(decrypted[separator_index + 1 :], digest_info)
    )


def _validate_id_token_signature(parts: Dict[str, Any]) -> Dict[str, Any]:
    header = _as_dict(parts.get("header"))
    if header.get("alg") != "RS256":
        return error("google_oidc_alg_not_allowed", 401, alg=_clean_text(header.get("alg"), 40), raw_secret_echoed=False)
    kid = str(header.get("kid") or "").strip()
    if not kid:
        return error("google_oidc_kid_required", 401, raw_secret_echoed=False)
    jwks = _load_jwks()
    if jwks.get("ok") is not True:
        return jwks
    keys = _as_list(_as_dict(jwks.get("jwks")).get("keys"))
    key = next((item for item in keys if isinstance(item, dict) and str(item.get("kid") or "") == kid), {})
    if not key:
        return error("google_oidc_jwk_not_found", 401, kid=_clean_text(kid, 80), raw_secret_echoed=False)
    if str(key.get("kty") or "") != "RSA":
        return error("google_oidc_jwk_type_invalid", 401, kid=_clean_text(kid, 80), raw_secret_echoed=False)
    if not _verify_rs256_signature(
        bytes(parts.get("signing_input") or b""),
        bytes(parts.get("signature") or b""),
        key,
    ):
        return error("google_oidc_signature_invalid", 401, kid=_clean_text(kid, 80), raw_secret_echoed=False)
    return {
        "ok": True,
        "kid": kid,
        "jwks_source": jwks.get("jwks_source", GOOGLE_JWKS_URI),
        "signature_verified": True,
    }


def _claim_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _claim_int(value: Any) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return 0


def _validate_id_token_claims(
    claims: Dict[str, Any],
    *,
    config: Dict[str, Any],
    nonce_hash: str,
) -> Dict[str, Any]:
    now = _now()
    issuer = str(claims.get("iss") or "").strip()
    if issuer not in {GOOGLE_ISSUER, GOOGLE_ISSUER_ALT}:
        return error("google_oidc_issuer_invalid", 401, issuer=_clean_text(issuer, 80), raw_secret_echoed=False)
    audience = claims.get("aud")
    audiences = [str(item) for item in audience] if isinstance(audience, list) else [str(audience or "")]
    if str(config.get("client_id") or "") not in audiences:
        return error("google_oidc_audience_invalid", 401, raw_secret_echoed=False)
    expires_at = _claim_int(claims.get("exp"))
    if not expires_at or expires_at <= now - JWT_TIME_SKEW_SECONDS:
        return error("google_oidc_token_expired", 401, raw_secret_echoed=False)
    issued_at = _claim_int(claims.get("iat"))
    if issued_at and issued_at > now + JWT_TIME_SKEW_SECONDS:
        return error("google_oidc_iat_in_future", 401, raw_secret_echoed=False)
    if nonce_hash and not hmac.compare_digest(_hash(claims.get("nonce")), nonce_hash):
        return error("google_oidc_nonce_invalid", 401, raw_secret_echoed=False)
    if not str(claims.get("sub") or "").strip():
        return error("google_oidc_subject_required", 401, raw_secret_echoed=False)
    if not _claim_bool(claims.get("email_verified")):
        return error("google_oidc_email_not_verified", 403, raw_secret_echoed=False)
    hosted_domain = str(config.get("hosted_domain") or "").strip().lower()
    if hosted_domain and str(claims.get("hd") or "").strip().lower() != hosted_domain:
        return error("google_oidc_hosted_domain_invalid", 403, raw_secret_echoed=False)
    return {"ok": True, "claims_valid": True}


def _validate_id_token(id_token: str, *, workspace_id: str, nonce_hash: str) -> Dict[str, Any]:
    config = _google_config(workspace_id)
    parts = _jwt_parts(id_token)
    if parts.get("ok") is not True:
        return parts
    signature = _validate_id_token_signature(parts)
    if signature.get("ok") is not True:
        return signature
    claims = _as_dict(parts.get("claims"))
    claim_status = _validate_id_token_claims(claims, config=config, nonce_hash=nonce_hash)
    if claim_status.get("ok") is not True:
        return claim_status
    account_policy = _validate_account_policy(claims)
    if account_policy.get("ok") is not True:
        return account_policy
    email = str(claims.get("email") or "").strip().lower()
    return {
        "ok": True,
        "claims": claims,
        "google_identity": {
            "subject_hash": _hash(claims.get("sub")),
            "subject_hint": _hint(claims.get("sub")),
            "email_hash": _hash_email(email),
            "email_hint": _hint(email),
            "email_domain": account_policy.get("email_domain", ""),
            "email_verified": True,
            "name_hint": _hint(claims.get("name")),
            "issuer": str(claims.get("iss") or ""),
            "audience_verified": True,
            "nonce_verified": True,
            "signature_verified": True,
            "kid": signature.get("kid", ""),
            "jwks_source": signature.get("jwks_source", ""),
            "raw_claims_returned": False,
        },
        "account_policy": account_policy.get("account_policy", {}),
        "raw_secret_echoed": False,
    }


def _role_and_scopes(context: Dict[str, Any]) -> Dict[str, Any]:
    default_role = _clean_slug(os.getenv("LIVEUIN_GOOGLE_DEFAULT_ROLE"), "operator", 80)
    if default_role not in identity_session.ROLE_DEFAULT_SCOPES:
        default_role = "operator"
    role = default_role
    if _env_bool("LIVEUIN_GOOGLE_ALLOW_SURFACE_ROLE_POLICY", False):
        requested = _clean_slug(context.get("role_requested"), default_role, 80)
        if requested in {"operator", "ops", "connector_admin", "parent", "student", "guardian"}:
            role = requested
    return {
        "role": role,
        "scopes": identity_session.ROLE_DEFAULT_SCOPES.get(role, identity_session.ROLE_DEFAULT_SCOPES["operator"]),
        "role_source": "surface_policy" if role != default_role else "server_default",
    }


def _link_identity_and_issue_session(
    *,
    claims: Dict[str, Any],
    validation: Dict[str, Any],
    state_record: Dict[str, Any],
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    workspace_id = _clean_workspace(state_record.get("workspace_id") or DEFAULT_WORKSPACE_ID)
    context = _as_dict(state_record.get("request_context"))
    email = str(claims.get("email") or "").strip().lower()
    subject = str(claims.get("sub") or "").strip()
    access = workspace_access.resolve_google_workspace_access(
        workspace_id=workspace_id,
        email=email,
        email_verified=True,
        context=context,
        request_meta=request_meta,
    )
    if access.get("ok") is not True:
        return error(
            str(access.get("detail") or "google_workspace_access_denied"),
            int(access.get("status_code") or 403),
            workspace_access=access,
            raw_secret_echoed=False,
        )
    role_context = _as_dict(access.get("role_context"))
    linked = identity_svc.link_identity(
        {
            "workspace_id": workspace_id,
            "provider": "google_oidc",
            "provider_user_id": subject,
            "provider_app_id": _google_config(workspace_id)["client_id"],
            "verified_state": "verified",
            "surface": context.get("surface") or "ops_auth_shell",
            "channel": "google_oidc",
            "person": {
                "display_name": _clean_text(claims.get("name") or email or "Google user", 160),
                "locale": _clean_text(context.get("locale") or "en", 20),
                "role_flags": [role_context["role"]],
                "contacts": {"email_hash": _hash_email(email)} if email else {},
            },
            "consent": {
                "accepted": True,
                "scope": "google_oidc_login",
                "version": "google_oidc_v1",
                "source": "google_oidc",
                "notice": "Google authenticated this account for LiveUIN login.",
            },
            "metadata": {
                "canonical_owner": CANONICAL_OWNER,
                "google_subject_hash": _hash(subject),
                "google_email_hash": _hash_email(email),
                "google_email_verified": True,
                "google_kid": _as_dict(validation.get("google_identity")).get("kid", ""),
                "workspace_access_source": access.get("source", ""),
                "workspace_membership_id": _as_dict(access.get("membership")).get("membership_id", ""),
                "workspace_role_source": role_context.get("role_source", ""),
                "raw_google_tokens_stored": False,
                "raw_google_claims_stored": False,
            },
        },
        request_meta=request_meta,
    )
    if linked.get("ok") is not True:
        return error(
            str(linked.get("detail") or "google_identity_link_failed"),
            int(linked.get("status_code") or 500),
            identity_link=linked,
            raw_secret_echoed=False,
        )
    person_id = _clean_text(linked.get("person_id"), 96)
    membership_id = _clean_text(_as_dict(access.get("membership")).get("membership_id"), 120)
    if membership_id and person_id:
        workspace_access.bind_membership_person(membership_id, person_id, request_meta=request_meta)
    session_result = identity_session.issue_session(
        {
            "workspace_id": workspace_id,
            "actor_id": "person:" + person_id if person_id else "google:" + _hash(subject)[:16],
            "role": role_context["role"],
            "scopes": role_context["scopes"],
            "ttl_seconds": int(os.getenv("LIVEUIN_GOOGLE_SESSION_TTL_SECONDS") or DEFAULT_SESSION_TTL_SECONDS),
            "auth_method": "google_oidc",
            "metadata": {
                "provider": "google_oidc",
                "identity_link_id": _as_dict(linked.get("identity_link")).get("identity_link_id", ""),
                "person_id": person_id,
                "google_subject_hash": _hash(subject),
                "google_email_hash": _hash_email(email),
                "google_email_verified": True,
                "google_kid": _as_dict(validation.get("google_identity")).get("kid", ""),
                "oauth_state_hash": state_record.get("state_hash", ""),
                "workspace_access_source": access.get("source", ""),
                "workspace_membership_id": membership_id,
                "workspace_role_source": role_context.get("role_source", ""),
                "surface": context.get("surface") or "ops_auth_shell",
                "source": context.get("source") or "ops_auth_shell",
                "raw_google_code_stored": False,
                "raw_google_tokens_stored": False,
            },
        },
        request_meta=request_meta,
    )
    if session_result.get("ok") is not True:
        return session_result
    return {
        "ok": True,
        "identity_link": linked,
        "session_result": session_result,
        "role_context": role_context,
        "workspace_access": access,
    }


def _cookie_header(name: str, value: str, *, max_age: int, secure: bool = True, domain: str = "") -> str:
    jar = SimpleCookie()
    jar[name] = value
    morsel = jar[name]
    morsel["path"] = "/"
    morsel["max-age"] = str(max(0, max_age))
    morsel["httponly"] = True
    morsel["samesite"] = "Lax"
    if domain:
        morsel["domain"] = domain
    if secure:
        morsel["secure"] = True
    return morsel.OutputString()


def _session_cookie_domain(request_context: Dict[str, Any] | None = None, return_to: str = "") -> str:
    context = _as_dict(request_context)
    candidates = [
        str(context.get("host") or "").split(":", 1)[0].strip().lower(),
        str(urlparse(str(return_to or "")).hostname or "").strip().lower(),
    ]
    for host in candidates:
        if not host or host in {"localhost", "127.0.0.1", "host.docker.internal"}:
            continue
        if host == "liveuin.com" or host.endswith(".liveuin.com"):
            return ".liveuin.com"
    return ""


def _session_cookie_headers(session_result: Dict[str, Any], *, request_context: Dict[str, Any] | None = None, return_to: str = "") -> List[str]:
    credential = _as_dict(session_result.get("one_time_credential"))
    headers = _as_dict(credential.get("session_headers"))
    expires_at = _claim_int(credential.get("expires_at"))
    max_age = max(0, expires_at - _now()) if expires_at else DEFAULT_SESSION_TTL_SECONDS
    secure = not _env_bool("LIVEUIN_AUTH_COOKIE_ALLOW_INSECURE_LOCALHOST", False)
    domain = _session_cookie_domain(request_context, return_to)
    mapping = {
        "LIVEUIN_WORKSPACE_ID": headers.get("X-LiveUIN-Workspace-Id", ""),
        "LIVEUIN_ACTOR_ID": headers.get("X-LiveUIN-Actor-Id", ""),
        "LIVEUIN_ROLE": headers.get("X-LiveUIN-Role", ""),
        "LIVEUIN_SCOPES": headers.get("X-LiveUIN-Scopes", ""),
        "LIVEUIN_SESSION_ID": credential.get("session_id", ""),
        "LIVEUIN_SESSION_ISSUED_AT": headers.get("X-LiveUIN-Session-Issued-At", ""),
        "LIVEUIN_AUTH_METHOD": headers.get("X-LiveUIN-Auth-Method", ""),
        "LIVEUIN_SESSION_SIGNATURE": headers.get("X-LiveUIN-Session-Signature", ""),
    }
    return [_cookie_header(name, str(value), max_age=max_age, secure=secure, domain=domain) for name, value in mapping.items() if value]


def _b64url_json(value: Dict[str, Any]) -> str:
    payload = json.dumps(value or {}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def _native_runtime_source_host(request_context: Dict[str, Any] | None = None) -> str:
    context = _as_dict(request_context)
    host = str(context.get("host") or "").split(":", 1)[0].strip().lower()
    if not host:
        return ""
    if host in {"liveuin.com", "www.liveuin.com"}:
        return "app.liveuin.com"
    if host.endswith(".liveuin.com") or host.endswith(".laijuzhu.com"):
        return host
    return ""


def _with_query_values(url: str, values: Dict[str, str]) -> str:
    parsed = urlparse(url)
    existing = parse_qsl(parsed.query, keep_blank_values=True)
    seen = {key for key, _ in existing}
    for key, value in values.items():
        if not key or not value or key in seen:
            continue
        existing.append((key, value))
    next_query = urlencode(existing)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, next_query, parsed.fragment))


def _native_resident_redirect_url(
    return_to: str,
    session_result: Dict[str, Any],
    request_context: Dict[str, Any] | None = None,
) -> str:
    credential = _as_dict(session_result.get("one_time_credential"))
    if not credential:
        return return_to
    values = {
        "one_time_credential_b64": _b64url_json(credential),
        "liveuin_source_host": _native_runtime_source_host(request_context),
    }
    return _with_query_values(return_to, values)


def google_callback_response(
    query: Dict[str, List[str]] | None = None,
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    query = query if isinstance(query, dict) else {}
    if query.get("error"):
        return error(
            "google_oauth_denied",
            403,
            provider_error=_clean_text(query.get("error", [""])[0], 120),
            provider_error_description=_clean_text(query.get("error_description", [""])[0], 240),
            raw_secret_echoed=False,
        )
    code = str((query.get("code") or [""])[0]).strip()
    state = str((query.get("state") or [""])[0]).strip()
    if not code:
        return error("google_oauth_code_required", 400, raw_secret_echoed=False)
    if not state:
        return error("google_oauth_state_required", 400, raw_secret_echoed=False)
    consumed = _consume_state(state)
    if consumed.get("ok") is not True:
        return consumed

    workspace_id = _clean_workspace(consumed.get("workspace_id") or DEFAULT_WORKSPACE_ID)
    exchange = _exchange_authorization_code(
        code=code,
        workspace_id=workspace_id,
        redirect_uri=str(consumed.get("redirect_uri") or ""),
        request_meta=request_meta,
    )
    if exchange.get("ok") is not True:
        return exchange

    validation = _validate_id_token(
        str(exchange.get("id_token") or ""),
        workspace_id=workspace_id,
        nonce_hash=str(consumed.get("nonce_hash") or ""),
    )
    if validation.get("ok") is not True:
        return validation

    issued = _link_identity_and_issue_session(
        claims=_as_dict(validation.get("claims")),
        validation=validation,
        state_record=consumed,
        request_meta=request_meta,
    )
    if issued.get("ok") is not True:
        return issued

    session_result = _as_dict(issued.get("session_result"))
    request_context = _as_dict(consumed.get("request_context"))
    return_to = _final_return_url(str(consumed.get("return_to") or ""), request_context)
    redirect_url = (
        _native_resident_redirect_url(return_to, session_result, request_context)
        if urlparse(return_to).scheme in ALLOWED_NATIVE_RETURN_TO_SCHEMES
        else return_to
    )
    return _redact(
        {
            "ok": True,
            "schema_version": SCHEMA_VERSION,
            "phase": PHASE,
            "status": "google_oidc_login_verified",
            "status_code": 302,
            "redirect_url": redirect_url,
            "canonical_owner": CANONICAL_OWNER,
            "workspace_id": workspace_id,
            "google_identity": validation.get("google_identity", {}),
            "identity_link": _as_dict(issued.get("identity_link")).get("identity_link", {}),
            "workspace_access": _as_dict(issued.get("workspace_access")),
            "session": session_result.get("session", {}),
            "one_time_credential": session_result.get("one_time_credential", {}),
            "set_cookie_headers": _session_cookie_headers(
                session_result,
                request_context=request_context,
                return_to=return_to,
            ),
            "state": {
                "state_hash": consumed.get("state_hash", ""),
                "state_hint": consumed.get("state_hint", ""),
                "workspace_id": workspace_id,
                "return_to": return_to,
                "consumed_at_iso": consumed.get("consumed_at_iso", _now_iso()),
                "raw_secret_echoed": False,
            },
            "boundary": {
                "surface": "ops auth shell and connector/operator auth handoff",
                "layer": "Google OIDC callback into LiveUIN session issuer",
                "owner": CANONICAL_OWNER,
                "google_role": "authentication provider and consent screen only",
                "session_owner": "LiveUIN Identity",
                "connector_role": "SSO handoff only; no connector-owned session truth",
            },
            "raw_secret_returned_once": True,
            "raw_secret_stored": False,
        }
    )


def google_oauth_state_status(limit: int = 100) -> Dict[str, Any]:
    limit = max(1, min(int(limit or 100), 500))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT state_hash, nonce_hash, workspace_id, return_to, redirect_uri,
                   status, issued_at, expires_at, consumed_at
            FROM identity_google_oauth_states
            ORDER BY issued_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    states = []
    for row in rows:
        item = dict(row)
        item["issued_at_iso"] = _iso_from_epoch(item.get("issued_at"))
        item["expires_at_iso"] = _iso_from_epoch(item.get("expires_at"))
        item["consumed_at_iso"] = _iso_from_epoch(item.get("consumed_at"))
        item["raw_secret_echoed"] = False
        states.append(item)
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "canonical_owner": CANONICAL_OWNER,
        "state_count": len(states),
        "states": states,
        "sqlite_path": str(_sqlite_path()),
        "raw_secret_echoed": False,
    }
