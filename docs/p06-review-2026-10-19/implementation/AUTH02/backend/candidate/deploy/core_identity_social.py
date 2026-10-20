from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, Mapping

try:
    from . import core_identity_public as public_identity
    from . import core_identity_public_store as store
    from . import core_identity_service as identity_svc
    from . import core_identity_store as identity_store
    from . import core_identity_session as identity_session
    from . import core_identity_provider_credentials as provider_credentials
    from . import core_service_secret_resolver as service_secrets
except ImportError:  # pragma: no cover - supports direct app-folder deployment.
    import core_identity_public as public_identity
    import core_identity_public_store as store
    import core_identity_service as identity_svc
    import core_identity_store as identity_store
    import core_identity_session as identity_session
    import core_identity_provider_credentials as provider_credentials
    import core_service_secret_resolver as service_secrets


SCHEMA_VERSION = "liveuin-core-identity-social-v1"
PHASE = "p2a2-provider-neutral-public-identity-foundation"
CANONICAL_OWNER = "LiveUIN Identity/Core"
SUPPORTED_PROVIDERS = {"google", "apple"}
GOOGLE_ISSUERS = {"https://accounts.google.com", "accounts.google.com"}
APPLE_ISSUER = "https://appleid.apple.com"
GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs"
APPLE_JWKS_URI = "https://appleid.apple.com/auth/keys"
APPLE_TOKEN_ENDPOINT = "https://appleid.apple.com/auth/token"
APPLE_REVOKE_ENDPOINT = "https://appleid.apple.com/auth/revoke"
JWT_SKEW_SECONDS = 300
REAUTH_MAX_AGE_SECONDS = 10 * 60
JWKS_CACHE_TTL_SECONDS = 3600

_jwks_cache: Dict[str, tuple[int, Dict[str, Any]]] = {}


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
    return value.strip().lower() in {"1", "true", "yes", "on", "ready", "enabled"}


def _request_id(request_meta: Mapping[str, Any] | None) -> str:
    return _clean((request_meta or {}).get("request_id") or "req_" + uuid.uuid4().hex[:20], 80)


def _error(code: str, status_code: int, message: str, request_meta: Mapping[str, Any] | None = None, **extra: Any) -> Dict[str, Any]:
    return {
        "ok": False,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status_code": status_code,
        "error": {
            "code": code,
            "message": message,
            "field": extra.pop("field", None),
            "recoverable": bool(extra.pop("recoverable", status_code < 500)),
            "next_action": extra.pop("next_action", "retry_or_contact_support"),
        },
        "request_id": _request_id(request_meta),
        "canonical_owner": CANONICAL_OWNER,
        "raw_provider_payload_echoed": False,
        "raw_provider_token_stored": False,
        **extra,
    }


def _provider(value: Any) -> str:
    normalized = _clean(value, 24).lower()
    return normalized if normalized in SUPPORTED_PROVIDERS else ""


def _provider_config(provider: str) -> Dict[str, Any]:
    provider = _provider(provider)
    if provider == "google":
        client_id = _clean(os.getenv("LIVEUIN_GOOGLE_CLIENT_ID"), 240)
        native_id_token_ready = _bool_env("LIVEUIN_GOOGLE_NATIVE_ID_TOKEN_READY")
        blockers = []
        if not client_id:
            blockers.append("client_id_missing")
        if native_id_token_ready:
            flow_mode = "native_id_token"
        else:
            flow_mode = "authorization_code"
            if not _bool_env("LIVEUIN_GOOGLE_OIDC_TOKEN_EXCHANGE_READY"):
                blockers.append("token_exchange_configuration_not_validated")
            if not _bool_env("LIVEUIN_GOOGLE_OIDC_CALLBACK_VALIDATION_READY"):
                blockers.append("callback_validation_configuration_not_validated")
            if not _clean(os.getenv("LIVEUIN_GOOGLE_REDIRECT_URI"), 500):
                blockers.append("redirect_uri_missing")
            if not _clean(os.getenv("LIVEUIN_GOOGLE_CLIENT_SECRET_REF"), 240):
                blockers.append("client_secret_reference_missing")
        jwks_uri = GOOGLE_JWKS_URI
    elif provider == "apple":
        client_id = _clean(os.getenv("LIVEUIN_APPLE_CLIENT_ID") or os.getenv("LIVEUIN_APPLE_SERVICE_ID"), 240)
        native_id_token_ready = _bool_env("LIVEUIN_APPLE_NATIVE_ID_TOKEN_READY")
        blockers = []
        if not client_id:
            blockers.append("client_id_missing")
        if native_id_token_ready:
            flow_mode = "native_id_token"
            if not _bool_env("LIVEUIN_APPLE_TOKEN_EXCHANGE_READY"):
                blockers.append("authorization_code_exchange_not_ready")
            if not _clean(os.getenv("LIVEUIN_APPLE_CLIENT_SECRET_REF"), 240):
                blockers.append("client_secret_reference_missing")
        else:
            flow_mode = "authorization_code"
            if not _bool_env("LIVEUIN_APPLE_TOKEN_EXCHANGE_READY"):
                blockers.append("authorization_code_exchange_not_ready")
            if not _clean(os.getenv("LIVEUIN_APPLE_REDIRECT_URI"), 500):
                blockers.append("redirect_uri_missing")
            if not _clean(os.getenv("LIVEUIN_APPLE_CLIENT_SECRET_REF"), 240):
                blockers.append("client_secret_reference_missing")
        if not _clean(os.getenv("LIVEUIN_APPLE_TEAM_ID"), 40):
            blockers.append("team_id_missing")
        if not _clean(os.getenv("LIVEUIN_APPLE_KEY_ID"), 40):
            blockers.append("key_id_missing")
        if not _clean(os.getenv("LIVEUIN_APPLE_PRIVATE_KEY_REF"), 240):
            blockers.append("private_key_reference_missing")
        jwks_uri = APPLE_JWKS_URI
    else:
        return {"provider": "", "ready": False, "blockers": ["provider_invalid"]}

    pepper_ref_env = "LIVEUIN_APPLE_SUBJECT_PEPPER_REF" if provider == "apple" else "LIVEUIN_IDENTITY_PROVIDER_SUBJECT_PEPPER_REF"
    pepper_ready = bool(_clean(os.getenv(pepper_ref_env), 240))
    if not pepper_ready:
        blockers.append("subject_pepper_reference_missing")
    workspace_ready = bool(_clean(os.getenv("LIVEUIN_PUBLIC_WORKSPACE_ID"), 96))
    terms_ready = bool(_clean(os.getenv("LIVEUIN_PUBLIC_TERMS_VERSION"), 80))
    if not workspace_ready:
        blockers.append("public_workspace_missing")
    if not terms_ready:
        blockers.append("public_terms_version_missing")
    client_secret_ready = False
    if provider == "apple" and _clean(os.getenv("LIVEUIN_APPLE_CLIENT_SECRET_REF"), 240):
        client_secret_ready = service_secrets.resolve_identity_provider_client_secret("apple").get("ok") is True
        if not client_secret_ready:
            blockers.append("client_secret_unavailable")
    apple_jwks_ready = False
    if provider == "apple":
        apple_jwks_ready = bool(_as_dict(_jwks(jwks_uri)).get("keys"))
        if not apple_jwks_ready:
            blockers.append("jwks_unavailable")
    apple_configuration_present = bool(
        provider == "apple"
        and client_id
        and native_id_token_ready
        and _clean(os.getenv("LIVEUIN_APPLE_TEAM_ID"), 40)
        and _clean(os.getenv("LIVEUIN_APPLE_KEY_ID"), 40)
        and _clean(os.getenv("LIVEUIN_APPLE_PRIVATE_KEY_REF"), 240)
        and _clean(os.getenv("LIVEUIN_APPLE_CLIENT_SECRET_REF"), 240)
        and pepper_ready
        and workspace_ready
        and terms_ready
    )
    apple_token_validation_ready = bool(provider == "apple" and apple_configuration_present and apple_jwks_ready)
    apple_authorization_code_exchange_ready = bool(
        provider == "apple"
        and apple_configuration_present
        and client_secret_ready
        and _bool_env("LIVEUIN_APPLE_TOKEN_EXCHANGE_READY")
    )
    apple_mobile_integration_ready = bool(
        provider == "apple"
        and apple_configuration_present
        and apple_token_validation_ready
        and apple_authorization_code_exchange_ready
    )
    if provider == "apple" and not apple_token_validation_ready:
        blockers.append("token_validation_not_ready")
    if provider == "apple" and not apple_authorization_code_exchange_ready:
        blockers.append("authorization_code_exchange_not_ready")
    return {
        "provider": provider,
        "ready": not blockers,
        "client_id": client_id,
        "public_enabled": _bool_env(f"LIVEUIN_PUBLIC_{provider.upper()}_IDENTITY_ENABLED"),
        "native_id_token_ready": native_id_token_ready,
        "flow_mode": flow_mode,
        "client_id_configured": bool(client_id),
        "client_secret_reference_configured": bool(_clean(os.getenv(f"LIVEUIN_{provider.upper()}_CLIENT_SECRET_REF"), 240)),
        "client_secret_ready": client_secret_ready,
        "subject_pepper_reference_configured": pepper_ready,
        "issuer": APPLE_ISSUER if provider == "apple" else "",
        "jwks_uri": jwks_uri,
        "token_endpoint": APPLE_TOKEN_ENDPOINT if provider == "apple" else "",
        "revoke_endpoint": APPLE_REVOKE_ENDPOINT if provider == "apple" else "",
        "apple_configuration_present": apple_configuration_present,
        "apple_jwks_ready": apple_jwks_ready,
        "apple_client_secret_ready": client_secret_ready,
        "apple_token_validation_ready": apple_token_validation_ready,
        "apple_authorization_code_exchange_ready": apple_authorization_code_exchange_ready,
        "apple_revocation_ready": bool(
            provider == "apple"
            and (_bool_env("LIVEUIN_APPLE_REVOCATION_READY") or provider_credentials.capability_status().get("ready") is True)
            and client_secret_ready
            and bool(client_id)
        ),
        "apple_private_relay_ready": bool(provider == "apple" and _bool_env("LIVEUIN_APPLE_PRIVATE_RELAY_READY")),
        "apple_mobile_integration_ready": apple_mobile_integration_ready,
        "apple_public_identity_enabled": bool(provider == "apple" and _bool_env("LIVEUIN_PUBLIC_APPLE_IDENTITY_ENABLED")),
        "blockers": sorted(set(blockers)),
        "raw_secret_echoed": False,
    }


def provider_status(workspace_id: str = "", request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    configured_workspace = _clean(os.getenv("LIVEUIN_PUBLIC_WORKSPACE_ID"), 96)
    requested_workspace = _clean(workspace_id, 96)
    workspace_match = not requested_workspace or requested_workspace == configured_workspace
    google = _provider_config("google")
    apple = _provider_config("apple")
    graph_status = identity_graph_integrity_status(configured_workspace if workspace_match else "", request_meta)
    google_public = {key: value for key, value in google.items() if key != "client_id"}
    apple_public = {key: value for key, value in apple.items() if key != "client_id"}
    link_ready = bool(
        configured_workspace
        and _clean(os.getenv("LIVEUIN_IDENTITY_PROVIDER_SUBJECT_PEPPER_REF"), 240)
        and _clean(os.getenv("LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET_REF"), 240)
        and (google["ready"] or apple["ready"])
        and bool(graph_status.get("ok"))
    )
    return {
        "ok": workspace_match,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "canonical_owner": CANONICAL_OWNER,
        "workspace_id": configured_workspace if workspace_match else "",
        "google_public_identity_ready": bool(google["ready"] and workspace_match),
        "apple_public_identity_ready": bool(apple["ready"] and workspace_match),
        "apple_configuration_present": bool(apple.get("apple_configuration_present") and workspace_match),
        "apple_jwks_ready": bool(apple.get("apple_jwks_ready") and workspace_match),
        "apple_client_secret_ready": bool(apple.get("apple_client_secret_ready") and workspace_match),
        "apple_token_validation_ready": bool(apple.get("apple_token_validation_ready") and workspace_match),
        "apple_authorization_code_exchange_ready": bool(apple.get("apple_authorization_code_exchange_ready") and workspace_match),
        "apple_revocation_ready": bool(apple.get("apple_revocation_ready") and workspace_match),
        "apple_private_relay_ready": bool(apple.get("apple_private_relay_ready") and workspace_match),
        "apple_mobile_integration_ready": bool(apple.get("apple_mobile_integration_ready") and workspace_match),
        "apple_public_identity_enabled": bool(apple.get("apple_public_identity_enabled") and workspace_match),
        "social_account_linking_ready": bool(link_ready and workspace_match),
        "identity_graph_integrity_ready": bool(graph_status.get("ok") and workspace_match),
        "providers": {"google": google_public, "apple": apple_public},
        "mobile_enablement_allowed": False,
        "raw_provider_payload_echoed": False,
        "request_id": _request_id(request_meta),
    }


def _b64url_decode(value: Any) -> bytes:
    text = str(value or "")
    return base64.urlsafe_b64decode((text + "=" * (-len(text) % 4)).encode("ascii"))


def _b64url_json(value: Any) -> Dict[str, Any]:
    parsed = json.loads(_b64url_decode(value).decode("utf-8"))
    return parsed if isinstance(parsed, dict) else {}


def _http_json(url: str, *, form: Dict[str, str] | None = None) -> Dict[str, Any]:
    body = urllib.parse.urlencode(form or {}).encode("utf-8") if form is not None else None
    headers = {"Accept": "application/json", "User-Agent": "LiveUIN-Identity-Core/1"}
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data=body, headers=headers, method="POST" if form is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            value = json.loads(response.read(2_000_000).decode("utf-8"))
            return value if isinstance(value, dict) else {}
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError):
        return {}


def _jwks(uri: str) -> Dict[str, Any]:
    now = _now()
    cached = _jwks_cache.get(uri)
    if cached and cached[0] > now:
        return cached[1]
    document = _http_json(uri)
    if isinstance(document.get("keys"), list):
        _jwks_cache[uri] = (now + JWKS_CACHE_TTL_SECONDS, document)
    return document


def _rsa_rs256_valid(signing_input: bytes, signature: bytes, jwk: Mapping[str, Any]) -> bool:
    if str(jwk.get("kty") or "") != "RSA" or str(jwk.get("alg") or "RS256") != "RS256":
        return False
    try:
        modulus = int.from_bytes(_b64url_decode(jwk.get("n")), "big")
        exponent = int.from_bytes(_b64url_decode(jwk.get("e")), "big")
        if modulus.bit_length() < 2048 or exponent < 3:
            return False
        size = (modulus.bit_length() + 7) // 8
        encoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(size, "big")
        digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(signing_input).digest()
        padding = b"\x00\x01" + (b"\xff" * (size - len(digest_info) - 3)) + b"\x00" + digest_info
        return hmac.compare_digest(encoded, padding)
    except (TypeError, ValueError, OverflowError):
        return False


def _claims_from_token(provider: str, token: str, nonce: str) -> Dict[str, Any]:
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return _error("provider_token_invalid", 401, "The provider sign-in could not be verified.", next_action="try_again")
    try:
        header = _b64url_json(parts[0])
        claims = _b64url_json(parts[1])
        signature = _b64url_decode(parts[2])
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return _error("provider_token_invalid", 401, "The provider sign-in could not be verified.", next_action="try_again")
    if header.get("alg") != "RS256" or not header.get("kid"):
        return _error("provider_token_invalid", 401, "The provider sign-in could not be verified.", next_action="try_again")
    config = _provider_config(provider)
    keys = _as_dict(_jwks(config.get("jwks_uri"))).get("keys") or []
    jwk = next((item for item in keys if isinstance(item, dict) and item.get("kid") == header.get("kid")), None)
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    if not jwk or not _rsa_rs256_valid(signing_input, signature, jwk):
        return _error("provider_token_invalid", 401, "The provider sign-in could not be verified.", next_action="try_again")
    issuer = _clean(claims.get("iss"), 240)
    expected_issuers = GOOGLE_ISSUERS if provider == "google" else {APPLE_ISSUER}
    if issuer not in expected_issuers:
        return _error("provider_token_invalid", 401, "The provider sign-in could not be verified.", next_action="try_again", validation_failure="issuer")
    audience = claims.get("aud")
    audiences = [audience] if isinstance(audience, str) else audience if isinstance(audience, list) else []
    if config.get("client_id") and config.get("client_id") not in audiences:
        return _error("provider_token_invalid", 401, "The provider sign-in could not be verified.", next_action="try_again", validation_failure="audience")
    try:
        expires_at = int(claims.get("exp") or 0)
        issued_at = int(claims.get("iat") or 0)
    except (TypeError, ValueError):
        expires_at = issued_at = 0
    now = _now()
    if not expires_at or not issued_at or expires_at < now - JWT_SKEW_SECONDS or issued_at > now + JWT_SKEW_SECONDS:
        return _error("provider_token_invalid", 401, "The provider sign-in could not be verified.", next_action="try_again", validation_failure="time")
    subject = _clean(claims.get("sub"), 256)
    token_nonce = _clean(claims.get("nonce"), 240)
    if not subject or not nonce or not token_nonce or not hmac.compare_digest(token_nonce, nonce):
        return _error("provider_token_invalid", 401, "The provider sign-in could not be verified.", next_action="try_again", validation_failure="nonce")
    email_verified = claims.get("email_verified") is True or str(claims.get("email_verified") or "").lower() == "true"
    email = _clean(claims.get("email"), 320).lower()
    if email and ("@" not in email or "." not in email.rsplit("@", 1)[-1]):
        email = ""
    if not email_verified:
        email = ""
    return {
        "ok": True,
        "provider": provider,
        "subject": subject,
        # Never persist or echo a provider subject, even as a convenience hint.
        # The stable external subject is represented only by its protected hash.
        "subject_hint": "sid_" + hashlib.sha256(subject.encode("utf-8")).hexdigest()[:12],
        "email": email,
        "email_verified": email_verified,
        "name": _clean(claims.get("name") or " ".join(item for item in [claims.get("given_name"), claims.get("family_name")] if item), 160),
        "locale": _clean(claims.get("locale"), 20),
        "token_hash": hashlib.sha256(str(token or "").encode("utf-8")).hexdigest(),
        "nonce_hash": hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
        "expires_at": expires_at,
    }


def _provider_client_id(provider: str) -> str:
    if provider == "google":
        return _clean(os.getenv("LIVEUIN_GOOGLE_CLIENT_ID"), 240)
    return _clean(os.getenv("LIVEUIN_APPLE_CLIENT_ID") or os.getenv("LIVEUIN_APPLE_SERVICE_ID"), 240)


def _exchange_authorization_code(provider: str, code: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
    secret = service_secrets.resolve_identity_provider_client_secret(provider)
    if secret.get("ok") is not True:
        return _error("provider_not_ready", 503, "This sign-in method is not available yet.", next_action="use_email_password")
    endpoint = "https://oauth2.googleapis.com/token" if provider == "google" else "https://appleid.apple.com/auth/token"
    redirect_uri = _clean(payload.get("redirect_uri") or os.getenv(f"LIVEUIN_{provider.upper()}_REDIRECT_URI"), 500)
    verifier = _clean(payload.get("code_verifier"), 240)
    if provider == "google" and (not redirect_uri or not verifier):
        return _error("provider_token_invalid", 401, "The provider sign-in could not be verified.", next_action="try_again")
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": _provider_client_id(provider),
        "client_secret": str(secret.get("secret") or ""),
    }
    if redirect_uri:
        form["redirect_uri"] = redirect_uri
    if verifier:
        form["code_verifier"] = verifier
    response = _http_json(endpoint, form=form)
    token = _clean(response.get("id_token"), 20000)
    if not token:
        return _error("provider_token_invalid", 401, "The provider sign-in could not be verified.", next_action="try_again")
    provider_token_response = {
        "refresh_token": _clean(response.get("refresh_token"), 20000),
        "access_token": _clean(response.get("access_token"), 20000),
        "token_type": _clean(response.get("token_type") or "refresh_token", 32),
        "expires_in": int(response.get("expires_in") or 0),
    }
    return {
        "ok": True,
        "id_token": token,
        "authorization_code_hash": hashlib.sha256(code.encode("utf-8")).hexdigest(),
        "provider_token_response": provider_token_response,
    }


def _subject_hash(provider: str, subject: str) -> str:
    resolved = service_secrets.resolve_identity_provider_subject_pepper_for(provider)
    if resolved.get("ok") is not True:
        raise RuntimeError("provider_subject_pepper_unavailable")
    pepper = str(resolved.get("secret") or "").encode("utf-8")
    return hmac.new(pepper, f"{provider}:{subject}".encode("utf-8"), hashlib.sha256).hexdigest()


def _verified_claims(provider: str, payload: Mapping[str, Any], request_meta: Mapping[str, Any] | None) -> Dict[str, Any]:
    if _as_dict(payload).get("provider_access_token") or _as_dict(payload).get("access_token"):
        return _error("provider_access_token_not_accepted", 400, "This sign-in method could not be completed.", request_meta, next_action="try_again")
    nonce = _clean(payload.get("nonce"), 240)
    if not nonce:
        return _error("nonce_required", 400, "This sign-in method could not be completed.", request_meta, next_action="try_again")
    id_token = _clean(payload.get("id_token"), 20000)
    authorization_code = _clean(payload.get("authorization_code") or payload.get("code"), 1000)
    if bool(id_token) == bool(authorization_code):
        return _error("provider_token_required", 400, "This sign-in method could not be completed.", request_meta, next_action="try_again")
    state = _clean(payload.get("state"), 240)
    if authorization_code and not state:
        return _error("state_required", 400, "This sign-in method could not be completed.", request_meta, next_action="try_again")
    if authorization_code and not hmac.compare_digest(state, nonce):
        return _error("state_invalid", 401, "This sign-in method could not be verified.", request_meta, next_action="try_again")
    config = _provider_config(provider)
    if not config.get("ready"):
        return _error("provider_not_ready", 503, "This sign-in method is not available yet.", request_meta, next_action="use_email_password", readiness_blockers=config.get("blockers", []))
    if not config.get("public_enabled"):
        return _error("provider_not_ready", 503, "This sign-in method is not available yet.", request_meta, next_action="use_email_password", readiness_blockers=["public_enablement_disabled"])
    authorization_code_hash = ""
    provider_token_response: Dict[str, Any] = {}
    if authorization_code:
        exchanged = _exchange_authorization_code(provider, authorization_code, payload)
        if exchanged.get("ok") is not True:
            exchanged["request_id"] = _request_id(request_meta)
            return exchanged
        id_token = exchanged["id_token"]
        authorization_code_hash = exchanged.get("authorization_code_hash", "")
        provider_token_response = _as_dict(exchanged.get("provider_token_response"))
    claims = _claims_from_token(provider, id_token, nonce)
    if claims.get("ok") is not True:
        claims["request_id"] = _request_id(request_meta)
        return claims
    try:
        subject_hash = _subject_hash(provider, claims["subject"])
    except RuntimeError:
        return _error("provider_not_ready", 503, "This sign-in method is not available yet.", request_meta, next_action="use_email_password")
    workspace_id = _clean(os.getenv("LIVEUIN_PUBLIC_WORKSPACE_ID"), 96)
    replay_expiry = min(int(claims.get("expires_at") or (_now() + 600)), _now() + 3600)
    replay_values = [("provider_token", claims["token_hash"]), ("provider_nonce", claims["nonce_hash"])]
    if authorization_code_hash:
        replay_values.append(("authorization_code", authorization_code_hash))
    for replay_kind, value in replay_values:
        if not store.consume_provider_replay(workspace_id=workspace_id, provider=provider, replay_kind=replay_kind, value=value, expires_at=replay_expiry):
            return _error("provider_token_replay", 401, "This sign-in attempt has already been used. Start again.", request_meta, next_action="try_again")
    claims["subject_hash"] = subject_hash
    claims["verified_email_hash"] = public_identity._email_hash(claims.get("email")) if claims.get("email_verified") and claims.get("email") else ""
    claims["provider_token_response"] = provider_token_response
    return claims


def _store_provider_credential(
    provider: str,
    account: Mapping[str, Any],
    provider_identity: Mapping[str, Any],
    claims: Mapping[str, Any],
    request_meta: Mapping[str, Any] | None,
) -> Dict[str, Any]:
    if provider != "apple":
        return {"ok": True, "stored": False, "provider": provider}
    token_response = _as_dict(claims.get("provider_token_response"))
    refresh_token = _clean(token_response.get("refresh_token"), 20000)
    access_token = _clean(token_response.get("access_token"), 20000)
    existing = provider_credentials.get_for_account(str(account.get("account_id") or ""), str(account.get("workspace_id") or ""), "apple")
    if not refresh_token and not access_token and existing:
        return {"ok": True, "stored": False, "provider": provider, "existing": True}
    if not refresh_token and not access_token:
        return _error(
            "provider_credential_required",
            503,
            "This sign-in method is not available until its secure provider credential is established.",
            request_meta,
            next_action="try_again",
        )
    if provider_credentials.capability_status().get("ready") is not True:
        return _error("provider_credential_store_not_ready", 503, "This sign-in method is not available yet.", request_meta, next_action="use_email_password")
    try:
        result = provider_credentials.upsert(
            workspace_id=str(account.get("workspace_id") or ""),
            account_id=str(account.get("account_id") or ""),
            person_id=str(account.get("person_id") or ""),
            provider=provider,
            provider_link_id=str(provider_identity.get("provider_identity_id") or ""),
            refresh_token=refresh_token,
            access_token=access_token,
            token_type=_clean(token_response.get("token_type") or ("refresh_token" if refresh_token else "access_token"), 32),
            expires_at=_now() + max(0, min(int(token_response.get("expires_in") or 0), 60 * 60 * 24 * 365)),
            issued_at=_now(),
        )
    except (RuntimeError, ValueError, TypeError):
        return _error("provider_credential_store_failed", 503, "This sign-in method could not be completed safely.", request_meta, next_action="try_again")
    if result.get("ok") is not True:
        return _error("provider_credential_store_failed", 503, "This sign-in method could not be completed safely.", request_meta, next_action="try_again")
    return {"ok": True, "stored": True, "provider": provider}


def _apple_credential_preflight(claims: Mapping[str, Any], request_meta: Mapping[str, Any] | None) -> Dict[str, Any]:
    token_response = _as_dict(claims.get("provider_token_response"))
    if not _clean(token_response.get("refresh_token"), 20000) and not _clean(token_response.get("access_token"), 20000):
        return _error(
            "provider_credential_required",
            503,
            "This sign-in method is not available until its secure provider credential is established.",
            request_meta,
            next_action="try_again",
        )
    if provider_credentials.capability_status().get("ready") is not True:
        return _error("provider_credential_store_not_ready", 503, "This sign-in method is not available yet.", request_meta, next_action="use_email_password")
    return {"ok": True}


def _identity_graph_check(
    provider: str,
    account: Mapping[str, Any],
    provider_identity: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    """Validate the public-provider -> account -> canonical-Person graph."""
    configured_workspace = _clean(os.getenv("LIVEUIN_PUBLIC_WORKSPACE_ID"), 96)
    account_id = _clean_id(account.get("account_id"))
    account_workspace = _clean_id(account.get("workspace_id"), 96)
    account_person = _clean_id(account.get("person_id"))
    if not configured_workspace or not account_id or not account_workspace or not account_person:
        return {"ok": False, "code": "graph_account_identity_missing"}
    if account_workspace != configured_workspace:
        return {"ok": False, "code": "graph_workspace_mismatch"}
    link = dict(provider_identity or {})
    if not link:
        candidates = [
            item
            for item in store.list_provider_identities_for_account(account_id, account_workspace)
            if item.get("provider") == provider and item.get("link_state") == "linked"
        ]
        if len(candidates) != 1:
            return {"ok": False, "code": "graph_provider_link_missing_or_ambiguous"}
        link = candidates[0]
    if (
        _clean(link.get("provider"), 32) != provider
        or _clean_id(link.get("account_id")) != account_id
        or _clean_id(link.get("person_id")) != account_person
        or _clean_id(link.get("workspace_id"), 96) != account_workspace
        or _clean(link.get("link_state") or "linked", 32) != "linked"
    ):
        return {"ok": False, "code": "graph_provider_account_person_mismatch"}
    canonical_person = identity_store.get_person(account_person, account_workspace)
    if not canonical_person or _clean_id(canonical_person.get("person_id")) != account_person or _clean_id(canonical_person.get("workspace_id"), 96) != account_workspace:
        return {"ok": False, "code": "graph_canonical_person_missing"}
    return {"ok": True, "provider_identity_id": _clean_id(link.get("provider_identity_id"))}


def identity_graph_integrity_status(workspace_id: str = "", request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    """Return a redacted, fail-closed readiness result for social identity links."""
    configured_workspace = _clean(os.getenv("LIVEUIN_PUBLIC_WORKSPACE_ID"), 96)
    requested_workspace = _clean(workspace_id, 96)
    if not configured_workspace or (requested_workspace and requested_workspace != configured_workspace):
        return {"ok": False, "checked_links": 0, "issue_count": 1, "issues": ["graph_workspace_mismatch"]}
    try:
        links = store.list_provider_identities(configured_workspace, link_state="linked")
        issues = []
        for link in links:
            account = store.get_account(link.get("account_id", ""))
            check = _identity_graph_check(str(link.get("provider") or ""), account, link)
            if check.get("ok") is not True:
                issues.append(str(check.get("code") or "graph_invalid"))
        return {
            "ok": not issues,
            "checked_links": len(links),
            "issue_count": len(issues),
            "issues": sorted(set(issues)),
            "raw_secret_echoed": False,
            "request_id": _request_id(request_meta),
        }
    except Exception:
        return {
            "ok": False,
            "checked_links": 0,
            "issue_count": 1,
            "issues": ["graph_integrity_check_failed"],
            "raw_secret_echoed": False,
            "request_id": _request_id(request_meta),
        }


def _graph_error(request_meta: Mapping[str, Any] | None) -> Dict[str, Any]:
    return _error(
        "identity_graph_integrity_failed",
        503,
        "This sign-in method is temporarily unavailable.",
        request_meta,
        next_action="use_email_password",
    )


def _compensate_new_social_account(account_id: str, person_id: str, workspace_id: str, request_meta: Mapping[str, Any] | None) -> None:
    try:
        store.delete_social_account_if_unissued(account_id, person_id, workspace_id, dict(request_meta or {}))
    finally:
        identity_store.delete_person_if_unreferenced(person_id, workspace_id)


def _account_result(
    provider: str,
    account: Dict[str, Any],
    request_meta: Mapping[str, Any] | None,
    *,
    provider_linked: bool,
    provider_identity: Mapping[str, Any] | None = None,
    status: str = "authenticated",
) -> Dict[str, Any]:
    if public_identity._state(account) in {"account_disabled", "deletion_pending", "account_deleted"}:
        return _error("account_unavailable", 403, "This account is not available.", request_meta, next_action="contact_support")
    if provider_linked:
        graph = _identity_graph_check(provider, account, provider_identity)
        if graph.get("ok") is not True:
            return _graph_error(request_meta)
    session = public_identity._issue_session(account, request_meta, f"public_{provider}")
    if session.get("ok") is False:
        return session
    state = public_identity._state(account)
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": status,
        "provider": provider,
        "provider_linked": provider_linked,
        "profile_state": state,
        "next_action": public_identity._next_action(account),
        "authorized_profiles": public_identity._public_profile_entitlements(account),
        "localpro_authorization_issued": False,
        "account_state": state,
        "request_id": _request_id(request_meta),
        **session,
    }


def _new_social_account(provider: str, claims: Dict[str, Any], workspace_id: str, payload: Mapping[str, Any], request_meta: Mapping[str, Any] | None) -> Dict[str, Any]:
    admission_failure = public_identity._admission_for_hash(claims.get("verified_email_hash") if claims.get("email_verified") is True else None, workspace_id, request_meta)
    if admission_failure:
        return admission_failure
    terms = _clean(payload.get("accepted_terms_version"), 80)
    approved_terms = _clean(os.getenv("LIVEUIN_PUBLIC_TERMS_VERSION"), 80)
    if not terms or terms != approved_terms:
        return _error("terms_required", 400, "Accept the current LiveUIN terms to continue.", request_meta, field="accepted_terms_version", next_action="accept_terms")
    if provider == "apple":
        credential_preflight = _apple_credential_preflight(claims, request_meta)
        if credential_preflight.get("ok") is not True:
            return credential_preflight
    account_id = "acct_" + uuid.uuid4().hex[:20]
    person_id = "per_" + uuid.uuid4().hex[:20]
    now = _now()
    try:
        random_password = secrets.token_urlsafe(48)
        password_hash = public_identity._password_hash(random_password)
    except (RuntimeError, TypeError, ValueError):
        return _error("identity_security_not_ready", 503, "This sign-in method is not available yet.", request_meta, next_action="use_email_password")
    try:
        person = identity_store.upsert_person({
            "person_id": person_id,
            "workspace_id": workspace_id,
            "display_name": claims.get("name", ""),
            "locale": claims.get("locale", "") or "en",
            "role_flags": ["tenant"],
            "contacts": {"email_hash": claims.get("verified_email_hash", "")},
            "consent_state": "accepted",
            "metadata": {"provider_identity": provider, "provider_name_captured": bool(claims.get("name"))},
            "created_at": now,
            "updated_at": now,
        })
    except Exception:
        identity_store.delete_person_if_unreferenced(person_id, workspace_id)
        return _error("identity_graph_integrity_failed", 503, "This sign-in method is temporarily unavailable.", request_meta, next_action="use_email_password")
    if not person or _clean_id(person.get("person_id")) != person_id or _clean_id(person.get("workspace_id"), 96) != workspace_id:
        identity_store.delete_person_if_unreferenced(person_id, workspace_id)
        return _error("identity_graph_integrity_failed", 503, "This sign-in method is temporarily unavailable.", request_meta, next_action="use_email_password")
    provider_identity = {
        "provider_identity_id": "pvid_" + uuid.uuid4().hex[:20],
        "workspace_id": workspace_id,
        "provider": provider,
        "subject_hash": claims["subject_hash"],
        "subject_hint": claims.get("subject_hint", ""),
        "account_id": account_id,
        "person_id": person_id,
        "verified_email_hash": claims.get("verified_email_hash", ""),
        "verified_email_state": "verified" if claims.get("email_verified") else "unknown",
        "created_at": now,
        "updated_at": now,
    }
    account = store.create_social_account_with_provider(
        account={
            "account_id": account_id,
            "workspace_id": workspace_id,
            "email_hash": claims.get("verified_email_hash", ""),
            "email_hint": "",
            "person_id": person_id,
            "email_verified_at": now,
            "locale": claims.get("locale", "") or "en",
            "display_name": claims.get("name", ""),
            "password_hash": password_hash,
            "password_hash_version": "bcrypt-12-provider-random",
            "created_at": now,
            "updated_at": now,
        },
        provider_identity=provider_identity,
        request_meta=dict(request_meta or {}),
    )
    graph = _identity_graph_check(provider, account, provider_identity)
    if graph.get("ok") is not True:
        _compensate_new_social_account(account_id, person_id, workspace_id, request_meta)
        return _graph_error(request_meta)
    credential_result = _store_provider_credential(provider, account, provider_identity, claims, request_meta)
    if credential_result.get("ok") is not True:
        # A newly-created Apple account must never be left without the
        # revocation credential required by the deletion contract.
        store.mark_provider_identity_state(provider_identity["provider_identity_id"], "revocation_required", dict(request_meta or {}))
        return credential_result
    return _account_result(provider, account, request_meta, provider_linked=True, provider_identity=provider_identity, status="profile_incomplete")


def exchange(provider: str, payload: Dict[str, Any] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    request_meta = request_meta or {}
    provider = _provider(provider)
    if not provider:
        return _error("provider_invalid", 400, "This sign-in method is not supported.", request_meta, next_action="use_email_password")
    workspace_id = _clean(os.getenv("LIVEUIN_PUBLIC_WORKSPACE_ID"), 96)
    if not workspace_id:
        return _error("public_workspace_not_configured", 503, "This sign-in method is not available yet.", request_meta, next_action="use_email_password")
    claims = _verified_claims(provider, _as_dict(payload), request_meta)
    if claims.get("ok") is not True:
        return claims
    linked = store.get_provider_identity(workspace_id, provider, claims["subject_hash"])
    if linked:
        account = store.get_account(linked.get("account_id", ""))
        if not account:
            return _error("account_unavailable", 403, "This account is not available.", request_meta, next_action="contact_support")
        admission_failure = public_identity._admission_for_account(account, request_meta)
        if admission_failure:
            return admission_failure
        graph = _identity_graph_check(provider, account, linked)
        if graph.get("ok") is not True:
            return _graph_error(request_meta)
        credential_result = _store_provider_credential(provider, account, linked, claims, request_meta)
        if credential_result.get("ok") is not True:
            return credential_result
        return _account_result(provider, account, request_meta, provider_linked=True, provider_identity=linked)
    if not claims.get("email_verified") or not claims.get("verified_email_hash"):
        return _error("provider_email_required", 400, "The provider did not return a verified email for this sign-in.", request_meta, next_action="try_again")
    admission_failure = public_identity._admission_for_hash(claims["verified_email_hash"], workspace_id, request_meta)
    if admission_failure:
        return admission_failure
    existing = store.get_account_by_email_hash(claims["verified_email_hash"], workspace_id)
    if existing:
        return _error(
            "link_required",
            409,
            "This email already has a LiveUIN account. Sign in to that account before linking this provider.",
            request_meta,
            next_action="authenticate_and_link",
            provider=provider,
            verified_email_state="verified",
        )
    return _new_social_account(provider, claims, workspace_id, _as_dict(payload), request_meta)


def _recent_authenticated_account(headers: Mapping[str, Any] | None, request_meta: Mapping[str, Any] | None) -> tuple[Dict[str, Any], Dict[str, Any]]:
    account, failure = public_identity._session_account(headers, request_meta, require_admission=True)
    if failure:
        return {}, failure
    issued_raw = ""
    for key, value in (headers or {}).items():
        if str(key).lower() == "x-liveuin-session-issued-at":
            issued_raw = str(value or "").strip()
            break
    try:
        issued_at = int(float(issued_raw))
    except (TypeError, ValueError):
        issued_at = 0
    if not issued_at or _now() - issued_at > REAUTH_MAX_AGE_SECONDS:
        return {}, _error("recent_authentication_required", 401, "Sign in again before linking a new sign-in method.", request_meta, next_action="sign_in")
    return account, {}


def link(provider: str, payload: Dict[str, Any] | None, headers: Mapping[str, Any] | None, request_meta: Mapping[str, Any] | None = None) -> Dict[str, Any]:
    request_meta = request_meta or {}
    provider = _provider(provider)
    if not provider:
        return _error("provider_invalid", 400, "This sign-in method is not supported.", request_meta, next_action="use_email_password")
    account, failure = _recent_authenticated_account(headers, request_meta)
    if failure:
        return failure
    claims = _verified_claims(provider, _as_dict(payload), request_meta)
    if claims.get("ok") is not True:
        return claims
    workspace_id = _clean(account.get("workspace_id"), 96)
    linked = store.get_provider_identity(workspace_id, provider, claims["subject_hash"])
    if linked:
        if linked.get("account_id") != account.get("account_id"):
            return _error("provider_identity_conflict", 409, "That provider sign-in is already linked to another LiveUIN account.", request_meta, next_action="contact_support")
        return _account_result(provider, account, request_meta, provider_linked=True, provider_identity=linked, status="authenticated")
    verified_email_hash = claims.get("verified_email_hash", "")
    email_account = store.get_account_by_email_hash(verified_email_hash, workspace_id) if verified_email_hash else {}
    if email_account and email_account.get("account_id") != account.get("account_id"):
        return _error("provider_identity_conflict", 409, "That provider email belongs to another LiveUIN account.", request_meta, next_action="contact_support")
    provider_identity = {
        "provider_identity_id": "pvid_" + uuid.uuid4().hex[:20],
        "workspace_id": workspace_id,
        "provider": provider,
        "subject_hash": claims["subject_hash"],
        "subject_hint": claims.get("subject_hint", ""),
        "account_id": account.get("account_id", ""),
        "person_id": account.get("person_id", ""),
        "verified_email_hash": verified_email_hash,
        "verified_email_state": "verified" if claims.get("email_verified") else "unknown",
        "created_at": _now(),
        "updated_at": _now(),
    }
    try:
        store.link_provider_identity(provider_identity=provider_identity, request_meta=dict(request_meta))
    except Exception:
        return _error("provider_identity_conflict", 409, "That provider sign-in could not be linked safely. Try again.", request_meta, next_action="try_again")
    graph = _identity_graph_check(provider, account, provider_identity)
    if graph.get("ok") is not True:
        store.mark_provider_identity_state(provider_identity["provider_identity_id"], "integrity_blocked", dict(request_meta))
        return _graph_error(request_meta)
    credential_result = _store_provider_credential(provider, account, provider_identity, claims, request_meta)
    if credential_result.get("ok") is not True:
        store.mark_provider_identity_state(provider_identity["provider_identity_id"], "revocation_required", dict(request_meta))
        return credential_result
    return _account_result(provider, account, request_meta, provider_linked=True, provider_identity=provider_identity, status="authenticated")
