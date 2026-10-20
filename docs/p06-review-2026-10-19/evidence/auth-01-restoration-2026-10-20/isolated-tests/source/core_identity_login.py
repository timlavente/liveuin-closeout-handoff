from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from typing import Any, Dict, List

try:
    from . import core_identity_login_store as store
    from . import core_identity_service as identity_svc
    from . import core_identity_session as session
    from . import core_identity_store as identity_store
except ImportError:  # pragma: no cover - supports direct script execution.
    import core_identity_login_store as store
    import core_identity_service as identity_svc
    import core_identity_session as session
    import core_identity_store as identity_store


SCHEMA_VERSION = "liveuin-core-identity-login-v1"
PHASE = "phase28-identity-login-challenge-contract"
DEFAULT_WORKSPACE_ID = "laijuzhu"
CANONICAL_OWNER = "LiveUIN Identity"
DEFAULT_CHALLENGE_TTL_SECONDS = 60 * 10
MAX_CHALLENGE_TTL_SECONDS = 60 * 60
DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 24

ALLOWED_CHANNELS = {
    "email",
    "sms",
    "wechat_miniprogram",
    "wechat_official_account",
    "pass_link",
    "protected_viewing",
    "liveuin_app",
    "operator_portal",
    "connector_sso",
}

PURPOSE_DEFAULTS = {
    "pass_access": {"role": "parent", "scopes": ["pass.case.read"]},
    "protected_viewing": {"role": "parent", "scopes": ["pass.case.read", "viewing.reservation.write"]},
    "booking": {"role": "student", "scopes": ["pass.case.read", "inventory.hold.write", "booking.write"]},
    "payment_status": {"role": "parent", "scopes": ["pass.case.read"]},
    "support": {"role": "parent", "scopes": ["pass.case.read", "ops.ticket.write"]},
    "operator_portal": {"role": "operator", "scopes": ["ops.task.write", "ops.task.proof.write"]},
    "connect_admin": {"role": "connector_admin", "scopes": ["connect.case.handoff"]},
    "member_app": {"role": "student", "scopes": ["pass.case.read", "viewing.reservation.write", "booking.write"]},
}

FAMILY_CHANNEL_SCOPES = {
    "pass.case.read",
    "viewing.reservation.write",
    "booking.write",
    "inventory.hold.write",
    "ops.ticket.write",
}


def _now() -> int:
    return int(time.time())


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _iso_from_epoch(value: Any) -> str:
    try:
        epoch = int(value)
    except (TypeError, ValueError):
        epoch = 0
    if epoch <= 0:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


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


def _clean_id(value: Any, max_length: int = 120) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]", "", str(value or "").strip())
    return cleaned[:max_length]


def _clean_slug(value: Any, default: str = "", max_length: int = 120) -> str:
    cleaned = re.sub(r"[^a-z0-9_.:-]+", "_", str(value or "").strip().lower()).strip("_")
    return (cleaned or default)[:max_length]


def _clean_text(value: Any, max_length: int = 240) -> str:
    return str(value or "").strip()[:max_length]


def _hash(value: Any) -> str:
    return store.hash_secret(value)


def _hint(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 10:
        return text[:2] + "..." + text[-2:]
    return text[:5] + "..." + text[-4:]


def _bounded_ttl(value: Any, *, default: int, maximum: int) -> int:
    if value in (None, ""):
        return default
    try:
        parsed = int(float(str(value)))
    except (TypeError, ValueError):
        return default
    if parsed <= 0:
        return 0
    return min(parsed, maximum)


def _redact(value: Any) -> Any:
    if isinstance(value, list):
        return [_redact(item) for item in value[:100]]
    if not isinstance(value, dict):
        return value
    cleaned: Dict[str, Any] = {}
    for key, item in value.items():
        normalized = str(key).lower()
        if normalized in {
            "code",
            "openid",
            "otp",
            "raw_code",
            "raw_identifier",
            "raw_secret",
            "secret",
            "session_id",
            "token",
            "unionid",
            "verification_code",
        }:
            cleaned[str(key)] = "[redacted]"
        else:
            cleaned[str(key)] = _redact(item)
    return cleaned


def _public_challenge(challenge: Dict[str, Any]) -> Dict[str, Any]:
    public = store.public_challenge(challenge)
    return {
        **public,
        "issued_at_iso": _iso_from_epoch(public.get("issued_at")),
        "expires_at_iso": _iso_from_epoch(public.get("expires_at")),
        "verified_at_iso": _iso_from_epoch(public.get("verified_at")),
        "cancelled_at_iso": _iso_from_epoch(public.get("cancelled_at")),
        "raw_secret_echoed": False,
    }


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


def _channel(value: Any) -> str:
    channel = _clean_slug(value, "pass_link", 80)
    return channel if channel in ALLOWED_CHANNELS else "pass_link"


def _purpose(value: Any) -> str:
    purpose = _clean_slug(value, "pass_access", 80)
    return purpose if purpose in PURPOSE_DEFAULTS else "pass_access"


def _identity_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    identity = _as_dict(payload.get("identity"))
    provider = _clean_slug(payload.get("provider") or identity.get("provider"), "", 80)
    provider_user_id = _clean_text(
        payload.get("provider_user_id")
        or payload.get("openid")
        or identity.get("provider_user_id")
        or identity.get("openid"),
        256,
    )
    unionid = _clean_text(payload.get("unionid") or identity.get("unionid"), 256)
    return {
        "provider": provider,
        "provider_user_id": provider_user_id,
        "unionid": unionid,
        "provider_app_id": _clean_text(payload.get("provider_app_id") or identity.get("appid"), 120),
    }


def _resolve_or_link_person(payload: Dict[str, Any], request_meta: Dict[str, str] | None) -> Dict[str, Any]:
    workspace_id = _clean_id(payload.get("workspace_id") or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID
    person_id = _clean_id(payload.get("person_id"), 96)
    if person_id:
        person = identity_store.get_person(person_id, workspace_id)
        return {
            "workspace_id": workspace_id,
            "person_id": person_id,
            "household_id": _clean_id(payload.get("household_id") or _as_dict(person.get("metadata")).get("household_id"), 96),
            "case_id": _clean_id(payload.get("case_id"), 96),
            "person": person,
            "identity_link": {},
        }

    identity = _identity_payload(payload)
    provider = identity["provider"]
    provider_user_id = identity["provider_user_id"]
    unionid = identity["unionid"]
    if provider or provider_user_id or unionid:
        resolved = identity_svc.resolve_identity(
            provider=provider,
            provider_user_id=provider_user_id,
            unionid=unionid,
            workspace_id=workspace_id,
        )
        if resolved.get("ok") is not True and provider and (provider_user_id or unionid):
            link_payload = {
                **payload,
                "workspace_id": workspace_id,
                "provider": provider,
                "provider_user_id": provider_user_id,
                "unionid": unionid,
                "provider_app_id": identity["provider_app_id"],
                "surface": payload.get("surface") or "login_challenge",
                "channel": payload.get("channel") or provider,
                "metadata": {
                    **_as_dict(payload.get("metadata")),
                    "created_by": "liveuin_identity_login",
                    "raw_identifier_stored": False,
                },
            }
            resolved = identity_svc.link_identity(link_payload, request_meta)
        if resolved.get("ok") is True:
            link = _as_dict(resolved.get("identity_link"))
            return {
                "workspace_id": workspace_id,
                "person_id": _clean_id(resolved.get("person_id"), 96),
                "household_id": _clean_id(link.get("household_id") or payload.get("household_id"), 96),
                "case_id": _clean_id(link.get("case_id") or payload.get("case_id"), 96),
                "person": resolved,
                "identity_link": link,
            }

    return {
        "workspace_id": workspace_id,
        "person_id": "",
        "household_id": _clean_id(payload.get("household_id"), 96),
        "case_id": _clean_id(payload.get("case_id"), 96),
        "person": {},
        "identity_link": {},
    }


def _role_and_scopes(payload: Dict[str, Any], purpose: str, channel: str, person: Dict[str, Any]) -> Dict[str, Any]:
    defaults = PURPOSE_DEFAULTS[purpose]
    requested_role = _clean_slug(payload.get("role") or _as_dict(payload.get("actor")).get("role"), "", 80)
    role_flags = [_clean_slug(item, "", 80) for item in _as_list(person.get("role_flags")) if _clean_slug(item, "", 80)]
    role = requested_role or (role_flags[0] if role_flags else str(defaults["role"]))
    scopes = [
        _clean_slug(scope, "", 120)
        for scope in (_as_list(payload.get("scopes") or _as_dict(payload.get("actor")).get("scopes")) or _as_list(defaults["scopes"]))
        if _clean_slug(scope, "", 120)
    ]
    if channel.startswith("wechat") or channel in {"pass_link", "protected_viewing"}:
        if role not in {"parent", "student", "guardian"}:
            role = "parent"
        scopes = [scope for scope in scopes if scope in FAMILY_CHANNEL_SCOPES]
        if "pass.case.read" not in scopes:
            scopes.insert(0, "pass.case.read")
    cleaned: List[str] = []
    for scope in scopes or _as_list(defaults["scopes"]):
        if scope and scope not in cleaned:
            cleaned.append(scope)
    return {"role": role, "scopes": cleaned[:80]}


def _subject(payload: Dict[str, Any], identity: Dict[str, Any], person_id: str) -> Dict[str, str]:
    delivery = _as_dict(payload.get("delivery"))
    target = (
        payload.get("target_hash")
        or delivery.get("target_hash")
        or payload.get("email_hash")
        or payload.get("phone_hash")
        or identity.get("unionid")
        or identity.get("provider_user_id")
        or person_id
        or payload.get("case_id")
    )
    provider = identity.get("provider") or _clean_slug(payload.get("channel"), "pass_link", 80)
    subject_raw = str(target or "").strip()
    subject_hash = subject_raw if re.fullmatch(r"[0-9a-f]{64}", subject_raw) else _hash(subject_raw)
    return {
        "provider": provider,
        "subject_hash": subject_hash,
        "subject_hint": _hint(subject_raw),
        "delivery_target_hash": subject_hash,
        "delivery_target_hint": _hint(subject_raw),
    }


def _generate_code() -> str:
    return f"{secrets.randbelow(1000000):06d}"


def create_login_challenge(payload: Dict[str, Any] | None = None, request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    channel = _channel(payload.get("channel") or payload.get("surface"))
    purpose = _purpose(payload.get("purpose"))
    identity = _identity_payload(payload)
    identity_context = _resolve_or_link_person(payload, request_meta)
    workspace_id = identity_context["workspace_id"]
    person = _as_dict(identity_context.get("person"))
    person_id = _clean_id(identity_context.get("person_id"), 96)
    case_id = _clean_id(payload.get("case_id") or identity_context.get("case_id"), 96)
    household_id = _clean_id(payload.get("household_id") or identity_context.get("household_id"), 96)
    if not person_id and not identity.get("provider_user_id") and not identity.get("unionid") and not payload.get("target_hash"):
        return error("identity_or_target_required", 400)

    role_context = _role_and_scopes(payload, purpose, channel, person)
    actor_id = _clean_id(_as_dict(payload.get("actor")).get("actor_id") or payload.get("actor_id"), 120)
    if not actor_id:
        actor_id = "person:" + person_id if person_id else "identity:" + _hash(identity.get("unionid") or identity.get("provider_user_id") or payload.get("target_hash"))[:16]

    ttl_seconds = _bounded_ttl(payload.get("ttl_seconds"), default=DEFAULT_CHALLENGE_TTL_SECONDS, maximum=MAX_CHALLENGE_TTL_SECONDS)
    now = _now()
    expires_at = now + ttl_seconds if ttl_seconds else 0
    code = _generate_code()
    subject = _subject(payload, identity, person_id)
    stored = store.create_challenge(
        {
            "workspace_id": workspace_id,
            "person_id": person_id,
            "household_id": household_id,
            "case_id": case_id,
            "channel": channel,
            "purpose": purpose,
            "provider": subject["provider"],
            "subject_hash": subject["subject_hash"],
            "subject_hint": subject["subject_hint"],
            "delivery_target_hash": subject["delivery_target_hash"],
            "delivery_target_hint": subject["delivery_target_hint"],
            "actor_id": actor_id,
            "role": role_context["role"],
            "scopes": role_context["scopes"],
            "code_hash": _hash(code),
            "max_attempts": min(max(int(payload.get("max_attempts") or 5), 1), 10),
            "issued_at": now,
            "expires_at": expires_at,
            "metadata": {
                **_as_dict(payload.get("metadata")),
                "identity_link_id": _as_dict(identity_context.get("identity_link")).get("identity_link_id", ""),
                "surface": _clean_text(payload.get("surface") or channel, 80),
                "login_contract": PHASE,
                "raw_identifier_stored": False,
            },
        },
        request_meta=request_meta,
    )
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "identity_login_challenge_created",
        "canonical_owner": CANONICAL_OWNER,
        "workspace_id": workspace_id,
        "challenge": _public_challenge(stored),
        "one_time_challenge": {
            "challenge_id": stored.get("challenge_id", ""),
            "verification_code": code,
            "expires_at": expires_at,
            "expires_at_iso": _iso_from_epoch(expires_at),
            "local_preview_only": True,
            "raw_secret_returned_once": True,
            "raw_secret_stored": False,
        },
        "boundary": {
            "surface": "Laijuzhu Pass, protected viewing, LiveUIN app, operator portal, or WeChat channel entry",
            "layer": "user-facing local login challenge contract",
            "owner": CANONICAL_OWNER,
            "session_issuer": "LiveUIN Identity private credential issuer",
            "wechat_role": "WeChat supplies identity/OAuth/channel delivery only; verified login still mints a LiveUIN-owned session.",
            "secret_policy": "The verification code is returned once for local preview and only its hash is stored.",
        },
    }


def verify_login_challenge(
    challenge_id: str,
    payload: Dict[str, Any] | None = None,
    request_meta: Dict[str, str] | None = None,
    *,
    trusted_role: str | None = None,
    trusted_scopes: List[str] | None = None,
) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    challenge_id = _clean_id(challenge_id or payload.get("challenge_id"), 120)
    workspace_id = _clean_id(payload.get("workspace_id") or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID
    if not challenge_id:
        return error("challenge_id_required", 400)
    challenge = store.get_challenge(challenge_id, workspace_id=workspace_id)
    if not challenge:
        challenge = store.get_challenge(challenge_id)
    if not challenge:
        return error("identity_login_challenge_not_found", 404)
    if challenge.get("status") != "pending":
        return error("identity_login_challenge_not_pending", 409, challenge=_public_challenge(challenge))
    if challenge.get("expires_at") and int(challenge["expires_at"]) <= _now():
        expired = store.mark_status(challenge_id, workspace_id=str(challenge.get("workspace_id") or ""), status="expired", request_meta=request_meta)
        return error("identity_login_challenge_expired", 410, challenge=_public_challenge(expired or challenge))
    if int(challenge.get("attempts") or 0) >= int(challenge.get("max_attempts") or 5):
        locked = store.mark_status(challenge_id, workspace_id=str(challenge.get("workspace_id") or ""), status="locked", request_meta=request_meta)
        return error("identity_login_challenge_locked", 423, challenge=_public_challenge(locked or challenge))

    code = str(payload.get("verification_code") or payload.get("code") or "").strip()
    if not code:
        return error("verification_code_required", 400, challenge=_public_challenge(challenge))
    code_hash = _hash(code)
    if not hmac.compare_digest(code_hash, str(challenge.get("code_hash") or "")):
        next_attempts = int(challenge.get("attempts") or 0) + 1
        lock = next_attempts >= int(challenge.get("max_attempts") or 5)
        attempted = store.mark_attempt(challenge_id, workspace_id=str(challenge.get("workspace_id") or ""), success=False, lock=lock, request_meta=request_meta)
        return error(
            "identity_login_challenge_invalid_code",
            403,
            challenge=_public_challenge(attempted or challenge),
            raw_secret_echoed=False,
        )

    verified = store.mark_attempt(challenge_id, workspace_id=str(challenge.get("workspace_id") or ""), success=True, request_meta=request_meta)
    session_result = session.issue_session(
        {
            "workspace_id": verified.get("workspace_id") or challenge.get("workspace_id") or DEFAULT_WORKSPACE_ID,
            "actor_id": verified.get("actor_id") or challenge.get("actor_id"),
            "role": trusted_role if trusted_role is not None else (verified.get("role") or challenge.get("role")),
            "scopes": trusted_scopes if trusted_scopes is not None else (verified.get("scopes") or challenge.get("scopes")),
            "ttl_seconds": _bounded_ttl(
                payload.get("session_ttl_seconds"),
                default=DEFAULT_SESSION_TTL_SECONDS,
                maximum=session.MAX_SESSION_TTL_SECONDS,
            ),
            "auth_method": "liveuin_login_challenge",
            "metadata": {
                "challenge_id": challenge_id,
                "purpose": verified.get("purpose") or challenge.get("purpose"),
                "channel": verified.get("channel") or challenge.get("channel"),
                "person_id": verified.get("person_id") or challenge.get("person_id"),
                "case_id": verified.get("case_id") or challenge.get("case_id"),
                "login_contract": PHASE,
                "raw_code_stored": False,
            },
        },
        request_meta=request_meta,
    )
    if session_result.get("ok") is not True:
        return session_result
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "identity_login_challenge_verified",
        "canonical_owner": CANONICAL_OWNER,
        "workspace_id": verified.get("workspace_id") or challenge.get("workspace_id") or DEFAULT_WORKSPACE_ID,
        "challenge": _public_challenge(verified or challenge),
        "session": session_result.get("session", {}),
        "one_time_credential": session_result.get("one_time_credential", {}),
        "raw_secret_echoed": False,
        "boundary": {
            "surface": "Laijuzhu Pass/protected viewing/LiveUIN app login exchange",
            "layer": "login challenge verification into signed LiveUIN session",
            "owner": CANONICAL_OWNER,
            "session_issuer": "LiveUIN Identity private credential issuer",
            "wechat_role": "WeChat remains channel identity/delivery only and does not own the session or product truth.",
        },
    }


def cancel_login_challenge(
    challenge_id: str,
    payload: Dict[str, Any] | None = None,
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    challenge_id = _clean_id(challenge_id or payload.get("challenge_id"), 120)
    workspace_id = _clean_id(payload.get("workspace_id") or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID
    if not challenge_id:
        return error("challenge_id_required", 400)
    challenge = store.mark_status(challenge_id, workspace_id=workspace_id, status="cancelled", request_meta=request_meta)
    if not challenge:
        return error("identity_login_challenge_not_found", 404)
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "identity_login_challenge_cancelled",
        "canonical_owner": CANONICAL_OWNER,
        "challenge": _public_challenge(challenge),
    }


def list_login_challenges(workspace_id: str = DEFAULT_WORKSPACE_ID, limit: int = 100) -> Dict[str, Any]:
    workspace_id = _clean_id(workspace_id or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID
    records = store.list_challenges(workspace_id=workspace_id, limit=limit)
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "identity_login_challenges_listed",
        "canonical_owner": CANONICAL_OWNER,
        "workspace_id": workspace_id,
        "challenges": [_public_challenge(record) for record in records],
        "raw_secret_echoed": False,
    }


def login_status() -> Dict[str, Any]:
    storage = store.debug_summary()
    tables = storage["tables"]
    return {
        "ok": True,
        "service": "liveuin-core-identity-login-preview",
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "source": "liveuin_identity",
        "canonical_owner": CANONICAL_OWNER,
        "storage": storage["store"],
        "sqlite_path": storage["sqlite_path"],
        "login_challenge_count": tables.get("identity_login_challenges", 0),
        "login_audit_event_count": tables.get("identity_login_audit_events", 0),
        "routes": [
            "GET /api/core/identity/login/status",
            "POST /api/core/identity/login/challenges",
            "GET /api/core/identity/login/challenges",
            "POST /api/core/identity/login/challenges/{challenge_id}/verify",
            "POST /api/core/identity/login/challenges/{challenge_id}/cancel",
        ],
        "boundary": {
            "surface": "Laijuzhu Pass, protected viewing, LiveUIN app, operator portal, and WeChat channel login entry",
            "layer": "user-facing local login challenge contract",
            "owner": CANONICAL_OWNER,
            "credential_issuer_role": "Verified challenges call the existing private LiveUIN session issuer; login challenge tables do not store raw codes or session ids.",
            "wechat_role": "Identity/OAuth/callback/message delivery only; not canonical case, inventory, proof, payment, ticket, SLA, finance, or operator truth.",
        },
    }
