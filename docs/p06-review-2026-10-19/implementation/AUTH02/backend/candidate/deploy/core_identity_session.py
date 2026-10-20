from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
import uuid
from http.cookies import SimpleCookie
from typing import Any, Dict, Mapping

try:
    from . import core_identity_session_store as credential_store
    from . import core_identity_store as identity_store
except ImportError:  # pragma: no cover - supports direct script execution.
    import core_identity_session_store as credential_store
    import core_identity_store as identity_store


SCHEMA_VERSION = "liveuin-core-identity-session-v1"
PHASE = "phase27-identity-credential-issuer-contract"
DEFAULT_WORKSPACE_ID = "laijuzhu"
CANONICAL_OWNER = "LiveUIN Identity"
DEFAULT_SESSION_MAX_AGE_SECONDS = 60 * 60 * 24
DEFAULT_API_KEY_TTL_SECONDS = 60 * 60 * 24 * 90
MAX_SESSION_TTL_SECONDS = 60 * 60 * 24 * 30
MAX_API_KEY_TTL_SECONDS = 60 * 60 * 24 * 365

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-liveuin-api-key",
    "x-liveuin-connector-api-key",
    "x-liveuin-session-id",
    "x-liveuin-session-signature",
    "x-wechat-openid",
    "x-wechat-unionid",
}

ROLE_DEFAULT_SCOPES = {
    "accountant": ["finance.export.create", "finance.reconciliation.review"],
    "finance_manager": ["finance.ledger.post", "finance.export.create", "finance.reconciliation.write", "finance.reconciliation.review", "vendor_finance.holdback.release"],
    "finance_ops": ["finance.settlement.prepare", "finance.reconciliation.write"],
    "ops": [
        "pass.case.read",
        "connect.case.handoff",
        "contract.template.write",
        "contract.draft.write",
        "contract.execution.write",
        "team.note.write",
        "support.profile.write",
        "support.request.write",
        "living.application.write",
        "demand.assignment.write",
        "intelligence.event.write",
        "inventory.hold.write",
        "viewing.reservation.write",
        "booking.write",
        "ops.ticket.write",
        "ops.task.write",
        "ops.task.proof.write",
        "ops.task.proof.review",
    ],
    "ops_manager": [
        "contract.template.write",
        "contract.draft.write",
        "contract.execution.write",
        "team.note.write",
        "support.profile.write",
        "support.request.write",
        "living.application.write",
        "vendor_finance.holdback.release",
        "demand.assignment.write",
        "demand.routing.write",
        "inventory.offer.write",
        "inventory.hold.write",
        "viewing.slot.write",
        "viewing.reservation.write",
        "booking.write",
        "booking.deposit.write",
        "ops.ticket.write",
        "ops.task.write",
        "ops.task.proof.write",
        "ops.task.proof.review",
    ],
    "payment_ops": ["payment.provider_event.write", "booking.deposit.write"],
    "connector_admin": [
        "connect.case.handoff",
        "connect.offer.write",
        "partner.hierarchy.write",
        "partner.commission.write",
        "partner.contact.write",
        "partner.reminder.write",
        "contract.template.write",
        "contract.draft.write",
        "contract.execution.write",
        "team.note.write",
        "support.profile.write",
        "support.request.write",
        "demand.intake.write",
        "demand.run.write",
        "demand.assignment.write",
        "demand.routing.write",
        "demand.lead.write",
    ],
    "agent": [
        "partner.workspace.read",
        "partner.contact.write",
        "partner.reminder.write",
        "contract.template.write",
        "contract.draft.write",
        "contract.execution.write",
        "support.request.write",
        "demand.lead.write",
    ],
    "owner": ["owner.contact.write", "contract.template.write", "contract.draft.write", "contract.execution.write", "support.profile.write", "support.request.write"],
    "landlord": ["owner.contact.write", "contract.template.write", "contract.draft.write", "contract.execution.write", "support.profile.write", "support.request.write"],
    "tenant": ["living.saved_search.write", "living.application.write", "payment.intent.write", "lifecycle.checkin.write", "lifecycle.review.write"],
    "member": ["living.saved_search.write", "living.application.write", "payment.intent.write", "lifecycle.checkin.write", "lifecycle.review.write"],
    "operator": ["ops.task.write", "ops.task.proof.write"],
    "vendor": ["vendor.job.proof.write", "vendor.job.accept", "vendor.claim.write", "vendor.profile.write", "vendor.offer.write", "vendor.request.write"],
    "parent": ["pass.case.read", "viewing.reservation.write", "booking.write", "inventory.hold.write", "ops.ticket.write", "support.request.write", "living.saved_search.write", "living.application.write", "payment.intent.write", "lifecycle.checkin.write", "lifecycle.review.write"],
    "student": ["pass.case.read", "viewing.reservation.write", "booking.write", "inventory.hold.write", "ops.ticket.write", "support.request.write", "living.saved_search.write", "living.application.write", "payment.intent.write", "lifecycle.checkin.write", "lifecycle.review.write"],
    "guardian": ["pass.case.read", "viewing.reservation.write", "booking.write", "inventory.hold.write", "ops.ticket.write", "support.request.write", "living.saved_search.write", "living.application.write", "payment.intent.write", "lifecycle.checkin.write", "lifecycle.review.write"],
    "analyst": ["intelligence.event.write"],
    "demand_ops": ["intelligence.event.write", "demand.lead.write", "demand.queue.write", "demand.assignment.write"],
}


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


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


def _clean_id(value: Any, max_length: int = 120) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]", "", str(value or "").strip())[:max_length]


def _clean_slug(value: Any, default: str = "", max_length: int = 120) -> str:
    cleaned = re.sub(r"[^a-z0-9_.:-]+", "_", str(value or "").strip().lower()).strip("_")
    return (cleaned or default)[:max_length]


def _issuer_secret(prefix: str) -> str:
    return prefix + "_" + uuid.uuid4().hex + uuid.uuid4().hex


def _public_credential(record: Dict[str, Any]) -> Dict[str, Any]:
    record = _as_dict(record)
    if not record:
        return {}
    return _redact(record)


def _credential_actor_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    actor = _as_dict(payload.get("actor"))
    role = _clean_slug(payload.get("role") or actor.get("role"), "", 80)
    scopes = [
        _clean_slug(scope, "", 120)
        for scope in _as_list(payload.get("scopes") or actor.get("scopes") or ROLE_DEFAULT_SCOPES.get(role, []))
        if _clean_slug(scope, "", 120)
    ]
    cleaned: list[str] = []
    for scope in scopes:
        if scope and scope not in cleaned:
            cleaned.append(scope)
    return {
        "workspace_id": _clean_id(payload.get("workspace_id") or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID,
        "actor_id": _clean_id(payload.get("actor_id") or actor.get("actor_id"), 120),
        "role": role,
        "scopes": cleaned[:80],
    }


def _header(headers: Mapping[str, str] | None, key: str) -> str:
    if not headers:
        return ""
    target = key.lower()
    for header_key, value in headers.items():
        if str(header_key).lower() == target and value:
            return str(value).strip()
    return ""


COOKIE_TO_HEADER = {
    "LIVEUIN_WORKSPACE_ID": "X-LiveUIN-Workspace-Id",
    "LIVEUIN_ACTOR_ID": "X-LiveUIN-Actor-Id",
    "LIVEUIN_ROLE": "X-LiveUIN-Role",
    "LIVEUIN_SCOPES": "X-LiveUIN-Scopes",
    "LIVEUIN_SESSION_ID": "X-LiveUIN-Session-Id",
    "LIVEUIN_SESSION_ISSUED_AT": "X-LiveUIN-Session-Issued-At",
    "LIVEUIN_AUTH_METHOD": "X-LiveUIN-Auth-Method",
    "LIVEUIN_SESSION_SIGNATURE": "X-LiveUIN-Session-Signature",
}

PROFILE_ACTIVE_STATUSES = {"active", "authorized"}
PROFILE_BLOCKED_STATUSES = {"blocked", "revoked", "suspended", "disabled"}
REQUESTED_PROFILE_HEADER = "X-LiveUIN-Requested-Profile-Key"
REQUESTED_WORKSPACE_HEADER = "X-LiveUIN-Requested-Workspace-Id"


def _normalize_profile_key(value: Any) -> str:
    normalized = _clean_slug(value, "", 80)
    if normalized in {"tenant", "member", "resident", "student", "parent", "guardian"}:
        return "tenant"
    if normalized in {"localpro", "vendor", "earn"}:
        return "localpro"
    if normalized in {"landlord", "host", "owner"}:
        return "landlord"
    if normalized in {"partner", "agent"}:
        return "partner"
    if normalized in {"operator", "ops"}:
        return "operator"
    return normalized


def _default_route_for_profile(profile_key: str) -> str:
    return {
        "tenant": "/app/member",
        "localpro": "/app/earn",
        "landlord": "/host/onboarding",
        "partner": "/partner/dashboard",
        "operator": "/ops/control-tower",
    }.get(profile_key, "/app/member")


def _requested_profile_key(payload: Dict[str, Any], headers: Mapping[str, str] | None) -> str:
    access = _as_dict(payload.get("access") or payload.get("access_context"))
    return _normalize_profile_key(
        _header(headers, REQUESTED_PROFILE_HEADER)
        or payload.get("requested_profile_key")
        or payload.get("active_profile_key")
        or payload.get("profile_key")
        or access.get("requested_profile_key")
        or access.get("active_profile_key")
        or access.get("profile_key")
    )


def _requested_workspace_hint(payload: Dict[str, Any], headers: Mapping[str, str] | None) -> str:
    access = _as_dict(payload.get("access") or payload.get("access_context"))
    return _clean_id(
        _header(headers, REQUESTED_WORKSPACE_HEADER)
        or payload.get("requested_workspace_id")
        or access.get("requested_workspace_id"),
        96,
    )


def _is_public_identity_session(credential_record: Dict[str, Any]) -> bool:
    """Identify sessions issued by the public Identity/Core account owner."""
    metadata = _as_dict(credential_record.get("metadata"))
    auth_method = _clean_slug(credential_record.get("auth_method"), "", 80)
    return bool(
        auth_method.startswith("public_")
        or metadata.get("public_account_id")
        or metadata.get("identity_state")
    )


def _session_identity_record(credential_record: Dict[str, Any], actor: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve the server-owned session account/person references.

    Public Identity sessions carry the canonical public account in
    ``public_account_id``.  ``account_id`` remains a compatible legacy
    reference for older issuers, but it is never allowed to silently override
    the public reference.  Generic Core sessions retain their historic
    actor/account fallback semantics.
    """
    metadata = _as_dict(credential_record.get("metadata"))
    public_account_id = _clean_id(metadata.get("public_account_id"), 120)
    legacy_account_id = _clean_id(metadata.get("account_id"), 120)
    public_session = _is_public_identity_session(credential_record)

    if public_account_id and legacy_account_id and public_account_id != legacy_account_id:
        return {
            "ok": False,
            "detail": "session_account_reference_conflict",
            "status_code": 403,
            "public_identity_session": public_session,
        }

    if public_session:
        account_id = public_account_id or legacy_account_id
        person_id = _clean_id(metadata.get("person_id") or actor.get("actor_id"), 96)
        if not account_id:
            return {
                "ok": False,
                "detail": "session_public_account_reference_missing",
                "status_code": 403,
                "public_identity_session": True,
            }
        if not person_id:
            return {
                "ok": False,
                "detail": "session_person_reference_missing",
                "status_code": 403,
                "public_identity_session": True,
            }
        return {
            "ok": True,
            "person_id": person_id,
            "account_id": account_id,
            "public_account_id": account_id,
            "public_identity_session": True,
        }

    person_id = _clean_id(metadata.get("person_id") or metadata.get("account_id"), 96)
    account_id = _clean_id(metadata.get("account_id") or metadata.get("person_id") or actor.get("actor_id"), 120)
    return {
        "ok": True,
        "person_id": person_id,
        "account_id": account_id,
        "public_account_id": "",
        "public_identity_session": False,
    }


def _normalized_profile_permissions(value: Any, role: str) -> list[str]:
    raw = _as_list(value) or ROLE_DEFAULT_SCOPES.get(role, [])
    cleaned: list[str] = []
    for item in raw:
        scope = _clean_slug(item, "", 120)
        if scope and scope not in cleaned:
            cleaned.append(scope)
    return cleaned[:80]


def _profile_is_expired(record: Dict[str, Any], now: int) -> bool:
    effective_to = int(record.get("effective_to") or 0)
    return bool(effective_to and effective_to <= now)


def _public_profile_entitlement(record: Dict[str, Any]) -> Dict[str, Any]:
    metadata = _as_dict(record.get("metadata"))
    profile_key = _normalize_profile_key(record.get("profile_key"))
    effective_to = int(record.get("effective_to") or 0)
    return {
        "entitlement_id": str(record.get("entitlement_id") or ""),
        "account_id": str(record.get("account_id") or ""),
        "person_id": str(record.get("person_id") or ""),
        "profile_key": profile_key,
        "workspace_id": str(record.get("workspace_id") or ""),
        "workspace_label": str(metadata.get("workspace_label") or metadata.get("workspace_name") or record.get("workspace_id") or ""),
        "workspace_type": str(metadata.get("workspace_type") or "workspace"),
        "status": str(record.get("status") or ""),
        "subject_id": str(record.get("subject_id") or ""),
        "subject_role": str(record.get("subject_role") or ""),
        "allowed_actions": _normalized_profile_permissions(record.get("permissions"), str(record.get("subject_role") or "")),
        "default_route": str(metadata.get("default_route") or _default_route_for_profile(profile_key)),
        "route_restrictions": _as_list(record.get("route_restrictions")),
        "effective_from": int(record.get("effective_from") or 0),
        "effective_to": effective_to,
        "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(effective_to)) if effective_to else "",
        "is_default": bool(record.get("is_default")),
        "metadata": metadata,
    }


def _profile_entitlements_for_identity(person_id: str, account_id: str, workspace_id: str) -> list[Dict[str, Any]]:
    if person_id:
        records = identity_store.list_profile_entitlements(
            person_id=person_id,
            account_id=account_id,
            workspace_id=workspace_id,
            limit=200,
        )
        if records:
            return records
    if account_id:
        return identity_store.list_profile_entitlements(
            account_id=account_id,
            workspace_id=workspace_id,
            limit=200,
        )
    return []


def _resolve_profile_projection(
    *,
    base_actor: Dict[str, Any],
    base_workspace_id: str,
    entitlements: list[Dict[str, Any]],
    requested_profile_key: str,
    requested_workspace_id: str,
    expected_account_id: str = "",
    expected_person_id: str = "",
) -> Dict[str, Any]:
    now = int(time.time())
    normalized_records: list[Dict[str, Any]] = []
    for record in entitlements:
        if (
            str(record.get("workspace_id") or "") != str(base_workspace_id or "")
            or (expected_account_id and str(record.get("account_id") or "") != str(expected_account_id))
            or (expected_person_id and str(record.get("person_id") or "") != str(expected_person_id))
        ):
            continue
        profile_key = _normalize_profile_key(record.get("profile_key"))
        if not profile_key:
            continue
        normalized_records.append({**record, "profile_key": profile_key})

    if not normalized_records:
        return {
            "ok": True,
            "actor": base_actor,
            "workspace_id": base_workspace_id,
            "default_profile_key": "",
            "default_workspace_id": base_workspace_id,
            "active_profile_key": "",
            "active_workspace_id": base_workspace_id,
            "profile_entitlements": [],
        }

    active_records = [
        item
        for item in normalized_records
        if _clean_slug(item.get("status"), "", 80) in PROFILE_ACTIVE_STATUSES and not _profile_is_expired(item, now)
    ]
    public_entitlements = [_public_profile_entitlement(item) for item in active_records]
    default_record = next((item for item in active_records if item.get("is_default")), None) or next(
        (
            item
            for item in active_records
            if item.get("profile_key") == _normalize_profile_key(base_actor.get("role")) or str(item.get("workspace_id") or "") == base_workspace_id
        ),
        None,
    ) or (active_records[0] if active_records else None)

    target_profile_key = requested_profile_key or _normalize_profile_key(default_record.get("profile_key") if default_record else "")
    target_workspace_id = requested_workspace_id or str(default_record.get("workspace_id") or "") if default_record else requested_workspace_id

    if target_profile_key:
        matching_profile = [item for item in normalized_records if item.get("profile_key") == target_profile_key]
        if not matching_profile:
            return {
                "ok": False,
                "detail": "identity_profile_not_authorized",
                "status_code": 403,
                "profile_entitlements": public_entitlements,
            }
        if target_workspace_id:
            matching_profile = [item for item in matching_profile if str(item.get("workspace_id") or "") == target_workspace_id]
            if not matching_profile:
                return {
                    "ok": False,
                    "detail": "identity_profile_workspace_not_authorized",
                    "status_code": 403,
                    "profile_entitlements": public_entitlements,
                }
        active_matching_profile = [
            item
            for item in matching_profile
            if _clean_slug(item.get("status"), "", 80) in PROFILE_ACTIVE_STATUSES and not _profile_is_expired(item, now)
        ]
        chosen_pool = active_matching_profile or matching_profile
        chosen = next((item for item in chosen_pool if item.get("is_default")), None) or chosen_pool[0]
    else:
        chosen = default_record

    if not chosen:
        return {
            "ok": False,
            "detail": "identity_profile_not_authorized",
            "status_code": 403,
            "profile_entitlements": public_entitlements,
        }

    status = _clean_slug(chosen.get("status"), "", 80)
    if status in PROFILE_BLOCKED_STATUSES:
        return {
            "ok": False,
            "detail": "identity_profile_blocked",
            "status_code": 403,
            "profile_entitlements": public_entitlements,
        }
    if _profile_is_expired(chosen, now) or status == "expired":
        return {
            "ok": False,
            "detail": "identity_profile_expired",
            "status_code": 403,
            "profile_entitlements": public_entitlements,
        }
    if status not in PROFILE_ACTIVE_STATUSES:
        return {
            "ok": False,
            "detail": "identity_profile_not_active",
            "status_code": 403,
            "profile_entitlements": public_entitlements,
        }

    actor_role = _clean_slug(chosen.get("subject_role"), "", 80) or _clean_slug(base_actor.get("role"), "", 80)
    actor_id = _clean_id(chosen.get("subject_id") or base_actor.get("actor_id"), 120)
    actor = {
        **base_actor,
        "actor_id": actor_id,
        "role": actor_role,
        "scopes": _normalized_profile_permissions(chosen.get("permissions"), actor_role),
        "active_profile_key": str(chosen.get("profile_key") or ""),
        "active_workspace_id": str(chosen.get("workspace_id") or ""),
    }

    return {
        "ok": True,
        "actor": actor,
        "workspace_id": str(chosen.get("workspace_id") or base_workspace_id),
        "default_profile_key": str(default_record.get("profile_key") or chosen.get("profile_key") or ""),
        "default_workspace_id": str(default_record.get("workspace_id") or chosen.get("workspace_id") or base_workspace_id),
        "active_profile_key": str(chosen.get("profile_key") or ""),
        "active_workspace_id": str(chosen.get("workspace_id") or ""),
        "profile_entitlements": public_entitlements,
    }


def _headers_with_cookie_session(headers: Mapping[str, str] | None) -> Dict[str, str]:
    merged = {str(key): str(value) for key, value in (headers or {}).items()}
    cookie_header = _header(headers, "Cookie")
    if not cookie_header:
        return merged
    try:
        jar = SimpleCookie()
        jar.load(cookie_header)
    except Exception:
        return merged

    existing = {str(key).lower() for key in merged}
    for cookie_name, header_name in COOKIE_TO_HEADER.items():
        if header_name.lower() in existing:
            continue
        morsel = jar.get(cookie_name)
        value = morsel.value if morsel is not None else ""
        if value:
            merged[header_name] = value
    return merged


def _bearer(headers: Mapping[str, str] | None) -> str:
    authorization = _header(headers, "Authorization")
    if authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return ""


def _hash(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _signing_secret() -> str:
    return str(os.getenv("LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET") or "").strip()


def _session_max_age_seconds() -> int:
    raw = str(os.getenv("LIVEUIN_IDENTITY_SESSION_MAX_AGE_SECONDS") or "").strip()
    if not raw:
        return DEFAULT_SESSION_MAX_AGE_SECONDS
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_SESSION_MAX_AGE_SECONDS


def _credential_store_enforcement() -> bool:
    raw = str(os.getenv("LIVEUIN_IDENTITY_CREDENTIAL_STORE_ENFORCEMENT") or "").strip().lower()
    if not raw:
        return True
    return raw in {"1", "true", "yes", "on", "required", "require", "enforced"}


def _signature_payload(values: Dict[str, Any]) -> str:
    return json.dumps(
        {
            "workspace_id": str(values.get("workspace_id") or DEFAULT_WORKSPACE_ID),
            "actor_id": str(values.get("actor_id") or ""),
            "role": str(values.get("role") or ""),
            "scopes": _as_list(values.get("scopes")),
            "session_id": str(values.get("session_id") or ""),
            "issued_at": str(values.get("issued_at") or ""),
            "auth_method": str(values.get("auth_method") or ""),
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _session_signature(values: Dict[str, Any]) -> str:
    secret = _signing_secret()
    if not secret:
        return ""
    return hmac.new(secret.encode("utf-8"), _signature_payload(values).encode("utf-8"), hashlib.sha256).hexdigest()


def sign_session_headers(values: Dict[str, Any]) -> Dict[str, str]:
    workspace_id = _clean_id(values.get("workspace_id") or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID
    actor_id = _clean_id(values.get("actor_id"), 120)
    role = _clean_slug(values.get("role"), "", 80)
    scopes = [_clean_slug(scope, "", 120) for scope in _as_list(values.get("scopes")) if _clean_slug(scope, "", 120)]
    issued_at = str(values.get("issued_at") or int(time.time()))
    auth_method = _clean_slug(values.get("auth_method"), "signed_internal_session", 80)
    session_id = _clean_id(values.get("session_id"), 160)
    signature_values = {
        "workspace_id": workspace_id,
        "actor_id": actor_id,
        "role": role,
        "scopes": scopes,
        "session_id": session_id,
        "issued_at": issued_at,
        "auth_method": auth_method,
    }
    return {
        "X-LiveUIN-Workspace-Id": workspace_id,
        "X-LiveUIN-Actor-Id": actor_id,
        "X-LiveUIN-Role": role,
        "X-LiveUIN-Scopes": ",".join(scopes),
        "X-LiveUIN-Session-Id": session_id,
        "X-LiveUIN-Session-Issued-At": issued_at,
        "X-LiveUIN-Auth-Method": auth_method,
        "X-LiveUIN-Session-Signature": _session_signature(signature_values),
    }


def _session_header_values(headers: Mapping[str, str] | None) -> Dict[str, Any]:
    return {
        "workspace_id": _header(headers, "X-LiveUIN-Workspace-Id") or DEFAULT_WORKSPACE_ID,
        "actor_id": _header(headers, "X-LiveUIN-Actor-Id"),
        "role": _header(headers, "X-LiveUIN-Role"),
        "scopes": _as_list(_header(headers, "X-LiveUIN-Scopes")),
        "session_id": _header(headers, "X-LiveUIN-Session-Id"),
        "issued_at": _header(headers, "X-LiveUIN-Session-Issued-At"),
        "auth_method": _header(headers, "X-LiveUIN-Auth-Method"),
    }


def _session_header_validation(headers: Mapping[str, str] | None) -> Dict[str, Any]:
    values = _session_header_values(headers)
    session_id = str(values.get("session_id") or "")
    signature = _header(headers, "X-LiveUIN-Session-Signature")
    if not session_id or not signature or not _signing_secret():
        return {"verified": False, "validation": "session_signature_required"}

    expected = _session_signature(values)
    if not expected or not hmac.compare_digest(expected, signature):
        return {"verified": False, "validation": "session_signature_invalid"}

    issued_at = str(values.get("issued_at") or "").strip()
    try:
        issued_seconds = float(issued_at)
    except ValueError:
        return {"verified": False, "validation": "session_issued_at_invalid"}

    now = time.time()
    if issued_seconds > now + 300:
        return {"verified": False, "validation": "session_issued_at_in_future"}

    max_age_seconds = _session_max_age_seconds()
    if max_age_seconds and now - issued_seconds > max_age_seconds:
        return {"verified": False, "validation": "session_signature_expired"}

    workspace_hint = _clean_id(values.get("workspace_id") or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID
    session_id_hash = _hash(session_id)
    store_result = credential_store.validate_session_hash(session_id_hash, workspace_id=workspace_hint)
    if not store_result.get("found"):
        store_result = credential_store.validate_session_hash(session_id_hash)
    store_record = _as_dict(store_result.get("record"))
    if store_result.get("active"):
        if _session_store_claim_mismatch(store_record, values):
            return {
                "verified": False,
                "validation": "session_store_claim_mismatch",
                "store_record": store_record,
            }
        return {
            "verified": True,
            "validation": "signed_session_verified_store_active",
            "store_record": store_record,
        }
    if _credential_store_enforcement():
        return {
            "verified": False,
            "validation": str(store_result.get("validation") or "session_store_missing"),
            "store_record": store_record,
        }

    return {"verified": True, "validation": "signed_session_verified", "store_record": store_record}


def _normalized_scope_set(value: Any) -> set[str]:
    return {str(item).strip() for item in _as_list(value) if str(item).strip()}


def _session_store_claim_mismatch(record: Dict[str, Any], values: Dict[str, Any]) -> bool:
    if not record:
        return False
    comparisons = (
        ("workspace_id", DEFAULT_WORKSPACE_ID),
        ("actor_id", ""),
        ("role", ""),
        ("auth_method", ""),
    )
    for key, default in comparisons:
        record_value = str(record.get(key) or default)
        signed_value = str(values.get(key) or default)
        if record_value and signed_value and record_value != signed_value:
            return True
    record_scopes = _normalized_scope_set(record.get("scopes"))
    signed_scopes = _normalized_scope_set(values.get("scopes"))
    return bool(record_scopes and signed_scopes and record_scopes != signed_scopes)


def _credential_validation_detail(kind: str, validation: str) -> str:
    validation = str(validation or "")
    if kind == "liveuin_api_key":
        if validation == "api_key_revoked":
            return "identity_api_key_revoked"
        if validation == "api_key_rotated":
            return "identity_api_key_rotated"
        if validation == "api_key_expired":
            return "identity_api_key_expired"
        if validation == "api_key_inactive":
            return "identity_api_key_inactive"
        return "identity_api_key_unverified"
    if validation == "session_signature_expired" or validation == "session_expired":
        return "identity_session_expired"
    if validation == "session_revoked":
        return "identity_session_revoked"
    if validation == "session_rotated":
        return "identity_session_rotated"
    if validation == "session_inactive":
        return "identity_session_inactive"
    if validation == "session_store_missing":
        return "identity_session_not_registered"
    if validation == "session_store_claim_mismatch":
        return "identity_session_claim_mismatch"
    return "identity_session_signature_invalid"


def _store_validation_for_key(kind: str, credential_hash: str, workspace_hint: str) -> Dict[str, Any]:
    if kind == "liveuin_session":
        result = credential_store.validate_session_hash(credential_hash, workspace_id=workspace_hint)
        if not result.get("found"):
            result = credential_store.validate_session_hash(credential_hash)
        return result
    result = credential_store.validate_api_key_hash(credential_hash, workspace_id=workspace_hint)
    if not result.get("found"):
        result = credential_store.validate_api_key_hash(credential_hash)
    return result


def _hint(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 10:
        return text[:2] + "..." + text[-2:]
    return text[:5] + "..." + text[-4:]


def _safe_headers(headers: Mapping[str, str] | None) -> Dict[str, str]:
    safe: Dict[str, str] = {}
    if not headers:
        return safe
    for key, value in headers.items():
        normalized = str(key).lower()
        if normalized in SENSITIVE_HEADER_NAMES:
            safe[str(key)] = "[redacted]"
        elif normalized.startswith("x-liveuin") or normalized.startswith("x-wechat"):
            safe[str(key)] = str(value)[:160]
    return safe


def _redact(value: Any) -> Any:
    if isinstance(value, list):
        return [_redact(item) for item in value[:100]]
    if not isinstance(value, dict):
        return value
    cleaned: Dict[str, Any] = {}
    for key, item in value.items():
        key_text = str(key)
        if key_text.lower() in SENSITIVE_HEADER_NAMES or key_text.lower() in {
            "api_key",
            "authorization",
            "connector_api_key",
            "openid",
            "raw_token",
            "session_id",
            "token",
            "unionid",
        }:
            cleaned[key_text] = "[redacted]"
        else:
            cleaned[key_text] = _redact(item)
    return cleaned


def _workspace_id(payload: Dict[str, Any], headers: Mapping[str, str] | None) -> str:
    access = _as_dict(payload.get("access") or payload.get("access_context"))
    return (
        _clean_id(
            _header(headers, "X-LiveUIN-Workspace-Id")
            or payload.get("workspace_id")
            or access.get("workspace_id")
            or DEFAULT_WORKSPACE_ID,
            96,
        )
        or DEFAULT_WORKSPACE_ID
    )


def _scopes(actor: Dict[str, Any], access: Dict[str, Any], payload: Dict[str, Any], headers: Mapping[str, str] | None, role: str) -> list[str]:
    scopes = (
        _as_list(_header(headers, "X-LiveUIN-Scopes"))
        or _as_list(_header(headers, "X-LiveUIN-Session-Scopes"))
        or _as_list(actor.get("scopes"))
        or _as_list(access.get("scopes"))
        or _as_list(payload.get("scopes"))
    )
    if not scopes:
        scopes = ROLE_DEFAULT_SCOPES.get(role, [])
    cleaned: list[str] = []
    for scope in scopes:
        text = _clean_slug(scope, "", 120)
        if text and text not in cleaned:
            cleaned.append(text)
    return cleaned[:80]


def _credential(headers: Mapping[str, str] | None) -> Dict[str, Any]:
    session_id = _header(headers, "X-LiveUIN-Session-Id")
    api_key = _header(headers, "X-LiveUIN-API-Key")
    connector_key = _header(headers, "X-LiveUIN-Connector-API-Key")
    bearer = _bearer(headers)
    wechat_openid = _header(headers, "X-WeChat-OpenID")
    wechat_unionid = _header(headers, "X-WeChat-UnionID")
    channel = _clean_slug(_header(headers, "X-LiveUIN-Channel"), "", 80)
    workspace_hint = _clean_id(_header(headers, "X-LiveUIN-Workspace-Id") or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID

    if connector_key:
        return {
            "kind": "connector_api_key",
            "credential_hash": _hash(connector_key),
            "credential_hint": _hint(connector_key),
            "validation": "external_connect_authorizer_required",
            "verified": False,
        }
    if session_id:
        validation = _session_header_validation(headers)
        return {
            "kind": "liveuin_session",
            "credential_hash": _hash(session_id),
            "credential_hint": _hint(session_id),
            "validation": validation["validation"],
            "verified": validation["verified"],
            "store_record": _as_dict(validation.get("store_record")),
        }
    if api_key:
        credential_hash = _hash(api_key)
        store_result = _store_validation_for_key("liveuin_api_key", credential_hash, workspace_hint)
        store_active = bool(store_result.get("active"))
        validation = (
            str(store_result.get("validation") or "api_key_store_missing")
            if (store_active or _credential_store_enforcement())
            else "api_key_store_required"
        )
        return {
            "kind": "liveuin_api_key",
            "credential_hash": credential_hash,
            "credential_hint": _hint(api_key),
            "validation": validation,
            "verified": store_active,
            "store_record": _as_dict(store_result.get("record")),
        }
    if bearer:
        kind = "liveuin_session" if bearer.startswith(("sess_", "lus_")) else "liveuin_api_key"
        credential_hash = _hash(bearer)
        store_result = _store_validation_for_key(kind, credential_hash, workspace_hint)
        store_active = bool(store_result.get("active"))
        validation = (
            str(store_result.get("validation") or "session_or_api_key_store_missing")
            if (store_active or _credential_store_enforcement())
            else "session_or_api_key_store_required"
        )
        return {
            "kind": kind,
            "credential_hash": credential_hash,
            "credential_hint": _hint(bearer),
            "validation": validation,
            "verified": store_active,
            "store_record": _as_dict(store_result.get("record")),
        }
    if wechat_openid or wechat_unionid or channel == "wechat":
        subject = wechat_unionid or wechat_openid or "wechat_channel"
        return {
            "kind": "wechat_bridge_identity",
            "credential_hash": _hash(subject),
            "credential_hint": _hint(subject),
            "validation": "wechat_adapter_only",
            "verified": False,
        }
    return {}


def _actor_from_context(payload: Dict[str, Any], headers: Mapping[str, str] | None, workspace_id: str, credential: Dict[str, Any]) -> Dict[str, Any]:
    access = _as_dict(payload.get("access") or payload.get("access_context"))
    actor = {**_as_dict(payload.get("actor") or access.get("actor"))}
    credential_kind = str(credential.get("kind") or "")
    store_record = _as_dict(credential.get("store_record"))

    if credential_kind == "connector_api_key":
        connector_scopes = [
            _clean_slug(scope, "", 120)
            for scope in ROLE_DEFAULT_SCOPES.get("connector_admin", ["connect.case.handoff"])
            if _clean_slug(scope, "", 120)
        ]
        return {
            "actor_id": "connect:" + workspace_id,
            "role": "connector_admin",
            "scopes": connector_scopes,
        }
    if credential_kind == "wechat_bridge_identity":
        return {
            "actor_id": "wechat:" + str(credential.get("credential_hash", ""))[:16],
            "role": "parent",
            "scopes": ["pass.case.read"],
        }
    if credential_kind in {"liveuin_api_key", "liveuin_session"} and credential.get("verified") is True and store_record:
        return {
            "actor_id": _clean_id(store_record.get("actor_id"), 120),
            "role": _clean_slug(store_record.get("role"), "", 80),
            "scopes": [_clean_slug(scope, "", 120) for scope in _as_list(store_record.get("scopes")) if _clean_slug(scope, "", 120)],
        }

    role = _clean_slug(_header(headers, "X-LiveUIN-Role") or actor.get("role") or actor.get("persona_role"), "", 80)
    actor_id = _clean_id(_header(headers, "X-LiveUIN-Actor-Id") or actor.get("actor_id"), 120)
    scopes = _scopes(actor, access, payload, headers, role)
    return {
        "actor_id": actor_id,
        "role": role,
        "scopes": scopes,
    }


def _source_family(payload: Dict[str, Any], headers: Mapping[str, str] | None, credential: Dict[str, Any]) -> str:
    access = _as_dict(payload.get("access") or payload.get("access_context"))
    context = _as_dict(payload.get("context") or payload.get("metadata"))
    credential_kind = str(credential.get("kind") or "")
    requested_source_family = _clean_slug(
        _header(headers, "X-LiveUIN-Source-Family")
        or payload.get("source_family")
        or access.get("source_family")
        or context.get("source_family"),
        "",
        120,
    )
    if credential_kind == "connector_api_key":
        if requested_source_family == "liveuin_demand":
            return requested_source_family
        return "liveuin_connector"
    if credential_kind == "wechat_bridge_identity":
        return "wechat"
    default = "liveuin_core"
    return _clean_slug(
        requested_source_family
        or default,
        default,
        120,
    )


def _idempotency_key(payload: Dict[str, Any], headers: Mapping[str, str] | None) -> str:
    access = _as_dict(payload.get("access") or payload.get("access_context"))
    return _clean_id(
        _header(headers, "Idempotency-Key")
        or _header(headers, "X-Idempotency-Key")
        or _header(headers, "X-LiveUIN-Idempotency-Key")
        or payload.get("idempotency_key")
        or access.get("idempotency_key"),
        160,
    )


def error(detail: str, status_code: int = 403, **extra: Any) -> Dict[str, Any]:
    return {
        "ok": False,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "detail": detail,
        "status_code": status_code,
        "canonical_owner": CANONICAL_OWNER,
        **extra,
    }


def resolve_access_context(
    payload: Dict[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    *,
    method: str = "",
    path: str = "",
    request_meta: Dict[str, str] | None = None,
    require_identity: bool = True,
) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    effective_headers = _headers_with_cookie_session(headers)
    access = _as_dict(payload.get("access") or payload.get("access_context"))
    workspace_id = _workspace_id(payload, effective_headers)
    payload_workspace_id = _clean_id(payload.get("workspace_id") or access.get("workspace_id"), 96)
    header_workspace_id = _clean_id(_header(effective_headers, "X-LiveUIN-Workspace-Id"), 96)
    if require_identity and payload_workspace_id and header_workspace_id and payload_workspace_id != header_workspace_id:
        return error(
            "identity_session_workspace_mismatch",
            403,
            workspace_id=payload_workspace_id,
            session_workspace_id=header_workspace_id,
            identity_session={
                "resolved": False,
                "safe_headers": _safe_headers(effective_headers),
                "route": path,
                "method": method.upper(),
            },
        )

    credential = _credential(effective_headers)
    if not credential and access.get("actor"):
        credential = {
            "kind": "upstream_access_context",
            "credential_hash": "",
            "credential_hint": "",
            "validation": _clean_slug(_as_dict(access.get("context")).get("authorized_by"), "upstream_authorizer_required", 120),
            "verified": True,
        }
    credential_record = _as_dict(credential.get("store_record"))
    credential_workspace_id = _clean_id(credential_record.get("workspace_id"), 96)
    if credential_workspace_id and not payload_workspace_id and not header_workspace_id:
        workspace_id = credential_workspace_id
    elif require_identity and credential_workspace_id and credential_workspace_id != workspace_id:
        return error(
            "identity_credential_workspace_mismatch",
            403,
            workspace_id=workspace_id,
            credential_workspace_id=credential_workspace_id,
            identity_session={
                "resolved": False,
                "credential_kind": credential.get("kind", ""),
                "credential_hint": credential.get("credential_hint", ""),
                "credential_validation": credential.get("validation", ""),
                "credential_verified": bool(credential.get("verified")),
                "raw_secret_echoed": False,
                "route": path,
                "method": method.upper(),
            },
        )
    credential_kind = str(credential.get("kind") or "")

    if require_identity and credential_kind == "liveuin_session" and credential.get("verified") is not True:
        detail = _credential_validation_detail(credential_kind, str(credential.get("validation") or ""))
        return error(
            detail,
            403,
            workspace_id=workspace_id,
            identity_session={
                "resolved": False,
                "credential_kind": credential_kind,
                "credential_hint": credential.get("credential_hint", ""),
                "credential_validation": credential.get("validation", ""),
                "raw_secret_echoed": False,
                "route": path,
                "method": method.upper(),
            },
        )

    if require_identity and credential_kind == "liveuin_api_key" and _credential_store_enforcement() and credential.get("verified") is not True:
        return error(
            _credential_validation_detail(credential_kind, str(credential.get("validation") or "")),
            403,
            workspace_id=workspace_id,
            identity_session={
                "resolved": False,
                "credential_kind": credential_kind,
                "credential_hint": credential.get("credential_hint", ""),
                "credential_validation": credential.get("validation", ""),
                "raw_secret_echoed": False,
                "route": path,
                "method": method.upper(),
            },
        )

    actor = _actor_from_context(payload, effective_headers, workspace_id, credential)
    identity_record = _session_identity_record(credential_record, actor)
    if identity_record.get("ok") is False:
        return error(
            str(identity_record.get("detail") or "session_account_reference_invalid"),
            int(identity_record.get("status_code") or 403),
            workspace_id=workspace_id,
            identity_session={
                "resolved": False,
                "credential_kind": credential_kind,
                "credential_hint": credential.get("credential_hint", ""),
                "credential_validation": credential.get("validation", ""),
                "credential_verified": bool(credential.get("verified")),
                "public_identity_session": bool(identity_record.get("public_identity_session")),
                "raw_secret_echoed": False,
                "route": path,
                "method": method.upper(),
            },
        )
    requested_profile_key = _requested_profile_key(payload, effective_headers)
    requested_workspace_id = _requested_workspace_hint(payload, effective_headers)
    profile_projection = _resolve_profile_projection(
        base_actor=actor,
        base_workspace_id=workspace_id,
        entitlements=_profile_entitlements_for_identity(identity_record["person_id"], identity_record["account_id"], workspace_id),
        requested_profile_key=requested_profile_key,
        requested_workspace_id=requested_workspace_id,
        expected_account_id=identity_record["account_id"],
        expected_person_id=identity_record["person_id"],
    )
    if profile_projection.get("ok") is False:
        return error(
            str(profile_projection.get("detail") or "identity_profile_not_authorized"),
            int(profile_projection.get("status_code") or 403),
            workspace_id=requested_workspace_id or workspace_id,
            profile_entitlements=profile_projection.get("profile_entitlements") or [],
            identity_session={
                "resolved": bool(credential_kind),
                "credential_kind": credential_kind or "none",
                "credential_hint": credential.get("credential_hint", ""),
                "credential_validation": credential.get("validation", ""),
                "verified": bool(credential.get("verified")),
                "route": path,
                "method": method.upper(),
            },
        )
    actor = _as_dict(profile_projection.get("actor")) or actor
    actor = {
        **actor,
        "account_id": identity_record["account_id"],
        "person_id": identity_record["person_id"],
    }
    workspace_id = _clean_id(profile_projection.get("workspace_id") or workspace_id, 96) or workspace_id
    person = identity_store.get_person(identity_record["person_id"], workspace_id)
    display_name = str(person.get("display_name") or "").strip()
    if display_name:
        actor = {**actor, "display_name": display_name}
    source_family = _source_family(payload, effective_headers, credential)
    idempotency_key = _idempotency_key(payload, effective_headers)

    if require_identity and (not credential_kind or not actor.get("actor_id") or not actor.get("role")):
        return error(
            "identity_session_required",
            403,
            workspace_id=workspace_id,
            identity_session={
                "resolved": False,
                "safe_headers": _safe_headers(effective_headers),
                "route": path,
                "method": method.upper(),
            },
        )

    if require_identity and not actor.get("scopes"):
        return error(
            "identity_scopes_required",
            403,
            workspace_id=workspace_id,
            identity_session={
                "resolved": False,
                "credential_kind": credential_kind,
                "actor_id": actor.get("actor_id", ""),
                "role": actor.get("role", ""),
                "route": path,
                "method": method.upper(),
            },
        )

    bridge_only = credential_kind == "wechat_bridge_identity"
    access_context = {
        **access,
        "workspace_id": workspace_id,
        "actor": actor,
        "scopes": actor["scopes"],
        "account_id": identity_record["account_id"],
        "person_id": identity_record["person_id"],
        "profile_entitlements": profile_projection.get("profile_entitlements") or [],
        "default_profile_key": profile_projection.get("default_profile_key") or "",
        "default_workspace_id": profile_projection.get("default_workspace_id") or workspace_id,
        "active_profile_key": profile_projection.get("active_profile_key") or "",
        "active_workspace_id": profile_projection.get("active_workspace_id") or workspace_id,
        "source_family": source_family,
        "idempotency_key": idempotency_key,
        "context": {
            **_as_dict(access.get("context")),
            "identity_session_schema": SCHEMA_VERSION,
            "identity_session_phase": PHASE,
            "identity_resolved_at": _now_iso(),
            "credential_kind": credential_kind or "none",
            "credential_hash": credential.get("credential_hash", ""),
            "credential_hint": credential.get("credential_hint", ""),
            "credential_validation": credential.get("validation", ""),
            "credential_verified": bool(credential.get("verified")),
            "credential_store_status": credential_record.get("status", ""),
            "credential_key_id": credential_record.get("key_id", ""),
            "credential_policy_version": credential_record.get("policy_version", ""),
            "public_identity_session": bool(identity_record.get("public_identity_session")),
            "public_account_id": identity_record.get("public_account_id", ""),
            "bridge_only": bridge_only,
            "channel_role": "identity_or_message_delivery_only" if bridge_only else "",
            "method": method.upper(),
            "route": path,
            "request_ip": _as_dict(request_meta).get("ip", ""),
        },
    }
    response = {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "identity_session_resolved" if credential_kind else "identity_session_optional",
        "canonical_owner": CANONICAL_OWNER,
        "workspace_id": workspace_id,
        "actor": actor,
        "display_name": display_name,
        "account_id": identity_record["account_id"],
        "person_id": identity_record["person_id"],
        "profile_entitlements": profile_projection.get("profile_entitlements") or [],
        "source_family": source_family,
        "idempotency_key": idempotency_key,
        "identity_session": {
            "resolved": bool(credential_kind),
            "credential_kind": credential_kind or "none",
            "credential_hint": credential.get("credential_hint", ""),
            "credential_hash": credential.get("credential_hash", ""),
            "credential_validation": credential.get("validation", ""),
            "verified": bool(credential.get("verified")),
            "credential_store_status": credential_record.get("status", ""),
            "credential_key_id": credential_record.get("key_id", ""),
            "credential_policy_version": credential_record.get("policy_version", ""),
            "public_identity_session": bool(identity_record.get("public_identity_session")),
            "public_account_id": identity_record.get("public_account_id", ""),
            "bridge_only": bridge_only,
            "safe_headers": _safe_headers(headers),
            "raw_secret_echoed": False,
        },
        "access": _redact(access_context),
        "boundary": {
            "surface": "Core API gateway, Admin, Connect handoff, channel bridge, and adapter request context",
            "layer": "identity/session context resolver",
            "owner": CANONICAL_OWNER,
            "access_role": "Normalizes actor, role, scopes, workspace, source family, and idempotency context before Core Access policy evaluation.",
            "wechat_role": "Identity/OAuth/message-delivery bridge only; WeChat context does not grant product-write authority.",
            "connector_role": "Connector API keys identify handoff transport; connector records do not become product truth.",
            "secret_policy": "Raw sessions, API keys, bearer tokens, openids, and unionids are never echoed; only hashes/hints are returned.",
        },
    }
    encoded = json.dumps(response, sort_keys=True)
    for secret_name in ("session_id", "api_key", "authorization", "openid", "unionid"):
        if secret_name in encoded.lower().replace("[redacted]", ""):
            response["identity_session"]["raw_secret_echoed"] = False
            break
    return response


def access_headers(access_context: Dict[str, Any], headers: Mapping[str, str] | None = None) -> Dict[str, str]:
    access_context = _as_dict(access_context)
    actor = _as_dict(access_context.get("actor"))
    merged = {
        "X-LiveUIN-Workspace-Id": str(access_context.get("workspace_id") or DEFAULT_WORKSPACE_ID),
        "X-LiveUIN-Actor-Id": str(actor.get("actor_id") or ""),
        "X-LiveUIN-Role": str(actor.get("role") or ""),
        "X-LiveUIN-Scopes": ",".join(str(scope) for scope in _as_list(actor.get("scopes") or access_context.get("scopes"))),
        "X-LiveUIN-Source-Family": str(access_context.get("source_family") or "liveuin_core"),
    }
    idempotency_key = str(access_context.get("idempotency_key") or "")
    if idempotency_key:
        merged["Idempotency-Key"] = idempotency_key
    if headers:
        for key in ("User-Agent", "Referer"):
            value = _header(headers, key)
            if value:
                merged[key] = value
    return merged


def public_context(resolved: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(resolved, dict):
        return {}
    identity = _as_dict(resolved.get("identity_session") or resolved)
    actor = _as_dict(resolved.get("actor"))
    return {
        "schema_version": resolved.get("schema_version", SCHEMA_VERSION),
        "phase": resolved.get("phase", PHASE),
        "status": resolved.get("status", ""),
        "workspace_id": resolved.get("workspace_id", ""),
        "actor": actor,
        "source_family": resolved.get("source_family", ""),
        "credential_kind": identity.get("credential_kind", ""),
        "credential_hint": identity.get("credential_hint", ""),
        "credential_hash": identity.get("credential_hash", ""),
        "credential_validation": identity.get("credential_validation", ""),
        "verified": bool(identity.get("verified") or identity.get("credential_verified")),
        "credential_store_status": identity.get("credential_store_status", ""),
        "credential_key_id": identity.get("credential_key_id", ""),
        "credential_policy_version": identity.get("credential_policy_version", ""),
        "bridge_only": bool(identity.get("bridge_only")),
        "raw_secret_echoed": False,
    }


def issue_session(payload: Dict[str, Any] | None = None, request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    if not _signing_secret():
        return error("identity_session_signing_secret_required", 500)
    actor_payload = _credential_actor_payload(payload)
    if not actor_payload["actor_id"]:
        return error("actor_id_required", 400)
    if not actor_payload["role"]:
        return error("role_required", 400)
    if not actor_payload["scopes"]:
        return error("scopes_required", 400)

    now = int(time.time())
    ttl_seconds = _bounded_ttl(
        payload.get("ttl_seconds") or payload.get("session_ttl_seconds"),
        default=DEFAULT_SESSION_MAX_AGE_SECONDS,
        maximum=MAX_SESSION_TTL_SECONDS,
    )
    expires_at = now + ttl_seconds if ttl_seconds else 0
    session_id = _issuer_secret("lus")
    auth_method = _clean_slug(payload.get("auth_method"), "liveuin_identity_issuer", 80)
    session_headers = sign_session_headers(
        {
            **actor_payload,
            "session_id": session_id,
            "issued_at": str(now),
            "auth_method": auth_method,
        }
    )
    stored = credential_store.upsert_session(
        {
            **actor_payload,
            "session_id": session_id,
            "auth_method": auth_method,
            "issued_at": now,
            "expires_at": expires_at,
            "policy_version": _clean_id(payload.get("policy_version"), 80),
            "metadata": {
                **_as_dict(payload.get("metadata")),
                "issuer": "liveuin_identity",
                "issuer_contract": PHASE,
                "surface": "private_core_identity_admin",
            },
        },
        request_meta=request_meta,
    )
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "identity_session_issued",
        "canonical_owner": CANONICAL_OWNER,
        "workspace_id": actor_payload["workspace_id"],
        "session": _public_credential(stored),
        "one_time_credential": {
            "credential_kind": "liveuin_session",
            "session_id": session_id,
            "session_headers": session_headers,
            "expires_at": expires_at,
            "expires_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at)) if expires_at else "",
            "raw_secret_returned_once": True,
            "raw_secret_stored": False,
        },
        "boundary": {
            "surface": "private Core Identity admin issuer",
            "layer": "local session issuance contract for gateway context",
            "owner": CANONICAL_OWNER,
            "not_production_idp": True,
            "secret_policy": "The raw session is returned once to the caller and only its hash is stored.",
            "wechat_role": "WeChat remains an identity/message bridge and does not mint LiveUIN product-write credentials.",
        },
    }


def issue_api_key(payload: Dict[str, Any] | None = None, request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    actor_payload = _credential_actor_payload(payload)
    if not actor_payload["actor_id"]:
        return error("actor_id_required", 400)
    if not actor_payload["role"]:
        return error("role_required", 400)
    if not actor_payload["scopes"]:
        return error("scopes_required", 400)

    now = int(time.time())
    ttl_seconds = _bounded_ttl(
        payload.get("ttl_seconds") or payload.get("api_key_ttl_seconds"),
        default=DEFAULT_API_KEY_TTL_SECONDS,
        maximum=MAX_API_KEY_TTL_SECONDS,
    )
    expires_at = now + ttl_seconds if ttl_seconds else 0
    api_key = _issuer_secret("luak")
    key_id = _clean_id(payload.get("key_id"), 120) or ("key_" + uuid.uuid4().hex[:16])
    stored = credential_store.upsert_api_key(
        {
            **actor_payload,
            "api_key": api_key,
            "key_id": key_id,
            "issued_at": now,
            "expires_at": expires_at,
            "policy_version": _clean_id(payload.get("policy_version"), 80),
            "metadata": {
                **_as_dict(payload.get("metadata")),
                "issuer": "liveuin_identity",
                "issuer_contract": PHASE,
                "surface": "private_core_identity_admin",
            },
        },
        request_meta=request_meta,
    )
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "identity_api_key_issued",
        "canonical_owner": CANONICAL_OWNER,
        "workspace_id": actor_payload["workspace_id"],
        "api_key": _public_credential(stored),
        "one_time_credential": {
            "credential_kind": "liveuin_api_key",
            "key_id": key_id,
            "api_key": api_key,
            "header_name": "X-LiveUIN-API-Key",
            "expires_at": expires_at,
            "expires_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_at)) if expires_at else "",
            "raw_secret_returned_once": True,
            "raw_secret_stored": False,
        },
        "boundary": {
            "surface": "private Core Identity admin issuer",
            "layer": "local API-key issuance contract for gateway context",
            "owner": CANONICAL_OWNER,
            "not_production_idp": True,
            "secret_policy": "The raw API key is returned once to the caller and only its hash is stored.",
            "connector_role": "Connector keys identify handoff transport only and do not make connector tables product truth.",
        },
    }


def _api_key_hash_from_payload(payload: Dict[str, Any]) -> str:
    explicit_hash = str(payload.get("api_key_hash") or payload.get("credential_hash") or "").strip()
    if explicit_hash:
        return explicit_hash
    raw_key = str(payload.get("api_key") or payload.get("raw_api_key") or "").strip()
    if raw_key:
        return credential_store.hash_secret(raw_key)
    key_id = _clean_id(payload.get("key_id"), 120)
    workspace_id = _clean_id(payload.get("workspace_id") or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID
    if key_id:
        for item in credential_store.list_api_keys(workspace_id=workspace_id, limit=500):
            if item.get("key_id") == key_id:
                return str(item.get("api_key_hash") or "")
    return ""


def revoke_session(payload: Dict[str, Any] | None = None, request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    session_hash = str(payload.get("session_id_hash") or payload.get("credential_hash") or "").strip()
    if not session_hash and payload.get("session_id"):
        session_hash = credential_store.hash_secret(payload.get("session_id"))
    if not session_hash:
        return error("session_id_or_hash_required", 400)
    workspace_id = _clean_id(payload.get("workspace_id") or "", 96)
    revoked = credential_store.revoke_session(
        session_hash,
        workspace_id=workspace_id,
        reason=_clean_slug(payload.get("reason"), "manual_revocation", 120),
        request_meta=request_meta,
    )
    if not revoked:
        return error("identity_session_not_found", 404)
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "identity_session_revoked",
        "canonical_owner": CANONICAL_OWNER,
        "session": _public_credential(revoked),
        "raw_secret_echoed": False,
    }


IDENTITY_SESSION_COOKIE_NAMES = tuple(COOKIE_TO_HEADER)


def logout_session(
    headers: Mapping[str, str] | None = None,
    *,
    request_context: Dict[str, Any] | None = None,
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    effective_headers = _headers_with_cookie_session(headers)
    session_header = COOKIE_TO_HEADER.get("LIVEUIN_SESSION_ID", "X-LiveUIN-Session-Id")
    session_id = _header(effective_headers, session_header)
    revoked = False

    if session_id:
        result = revoke_session(
            {"session_id": session_id, "reason": "logout"},
            request_meta,
        )
        # Read back the current credential only. Unknown/already inactive logout
        # remains idempotent, while failed durable revocation cannot report success.
        validation = credential_store.validate_session_hash(credential_store.hash_secret(session_id))
        if validation.get("active") is not False:
            return error("identity_session_logout_incomplete", 503)
        revoked = bool(result.get("ok"))

    host = str(_as_dict(request_context).get("host") or "").split(":", 1)[0].strip().lower()
    domain = ".liveuin.com" if host == "liveuin.com" or host.endswith(".liveuin.com") else ""
    cleared = []
    for name in IDENTITY_SESSION_COOKIE_NAMES:
        parts = [f"{name}=", "Max-Age=0", "Path=/", "HttpOnly", "SameSite=Lax", "Secure"]
        if domain:
            parts.append(f"Domain={domain}")
        cleared.append("; ".join(parts))

    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "identity_session_logged_out",
        "revoked": revoked,
        "set_cookie_headers": cleared,
        "raw_secret_echoed": False,
    }


def revoke_active_workspace_sessions(
    workspace_id: str,
    *,
    actor_ids: list[str] | None = None,
    exclude_session_ids: list[str] | None = None,
    reason: str = "workspace_session_revocation",
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    """Revoke every active session for a tightly scoped internal workspace role set."""
    workspace_id = _clean_id(workspace_id, 96)
    if not workspace_id:
        return error("workspace_id_required", 400)
    allowed_actor_ids = {_clean_id(actor_id, 96) for actor_id in (actor_ids or []) if _clean_id(actor_id, 96)}
    excluded_hashes = {credential_store.hash_secret(session_id) for session_id in (exclude_session_ids or []) if str(session_id or "").strip()}
    revoked = 0
    failures: list[str] = []
    before_updated_at = 0
    before_session_id_hash = ""
    while True:
        records = credential_store.list_sessions(
            workspace_id=workspace_id,
            limit=500,
            before_updated_at=before_updated_at,
            before_session_id_hash=before_session_id_hash,
        )
        if not records:
            break
        for record in records:
            if record.get("status") != "active" or str(record.get("session_id_hash") or "") in excluded_hashes or (allowed_actor_ids and record.get("actor_id") not in allowed_actor_ids):
                continue
            response = revoke_session(
                {
                    "workspace_id": workspace_id,
                    "session_id_hash": str(record.get("session_id_hash") or ""),
                    "reason": reason,
                },
                request_meta,
            )
            if response.get("ok") is False:
                failures.append(str(record.get("session_id_hint") or record.get("actor_id") or "session"))
            else:
                revoked += 1
        before_updated_at = int(records[-1].get("updated_at") or 0)
        before_session_id_hash = str(records[-1].get("session_id_hash") or "")
    if failures:
        return error("workspace_session_revocation_incomplete", 503, revoked_count=revoked, failed_session_hints=failures)
    return {
        "ok": True,
        "status": "workspace_sessions_revoked",
        "workspace_id": workspace_id,
        "revoked_count": revoked,
        "raw_secret_echoed": False,
    }


def revoke_api_key(payload: Dict[str, Any] | None = None, request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    api_key_hash = _api_key_hash_from_payload(payload)
    key_id = _clean_id(payload.get("key_id"), 120)
    if not api_key_hash and not key_id:
        return error("api_key_or_key_id_required", 400)
    revoked = credential_store.revoke_api_key(
        api_key_hash,
        key_id=key_id,
        workspace_id=_clean_id(payload.get("workspace_id") or "", 96),
        reason=_clean_slug(payload.get("reason"), "manual_revocation", 120),
        request_meta=request_meta,
    )
    if not revoked:
        return error("identity_api_key_not_found", 404)
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "identity_api_key_revoked",
        "canonical_owner": CANONICAL_OWNER,
        "api_key": _public_credential(revoked),
        "raw_secret_echoed": False,
    }


def rotate_api_key(payload: Dict[str, Any] | None = None, request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    old_hash = _api_key_hash_from_payload(payload)
    if not old_hash:
        return error("api_key_or_key_id_required", 400)
    new_api_key = _issuer_secret("luak")
    now = int(time.time())
    ttl_seconds = _bounded_ttl(
        payload.get("ttl_seconds") or payload.get("api_key_ttl_seconds"),
        default=DEFAULT_API_KEY_TTL_SECONDS,
        maximum=MAX_API_KEY_TTL_SECONDS,
    )
    rotated = credential_store.rotate_api_key(
        old_hash,
        {
            "api_key": new_api_key,
            "key_id": _clean_id(payload.get("new_key_id"), 120) or ("key_" + uuid.uuid4().hex[:16]),
            "expires_at": now + ttl_seconds if ttl_seconds else 0,
            "policy_version": _clean_id(payload.get("policy_version"), 80),
            "metadata": {
                **_as_dict(payload.get("metadata")),
                "issuer": "liveuin_identity",
                "issuer_contract": PHASE,
                "surface": "private_core_identity_admin",
                "rotation_reason": _clean_slug(payload.get("reason"), "manual_rotation", 120),
            },
        },
        request_meta=request_meta,
    )
    if rotated.get("ok") is False:
        return error(str(rotated.get("detail") or "identity_api_key_rotation_failed"), 404)
    created = _as_dict(rotated.get("api_key"))
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "identity_api_key_rotated",
        "canonical_owner": CANONICAL_OWNER,
        "rotated_from": _public_credential(_as_dict(rotated.get("rotated_from"))),
        "api_key": _public_credential(created),
        "one_time_credential": {
            "credential_kind": "liveuin_api_key",
            "key_id": created.get("key_id", ""),
            "api_key": new_api_key,
            "header_name": "X-LiveUIN-API-Key",
            "expires_at": created.get("expires_at", 0),
            "raw_secret_returned_once": True,
            "raw_secret_stored": False,
        },
    }


def list_credentials(workspace_id: str = DEFAULT_WORKSPACE_ID, limit: int = 100) -> Dict[str, Any]:
    workspace_id = _clean_id(workspace_id or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID
    limit = max(1, min(int(limit or 100), 500))
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "status": "identity_credentials_listed",
        "canonical_owner": CANONICAL_OWNER,
        "workspace_id": workspace_id,
        "sessions": [_public_credential(item) for item in credential_store.list_sessions(workspace_id=workspace_id, limit=limit)],
        "api_keys": [_public_credential(item) for item in credential_store.list_api_keys(workspace_id=workspace_id, limit=limit)],
        "raw_secret_echoed": False,
    }


def prepare_guard_inputs(
    headers: Mapping[str, str] | None,
    payload: Dict[str, Any] | None,
    *,
    session_context: Dict[str, Any] | None = None,
    required: bool = True,
    method: str = "POST",
    path: str = "",
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    session_context = session_context if isinstance(session_context, dict) else {}
    merged_payload = dict(payload)
    if session_context:
        context_access = _as_dict(session_context.get("access") or session_context.get("access_context"))
        if context_access:
            merged_payload["access"] = {
                **_as_dict(merged_payload.get("access") or merged_payload.get("access_context")),
                **context_access,
            }
        elif session_context.get("actor"):
            merged_payload["access"] = {
                **_as_dict(merged_payload.get("access") or merged_payload.get("access_context")),
                "actor": _as_dict(session_context.get("actor")),
                "workspace_id": session_context.get("workspace_id") or payload.get("workspace_id") or DEFAULT_WORKSPACE_ID,
                "source_family": session_context.get("source_family") or "liveuin_core",
                "idempotency_key": session_context.get("idempotency_key") or payload.get("idempotency_key") or "",
                "context": _as_dict(session_context.get("context")),
            }

    resolved = resolve_access_context(
        merged_payload,
        headers,
        method=method,
        path=path,
        request_meta=request_meta,
        require_identity=required,
    )
    if resolved.get("ok") is False:
        return resolved

    access = _as_dict(resolved.get("access"))
    cleaned_payload = {key: value for key, value in payload.items() if key not in {"actor", "scopes"}}
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "payload": {
            **cleaned_payload,
            "workspace_id": resolved.get("workspace_id") or payload.get("workspace_id") or DEFAULT_WORKSPACE_ID,
            "access": access,
        },
        "headers": access_headers(access, headers),
        "identity_session": resolved,
    }


def status() -> Dict[str, Any]:
    credential_store_summary = credential_store.debug_summary()
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "service": "liveuin-core-identity-session",
        "canonical_owner": CANONICAL_OWNER,
        "session_signature_required": True,
        "signing_secret_configured": bool(_signing_secret()),
        "credential_store_enforcement": _credential_store_enforcement(),
        "credential_store": credential_store_summary["store"],
        "credential_store_sqlite_path": credential_store_summary["sqlite_path"],
        "credential_store_tables": credential_store_summary["tables"],
        "credential_families": [
            "liveuin_session",
            "liveuin_api_key",
            "connector_api_key",
            "wechat_bridge_identity",
            "upstream_access_context",
        ],
        "session_max_age_seconds": _session_max_age_seconds(),
        "routes": [
            "GET /api/core/identity/session/status",
            "POST /api/core/identity/session/resolve",
            "POST /api/core/identity/session/issue",
            "POST /api/core/identity/session/revoke",
            "GET /api/core/identity/credentials",
            "POST /api/core/identity/api-keys",
            "POST /api/core/identity/api-keys/revoke",
            "POST /api/core/identity/api-keys/rotate",
        ],
        "boundary": {
            "surface": "Core gateway identity/session middleware",
            "layer": "identity context normalization and private local credential issuance before access policy",
            "owner": CANONICAL_OWNER,
            "local_issuer_role": "Mints local gateway sessions/API keys for private Core/Admin use and returns raw credentials once; production still needs the real LiveUIN login/session issuer and vault-backed credential persistence.",
            "credential_store_role": "Stores hashes, roles, scopes, status, expiry, revocation, and rotation lineage for LiveUIN sessions and API keys; raw secrets are never stored.",
            "does_not_make_channels_truth": True,
            "wechat_role": "identity/OAuth/callback/message delivery only; bridge credentials are forced to Pass/channel context",
            "connector_role": "authorized handoff transport only; connector records do not become product truth",
        },
    }
