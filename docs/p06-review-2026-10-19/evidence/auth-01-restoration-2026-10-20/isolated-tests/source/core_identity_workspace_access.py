from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import time
import uuid
from typing import Any, Dict, List

try:
    from . import core_identity_session as identity_session
    from . import core_identity_store as store
except ImportError:  # pragma: no cover - supports direct script execution.
    import core_identity_session as identity_session
    import core_identity_store as store


SCHEMA_VERSION = "liveuin-core-identity-workspace-access-v1"
PHASE = "phase36-google-workspace-membership-admission"
DEFAULT_WORKSPACE_ID = "laijuzhu"
CANONICAL_OWNER = "LiveUIN Identity + Core Access"

ACTIVE_WORKSPACE_STATUSES = {"active", "workspace_created", "paid", "trialing"}
ACTIVE_MEMBER_STATUSES = {"active"}
PENDING_MEMBER_STATUSES = {"pending", "pending_approval", "invited"}
BLOCKED_MEMBER_STATUSES = {"suspended", "revoked", "blocked", "disabled"}

CONNECT_PLAN_SEAT_LIMITS = {
    "starter": 1,
    "pro": 3,
    "scale": 10,
    "enterprise": None,
}

WORKSPACE_ROLE_TO_ACCESS_ROLE = {
    "owner": "connector_admin",
    "admin": "connector_admin",
    "billing_admin": "connector_admin",
    "manager": "agent",
    "member": "agent",
    "assistant": "agent",
    "viewer": "agent",
    "subscriber": "agent",
}

ELEVATED_ACCESS_ROLES = {
    "accountant",
    "admin",
    "booking_ops",
    "finance_manager",
    "finance_ops",
    "identity_admin",
    "operator",
    "ops",
    "ops_manager",
    "payment_ops",
    "super_admin",
    "trust_reviewer",
    "vendor",
}

OPS_PORTAL_ACCESS_ROLES = {"operator", "ops", "ops_manager", "super_admin"}

SENSITIVE_KEYS = {
    "access_token",
    "authorization",
    "client_secret",
    "code",
    "contact_email",
    "email",
    "id_token",
    "raw_secret",
    "refresh_token",
    "session",
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


def _clean_workspace(value: Any) -> str:
    text = str(value or "").strip()
    cleaned = "".join(ch for ch in text if ch.isalnum() or ch in {"_", "-", ".", ":"})
    return cleaned[:96] or DEFAULT_WORKSPACE_ID


def _clean_slug(value: Any, default: str = "", max_length: int = 120) -> str:
    cleaned = re.sub(r"[^a-z0-9_.:-]+", "_", str(value or "").strip().lower()).strip("_")
    return (cleaned or default)[:max_length]


def _clean_text(value: Any, max_length: int = 240) -> str:
    return str(value or "").strip()[:max_length]


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


def _hash(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _email(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if "@" in text and not text.startswith("@") and not text.endswith("@") else ""


def _email_hash(value: Any) -> str:
    email = _email(value)
    return _hash(email) if email else ""


def _email_domain(value: Any) -> str:
    email = _email(value)
    return email.rsplit("@", 1)[1] if "@" in email else ""


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


def error(detail: str, status_code: int = 400, **extra: Any) -> Dict[str, Any]:
    return {"ok": False, "detail": detail, "status_code": status_code, **extra}


def _plan_slug(value: Any) -> str:
    plan = _clean_slug(value, "starter", 40)
    return plan if plan in CONNECT_PLAN_SEAT_LIMITS else "starter"


def _seat_limit(plan_type: Any, metadata: Dict[str, Any] | None = None) -> int | None:
    metadata = _as_dict(metadata)
    for candidate in (
        _as_dict(metadata.get("feature_limits")).get("team_seats"),
        _as_dict(metadata.get("tier_policy")).get("team_seats"),
        _as_dict(metadata.get("billing")).get("team_seats"),
        metadata.get("seat_limit"),
        metadata.get("users"),
    ):
        if candidate in (None, ""):
            continue
        try:
            parsed = int(candidate)
        except (TypeError, ValueError):
            continue
        if parsed > 0:
            return parsed
    return CONNECT_PLAN_SEAT_LIMITS.get(_plan_slug(plan_type))


def _access_role(workspace_role: Any = "", access_role: Any = "") -> str:
    requested = _clean_slug(access_role, "", 80)
    if requested:
        return requested if requested in identity_session.ROLE_DEFAULT_SCOPES else ""
    workspace_role = _clean_slug(workspace_role, "member", 80)
    if workspace_role in WORKSPACE_ROLE_TO_ACCESS_ROLE:
        mapped = WORKSPACE_ROLE_TO_ACCESS_ROLE[workspace_role]
        return mapped if mapped in identity_session.ROLE_DEFAULT_SCOPES else ""
    return workspace_role if workspace_role in identity_session.ROLE_DEFAULT_SCOPES else ""


def _scopes_for_role(access_role: str) -> List[str]:
    scopes = identity_session.ROLE_DEFAULT_SCOPES.get(access_role)
    if scopes is not None:
        return list(scopes)
    return []


def _public_workspace_record(record: Dict[str, Any]) -> Dict[str, Any]:
    record = _as_dict(record)
    if not record:
        return {}
    return {
        "workspace_id": record.get("workspace_id", ""),
        "source": record.get("source", ""),
        "product_line": record.get("product_line", ""),
        "plan_type": record.get("plan_type", ""),
        "status": record.get("status", ""),
        "contact_email_hash_present": bool(record.get("contact_email_hash")),
        "contact_email_domain": record.get("contact_email_domain", ""),
        "seat_limit": record.get("seat_limit"),
        "updated_at": _iso_from_epoch(record.get("updated_at")),
        "raw_email_stored": False,
    }


def _public_membership(record: Dict[str, Any]) -> Dict[str, Any]:
    record = _as_dict(record)
    if not record:
        return {}
    return {
        "membership_id": record.get("membership_id", ""),
        "workspace_id": record.get("workspace_id", ""),
        "person_id": record.get("person_id", ""),
        "email_hash_present": bool(record.get("email_hash")),
        "email_domain": record.get("email_domain", ""),
        "workspace_role": record.get("workspace_role", ""),
        "access_role": record.get("access_role", ""),
        "status": record.get("status", ""),
        "source": record.get("source", ""),
        "plan_type": record.get("plan_type", ""),
        "seat_limit": record.get("seat_limit"),
        "elevated_approval_required": bool(record.get("elevated_approval_required")),
        "approved": bool(record.get("approved_by") or record.get("approved_at")),
        "updated_at": _iso_from_epoch(record.get("updated_at")),
        "raw_email_stored": False,
    }


def _public_invite(record: Dict[str, Any]) -> Dict[str, Any]:
    record = _as_dict(record)
    if not record:
        return {}
    return {
        "invite_id": record.get("invite_id", ""),
        "workspace_id": record.get("workspace_id", ""),
        "email_hash_present": bool(record.get("email_hash")),
        "email_domain": record.get("email_domain", ""),
        "workspace_role": record.get("workspace_role", ""),
        "access_role": record.get("access_role", ""),
        "status": record.get("status", ""),
        "invited_by": record.get("invited_by", ""),
        "expires_at": _iso_from_epoch(record.get("expires_at")),
        "accepted_at": _iso_from_epoch(record.get("accepted_at")),
        "raw_email_stored": False,
    }


def _audit(event_type: str, workspace_id: str, payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> str:
    event_id = "iwa_evt_" + uuid.uuid4().hex[:16]
    store.append_audit_event(
        {
            "event_id": event_id,
            "workspace_id": workspace_id,
            "event_type": event_type,
            "object_type": "workspace_access",
            "object_id": _clean_text(payload.get("membership_id") or payload.get("invite_id") or workspace_id, 120),
            "payload": _redact(payload),
            "received_at": _now(),
        },
        request_meta,
    )
    return event_id


def _workspace_active(record: Dict[str, Any]) -> bool:
    status = _clean_slug(record.get("status"), "", 80)
    if status not in ACTIVE_WORKSPACE_STATUSES:
        return False
    plan_type = _plan_slug(record.get("plan_type"))
    billing = _as_dict(_as_dict(record.get("metadata")).get("billing"))
    if plan_type != "starter" and billing:
        return bool(billing.get("paid_entitlement_active") or billing.get("status") in {"active", "paid", "trialing"})
    return True


def sync_connect_workspace(site: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    site = _as_dict(site)
    workspace_id = _clean_workspace(site.get("workspace_id"))
    contact_email = _email(site.get("contact_email") or _as_dict(site.get("billing")).get("email"))
    plan_type = _plan_slug(site.get("plan_type"))
    metadata = _redact(
        {
            "canonical_owner": CANONICAL_OWNER,
            "source_system": _clean_text(site.get("source_system"), 120),
            "brand_slug": _clean_slug(site.get("brand_slug"), "", 120),
            "brand_display_name": _clean_text(site.get("brand_display_name"), 160),
            "source_brand": _clean_text(site.get("source_brand"), 160),
            "operator_brand": _clean_text(site.get("operator_brand"), 160),
            "site_url": _clean_text(site.get("site_url"), 240),
            "portal_base_url": _clean_text(site.get("portal_base_url"), 240),
            "connector_api_key_prefix": _clean_text(site.get("connector_api_key_prefix"), 32),
            "plugin": _clean_text(site.get("plugin"), 80),
            "plugin_version": _clean_text(site.get("plugin_version"), 40),
            "last_install_exchange_at": site.get("last_install_exchange_at"),
            "environment": _clean_slug(site.get("environment"), "production", 80),
            "partner_type": _clean_slug(site.get("partner_type"), "", 80),
            "allowed_domains": _as_list(site.get("allowed_domains")),
            "allowed_return_urls": _as_list(site.get("allowed_return_urls")),
            "tier_policy": _as_dict(site.get("tier_policy")),
            "feature_limits": _as_dict(site.get("feature_limits")),
            "branding_policy": _as_dict(site.get("branding_policy")),
            "entitlement_flags": _as_dict(site.get("entitlement_flags")),
            "usage": _as_dict(site.get("usage")),
            "billing": _as_dict(site.get("billing") or _as_dict(site.get("metadata")).get("billing")),
            "raw_contact_email_stored": False,
        }
    )
    record = store.upsert_workspace_record(
        {
            "workspace_id": workspace_id,
            "source": "liveuin_connect",
            "product_line": "connect",
            "plan_type": plan_type,
            "status": _clean_slug(site.get("status"), "active", 80),
            "contact_email_hash": _email_hash(contact_email),
            "contact_email_domain": _email_domain(contact_email),
            "seat_limit": _seat_limit(plan_type, metadata),
            "metadata": metadata,
        }
    )
    _audit(
        "identity.workspace_record_synced",
        workspace_id,
        {"workspace_id": workspace_id, "plan_type": plan_type, "contact_email_hash_present": bool(contact_email)},
        request_meta,
    )
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "workspace": _public_workspace_record(record),
    }


def provision_host_pilot_workspace(
    payload: Dict[str, Any],
    *,
    actor_id: str,
    idempotency_key: str,
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    """Provision the isolated Singapore Host pilot and its sole first owner."""
    payload = _as_dict(payload)
    actor_id = _clean_text(actor_id, 120)
    if not actor_id:
        return error("identity_admin_actor_required", 403)
    if payload.get("confirm_owner_authorized") is not True:
        return error("host_pilot_owner_authorization_confirmation_required", 400)
    if payload.get("workspace_id"):
        return error("host_pilot_workspace_id_is_server_generated", 400)

    email = _email(payload.get("owner_email"))
    if not email or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return error("host_pilot_owner_email_invalid", 400)
    configured_pods = str(os.getenv("LIVEUIN_IDENTITY_HOST_PILOT_POD_ALLOWLIST") or "sg=SG")
    approved_pods: Dict[str, str] = {}
    for entry in configured_pods.split(","):
        pod_token, separator, country_token = entry.strip().partition("=")
        pod_key = _clean_slug(pod_token, "", 64)
        pod_country = country_token.strip().upper()
        if not separator or not pod_key or not re.fullmatch(r"[A-Z]{2}", pod_country) or pod_key in approved_pods:
            return error("host_pilot_pod_configuration_invalid", 500)
        approved_pods[pod_key] = pod_country
    if not approved_pods:
        return error("host_pilot_pod_configuration_invalid", 500)

    pod_id = _clean_slug(payload.get("pod_id"), "", 64)
    country_code = str(payload.get("country_code") or "").strip().upper()
    if pod_id and not country_code:
        country_code = approved_pods.get(pod_id, "")
    if not re.fullmatch(r"[A-Z]{2}", country_code):
        return error("host_pilot_country_code_invalid", 400)
    if pod_id:
        if approved_pods.get(pod_id) != country_code:
            return error("host_pilot_pod_not_approved", 403)
    else:
        matching_pods = [key for key, value in approved_pods.items() if value == country_code]
        if not matching_pods:
            return error("host_pilot_pod_not_approved", 403)
        if len(matching_pods) != 1:
            return error("host_pilot_pod_id_required", 400, country_code=country_code)
        pod_id = matching_pods[0]

    try:
        key_uuid = uuid.UUID(str(idempotency_key or "").strip())
    except (TypeError, ValueError, AttributeError):
        return error("host_pilot_idempotency_key_must_be_uuid_v4", 400)
    if key_uuid.version != 4:
        return error("host_pilot_idempotency_key_must_be_uuid_v4", 400)

    now = _now()
    workspace_id = "host_" + key_uuid.hex
    email_hash = _email_hash(email)
    email_domain = _email_domain(email)
    idempotency_hash = hashlib.sha256(key_uuid.bytes).hexdigest()
    membership_id = "wmem_" + uuid.uuid4().hex[:16]
    event_id = "iwa_evt_" + uuid.uuid4().hex[:16]
    record = {
        "workspace_id": workspace_id,
        "source": "liveuin_identity_admin_host_pilot",
        "product_line": "host",
        "plan_type": "starter",
        "status": "active",
        "contact_email_hash": email_hash,
        "contact_email_domain": email_domain,
        "seat_limit": 1,
        "metadata": {
            "canonical_owner": CANONICAL_OWNER,
            "pilot_mode": "single_owner",
            "pod_id": pod_id,
            "country_code": country_code,
            "provisioned_by_actor_id": actor_id,
            "provisioning_idempotency_hash": idempotency_hash,
            "raw_owner_email_stored": False,
        },
        "created_at": now,
        "updated_at": now,
    }
    membership = {
        "membership_id": membership_id,
        "workspace_id": workspace_id,
        "email_hash": email_hash,
        "email_domain": email_domain,
        "workspace_role": "owner",
        "access_role": "owner",
        "status": "active",
        "source": "identity_admin_host_pilot",
        "plan_type": "starter",
        "seat_limit": 1,
        "elevated_approval_required": False,
        "approved_by": actor_id,
        "approved_at": now,
        "metadata": {
            "canonical_owner": CANONICAL_OWNER,
            "pod_id": pod_id,
            "country_code": country_code,
            "raw_email_stored": False,
            "provisioning_flow": "host_pilot_admin_provision",
        },
        "created_at": now,
        "updated_at": now,
    }
    audit_payload = {
        "workspace_id": workspace_id,
        "product_line": "host",
        "status": "active",
        "country_code": country_code,
        "membership_id": membership_id,
        "workspace_role": "owner",
        "access_role": "owner",
        "owner_email_hash_present": True,
        "owner_email_domain": email_domain,
        "provisioned_by_actor_id": actor_id,
        "provisioning_idempotency_hash": idempotency_hash,
        "raw_owner_email_stored": False,
    }

    try:
        result = store.create_host_workspace_with_owner(
            {
                **record,
                "metadata": {**record["metadata"], "country_code": country_code},
            },
            membership,
            {
                "event_id": event_id,
                "workspace_id": workspace_id,
                "event_type": "identity.host_workspace_provisioned",
                "object_type": "host_workspace",
                "object_id": workspace_id,
                "payload": audit_payload,
                "received_at": now,
            },
            request_meta,
        )
    except sqlite3.IntegrityError:
        return error("host_workspace_provisioning_conflict", 409)
    except sqlite3.Error:
        return error("host_workspace_provisioning_storage_unavailable", 503)
    except ValueError:
        return error("host_workspace_provisioning_contract_invalid", 500)

    if result.get("ok") is not True:
        detail = str(result.get("detail") or "host_workspace_provisioning_conflict")
        return error(detail, 409)

    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "status": "host_workspace_provisioned" if result.get("created") else "host_workspace_provisioning_replayed",
        "created": bool(result.get("created")),
        "workspace": _public_workspace_record(result.get("workspace")),
        "membership": _public_membership(result.get("membership")),
        "audit_event_id": str(result.get("audit_event_id") or ""),
        "raw_email_stored": False,
    }


def _load_connect_workspace_from_postgres(workspace_id: str) -> Dict[str, Any]:
    if not (os.getenv("LIVEUIN_DB_DSN") or os.getenv("OPS_DB_DSN") or os.getenv("DATABASE_URL")):
        return {}
    try:
        from db import get_db_connection
        from psycopg2.extras import RealDictCursor
    except Exception:
        return {}
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT workspace_id, brand_slug, source_system, plan_type, status,
                           contact_email, tier_policy, feature_limits,
                           entitlement_flags, metadata
                    FROM ops.connect_workspaces
                    WHERE workspace_id = %s
                    LIMIT 1;
                    """,
                    (workspace_id,),
                )
                row = cur.fetchone()
    except Exception:
        return {}
    if not row:
        return {}
    synced = sync_connect_workspace(dict(row), {"source": "connect_postgres_lookup"})
    return store.get_workspace_record(workspace_id) if synced.get("ok") else {}


def _workspace_record(workspace_id: str) -> Dict[str, Any]:
    workspace_id = _clean_workspace(workspace_id)
    record = store.get_workspace_record(workspace_id)
    if record:
        return record
    return _load_connect_workspace_from_postgres(workspace_id)


def _membership_allowed(membership: Dict[str, Any]) -> Dict[str, Any]:
    status = _clean_slug(membership.get("status"), "", 80)
    access_role = _access_role(membership.get("workspace_role"), membership.get("access_role"))
    if status in BLOCKED_MEMBER_STATUSES:
        return error("google_workspace_membership_blocked", 403, membership=_public_membership(membership))
    if status in PENDING_MEMBER_STATUSES:
        return error("google_workspace_membership_pending", 403, membership=_public_membership(membership))
    if status not in ACTIVE_MEMBER_STATUSES:
        return error("google_workspace_membership_not_active", 403, membership=_public_membership(membership))
    if access_role in ELEVATED_ACCESS_ROLES and not (membership.get("approved_by") or membership.get("approved_at")):
        return error(
            "google_workspace_elevated_access_requires_approval",
            403,
            membership=_public_membership(membership),
        )
    return {"ok": True, "access_role": access_role}


def _seat_available(workspace_id: str, seat_limit: int | None) -> bool:
    if seat_limit is None:
        return True
    return store.count_active_workspace_memberships(workspace_id) < int(seat_limit)


def _role_context(access_role: str, role_source: str, **extra: Any) -> Dict[str, Any]:
    return {
        "role": access_role,
        "scopes": _scopes_for_role(access_role),
        "role_source": role_source,
        **extra,
    }


def grant_workspace_membership(
    payload: Dict[str, Any],
    request_meta: Dict[str, str] | None = None,
    *,
    authenticated_approver_id: str = "",
) -> Dict[str, Any]:
    payload = _as_dict(payload)
    payload.pop("approved_by", None)
    payload.pop("approver", None)
    payload.pop("approved_at", None)
    membership_metadata = _as_dict(payload.get("metadata")).copy()
    membership_metadata.pop("approved_by", None)
    membership_metadata.pop("approver", None)
    membership_metadata.pop("approved_at", None)
    workspace_id = _clean_workspace(payload.get("workspace_id"))
    email = _email(payload.get("email"))
    email_hash = _clean_text(payload.get("email_hash") or _email_hash(email), 128)
    person_id = _clean_text(payload.get("person_id"), 96)
    if not email_hash and not person_id:
        return error("workspace_membership_email_or_person_required")

    workspace_role = _clean_slug(payload.get("workspace_role") or payload.get("role"), "member", 80)
    access_role = _access_role(workspace_role, payload.get("access_role"))
    if not access_role:
        return error("workspace_membership_access_role_invalid", 422)
    workspace = _workspace_record(workspace_id)
    plan_type = _plan_slug(payload.get("plan_type") or workspace.get("plan_type"))
    seat_limit = payload.get("seat_limit")
    if seat_limit in (None, ""):
        seat_limit = _seat_limit(plan_type, _as_dict(workspace.get("metadata")))
    elevated = access_role in ELEVATED_ACCESS_ROLES
    status = _clean_slug(payload.get("status"), "active", 80)
    approved_by = _clean_text(authenticated_approver_id, 120) if elevated and status == "active" else ""
    approved_at = _now() if approved_by else None
    if elevated and status == "active" and not approved_by:
        return error("workspace_membership_elevated_approval_required", 403, access_role=access_role)
    existing = store.get_workspace_membership_by_email(workspace_id, email_hash) if email_hash else {}
    if not existing and person_id:
        existing = store.get_workspace_membership_by_person(workspace_id, person_id)
    if status == "active" and not existing and not _seat_available(workspace_id, seat_limit):
        return error("workspace_membership_seat_limit_exceeded", 403, seat_limit=seat_limit)

    membership = store.upsert_workspace_membership(
        {
            "membership_id": existing.get("membership_id") or "wmem_" + uuid.uuid4().hex[:16],
            "workspace_id": workspace_id,
            "person_id": person_id,
            "email_hash": email_hash,
            "email_domain": _clean_text(payload.get("email_domain") or _email_domain(email), 120),
            "workspace_role": workspace_role,
            "access_role": access_role,
            "status": status,
            "source": _clean_slug(payload.get("source"), "manual", 80),
            "plan_type": plan_type,
            "seat_limit": seat_limit,
            "elevated_approval_required": elevated,
            "approved_by": approved_by,
            "approved_at": approved_at,
            "metadata": {
                "canonical_owner": CANONICAL_OWNER,
                "raw_email_stored": False,
                **membership_metadata,
            },
        }
    )
    audit_payload = _public_membership(membership)
    if approved_by:
        audit_payload.update(
            {
                "approved_by_actor_id": approved_by,
                "approved_at": approved_at,
            }
        )
    event_id = _audit(
        "identity.workspace_membership_granted",
        workspace_id,
        audit_payload,
        request_meta,
    )
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "workspace_id": workspace_id,
        "membership": _public_membership(membership),
        "audit_event_id": event_id,
    }


def invite_workspace_member(
    payload: Dict[str, Any],
    request_meta: Dict[str, str] | None = None,
    *,
    authenticated_approver_id: str = "",
) -> Dict[str, Any]:
    payload = _as_dict(payload)
    payload.pop("approved_by", None)
    payload.pop("approver", None)
    payload.pop("approved_at", None)
    payload.pop("invited_by", None)
    invite_metadata = _as_dict(payload.get("metadata")).copy()
    invite_metadata.pop("approved_by", None)
    invite_metadata.pop("approver", None)
    invite_metadata.pop("approved_at", None)
    invite_metadata.pop("invited_by", None)
    payload["metadata"] = invite_metadata
    workspace_id = _clean_workspace(payload.get("workspace_id"))
    email = _email(payload.get("email"))
    if not email:
        return error("workspace_invite_email_required")
    workspace_role = _clean_slug(payload.get("workspace_role") or payload.get("role"), "member", 80)
    access_role = _access_role(workspace_role, payload.get("access_role"))
    if not access_role:
        return error("workspace_invite_access_role_invalid", 422)
    elevated = access_role in ELEVATED_ACCESS_ROLES
    authenticated_actor_id = _clean_text(authenticated_approver_id, 120)
    approved_by = authenticated_actor_id if elevated else ""
    approved_at = _now() if approved_by else None
    status = "invited" if (not elevated or approved_by) else "pending"
    ttl_seconds = int(payload.get("ttl_seconds") or 60 * 60 * 24 * 14)
    invite = store.upsert_workspace_invite(
        {
            "invite_id": _clean_text(payload.get("invite_id"), 120) or "winv_" + uuid.uuid4().hex[:16],
            "workspace_id": workspace_id,
            "email_hash": _email_hash(email),
            "email_domain": _email_domain(email),
            "workspace_role": workspace_role,
            "access_role": access_role,
            "status": status,
            "invited_by": authenticated_actor_id,
            "expires_at": int(payload.get("expires_at") or (_now() + ttl_seconds)),
            "metadata": {
                "canonical_owner": CANONICAL_OWNER,
                "raw_email_stored": False,
                "elevated_approval_required": elevated,
                "approved_by": approved_by,
                "approved_at": approved_at,
                **_as_dict(payload.get("metadata")),
            },
        }
    )
    audit_payload = _public_invite(invite)
    audit_payload["invited_by_actor_id"] = authenticated_actor_id
    if approved_by:
        audit_payload["approved_by_actor_id"] = approved_by
        audit_payload["approved_at"] = approved_at
    event_id = _audit("identity.workspace_invite_created", workspace_id, audit_payload, request_meta)
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "workspace_id": workspace_id,
        "invite": _public_invite(invite),
        "audit_event_id": event_id,
    }


def bind_membership_person(membership_id: str, person_id: str, request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    membership = store.get_workspace_membership(_clean_text(membership_id, 120))
    person_id = _clean_text(person_id, 96)
    if not membership or not person_id:
        return error("workspace_membership_bind_not_found", 404)
    membership["person_id"] = person_id
    updated = store.upsert_workspace_membership(membership)
    event_id = _audit("identity.workspace_membership_bound_person", updated["workspace_id"], _public_membership(updated), request_meta)
    return {"ok": True, "membership": _public_membership(updated), "audit_event_id": event_id}


def _access_from_existing_membership(workspace_id: str, email_hash: str) -> Dict[str, Any]:
    membership = store.get_workspace_membership_by_email(workspace_id, email_hash)
    if not membership:
        return {}
    allowed = _membership_allowed(membership)
    if allowed.get("ok") is not True:
        return allowed
    access_role = str(allowed.get("access_role") or membership.get("access_role"))
    return {
        "ok": True,
        "source": "workspace_membership",
        "membership": membership,
        "role_context": _role_context(access_role, "workspace_membership", membership=_public_membership(membership)),
    }


def resolve_ops_workspace_access(email_hash: str, workspace_id: str = "") -> Dict[str, Any]:
    """Resolve Ops access from active membership; never invent a tenant."""
    email_hash = _clean_text(email_hash, 128)
    requested_workspace_id = _clean_workspace(workspace_id) if str(workspace_id or "").strip() else ""
    if not email_hash:
        return error("ops_workspace_membership_required", 403)

    memberships = (
        [store.get_workspace_membership_by_email(requested_workspace_id, email_hash)]
        if requested_workspace_id
        else store.list_workspace_memberships_by_email(email_hash, limit=50)
    )
    candidates: List[Dict[str, Any]] = []
    for membership in memberships:
        if not membership or str(membership.get("status") or "").strip().lower() not in ACTIVE_MEMBER_STATUSES:
            continue
        access_role = _access_role(membership.get("workspace_role"), membership.get("access_role"))
        if access_role not in OPS_PORTAL_ACCESS_ROLES:
            continue
        if _membership_allowed(membership).get("ok") is not True:
            continue
        candidates.append(
            {
                "workspace_id": str(membership.get("workspace_id") or ""),
                "membership": membership,
                "role_context": _role_context(
                    access_role,
                    "workspace_membership",
                    membership=_public_membership(membership),
                ),
            }
        )

    unique = {item["workspace_id"]: item for item in candidates if item.get("workspace_id")}
    if len(unique) == 1:
        return {"ok": True, **next(iter(unique.values()))}
    if len(unique) > 1:
        return error("ops_workspace_selection_required", 409)
    return error("ops_workspace_membership_required", 403)


def _access_from_invite(workspace_id: str, email_hash: str, request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    invite = store.find_active_workspace_invite(workspace_id, email_hash, _now())
    if not invite:
        return {}
    access_role = _access_role(invite.get("workspace_role"), invite.get("access_role"))
    elevated = access_role in ELEVATED_ACCESS_ROLES
    invite_meta = _as_dict(invite.get("metadata"))
    if elevated and not invite_meta.get("approved_by"):
        return error("google_workspace_invite_elevated_access_requires_approval", 403, invite=_public_invite(invite))
    workspace = _workspace_record(workspace_id)
    seat_limit = _seat_limit(workspace.get("plan_type"), _as_dict(workspace.get("metadata")))
    if not _seat_available(workspace_id, seat_limit):
        return error("google_workspace_invite_seat_limit_exceeded", 403, seat_limit=seat_limit, invite=_public_invite(invite))
    membership = store.upsert_workspace_membership(
        {
            "membership_id": "wmem_" + uuid.uuid4().hex[:16],
            "workspace_id": workspace_id,
            "email_hash": invite.get("email_hash"),
            "email_domain": invite.get("email_domain"),
            "workspace_role": invite.get("workspace_role"),
            "access_role": access_role,
            "status": "active",
            "source": "workspace_invite",
            "plan_type": _plan_slug(workspace.get("plan_type")),
            "seat_limit": seat_limit,
            "elevated_approval_required": elevated,
            "approved_by": _clean_text(invite_meta.get("approved_by") or invite.get("invited_by"), 120) if elevated else "",
            "approved_at": _now() if elevated else None,
            "metadata": {
                "canonical_owner": CANONICAL_OWNER,
                "accepted_invite_id": invite.get("invite_id"),
                "raw_email_stored": False,
            },
        }
    )
    invite["status"] = "accepted"
    invite["accepted_at"] = _now()
    store.upsert_workspace_invite(invite)
    _audit("identity.workspace_invite_accepted", workspace_id, _public_invite(invite), request_meta)
    return {
        "ok": True,
        "source": "workspace_invite",
        "membership": membership,
        "role_context": _role_context(access_role, "workspace_invite", membership=_public_membership(membership)),
    }


def _access_from_connect_owner(workspace_id: str, email_hash: str, request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    workspace = _workspace_record(workspace_id)
    if not workspace or not _workspace_active(workspace):
        return {}
    if not email_hash or email_hash != workspace.get("contact_email_hash"):
        return {}
    plan_type = _plan_slug(workspace.get("plan_type"))
    seat_limit = _seat_limit(plan_type, _as_dict(workspace.get("metadata")))
    existing = store.get_workspace_membership_by_email(workspace_id, email_hash)
    if not existing and not _seat_available(workspace_id, seat_limit):
        return error("google_connect_owner_seat_limit_exceeded", 403, seat_limit=seat_limit)
    membership = store.upsert_workspace_membership(
        {
            "membership_id": existing.get("membership_id") or "wmem_" + uuid.uuid4().hex[:16],
            "workspace_id": workspace_id,
            "email_hash": email_hash,
            "email_domain": workspace.get("contact_email_domain", ""),
            "workspace_role": "owner",
            "access_role": "connector_admin",
            "status": "active",
            "source": "connect_billing_owner",
            "plan_type": plan_type,
            "seat_limit": seat_limit,
            "elevated_approval_required": False,
            "metadata": {
                "canonical_owner": CANONICAL_OWNER,
                "workspace_source": workspace.get("source", ""),
                "raw_email_stored": False,
            },
        }
    )
    _audit("identity.connect_owner_auto_provisioned", workspace_id, _public_membership(membership), request_meta)
    return {
        "ok": True,
        "source": "connect_billing_owner",
        "membership": membership,
        "role_context": _role_context("connector_admin", "connect_billing_owner", membership=_public_membership(membership)),
    }


def _access_from_bootstrap(workspace_id: str, email_hash: str, email_domain: str, request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    if not _env_bool("LIVEUIN_GOOGLE_BOOTSTRAP_WORKSPACE_ACCESS_ENABLED", False):
        return {}
    access_role = _access_role("", os.getenv("LIVEUIN_GOOGLE_BOOTSTRAP_ROLE") or os.getenv("LIVEUIN_GOOGLE_DEFAULT_ROLE") or "connector_admin")
    if access_role in ELEVATED_ACCESS_ROLES and not _env_bool("LIVEUIN_GOOGLE_BOOTSTRAP_ELEVATED_ACCESS_READY", False):
        return error("google_bootstrap_elevated_access_requires_explicit_ready", 403, access_role=access_role)
    workspace = _workspace_record(workspace_id)
    plan_type = _plan_slug(workspace.get("plan_type"))
    seat_limit = _seat_limit(plan_type, _as_dict(workspace.get("metadata")))
    existing = store.get_workspace_membership_by_email(workspace_id, email_hash)
    membership = store.upsert_workspace_membership(
        {
            "membership_id": existing.get("membership_id") or "wmem_" + uuid.uuid4().hex[:16],
            "workspace_id": workspace_id,
            "email_hash": email_hash,
            "email_domain": email_domain,
            "workspace_role": "member",
            "access_role": access_role,
            "status": "active",
            "source": "google_bootstrap_allowlist",
            "plan_type": plan_type,
            "seat_limit": seat_limit,
            "elevated_approval_required": access_role in ELEVATED_ACCESS_ROLES,
            "approved_by": "server_bootstrap_policy" if access_role in ELEVATED_ACCESS_ROLES else "",
            "approved_at": _now() if access_role in ELEVATED_ACCESS_ROLES else None,
            "metadata": {"canonical_owner": CANONICAL_OWNER, "raw_email_stored": False},
        }
    )
    _audit("identity.google_bootstrap_membership_created", workspace_id, _public_membership(membership), request_meta)
    return {
        "ok": True,
        "source": "google_bootstrap_allowlist",
        "membership": membership,
        "role_context": _role_context(access_role, "google_bootstrap_allowlist", membership=_public_membership(membership)),
    }


def resolve_google_workspace_access(
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    email: str = "",
    email_verified: bool = False,
    context: Dict[str, Any] | None = None,
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    workspace_id = _clean_workspace(workspace_id)
    email = _email(email)
    if not email or not email_verified:
        return error("google_verified_email_required_for_workspace_access", 403)
    email_hash = _email_hash(email)
    email_domain = _email_domain(email)

    for resolver in (
        lambda: _access_from_existing_membership(workspace_id, email_hash),
        lambda: _access_from_invite(workspace_id, email_hash, request_meta),
        lambda: _access_from_connect_owner(workspace_id, email_hash, request_meta),
        lambda: _access_from_bootstrap(workspace_id, email_hash, email_domain, request_meta),
    ):
        result = resolver()
        if not result:
            continue
        if result.get("ok") is not True:
            return result
        role_context = _as_dict(result.get("role_context"))
        return {
            "ok": True,
            "schema_version": SCHEMA_VERSION,
            "phase": PHASE,
            "canonical_owner": CANONICAL_OWNER,
            "workspace_id": workspace_id,
            "source": result.get("source", ""),
            "role_context": role_context,
            "membership": role_context.get("membership") or _public_membership(_as_dict(result.get("membership"))),
            "email_hash": email_hash,
            "email_domain": email_domain,
            "raw_email_stored": False,
        }

    return error(
        "google_workspace_access_not_granted",
        403,
        workspace_id=workspace_id,
        email_hash=email_hash,
        email_domain=email_domain,
        reason="No active workspace membership, accepted invite, Connect owner contact, or explicit bootstrap policy matched.",
        raw_email_stored=False,
    )


def workspace_access_status(workspace_id: str = DEFAULT_WORKSPACE_ID) -> Dict[str, Any]:
    workspace_id = _clean_workspace(workspace_id)
    workspace = _workspace_record(workspace_id)
    memberships = store.list_workspace_memberships(workspace_id=workspace_id, limit=100)
    invites = store.list_workspace_invites(workspace_id=workspace_id, limit=100)
    return {
        "ok": True,
        "ready": True,
        "service": "liveuin-core-identity-workspace-access",
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "canonical_owner": CANONICAL_OWNER,
        "workspace_id": workspace_id,
        "workspace": _public_workspace_record(workspace),
        "membership_count": len(memberships),
        "active_membership_count": store.count_active_workspace_memberships(workspace_id),
        "invite_count": len(invites),
        "connect_postgres_lookup_configured": bool(os.getenv("LIVEUIN_DB_DSN") or os.getenv("OPS_DB_DSN") or os.getenv("DATABASE_URL")),
        "bootstrap_workspace_access_enabled": _env_bool("LIVEUIN_GOOGLE_BOOTSTRAP_WORKSPACE_ACCESS_ENABLED", False),
        "bootstrap_elevated_access_ready": _env_bool("LIVEUIN_GOOGLE_BOOTSTRAP_ELEVATED_ACCESS_READY", False),
        "seat_policy": CONNECT_PLAN_SEAT_LIMITS,
        "raw_email_stored": False,
        "boundary": {
            "surface": "Google login callback, Connect workspace owner setup, workspace invites, and team membership",
            "layer": "identity admission plus workspace role/scope resolution",
            "owner": CANONICAL_OWNER,
            "plan_role": "Connect plan unlocks features and seat policy; it does not by itself prove a person should be an operator/admin.",
            "google_role": "Google proves verified email ownership only.",
            "connector_role": "Connector setup can sync owner/contact and entitlements but does not own session truth.",
        },
    }


def list_workspace_memberships(workspace_id: str = DEFAULT_WORKSPACE_ID, limit: int = 100) -> Dict[str, Any]:
    workspace_id = _clean_workspace(workspace_id)
    rows = store.list_workspace_memberships(workspace_id=workspace_id, limit=max(1, min(int(limit or 100), 500)))
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "canonical_owner": CANONICAL_OWNER,
        "workspace_id": workspace_id,
        "memberships": [_public_membership(item) for item in rows],
        "membership_count": len(rows),
        "raw_email_stored": False,
    }


def list_workspace_invites(workspace_id: str = DEFAULT_WORKSPACE_ID, limit: int = 100) -> Dict[str, Any]:
    workspace_id = _clean_workspace(workspace_id)
    rows = store.list_workspace_invites(workspace_id=workspace_id, limit=max(1, min(int(limit or 100), 500)))
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "canonical_owner": CANONICAL_OWNER,
        "workspace_id": workspace_id,
        "invites": [_public_invite(item) for item in rows],
        "invite_count": len(rows),
        "raw_email_stored": False,
    }
