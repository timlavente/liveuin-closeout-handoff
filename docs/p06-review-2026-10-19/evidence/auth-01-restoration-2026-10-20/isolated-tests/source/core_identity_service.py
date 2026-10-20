from __future__ import annotations

import hashlib
import re
import time
import uuid
from typing import Any, Dict, List

try:
    from . import core_identity_store as store
    from . import core_identity_login_store as login_store
    from . import core_identity_session_store as session_store
    from . import core_identity_session as identity_session
    from . import core_access_service as access_svc
except ImportError:  # pragma: no cover - supports direct script execution.
    import core_identity_store as store
    import core_identity_login_store as login_store
    import core_identity_session_store as session_store
    import core_identity_session as identity_session
    import core_access_service as access_svc


SCHEMA_VERSION = "liveuin-core-identity-v1"
PHASE = "phase2-laijuzhu-wechat-identity-link"
DEFAULT_WORKSPACE_ID = "laijuzhu"
CONTINUITY_VERSION = "ECC-CANONICAL-IDENTITY-CONTINUITY-v1"

ALLOWED_PROVIDERS = {
    "google_oidc",
    "wechat_miniprogram",
    "wechat_official_account",
    "wechat_unionid",
    "phone_hash",
    "email_hash",
    "partner_user",
    "liveuin_user",
}

ALLOWED_CONSENT_STATUSES = {"accepted", "pending", "withdrawn"}


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


def _clean_string(value: Any, max_length: int = 240) -> str:
    return str(value or "").strip()[:max_length]


def _clean_id(value: Any, max_length: int = 96) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "", str(value or "").strip())
    return cleaned[:max_length]


def _clean_provider(value: Any) -> str:
    provider = re.sub(r"[^a-z0-9_]", "_", str(value or "").strip().lower())
    provider = re.sub(r"_+", "_", provider).strip("_")
    return provider if provider in ALLOWED_PROVIDERS else ""


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _workspace_id(payload: Dict[str, Any]) -> str:
    return _clean_id(payload.get("workspace_id") or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID


def _sha(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _hint(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""

    if len(text) <= 8:
        return "*" * len(text)

    return text[:4] + "..." + text[-4:]


def _subject_from_payload(provider: str, payload: Dict[str, Any]) -> str:
    identity = _as_dict(payload.get("identity"))
    if provider == "wechat_miniprogram":
        return _clean_string(payload.get("provider_user_id") or payload.get("openid") or identity.get("openid"), 256)
    if provider == "wechat_official_account":
        return _clean_string(payload.get("provider_user_id") or payload.get("official_openid") or identity.get("official_openid") or identity.get("openid"), 256)
    if provider == "wechat_unionid":
        return _clean_string(payload.get("provider_user_id") or payload.get("unionid") or identity.get("unionid"), 256)
    if provider in {"phone_hash", "email_hash"}:
        return _clean_string(payload.get("provider_user_id") or identity.get(provider) or payload.get(provider), 256)

    return _clean_string(payload.get("provider_user_id") or identity.get("provider_user_id") or identity.get("id"), 256)


def _unionid_from_payload(payload: Dict[str, Any]) -> str:
    identity = _as_dict(payload.get("identity"))
    return _clean_string(payload.get("unionid") or identity.get("unionid"), 256)


def _person_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    person = _as_dict(payload.get("person")).copy()
    lead = _as_dict(payload.get("lead"))
    if not person and lead:
        person = {
            "display_name": lead.get("name") or lead.get("parent_name") or lead.get("student_name"),
            "locale": lead.get("locale") or "zh-CN",
            "role_flags": ["parent"],
            "contacts": {
                "phone_hash": lead.get("phone_hash") or "",
                "email_hash": lead.get("email_hash") or "",
            },
        }

    return person


def _contact_payload(person: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, str]:
    contacts = _as_dict(person.get("contacts")).copy()
    for key in ("phone_hash", "email_hash", "wechat_unionid_hash"):
        value = _clean_string(contacts.get(key) or payload.get(key), 256)
        if value:
            contacts[key] = value

    return {str(key): _clean_string(value, 256) for key, value in contacts.items() if _clean_string(value, 256)}


def _role_flags(person: Dict[str, Any], payload: Dict[str, Any]) -> List[str]:
    roles: List[str] = []
    for role in _as_list(person.get("role_flags") or payload.get("role_flags")):
        cleaned = re.sub(r"[^a-z0-9_]", "_", str(role or "").strip().lower()).strip("_")
        if cleaned and cleaned not in roles:
            roles.append(cleaned)

    if not roles:
        roles.append("parent")

    return roles[:12]


def _household_id(payload: Dict[str, Any], case_id: str) -> str:
    household_id = _clean_id(payload.get("household_id") or _as_dict(payload.get("household")).get("id"), 96)
    if household_id:
        return household_id
    if case_id:
        return "hh_" + _clean_id(case_id.lower(), 80)

    return "hh_" + uuid.uuid4().hex[:16]


def _public_link(link: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "identity_link_id": link.get("identity_link_id", ""),
        "provider": link.get("provider", ""),
        "provider_subject_hint": link.get("provider_subject_hint", ""),
        "unionid_hint": link.get("unionid_hint", ""),
        "provider_app_id": link.get("provider_app_id", ""),
        "verified_state": link.get("verified_state", "captured"),
        "case_id": link.get("case_id", ""),
        "household_id": link.get("household_id", ""),
        "created_at": _iso_from_epoch(link.get("created_at")),
        "updated_at": _iso_from_epoch(link.get("updated_at")),
    }


def _public_consent(consent: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "consent_id": consent.get("consent_id", ""),
        "scope": consent.get("scope", ""),
        "version": consent.get("version", ""),
        "source": consent.get("source", ""),
        "status": consent.get("status", "pending"),
        "case_id": consent.get("case_id", ""),
        "accepted_at": _iso_from_epoch(consent.get("accepted_at")),
        "withdrawn_at": _iso_from_epoch(consent.get("withdrawn_at")),
        "created_at": _iso_from_epoch(consent.get("created_at")),
    }


def _person_response(
    person: Dict[str, Any],
    *,
    link: Dict[str, Any] | None = None,
    consent: Dict[str, Any] | None = None,
    event_id: str = "",
    transport: str = "core_api",
) -> Dict[str, Any]:
    workspace_id = _clean_id(person.get("workspace_id") or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID
    person_id = _clean_id(person.get("person_id"), 96)
    links = store.list_links_for_person(person_id, workspace_id)
    consents = store.list_consents_for_person(person_id, workspace_id)

    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "source": "liveuin_identity",
        "canonical_owner": "LiveUIN Identity",
        "transport": transport,
        "workspace_id": workspace_id,
        "person_id": person_id,
        "display_name": person.get("display_name", ""),
        "locale": person.get("locale", ""),
        "role_flags": _as_list(person.get("role_flags")),
        "contacts": _as_dict(person.get("contacts")),
        "consent_state": person.get("consent_state", "pending"),
        "identity_link": _public_link(link or links[0]) if (link or links) else {},
        "identity_links": [_public_link(item) for item in links],
        "consent_record": _public_consent(consent or consents[0]) if (consent or consents) else {},
        "consent_records": [_public_consent(item) for item in consents],
        "audit_event_id": event_id,
        "created_at": _iso_from_epoch(person.get("created_at")),
        "updated_at": _iso_from_epoch(person.get("updated_at")),
        "routes": {
            "resolve": "/api/core/identity/resolve",
            "person": "/api/core/identity/persons/" + person_id,
            "link": "/api/core/identity/links",
        },
    }


def error(detail: str, status_code: int = 400, **extra: Any) -> Dict[str, Any]:
    return {"ok": False, "detail": detail, "status_code": status_code, **extra}


def _continuity_actor(payload: Dict[str, Any]) -> str:
    actor = _as_dict(payload.get("actor"))
    return _clean_id(payload.get("actor_id") or actor.get("actor_id") or payload.get("reviewed_by"), 120)


def _continuity_idempotency_key(payload: Dict[str, Any], operation_type: str) -> str:
    return _clean_id(payload.get("idempotency_key") or payload.get("operation_id") or payload.get("request_id"), 160) or (
        "g07_" + _sha(str({k: v for k, v in payload.items() if k not in {"actor", "reviewer_fresh"}}) + operation_type)[:32]
    )


def _continuity_existing(workspace_id: str, idempotency_key: str) -> Dict[str, Any]:
    existing = store.get_continuity_decision_by_idempotency(workspace_id, idempotency_key)
    if existing:
        return {"ok": True, "duplicate_response": _continuity_response(existing, duplicate=True)}
    return {}


def _continuity_precheck(payload: Dict[str, Any], operation_type: str) -> Dict[str, Any]:
    workspace_id = _workspace_id(payload)
    idempotency_key = _continuity_idempotency_key(payload, operation_type)
    existing = _continuity_existing(workspace_id, idempotency_key)
    if existing:
        return existing
    actor_id = _continuity_actor(payload)
    if not actor_id:
        return error("identity_continuity_actor_required", 403)
    reviewed_by = _clean_id(payload.get("reviewed_by"), 120)
    if reviewed_by and reviewed_by != actor_id:
        return error("identity_continuity_review_required", 403, reason="stale_or_conflicting_reviewer")
    if payload.get("reviewer_fresh") is False or payload.get("stale_reviewer") is True:
        return error("identity_continuity_review_required", 403, reason="stale_reviewer")
    if "authority" in payload or "canonical_identity_resolved" in payload:
        return error("identity_continuity_review_required", 403, reason="client_supplied_authority_denied")
    return {"ok": True, "workspace_id": workspace_id, "idempotency_key": idempotency_key, "actor_id": actor_id}


def _audit_continuity(decision: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> None:
    store.append_audit_event(
        {
            "event_id": "idt_evt_" + uuid.uuid4().hex[:16],
            "workspace_id": decision.get("workspace_id", DEFAULT_WORKSPACE_ID),
            "person_id": decision.get("canonical_person_id") or decision.get("target_person_id") or "",
            "identity_link_id": decision.get("identity_link_id", ""),
            "event_type": "identity.continuity." + str(decision.get("operation_type") or "decision"),
            "object_type": "identity_continuity_decision",
            "object_id": decision.get("decision_id", ""),
            "payload": {
                "continuity_version": CONTINUITY_VERSION,
                "status": decision.get("status", ""),
                "quarantine_reason": decision.get("quarantine_reason", ""),
                "source_person_ids": decision.get("source_person_ids", []),
                "target_person_id": decision.get("target_person_id", ""),
                "actor_id": decision.get("actor_id", ""),
            },
            "received_at": _now(),
        },
        request_meta,
    )


def _record_continuity_decision(
    *,
    workspace_id: str,
    operation_type: str,
    status: str,
    actor_id: str,
    idempotency_key: str,
    canonical_person_id: str = "",
    source_person_ids: List[str] | None = None,
    target_person_id: str = "",
    identity_link_id: str = "",
    provider: str = "",
    provider_subject_hash: str = "",
    unionid_hash: str = "",
    quarantine_reason: str = "",
    payload: Dict[str, Any] | None = None,
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    decision_id = "g07_" + _sha(f"{workspace_id}:{operation_type}:{idempotency_key}")[:24]
    decision = store.upsert_continuity_decision(
        {
            "decision_id": decision_id,
            "workspace_id": workspace_id,
            "operation_type": operation_type,
            "status": status,
            "canonical_person_id": canonical_person_id,
            "source_person_ids": source_person_ids or [],
            "target_person_id": target_person_id,
            "identity_link_id": identity_link_id,
            "provider": provider,
            "provider_subject_hash": provider_subject_hash,
            "unionid_hash": unionid_hash,
            "idempotency_key": idempotency_key,
            "quarantine_reason": quarantine_reason,
            "actor_id": actor_id,
            "payload": {
                **_as_dict(payload),
                "continuity_version": CONTINUITY_VERSION,
                "g08_g09_re_evaluation_required": True,
                "g11_revoked_paths_remain_revoked": True,
                "raw_identifier_stored": False,
                "fallback_truth_created": False,
            },
            "created_at": _now(),
            "updated_at": _now(),
        },
        request_meta,
    )
    _audit_continuity(decision, request_meta)
    return _continuity_response(decision)


def _continuity_response(decision: Dict[str, Any], *, duplicate: bool = False, extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "object_version": CONTINUITY_VERSION,
        "phase": PHASE,
        "source": "liveuin_identity",
        "canonical_owner": "LiveUIN Identity",
        "status": "identity_continuity_decision",
        "workspace_id": decision.get("workspace_id", DEFAULT_WORKSPACE_ID),
        "continuity_decision": decision,
        "duplicate": duplicate,
        "controls": {
            "workspace_explicit": True,
            "provider_payload_not_truth": True,
            "ambiguous_links_quarantined": True,
            "idempotent": True,
            "sessions_invalidated_on_split_merge_unlink": True,
            "g08_g09_re_evaluation_required": True,
            "g11_revoked_paths_remain_revoked": True,
        },
        **(extra or {}),
    }


def _call_g08_g09_boundary(workspace_id: str, request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    try:
        return access_svc.reconcile_legacy_participant_grants(workspace_id=workspace_id, request_meta=request_meta)
    except Exception as exc:  # pragma: no cover - fail closed if optional boundary is unavailable.
        return {"ok": False, "detail": "g08_g09_re_evaluation_unavailable", "error": str(exc)}


def _revoke_person_sessions(workspace_id: str, person_ids: List[str], reason: str, request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    actor_ids = [_clean_id(item, 120) for item in person_ids if _clean_id(item, 120)]
    if not actor_ids:
        return {"ok": True, "revoked_count": 0}
    return identity_session.revoke_active_workspace_sessions(
        workspace_id,
        actor_ids=actor_ids,
        reason=reason,
        request_meta=request_meta,
    )


def link_identity(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return error("invalid_payload")

    provider = _clean_provider(payload.get("provider") or _as_dict(payload.get("identity")).get("provider"))
    if not provider:
        return error("provider_invalid")

    subject = _subject_from_payload(provider, payload)
    if not subject:
        return error("provider_user_id_required")

    workspace_id = _workspace_id(payload)
    subject_hash = _sha(subject)
    unionid = _unionid_from_payload(payload)
    unionid_hash = _sha(unionid)
    person = _person_payload(payload)
    existing_link = store.find_link(
        workspace_id=workspace_id,
        provider=provider,
        provider_subject_hash=subject_hash,
        unionid_hash=unionid_hash,
    )
    person_id = _clean_id(payload.get("person_id") or person.get("person_id") or existing_link.get("person_id"), 96)
    if not person_id:
        person_id = "per_" + uuid.uuid4().hex[:16]

    case_id = _clean_id(payload.get("case_id") or _as_dict(payload.get("case")).get("id"), 96)
    household_id = _household_id(payload, case_id)
    consent = _as_dict(payload.get("consent"))
    consent_accepted = bool(consent.get("accepted")) or str(consent.get("status") or "").lower() == "accepted"
    consent_status = "accepted" if consent_accepted else _clean_string(consent.get("status") or "pending", 40)
    if consent_status not in ALLOWED_CONSENT_STATUSES:
        consent_status = "pending"

    existing_person = store.get_person(person_id, workspace_id)
    contacts = {
        **_as_dict(existing_person.get("contacts")),
        **_contact_payload(person, payload),
    }
    if unionid_hash:
        contacts["wechat_unionid_hash"] = unionid_hash

    stored_person = store.upsert_person(
        {
            "person_id": person_id,
            "workspace_id": workspace_id,
            "display_name": _clean_string(person.get("display_name") or person.get("name") or existing_person.get("display_name") or "Laijuzhu family contact", 160),
            "locale": _clean_string(person.get("locale") or existing_person.get("locale") or payload.get("locale") or "zh-CN", 20),
            "role_flags": _role_flags(person, payload),
            "contacts": contacts,
            "consent_state": "accepted" if consent_accepted else existing_person.get("consent_state") or consent_status,
            "metadata": {
                **_as_dict(existing_person.get("metadata")),
                **_as_dict(payload.get("metadata")),
                "canonical_owner": "LiveUIN Identity",
                "surface": _clean_string(payload.get("surface") or "wechat_identity_link", 80),
                "updated_at": _now_iso(),
            },
            "created_at": existing_person.get("created_at") or _now(),
            "updated_at": _now(),
        }
    )

    same_provider_subject = (
        existing_link.get("provider") == provider
        and existing_link.get("provider_subject_hash") == subject_hash
    )
    identity_link_id = existing_link.get("identity_link_id") if same_provider_subject else ""
    if not identity_link_id:
        identity_link_id = "idlk_" + uuid.uuid4().hex[:16]
    stored_link = store.upsert_link(
        {
            "identity_link_id": identity_link_id,
            "workspace_id": workspace_id,
            "person_id": person_id,
            "provider": provider,
            "provider_subject_hash": subject_hash,
            "provider_subject_hint": _hint(subject),
            "unionid_hash": unionid_hash,
            "unionid_hint": _hint(unionid),
            "provider_app_id": _clean_string(payload.get("provider_app_id") or _as_dict(payload.get("identity")).get("appid"), 120),
            "verified_state": _clean_string(payload.get("verified_state") or "captured", 60),
            "case_id": case_id,
            "household_id": household_id,
            "metadata": {
                **_as_dict(payload.get("metadata")),
                "channel": _clean_string(payload.get("channel") or "wechat", 80),
                "raw_identifier_stored": False,
            },
            "created_at": existing_link.get("created_at") if same_provider_subject else _now(),
            "updated_at": _now(),
        }
    )

    stored_consent: Dict[str, Any] = {}
    if consent:
        created_at = _now()
        stored_consent = store.create_consent(
            {
                "consent_id": "cns_" + uuid.uuid4().hex[:16],
                "workspace_id": workspace_id,
                "person_id": person_id,
                "case_id": case_id,
                "scope": _clean_string(consent.get("scope") or "identity_link", 120),
                "version": _clean_string(consent.get("version") or "v1", 60),
                "source": _clean_string(consent.get("source") or provider, 120),
                "status": consent_status,
                "payload": {
                    "scope": _clean_string(consent.get("scope") or "identity_link", 120),
                    "notice": _clean_string(consent.get("notice"), 240),
                    "source": _clean_string(consent.get("source") or provider, 120),
                    "accepted": consent_accepted,
                },
                "accepted_at": created_at if consent_status == "accepted" else None,
                "withdrawn_at": created_at if consent_status == "withdrawn" else None,
                "created_at": created_at,
            }
        )

    event_id = "idt_evt_" + uuid.uuid4().hex[:16]
    store.append_audit_event(
        {
            "event_id": event_id,
            "workspace_id": workspace_id,
            "person_id": person_id,
            "identity_link_id": stored_link["identity_link_id"],
            "event_type": "identity.linked",
            "object_type": "identity_link",
            "object_id": stored_link["identity_link_id"],
            "payload": {
                "provider": provider,
                "provider_subject_hint": stored_link.get("provider_subject_hint"),
                "unionid_hint": stored_link.get("unionid_hint"),
                "case_id": case_id,
                "household_id": household_id,
                "consent_status": stored_consent.get("status") or consent_status,
                "source": "liveuin_identity",
            },
            "received_at": _now(),
        },
        request_meta,
    )

    return _person_response(stored_person, link=stored_link, consent=stored_consent, event_id=event_id)


def continuity_provider_link(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    precheck = _continuity_precheck(payload, "provider_link")
    if precheck.get("ok") is not True:
        return precheck
    if precheck.get("duplicate_response"):
        return _as_dict(precheck.get("duplicate_response"))
    workspace_id = precheck["workspace_id"]
    idempotency_key = precheck["idempotency_key"]
    actor_id = precheck["actor_id"]
    provider = _clean_provider(payload.get("provider") or _as_dict(payload.get("identity")).get("provider"))
    subject = _subject_from_payload(provider, payload) if provider else ""
    if not provider:
        return error("provider_invalid")
    if not subject:
        return error("provider_user_id_required")
    subject_hash = _sha(subject)
    unionid_hash = _sha(_unionid_from_payload(payload))
    requested_person_id = _clean_id(payload.get("person_id") or payload.get("target_person_id"), 96)
    existing_link = store.find_link(workspace_id=workspace_id, provider=provider, provider_subject_hash=subject_hash)
    if existing_link and requested_person_id and existing_link.get("person_id") != requested_person_id:
        return _record_continuity_decision(
            workspace_id=workspace_id,
            operation_type="provider_link",
            status="review_required",
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            canonical_person_id=existing_link.get("person_id", ""),
            target_person_id=requested_person_id,
            identity_link_id=existing_link.get("identity_link_id", ""),
            provider=provider,
            provider_subject_hash=subject_hash,
            unionid_hash=unionid_hash,
            quarantine_reason="provider_subject_conflict",
            payload={"mutation_performed": False},
            request_meta=request_meta,
        )
    union_links = store.list_links_by_unionid(workspace_id, unionid_hash) if unionid_hash else []
    union_person_ids = sorted({link.get("person_id", "") for link in union_links if link.get("person_id")})
    if len(union_person_ids) > 1:
        return _record_continuity_decision(
            workspace_id=workspace_id,
            operation_type="provider_link",
            status="review_required",
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            source_person_ids=union_person_ids,
            provider=provider,
            provider_subject_hash=subject_hash,
            unionid_hash=unionid_hash,
            quarantine_reason="ambiguous_unionid_duplicate",
            payload={"mutation_performed": False},
            request_meta=request_meta,
        )
    linked_payload = {**payload, "workspace_id": workspace_id}
    if union_person_ids and not requested_person_id:
        linked_payload["person_id"] = union_person_ids[0]
    linked = link_identity(linked_payload, request_meta)
    if linked.get("ok") is False:
        return linked
    decision = _record_continuity_decision(
        workspace_id=workspace_id,
        operation_type="provider_link",
        status="linked",
        actor_id=actor_id,
        idempotency_key=idempotency_key,
        canonical_person_id=linked.get("person_id", ""),
        identity_link_id=_as_dict(linked.get("identity_link")).get("identity_link_id", ""),
        provider=provider,
        provider_subject_hash=subject_hash,
        unionid_hash=unionid_hash,
        payload={"mutation_performed": True},
        request_meta=request_meta,
    )
    decision["person"] = linked
    return decision


def continuity_merge(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    precheck = _continuity_precheck(payload, "merge")
    if precheck.get("ok") is not True:
        return precheck
    if precheck.get("duplicate_response"):
        return _as_dict(precheck.get("duplicate_response"))
    if payload.get("reviewed") is not True:
        return error("identity_continuity_review_required", 403)
    workspace_id = precheck["workspace_id"]
    target_person_id = _clean_id(payload.get("target_person_id") or payload.get("canonical_person_id"), 96)
    source_person_ids = [_clean_id(item, 96) for item in _as_list(payload.get("source_person_ids")) if _clean_id(item, 96)]
    if not target_person_id or not source_person_ids:
        return error("target_and_source_person_required")
    if not store.get_person(target_person_id, workspace_id):
        return error("identity_continuity_review_required", 403, reason="target_person_missing")
    missing = [person_id for person_id in source_person_ids if not store.get_person(person_id, workspace_id)]
    if missing:
        return error("identity_continuity_review_required", 403, reason="source_person_missing")
    moved = 0
    for source_id in source_person_ids:
        if source_id == target_person_id:
            continue
        moved += store.move_links_to_person(
            workspace_id,
            source_id,
            target_person_id,
            {"continuity_state": "merged", "merged_from_person_id": source_id, "merged_at": _now_iso()},
        )
        source = store.get_person(source_id, workspace_id)
        if source:
            store.upsert_person(
                {
                    **source,
                    "metadata": {**_as_dict(source.get("metadata")), "continuity_state": "merged", "merged_into_person_id": target_person_id, "merged_at": _now_iso()},
                    "updated_at": _now(),
                }
            )
    session_revoke = _revoke_person_sessions(workspace_id, source_person_ids, "g07_identity_merge", request_meta)
    reevaluation = _call_g08_g09_boundary(workspace_id, request_meta)
    return _record_continuity_decision(
        workspace_id=workspace_id,
        operation_type="merge",
        status="merged",
        actor_id=precheck["actor_id"],
        idempotency_key=precheck["idempotency_key"],
        canonical_person_id=target_person_id,
        source_person_ids=source_person_ids,
        target_person_id=target_person_id,
        payload={"moved_link_count": moved, "session_revocation": session_revoke, "g08_g09_re_evaluation": reevaluation},
        request_meta=request_meta,
    )


def continuity_split(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    precheck = _continuity_precheck(payload, "split")
    if precheck.get("ok") is not True:
        return precheck
    if precheck.get("duplicate_response"):
        return _as_dict(precheck.get("duplicate_response"))
    if payload.get("reviewed") is not True:
        return error("identity_continuity_review_required", 403)
    workspace_id = precheck["workspace_id"]
    source_person_id = _clean_id(payload.get("source_person_id"), 96)
    target_person_id = _clean_id(payload.get("target_person_id"), 96) or "per_" + uuid.uuid4().hex[:16]
    link_ids = [_clean_id(item, 96) for item in _as_list(payload.get("identity_link_ids")) if _clean_id(item, 96)]
    if not source_person_id or not link_ids:
        return error("source_person_and_links_required")
    source = store.get_person(source_person_id, workspace_id)
    if not source:
        return error("identity_continuity_review_required", 403, reason="source_person_missing")
    links = store.list_links_for_person(source_person_id, workspace_id)
    if len(links) <= len(link_ids):
        return error("identity_continuity_review_required", 403, reason="last_link_split_requires_locked_state")
    target = store.get_person(target_person_id, workspace_id) or store.upsert_person(
        {
            "person_id": target_person_id,
            "workspace_id": workspace_id,
            "display_name": _clean_string(_as_dict(payload.get("target_person")).get("display_name") or "Reviewed split identity", 160),
            "locale": _clean_string(source.get("locale") or "zh-CN", 20),
            "role_flags": _as_list(source.get("role_flags")),
            "contacts": {},
            "consent_state": "pending",
            "metadata": {"continuity_state": "split_target", "split_from_person_id": source_person_id, "created_by_g07": True},
            "created_at": _now(),
            "updated_at": _now(),
        }
    )
    moved = 0
    for link_id in link_ids:
        link = store.get_link(link_id, workspace_id)
        if not link or link.get("person_id") != source_person_id:
            return error("identity_continuity_review_required", 403, reason="link_not_owned_by_source")
        store.update_link({**link, "person_id": target["person_id"], "verified_state": "reviewed", "metadata": {**_as_dict(link.get("metadata")), "continuity_state": "split", "split_from_person_id": source_person_id}})
        moved += 1
    session_revoke = _revoke_person_sessions(workspace_id, [source_person_id, target["person_id"]], "g07_identity_split", request_meta)
    reevaluation = _call_g08_g09_boundary(workspace_id, request_meta)
    return _record_continuity_decision(
        workspace_id=workspace_id,
        operation_type="split",
        status="split",
        actor_id=precheck["actor_id"],
        idempotency_key=precheck["idempotency_key"],
        canonical_person_id=source_person_id,
        source_person_ids=[source_person_id],
        target_person_id=target["person_id"],
        payload={"moved_link_count": moved, "session_revocation": session_revoke, "g08_g09_re_evaluation": reevaluation},
        request_meta=request_meta,
    )


def continuity_unlink(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    precheck = _continuity_precheck(payload, "unlink")
    if precheck.get("ok") is not True:
        return precheck
    if precheck.get("duplicate_response"):
        return _as_dict(precheck.get("duplicate_response"))
    if payload.get("reviewed") is not True:
        return error("identity_continuity_review_required", 403)
    workspace_id = precheck["workspace_id"]
    link_id = _clean_id(payload.get("identity_link_id"), 96)
    link = store.get_link(link_id, workspace_id)
    if not link:
        return error("identity_link_not_found", 404)
    links = store.list_links_for_person(link.get("person_id", ""), workspace_id)
    if len(links) <= 1:
        return _record_continuity_decision(
            workspace_id=workspace_id,
            operation_type="unlink",
            status="review_required",
            actor_id=precheck["actor_id"],
            idempotency_key=precheck["idempotency_key"],
            canonical_person_id=link.get("person_id", ""),
            identity_link_id=link_id,
            quarantine_reason="last_link_unlink_requires_locked_state",
            payload={"mutation_performed": False},
            request_meta=request_meta,
        )
    updated = store.update_link({**link, "verified_state": "unlinked", "metadata": {**_as_dict(link.get("metadata")), "continuity_state": "unlinked", "unlinked_at": _now_iso()}})
    session_revoke = _revoke_person_sessions(workspace_id, [link.get("person_id", "")], "g07_identity_unlink", request_meta)
    reevaluation = _call_g08_g09_boundary(workspace_id, request_meta)
    return _record_continuity_decision(
        workspace_id=workspace_id,
        operation_type="unlink",
        status="unlinked",
        actor_id=precheck["actor_id"],
        idempotency_key=precheck["idempotency_key"],
        canonical_person_id=link.get("person_id", ""),
        identity_link_id=link_id,
        provider=link.get("provider", ""),
        provider_subject_hash=link.get("provider_subject_hash", ""),
        unionid_hash=link.get("unionid_hash", ""),
        payload={"identity_link": _public_link(updated), "session_revocation": session_revoke, "g08_g09_re_evaluation": reevaluation},
        request_meta=request_meta,
    )


def continuity_quarantine(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    precheck = _continuity_precheck(payload, "quarantine")
    if precheck.get("ok") is not True:
        return precheck
    if precheck.get("duplicate_response"):
        return _as_dict(precheck.get("duplicate_response"))
    workspace_id = precheck["workspace_id"]
    link_id = _clean_id(payload.get("identity_link_id"), 96)
    link = store.get_link(link_id, workspace_id) if link_id else {}
    if link:
        store.update_link({**link, "verified_state": "quarantined", "metadata": {**_as_dict(link.get("metadata")), "continuity_state": "quarantined", "quarantined_at": _now_iso()}})
    return _record_continuity_decision(
        workspace_id=workspace_id,
        operation_type="quarantine",
        status="review_required",
        actor_id=precheck["actor_id"],
        idempotency_key=precheck["idempotency_key"],
        canonical_person_id=link.get("person_id", ""),
        identity_link_id=link_id,
        quarantine_reason=_clean_string(payload.get("reason") or "manual_quarantine", 120),
        payload={"mutation_performed": bool(link)},
        request_meta=request_meta,
    )


def continuity_recover(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    precheck = _continuity_precheck(payload, "recover")
    if precheck.get("ok") is not True:
        return precheck
    if precheck.get("duplicate_response"):
        return _as_dict(precheck.get("duplicate_response"))
    if payload.get("reviewed") is not True:
        return error("identity_continuity_review_required", 403)
    workspace_id = precheck["workspace_id"]
    link_id = _clean_id(payload.get("identity_link_id"), 96)
    target_person_id = _clean_id(payload.get("target_person_id"), 96)
    link = store.get_link(link_id, workspace_id)
    if not link or not target_person_id or not store.get_person(target_person_id, workspace_id):
        return error("identity_continuity_review_required", 403, reason="recovery_target_required")
    old_person_id = link.get("person_id", "")
    updated = store.update_link({**link, "person_id": target_person_id, "verified_state": "reviewed", "metadata": {**_as_dict(link.get("metadata")), "continuity_state": "recovered", "recovered_at": _now_iso(), "recovered_from_person_id": old_person_id}})
    session_revoke = _revoke_person_sessions(workspace_id, [old_person_id, target_person_id], "g07_identity_recovery", request_meta)
    reevaluation = _call_g08_g09_boundary(workspace_id, request_meta)
    return _record_continuity_decision(
        workspace_id=workspace_id,
        operation_type="recover",
        status="recovered",
        actor_id=precheck["actor_id"],
        idempotency_key=precheck["idempotency_key"],
        canonical_person_id=target_person_id,
        source_person_ids=[old_person_id],
        target_person_id=target_person_id,
        identity_link_id=link_id,
        provider=link.get("provider", ""),
        provider_subject_hash=link.get("provider_subject_hash", ""),
        unionid_hash=link.get("unionid_hash", ""),
        payload={"identity_link": _public_link(updated), "session_revocation": session_revoke, "g08_g09_re_evaluation": reevaluation},
        request_meta=request_meta,
    )


def list_continuity_decisions(workspace_id: str = DEFAULT_WORKSPACE_ID, person_id: str = "", limit: int = 100) -> Dict[str, Any]:
    workspace_id = _clean_id(workspace_id, 96) or DEFAULT_WORKSPACE_ID
    rows = store.list_continuity_decisions(workspace_id=workspace_id, person_id=_clean_id(person_id, 96), limit=limit)
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "object_version": CONTINUITY_VERSION,
        "phase": PHASE,
        "source": "liveuin_identity",
        "canonical_owner": "LiveUIN Identity",
        "workspace_id": workspace_id,
        "continuity_decisions": rows,
        "continuity_decision_count": len(rows),
    }


def resolve_identity(
    *,
    provider: str = "",
    provider_user_id: str = "",
    unionid: str = "",
    workspace_id: str = DEFAULT_WORKSPACE_ID,
) -> Dict[str, Any]:
    provider = _clean_provider(provider)
    workspace_id = _clean_id(workspace_id, 96) or DEFAULT_WORKSPACE_ID
    subject_hash = _sha(provider_user_id)
    unionid_hash = _sha(unionid)
    if not provider and not unionid_hash:
        return error("provider_or_unionid_required")
    if provider and not subject_hash and not unionid_hash:
        return error("provider_user_id_required")

    link = store.find_link(
        workspace_id=workspace_id,
        provider=provider,
        provider_subject_hash=subject_hash,
        unionid_hash=unionid_hash,
    )
    if not link:
        return error("identity_link_not_found", 404)
    if link.get("verified_state") in {"quarantined", "unlinked", "superseded", "locked"}:
        return error("identity_link_review_required", 403)

    person = store.get_person(link["person_id"], workspace_id)
    if not person:
        return error("person_not_found", 404)

    response = _person_response(person, link=link)
    response["resolved"] = True
    return response


def get_person(person_id: str, workspace_id: str = DEFAULT_WORKSPACE_ID) -> Dict[str, Any]:
    person_id = _clean_id(person_id, 96)
    workspace_id = _clean_id(workspace_id, 96) or DEFAULT_WORKSPACE_ID
    if not person_id:
        return error("person_id_required")

    person = store.get_person(person_id, workspace_id)
    if not person:
        return error("person_not_found", 404)

    return _person_response(person)


def identity_status() -> Dict[str, Any]:
    storage = store.debug_summary()
    credential_storage = session_store.debug_summary()
    login_storage = login_store.debug_summary()
    tables = storage["tables"]
    credential_tables = credential_storage["tables"]
    login_tables = login_storage["tables"]
    return {
        "ok": True,
        "service": "liveuin-core-identity-preview",
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "source": "liveuin_identity",
        "canonical_owner": "LiveUIN Identity",
        "storage": storage["store"],
        "sqlite_path": storage["sqlite_path"],
        "credential_storage": credential_storage["store"],
        "credential_sqlite_path": credential_storage["sqlite_path"],
        "login_storage": login_storage["store"],
        "login_sqlite_path": login_storage["sqlite_path"],
        "person_count": tables.get("identity_persons", 0),
        "identity_link_count": tables.get("identity_links", 0),
        "consent_count": tables.get("identity_consent_records", 0),
        "audit_event_count": tables.get("identity_audit_events", 0),
        "continuity_decision_count": tables.get("identity_continuity_decisions", 0),
        "session_credential_count": credential_tables.get("identity_session_credentials", 0),
        "api_key_credential_count": credential_tables.get("identity_api_key_credentials", 0),
        "credential_audit_event_count": credential_tables.get("identity_credential_audit_events", 0),
        "login_challenge_count": login_tables.get("identity_login_challenges", 0),
        "login_audit_event_count": login_tables.get("identity_login_audit_events", 0),
        "routes": [
            "POST /api/core/identity/links",
            "GET /api/core/identity/resolve",
            "GET /api/core/identity/persons/{person_id}",
            "POST /api/core/identity/continuity/provider-link",
            "POST /api/core/identity/continuity/merge",
            "POST /api/core/identity/continuity/split",
            "POST /api/core/identity/continuity/unlink",
            "POST /api/core/identity/continuity/quarantine",
            "POST /api/core/identity/continuity/recover",
            "GET /api/core/identity/continuity/decisions",
            "GET /api/core/identity/login/status",
            "GET /api/core/identity/workspace-access/status",
            "POST /api/core/identity/workspaces/host-pilot",
            "GET /api/core/identity/workspace-memberships",
            "GET /api/core/identity/workspace-invites",
            "POST /api/core/identity/workspace-memberships",
            "POST /api/core/identity/workspace-invites",
            "GET /api/core/identity/profile-authorizations",
            "POST /api/core/identity/profile-authorizations/tenant/sync",
            "POST /api/core/identity/profile-authorizations/localpro/sync",
            "POST /api/core/identity/profile-authorizations/{entitlement_id}/transition",
            "POST /api/core/identity/login/challenges",
            "GET /api/core/identity/login/challenges",
            "POST /api/core/identity/login/challenges/{challenge_id}/verify",
            "POST /api/core/identity/login/challenges/{challenge_id}/cancel",
            "GET /api/core/identity/session/status",
            "POST /api/core/identity/session/resolve",
            "POST /api/core/identity/session/issue",
            "POST /api/core/identity/session/revoke",
            "GET /api/core/identity/credentials",
            "POST /api/core/identity/api-keys",
            "POST /api/core/identity/api-keys/revoke",
            "POST /api/core/identity/api-keys/rotate",
            "GET /api/core/identity/status",
        ],
        "boundary": {
            "surface": "WeChat Mini Program / Official Account identity handoff plus Core gateway session context",
            "layer": "canonical identity link, user-facing local login challenge, identity/session context, and private local credential issuer contract",
            "owner": "LiveUIN Identity",
            "wechat_role": "identity/OAuth/callback capture and message delivery only",
            "access_role": "normalizes actor, role, scopes, workspace, and credential hints for Core Access",
            "login_role": "turns verified Pass/protected-viewing/app/channel challenges into LiveUIN-owned sessions without storing raw codes or session ids",
            "credential_issuer_role": "mints local gateway sessions/API keys for private Core/Admin use; production still needs real LiveUIN login/session issuance and vault-backed persistence",
            "credential_store_role": "stores only hashes, actor/workspace/scope claims, status, expiry, revocation, and rotation lineage for LiveUIN sessions and API keys",
            "continuity_role": "persists G07 provider-link, duplicate-review, merge, split, unlink, quarantine, recovery, audit and idempotency decisions without making channel/provider payloads truth",
        },
    }
