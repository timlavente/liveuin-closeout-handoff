from __future__ import annotations

from contextlib import contextmanager
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List


def data_dir() -> Path:
    configured = os.getenv("LIVEUIN_CORE_IDENTITY_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()

    return Path(__file__).resolve().parents[1] / "runtime" / "core-identity-data"


def sqlite_path() -> Path:
    configured = os.getenv("LIVEUIN_CORE_IDENTITY_SQLITE_PATH", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()

    return data_dir() / "liveuin-core-identity.sqlite3"


def encode_json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=True, sort_keys=True)


def decode_json(value: Any, fallback: Any) -> Any:
    if value is None or value == "":
        return fallback

    if isinstance(value, (dict, list)):
        return value

    try:
        decoded = json.loads(str(value))
    except (TypeError, ValueError):
        return fallback

    return decoded if decoded is not None else fallback


@contextmanager
def connection() -> Iterator[sqlite3.Connection]:
    target = sqlite_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    ensure_schema(conn)
    try:
        yield conn
    finally:
        conn.close()


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS identity_persons (
            person_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            display_name TEXT NOT NULL DEFAULT '',
            locale TEXT NOT NULL DEFAULT '',
            role_flags_json TEXT NOT NULL DEFAULT '[]',
            contacts_json TEXT NOT NULL DEFAULT '{}',
            consent_state TEXT NOT NULL DEFAULT 'pending',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_identity_persons_workspace_updated
            ON identity_persons(workspace_id, updated_at DESC);

        CREATE TABLE IF NOT EXISTS identity_links (
            identity_link_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            person_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            provider_subject_hash TEXT NOT NULL,
            provider_subject_hint TEXT NOT NULL DEFAULT '',
            unionid_hash TEXT NOT NULL DEFAULT '',
            unionid_hint TEXT NOT NULL DEFAULT '',
            provider_app_id TEXT NOT NULL DEFAULT '',
            verified_state TEXT NOT NULL DEFAULT 'captured',
            case_id TEXT NOT NULL DEFAULT '',
            household_id TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE (workspace_id, provider, provider_subject_hash)
        );

        CREATE INDEX IF NOT EXISTS idx_identity_links_person_updated
            ON identity_links(workspace_id, person_id, updated_at DESC);

        CREATE INDEX IF NOT EXISTS idx_identity_links_unionid
            ON identity_links(workspace_id, unionid_hash);

        CREATE INDEX IF NOT EXISTS idx_identity_links_case
            ON identity_links(workspace_id, case_id);

        CREATE TABLE IF NOT EXISTS identity_consent_records (
            consent_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            person_id TEXT NOT NULL,
            case_id TEXT NOT NULL DEFAULT '',
            scope TEXT NOT NULL DEFAULT '',
            version TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending',
            payload_json TEXT NOT NULL DEFAULT '{}',
            accepted_at INTEGER,
            withdrawn_at INTEGER,
            created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_identity_consent_person_created
            ON identity_consent_records(workspace_id, person_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS identity_workspace_records (
            workspace_id TEXT PRIMARY KEY,
            source TEXT NOT NULL DEFAULT 'liveuin_identity',
            product_line TEXT NOT NULL DEFAULT 'connect',
            plan_type TEXT NOT NULL DEFAULT 'starter',
            status TEXT NOT NULL DEFAULT 'active',
            contact_email_hash TEXT NOT NULL DEFAULT '',
            contact_email_domain TEXT NOT NULL DEFAULT '',
            seat_limit INTEGER,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_identity_workspace_records_status
            ON identity_workspace_records(status, updated_at DESC);

        CREATE TABLE IF NOT EXISTS identity_workspace_memberships (
            membership_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            person_id TEXT NOT NULL DEFAULT '',
            email_hash TEXT NOT NULL DEFAULT '',
            email_domain TEXT NOT NULL DEFAULT '',
            workspace_role TEXT NOT NULL DEFAULT 'member',
            access_role TEXT NOT NULL DEFAULT 'agent',
            status TEXT NOT NULL DEFAULT 'active',
            source TEXT NOT NULL DEFAULT 'manual',
            plan_type TEXT NOT NULL DEFAULT '',
            seat_limit INTEGER,
            elevated_approval_required INTEGER NOT NULL DEFAULT 0,
            approved_by TEXT NOT NULL DEFAULT '',
            approved_at INTEGER,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_workspace_memberships_email_unique
            ON identity_workspace_memberships(workspace_id, email_hash)
            WHERE email_hash <> '';

        CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_workspace_memberships_person_unique
            ON identity_workspace_memberships(workspace_id, person_id)
            WHERE person_id <> '';

        CREATE INDEX IF NOT EXISTS idx_identity_workspace_memberships_workspace_status
            ON identity_workspace_memberships(workspace_id, status, updated_at DESC);

        CREATE TABLE IF NOT EXISTS identity_workspace_invites (
            invite_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            email_hash TEXT NOT NULL,
            email_domain TEXT NOT NULL DEFAULT '',
            workspace_role TEXT NOT NULL DEFAULT 'member',
            access_role TEXT NOT NULL DEFAULT 'agent',
            status TEXT NOT NULL DEFAULT 'invited',
            invited_by TEXT NOT NULL DEFAULT '',
            expires_at INTEGER,
            accepted_at INTEGER,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_identity_workspace_invites_email_status
            ON identity_workspace_invites(workspace_id, email_hash, status, updated_at DESC);

        CREATE TABLE IF NOT EXISTS identity_profile_entitlements (
            entitlement_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            account_id TEXT NOT NULL DEFAULT '',
            person_id TEXT NOT NULL DEFAULT '',
            profile_key TEXT NOT NULL DEFAULT '',
            subject_id TEXT NOT NULL DEFAULT '',
            subject_role TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            permissions_json TEXT NOT NULL DEFAULT '[]',
            route_restrictions_json TEXT NOT NULL DEFAULT '[]',
            effective_from INTEGER NOT NULL DEFAULT 0,
            effective_to INTEGER NOT NULL DEFAULT 0,
            is_default INTEGER NOT NULL DEFAULT 0,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_identity_profile_entitlements_person
            ON identity_profile_entitlements(person_id, status, updated_at DESC);

        CREATE INDEX IF NOT EXISTS idx_identity_profile_entitlements_account
            ON identity_profile_entitlements(account_id, status, updated_at DESC);

        CREATE INDEX IF NOT EXISTS idx_identity_profile_entitlements_workspace_profile
            ON identity_profile_entitlements(workspace_id, profile_key, status, updated_at DESC);

        CREATE TABLE IF NOT EXISTS identity_audit_events (
            event_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            person_id TEXT NOT NULL DEFAULT '',
            identity_link_id TEXT NOT NULL DEFAULT '',
            event_type TEXT NOT NULL,
            object_type TEXT NOT NULL DEFAULT 'identity_link',
            object_id TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL DEFAULT '{}',
            request_meta_json TEXT NOT NULL DEFAULT '{}',
            received_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_identity_audit_person_received
            ON identity_audit_events(workspace_id, person_id, received_at DESC);

        CREATE TABLE IF NOT EXISTS identity_continuity_decisions (
            decision_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            operation_type TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'review_required',
            canonical_person_id TEXT NOT NULL DEFAULT '',
            source_person_ids_json TEXT NOT NULL DEFAULT '[]',
            target_person_id TEXT NOT NULL DEFAULT '',
            identity_link_id TEXT NOT NULL DEFAULT '',
            provider TEXT NOT NULL DEFAULT '',
            provider_subject_hash TEXT NOT NULL DEFAULT '',
            unionid_hash TEXT NOT NULL DEFAULT '',
            idempotency_key TEXT NOT NULL DEFAULT '',
            quarantine_reason TEXT NOT NULL DEFAULT '',
            actor_id TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_identity_continuity_idempotency
            ON identity_continuity_decisions(workspace_id, idempotency_key)
            WHERE idempotency_key <> '';

        CREATE INDEX IF NOT EXISTS idx_identity_continuity_person_updated
            ON identity_continuity_decisions(workspace_id, canonical_person_id, updated_at DESC);
        """
    )
    conn.commit()


def row_to_person(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}

    data = dict(row)
    return {
        "person_id": str(data.get("person_id") or ""),
        "workspace_id": str(data.get("workspace_id") or "laijuzhu"),
        "display_name": str(data.get("display_name") or ""),
        "locale": str(data.get("locale") or ""),
        "role_flags": decode_json(data.get("role_flags_json"), []),
        "contacts": decode_json(data.get("contacts_json"), {}),
        "consent_state": str(data.get("consent_state") or "pending"),
        "metadata": decode_json(data.get("metadata_json"), {}),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
    }


def row_to_link(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}

    data = dict(row)
    return {
        "identity_link_id": str(data.get("identity_link_id") or ""),
        "workspace_id": str(data.get("workspace_id") or "laijuzhu"),
        "person_id": str(data.get("person_id") or ""),
        "provider": str(data.get("provider") or ""),
        "provider_subject_hash": str(data.get("provider_subject_hash") or ""),
        "provider_subject_hint": str(data.get("provider_subject_hint") or ""),
        "unionid_hash": str(data.get("unionid_hash") or ""),
        "unionid_hint": str(data.get("unionid_hint") or ""),
        "provider_app_id": str(data.get("provider_app_id") or ""),
        "verified_state": str(data.get("verified_state") or "captured"),
        "case_id": str(data.get("case_id") or ""),
        "household_id": str(data.get("household_id") or ""),
        "metadata": decode_json(data.get("metadata_json"), {}),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
    }


def row_to_consent(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}

    data = dict(row)
    return {
        "consent_id": str(data.get("consent_id") or ""),
        "workspace_id": str(data.get("workspace_id") or "laijuzhu"),
        "person_id": str(data.get("person_id") or ""),
        "case_id": str(data.get("case_id") or ""),
        "scope": str(data.get("scope") or ""),
        "version": str(data.get("version") or ""),
        "source": str(data.get("source") or ""),
        "status": str(data.get("status") or "pending"),
        "payload": decode_json(data.get("payload_json"), {}),
        "accepted_at": int(data.get("accepted_at") or 0),
        "withdrawn_at": int(data.get("withdrawn_at") or 0),
        "created_at": int(data.get("created_at") or 0),
    }


def row_to_workspace_record(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}

    data = dict(row)
    seat_limit = data.get("seat_limit")
    return {
        "workspace_id": str(data.get("workspace_id") or "laijuzhu"),
        "source": str(data.get("source") or "liveuin_identity"),
        "product_line": str(data.get("product_line") or "connect"),
        "plan_type": str(data.get("plan_type") or "starter"),
        "status": str(data.get("status") or "active"),
        "contact_email_hash": str(data.get("contact_email_hash") or ""),
        "contact_email_domain": str(data.get("contact_email_domain") or ""),
        "seat_limit": int(seat_limit) if seat_limit is not None else None,
        "metadata": decode_json(data.get("metadata_json"), {}),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
    }


def row_to_workspace_membership(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}

    data = dict(row)
    seat_limit = data.get("seat_limit")
    return {
        "membership_id": str(data.get("membership_id") or ""),
        "workspace_id": str(data.get("workspace_id") or "laijuzhu"),
        "person_id": str(data.get("person_id") or ""),
        "email_hash": str(data.get("email_hash") or ""),
        "email_domain": str(data.get("email_domain") or ""),
        "workspace_role": str(data.get("workspace_role") or "member"),
        "access_role": str(data.get("access_role") or "agent"),
        "status": str(data.get("status") or "active"),
        "source": str(data.get("source") or "manual"),
        "plan_type": str(data.get("plan_type") or ""),
        "seat_limit": int(seat_limit) if seat_limit is not None else None,
        "elevated_approval_required": bool(int(data.get("elevated_approval_required") or 0)),
        "approved_by": str(data.get("approved_by") or ""),
        "approved_at": int(data.get("approved_at") or 0),
        "metadata": decode_json(data.get("metadata_json"), {}),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
    }


def row_to_workspace_invite(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}

    data = dict(row)
    return {
        "invite_id": str(data.get("invite_id") or ""),
        "workspace_id": str(data.get("workspace_id") or "laijuzhu"),
        "email_hash": str(data.get("email_hash") or ""),
        "email_domain": str(data.get("email_domain") or ""),
        "workspace_role": str(data.get("workspace_role") or "member"),
        "access_role": str(data.get("access_role") or "agent"),
        "status": str(data.get("status") or "invited"),
        "invited_by": str(data.get("invited_by") or ""),
        "expires_at": int(data.get("expires_at") or 0),
        "accepted_at": int(data.get("accepted_at") or 0),
        "metadata": decode_json(data.get("metadata_json"), {}),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
    }


def row_to_profile_entitlement(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}

    data = dict(row)
    return {
        "entitlement_id": str(data.get("entitlement_id") or ""),
        "workspace_id": str(data.get("workspace_id") or "laijuzhu"),
        "account_id": str(data.get("account_id") or ""),
        "person_id": str(data.get("person_id") or ""),
        "profile_key": str(data.get("profile_key") or ""),
        "subject_id": str(data.get("subject_id") or ""),
        "subject_role": str(data.get("subject_role") or ""),
        "status": str(data.get("status") or "active"),
        "permissions": decode_json(data.get("permissions_json"), []),
        "route_restrictions": decode_json(data.get("route_restrictions_json"), []),
        "effective_from": int(data.get("effective_from") or 0),
        "effective_to": int(data.get("effective_to") or 0),
        "is_default": bool(int(data.get("is_default") or 0)),
        "metadata": decode_json(data.get("metadata_json"), {}),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
    }


def row_to_audit_event(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}

    data = dict(row)
    return {
        "event_id": str(data.get("event_id") or ""),
        "workspace_id": str(data.get("workspace_id") or "laijuzhu"),
        "person_id": str(data.get("person_id") or ""),
        "identity_link_id": str(data.get("identity_link_id") or ""),
        "event_type": str(data.get("event_type") or ""),
        "object_type": str(data.get("object_type") or ""),
        "object_id": str(data.get("object_id") or ""),
        "payload": decode_json(data.get("payload_json"), {}),
        "request_meta": decode_json(data.get("request_meta_json"), {}),
        "received_at": int(data.get("received_at") or 0),
    }


def row_to_continuity_decision(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}

    data = dict(row)
    return {
        "decision_id": str(data.get("decision_id") or ""),
        "workspace_id": str(data.get("workspace_id") or "laijuzhu"),
        "operation_type": str(data.get("operation_type") or ""),
        "status": str(data.get("status") or "review_required"),
        "canonical_person_id": str(data.get("canonical_person_id") or ""),
        "source_person_ids": decode_json(data.get("source_person_ids_json"), []),
        "target_person_id": str(data.get("target_person_id") or ""),
        "identity_link_id": str(data.get("identity_link_id") or ""),
        "provider": str(data.get("provider") or ""),
        "provider_subject_hash": str(data.get("provider_subject_hash") or ""),
        "unionid_hash": str(data.get("unionid_hash") or ""),
        "idempotency_key": str(data.get("idempotency_key") or ""),
        "quarantine_reason": str(data.get("quarantine_reason") or ""),
        "actor_id": str(data.get("actor_id") or ""),
        "payload": decode_json(data.get("payload_json"), {}),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
    }


def get_person(person_id: str, workspace_id: str = "laijuzhu") -> Dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM identity_persons
            WHERE person_id = ?
              AND workspace_id = ?
            LIMIT 1;
            """,
            (person_id, workspace_id),
        ).fetchone()

    return row_to_person(row)


def find_link(
    *,
    workspace_id: str,
    provider: str = "",
    provider_subject_hash: str = "",
    unionid_hash: str = "",
) -> Dict[str, Any]:
    with connection() as conn:
        if provider and provider_subject_hash:
            row = conn.execute(
                """
                SELECT *
                FROM identity_links
                WHERE workspace_id = ?
                  AND provider = ?
                  AND provider_subject_hash = ?
                LIMIT 1;
                """,
                (workspace_id, provider, provider_subject_hash),
            ).fetchone()
            if row:
                return row_to_link(row)

        if unionid_hash:
            row = conn.execute(
                """
                SELECT *
                FROM identity_links
                WHERE workspace_id = ?
                  AND unionid_hash = ?
                ORDER BY updated_at DESC
                LIMIT 1;
                """,
                (workspace_id, unionid_hash),
            ).fetchone()
            if row:
                return row_to_link(row)

    return {}


def get_link(identity_link_id: str, workspace_id: str = "laijuzhu") -> Dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM identity_links
            WHERE workspace_id = ?
              AND identity_link_id = ?
            LIMIT 1;
            """,
            (workspace_id, identity_link_id),
        ).fetchone()
    return row_to_link(row)


def list_links_by_unionid(workspace_id: str, unionid_hash: str, limit: int = 100) -> List[Dict[str, Any]]:
    if not unionid_hash:
        return []
    limit = max(1, min(int(limit or 100), 500))
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM identity_links
            WHERE workspace_id = ?
              AND unionid_hash = ?
            ORDER BY updated_at DESC
            LIMIT ?;
            """,
            (workspace_id, unionid_hash, limit),
        ).fetchall()
    return [row_to_link(row) for row in rows]


def upsert_person(record: Dict[str, Any]) -> Dict[str, Any]:
    now = int(record.get("updated_at") or time.time())
    created_at = int(record.get("created_at") or now)
    person_id = str(record["person_id"])
    workspace_id = str(record.get("workspace_id") or "laijuzhu")

    with connection() as conn:
        conn.execute(
            """
            INSERT INTO identity_persons (
                person_id, workspace_id, display_name, locale, role_flags_json,
                contacts_json, consent_state, metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(person_id) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                display_name = excluded.display_name,
                locale = excluded.locale,
                role_flags_json = excluded.role_flags_json,
                contacts_json = excluded.contacts_json,
                consent_state = excluded.consent_state,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at;
            """,
            (
                person_id,
                workspace_id,
                str(record.get("display_name") or ""),
                str(record.get("locale") or ""),
                encode_json(record.get("role_flags") or []),
                encode_json(record.get("contacts") or {}),
                str(record.get("consent_state") or "pending"),
                encode_json(record.get("metadata") or {}),
                created_at,
                now,
            ),
        )
        conn.commit()

    return get_person(person_id, workspace_id)


def upsert_link(record: Dict[str, Any]) -> Dict[str, Any]:
    now = int(record.get("updated_at") or time.time())
    created_at = int(record.get("created_at") or now)
    workspace_id = str(record.get("workspace_id") or "laijuzhu")

    with connection() as conn:
        conn.execute(
            """
            INSERT INTO identity_links (
                identity_link_id, workspace_id, person_id, provider,
                provider_subject_hash, provider_subject_hint, unionid_hash,
                unionid_hint, provider_app_id, verified_state, case_id,
                household_id, metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id, provider, provider_subject_hash) DO UPDATE SET
                person_id = excluded.person_id,
                unionid_hash = excluded.unionid_hash,
                unionid_hint = excluded.unionid_hint,
                provider_app_id = excluded.provider_app_id,
                verified_state = excluded.verified_state,
                case_id = excluded.case_id,
                household_id = excluded.household_id,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at;
            """,
            (
                str(record["identity_link_id"]),
                workspace_id,
                str(record["person_id"]),
                str(record["provider"]),
                str(record["provider_subject_hash"]),
                str(record.get("provider_subject_hint") or ""),
                str(record.get("unionid_hash") or ""),
                str(record.get("unionid_hint") or ""),
                str(record.get("provider_app_id") or ""),
                str(record.get("verified_state") or "captured"),
                str(record.get("case_id") or ""),
                str(record.get("household_id") or ""),
                encode_json(record.get("metadata") or {}),
                created_at,
                now,
            ),
        )
        conn.commit()

    return find_link(
        workspace_id=workspace_id,
        provider=str(record["provider"]),
        provider_subject_hash=str(record["provider_subject_hash"]),
    )


def update_link(record: Dict[str, Any]) -> Dict[str, Any]:
    now = int(record.get("updated_at") or time.time())
    with connection() as conn:
        conn.execute(
            """
            UPDATE identity_links
            SET person_id = ?, verified_state = ?, metadata_json = ?, updated_at = ?
            WHERE workspace_id = ? AND identity_link_id = ?;
            """,
            (
                str(record.get("person_id") or ""),
                str(record.get("verified_state") or "captured"),
                encode_json(record.get("metadata") or {}),
                now,
                str(record.get("workspace_id") or "laijuzhu"),
                str(record.get("identity_link_id") or ""),
            ),
        )
        conn.commit()
    return get_link(str(record.get("identity_link_id") or ""), str(record.get("workspace_id") or "laijuzhu"))


def move_links_to_person(workspace_id: str, source_person_id: str, target_person_id: str, metadata: Dict[str, Any] | None = None) -> int:
    now = int(time.time())
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM identity_links
            WHERE workspace_id = ? AND person_id = ?;
            """,
            (workspace_id, source_person_id),
        ).fetchall()
        count = 0
        for row in rows:
            link = row_to_link(row)
            merged_metadata = {**link.get("metadata", {}), **(metadata or {})}
            conn.execute(
                """
                UPDATE identity_links
                SET person_id = ?, metadata_json = ?, updated_at = ?
                WHERE workspace_id = ? AND identity_link_id = ?;
                """,
                (target_person_id, encode_json(merged_metadata), now, workspace_id, link["identity_link_id"]),
            )
            count += 1
        conn.commit()
    return count


def create_consent(record: Dict[str, Any]) -> Dict[str, Any]:
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO identity_consent_records (
                consent_id, workspace_id, person_id, case_id, scope, version,
                source, status, payload_json, accepted_at, withdrawn_at, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                str(record["consent_id"]),
                str(record.get("workspace_id") or "laijuzhu"),
                str(record["person_id"]),
                str(record.get("case_id") or ""),
                str(record.get("scope") or ""),
                str(record.get("version") or ""),
                str(record.get("source") or ""),
                str(record.get("status") or "pending"),
                encode_json(record.get("payload") or {}),
                record.get("accepted_at"),
                record.get("withdrawn_at"),
                int(record.get("created_at") or time.time()),
            ),
        )
        conn.commit()

    return get_consent(str(record["consent_id"]))


def get_consent(consent_id: str) -> Dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM identity_consent_records
            WHERE consent_id = ?
            LIMIT 1;
            """,
            (consent_id,),
        ).fetchone()

    return row_to_consent(row)


def get_workspace_record(workspace_id: str = "laijuzhu") -> Dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM identity_workspace_records
            WHERE workspace_id = ?
            LIMIT 1;
            """,
            (workspace_id,),
        ).fetchone()

    return row_to_workspace_record(row)


def list_workspace_records(
    *,
    source: str = "",
    product_line: str = "",
    plan_type: str = "",
    status: str = "",
    limit: int = 100,
) -> List[Dict[str, Any]]:
    limit = max(1, min(500, int(limit or 100)))
    clauses = ["1 = 1"]
    params: List[Any] = []
    for field, value in (("source", source), ("product_line", product_line), ("plan_type", plan_type), ("status", status)):
        if value:
            clauses.append(f"{field} = ?")
            params.append(value)
    params.append(limit)
    with connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM identity_workspace_records
            WHERE {' AND '.join(clauses)}
            ORDER BY updated_at DESC
            LIMIT ?;
            """,
            tuple(params),
        ).fetchall()
    return [row_to_workspace_record(row) for row in rows]


def upsert_workspace_record(record: Dict[str, Any]) -> Dict[str, Any]:
    now = int(record.get("updated_at") or time.time())
    created_at = int(record.get("created_at") or now)
    workspace_id = str(record.get("workspace_id") or "laijuzhu")

    with connection() as conn:
        conn.execute(
            """
            INSERT INTO identity_workspace_records (
                workspace_id, source, product_line, plan_type, status,
                contact_email_hash, contact_email_domain, seat_limit,
                metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id) DO UPDATE SET
                source = excluded.source,
                product_line = excluded.product_line,
                plan_type = excluded.plan_type,
                status = excluded.status,
                contact_email_hash = excluded.contact_email_hash,
                contact_email_domain = excluded.contact_email_domain,
                seat_limit = excluded.seat_limit,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at;
            """,
            (
                workspace_id,
                str(record.get("source") or "liveuin_identity"),
                str(record.get("product_line") or "connect"),
                str(record.get("plan_type") or "starter"),
                str(record.get("status") or "active"),
                str(record.get("contact_email_hash") or ""),
                str(record.get("contact_email_domain") or ""),
                record.get("seat_limit"),
                encode_json(record.get("metadata") or {}),
                created_at,
                now,
            ),
        )
        conn.commit()

    return get_workspace_record(workspace_id)


def create_host_workspace_with_owner(
    workspace_record: Dict[str, Any],
    owner_membership: Dict[str, Any],
    audit_event: Dict[str, Any],
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    """Atomically create one Host pilot workspace, its first owner, and its audit event."""
    workspace_record = dict(workspace_record or {})
    owner_membership = dict(owner_membership or {})
    audit_event = dict(audit_event or {})
    workspace_id = str(workspace_record.get("workspace_id") or "")
    membership_id = str(owner_membership.get("membership_id") or "")
    email_hash = str(owner_membership.get("email_hash") or "")
    metadata = workspace_record.get("metadata") if isinstance(workspace_record.get("metadata"), dict) else {}
    idempotency_hash = str(metadata.get("provisioning_idempotency_hash") or "")
    country_code = str(metadata.get("country_code") or "")

    if (
        not workspace_id.startswith("host_")
        or workspace_record.get("product_line") != "host"
        or workspace_record.get("status") != "active"
        or owner_membership.get("workspace_id") != workspace_id
        or owner_membership.get("workspace_role") != "owner"
        or owner_membership.get("access_role") != "owner"
        or owner_membership.get("status") != "active"
        or not membership_id
        or not email_hash
        or not idempotency_hash
        or len(country_code) != 2
        or not country_code.isascii()
        or not country_code.isalpha()
        or country_code != country_code.upper()
        or audit_event.get("event_type") != "identity.host_workspace_provisioned"
        or audit_event.get("workspace_id") != workspace_id
        or not str(audit_event.get("event_id") or "")
    ):
        raise ValueError("host_workspace_provisioning_contract_invalid")

    now = int(workspace_record.get("updated_at") or time.time())
    created_at = int(workspace_record.get("created_at") or now)
    request_meta = request_meta or {}

    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        try:
            existing_row = conn.execute(
                "SELECT * FROM identity_workspace_records WHERE workspace_id = ? LIMIT 1;",
                (workspace_id,),
            ).fetchone()
            if existing_row:
                existing = row_to_workspace_record(existing_row)
                existing_metadata = existing.get("metadata") if isinstance(existing.get("metadata"), dict) else {}
                same_request = (
                    existing.get("product_line") == "host"
                    and existing.get("status") == "active"
                    and existing.get("contact_email_hash") == str(workspace_record.get("contact_email_hash") or "")
                    and existing_metadata.get("provisioning_idempotency_hash") == idempotency_hash
                    and existing_metadata.get("country_code") == country_code
                )
                if not same_request:
                    conn.rollback()
                    return {"ok": False, "detail": "host_workspace_provisioning_conflict"}

                owner_rows = conn.execute(
                    """
                    SELECT * FROM identity_workspace_memberships
                    WHERE workspace_id = ? AND status = 'active'
                      AND workspace_role IN ('owner', 'landlord')
                      AND access_role IN ('owner', 'landlord')
                    ORDER BY updated_at DESC LIMIT 2;
                    """,
                    (workspace_id,),
                ).fetchall()
                if (
                    len(owner_rows) != 1
                    or owner_rows[0]["workspace_role"] != "owner"
                    or owner_rows[0]["access_role"] != "owner"
                    or owner_rows[0]["email_hash"] != email_hash
                ):
                    conn.rollback()
                    return {"ok": False, "detail": "host_workspace_provisioning_conflict"}
                event_row = conn.execute(
                    """
                    SELECT event_id FROM identity_audit_events
                    WHERE workspace_id = ? AND event_type = ?
                    ORDER BY received_at DESC LIMIT 1;
                    """,
                    (workspace_id, "identity.host_workspace_provisioned"),
                ).fetchone()
                result = {
                    "ok": True,
                    "created": False,
                    "workspace": existing,
                    "membership": row_to_workspace_membership(owner_rows[0]),
                    "audit_event_id": str(event_row["event_id"] or "") if event_row else "",
                }
                conn.rollback()
                return result

            active_pilots = conn.execute(
                """
                SELECT metadata_json FROM identity_workspace_records
                WHERE lower(product_line) IN ('host', 'owner') AND status = 'active';
                """
            ).fetchall()
            for pilot_row in active_pilots:
                pilot_metadata = decode_json(pilot_row["metadata_json"], {})
                if isinstance(pilot_metadata, dict) and pilot_metadata.get("pilot_mode") == "single_owner":
                    conn.rollback()
                    return {"ok": False, "detail": "host_pilot_workspace_already_exists"}

            conn.execute(
                """
                INSERT INTO identity_workspace_records (
                    workspace_id, source, product_line, plan_type, status,
                    contact_email_hash, contact_email_domain, seat_limit,
                    metadata_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    workspace_id,
                    str(workspace_record.get("source") or "liveuin_identity_admin"),
                    "host",
                    "starter",
                    "active",
                    str(workspace_record.get("contact_email_hash") or ""),
                    str(workspace_record.get("contact_email_domain") or ""),
                    1,
                    encode_json(metadata),
                    created_at,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO identity_workspace_memberships (
                    membership_id, workspace_id, person_id, email_hash, email_domain,
                    workspace_role, access_role, status, source, plan_type, seat_limit,
                    elevated_approval_required, approved_by, approved_at, metadata_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    membership_id,
                    workspace_id,
                    str(owner_membership.get("person_id") or ""),
                    email_hash,
                    str(owner_membership.get("email_domain") or ""),
                    "owner",
                    "owner",
                    "active",
                    str(owner_membership.get("source") or "identity_admin_host_provisioning"),
                    "starter",
                    1,
                    0,
                    str(owner_membership.get("approved_by") or ""),
                    owner_membership.get("approved_at"),
                    encode_json(owner_membership.get("metadata") or {}),
                    created_at,
                    now,
                ),
            )
            conn.execute(
                """
                INSERT INTO identity_audit_events (
                    event_id, workspace_id, person_id, identity_link_id,
                    event_type, object_type, object_id, payload_json,
                    request_meta_json, received_at
                ) VALUES (?, ?, '', '', ?, ?, ?, ?, ?, ?);
                """,
                (
                    str(audit_event["event_id"]),
                    workspace_id,
                    str(audit_event["event_type"]),
                    str(audit_event.get("object_type") or "host_workspace"),
                    str(audit_event.get("object_id") or workspace_id),
                    encode_json(audit_event.get("payload") or {}),
                    encode_json(request_meta),
                    int(audit_event.get("received_at") or now),
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    return {
        "ok": True,
        "created": True,
        "workspace": get_workspace_record(workspace_id),
        "membership": get_workspace_membership(membership_id),
        "audit_event_id": str(audit_event["event_id"]),
    }


def get_workspace_membership(membership_id: str) -> Dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM identity_workspace_memberships
            WHERE membership_id = ?
            LIMIT 1;
            """,
            (membership_id,),
        ).fetchone()

    return row_to_workspace_membership(row)


def get_workspace_membership_by_email(workspace_id: str, email_hash: str) -> Dict[str, Any]:
    if not email_hash:
        return {}

    with connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM identity_workspace_memberships
            WHERE workspace_id = ?
              AND email_hash = ?
            ORDER BY updated_at DESC
            LIMIT 1;
            """,
            (workspace_id, email_hash),
        ).fetchone()

    return row_to_workspace_membership(row)


def get_workspace_membership_by_person(workspace_id: str, person_id: str) -> Dict[str, Any]:
    if not person_id:
        return {}

    with connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM identity_workspace_memberships
            WHERE workspace_id = ?
              AND person_id = ?
            ORDER BY updated_at DESC
            LIMIT 1;
            """,
            (workspace_id, person_id),
        ).fetchone()

    return row_to_workspace_membership(row)


def upsert_workspace_membership(record: Dict[str, Any]) -> Dict[str, Any]:
    now = int(record.get("updated_at") or time.time())
    created_at = int(record.get("created_at") or now)
    workspace_id = str(record.get("workspace_id") or "laijuzhu")
    email_hash = str(record.get("email_hash") or "")
    person_id = str(record.get("person_id") or "")
    existing = get_workspace_membership_by_email(workspace_id, email_hash) if email_hash else {}
    if not existing and person_id:
        existing = get_workspace_membership_by_person(workspace_id, person_id)
    membership_id = str(existing.get("membership_id") or record.get("membership_id") or "")
    if not membership_id:
        raise ValueError("membership_id_required")

    with connection() as conn:
        conn.execute(
            """
            INSERT INTO identity_workspace_memberships (
                membership_id, workspace_id, person_id, email_hash, email_domain,
                workspace_role, access_role, status, source, plan_type, seat_limit,
                elevated_approval_required, approved_by, approved_at, metadata_json,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(membership_id) DO UPDATE SET
                person_id = CASE
                    WHEN excluded.person_id <> '' THEN excluded.person_id
                    ELSE identity_workspace_memberships.person_id
                END,
                email_hash = CASE
                    WHEN excluded.email_hash <> '' THEN excluded.email_hash
                    ELSE identity_workspace_memberships.email_hash
                END,
                email_domain = CASE
                    WHEN excluded.email_domain <> '' THEN excluded.email_domain
                    ELSE identity_workspace_memberships.email_domain
                END,
                workspace_role = excluded.workspace_role,
                access_role = excluded.access_role,
                status = excluded.status,
                source = excluded.source,
                plan_type = excluded.plan_type,
                seat_limit = excluded.seat_limit,
                elevated_approval_required = excluded.elevated_approval_required,
                approved_by = excluded.approved_by,
                approved_at = excluded.approved_at,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at;
            """,
            (
                membership_id,
                workspace_id,
                person_id,
                email_hash,
                str(record.get("email_domain") or ""),
                str(record.get("workspace_role") or "member"),
                str(record.get("access_role") or "agent"),
                str(record.get("status") or "active"),
                str(record.get("source") or "manual"),
                str(record.get("plan_type") or ""),
                record.get("seat_limit"),
                1 if record.get("elevated_approval_required") else 0,
                str(record.get("approved_by") or ""),
                record.get("approved_at"),
                encode_json(record.get("metadata") or {}),
                existing.get("created_at") or created_at,
                now,
            ),
        )
        conn.commit()

    return get_workspace_membership(membership_id)


def list_workspace_memberships(workspace_id: str = "laijuzhu", limit: int = 100) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 100), 500))
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM identity_workspace_memberships
            WHERE workspace_id = ?
            ORDER BY updated_at DESC
            LIMIT ?;
            """,
            (workspace_id, limit),
        ).fetchall()

    return [row_to_workspace_membership(row) for row in rows]


def count_active_workspace_memberships(workspace_id: str = "laijuzhu") -> int:
    with connection() as conn:
        row = conn.execute(
            """
            SELECT count(*) AS total
            FROM identity_workspace_memberships
            WHERE workspace_id = ?
              AND status = 'active';
            """,
            (workspace_id,),
        ).fetchone()

    return int(row["total"] or 0) if row else 0


def upsert_workspace_invite(record: Dict[str, Any]) -> Dict[str, Any]:
    now = int(record.get("updated_at") or time.time())
    created_at = int(record.get("created_at") or now)
    invite_id = str(record["invite_id"])

    with connection() as conn:
        conn.execute(
            """
            INSERT INTO identity_workspace_invites (
                invite_id, workspace_id, email_hash, email_domain, workspace_role,
                access_role, status, invited_by, expires_at, accepted_at,
                metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(invite_id) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                email_hash = excluded.email_hash,
                email_domain = excluded.email_domain,
                workspace_role = excluded.workspace_role,
                access_role = excluded.access_role,
                status = excluded.status,
                invited_by = excluded.invited_by,
                expires_at = excluded.expires_at,
                accepted_at = excluded.accepted_at,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at;
            """,
            (
                invite_id,
                str(record.get("workspace_id") or "laijuzhu"),
                str(record.get("email_hash") or ""),
                str(record.get("email_domain") or ""),
                str(record.get("workspace_role") or "member"),
                str(record.get("access_role") or "agent"),
                str(record.get("status") or "invited"),
                str(record.get("invited_by") or ""),
                record.get("expires_at"),
                record.get("accepted_at"),
                encode_json(record.get("metadata") or {}),
                created_at,
                now,
            ),
        )
        conn.commit()

    return get_workspace_invite(invite_id)


def get_workspace_invite(invite_id: str) -> Dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM identity_workspace_invites
            WHERE invite_id = ?
            LIMIT 1;
            """,
            (invite_id,),
        ).fetchone()

    return row_to_workspace_invite(row)


def find_active_workspace_invite(workspace_id: str, email_hash: str, now: int | None = None) -> Dict[str, Any]:
    if not email_hash:
        return {}

    now = int(now or time.time())
    with connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM identity_workspace_invites
            WHERE workspace_id = ?
              AND email_hash = ?
              AND status IN ('invited', 'pending')
              AND (expires_at IS NULL OR expires_at = 0 OR expires_at > ?)
            ORDER BY updated_at DESC
            LIMIT 1;
            """,
            (workspace_id, email_hash, now),
        ).fetchone()

    return row_to_workspace_invite(row)


def list_workspace_invites(workspace_id: str = "laijuzhu", limit: int = 100) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 100), 500))
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM identity_workspace_invites
            WHERE workspace_id = ?
            ORDER BY updated_at DESC
            LIMIT ?;
            """,
            (workspace_id, limit),
        ).fetchall()

    return [row_to_workspace_invite(row) for row in rows]


def get_profile_entitlement(entitlement_id: str) -> Dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM identity_profile_entitlements
            WHERE entitlement_id = ?
            LIMIT 1;
            """,
            (entitlement_id,),
        ).fetchone()

    return row_to_profile_entitlement(row)


def upsert_profile_entitlement(record: Dict[str, Any]) -> Dict[str, Any]:
    now = int(record.get("updated_at") or time.time())
    created_at = int(record.get("created_at") or now)
    entitlement_id = str(record["entitlement_id"])

    with connection() as conn:
        conn.execute(
            """
            INSERT INTO identity_profile_entitlements (
                entitlement_id, workspace_id, account_id, person_id, profile_key,
                subject_id, subject_role, status, permissions_json, route_restrictions_json,
                effective_from, effective_to, is_default, metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(entitlement_id) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                account_id = excluded.account_id,
                person_id = excluded.person_id,
                profile_key = excluded.profile_key,
                subject_id = excluded.subject_id,
                subject_role = excluded.subject_role,
                status = excluded.status,
                permissions_json = excluded.permissions_json,
                route_restrictions_json = excluded.route_restrictions_json,
                effective_from = excluded.effective_from,
                effective_to = excluded.effective_to,
                is_default = excluded.is_default,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at;
            """,
            (
                entitlement_id,
                str(record.get("workspace_id") or "laijuzhu"),
                str(record.get("account_id") or ""),
                str(record.get("person_id") or ""),
                str(record.get("profile_key") or ""),
                str(record.get("subject_id") or ""),
                str(record.get("subject_role") or ""),
                str(record.get("status") or "active"),
                encode_json(record.get("permissions") or []),
                encode_json(record.get("route_restrictions") or []),
                int(record.get("effective_from") or 0),
                int(record.get("effective_to") or 0),
                1 if record.get("is_default") else 0,
                encode_json(record.get("metadata") or {}),
                created_at,
                now,
            ),
        )
        conn.commit()

    return get_profile_entitlement(entitlement_id)


def list_profile_entitlements(
    *,
    person_id: str = "",
    account_id: str = "",
    workspace_id: str = "",
    limit: int = 100,
) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 100), 500))
    clauses: List[str] = []
    params: List[Any] = []
    if person_id:
        clauses.append("person_id = ?")
        params.append(person_id)
    if account_id:
        clauses.append("account_id = ?")
        params.append(account_id)
    if workspace_id:
        clauses.append("workspace_id = ?")
        params.append(workspace_id)
    if not clauses:
        return []
    params.append(limit)
    with connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM identity_profile_entitlements
            WHERE {" AND ".join(clauses)}
            ORDER BY is_default DESC, updated_at DESC, entitlement_id DESC
            LIMIT ?;
            """,
            tuple(params),
        ).fetchall()

    return [row_to_profile_entitlement(row) for row in rows]


def list_audit_events(
    *,
    workspace_id: str = "",
    person_id: str = "",
    object_type: str = "",
    object_id: str = "",
    event_type: str = "",
    limit: int = 100,
) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 100), 500))
    clauses: List[str] = []
    params: List[Any] = []
    if workspace_id:
        clauses.append("workspace_id = ?")
        params.append(workspace_id)
    if person_id:
        clauses.append("person_id = ?")
        params.append(person_id)
    if object_type:
        clauses.append("object_type = ?")
        params.append(object_type)
    if object_id:
        clauses.append("object_id = ?")
        params.append(object_id)
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if not clauses:
        return []
    params.append(limit)
    with connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM identity_audit_events
            WHERE {" AND ".join(clauses)}
            ORDER BY received_at DESC, event_id DESC
            LIMIT ?;
            """,
            tuple(params),
        ).fetchall()

    return [row_to_audit_event(row) for row in rows]


def list_links_for_person(person_id: str, workspace_id: str = "laijuzhu") -> List[Dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM identity_links
            WHERE workspace_id = ?
              AND person_id = ?
            ORDER BY updated_at DESC;
            """,
            (workspace_id, person_id),
        ).fetchall()

    return [row_to_link(row) for row in rows]


def list_consents_for_person(person_id: str, workspace_id: str = "laijuzhu") -> List[Dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM identity_consent_records
            WHERE workspace_id = ?
              AND person_id = ?
            ORDER BY created_at DESC;
            """,
            (workspace_id, person_id),
        ).fetchall()

    return [row_to_consent(row) for row in rows]


def append_audit_event(record: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> None:
    request_meta = request_meta or {}
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO identity_audit_events (
                event_id, workspace_id, person_id, identity_link_id,
                event_type, object_type, object_id, payload_json,
                request_meta_json, received_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                str(record["event_id"]),
                str(record.get("workspace_id") or "laijuzhu"),
                str(record.get("person_id") or ""),
                str(record.get("identity_link_id") or ""),
                str(record["event_type"]),
                str(record.get("object_type") or "identity_link"),
                str(record.get("object_id") or record.get("identity_link_id") or ""),
                encode_json(record.get("payload") or {}),
                encode_json(request_meta),
                int(record.get("received_at") or time.time()),
            ),
        )
        conn.commit()


def upsert_continuity_decision(record: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    now = int(record.get("updated_at") or time.time())
    created_at = int(record.get("created_at") or now)
    workspace_id = str(record.get("workspace_id") or "laijuzhu")
    decision_id = str(record.get("decision_id") or "")
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO identity_continuity_decisions (
                decision_id, workspace_id, operation_type, status, canonical_person_id,
                source_person_ids_json, target_person_id, identity_link_id, provider,
                provider_subject_hash, unionid_hash, idempotency_key, quarantine_reason,
                actor_id, payload_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(decision_id) DO UPDATE SET
                status = excluded.status,
                canonical_person_id = excluded.canonical_person_id,
                source_person_ids_json = excluded.source_person_ids_json,
                target_person_id = excluded.target_person_id,
                identity_link_id = excluded.identity_link_id,
                provider = excluded.provider,
                provider_subject_hash = excluded.provider_subject_hash,
                unionid_hash = excluded.unionid_hash,
                idempotency_key = excluded.idempotency_key,
                quarantine_reason = excluded.quarantine_reason,
                actor_id = excluded.actor_id,
                payload_json = excluded.payload_json,
                updated_at = excluded.updated_at;
            """,
            (
                decision_id,
                workspace_id,
                str(record.get("operation_type") or ""),
                str(record.get("status") or "review_required"),
                str(record.get("canonical_person_id") or ""),
                encode_json(record.get("source_person_ids") or []),
                str(record.get("target_person_id") or ""),
                str(record.get("identity_link_id") or ""),
                str(record.get("provider") or ""),
                str(record.get("provider_subject_hash") or ""),
                str(record.get("unionid_hash") or ""),
                str(record.get("idempotency_key") or ""),
                str(record.get("quarantine_reason") or ""),
                str(record.get("actor_id") or ""),
                encode_json(record.get("payload") or {}),
                created_at,
                now,
            ),
        )
        conn.commit()
    return get_continuity_decision(decision_id, workspace_id)


def get_continuity_decision(decision_id: str, workspace_id: str = "laijuzhu") -> Dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM identity_continuity_decisions
            WHERE workspace_id = ? AND decision_id = ?
            LIMIT 1;
            """,
            (workspace_id, decision_id),
        ).fetchone()
    return row_to_continuity_decision(row)


def get_continuity_decision_by_idempotency(workspace_id: str, idempotency_key: str) -> Dict[str, Any]:
    if not idempotency_key:
        return {}
    with connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM identity_continuity_decisions
            WHERE workspace_id = ? AND idempotency_key = ?
            LIMIT 1;
            """,
            (workspace_id, idempotency_key),
        ).fetchone()
    return row_to_continuity_decision(row)


def list_continuity_decisions(workspace_id: str = "laijuzhu", person_id: str = "", limit: int = 100) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 100), 500))
    clauses = ["workspace_id = ?"]
    params: List[Any] = [workspace_id]
    if person_id:
        clauses.append("(canonical_person_id = ? OR target_person_id = ? OR source_person_ids_json LIKE ?)")
        params.extend([person_id, person_id, f"%{person_id}%"])
    params.append(limit)
    with connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM identity_continuity_decisions
            WHERE {' AND '.join(clauses)}
            ORDER BY updated_at DESC, decision_id DESC
            LIMIT ?;
            """,
            tuple(params),
        ).fetchall()
    return [row_to_continuity_decision(row) for row in rows]


def debug_summary() -> Dict[str, Any]:
    tables: Dict[str, int] = {}
    with connection() as conn:
        for table in (
            "identity_persons",
            "identity_links",
            "identity_consent_records",
            "identity_workspace_records",
            "identity_workspace_memberships",
            "identity_workspace_invites",
            "identity_profile_entitlements",
            "identity_audit_events",
            "identity_continuity_decisions",
        ):
            row = conn.execute(f"SELECT count(*) AS total FROM {table};").fetchone()
            tables[table] = int(row["total"] or 0) if row else 0

    return {
        "ok": True,
        "store": "sqlite",
        "sqlite_path": str(sqlite_path()),
        "tables": tables,
    }
