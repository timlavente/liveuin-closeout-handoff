from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List


def data_dir() -> Path:
    configured = os.getenv("LIVEUIN_CORE_IDENTITY_LOGIN_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[1] / "runtime" / "core-identity-login-data"


def sqlite_path() -> Path:
    configured = os.getenv("LIVEUIN_CORE_IDENTITY_LOGIN_SQLITE_PATH", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return data_dir() / "liveuin-core-identity-login.sqlite3"


def encode_json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=True, sort_keys=True)


def decode_json(value: Any, fallback: Any) -> Any:
    if value in (None, ""):
        return fallback
    if isinstance(value, (dict, list)):
        return value
    try:
        decoded = json.loads(str(value))
    except (TypeError, ValueError):
        return fallback
    return decoded if decoded is not None else fallback


def hash_secret(value: Any) -> str:
    return hashlib.sha256(str(value or "").strip().encode("utf-8")).hexdigest()


def _now() -> int:
    return int(time.time())


def _clean_id(value: Any, max_length: int = 120) -> str:
    return "".join(ch for ch in str(value or "").strip() if ch.isalnum() or ch in "_.:-")[:max_length]


def _hint(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 10:
        return text[:2] + "..." + text[-2:]
    return text[:5] + "..." + text[-4:]


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: Dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).lower()
            if normalized in {
                "code",
                "code_hash",
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
                continue
            cleaned[str(key)] = _redact(item)
        return cleaned
    if isinstance(value, list):
        return [_redact(item) for item in value[:100]]
    if isinstance(value, str) and value.startswith(("http://", "https://", "s3://")):
        return "[redacted_ref]"
    return value


def _scopes(value: Any) -> List[str]:
    scopes = value if isinstance(value, list) else [value] if isinstance(value, str) and value.strip() else []
    cleaned: List[str] = []
    for item in scopes:
        scope = _clean_id(str(item or "").strip(), 120)
        if scope and scope not in cleaned:
            cleaned.append(scope)
    return cleaned[:80]


def _connection() -> sqlite3.Connection:
    target = sqlite_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    ensure_schema(conn)
    return conn


def _has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(str(row[1]) == column for row in rows)


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS identity_login_challenges (
            challenge_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            person_id TEXT NOT NULL DEFAULT '',
            household_id TEXT NOT NULL DEFAULT '',
            case_id TEXT NOT NULL DEFAULT '',
            channel TEXT NOT NULL DEFAULT '',
            purpose TEXT NOT NULL DEFAULT '',
            provider TEXT NOT NULL DEFAULT '',
            subject_hash TEXT NOT NULL DEFAULT '',
            subject_hint TEXT NOT NULL DEFAULT '',
            delivery_target_hash TEXT NOT NULL DEFAULT '',
            delivery_target_hint TEXT NOT NULL DEFAULT '',
            actor_id TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT '',
            scopes_json TEXT NOT NULL DEFAULT '[]',
            code_hash TEXT NOT NULL DEFAULT '',
            attempts INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 5,
            status TEXT NOT NULL DEFAULT 'pending',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            issued_at INTEGER NOT NULL DEFAULT 0,
            expires_at INTEGER NOT NULL DEFAULT 0,
            verified_at INTEGER NOT NULL DEFAULT 0,
            cancelled_at INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    for column, ddl in (
        ("person_id", "ALTER TABLE identity_login_challenges ADD COLUMN person_id TEXT NOT NULL DEFAULT ''"),
        ("household_id", "ALTER TABLE identity_login_challenges ADD COLUMN household_id TEXT NOT NULL DEFAULT ''"),
        ("case_id", "ALTER TABLE identity_login_challenges ADD COLUMN case_id TEXT NOT NULL DEFAULT ''"),
        ("channel", "ALTER TABLE identity_login_challenges ADD COLUMN channel TEXT NOT NULL DEFAULT ''"),
        ("purpose", "ALTER TABLE identity_login_challenges ADD COLUMN purpose TEXT NOT NULL DEFAULT ''"),
        ("provider", "ALTER TABLE identity_login_challenges ADD COLUMN provider TEXT NOT NULL DEFAULT ''"),
        ("subject_hash", "ALTER TABLE identity_login_challenges ADD COLUMN subject_hash TEXT NOT NULL DEFAULT ''"),
        ("subject_hint", "ALTER TABLE identity_login_challenges ADD COLUMN subject_hint TEXT NOT NULL DEFAULT ''"),
        ("delivery_target_hash", "ALTER TABLE identity_login_challenges ADD COLUMN delivery_target_hash TEXT NOT NULL DEFAULT ''"),
        ("delivery_target_hint", "ALTER TABLE identity_login_challenges ADD COLUMN delivery_target_hint TEXT NOT NULL DEFAULT ''"),
        ("actor_id", "ALTER TABLE identity_login_challenges ADD COLUMN actor_id TEXT NOT NULL DEFAULT ''"),
        ("role", "ALTER TABLE identity_login_challenges ADD COLUMN role TEXT NOT NULL DEFAULT ''"),
        ("scopes_json", "ALTER TABLE identity_login_challenges ADD COLUMN scopes_json TEXT NOT NULL DEFAULT '[]'"),
        ("code_hash", "ALTER TABLE identity_login_challenges ADD COLUMN code_hash TEXT NOT NULL DEFAULT ''"),
        ("attempts", "ALTER TABLE identity_login_challenges ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0"),
        ("max_attempts", "ALTER TABLE identity_login_challenges ADD COLUMN max_attempts INTEGER NOT NULL DEFAULT 5"),
        ("verified_at", "ALTER TABLE identity_login_challenges ADD COLUMN verified_at INTEGER NOT NULL DEFAULT 0"),
        ("cancelled_at", "ALTER TABLE identity_login_challenges ADD COLUMN cancelled_at INTEGER NOT NULL DEFAULT 0"),
        ("created_at", "ALTER TABLE identity_login_challenges ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0"),
        ("updated_at", "ALTER TABLE identity_login_challenges ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0"),
    ):
        if not _has_column(conn, "identity_login_challenges", column):
            conn.execute(ddl)
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_identity_login_workspace
            ON identity_login_challenges(workspace_id, status, issued_at DESC);
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS identity_login_audit_events (
            event_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            challenge_id TEXT NOT NULL DEFAULT '',
            event_type TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL DEFAULT '{}',
            request_meta_json TEXT NOT NULL DEFAULT '{}',
            received_at INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    for column, ddl in (
        ("workspace_id", "ALTER TABLE identity_login_audit_events ADD COLUMN workspace_id TEXT NOT NULL DEFAULT 'laijuzhu'"),
        ("challenge_id", "ALTER TABLE identity_login_audit_events ADD COLUMN challenge_id TEXT NOT NULL DEFAULT ''"),
        ("event_type", "ALTER TABLE identity_login_audit_events ADD COLUMN event_type TEXT NOT NULL DEFAULT ''"),
        ("status", "ALTER TABLE identity_login_audit_events ADD COLUMN status TEXT NOT NULL DEFAULT ''"),
        ("payload_json", "ALTER TABLE identity_login_audit_events ADD COLUMN payload_json TEXT NOT NULL DEFAULT '{}'"),
        ("request_meta_json", "ALTER TABLE identity_login_audit_events ADD COLUMN request_meta_json TEXT NOT NULL DEFAULT '{}'"),
        ("received_at", "ALTER TABLE identity_login_audit_events ADD COLUMN received_at INTEGER NOT NULL DEFAULT 0"),
    ):
        if not _has_column(conn, "identity_login_audit_events", column):
            conn.execute(ddl)
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_identity_login_audit_workspace
            ON identity_login_audit_events(workspace_id, challenge_id, received_at DESC);
        """
    )
    conn.commit()


def _row_json(row: sqlite3.Row | Dict[str, Any], key: str, fallback: Any) -> Any:
    return decode_json(dict(row).get(key), fallback)


def _challenge_record(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}
    data = dict(row)
    return {
        "challenge_id": str(data.get("challenge_id") or ""),
        "workspace_id": str(data.get("workspace_id") or "laijuzhu"),
        "person_id": str(data.get("person_id") or ""),
        "household_id": str(data.get("household_id") or ""),
        "case_id": str(data.get("case_id") or ""),
        "channel": str(data.get("channel") or ""),
        "purpose": str(data.get("purpose") or ""),
        "provider": str(data.get("provider") or ""),
        "subject_hash": str(data.get("subject_hash") or ""),
        "subject_hint": str(data.get("subject_hint") or ""),
        "delivery_target_hash": str(data.get("delivery_target_hash") or ""),
        "delivery_target_hint": str(data.get("delivery_target_hint") or ""),
        "actor_id": str(data.get("actor_id") or ""),
        "role": str(data.get("role") or ""),
        "scopes": _row_json(row, "scopes_json", []),
        "code_hash": str(data.get("code_hash") or ""),
        "attempts": int(data.get("attempts") or 0),
        "max_attempts": int(data.get("max_attempts") or 5),
        "status": str(data.get("status") or "pending"),
        "metadata": _row_json(row, "metadata_json", {}),
        "issued_at": int(data.get("issued_at") or 0),
        "expires_at": int(data.get("expires_at") or 0),
        "verified_at": int(data.get("verified_at") or 0),
        "cancelled_at": int(data.get("cancelled_at") or 0),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
    }


def _record_audit(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    challenge_id: str,
    event_type: str,
    status: str,
    payload: Dict[str, Any] | None = None,
    request_meta: Dict[str, str] | None = None,
) -> None:
    event_id = "login_evt_" + hashlib.sha1(f"{challenge_id}:{event_type}:{time.time_ns()}".encode("utf-8")).hexdigest()[:20]
    recorded_at = _now()
    columns = [
        "event_id",
        "workspace_id",
        "challenge_id",
        "event_type",
        "status",
        "payload_json",
        "request_meta_json",
    ]
    values: List[Any] = [
        event_id,
        workspace_id,
        challenge_id,
        event_type,
        status,
        encode_json(_redact(payload or {})),
        encode_json(_redact(request_meta or {})),
    ]
    if _has_column(conn, "identity_login_audit_events", "received_at"):
        columns.append("received_at")
        values.append(recorded_at)
    if _has_column(conn, "identity_login_audit_events", "recorded_at"):
        columns.append("recorded_at")
        values.append(recorded_at)
    placeholders = ", ".join("?" for _ in columns)
    conn.execute(
        f"""
        INSERT INTO identity_login_audit_events (
            {", ".join(columns)}
        )
        VALUES ({placeholders});
        """,
        tuple(values),
    )


def create_challenge(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    now = _now()
    challenge_id = _clean_id(payload.get("challenge_id"), 120) or (
        "lch_" + hashlib.sha1(f"{payload.get('workspace_id')}:{payload.get('actor_id')}:{time.time_ns()}".encode("utf-8")).hexdigest()[:20]
    )
    workspace_id = _clean_id(payload.get("workspace_id") or "laijuzhu", 96) or "laijuzhu"
    record = {
        "challenge_id": challenge_id,
        "workspace_id": workspace_id,
        "person_id": _clean_id(payload.get("person_id"), 96),
        "household_id": _clean_id(payload.get("household_id"), 96),
        "case_id": _clean_id(payload.get("case_id"), 96),
        "channel": _clean_id(payload.get("channel"), 80),
        "purpose": _clean_id(payload.get("purpose"), 80),
        "provider": _clean_id(payload.get("provider"), 80),
        "subject_hash": str(payload.get("subject_hash") or "").strip(),
        "subject_hint": str(payload.get("subject_hint") or _hint(payload.get("subject_hash"))),
        "delivery_target_hash": str(payload.get("delivery_target_hash") or "").strip(),
        "delivery_target_hint": str(payload.get("delivery_target_hint") or _hint(payload.get("delivery_target_hash"))),
        "actor_id": _clean_id(payload.get("actor_id"), 120),
        "role": _clean_id(payload.get("role"), 80),
        "scopes": _scopes(payload.get("scopes")),
        "code_hash": str(payload.get("code_hash") or "").strip(),
        "attempts": max(0, int(payload.get("attempts") or 0)),
        "max_attempts": min(max(int(payload.get("max_attempts") or 5), 1), 10),
        "status": _clean_id(payload.get("status") or "pending", 40) or "pending",
        "metadata": _redact(payload.get("metadata") or {}),
        "issued_at": int(payload.get("issued_at") or now),
        "expires_at": int(payload.get("expires_at") or 0),
        "verified_at": int(payload.get("verified_at") or 0),
        "cancelled_at": int(payload.get("cancelled_at") or 0),
        "created_at": int(payload.get("created_at") or now),
        "updated_at": now,
    }
    with _connection() as conn:
        conn.execute(
            """
            INSERT INTO identity_login_challenges (
                challenge_id, workspace_id, person_id, household_id, case_id, channel, purpose, provider,
                subject_hash, subject_hint, delivery_target_hash, delivery_target_hint, actor_id, role, scopes_json,
                code_hash, attempts, max_attempts, status, metadata_json, issued_at, expires_at, verified_at,
                cancelled_at, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(challenge_id) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                person_id = excluded.person_id,
                household_id = excluded.household_id,
                case_id = excluded.case_id,
                channel = excluded.channel,
                purpose = excluded.purpose,
                provider = excluded.provider,
                subject_hash = excluded.subject_hash,
                subject_hint = excluded.subject_hint,
                delivery_target_hash = excluded.delivery_target_hash,
                delivery_target_hint = excluded.delivery_target_hint,
                actor_id = excluded.actor_id,
                role = excluded.role,
                scopes_json = excluded.scopes_json,
                code_hash = excluded.code_hash,
                attempts = excluded.attempts,
                max_attempts = excluded.max_attempts,
                status = excluded.status,
                metadata_json = excluded.metadata_json,
                issued_at = excluded.issued_at,
                expires_at = excluded.expires_at,
                verified_at = excluded.verified_at,
                cancelled_at = excluded.cancelled_at,
                updated_at = excluded.updated_at;
            """,
            (
                record["challenge_id"],
                record["workspace_id"],
                record["person_id"],
                record["household_id"],
                record["case_id"],
                record["channel"],
                record["purpose"],
                record["provider"],
                record["subject_hash"],
                record["subject_hint"],
                record["delivery_target_hash"],
                record["delivery_target_hint"],
                record["actor_id"],
                record["role"],
                encode_json(record["scopes"]),
                record["code_hash"],
                record["attempts"],
                record["max_attempts"],
                record["status"],
                encode_json(record["metadata"]),
                record["issued_at"],
                record["expires_at"],
                record["verified_at"],
                record["cancelled_at"],
                record["created_at"],
                record["updated_at"],
            ),
        )
        _record_audit(
            conn,
            workspace_id=workspace_id,
            challenge_id=challenge_id,
            event_type="login_challenge.created",
            status=record["status"],
            payload={
                "channel": record["channel"],
                "purpose": record["purpose"],
                "role": record["role"],
                "scopes": record["scopes"],
            },
            request_meta=request_meta,
        )
        conn.commit()
    return get_challenge(challenge_id, workspace_id=workspace_id)


def get_challenge(challenge_id: str, workspace_id: str = "") -> Dict[str, Any]:
    challenge_id = _clean_id(challenge_id, 120)
    if not challenge_id:
        return {}
    with _connection() as conn:
        if workspace_id:
            row = conn.execute(
                "SELECT * FROM identity_login_challenges WHERE challenge_id = ? AND workspace_id = ? LIMIT 1",
                (challenge_id, _clean_id(workspace_id, 96) or "laijuzhu"),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM identity_login_challenges WHERE challenge_id = ? LIMIT 1",
                (challenge_id,),
            ).fetchone()
    return _challenge_record(row)


def mark_attempt(
    challenge_id: str,
    *,
    workspace_id: str = "",
    success: bool,
    lock: bool = False,
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    challenge = get_challenge(challenge_id, workspace_id=workspace_id)
    if not challenge:
        return {}
    now = _now()
    next_attempts = int(challenge.get("attempts") or 0) + 1
    if success:
        next_status = "verified"
        verified_at = now
        cancelled_at = int(challenge.get("cancelled_at") or 0)
        event_type = "login_challenge.verified"
    else:
        next_status = "locked" if lock else "pending"
        verified_at = int(challenge.get("verified_at") or 0)
        cancelled_at = int(challenge.get("cancelled_at") or 0)
        event_type = "login_challenge.locked" if lock else "login_challenge.failed_attempt"
    with _connection() as conn:
        conn.execute(
            """
            UPDATE identity_login_challenges
            SET attempts = ?, status = ?, verified_at = ?, cancelled_at = ?, updated_at = ?
            WHERE challenge_id = ? AND workspace_id = ?;
            """,
            (
                next_attempts,
                next_status,
                verified_at,
                cancelled_at,
                now,
                challenge["challenge_id"],
                challenge["workspace_id"],
            ),
        )
        _record_audit(
            conn,
            workspace_id=challenge["workspace_id"],
            challenge_id=challenge["challenge_id"],
            event_type=event_type,
            status=next_status,
            payload={"attempts": next_attempts, "max_attempts": challenge.get("max_attempts", 5)},
            request_meta=request_meta,
        )
        conn.commit()
    return get_challenge(challenge["challenge_id"], workspace_id=challenge["workspace_id"])


def mark_status(
    challenge_id: str,
    *,
    workspace_id: str = "",
    status: str,
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    challenge = get_challenge(challenge_id, workspace_id=workspace_id)
    if not challenge:
        return {}
    now = _now()
    status = _clean_id(status, 40) or challenge.get("status") or "pending"
    verified_at = int(challenge.get("verified_at") or 0)
    cancelled_at = int(challenge.get("cancelled_at") or 0)
    if status == "expired" and not verified_at:
        verified_at = 0
    if status == "cancelled":
        cancelled_at = now
    with _connection() as conn:
        conn.execute(
            """
            UPDATE identity_login_challenges
            SET status = ?, verified_at = ?, cancelled_at = ?, updated_at = ?
            WHERE challenge_id = ? AND workspace_id = ?;
            """,
            (
                status,
                verified_at,
                cancelled_at,
                now,
                challenge["challenge_id"],
                challenge["workspace_id"],
            ),
        )
        _record_audit(
            conn,
            workspace_id=challenge["workspace_id"],
            challenge_id=challenge["challenge_id"],
            event_type=f"login_challenge.{status}",
            status=status,
            payload={},
            request_meta=request_meta,
        )
        conn.commit()
    return get_challenge(challenge["challenge_id"], workspace_id=challenge["workspace_id"])


def list_challenges(workspace_id: str = "laijuzhu", limit: int = 100) -> List[Dict[str, Any]]:
    workspace_id = _clean_id(workspace_id, 96) or "laijuzhu"
    limit = max(1, min(500, int(limit or 100)))
    with _connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM identity_login_challenges
            WHERE workspace_id = ?
            ORDER BY updated_at DESC, created_at DESC
            LIMIT ?;
            """,
            (workspace_id, limit),
        ).fetchall()
    return [_challenge_record(row) for row in rows]


def public_challenge(challenge: Dict[str, Any]) -> Dict[str, Any]:
    record = _challenge_record(challenge)
    if not record:
        return {}
    return {
        "challenge_id": record["challenge_id"],
        "workspace_id": record["workspace_id"],
        "person_id": record["person_id"],
        "household_id": record["household_id"],
        "case_id": record["case_id"],
        "channel": record["channel"],
        "purpose": record["purpose"],
        "provider": record["provider"],
        "subject_hint": record["subject_hint"],
        "delivery_target_hint": record["delivery_target_hint"],
        "actor_id": record["actor_id"],
        "role": record["role"],
        "scopes": record["scopes"],
        "attempts": record["attempts"],
        "max_attempts": record["max_attempts"],
        "status": record["status"],
        "metadata": record["metadata"],
        "issued_at": record["issued_at"],
        "expires_at": record["expires_at"],
        "verified_at": record["verified_at"],
        "cancelled_at": record["cancelled_at"],
        "raw_secret_echoed": False,
    }


def debug_summary() -> Dict[str, Any]:
    with _connection() as conn:
        challenge_count = conn.execute("SELECT COUNT(*) FROM identity_login_challenges").fetchone()[0]
        audit_count = conn.execute("SELECT COUNT(*) FROM identity_login_audit_events").fetchone()[0]
    return {
        "store": "sqlite",
        "sqlite_path": str(sqlite_path()),
        "tables": {
            "identity_login_challenges": int(challenge_count),
            "identity_login_audit_events": int(audit_count),
        },
    }
