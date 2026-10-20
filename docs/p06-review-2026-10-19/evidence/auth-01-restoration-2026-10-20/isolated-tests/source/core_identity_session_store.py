from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List


def data_dir() -> Path:
    configured = os.getenv("LIVEUIN_CORE_IDENTITY_SESSION_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[1] / "runtime" / "core-identity-session-data"


def sqlite_path() -> Path:
    configured = os.getenv("LIVEUIN_CORE_IDENTITY_SESSION_SQLITE_PATH", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return data_dir() / "liveuin-core-identity-session.sqlite3"


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
            if normalized in {"api_key", "raw_api_key", "session_id", "raw_session_id", "authorization", "bearer", "token", "secret"}:
                continue
            cleaned[str(key)] = _redact(item)
        return cleaned
    if isinstance(value, list):
        return [_redact(item) for item in value[:100]]
    if isinstance(value, str) and value.startswith(("http://", "https://", "s3://")):
        return "[redacted_ref]"
    return value


def _now() -> int:
    return int(time.time())


def _clean_id(value: Any, max_length: int = 120) -> str:
    return "".join(ch for ch in str(value or "").strip() if ch.isalnum() or ch in "_.:-")[:max_length]


def _clean_role(value: Any) -> str:
    return _clean_id(str(value or "").strip().lower().replace(" ", "_"), 80)


def _scopes(value: Any) -> List[str]:
    scopes = value if isinstance(value, list) else [value] if isinstance(value, str) and value.strip() else []
    cleaned: List[str] = []
    for item in scopes:
        scope = _clean_id(str(item or "").strip(), 120)
        if scope and scope not in cleaned:
            cleaned.append(scope)
    return cleaned[:80]


def open_connection() -> sqlite3.Connection:
    target = sqlite_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    ensure_schema(conn)
    return conn


@contextmanager
def connection() -> Iterator[sqlite3.Connection]:
    conn = open_connection()
    try:
        yield conn
    finally:
        conn.close()


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS identity_session_credentials (
            session_id_hash TEXT PRIMARY KEY,
            session_id_hint TEXT NOT NULL DEFAULT '',
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            actor_id TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT '',
            scopes_json TEXT NOT NULL DEFAULT '[]',
            auth_method TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            issued_at INTEGER NOT NULL DEFAULT 0,
            expires_at INTEGER NOT NULL DEFAULT 0,
            revoked_at INTEGER NOT NULL DEFAULT 0,
            revoked_reason TEXT NOT NULL DEFAULT '',
            rotated_to_hash TEXT NOT NULL DEFAULT '',
            policy_version TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_identity_session_workspace
            ON identity_session_credentials(workspace_id, status, expires_at);

        CREATE TABLE IF NOT EXISTS identity_api_key_credentials (
            api_key_hash TEXT PRIMARY KEY,
            api_key_hint TEXT NOT NULL DEFAULT '',
            key_id TEXT NOT NULL UNIQUE,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            actor_id TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT '',
            scopes_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'active',
            issued_at INTEGER NOT NULL DEFAULT 0,
            expires_at INTEGER NOT NULL DEFAULT 0,
            revoked_at INTEGER NOT NULL DEFAULT 0,
            revoked_reason TEXT NOT NULL DEFAULT '',
            rotated_to_hash TEXT NOT NULL DEFAULT '',
            rotated_from_hash TEXT NOT NULL DEFAULT '',
            policy_version TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_identity_api_key_workspace
            ON identity_api_key_credentials(workspace_id, status, expires_at);

        CREATE TABLE IF NOT EXISTS identity_credential_audit_events (
            event_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            credential_kind TEXT NOT NULL DEFAULT '',
            credential_hash TEXT NOT NULL DEFAULT '',
            key_id TEXT NOT NULL DEFAULT '',
            actor_id TEXT NOT NULL DEFAULT '',
            event_type TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL DEFAULT '{}',
            request_meta_json TEXT NOT NULL DEFAULT '{}',
            recorded_at INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    _ensure_legacy_columns(
        conn,
        "identity_session_credentials",
        {
            "session_id_hint": "TEXT NOT NULL DEFAULT ''",
            "workspace_id": "TEXT NOT NULL DEFAULT 'laijuzhu'",
            "actor_id": "TEXT NOT NULL DEFAULT ''",
            "role": "TEXT NOT NULL DEFAULT ''",
            "scopes_json": "TEXT NOT NULL DEFAULT '[]'",
            "auth_method": "TEXT NOT NULL DEFAULT ''",
            "status": "TEXT NOT NULL DEFAULT 'active'",
            "issued_at": "INTEGER NOT NULL DEFAULT 0",
            "expires_at": "INTEGER NOT NULL DEFAULT 0",
            "revoked_at": "INTEGER NOT NULL DEFAULT 0",
            "revoked_reason": "TEXT NOT NULL DEFAULT ''",
            "rotated_to_hash": "TEXT NOT NULL DEFAULT ''",
            "policy_version": "TEXT NOT NULL DEFAULT ''",
            "metadata_json": "TEXT NOT NULL DEFAULT '{}'",
            "created_at": "INTEGER NOT NULL DEFAULT 0",
            "updated_at": "INTEGER NOT NULL DEFAULT 0",
        },
    )
    _ensure_legacy_columns(
        conn,
        "identity_api_key_credentials",
        {
            "api_key_hint": "TEXT NOT NULL DEFAULT ''",
            "key_id": "TEXT NOT NULL DEFAULT ''",
            "workspace_id": "TEXT NOT NULL DEFAULT 'laijuzhu'",
            "actor_id": "TEXT NOT NULL DEFAULT ''",
            "role": "TEXT NOT NULL DEFAULT ''",
            "scopes_json": "TEXT NOT NULL DEFAULT '[]'",
            "status": "TEXT NOT NULL DEFAULT 'active'",
            "issued_at": "INTEGER NOT NULL DEFAULT 0",
            "expires_at": "INTEGER NOT NULL DEFAULT 0",
            "revoked_at": "INTEGER NOT NULL DEFAULT 0",
            "revoked_reason": "TEXT NOT NULL DEFAULT ''",
            "rotated_to_hash": "TEXT NOT NULL DEFAULT ''",
            "rotated_from_hash": "TEXT NOT NULL DEFAULT ''",
            "policy_version": "TEXT NOT NULL DEFAULT ''",
            "metadata_json": "TEXT NOT NULL DEFAULT '{}'",
            "created_at": "INTEGER NOT NULL DEFAULT 0",
            "updated_at": "INTEGER NOT NULL DEFAULT 0",
        },
    )
    _ensure_legacy_columns(
        conn,
        "identity_credential_audit_events",
        {
            "key_id": "TEXT NOT NULL DEFAULT ''",
            "actor_id": "TEXT NOT NULL DEFAULT ''",
            "event_type": "TEXT NOT NULL DEFAULT ''",
            "status": "TEXT NOT NULL DEFAULT ''",
            "payload_json": "TEXT NOT NULL DEFAULT '{}'",
            "request_meta_json": "TEXT NOT NULL DEFAULT '{}'",
            "recorded_at": "INTEGER NOT NULL DEFAULT 0",
            "created_at": "INTEGER NOT NULL DEFAULT 0",
        },
    )
    conn.commit()


def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    return {
        str(row[1])
        for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        if len(row) > 1
    }


def _ensure_legacy_columns(
    conn: sqlite3.Connection,
    table_name: str,
    columns: Dict[str, str],
) -> None:
    existing = _table_columns(conn, table_name)
    for column_name, definition in columns.items():
        if column_name in existing:
            continue
        conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def _row_json(row: sqlite3.Row | Dict[str, Any], key: str, fallback: Any) -> Any:
    return decode_json(dict(row).get(key), fallback)


def _session_record(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}
    data = dict(row)
    return {
        "credential_kind": "liveuin_session",
        "session_id_hash": str(data.get("session_id_hash") or ""),
        "session_id_hint": str(data.get("session_id_hint") or ""),
        "workspace_id": str(data.get("workspace_id") or "laijuzhu"),
        "actor_id": str(data.get("actor_id") or ""),
        "role": str(data.get("role") or ""),
        "scopes": _row_json(row, "scopes_json", []),
        "auth_method": str(data.get("auth_method") or ""),
        "status": str(data.get("status") or "active"),
        "issued_at": int(data.get("issued_at") or 0),
        "expires_at": int(data.get("expires_at") or 0),
        "revoked_at": int(data.get("revoked_at") or 0),
        "revoked_reason": str(data.get("revoked_reason") or ""),
        "rotated_to_hash": str(data.get("rotated_to_hash") or ""),
        "policy_version": str(data.get("policy_version") or ""),
        "metadata": _row_json(row, "metadata_json", {}),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
    }


def _api_key_record(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}
    data = dict(row)
    return {
        "credential_kind": "liveuin_api_key",
        "api_key_hash": str(data.get("api_key_hash") or ""),
        "api_key_hint": str(data.get("api_key_hint") or ""),
        "key_id": str(data.get("key_id") or ""),
        "workspace_id": str(data.get("workspace_id") or "laijuzhu"),
        "actor_id": str(data.get("actor_id") or ""),
        "role": str(data.get("role") or ""),
        "scopes": _row_json(row, "scopes_json", []),
        "status": str(data.get("status") or "active"),
        "issued_at": int(data.get("issued_at") or 0),
        "expires_at": int(data.get("expires_at") or 0),
        "revoked_at": int(data.get("revoked_at") or 0),
        "revoked_reason": str(data.get("revoked_reason") or ""),
        "rotated_to_hash": str(data.get("rotated_to_hash") or ""),
        "rotated_from_hash": str(data.get("rotated_from_hash") or ""),
        "policy_version": str(data.get("policy_version") or ""),
        "metadata": _row_json(row, "metadata_json", {}),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
    }


def _record_audit(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    credential_kind: str,
    credential_hash: str,
    key_id: str,
    actor_id: str,
    event_type: str,
    status: str,
    payload: Dict[str, Any] | None = None,
    request_meta: Dict[str, str] | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO identity_credential_audit_events (
            event_id, workspace_id, credential_kind, credential_hash, key_id, actor_id,
            event_type, status, payload_json, request_meta_json, recorded_at, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            "cred_evt_" + hashlib.sha1(f"{credential_kind}:{credential_hash}:{event_type}:{time.time_ns()}".encode("utf-8")).hexdigest()[:20],
            workspace_id,
            credential_kind,
            credential_hash,
            key_id,
            actor_id,
            event_type,
            status,
            encode_json(_redact(payload or {})),
            encode_json(_redact(request_meta or {})),
            _now(),
            _now(),
        ),
    )


def upsert_session(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    now = _now()
    session_id = str(payload.get("session_id") or "").strip()
    session_id_hash = str(payload.get("session_id_hash") or "").strip() or hash_secret(session_id)
    workspace_id = _clean_id(payload.get("workspace_id") or "laijuzhu", 96) or "laijuzhu"
    record = {
        "session_id_hash": session_id_hash,
        "session_id_hint": _hint(session_id or payload.get("session_id_hint")),
        "workspace_id": workspace_id,
        "actor_id": _clean_id(payload.get("actor_id"), 120),
        "role": _clean_role(payload.get("role")),
        "scopes": _scopes(payload.get("scopes")),
        "auth_method": _clean_id(payload.get("auth_method"), 80),
        "status": _clean_id(payload.get("status") or "active", 40) or "active",
        "issued_at": int(payload.get("issued_at") or now),
        "expires_at": int(payload.get("expires_at") or 0),
        "revoked_at": int(payload.get("revoked_at") or 0),
        "revoked_reason": str(payload.get("revoked_reason") or ""),
        "rotated_to_hash": str(payload.get("rotated_to_hash") or ""),
        "policy_version": _clean_id(payload.get("policy_version"), 80),
        "metadata": _redact(payload.get("metadata") or {}),
        "created_at": int(payload.get("created_at") or now),
        "updated_at": now,
    }
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO identity_session_credentials (
                session_id_hash, session_id_hint, workspace_id, actor_id, role, scopes_json,
                auth_method, status, issued_at, expires_at, revoked_at, revoked_reason,
                rotated_to_hash, policy_version, metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id_hash) DO UPDATE SET
                session_id_hint = excluded.session_id_hint,
                workspace_id = excluded.workspace_id,
                actor_id = excluded.actor_id,
                role = excluded.role,
                scopes_json = excluded.scopes_json,
                auth_method = excluded.auth_method,
                status = excluded.status,
                issued_at = excluded.issued_at,
                expires_at = excluded.expires_at,
                revoked_at = excluded.revoked_at,
                revoked_reason = excluded.revoked_reason,
                rotated_to_hash = excluded.rotated_to_hash,
                policy_version = excluded.policy_version,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at;
            """,
            (
                record["session_id_hash"],
                record["session_id_hint"],
                record["workspace_id"],
                record["actor_id"],
                record["role"],
                encode_json(record["scopes"]),
                record["auth_method"],
                record["status"],
                record["issued_at"],
                record["expires_at"],
                record["revoked_at"],
                record["revoked_reason"],
                record["rotated_to_hash"],
                record["policy_version"],
                encode_json(record["metadata"]),
                record["created_at"],
                record["updated_at"],
            ),
        )
        _record_audit(
            conn,
            workspace_id=workspace_id,
            credential_kind="liveuin_session",
            credential_hash=record["session_id_hash"],
            key_id="",
            actor_id=record["actor_id"],
            event_type="session.upserted",
            status=record["status"],
            payload={"auth_method": record["auth_method"]},
            request_meta=request_meta,
        )
        conn.commit()
    return list_sessions(workspace_id=workspace_id, limit=1, session_id_hash=session_id_hash)[0]


def validate_session_hash(session_id_hash: str, workspace_id: str = "") -> Dict[str, Any]:
    session_id_hash = str(session_id_hash or "").strip()
    if not session_id_hash:
        return {"found": False, "active": False, "validation": "session_store_missing", "record": {}}
    with connection() as conn:
        if workspace_id:
            row = conn.execute(
                "SELECT * FROM identity_session_credentials WHERE session_id_hash = ? AND workspace_id = ? LIMIT 1",
                (session_id_hash, workspace_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM identity_session_credentials WHERE session_id_hash = ? LIMIT 1",
                (session_id_hash,),
            ).fetchone()
    record = _session_record(row)
    if not record:
        return {"found": False, "active": False, "validation": "session_store_missing", "record": {}}
    if record["status"] == "revoked":
        return {"found": True, "active": False, "validation": "session_revoked", "record": record}
    if record["status"] == "rotated":
        return {"found": True, "active": False, "validation": "session_rotated", "record": record}
    if record["status"] != "active":
        return {"found": True, "active": False, "validation": "session_inactive", "record": record}
    if record["expires_at"] and record["expires_at"] <= _now():
        return {"found": True, "active": False, "validation": "session_expired", "record": record}
    return {"found": True, "active": True, "validation": "session_store_active", "record": record}


def list_sessions(
    workspace_id: str = "laijuzhu",
    limit: int = 100,
    session_id_hash: str = "",
    before_updated_at: int = 0,
    before_session_id_hash: str = "",
) -> List[Dict[str, Any]]:
    workspace_id = _clean_id(workspace_id, 96) or "laijuzhu"
    limit = max(1, min(500, int(limit or 100)))
    clauses = ["workspace_id = ?"]
    params: List[Any] = [workspace_id]
    if session_id_hash:
        clauses.append("session_id_hash = ?")
        params.append(session_id_hash)
    if before_updated_at:
        clauses.append("(updated_at < ? OR (updated_at = ? AND session_id_hash < ?))")
        params.extend((int(before_updated_at), int(before_updated_at), str(before_session_id_hash or "")))
    params.append(limit)
    with connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM identity_session_credentials
            WHERE {" AND ".join(clauses)}
            ORDER BY updated_at DESC, session_id_hash DESC
            LIMIT ?;
            """,
            tuple(params),
        ).fetchall()
    return [_session_record(row) for row in rows]


def revoke_session(session_hash: str, workspace_id: str = "", reason: str = "", request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    session_hash = str(session_hash or "").strip()
    if not session_hash:
        return {}
    now = _now()
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM identity_session_credentials WHERE session_id_hash = ? LIMIT 1",
            (session_hash,),
        ).fetchone()
        record = _session_record(row)
        if not record or (workspace_id and record.get("workspace_id") != workspace_id):
            return {}
        conn.execute(
            """
            UPDATE identity_session_credentials
            SET status = 'revoked', revoked_at = ?, revoked_reason = ?, updated_at = ?
            WHERE session_id_hash = ?;
            """,
            (now, str(reason or "manual_revocation"), now, session_hash),
        )
        _record_audit(
            conn,
            workspace_id=record["workspace_id"],
            credential_kind="liveuin_session",
            credential_hash=session_hash,
            key_id="",
            actor_id=record.get("actor_id", ""),
            event_type="session.revoked",
            status="revoked",
            payload={"reason": reason},
            request_meta=request_meta,
        )
        conn.commit()
    return list_sessions(workspace_id=record["workspace_id"], limit=1, session_id_hash=session_hash)[0]


def upsert_api_key(payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    now = _now()
    raw_api_key = str(payload.get("api_key") or "").strip()
    api_key_hash = str(payload.get("api_key_hash") or "").strip() or hash_secret(raw_api_key)
    workspace_id = _clean_id(payload.get("workspace_id") or "laijuzhu", 96) or "laijuzhu"
    key_id = _clean_id(payload.get("key_id"), 120)
    record = {
        "api_key_hash": api_key_hash,
        "api_key_hint": _hint(raw_api_key or payload.get("api_key_hint")),
        "key_id": key_id or ("key_" + hashlib.sha1(f"{api_key_hash}:{now}".encode("utf-8")).hexdigest()[:16]),
        "workspace_id": workspace_id,
        "actor_id": _clean_id(payload.get("actor_id"), 120),
        "role": _clean_role(payload.get("role")),
        "scopes": _scopes(payload.get("scopes")),
        "status": _clean_id(payload.get("status") or "active", 40) or "active",
        "issued_at": int(payload.get("issued_at") or now),
        "expires_at": int(payload.get("expires_at") or 0),
        "revoked_at": int(payload.get("revoked_at") or 0),
        "revoked_reason": str(payload.get("revoked_reason") or ""),
        "rotated_to_hash": str(payload.get("rotated_to_hash") or ""),
        "rotated_from_hash": str(payload.get("rotated_from_hash") or ""),
        "policy_version": _clean_id(payload.get("policy_version"), 80),
        "metadata": _redact(payload.get("metadata") or {}),
        "created_at": int(payload.get("created_at") or now),
        "updated_at": now,
    }
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO identity_api_key_credentials (
                api_key_hash, api_key_hint, key_id, workspace_id, actor_id, role, scopes_json,
                status, issued_at, expires_at, revoked_at, revoked_reason, rotated_to_hash,
                rotated_from_hash, policy_version, metadata_json, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(api_key_hash) DO UPDATE SET
                api_key_hint = excluded.api_key_hint,
                key_id = excluded.key_id,
                workspace_id = excluded.workspace_id,
                actor_id = excluded.actor_id,
                role = excluded.role,
                scopes_json = excluded.scopes_json,
                status = excluded.status,
                issued_at = excluded.issued_at,
                expires_at = excluded.expires_at,
                revoked_at = excluded.revoked_at,
                revoked_reason = excluded.revoked_reason,
                rotated_to_hash = excluded.rotated_to_hash,
                rotated_from_hash = excluded.rotated_from_hash,
                policy_version = excluded.policy_version,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at;
            """,
            (
                record["api_key_hash"],
                record["api_key_hint"],
                record["key_id"],
                record["workspace_id"],
                record["actor_id"],
                record["role"],
                encode_json(record["scopes"]),
                record["status"],
                record["issued_at"],
                record["expires_at"],
                record["revoked_at"],
                record["revoked_reason"],
                record["rotated_to_hash"],
                record["rotated_from_hash"],
                record["policy_version"],
                encode_json(record["metadata"]),
                record["created_at"],
                record["updated_at"],
            ),
        )
        _record_audit(
            conn,
            workspace_id=workspace_id,
            credential_kind="liveuin_api_key",
            credential_hash=record["api_key_hash"],
            key_id=record["key_id"],
            actor_id=record["actor_id"],
            event_type="api_key.upserted",
            status=record["status"],
            payload={"key_id": record["key_id"]},
            request_meta=request_meta,
        )
        conn.commit()
    return list_api_keys(workspace_id=workspace_id, limit=1, api_key_hash=api_key_hash)[0]


def validate_api_key_hash(api_key_hash: str, workspace_id: str = "") -> Dict[str, Any]:
    api_key_hash = str(api_key_hash or "").strip()
    if not api_key_hash:
        return {"found": False, "active": False, "validation": "api_key_missing", "record": {}}
    with connection() as conn:
        if workspace_id:
            row = conn.execute(
                "SELECT * FROM identity_api_key_credentials WHERE api_key_hash = ? AND workspace_id = ? LIMIT 1",
                (api_key_hash, workspace_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM identity_api_key_credentials WHERE api_key_hash = ? LIMIT 1",
                (api_key_hash,),
            ).fetchone()
    record = _api_key_record(row)
    if not record:
        return {"found": False, "active": False, "validation": "api_key_missing", "record": {}}
    if record["status"] == "revoked":
        return {"found": True, "active": False, "validation": "api_key_revoked", "record": record}
    if record["status"] == "rotated":
        return {"found": True, "active": False, "validation": "api_key_rotated", "record": record}
    if record["status"] != "active":
        return {"found": True, "active": False, "validation": "api_key_inactive", "record": record}
    if record["expires_at"] and record["expires_at"] <= _now():
        return {"found": True, "active": False, "validation": "api_key_expired", "record": record}
    return {"found": True, "active": True, "validation": "api_key_store_verified", "record": record}


def list_api_keys(workspace_id: str = "laijuzhu", limit: int = 100, api_key_hash: str = "") -> List[Dict[str, Any]]:
    workspace_id = _clean_id(workspace_id, 96) or "laijuzhu"
    limit = max(1, min(500, int(limit or 100)))
    clauses = ["workspace_id = ?"]
    params: List[Any] = [workspace_id]
    if api_key_hash:
        clauses.append("api_key_hash = ?")
        params.append(api_key_hash)
    params.append(limit)
    with connection() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM identity_api_key_credentials
            WHERE {" AND ".join(clauses)}
            ORDER BY updated_at DESC
            LIMIT ?;
            """,
            tuple(params),
        ).fetchall()
    return [_api_key_record(row) for row in rows]


def revoke_api_key(
    api_key_hash: str,
    *,
    key_id: str = "",
    workspace_id: str = "",
    reason: str = "",
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    api_key_hash = str(api_key_hash or "").strip()
    key_id = _clean_id(key_id, 120)
    now = _now()
    with connection() as conn:
        if api_key_hash:
            row = conn.execute(
                "SELECT * FROM identity_api_key_credentials WHERE api_key_hash = ? LIMIT 1",
                (api_key_hash,),
            ).fetchone()
        elif key_id:
            row = conn.execute(
                "SELECT * FROM identity_api_key_credentials WHERE key_id = ? LIMIT 1",
                (key_id,),
            ).fetchone()
        else:
            return {}
        record = _api_key_record(row)
        if not record or (workspace_id and record.get("workspace_id") != workspace_id):
            return {}
        conn.execute(
            """
            UPDATE identity_api_key_credentials
            SET status = 'revoked', revoked_at = ?, revoked_reason = ?, updated_at = ?
            WHERE api_key_hash = ?;
            """,
            (now, str(reason or "manual_revocation"), now, record["api_key_hash"]),
        )
        _record_audit(
            conn,
            workspace_id=record["workspace_id"],
            credential_kind="liveuin_api_key",
            credential_hash=record["api_key_hash"],
            key_id=record["key_id"],
            actor_id=record.get("actor_id", ""),
            event_type="api_key.revoked",
            status="revoked",
            payload={"reason": reason, "key_id": record["key_id"]},
            request_meta=request_meta,
        )
        conn.commit()
    return list_api_keys(workspace_id=record["workspace_id"], limit=1, api_key_hash=record["api_key_hash"])[0]


def rotate_api_key(api_key_hash: str, payload: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    api_key_hash = str(api_key_hash or "").strip()
    if not api_key_hash:
        return {"ok": False, "detail": "api_key_or_key_id_required"}
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM identity_api_key_credentials WHERE api_key_hash = ? LIMIT 1",
            (api_key_hash,),
        ).fetchone()
        existing = _api_key_record(row)
        if not existing:
            return {"ok": False, "detail": "identity_api_key_not_found"}
        now = _now()
        new_record = upsert_api_key(
            {
                "api_key": payload.get("api_key"),
                "key_id": payload.get("key_id"),
                "workspace_id": existing["workspace_id"],
                "actor_id": existing["actor_id"],
                "role": existing["role"],
                "scopes": existing["scopes"],
                "expires_at": int(payload.get("expires_at") or existing.get("expires_at") or 0),
                "policy_version": payload.get("policy_version") or existing.get("policy_version"),
                "metadata": {
                    **existing.get("metadata", {}),
                    **_redact(payload.get("metadata") or {}),
                },
                "rotated_from_hash": existing["api_key_hash"],
            },
            request_meta,
        )
        conn.execute(
            """
            UPDATE identity_api_key_credentials
            SET status = 'rotated', rotated_to_hash = ?, revoked_reason = ?, updated_at = ?
            WHERE api_key_hash = ?;
            """,
            (
                new_record["api_key_hash"],
                str(_redact(payload.get("metadata") or {}).get("rotation_reason") or "manual_rotation"),
                now,
                existing["api_key_hash"],
            ),
        )
        _record_audit(
            conn,
            workspace_id=existing["workspace_id"],
            credential_kind="liveuin_api_key",
            credential_hash=existing["api_key_hash"],
            key_id=existing["key_id"],
            actor_id=existing.get("actor_id", ""),
            event_type="api_key.rotated",
            status="rotated",
            payload={"rotated_to_hash": new_record["api_key_hash"], "new_key_id": new_record["key_id"]},
            request_meta=request_meta,
        )
        conn.commit()
    rotated_from = list_api_keys(workspace_id=existing["workspace_id"], limit=1, api_key_hash=existing["api_key_hash"])[0]
    return {"ok": True, "rotated_from": rotated_from, "api_key": new_record}


def debug_summary() -> Dict[str, Any]:
    with connection() as conn:
        session_count = conn.execute("SELECT COUNT(*) FROM identity_session_credentials").fetchone()[0]
        api_key_count = conn.execute("SELECT COUNT(*) FROM identity_api_key_credentials").fetchone()[0]
        audit_event_count = conn.execute("SELECT COUNT(*) FROM identity_credential_audit_events").fetchone()[0]
    return {
        "store": "sqlite",
        "sqlite_path": str(sqlite_path()),
        "tables": {
            "identity_session_credentials": int(session_count),
            "identity_api_key_credentials": int(api_key_count),
            "identity_credential_audit_events": int(audit_event_count),
        },
    }
