from __future__ import annotations

import importlib
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List


REPLAY_STORE_DRIVER_ENV = "LIVEUIN_ADAPTER_REPLAY_STORE_DRIVER"
REPLAY_STORE_DSN_ENV = "LIVEUIN_ADAPTER_REPLAY_STORE_DSN"
REPLAY_REQUIRE_SHARED_ENV = "LIVEUIN_ADAPTER_REPLAY_REQUIRE_SHARED_STORE"
SUPPORTED_REPLAY_STORE_DRIVERS = {"sqlite", "postgres", "postgresql"}

DEFAULT_WORKSPACE_ID = "laijuzhu"

_REPLAY_PG_MODULE: Any | None = None
_REPLAY_PG_ATTEMPTED = False
_POSTGRES_DSN_ENV_NAMES = (
    "LIVEUIN_ADAPTER_REPLAY_POSTGRES_DSN",
    "LIVEUIN_ADAPTER_REPLAY_STORE_DSN",
    "LIVEUIN_CORE_ACCESS_REPLAY_POSTGRES_DSN",
    "LIVEUIN_CORE_ACCESS_POSTGRES_DSN",
    "DATABASE_URL",
)


def _replay_pg_module() -> Any | None:
    global _REPLAY_PG_MODULE, _REPLAY_PG_ATTEMPTED
    if _REPLAY_PG_ATTEMPTED:
        return _REPLAY_PG_MODULE
    _REPLAY_PG_ATTEMPTED = True
    for name in ("deploy.core_adapter_replay_postgres_store", "core_adapter_replay_postgres_store"):
        try:
            _REPLAY_PG_MODULE = importlib.import_module(name)
            return _REPLAY_PG_MODULE
        except Exception:
            continue
    _REPLAY_PG_MODULE = None
    return None


def _replay_pg_dsn_configured() -> bool:
    return any(str(os.getenv(name, "")).strip() for name in _POSTGRES_DSN_ENV_NAMES)


def data_dir() -> Path:
    configured = os.getenv("LIVEUIN_CORE_ACCESS_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()
    configured_path = os.getenv("LIVEUIN_CORE_ACCESS_SQLITE_PATH", "").strip()
    if configured_path:
        return Path(configured_path).expanduser().parent
    return Path.cwd() / "data"


def sqlite_path() -> Path:
    configured = os.getenv("LIVEUIN_CORE_ACCESS_SQLITE_PATH", "").strip()
    if configured:
        return Path(configured).expanduser()
    root = data_dir()
    current = root / "core-access.sqlite3"
    legacy = root / "liveuin-core-access.sqlite3"
    if legacy.exists() and not current.exists():
        return legacy
    return current


def replay_store_driver() -> str:
    configured = os.getenv(REPLAY_STORE_DRIVER_ENV, "").strip().lower()
    if configured in SUPPORTED_REPLAY_STORE_DRIVERS:
        return configured
    if _replay_pg_dsn_configured():
        return "postgres"
    return "sqlite"


def replay_postgres_active() -> bool:
    return replay_store_driver() in {"postgres", "postgresql"}


def _replay_postgres_error() -> str:
    if not _replay_pg_dsn_configured():
        return "replay_postgres_dsn_missing"
    replay_pg_store = _replay_pg_module()
    if replay_pg_store is None:
        return "replay_postgres_store_not_loaded"
    if not replay_pg_store.dsn():
        return "replay_postgres_dsn_missing"
    if not replay_pg_store.driver_available():
        return "replay_postgres_driver_missing"
    return ""


def _replay_postgres_summary() -> Dict[str, Any]:
    dsn_configured = _replay_pg_dsn_configured()
    replay_pg_store = _replay_pg_module() if dsn_configured else None
    error = _replay_postgres_error()
    return {
        "store_driver": replay_store_driver(),
        "shared_replay_store": replay_postgres_active(),
        "dsn_configured": dsn_configured,
        "driver_available": bool(replay_pg_store is not None and replay_pg_store.driver_available()),
        "error": error,
        "claim_supported": replay_postgres_active() and not error,
    }


def _clean_driver(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if text in SUPPORTED_REPLAY_STORE_DRIVERS else "sqlite"


def _truthy_env(name: str) -> bool:
    return str(os.getenv(name, "")).strip().lower() in {"1", "true", "yes", "on"}


def replay_store_status() -> Dict[str, Any]:
    summary = _replay_postgres_summary()
    return {
        "store_driver": replay_store_driver(),
        "shared_replay_store": replay_postgres_active(),
        "postgres_ready": bool(summary.get("claim_supported")),
        "postgres_dsn_configured": bool(summary.get("dsn_configured")),
        "postgres_driver_available": bool(summary.get("driver_available")),
        "require_shared_store": _truthy_env(REPLAY_REQUIRE_SHARED_ENV),
        "sqlite_path": str(sqlite_path()),
        "error": summary.get("error", ""),
    }


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
    return fallback if decoded is None else decoded


def connection() -> sqlite3.Connection:
    path = sqlite_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _migrate_legacy_schema(conn: sqlite3.Connection) -> None:
    migrations = {
        "access_source_assessments": {
            "controls": ("TEXT NOT NULL DEFAULT '{}'", "controls_json"),
            "context": ("TEXT NOT NULL DEFAULT '{}'", "context_json"),
            "request_meta": ("TEXT NOT NULL DEFAULT '{}'", "request_meta_json"),
            "created_at": ("INTEGER NOT NULL DEFAULT 0", "assessed_at"),
        },
        "access_idempotency_claims": {
            "request_payload": ("TEXT NOT NULL DEFAULT '{}'", "request_payload_json"),
            "response_ref": ("TEXT NOT NULL DEFAULT '{}'", "response_ref_json"),
            "request_meta": ("TEXT NOT NULL DEFAULT '{}'", "request_meta_json"),
        },
        "access_adapter_replay_nonces": {
            "context": ("TEXT NOT NULL DEFAULT '{}'", "context_json"),
            "request_meta": ("TEXT NOT NULL DEFAULT '{}'", "request_meta_json"),
        },
        "access_participant_grants": {
            "conditions": ("TEXT NOT NULL DEFAULT '{}'", "conditions_json"),
            "provenance": ("TEXT NOT NULL DEFAULT '{}'", "provenance_json"),
            "revocation_propagation": ("TEXT NOT NULL DEFAULT '{}'", "revocation_propagation_json"),
            "request_meta": ("TEXT NOT NULL DEFAULT '{}'", "request_meta_json"),
        },
        "access_participant_grant_events": {
            "event_payload": ("TEXT NOT NULL DEFAULT '{}'", "event_payload_json"),
            "request_meta": ("TEXT NOT NULL DEFAULT '{}'", "request_meta_json"),
        },
    }
    for table, additions in migrations.items():
        columns = _table_columns(conn, table)
        if not columns:
            continue
        for column, (definition, legacy_column) in additions.items():
            if column not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                columns.add(column)
            if legacy_column in columns:
                default_value = "0" if "INTEGER" in definition else "'{}'"
                conn.execute(
                    f"UPDATE {table} SET {column} = {legacy_column} "
                    f"WHERE {legacy_column} IS NOT NULL AND {column} = {default_value}"
                )


def ensure_schema() -> None:
    with connection() as conn:
        _migrate_legacy_schema(conn)
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS access_decisions (
                decision_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
                actor_id TEXT NOT NULL DEFAULT '',
                actor_role TEXT NOT NULL DEFAULT '',
                surface TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT '',
                resource_type TEXT NOT NULL DEFAULT '',
                resource_id TEXT NOT NULL DEFAULT '',
                decision TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                required_scopes TEXT NOT NULL DEFAULT '[]',
                provided_scopes TEXT NOT NULL DEFAULT '[]',
                source_family TEXT NOT NULL DEFAULT '',
                source_truth_status TEXT NOT NULL DEFAULT '',
                policy TEXT NOT NULL DEFAULT '{}',
                context TEXT NOT NULL DEFAULT '{}',
                request_meta TEXT NOT NULL DEFAULT '{}',
                created_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_access_decisions_workspace_created
                ON access_decisions(workspace_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS access_source_assessments (
                assessment_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
                source_family TEXT NOT NULL DEFAULT '',
                source_system TEXT NOT NULL DEFAULT '',
                claim_type TEXT NOT NULL DEFAULT '',
                intended_owner TEXT NOT NULL DEFAULT '',
                canonical_owner TEXT NOT NULL DEFAULT '',
                truth_status TEXT NOT NULL DEFAULT '',
                allowed_as_canonical INTEGER NOT NULL DEFAULT 0,
                allowed_as_evidence INTEGER NOT NULL DEFAULT 0,
                reason TEXT NOT NULL DEFAULT '',
                controls TEXT NOT NULL DEFAULT '{}',
                context TEXT NOT NULL DEFAULT '{}',
                request_meta TEXT NOT NULL DEFAULT '{}',
                created_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_access_source_workspace_created
                ON access_source_assessments(workspace_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS access_idempotency_claims (
                claim_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
                idempotency_key TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT '',
                actor_id TEXT NOT NULL DEFAULT '',
                resource_type TEXT NOT NULL DEFAULT '',
                resource_id TEXT NOT NULL DEFAULT '',
                request_hash TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'reserved',
                result_status TEXT NOT NULL DEFAULT '',
                request_payload TEXT NOT NULL DEFAULT '{}',
                response_ref TEXT NOT NULL DEFAULT '{}',
                first_seen_at INTEGER NOT NULL DEFAULT 0,
                last_seen_at INTEGER NOT NULL DEFAULT 0,
                completed_at INTEGER NOT NULL DEFAULT 0,
                request_meta TEXT NOT NULL DEFAULT '{}'
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_access_idempotency_workspace_key
                ON access_idempotency_claims(workspace_id, idempotency_key);

            CREATE INDEX IF NOT EXISTS idx_access_idempotency_workspace_seen
                ON access_idempotency_claims(workspace_id, last_seen_at DESC);

            CREATE TABLE IF NOT EXISTS access_adapter_replay_nonces (
                replay_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
                adapter_id TEXT NOT NULL DEFAULT '',
                source_family TEXT NOT NULL DEFAULT '',
                nonce TEXT NOT NULL DEFAULT '',
                method TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL DEFAULT '',
                payload_hash TEXT NOT NULL DEFAULT '',
                signature_hash TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'accepted',
                context TEXT NOT NULL DEFAULT '{}',
                request_meta TEXT NOT NULL DEFAULT '{}',
                first_seen_at INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_access_adapter_replay_nonce
                ON access_adapter_replay_nonces(workspace_id, adapter_id, nonce);

            CREATE INDEX IF NOT EXISTS idx_access_adapter_replay_workspace_seen
                ON access_adapter_replay_nonces(workspace_id, first_seen_at DESC);

            CREATE TABLE IF NOT EXISTS access_participant_grants (
                grant_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
                case_id TEXT NOT NULL DEFAULT '',
                participant_id TEXT NOT NULL DEFAULT '',
                participant_role TEXT NOT NULL DEFAULT '',
                subject_id TEXT NOT NULL DEFAULT '',
                subject_role TEXT NOT NULL DEFAULT '',
                grant_type TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                consent_state TEXT NOT NULL DEFAULT 'consented',
                allowed_actions TEXT NOT NULL DEFAULT '[]',
                allowed_resources TEXT NOT NULL DEFAULT '[]',
                scope TEXT NOT NULL DEFAULT '',
                source_family TEXT NOT NULL DEFAULT 'liveuin_core',
                issued_by TEXT NOT NULL DEFAULT '',
                revoked_by TEXT NOT NULL DEFAULT '',
                revoked_reason TEXT NOT NULL DEFAULT '',
                conditions TEXT NOT NULL DEFAULT '{}',
                provenance TEXT NOT NULL DEFAULT '{}',
                revocation_propagation TEXT NOT NULL DEFAULT '{}',
                request_meta TEXT NOT NULL DEFAULT '{}',
                created_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER NOT NULL DEFAULT 0,
                revoked_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_access_participant_grants_case_participant
                ON access_participant_grants(workspace_id, case_id, participant_id, status);

            CREATE INDEX IF NOT EXISTS idx_access_participant_grants_subject
                ON access_participant_grants(workspace_id, subject_id, status);

            CREATE TABLE IF NOT EXISTS access_participant_grant_events (
                event_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
                grant_id TEXT NOT NULL DEFAULT '',
                case_id TEXT NOT NULL DEFAULT '',
                participant_id TEXT NOT NULL DEFAULT '',
                event_type TEXT NOT NULL DEFAULT '',
                event_payload TEXT NOT NULL DEFAULT '{}',
                request_meta TEXT NOT NULL DEFAULT '{}',
                created_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_access_participant_grant_events_grant
                ON access_participant_grant_events(workspace_id, grant_id, created_at DESC);
            """
        )
        conn.commit()


def _row_payload(row: Any) -> Dict[str, Any]:
    if not row:
        return {}
    if isinstance(row, sqlite3.Row):
        raw = dict(row)
    elif isinstance(row, dict):
        raw = dict(row)
    else:
        return {}

    decoded = dict(raw)
    for key in ("required_scopes", "provided_scopes", "allowed_actions", "allowed_resources"):
        if key in decoded:
            decoded[key] = decode_json(decoded.get(key), [])
    for key in (
        "policy",
        "context",
        "controls",
        "request_meta",
        "request_payload",
        "response_ref",
        "conditions",
        "provenance",
        "revocation_propagation",
        "event_payload",
    ):
        if key in decoded:
            decoded[key] = decode_json(decoded.get(key), {})
    for key in (
        "allowed_as_canonical",
        "allowed_as_evidence",
    ):
        if key in decoded:
            decoded[key] = bool(decoded.get(key))
    for key in (
        "created_at",
        "first_seen_at",
        "last_seen_at",
        "completed_at",
        "expires_at",
        "updated_at",
        "revoked_at",
    ):
        if key in decoded:
            decoded[key] = int(decoded.get(key) or 0)
    return decoded


def _now(record: Dict[str, Any] | None = None) -> int:
    candidate = 0 if not isinstance(record, dict) else int(record.get("created_at") or record.get("first_seen_at") or 0)
    return candidate or int(time.time())


def _insert_json_columns(record: Dict[str, Any], keys: List[str]) -> Dict[str, Any]:
    payload = dict(record)
    for key in keys:
        payload[key] = encode_json(payload.get(key))
    return payload


def record_decision(record: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    ensure_schema()
    now = _now(record)
    payload = _insert_json_columns(
        {
            **record,
            "request_meta": request_meta or {},
            "created_at": now,
        },
        ["required_scopes", "provided_scopes", "policy", "context", "request_meta"],
    )
    with connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO access_decisions (
                decision_id, workspace_id, actor_id, actor_role, surface, action, resource_type,
                resource_id, decision, reason, required_scopes, provided_scopes, source_family,
                source_truth_status, policy, context, request_meta, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.get("decision_id", ""),
                payload.get("workspace_id", DEFAULT_WORKSPACE_ID),
                payload.get("actor_id", ""),
                payload.get("actor_role", ""),
                payload.get("surface", ""),
                payload.get("action", ""),
                payload.get("resource_type", ""),
                payload.get("resource_id", ""),
                payload.get("decision", ""),
                payload.get("reason", ""),
                payload.get("required_scopes", "[]"),
                payload.get("provided_scopes", "[]"),
                payload.get("source_family", ""),
                payload.get("source_truth_status", ""),
                payload.get("policy", "{}"),
                payload.get("context", "{}"),
                payload.get("request_meta", "{}"),
                payload.get("created_at", now),
            ),
        )
        row = conn.execute("SELECT * FROM access_decisions WHERE decision_id = ?", (payload.get("decision_id", ""),)).fetchone()
    return _row_payload(row)


def get_decision(decision_id: str) -> Dict[str, Any]:
    ensure_schema()
    with connection() as conn:
        row = conn.execute("SELECT * FROM access_decisions WHERE decision_id = ? LIMIT 1", (decision_id,)).fetchone()
    return _row_payload(row)


def list_decisions(
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    actor_id: str = "",
    action: str = "",
    decision: str = "",
    limit: int = 50,
) -> List[Dict[str, Any]]:
    ensure_schema()
    sql = "SELECT * FROM access_decisions WHERE workspace_id = ?"
    params: List[Any] = [workspace_id]
    if actor_id:
        sql += " AND actor_id = ?"
        params.append(actor_id)
    if action:
        sql += " AND action = ?"
        params.append(action)
    if decision:
        sql += " AND decision = ?"
        params.append(decision)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(max(1, int(limit or 50)))
    with connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_payload(row) for row in rows]


def record_source_assessment(record: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    ensure_schema()
    now = _now(record)
    payload = _insert_json_columns(
        {
            **record,
            "request_meta": request_meta or {},
            "created_at": now,
        },
        ["controls", "context", "request_meta"],
    )
    values = {
        "assessment_id": payload.get("assessment_id", ""),
        "workspace_id": payload.get("workspace_id", DEFAULT_WORKSPACE_ID),
        "source_family": payload.get("source_family", ""),
        "source_system": payload.get("source_system", ""),
        "claim_type": payload.get("claim_type", ""),
        "intended_owner": payload.get("intended_owner", ""),
        "canonical_owner": payload.get("canonical_owner", ""),
        "truth_status": payload.get("truth_status", ""),
        "allowed_as_canonical": 1 if payload.get("allowed_as_canonical") else 0,
        "allowed_as_evidence": 1 if payload.get("allowed_as_evidence") else 0,
        "reason": payload.get("reason", ""),
        "controls": payload.get("controls", "{}"),
        "controls_json": payload.get("controls", "{}"),
        "context": payload.get("context", "{}"),
        "context_json": payload.get("context", "{}"),
        "request_meta": payload.get("request_meta", "{}"),
        "request_meta_json": payload.get("request_meta", "{}"),
        "created_at": payload.get("created_at", now),
        "assessed_at": payload.get("created_at", now),
    }
    with connection() as conn:
        table_columns = _table_columns(conn, "access_source_assessments")
        insert_columns = [column for column in values if column in table_columns]
        quoted_columns = ", ".join(f'"{column}"' for column in insert_columns)
        placeholders = ", ".join("?" for _ in insert_columns)
        update_columns = [column for column in insert_columns if column != "assessment_id"]
        updates = ", ".join(f'"{column}" = excluded."{column}"' for column in update_columns)
        conn.execute(
            f"INSERT INTO access_source_assessments ({quoted_columns}) VALUES ({placeholders}) "
            f"ON CONFLICT(assessment_id) DO UPDATE SET {updates}",
            tuple(values[column] for column in insert_columns),
        )
        row = conn.execute(
            "SELECT * FROM access_source_assessments WHERE assessment_id = ?",
            (payload.get("assessment_id", ""),),
        ).fetchone()
    return _row_payload(row)


def get_source_assessment(assessment_id: str) -> Dict[str, Any]:
    ensure_schema()
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM access_source_assessments WHERE assessment_id = ? LIMIT 1",
            (assessment_id,),
        ).fetchone()
    return _row_payload(row)


def list_source_assessments(
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    source_family: str = "",
    truth_status: str = "",
    limit: int = 50,
) -> List[Dict[str, Any]]:
    ensure_schema()
    sql = "SELECT * FROM access_source_assessments WHERE workspace_id = ?"
    params: List[Any] = [workspace_id]
    if source_family:
        sql += " AND source_family = ?"
        params.append(source_family)
    if truth_status:
        sql += " AND truth_status = ?"
        params.append(truth_status)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(max(1, int(limit or 50)))
    with connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_payload(row) for row in rows]


def get_idempotency_claim(idempotency_key: str, workspace_id: str) -> Dict[str, Any]:
    ensure_schema()
    with connection() as conn:
        row = conn.execute(
            """
            SELECT * FROM access_idempotency_claims
            WHERE workspace_id = ? AND idempotency_key = ?
            LIMIT 1
            """,
            (workspace_id, idempotency_key),
        ).fetchone()
    return _row_payload(row)


def claim_idempotency_record(record: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    ensure_schema()
    payload = _insert_json_columns(
        {
            **record,
            "request_meta": request_meta or {},
        },
        ["request_payload", "response_ref", "request_meta"],
    )
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        inserted = conn.execute(
            """
            INSERT INTO access_idempotency_claims (
                claim_id, workspace_id, idempotency_key, action, actor_id, resource_type,
                resource_id, request_hash, status, result_status, request_payload, response_ref,
                first_seen_at, last_seen_at, completed_at, request_meta
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id, idempotency_key) DO NOTHING
            """,
            (
                payload.get("claim_id", ""),
                payload.get("workspace_id", DEFAULT_WORKSPACE_ID),
                payload.get("idempotency_key", ""),
                payload.get("action", ""),
                payload.get("actor_id", ""),
                payload.get("resource_type", ""),
                payload.get("resource_id", ""),
                payload.get("request_hash", ""),
                payload.get("status", "reserved"),
                payload.get("result_status", ""),
                payload.get("request_payload", "{}"),
                payload.get("response_ref", "{}"),
                int(payload.get("first_seen_at") or 0),
                int(payload.get("last_seen_at") or 0),
                int(payload.get("completed_at") or 0),
                payload.get("request_meta", "{}"),
            ),
        )
        row = conn.execute(
            """
            SELECT * FROM access_idempotency_claims
            WHERE workspace_id = ? AND idempotency_key = ?
            LIMIT 1
            """,
            (payload.get("workspace_id", DEFAULT_WORKSPACE_ID), payload.get("idempotency_key", "")),
        ).fetchone()
    return {"created": inserted.rowcount == 1, "record": _row_payload(row)}


def record_idempotency_claim(record: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    """Compatibility wrapper; duplicate keys preserve the first durable claim."""
    return claim_idempotency_record(record, request_meta).get("record", {})


def update_idempotency_claim(
    *,
    workspace_id: str,
    idempotency_key: str,
    status: str,
    result_status: str,
    response_ref: Dict[str, Any],
    completed_at: int,
) -> Dict[str, Any]:
    ensure_schema()
    now = int(time.time())
    with connection() as conn:
        conn.execute(
            """
            UPDATE access_idempotency_claims
            SET status = ?, result_status = ?, response_ref = ?, completed_at = ?, last_seen_at = ?
            WHERE workspace_id = ? AND idempotency_key = ?
            """,
            (
                status,
                result_status,
                encode_json(response_ref),
                int(completed_at or 0),
                now,
                workspace_id,
                idempotency_key,
            ),
        )
        row = conn.execute(
            """
            SELECT * FROM access_idempotency_claims
            WHERE workspace_id = ? AND idempotency_key = ?
            LIMIT 1
            """,
            (workspace_id, idempotency_key),
        ).fetchone()
    return _row_payload(row)


def touch_idempotency_claim(*, workspace_id: str, idempotency_key: str) -> Dict[str, Any]:
    ensure_schema()
    now = int(time.time())
    with connection() as conn:
        conn.execute(
            """
            UPDATE access_idempotency_claims
            SET last_seen_at = ?
            WHERE workspace_id = ? AND idempotency_key = ?
            """,
            (now, workspace_id, idempotency_key),
        )
        row = conn.execute(
            """
            SELECT * FROM access_idempotency_claims
            WHERE workspace_id = ? AND idempotency_key = ?
            LIMIT 1
            """,
            (workspace_id, idempotency_key),
        ).fetchone()
    return _row_payload(row)


def list_idempotency_claims(
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    action: str = "",
    status: str = "",
    limit: int = 50,
) -> List[Dict[str, Any]]:
    ensure_schema()
    sql = "SELECT * FROM access_idempotency_claims WHERE workspace_id = ?"
    params: List[Any] = [workspace_id]
    if action:
        sql += " AND action = ?"
        params.append(action)
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY last_seen_at DESC, first_seen_at DESC LIMIT ?"
    params.append(max(1, int(limit or 50)))
    with connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_payload(row) for row in rows]


def delete_idempotency_claim(idempotency_key: str, workspace_id: str) -> int:
    """Remove an explicitly named smoke-test claim."""
    ensure_schema()
    with connection() as conn:
        result = conn.execute(
            "DELETE FROM access_idempotency_claims WHERE workspace_id = ? AND idempotency_key = ?",
            (workspace_id, idempotency_key),
        )
        return int(result.rowcount or 0)


def delete_smoke_audit_records(marker: str) -> int:
    allowed_prefixes = (
        "payment-replay-production-smoke-",
        "external-callback-production-smoke-",
        "route-diag-",
    )
    marker = str(marker or "").strip()
    if not marker.startswith(allowed_prefixes) or len(marker) < 24:
        raise ValueError("approved_smoke_audit_marker_required")
    pattern = "%" + marker + "%"
    removed = 0
    ensure_schema()
    with connection() as conn:
        for table in ("access_source_assessments", "access_policy_decisions", "access_decisions"):
            columns = [
                str(row[1])
                for row in conn.execute(f'PRAGMA table_info("{table}")')
                if str(row[2] or "").upper() in {"TEXT", ""}
            ]
            if not columns:
                continue
            where = " OR ".join(f'CAST("{column}" AS TEXT) LIKE ?' for column in columns)
            result = conn.execute(
                f'DELETE FROM "{table}" WHERE {where}',
                tuple(pattern for _ in columns),
            )
            removed += int(result.rowcount or 0)
    return removed


def upsert_participant_grant(record: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    ensure_schema()
    now = _now(record)
    payload = _insert_json_columns(
        {
            **record,
            "request_meta": request_meta or {},
            "created_at": int(record.get("created_at") or now),
            "updated_at": int(record.get("updated_at") or now),
        },
        ["allowed_actions", "allowed_resources", "conditions", "provenance", "revocation_propagation", "request_meta"],
    )
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO access_participant_grants (
                grant_id, workspace_id, case_id, participant_id, participant_role, subject_id,
                subject_role, grant_type, status, consent_state, allowed_actions,
                allowed_resources, scope, source_family, issued_by, revoked_by,
                revoked_reason, conditions, provenance, revocation_propagation, request_meta,
                created_at, updated_at, expires_at, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(grant_id) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                case_id = excluded.case_id,
                participant_id = excluded.participant_id,
                participant_role = excluded.participant_role,
                subject_id = excluded.subject_id,
                subject_role = excluded.subject_role,
                grant_type = excluded.grant_type,
                status = excluded.status,
                consent_state = excluded.consent_state,
                allowed_actions = excluded.allowed_actions,
                allowed_resources = excluded.allowed_resources,
                scope = excluded.scope,
                source_family = excluded.source_family,
                issued_by = excluded.issued_by,
                revoked_by = excluded.revoked_by,
                revoked_reason = excluded.revoked_reason,
                conditions = excluded.conditions,
                provenance = excluded.provenance,
                revocation_propagation = excluded.revocation_propagation,
                request_meta = excluded.request_meta,
                updated_at = excluded.updated_at,
                expires_at = excluded.expires_at,
                revoked_at = excluded.revoked_at
            """,
            (
                payload.get("grant_id", ""),
                payload.get("workspace_id", DEFAULT_WORKSPACE_ID),
                payload.get("case_id", ""),
                payload.get("participant_id", ""),
                payload.get("participant_role", ""),
                payload.get("subject_id", ""),
                payload.get("subject_role", ""),
                payload.get("grant_type", ""),
                payload.get("status", "active"),
                payload.get("consent_state", "consented"),
                payload.get("allowed_actions", "[]"),
                payload.get("allowed_resources", "[]"),
                payload.get("scope", ""),
                payload.get("source_family", "liveuin_core"),
                payload.get("issued_by", ""),
                payload.get("revoked_by", ""),
                payload.get("revoked_reason", ""),
                payload.get("conditions", "{}"),
                payload.get("provenance", "{}"),
                payload.get("revocation_propagation", "{}"),
                payload.get("request_meta", "{}"),
                payload.get("created_at", now),
                payload.get("updated_at", now),
                int(payload.get("expires_at") or 0),
                int(payload.get("revoked_at") or 0),
            ),
        )
        row = conn.execute("SELECT * FROM access_participant_grants WHERE grant_id = ?", (payload.get("grant_id", ""),)).fetchone()
    return _row_payload(row)


def get_participant_grant(grant_id: str, workspace_id: str = DEFAULT_WORKSPACE_ID) -> Dict[str, Any]:
    ensure_schema()
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM access_participant_grants WHERE workspace_id = ? AND grant_id = ? LIMIT 1",
            (workspace_id, grant_id),
        ).fetchone()
    return _row_payload(row)


def find_participant_grant(
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    case_id: str,
    participant_id: str,
    action: str = "",
    resource_type: str = "",
    resource_id: str = "",
) -> Dict[str, Any]:
    ensure_schema()
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT * FROM access_participant_grants
            WHERE workspace_id = ? AND case_id = ? AND participant_id = ?
            ORDER BY updated_at DESC, created_at DESC
            """,
            (workspace_id, case_id, participant_id),
        ).fetchall()
    candidates = [_row_payload(row) for row in rows]
    for candidate in candidates:
        actions = set(str(item) for item in candidate.get("allowed_actions") or [])
        resources = set(str(item) for item in candidate.get("allowed_resources") or [])
        action_ok = not action or "*" in actions or action in actions
        resource_keys = {"*", resource_type, resource_id, f"{resource_type}:{resource_id}" if resource_type and resource_id else ""}
        resource_ok = not (resource_type or resource_id) or bool(resources.intersection(resource_keys))
        if action_ok and resource_ok:
            return candidate
    return candidates[0] if candidates else {}


def list_participant_grants(
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    case_id: str = "",
    participant_id: str = "",
    status: str = "",
    limit: int = 50,
) -> List[Dict[str, Any]]:
    ensure_schema()
    sql = "SELECT * FROM access_participant_grants WHERE workspace_id = ?"
    params: List[Any] = [workspace_id]
    if case_id:
        sql += " AND case_id = ?"
        params.append(case_id)
    if participant_id:
        sql += " AND participant_id = ?"
        params.append(participant_id)
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY updated_at DESC, created_at DESC LIMIT ?"
    params.append(max(1, int(limit or 50)))
    with connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_payload(row) for row in rows]


def record_participant_grant_event(record: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    ensure_schema()
    now = _now(record)
    payload = _insert_json_columns(
        {
            **record,
            "request_meta": request_meta or {},
            "created_at": int(record.get("created_at") or now),
        },
        ["event_payload", "request_meta"],
    )
    with connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO access_participant_grant_events (
                event_id, workspace_id, grant_id, case_id, participant_id,
                event_type, event_payload, request_meta, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.get("event_id", ""),
                payload.get("workspace_id", DEFAULT_WORKSPACE_ID),
                payload.get("grant_id", ""),
                payload.get("case_id", ""),
                payload.get("participant_id", ""),
                payload.get("event_type", ""),
                payload.get("event_payload", "{}"),
                payload.get("request_meta", "{}"),
                payload.get("created_at", now),
            ),
        )
        row = conn.execute("SELECT * FROM access_participant_grant_events WHERE event_id = ?", (payload.get("event_id", ""),)).fetchone()
    return _row_payload(row)


def reconcile_participant_grant_pending_evidence(
    grant: Dict[str, Any],
    event: Dict[str, Any],
    request_meta: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    ensure_schema()
    now = _now(grant)
    grant_payload = _insert_json_columns(
        {
            **grant,
            "request_meta": request_meta or {},
            "updated_at": int(grant.get("updated_at") or now),
        },
        ["allowed_actions", "allowed_resources", "conditions", "provenance", "revocation_propagation", "request_meta"],
    )
    event_payload = _insert_json_columns(
        {
            **event,
            "request_meta": request_meta or {},
            "created_at": int(event.get("created_at") or now),
        },
        ["event_payload", "request_meta"],
    )
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                """
                UPDATE access_participant_grants
                SET status = ?,
                    conditions = ?,
                    provenance = ?,
                    revocation_propagation = ?,
                    request_meta = ?,
                    updated_at = ?
                WHERE workspace_id = ? AND grant_id = ? AND status IN ('active', 'limited')
                """,
                (
                    "pending_evidence",
                    grant_payload.get("conditions", "{}"),
                    grant_payload.get("provenance", "{}"),
                    grant_payload.get("revocation_propagation", "{}"),
                    grant_payload.get("request_meta", "{}"),
                    int(grant_payload.get("updated_at") or now),
                    grant_payload.get("workspace_id", DEFAULT_WORKSPACE_ID),
                    grant_payload.get("grant_id", ""),
                ),
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO access_participant_grant_events (
                    event_id, workspace_id, grant_id, case_id, participant_id,
                    event_type, event_payload, request_meta, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_payload.get("event_id", ""),
                    event_payload.get("workspace_id", DEFAULT_WORKSPACE_ID),
                    event_payload.get("grant_id", ""),
                    event_payload.get("case_id", ""),
                    event_payload.get("participant_id", ""),
                    event_payload.get("event_type", ""),
                    event_payload.get("event_payload", "{}"),
                    event_payload.get("request_meta", "{}"),
                    event_payload.get("created_at", now),
                ),
            )
            row = conn.execute(
                "SELECT * FROM access_participant_grants WHERE workspace_id = ? AND grant_id = ? LIMIT 1",
                (grant_payload.get("workspace_id", DEFAULT_WORKSPACE_ID), grant_payload.get("grant_id", "")),
            ).fetchone()
            event_row = conn.execute(
                "SELECT * FROM access_participant_grant_events WHERE event_id = ? LIMIT 1",
                (event_payload.get("event_id", ""),),
            ).fetchone()
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return {"participant_grant": _row_payload(row), "event": _row_payload(event_row)}


def list_participant_grant_events(
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    grant_id: str = "",
    limit: int = 50,
) -> List[Dict[str, Any]]:
    ensure_schema()
    sql = "SELECT * FROM access_participant_grant_events WHERE workspace_id = ?"
    params: List[Any] = [workspace_id]
    if grant_id:
        sql += " AND grant_id = ?"
        params.append(grant_id)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(max(1, int(limit or 50)))
    with connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_payload(row) for row in rows]


def get_adapter_replay_nonce(
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    adapter_id: str,
    nonce: str,
) -> Dict[str, Any]:
    ensure_schema()
    with connection() as conn:
        row = conn.execute(
            """
            SELECT * FROM access_adapter_replay_nonces
            WHERE workspace_id = ? AND adapter_id = ? AND nonce = ?
            LIMIT 1
            """,
            (workspace_id, adapter_id, nonce),
        ).fetchone()
    return _row_payload(row)


def claim_adapter_replay_nonce(record: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    ensure_schema()
    now = int(record.get("first_seen_at") or time.time())
    workspace_id = str(record.get("workspace_id") or DEFAULT_WORKSPACE_ID)
    adapter_id = str(record.get("adapter_id") or "")
    nonce = str(record.get("nonce") or "")
    expires_at = int(record.get("expires_at") or 0)
    with connection() as conn:
        conn.execute(
            """
            DELETE FROM access_adapter_replay_nonces
            WHERE workspace_id = ? AND expires_at > 0 AND expires_at < ?
            """,
            (workspace_id, now),
        )
        existing = conn.execute(
            """
            SELECT * FROM access_adapter_replay_nonces
            WHERE workspace_id = ? AND adapter_id = ? AND nonce = ?
            LIMIT 1
            """,
            (workspace_id, adapter_id, nonce),
        ).fetchone()
        if existing:
            return {
                "ok": False,
                "detail": "adapter_signature_replay_detected",
                "status_code": 409,
                "replay": _row_payload(existing),
                "replay_store": replay_store_status(),
            }

        payload = _insert_json_columns(
            {
                **record,
                "request_meta": request_meta or {},
            },
            ["context", "request_meta"],
        )
        conn.execute(
            """
            INSERT INTO access_adapter_replay_nonces (
                replay_id, workspace_id, adapter_id, source_family, nonce, method, path,
                payload_hash, signature_hash, status, context, request_meta, first_seen_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.get("replay_id", ""),
                workspace_id,
                adapter_id,
                payload.get("source_family", ""),
                nonce,
                payload.get("method", "POST"),
                payload.get("path", ""),
                payload.get("payload_hash", ""),
                payload.get("signature_hash", ""),
                payload.get("status", "accepted"),
                payload.get("context", "{}"),
                payload.get("request_meta", "{}"),
                now,
                expires_at,
            ),
        )
        row = conn.execute(
            """
            SELECT * FROM access_adapter_replay_nonces
            WHERE workspace_id = ? AND adapter_id = ? AND nonce = ?
            LIMIT 1
            """,
            (workspace_id, adapter_id, nonce),
        ).fetchone()
    return {
        "ok": True,
        "replay": _row_payload(row),
        "replay_store": replay_store_status(),
    }


def list_adapter_replay_nonces(
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    adapter_id: str = "",
    source_family: str = "",
    limit: int = 50,
) -> List[Dict[str, Any]]:
    ensure_schema()
    sql = "SELECT * FROM access_adapter_replay_nonces WHERE workspace_id = ?"
    params: List[Any] = [workspace_id]
    if adapter_id:
        sql += " AND adapter_id = ?"
        params.append(adapter_id)
    if source_family:
        sql += " AND source_family = ?"
        params.append(source_family)
    sql += " ORDER BY first_seen_at DESC LIMIT ?"
    params.append(max(1, int(limit or 50)))
    with connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_row_payload(row) for row in rows]


def stats(workspace_id: str) -> Dict[str, Any]:
    ensure_schema()
    with connection() as conn:
        decision_count = int(
            conn.execute("SELECT COUNT(*) FROM access_decisions WHERE workspace_id = ?", (workspace_id,)).fetchone()[0]
        )
        denied_decision_count = int(
            conn.execute(
                "SELECT COUNT(*) FROM access_decisions WHERE workspace_id = ? AND decision = 'deny'",
                (workspace_id,),
            ).fetchone()[0]
        )
        source_assessment_count = int(
            conn.execute("SELECT COUNT(*) FROM access_source_assessments WHERE workspace_id = ?", (workspace_id,)).fetchone()[0]
        )
        idempotency_claim_count = int(
            conn.execute("SELECT COUNT(*) FROM access_idempotency_claims WHERE workspace_id = ?", (workspace_id,)).fetchone()[0]
        )
        adapter_replay_nonce_count = int(
            conn.execute("SELECT COUNT(*) FROM access_adapter_replay_nonces WHERE workspace_id = ?", (workspace_id,)).fetchone()[0]
        )
        participant_grant_count = int(
            conn.execute("SELECT COUNT(*) FROM access_participant_grants WHERE workspace_id = ?", (workspace_id,)).fetchone()[0]
        )
        revoked_participant_grant_count = int(
            conn.execute(
                "SELECT COUNT(*) FROM access_participant_grants WHERE workspace_id = ? AND status = 'revoked'",
                (workspace_id,),
            ).fetchone()[0]
        )
        participant_grant_event_count = int(
            conn.execute("SELECT COUNT(*) FROM access_participant_grant_events WHERE workspace_id = ?", (workspace_id,)).fetchone()[0]
        )
    return {
        "store_driver": _clean_driver(replay_store_driver()),
        "sqlite_path": str(sqlite_path()),
        "decision_count": decision_count,
        "denied_decision_count": denied_decision_count,
        "source_assessment_count": source_assessment_count,
        "idempotency_claim_count": idempotency_claim_count,
        "adapter_replay_nonce_count": adapter_replay_nonce_count,
        "participant_grant_count": participant_grant_count,
        "revoked_participant_grant_count": revoked_participant_grant_count,
        "participant_grant_event_count": participant_grant_event_count,
        "shared_replay_store": replay_postgres_active(),
    }


def status(workspace_id: str = DEFAULT_WORKSPACE_ID) -> Dict[str, Any]:
    tables = [
        "access_decisions",
        "access_source_assessments",
        "access_idempotency_claims",
        "access_adapter_replay_nonces",
        "access_participant_grants",
        "access_participant_grant_events",
    ]
    return {
        "ok": True,
        "service": "liveuin-core-access-store",
        "workspace_id": workspace_id,
        "sqlite_path": str(sqlite_path()),
        "tables": tables,
        "stats": stats(workspace_id),
        "replay_store": replay_store_status(),
    }
