from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterator, List

try:
    from .core_identity_public_schema import MIGRATION_CHECKSUM, MIGRATION_VERSION, SCHEMA_SQL, SCHEMA_VERSION
except ImportError:  # pragma: no cover - direct app-folder deployment.
    from core_identity_public_schema import MIGRATION_CHECKSUM, MIGRATION_VERSION, SCHEMA_SQL, SCHEMA_VERSION


NOTIFICATION_DELIVERY_STATES = {"CREATED", "ACCEPTED", "FAILED_RETRYABLE", "FAILED_PERMANENT"}


def _now() -> int:
    return int(time.time())


def _clean(value: Any, max_length: int = 240) -> str:
    return str(value or "").strip()[:max_length]


def _clean_id(value: Any, max_length: int = 160) -> str:
    return "".join(ch for ch in str(value or "").strip() if ch.isalnum() or ch in "_.:-")[:max_length]


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=True, sort_keys=True)


def _decode(value: Any, fallback: Any) -> Any:
    if value in (None, ""):
        return fallback
    if isinstance(value, (dict, list)):
        return value
    try:
        result = json.loads(str(value))
    except (TypeError, ValueError):
        return fallback
    return result if result is not None else fallback


def hash_value(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def data_dir() -> Path:
    configured = os.getenv("LIVEUIN_CORE_IDENTITY_PUBLIC_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[1] / "runtime" / "staging" / "core-identity-public"


def sqlite_path() -> Path:
    configured = os.getenv("LIVEUIN_CORE_IDENTITY_PUBLIC_SQLITE_PATH", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return data_dir() / "liveuin-core-identity-public.sqlite3"


def backup_dir() -> Path:
    configured = os.getenv("LIVEUIN_CORE_IDENTITY_PUBLIC_BACKUP_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return data_dir() / "backups"


@contextmanager
def connection() -> Iterator[sqlite3.Connection]:
    target = sqlite_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    ensure_schema(conn)
    try:
        yield conn
    finally:
        conn.close()


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    _migrate_password_reset_account_nullable(conn)
    required_columns = {
        "identity_public_accounts": {
            "email_provider_subject_hash": "TEXT NOT NULL DEFAULT ''",
        },
        "identity_public_registrations": {
            "resend_count": "INTEGER NOT NULL DEFAULT 0",
            "idempotency_key_hash": "TEXT NOT NULL DEFAULT ''",
            "last_delivery_at": "INTEGER NOT NULL DEFAULT 0",
            "last_delivery_error": "TEXT NOT NULL DEFAULT ''",
        },
        "identity_public_password_resets": {},
    }
    for table, columns in required_columns.items():
        existing = {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        for name, definition in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
    recorded = conn.execute(
        "SELECT checksum FROM identity_public_schema_migrations WHERE version = ?",
        (MIGRATION_VERSION,),
    ).fetchone()
    if recorded and str(recorded[0]) != MIGRATION_CHECKSUM:
        raise RuntimeError("identity_public_migration_checksum_mismatch")
    conn.execute(
        "INSERT OR IGNORE INTO identity_public_schema_migrations(version, checksum, applied_at) VALUES (?, ?, ?)",
        (MIGRATION_VERSION, MIGRATION_CHECKSUM, _now()),
    )
    conn.commit()


def _migrate_password_reset_account_nullable(conn: sqlite3.Connection) -> None:
    """Allow enumeration-safe decoy reset records without an account FK."""
    columns = {str(row[1]): row for row in conn.execute("PRAGMA table_info(identity_public_password_resets)").fetchall()}
    account_column = columns.get("account_id")
    if not account_column or int(account_column[3] or 0) == 0:
        return
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("ALTER TABLE identity_public_password_resets RENAME TO identity_public_password_resets_legacy")
    conn.execute(
        """
        CREATE TABLE identity_public_password_resets (
            reset_id TEXT PRIMARY KEY,
            account_id TEXT,
            workspace_id TEXT NOT NULL,
            email_hash TEXT NOT NULL,
            verification_code_hash TEXT NOT NULL,
            reset_token_hash TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'verification_pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 5,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            verified_at INTEGER NOT NULL DEFAULT 0,
            completed_at INTEGER NOT NULL DEFAULT 0,
            idempotency_key_hash TEXT NOT NULL DEFAULT '',
            delivery_mode TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY (account_id) REFERENCES identity_public_accounts(account_id)
        )
        """
    )
    conn.execute(
        """
        INSERT INTO identity_public_password_resets(
            reset_id, account_id, workspace_id, email_hash, verification_code_hash,
            reset_token_hash, status, attempts, max_attempts, issued_at, expires_at,
            verified_at, completed_at, idempotency_key_hash, delivery_mode, created_at, updated_at
        )
        SELECT reset_id, account_id, workspace_id, email_hash, verification_code_hash,
            reset_token_hash, status, attempts, max_attempts, issued_at, expires_at,
            verified_at, completed_at, idempotency_key_hash, delivery_mode, created_at, updated_at
        FROM identity_public_password_resets_legacy
        """
    )
    conn.execute("DROP TABLE identity_public_password_resets_legacy")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_identity_public_password_resets_account ON identity_public_password_resets(account_id, status, updated_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_identity_public_password_resets_token ON identity_public_password_resets(reset_token_hash, status)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_identity_public_password_resets_idempotency ON identity_public_password_resets(workspace_id, idempotency_key_hash, updated_at DESC)"
    )
    conn.execute("PRAGMA foreign_keys=ON")


def _account(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}
    data = dict(row)
    return {
        "account_id": _clean_id(data.get("account_id")),
        "workspace_id": _clean_id(data.get("workspace_id"), 96),
        "email_hash": _clean(data.get("email_hash"), 128),
        "email_provider_subject_hash": _clean(data.get("email_provider_subject_hash"), 128),
        "email_hint": _clean(data.get("email_hint"), 80),
        "person_id": _clean_id(data.get("person_id")),
        "status": _clean(data.get("status") or "email_verification_pending", 60),
        "email_verified_at": int(data.get("email_verified_at") or 0),
        "profile_completion_state": _clean(data.get("profile_completion_state") or "incomplete", 40),
        "tenant_entitlement_state": _clean(data.get("tenant_entitlement_state") or "not_issued", 40),
        "localpro_application_state": _clean(data.get("localpro_application_state") or "not_started", 40),
        "localpro_authorization_state": _clean(data.get("localpro_authorization_state") or "not_issued", 40),
        "accepted_terms_version": _clean(data.get("accepted_terms_version"), 80),
        "locale": _clean(data.get("locale"), 20),
        "display_name": _clean(data.get("display_name"), 160),
        "deletion_status": _clean(data.get("deletion_status") or "not_requested", 40),
        "password_hash_version": _clean(data.get("password_hash_version"), 80),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
        "password_hash": _clean(data.get("password_hash"), 240),
    }


def _registration(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}
    data = dict(row)
    return {
        "registration_id": _clean_id(data.get("registration_id")),
        "account_id": _clean_id(data.get("account_id")),
        "workspace_id": _clean_id(data.get("workspace_id"), 96),
        "email_hash": _clean(data.get("email_hash"), 128),
        "status": _clean(data.get("status") or "email_verification_pending", 60),
        "attempts": int(data.get("attempts") or 0),
        "max_attempts": int(data.get("max_attempts") or 5),
        "issued_at": int(data.get("issued_at") or 0),
        "expires_at": int(data.get("expires_at") or 0),
        "verified_at": int(data.get("verified_at") or 0),
        "delivery_mode": _clean(data.get("delivery_mode"), 40),
        "resend_count": int(data.get("resend_count") or 0),
        "idempotency_key_hash": _clean(data.get("idempotency_key_hash"), 128),
        "last_delivery_at": int(data.get("last_delivery_at") or 0),
        "last_delivery_error": _clean(data.get("last_delivery_error"), 160),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
        "verification_code_hash": _clean(data.get("verification_code_hash"), 128),
    }


def get_account(account_id: str) -> Dict[str, Any]:
    with connection() as conn:
        row = conn.execute("SELECT * FROM identity_public_accounts WHERE account_id = ?", (_clean_id(account_id),)).fetchone()
    return _account(row)


def get_account_by_email_hash(email_hash: str, workspace_id: str = "") -> Dict[str, Any]:
    if not _clean(workspace_id, 96):
        return {}
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM identity_public_accounts WHERE workspace_id = ? AND email_hash = ? LIMIT 1",
            (_clean_id(workspace_id, 96), _clean(email_hash, 128)),
        ).fetchone()
    return _account(row)


def get_account_by_person_id(person_id: str, workspace_id: str = "") -> Dict[str, Any]:
    if not _clean(workspace_id, 96):
        return {}
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM identity_public_accounts WHERE workspace_id = ? AND person_id = ? LIMIT 1",
            (_clean_id(workspace_id, 96), _clean_id(person_id)),
        ).fetchone()
    return _account(row)


def _provider_identity(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}
    data = dict(row)
    return {
        "provider_identity_id": _clean_id(data.get("provider_identity_id")),
        "workspace_id": _clean_id(data.get("workspace_id"), 96),
        "provider": _clean(data.get("provider"), 32),
        "subject_hash": _clean(data.get("subject_hash"), 128),
        "subject_hint": _clean(data.get("subject_hint"), 80),
        "account_id": _clean_id(data.get("account_id")),
        "person_id": _clean_id(data.get("person_id")),
        "verified_email_hash": _clean(data.get("verified_email_hash"), 128),
        "verified_email_state": _clean(data.get("verified_email_state") or "unknown", 32),
        "link_state": _clean(data.get("link_state") or "linked", 32),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
    }


def get_provider_identity(workspace_id: str, provider: str, subject_hash: str) -> Dict[str, Any]:
    workspace = _clean_id(workspace_id, 96)
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM identity_public_provider_identities WHERE workspace_id = ? AND provider = ? AND subject_hash = ? LIMIT 1",
            (workspace, _clean(provider, 32), _clean(subject_hash, 128)),
        ).fetchone()
    return _provider_identity(row)


def get_provider_identity_by_email_hash(workspace_id: str, verified_email_hash: str) -> Dict[str, Any]:
    workspace = _clean_id(workspace_id, 96)
    email_hash = _clean(verified_email_hash, 128)
    if not workspace or not email_hash:
        return {}
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM identity_public_provider_identities WHERE workspace_id = ? AND verified_email_hash = ? ORDER BY updated_at DESC LIMIT 1",
            (workspace, email_hash),
        ).fetchone()
    return _provider_identity(row)


def create_social_account_with_provider(
    *,
    account: Dict[str, Any],
    provider_identity: Dict[str, Any],
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    now = _now()
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            INSERT INTO identity_public_accounts(
                account_id, workspace_id, email_hash, email_provider_subject_hash, email_hint, person_id, status,
                email_verified_at, profile_completion_state, tenant_entitlement_state,
                localpro_application_state, localpro_authorization_state,
                accepted_terms_version, locale, display_name, deletion_status,
                password_hash, password_hash_version, created_at, updated_at
            ) VALUES (?, ?, ?, '', ?, ?, 'authenticated', ?, 'incomplete', 'not_issued', 'not_started', 'not_issued', '', ?, ?, 'not_requested', ?, ?, ?, ?)
            """,
            (
                _clean_id(account["account_id"]), _clean_id(account.get("workspace_id"), 96),
                _clean(account.get("email_hash"), 128), _clean(account.get("email_hint"), 80),
                _clean_id(account.get("person_id")), int(account.get("email_verified_at") or now),
                _clean(account.get("locale"), 20), _clean(account.get("display_name"), 160),
                _clean(account.get("password_hash"), 240), _clean(account.get("password_hash_version") or "bcrypt-12-provider-random", 80),
                int(account.get("created_at") or now), int(account.get("updated_at") or now),
            ),
        )
        conn.execute(
            """
            INSERT INTO identity_public_provider_identities(
                provider_identity_id, workspace_id, provider, subject_hash, subject_hint,
                account_id, person_id, verified_email_hash, verified_email_state,
                link_state, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'linked', ?, ?)
            """,
            (
                _clean_id(provider_identity["provider_identity_id"]), _clean_id(provider_identity.get("workspace_id"), 96),
                _clean(provider_identity.get("provider"), 32), _clean(provider_identity.get("subject_hash"), 128),
                _clean(provider_identity.get("subject_hint"), 80), _clean_id(provider_identity.get("account_id")),
                _clean_id(provider_identity.get("person_id")), _clean(provider_identity.get("verified_email_hash"), 128),
                _clean(provider_identity.get("verified_email_state") or "unknown", 32),
                int(provider_identity.get("created_at") or now), int(provider_identity.get("updated_at") or now),
            ),
        )
        _audit_conn(
            conn,
            account_id=account["account_id"],
            registration_id="",
            workspace_id=account.get("workspace_id") or "",
            event_type="identity.public.provider_account_created",
            payload={
                "provider": _clean(provider_identity.get("provider"), 32),
                "provider_identity_id": _clean_id(provider_identity.get("provider_identity_id")),
                "profile_state": "incomplete",
                "tenant_entitlement_state": "not_issued",
                "localpro_authorization_state": "not_issued",
            },
            request_meta=request_meta,
        )
        conn.commit()
    return get_account(account["account_id"])


def link_provider_identity(
    *,
    provider_identity: Dict[str, Any],
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    now = _now()
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            INSERT INTO identity_public_provider_identities(
                provider_identity_id, workspace_id, provider, subject_hash, subject_hint,
                account_id, person_id, verified_email_hash, verified_email_state,
                link_state, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'linked', ?, ?)
            """,
            (
                _clean_id(provider_identity["provider_identity_id"]), _clean_id(provider_identity.get("workspace_id"), 96),
                _clean(provider_identity.get("provider"), 32), _clean(provider_identity.get("subject_hash"), 128),
                _clean(provider_identity.get("subject_hint"), 80), _clean_id(provider_identity.get("account_id")),
                _clean_id(provider_identity.get("person_id")), _clean(provider_identity.get("verified_email_hash"), 128),
                _clean(provider_identity.get("verified_email_state") or "unknown", 32),
                int(provider_identity.get("created_at") or now), int(provider_identity.get("updated_at") or now),
            ),
        )
        _audit_conn(
            conn,
            account_id=provider_identity.get("account_id") or "",
            registration_id="",
            workspace_id=provider_identity.get("workspace_id") or "",
            event_type="identity.public.provider_linked",
            payload={
                "provider": _clean(provider_identity.get("provider"), 32),
                "provider_identity_id": _clean_id(provider_identity.get("provider_identity_id")),
                "link_state": "linked",
            },
            request_meta=request_meta,
        )
        conn.commit()
    return get_provider_identity(provider_identity.get("workspace_id") or "", provider_identity.get("provider") or "", provider_identity.get("subject_hash") or "")


def list_provider_identities_for_account(account_id: str, workspace_id: str = "") -> List[Dict[str, Any]]:
    account_id = _clean_id(account_id)
    workspace_id = _clean_id(workspace_id, 96)
    if not account_id:
        return []
    clauses = ["account_id = ?"]
    params: List[Any] = [account_id]
    if workspace_id:
        clauses.append("workspace_id = ?")
        params.append(workspace_id)
    with connection() as conn:
        rows = conn.execute(
            f"SELECT * FROM identity_public_provider_identities WHERE {' AND '.join(clauses)} ORDER BY updated_at DESC",
            tuple(params),
        ).fetchall()
    return [_provider_identity(row) for row in rows]


def list_provider_identities(workspace_id: str = "", provider: str = "", link_state: str = "") -> List[Dict[str, Any]]:
    """List social provider links for canonical graph-integrity checks."""
    workspace_id = _clean_id(workspace_id, 96)
    provider = _clean(provider, 32)
    link_state = _clean(link_state, 32)
    clauses: List[str] = []
    params: List[Any] = []
    if workspace_id:
        clauses.append("workspace_id = ?")
        params.append(workspace_id)
    if provider:
        clauses.append("provider = ?")
        params.append(provider)
    if link_state:
        clauses.append("link_state = ?")
        params.append(link_state)
    query = "SELECT * FROM identity_public_provider_identities"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY updated_at DESC, provider_identity_id ASC"
    with connection() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
    return [_provider_identity(row) for row in rows]


def delete_social_account_if_unissued(
    account_id: str,
    person_id: str,
    workspace_id: str,
    request_meta: Dict[str, Any] | None = None,
) -> bool:
    """Compensate a just-created social account before any session is issued."""
    account_id = _clean_id(account_id)
    person_id = _clean_id(person_id)
    workspace_id = _clean_id(workspace_id, 96)
    if not account_id or not person_id or not workspace_id:
        return False
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT account_id, person_id, workspace_id, status,
                   profile_completion_state, tenant_entitlement_state,
                   localpro_application_state, localpro_authorization_state
            FROM identity_public_accounts
            WHERE account_id = ?
            LIMIT 1
            """,
            (account_id,),
        ).fetchone()
        if not row or any(
            (
                str(row[1] or "") != person_id,
                str(row[2] or "") != workspace_id,
                str(row[3] or "") != "authenticated",
                str(row[4] or "") != "incomplete",
                str(row[5] or "") != "not_issued",
                str(row[6] or "") != "not_started",
                str(row[7] or "") != "not_issued",
            )
        ):
            conn.rollback()
            return False
        _audit_conn(
            conn,
            account_id=account_id,
            registration_id="",
            workspace_id=workspace_id,
            event_type="identity.public.social_account_compensated",
            payload={"reason": "identity_graph_integrity_failed", "provider_links_removed": True},
            request_meta=request_meta,
        )
        conn.execute("DELETE FROM identity_public_provider_identities WHERE account_id = ? AND workspace_id = ?", (account_id, workspace_id))
        deleted = conn.execute("DELETE FROM identity_public_accounts WHERE account_id = ? AND person_id = ? AND workspace_id = ?", (account_id, person_id, workspace_id)).rowcount
        conn.commit()
    return bool(deleted)


def mark_provider_identity_state(
    provider_identity_id: str,
    link_state: str,
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    provider_identity_id = _clean_id(provider_identity_id)
    if not provider_identity_id:
        return {}
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM identity_public_provider_identities WHERE provider_identity_id = ? LIMIT 1",
            (provider_identity_id,),
        ).fetchone()
        if not row:
            return {}
        data = dict(row)
        now = _now()
        conn.execute(
            "UPDATE identity_public_provider_identities SET link_state = ?, updated_at = ? WHERE provider_identity_id = ?",
            (_clean(link_state, 32), now, provider_identity_id),
        )
        _audit_conn(
            conn,
            account_id=data.get("account_id") or "",
            registration_id="",
            workspace_id=data.get("workspace_id") or "",
            event_type="identity.public.provider_link_state_changed",
            payload={"provider": _clean(data.get("provider"), 32), "link_state": _clean(link_state, 32)},
            request_meta=request_meta,
        )
        conn.commit()
    return get_provider_identity(data.get("workspace_id") or "", data.get("provider") or "", data.get("subject_hash") or "")


def delete_provider_identities_for_account(account_id: str, workspace_id: str = "") -> int:
    account_id = _clean_id(account_id)
    workspace_id = _clean_id(workspace_id, 96)
    if not account_id:
        return 0
    clauses = ["account_id = ?"]
    params: List[Any] = [account_id]
    if workspace_id:
        clauses.append("workspace_id = ?")
        params.append(workspace_id)
    with connection() as conn:
        result = conn.execute(
            f"DELETE FROM identity_public_provider_identities WHERE {' AND '.join(clauses)}",
            tuple(params),
        )
        conn.commit()
    return int(result.rowcount or 0)


def consume_provider_replay(*, workspace_id: str, provider: str, replay_kind: str, value: str, expires_at: int) -> bool:
    replay_key_hash = hash_value(f"{_clean_id(workspace_id, 96)}:{_clean(provider, 32)}:{_clean(replay_kind, 48)}:{value}")
    now = _now()
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM identity_public_provider_replays WHERE expires_at <= ?", (now,))
        try:
            conn.execute(
                "INSERT INTO identity_public_provider_replays(replay_key_hash, workspace_id, provider, replay_kind, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (replay_key_hash, _clean_id(workspace_id, 96), _clean(provider, 32), _clean(replay_kind, 48), int(expires_at), now),
            )
        except sqlite3.IntegrityError:
            conn.rollback()
            return False
        conn.commit()
    return True


def create_account_registration(
    *,
    account: Dict[str, Any],
    registration: Dict[str, Any],
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    now = _now()
    with connection() as conn:
        conn.execute("BEGIN")
        conn.execute(
            """
            INSERT INTO identity_public_accounts(
                account_id, workspace_id, email_hash, email_provider_subject_hash, email_hint, person_id, status,
                email_verified_at, profile_completion_state, tenant_entitlement_state,
                localpro_application_state, localpro_authorization_state,
                accepted_terms_version, locale, display_name, deletion_status,
                password_hash, password_hash_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, 'not_requested', ?, ?, ?, ?)
            """,
            (
                _clean_id(account["account_id"]),
                _clean_id(account.get("workspace_id"), 96),
                _clean(account["email_hash"], 128),
                _clean(account.get("email_provider_subject_hash"), 128),
                _clean(account.get("email_hint"), 80),
                _clean_id(account.get("person_id")),
                _clean(account.get("status") or "email_verification_pending", 60),
                _clean(account.get("profile_completion_state") or "incomplete", 40),
                _clean(account.get("tenant_entitlement_state") or "not_issued", 40),
                _clean(account.get("localpro_application_state") or "not_started", 40),
                _clean(account.get("localpro_authorization_state") or "not_issued", 40),
                _clean(account.get("accepted_terms_version"), 80),
                _clean(account.get("locale"), 20),
                _clean(account.get("display_name"), 160),
                _clean(account["password_hash"], 240),
                _clean(account.get("password_hash_version") or "bcrypt-12", 80),
                int(account.get("created_at") or now),
                int(account.get("updated_at") or now),
            ),
        )
        conn.execute(
            """
            INSERT INTO identity_public_registrations(
                registration_id, account_id, workspace_id, email_hash, verification_code_hash,
                status, attempts, max_attempts, issued_at, expires_at, verified_at,
                delivery_mode, resend_count, idempotency_key_hash, last_delivery_at,
                last_delivery_error, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 0, ?, ?, ?, 0, '', ?, ?)
            """,
            (
                _clean_id(registration["registration_id"]),
                _clean_id(registration["account_id"]),
                _clean_id(registration.get("workspace_id"), 96),
                _clean(registration["email_hash"], 128),
                _clean(registration["verification_code_hash"], 128),
                _clean(registration.get("status") or "email_verification_pending", 60),
                max(1, min(10, int(registration.get("max_attempts") or 5))),
                int(registration.get("issued_at") or now),
                int(registration["expires_at"]),
                _clean(registration.get("delivery_mode"), 40),
                int(registration.get("resend_count") or 0),
                _clean(registration.get("idempotency_key_hash"), 128),
                int(registration.get("created_at") or now),
                int(registration.get("updated_at") or now),
            ),
        )
        _audit_conn(
            conn,
            account_id=account["account_id"],
            registration_id=registration["registration_id"],
            workspace_id=account.get("workspace_id") or "",
            event_type="identity.public.registration_started",
            payload={"requested_default_profile": "tenant", "raw_email_stored": False},
            request_meta=request_meta,
        )
        conn.commit()
    return get_account(account["account_id"])


def get_registration(registration_id: str) -> Dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM identity_public_registrations WHERE registration_id = ? LIMIT 1",
            (_clean_id(registration_id),),
        ).fetchone()
    return _registration(row)


def get_registration_by_idempotency(idempotency_key_hash: str) -> Dict[str, Any]:
    key = _clean(idempotency_key_hash, 128)
    if not key:
        return {}
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM identity_public_registrations WHERE idempotency_key_hash = ? ORDER BY updated_at DESC LIMIT 1",
            (key,),
        ).fetchone()
    return _registration(row)


def get_latest_registration_by_email_hash(email_hash: str, workspace_id: str) -> Dict[str, Any]:
    if not _clean(workspace_id, 96):
        return {}
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM identity_public_registrations WHERE workspace_id = ? AND email_hash = ? ORDER BY updated_at DESC LIMIT 1",
            (_clean_id(workspace_id, 96), _clean(email_hash, 128)),
        ).fetchone()
    return _registration(row)


def prepare_registration_delivery(
    registration_id: str,
    *,
    code_hash: str,
    expires_at: int,
    delivery_mode: str,
    idempotency_key_hash: str,
    password_hash: str = "",
    password_hash_version: str = "",
    accepted_terms_version: str = "",
) -> Dict[str, Any]:
    registration = get_registration(registration_id)
    if not registration:
        return {}
    now = _now()
    with connection() as conn:
        if password_hash:
            conn.execute(
                "UPDATE identity_public_accounts SET password_hash = ?, password_hash_version = ?, accepted_terms_version = ?, status = 'email_verification_pending', updated_at = ? WHERE account_id = ?",
                (_clean(password_hash, 240), _clean(password_hash_version, 80), _clean(accepted_terms_version, 80), now, registration["account_id"]),
            )
        conn.execute(
            """
            UPDATE identity_public_registrations
            SET verification_code_hash = ?, status = 'email_verification_pending', attempts = 0,
                expires_at = ?, delivery_mode = ?, resend_count = resend_count + 1,
                idempotency_key_hash = ?, last_delivery_at = 0, last_delivery_error = '', updated_at = ?
            WHERE registration_id = ?
            """,
            (_clean(code_hash, 128), int(expires_at), _clean(delivery_mode, 40), _clean(idempotency_key_hash, 128), now, registration_id),
        )
        _audit_conn(
            conn,
            account_id=registration["account_id"],
            registration_id=registration_id,
            workspace_id=registration["workspace_id"],
            event_type="identity.public.registration_delivery_prepared",
            payload={"resend": registration.get("resend_count", 0) > 0},
            request_meta=None,
        )
        conn.commit()
    return get_registration(registration_id)


def mark_delivery_failed(registration_id: str, request_meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    registration = get_registration(registration_id)
    if not registration:
        return {}
    now = _now()
    with connection() as conn:
        conn.execute(
            "UPDATE identity_public_registrations SET status = 'delivery_failed', last_delivery_error = 'delivery_failed', updated_at = ? WHERE registration_id = ?",
            (now, registration["registration_id"]),
        )
        conn.execute(
            "UPDATE identity_public_accounts SET status = 'registration_started', updated_at = ? WHERE account_id = ?",
            (now, registration["account_id"]),
        )
        _audit_conn(
            conn,
            account_id=registration["account_id"],
            registration_id=registration["registration_id"],
            workspace_id=registration["workspace_id"],
            event_type="identity.public.registration_delivery_failed",
            payload={},
            request_meta=request_meta,
        )
        conn.commit()
    return get_registration(registration_id)


def mark_delivery_succeeded(registration_id: str, request_meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    registration = get_registration(registration_id)
    if not registration:
        return {}
    now = _now()
    with connection() as conn:
        conn.execute(
            "UPDATE identity_public_registrations SET last_delivery_at = ?, last_delivery_error = '', updated_at = ? WHERE registration_id = ?",
            (now, now, registration_id),
        )
        _audit_conn(
            conn,
            account_id=registration["account_id"],
            registration_id=registration_id,
            workspace_id=registration["workspace_id"],
            event_type="identity.public.registration_delivery_succeeded",
            payload={},
            request_meta=request_meta,
        )
        conn.commit()
    return get_registration(registration_id)


def mark_verification_attempt(
    registration_id: str,
    *,
    success: bool,
    lock: bool = False,
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    registration = get_registration(registration_id)
    if not registration:
        return {}
    now = _now()
    attempts = registration["attempts"] + 1
    status = "verified" if success else ("locked" if lock else "email_verification_pending")
    with connection() as conn:
        conn.execute(
            """
            UPDATE identity_public_registrations
            SET attempts = ?, status = ?, verified_at = ?, updated_at = ?
            WHERE registration_id = ?
            """,
            (attempts, status, now if success else 0, now, registration["registration_id"]),
        )
        if success:
            conn.execute(
                """
                UPDATE identity_public_accounts
                SET status = 'authenticated', email_verified_at = ?, updated_at = ?
                WHERE account_id = ?
                """,
                (now, now, registration["account_id"]),
            )
        _audit_conn(
            conn,
            account_id=registration["account_id"],
            registration_id=registration["registration_id"],
            workspace_id=registration["workspace_id"],
            event_type="identity.public.registration_verified" if success else "identity.public.registration_verification_failed",
            payload={"attempts": attempts, "locked": lock},
            request_meta=request_meta,
        )
        conn.commit()
    return get_registration(registration_id)


def bind_verified_person(account_id: str, person_id: str, request_meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    account = get_account(account_id)
    if not account or not _clean_id(person_id):
        return {}
    now = _now()
    with connection() as conn:
        conn.execute(
            "UPDATE identity_public_accounts SET person_id = ?, status = 'authenticated', updated_at = ? WHERE account_id = ? AND email_verified_at > 0",
            (_clean_id(person_id), now, _clean_id(account_id)),
        )
        _audit_conn(
            conn,
            account_id=account_id,
            registration_id="",
            workspace_id=account["workspace_id"],
            event_type="identity.public.verified_person_bound",
            payload={"person_id_bound": True},
            request_meta=request_meta,
        )
        conn.commit()
    return get_account(account_id)


def rollback_verified_registration(registration_id: str, request_meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    registration = get_registration(registration_id)
    if not registration:
        return {}
    now = _now()
    with connection() as conn:
        conn.execute(
            "UPDATE identity_public_registrations SET status = 'email_verification_pending', verified_at = 0, updated_at = ? WHERE registration_id = ?",
            (now, registration_id),
        )
        conn.execute(
            "UPDATE identity_public_accounts SET status = 'email_verification_pending', email_verified_at = 0, person_id = '', updated_at = ? WHERE account_id = ?",
            (now, registration["account_id"]),
        )
        _audit_conn(conn, account_id=registration["account_id"], registration_id=registration_id, workspace_id=registration["workspace_id"], event_type="identity.public.verification_compensated", payload={}, request_meta=request_meta)
        conn.commit()
    return get_registration(registration_id)


def update_account(account_id: str, fields: Dict[str, Any], request_meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    account = get_account(account_id)
    if not account:
        return {}
    allowed = {
        "status", "profile_completion_state", "tenant_entitlement_state",
        "localpro_application_state", "localpro_authorization_state",
        "locale", "display_name", "deletion_status", "password_hash",
        "password_hash_version", "accepted_terms_version", "person_id",
    }
    values = {key: fields[key] for key in allowed if key in fields}
    if not values:
        return account
    values["updated_at"] = _now()
    assignments = ", ".join(f"{key} = ?" for key in values)
    with connection() as conn:
        conn.execute(
            f"UPDATE identity_public_accounts SET {assignments} WHERE account_id = ?",
            tuple(values.values()) + (_clean_id(account_id),),
        )
        _audit_conn(
            conn,
            account_id=account_id,
            registration_id="",
            workspace_id=account["workspace_id"],
            event_type="identity.public.account_updated",
            payload={"fields": sorted(values.keys())},
            request_meta=request_meta,
        )
        conn.commit()
    return get_account(account_id)


def ensure_founder_qa_account(
    account: Dict[str, Any],
    provider_identity: Dict[str, Any] | None = None,
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Create or refresh the one server-controlled staging resident QA identity.

    This is intentionally separate from public registration.  It accepts no
    email address, creates no verification record, and only operates on the
    fixed founder-QA account/person selected by the staging route.
    """
    account_id = _clean_id(account.get("account_id"))
    workspace_id = _clean_id(account.get("workspace_id"), 96)
    person_id = _clean_id(account.get("person_id"))
    email_hash = _clean(account.get("email_hash"), 128)
    if not account_id or not workspace_id or not person_id or not email_hash:
        return {}

    existing = get_account(account_id)
    existing_by_email = get_account_by_email_hash(email_hash, workspace_id)
    if existing_by_email and existing_by_email.get("account_id") != account_id:
        return {}
    if existing and (
        existing.get("workspace_id") != workspace_id
        or (existing.get("person_id") and existing.get("person_id") != person_id)
        or existing.get("deletion_status") == "deleted"
    ):
        return {}

    now = _now()
    provider = provider_identity or {}
    provider_id = _clean_id(provider.get("provider_identity_id"))
    provider_name = _clean(provider.get("provider"), 32)
    provider_subject_hash = _clean(provider.get("subject_hash"), 128)
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        email_conflict = conn.execute(
            "SELECT account_id FROM identity_public_accounts WHERE workspace_id = ? AND email_hash = ? LIMIT 1",
            (workspace_id, email_hash),
        ).fetchone()
        if email_conflict and str(email_conflict[0]) != account_id:
            conn.rollback()
            return {}
        if provider_id and provider_name and provider_subject_hash:
            provider_conflict = conn.execute(
                "SELECT provider_identity_id, account_id, person_id FROM identity_public_provider_identities WHERE workspace_id = ? AND provider = ? AND subject_hash = ? LIMIT 1",
                (workspace_id, provider_name, provider_subject_hash),
            ).fetchone()
            provider_id_conflict = conn.execute(
                "SELECT provider_identity_id, account_id, person_id FROM identity_public_provider_identities WHERE provider_identity_id = ? LIMIT 1",
                (provider_id,),
            ).fetchone()
            for conflict in (provider_conflict, provider_id_conflict):
                if conflict and (str(conflict[1]) != account_id or str(conflict[2] or "") != person_id):
                    conn.rollback()
                    return {}
            if provider_conflict and str(provider_conflict[0]) != provider_id:
                provider_id = str(provider_conflict[0])

        conn.execute(
            """
            INSERT INTO identity_public_accounts(
                account_id, workspace_id, email_hash, email_provider_subject_hash, email_hint, person_id, status,
                email_verified_at, profile_completion_state, tenant_entitlement_state,
                localpro_application_state, localpro_authorization_state,
                accepted_terms_version, locale, display_name, deletion_status,
                password_hash, password_hash_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'tenant_active', ?, 'complete', 'active', 'not_started', 'not_issued', ?, ?, ?, 'not_requested', ?, ?, ?, ?)
            ON CONFLICT(account_id) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                email_hash = excluded.email_hash,
                email_provider_subject_hash = excluded.email_provider_subject_hash,
                email_hint = excluded.email_hint,
                person_id = excluded.person_id,
                status = excluded.status,
                email_verified_at = excluded.email_verified_at,
                profile_completion_state = excluded.profile_completion_state,
                tenant_entitlement_state = excluded.tenant_entitlement_state,
                localpro_application_state = excluded.localpro_application_state,
                localpro_authorization_state = excluded.localpro_authorization_state,
                accepted_terms_version = excluded.accepted_terms_version,
                locale = excluded.locale,
                display_name = excluded.display_name,
                deletion_status = excluded.deletion_status,
                password_hash = excluded.password_hash,
                password_hash_version = excluded.password_hash_version,
                updated_at = excluded.updated_at
            """,
            (
                account_id,
                workspace_id,
                email_hash,
                _clean(account.get("email_provider_subject_hash"), 128),
                _clean(account.get("email_hint"), 80),
                person_id,
                now,
                _clean(account.get("accepted_terms_version"), 80),
                _clean(account.get("locale") or "en", 20),
                _clean(account.get("display_name") or "LiveUIN QA Tenant", 160),
                "founder_qa_access_only",
                "founder_qa_no_password",
                int(existing.get("created_at") or now),
                now,
            ),
        )
        if provider_id and provider_name and provider_subject_hash:
            conn.execute(
                """
                INSERT INTO identity_public_provider_identities(
                    provider_identity_id, workspace_id, provider, subject_hash, subject_hint,
                    account_id, person_id, verified_email_hash, verified_email_state,
                    link_state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'verified', 'linked', ?, ?)
                ON CONFLICT(provider_identity_id) DO UPDATE SET
                    workspace_id = excluded.workspace_id,
                    provider = excluded.provider,
                    subject_hash = excluded.subject_hash,
                    subject_hint = excluded.subject_hint,
                    account_id = excluded.account_id,
                    person_id = excluded.person_id,
                    verified_email_hash = excluded.verified_email_hash,
                    verified_email_state = excluded.verified_email_state,
                    link_state = excluded.link_state,
                    updated_at = excluded.updated_at
                """,
                (
                    provider_id,
                    workspace_id,
                    provider_name,
                    provider_subject_hash,
                    _clean(provider.get("subject_hint"), 80),
                    account_id,
                    person_id,
                    _clean(provider.get("verified_email_hash"), 128),
                    now,
                    now,
                ),
            )
        _audit_conn(
            conn,
            account_id=account_id,
            registration_id="",
            workspace_id=workspace_id,
            event_type="identity.public.founder_qa_account_ready",
            payload={
                "staging_only": True,
                "email_verification_bypassed": True,
                "password_sign_in_disabled": True,
                "provider_linked": bool(provider_id),
            },
            request_meta=request_meta,
        )
        conn.commit()
    return get_account(account_id)


def create_refresh_credential(
    *,
    refresh_token_hash: str,
    account_id: str,
    workspace_id: str,
    session_id_hash: str,
    issued_at: int,
    expires_at: int,
) -> Dict[str, Any]:
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO identity_public_refresh_credentials(
                refresh_id_hash, account_id, workspace_id, session_id_hash,
                status, issued_at, expires_at, revoked_at, revoked_reason,
                rotated_to_hash, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'active', ?, ?, 0, '', '', ?, ?)
            """,
            (
                _clean(refresh_token_hash, 128), _clean_id(account_id), _clean_id(workspace_id, 96),
                _clean(session_id_hash, 128),
                int(issued_at), int(expires_at), _now(), _now(),
            ),
        )
        conn.commit()
    return get_refresh_by_hash(refresh_token_hash)


def get_refresh_by_hash(refresh_token_hash: str) -> Dict[str, Any]:
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM identity_public_refresh_credentials WHERE refresh_id_hash = ? LIMIT 1",
            (_clean(refresh_token_hash, 128),),
        ).fetchone()
    if not row:
        return {}
    data = dict(row)
    return {
        "refresh_id_hash": _clean(data.get("refresh_id_hash"), 128),
        "account_id": _clean_id(data.get("account_id")),
        "workspace_id": _clean_id(data.get("workspace_id"), 96),
        "session_id_hash": _clean(data.get("session_id_hash"), 128),
        "status": _clean(data.get("status") or "active", 40),
        "issued_at": int(data.get("issued_at") or 0),
        "expires_at": int(data.get("expires_at") or 0),
        "revoked_at": int(data.get("revoked_at") or 0),
        "revoked_reason": _clean(data.get("revoked_reason"), 120),
        "rotated_to_hash": _clean(data.get("rotated_to_hash"), 128),
    }


def rotate_refresh(old_hash: str, new_hash: str, request_meta: Dict[str, Any] | None = None) -> bool:
    result = rotate_refresh_atomic(
        old_hash,
        new_hash,
        session_id_hash="",
        issued_at=_now(),
        expires_at=_now() + 1,
        request_meta=request_meta,
    )
    return bool(result.get("ok"))


def rotate_refresh_atomic(
    old_hash: str,
    new_hash: str,
    *,
    session_id_hash: str,
    issued_at: int,
    expires_at: int,
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    now = _now()
    with connection() as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            old_row = conn.execute(
                "SELECT * FROM identity_public_refresh_credentials WHERE refresh_id_hash = ? AND status = 'active' AND expires_at > ? LIMIT 1",
                (_clean(old_hash, 128), now),
            ).fetchone()
            if not old_row:
                conn.rollback()
                return {"ok": False, "reason": "refresh_not_active"}
            old = dict(old_row)
            changed = conn.execute(
                "UPDATE identity_public_refresh_credentials SET status = 'rotated', rotated_to_hash = ?, revoked_at = ?, revoked_reason = 'refresh_rotation', updated_at = ? WHERE refresh_id_hash = ? AND status = 'active'",
                (_clean(new_hash, 128), now, now, _clean(old_hash, 128)),
            ).rowcount
            if changed != 1:
                conn.rollback()
                return {"ok": False, "reason": "refresh_race_lost"}
            conn.execute(
                """
                INSERT INTO identity_public_refresh_credentials(
                    refresh_id_hash, account_id, workspace_id, session_id_hash,
                    status, issued_at, expires_at, revoked_at, revoked_reason,
                    rotated_to_hash, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'active', ?, ?, 0, '', '', ?, ?)
                """,
                (
                    _clean(new_hash, 128), _clean_id(old.get("account_id")), _clean_id(old.get("workspace_id"), 96),
                    _clean(session_id_hash, 128), int(issued_at), int(expires_at), now, now,
                ),
            )
            _audit_conn(
                conn,
                account_id=_clean_id(old.get("account_id")),
                registration_id="",
                workspace_id=_clean_id(old.get("workspace_id"), 96),
                event_type="identity.public.refresh_rotated",
                payload={"old_refresh_revoked": True, "atomic": True},
                request_meta=request_meta,
            )
            conn.commit()
            return {"ok": True, "account_id": _clean_id(old.get("account_id")), "workspace_id": _clean_id(old.get("workspace_id"), 96), "old_session_id_hash": _clean(old.get("session_id_hash"), 128)}
        except Exception:
            conn.rollback()
            raise


def revoke_refresh_for_session(session_id_hash: str, reason: str = "logout") -> int:
    if not session_id_hash:
        return 0
    now = _now()
    with connection() as conn:
        result = conn.execute(
            "UPDATE identity_public_refresh_credentials SET status = 'revoked', revoked_at = ?, revoked_reason = ?, updated_at = ? WHERE session_id_hash = ? AND status = 'active'",
            (now, _clean(reason, 120), now, _clean(session_id_hash, 128)),
        )
        conn.commit()
    return int(result.rowcount or 0)


def revoke_refresh_for_account(account_id: str, reason: str = "password_reset") -> int:
    if not _clean_id(account_id):
        return 0
    now = _now()
    with connection() as conn:
        result = conn.execute(
            "UPDATE identity_public_refresh_credentials SET status = 'revoked', revoked_at = ?, revoked_reason = ?, updated_at = ? WHERE account_id = ? AND status = 'active'",
            (now, _clean(reason, 120), now, _clean_id(account_id)),
        )
        conn.commit()
    return int(result.rowcount or 0)


def retire_account_continuations(account_id: str, workspace_id: str = "", reason: str = "account_deletion") -> Dict[str, int]:
    account_id = _clean_id(account_id)
    workspace_id = _clean_id(workspace_id, 96)
    if not account_id:
        return {"password_resets": 0, "registrations": 0}
    now = _now()
    with connection() as conn:
        clauses = ["account_id = ?"]
        params: List[Any] = [account_id]
        if workspace_id:
            clauses.append("workspace_id = ?")
            params.append(workspace_id)
        reset_result = conn.execute(
            f"UPDATE identity_public_password_resets SET status = 'cancelled', verification_code_hash = '', reset_token_hash = '', updated_at = ? WHERE {' AND '.join(clauses)} AND status NOT IN ('completed', 'cancelled', 'superseded', 'retired')",
            tuple([now] + params),
        )
        registration_result = conn.execute(
            f"UPDATE identity_public_registrations SET status = 'cancelled', verification_code_hash = '', updated_at = ? WHERE {' AND '.join(clauses)} AND status NOT IN ('completed', 'cancelled', 'superseded')",
            tuple([now] + params),
        )
        conn.commit()
    return {"password_resets": int(reset_result.rowcount or 0), "registrations": int(registration_result.rowcount or 0)}


def finalize_account_deletion(account_id: str, workspace_id: str = "", request_meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    account_id = _clean_id(account_id)
    workspace_id = _clean_id(workspace_id, 96)
    if not account_id:
        return {}
    account = get_account(account_id)
    if not account or (workspace_id and account.get("workspace_id") != workspace_id):
        return {}
    now = _now()
    with connection() as conn:
        # step30c: email_hash was set to '' which violates UNIQUE(workspace_id, email_hash) for the SECOND deleted account in a
        # workspace; a per-account tombstone ('deleted:<account_id>', no email information) keeps rows unique and unmatchable.
        conn.execute(
            """
            UPDATE identity_public_accounts
            SET email_hash = 'deleted:' || account_id, email_provider_subject_hash = '', email_hint = '', person_id = '',
                status = 'account_disabled', profile_completion_state = 'deleted',
                tenant_entitlement_state = 'revoked', localpro_application_state = 'not_started',
                localpro_authorization_state = 'not_issued', display_name = 'Deleted account',
                deletion_status = 'deleted', password_hash = '', password_hash_version = 'deleted',
                updated_at = ?
            WHERE account_id = ?
            """,
            (now, account_id),
        )
        _audit_conn(
            conn,
            account_id=account_id,
            registration_id="",
            workspace_id=account.get("workspace_id") or workspace_id,
            event_type="identity.public.account_deletion_pseudonymized",
            payload={"pseudonymized": True, "password_invalidated": True, "raw_identity_removed": True},
            request_meta=request_meta,
        )
        conn.commit()
    return get_account(account_id)


def _password_reset(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}
    data = dict(row)
    return {
        "reset_id": _clean_id(data.get("reset_id")),
        "account_id": _clean_id(data.get("account_id")),
        "is_decoy": not bool(_clean_id(data.get("account_id"))),
        "workspace_id": _clean_id(data.get("workspace_id"), 96),
        "email_hash": _clean(data.get("email_hash"), 128),
        "verification_code_hash": _clean(data.get("verification_code_hash"), 128),
        "reset_token_hash": _clean(data.get("reset_token_hash"), 128),
        "status": _clean(data.get("status") or "verification_pending", 40),
        "attempts": int(data.get("attempts") or 0),
        "max_attempts": int(data.get("max_attempts") or 5),
        "issued_at": int(data.get("issued_at") or 0),
        "expires_at": int(data.get("expires_at") or 0),
        "verified_at": int(data.get("verified_at") or 0),
        "completed_at": int(data.get("completed_at") or 0),
        "idempotency_key_hash": _clean(data.get("idempotency_key_hash"), 128),
        "delivery_mode": _clean(data.get("delivery_mode"), 40),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
    }


def get_password_reset(reset_id: str, workspace_id: str = "") -> Dict[str, Any]:
    clean_reset_id = _clean_id(reset_id, 96)
    clean_workspace_id = _clean_id(workspace_id, 96)
    if not clean_reset_id:
        return {}
    with connection() as conn:
        if clean_workspace_id:
            row = conn.execute(
                "SELECT * FROM identity_public_password_resets WHERE reset_id = ? AND workspace_id = ? LIMIT 1",
                (clean_reset_id, clean_workspace_id),
            ).fetchone()
        else:
            row = conn.execute("SELECT * FROM identity_public_password_resets WHERE reset_id = ? LIMIT 1", (clean_reset_id,)).fetchone()
    return _password_reset(row)


def get_password_reset_by_idempotency(idempotency_key_hash: str, workspace_id: str = "") -> Dict[str, Any]:
    key = _clean(idempotency_key_hash, 128)
    clean_workspace_id = _clean_id(workspace_id, 96)
    if not key or not clean_workspace_id:
        return {}
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM identity_public_password_resets WHERE workspace_id = ? AND idempotency_key_hash = ? ORDER BY updated_at DESC LIMIT 1",
            (clean_workspace_id, key),
        ).fetchone()
    return _password_reset(row)


def _notification_delivery(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}
    data = dict(row)
    return {
        "notification_id": _clean_id(data.get("notification_id"), 160),
        "template": _clean(data.get("template"), 80),
        "correlation_id": _clean_id(data.get("correlation_id"), 160),
        "recipient_hash": _clean(data.get("recipient_hash"), 128),
        "request_id": _clean(data.get("request_id"), 80),
        "idempotency_key_hash": _clean(data.get("idempotency_key_hash"), 128),
        "transport": _clean(data.get("transport"), 40),
        "status": _clean(data.get("status") or "CREATED", 32),
        "result_code": _clean(data.get("result_code"), 80),
        "provider_reference": _clean(data.get("provider_reference"), 160),
        "attempt_count": int(data.get("attempt_count") or 0),
        "created_at": int(data.get("created_at") or 0),
        "updated_at": int(data.get("updated_at") or 0),
    }


def get_notification_delivery(notification_id: str = "", idempotency_key_hash: str = "") -> Dict[str, Any]:
    notification_id = _clean_id(notification_id, 160)
    idempotency_key_hash = _clean(idempotency_key_hash, 128)
    if not notification_id and not idempotency_key_hash:
        return {}
    with connection() as conn:
        if notification_id:
            row = conn.execute(
                "SELECT * FROM identity_notification_deliveries WHERE notification_id = ? LIMIT 1",
                (notification_id,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM identity_notification_deliveries WHERE idempotency_key_hash = ? LIMIT 1",
                (idempotency_key_hash,),
            ).fetchone()
    return _notification_delivery(row)


def prepare_notification_delivery(record: Dict[str, Any]) -> Dict[str, Any]:
    """Atomically claim an idempotency key without storing message secrets."""
    now = _now()
    notification_id = _clean_id(record.get("notification_id"), 160)
    idempotency_key_hash = _clean(record.get("idempotency_key_hash"), 128)
    if not notification_id or not idempotency_key_hash:
        return {"created": False, "record": {}}
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM identity_notification_deliveries WHERE idempotency_key_hash = ? LIMIT 1",
            (idempotency_key_hash,),
        ).fetchone()
        if row:
            conn.commit()
            return {"created": False, "record": _notification_delivery(row)}
        try:
            conn.execute(
                """
                INSERT INTO identity_notification_deliveries(
                    notification_id, template, correlation_id, recipient_hash, request_id,
                    idempotency_key_hash, transport, status, result_code, provider_reference,
                    attempt_count, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'CREATED', '', '', 0, ?, ?)
                """,
                (
                    notification_id,
                    _clean(record.get("template"), 80),
                    _clean_id(record.get("correlation_id"), 160),
                    _clean(record.get("recipient_hash"), 128),
                    _clean(record.get("request_id"), 80),
                    idempotency_key_hash,
                    _clean(record.get("transport"), 40),
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError:
            row = conn.execute(
                "SELECT * FROM identity_notification_deliveries WHERE notification_id = ? OR idempotency_key_hash = ? LIMIT 1",
                (notification_id, idempotency_key_hash),
            ).fetchone()
            conn.commit()
            return {"created": False, "record": _notification_delivery(row)}
        conn.commit()
        row = conn.execute(
            "SELECT * FROM identity_notification_deliveries WHERE notification_id = ? LIMIT 1",
            (notification_id,),
        ).fetchone()
    return {"created": True, "record": _notification_delivery(row)}


def update_notification_delivery(
    notification_id: str,
    *,
    status: str,
    result_code: str = "",
    provider_reference: str = "",
    attempt_count: int = 0,
) -> Dict[str, Any]:
    notification_id = _clean_id(notification_id, 160)
    if not notification_id:
        return {}
    if status not in NOTIFICATION_DELIVERY_STATES:
        return {}
    now = _now()
    with connection() as conn:
        conn.execute(
            """
            UPDATE identity_notification_deliveries
            SET status = ?, result_code = ?, provider_reference = ?, attempt_count = ?, updated_at = ?
            WHERE notification_id = ?
            """,
            (
                _clean(status, 32),
                _clean(result_code, 80),
                _clean(provider_reference, 160),
                max(0, min(20, int(attempt_count or 0))),
                now,
                notification_id,
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM identity_notification_deliveries WHERE notification_id = ? LIMIT 1",
            (notification_id,),
        ).fetchone()
    return _notification_delivery(row)


def get_password_reset_by_token_hash(reset_token_hash: str, workspace_id: str = "") -> Dict[str, Any]:
    token_hash = _clean(reset_token_hash, 128)
    clean_workspace_id = _clean_id(workspace_id, 96)
    if not token_hash:
        return {}
    with connection() as conn:
        if clean_workspace_id:
            row = conn.execute(
                "SELECT * FROM identity_public_password_resets WHERE reset_token_hash = ? AND workspace_id = ? AND status = 'verified' LIMIT 1",
                (token_hash, clean_workspace_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM identity_public_password_resets WHERE reset_token_hash = ? AND status = 'verified' LIMIT 1",
                (token_hash,),
            ).fetchone()
    return _password_reset(row)


def create_password_reset(record: Dict[str, Any], request_meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    now = _now()
    reset_id = _clean_id(record["reset_id"], 96)
    workspace_id = _clean_id(record["workspace_id"], 96)
    idempotency_key_hash = _clean(record.get("idempotency_key_hash"), 128)
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if idempotency_key_hash:
            existing = conn.execute(
                "SELECT * FROM identity_public_password_resets WHERE workspace_id = ? AND idempotency_key_hash = ? ORDER BY updated_at DESC LIMIT 1",
                (workspace_id, idempotency_key_hash),
            ).fetchone()
            if existing:
                conn.commit()
                return _password_reset(existing)
        conn.execute(
            """
            INSERT INTO identity_public_password_resets(
                reset_id, account_id, workspace_id, email_hash, verification_code_hash,
                reset_token_hash, status, attempts, max_attempts, issued_at, expires_at,
                verified_at, completed_at, idempotency_key_hash, delivery_mode, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, '', 'verification_pending', 0, ?, ?, ?, 0, 0, ?, ?, ?, ?)
            """,
            (
                reset_id, (record.get("account_id") or None), workspace_id,
                _clean(record["email_hash"], 128), _clean(record["verification_code_hash"], 128),
                max(1, min(10, int(record.get("max_attempts") or 5))), int(record.get("issued_at") or now),
                int(record["expires_at"]), idempotency_key_hash,
                _clean(record.get("delivery_mode"), 40), int(record.get("created_at") or now), int(record.get("updated_at") or now),
            ),
        )
        _audit_conn(
            conn,
            account_id=record.get("account_id", ""),
            registration_id="",
            workspace_id=workspace_id,
            event_type="identity.public.password_reset_requested",
            payload={"enumeration_safe": True, "decoy": not bool(record.get("account_id"))},
            request_meta=request_meta,
        )
        conn.commit()
    return get_password_reset(reset_id, workspace_id)


def supersede_password_resets_for_account(
    account_id: str,
    workspace_id: str,
    keep_reset_id: str,
    request_meta: Dict[str, Any] | None = None,
) -> int:
    account_id = _clean_id(account_id)
    workspace_id = _clean_id(workspace_id, 96)
    keep_reset_id = _clean_id(keep_reset_id, 96)
    if not account_id or not workspace_id:
        return 0
    now = _now()
    with connection() as conn:
        rows = conn.execute(
            "SELECT reset_id FROM identity_public_password_resets WHERE account_id = ? AND workspace_id = ? AND reset_id <> ? AND status IN ('verification_pending', 'verified', 'delivery_failed')",
            (account_id, workspace_id, keep_reset_id),
        ).fetchall()
        if not rows:
            return 0
        conn.execute(
            "UPDATE identity_public_password_resets SET status = 'superseded', verification_code_hash = '', reset_token_hash = '', updated_at = ? WHERE account_id = ? AND workspace_id = ? AND reset_id <> ? AND status IN ('verification_pending', 'verified', 'delivery_failed')",
            (now, account_id, workspace_id, keep_reset_id),
        )
        _audit_conn(
            conn,
            account_id=account_id,
            registration_id="",
            workspace_id=workspace_id,
            event_type="identity.public.password_reset_superseded",
            payload={"superseded_count": len(rows), "keep_reset_id_present": bool(keep_reset_id)},
            request_meta=request_meta,
        )
        conn.commit()
    return len(rows)


def retire_password_reset(
    reset_id: str,
    workspace_id: str,
    *,
    reason: str,
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    reset_id = _clean_id(reset_id, 96)
    workspace_id = _clean_id(workspace_id, 96)
    if not reset_id or not workspace_id:
        return {}
    now = _now()
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM identity_public_password_resets WHERE reset_id = ? AND workspace_id = ? LIMIT 1",
            (reset_id, workspace_id),
        ).fetchone()
        if not row:
            return {}
        reset = _password_reset(row)
        conn.execute(
            "UPDATE identity_public_password_resets SET status = 'retired', verification_code_hash = '', reset_token_hash = '', updated_at = ? WHERE reset_id = ? AND workspace_id = ? AND status <> 'completed'",
            (now, reset_id, workspace_id),
        )
        _audit_conn(
            conn,
            account_id=reset.get("account_id", ""),
            registration_id="",
            workspace_id=workspace_id,
            event_type="identity.public.password_reset_retired",
            payload={"reason": _clean(reason, 120), "reset_id_present": True},
            request_meta=request_meta,
        )
        conn.commit()
    return get_password_reset(reset_id, workspace_id)


def mark_password_reset_delivery_failed(reset_id: str, request_meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    reset = get_password_reset(reset_id)
    if not reset:
        return {}
    now = _now()
    with connection() as conn:
        conn.execute("UPDATE identity_public_password_resets SET status = 'delivery_failed', updated_at = ? WHERE reset_id = ?", (now, reset_id))
        _audit_conn(conn, account_id=reset["account_id"], registration_id="", workspace_id=reset["workspace_id"], event_type="identity.public.password_reset_delivery_failed", payload={}, request_meta=request_meta)
        conn.commit()
    return get_password_reset(reset_id)


def mark_password_reset_attempt(reset_id: str, *, success: bool, reset_token_hash: str = "", workspace_id: str = "", request_meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    reset = get_password_reset(reset_id, workspace_id)
    if not reset:
        return {}
    now = _now()
    attempts = reset["attempts"] + 1
    status = "verified" if success else ("locked" if attempts >= reset["max_attempts"] else "verification_pending")
    with connection() as conn:
        changed = conn.execute(
            "UPDATE identity_public_password_resets SET attempts = ?, status = ?, reset_token_hash = ?, verified_at = ?, updated_at = ? WHERE reset_id = ? AND workspace_id = ? AND status = 'verification_pending'",
            (attempts, status, _clean(reset_token_hash, 128), now if success else 0, now, reset_id, _clean_id(workspace_id, 96) if workspace_id else reset["workspace_id"]),
        ).rowcount
        if int(changed or 0) != 1:
            conn.rollback()
            current = get_password_reset(reset_id)
            current["claim_won"] = False
            return current
        _audit_conn(conn, account_id=reset["account_id"], registration_id="", workspace_id=reset["workspace_id"], event_type="identity.public.password_reset_verified" if success else "identity.public.password_reset_verification_failed", payload={"attempts": attempts}, request_meta=request_meta)
        conn.commit()
    current = get_password_reset(reset_id)
    current["claim_won"] = True
    return current


def complete_password_reset(reset_token_hash: str, password_hash: str, password_hash_version: str, workspace_id: str = "", request_meta: Dict[str, Any] | None = None) -> Dict[str, Any]:
    token_hash = _clean(reset_token_hash, 128)
    clean_workspace_id = _clean_id(workspace_id, 96)
    with connection() as conn:
        if clean_workspace_id:
            row = conn.execute("SELECT * FROM identity_public_password_resets WHERE reset_token_hash = ? AND workspace_id = ? AND status = 'verified' LIMIT 1", (token_hash, clean_workspace_id)).fetchone()
        else:
            row = conn.execute("SELECT * FROM identity_public_password_resets WHERE reset_token_hash = ? AND status = 'verified' LIMIT 1", (token_hash,)).fetchone()
        if not row:
            return {}
        reset = _password_reset(row)
        now = _now()
        conn.execute(
            "UPDATE identity_public_password_resets SET status = 'completed', completed_at = ?, updated_at = ? WHERE reset_id = ? AND status = 'verified'",
            (now, now, reset["reset_id"]),
        )
        if reset.get("account_id"):
            conn.execute(
                "UPDATE identity_public_accounts SET password_hash = ?, password_hash_version = ?, status = CASE WHEN status = 'account_disabled' THEN status ELSE status END, updated_at = ? WHERE account_id = ?",
                (_clean(password_hash, 240), _clean(password_hash_version, 80), now, reset["account_id"]),
            )
        _audit_conn(conn, account_id=reset["account_id"], registration_id="", workspace_id=reset["workspace_id"], event_type="identity.public.password_reset_completed", payload={}, request_meta=request_meta)
        conn.commit()
    return get_password_reset(reset["reset_id"])


def allow_rate(rate_type: str, key: str, *, limit: int, window_seconds: int) -> bool:
    now = _now()
    key_hash = hash_value(f"{rate_type}:{key}")
    with connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            cutoff = now - max(1, int(window_seconds))
            count = conn.execute(
                "SELECT COUNT(*) FROM identity_public_rate_events WHERE rate_key_hash = ? AND event_type = ? AND created_at >= ?",
                (key_hash, _clean(rate_type, 80), cutoff),
            ).fetchone()[0]
            if int(count) >= int(limit):
                conn.rollback()
                return False
            conn.execute(
                "INSERT INTO identity_public_rate_events(event_id, rate_key_hash, event_type, created_at) VALUES (?, ?, ?, ?)",
                ("rate_" + uuid.uuid4().hex[:20], key_hash, _clean(rate_type, 80), now),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return True


def _audit_conn(
    conn: sqlite3.Connection,
    *,
    account_id: str,
    registration_id: str,
    workspace_id: str,
    event_type: str,
    payload: Dict[str, Any] | None,
    request_meta: Dict[str, Any] | None,
) -> None:
    conn.execute(
        """
        INSERT INTO identity_public_audit_events(
            event_id, account_id, registration_id, workspace_id, event_type,
            payload_json, request_meta_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "p2a_evt_" + uuid.uuid4().hex[:20], _clean_id(account_id), _clean_id(registration_id),
            _clean_id(workspace_id, 96), _clean(event_type, 120),
            _json(payload or {}), _json(request_meta or {}), _now(),
        ),
    )


def append_audit_event(
    *,
    account_id: str,
    registration_id: str = "",
    workspace_id: str = "",
    event_type: str,
    payload: Dict[str, Any] | None = None,
    request_meta: Dict[str, Any] | None = None,
) -> None:
    with connection() as conn:
        _audit_conn(conn, account_id=account_id, registration_id=registration_id, workspace_id=workspace_id, event_type=event_type, payload=payload, request_meta=request_meta)
        conn.commit()


def debug_summary() -> Dict[str, Any]:
    with connection() as conn:
        counts = {}
        for table in (
            "identity_public_accounts", "identity_public_registrations",
            "identity_public_refresh_credentials", "identity_public_audit_events",
        ):
            counts[table] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
    with connection() as conn:
        migrations = [dict(row) for row in conn.execute("SELECT version, checksum, applied_at FROM identity_public_schema_migrations ORDER BY applied_at").fetchall()]
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "migration": MIGRATION_VERSION,
        "migration_checksum": MIGRATION_CHECKSUM,
        "sqlite_path": str(sqlite_path()),
        "backup_dir": str(backup_dir()),
        "tables": counts,
        "migrations": migrations,
    }


def backup_snapshot(destination: str = "") -> Dict[str, Any]:
    target_dir = Path(destination).expanduser().resolve() if destination else backup_dir()
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = target_dir / f"liveuin-core-identity-public-{_now()}.sqlite3"
    source = sqlite_path()
    with connection() as conn, sqlite3.connect(target) as backup_conn:
        conn.backup(backup_conn)
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return {"ok": True, "source": str(source), "backup": str(target), "retention_days": int(os.getenv("LIVEUIN_CORE_IDENTITY_PUBLIC_BACKUP_RETENTION_DAYS", "14"))}
