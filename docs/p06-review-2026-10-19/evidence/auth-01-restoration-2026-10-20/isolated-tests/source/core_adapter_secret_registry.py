from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List


SCHEMA_VERSION = "liveuin-adapter-secret-registry-v1"
PHASE = "phase28-adapter-secret-reference-rotation"
DEFAULT_WORKSPACE_ID = "laijuzhu"
CANONICAL_OWNER = "LiveUIN Core/Admin Access Governance"

ACTIVE_STATUSES = {"active"}
INACTIVE_STATUSES = {"expired", "revoked", "rotated"}
ALL_STATUSES = ACTIVE_STATUSES | INACTIVE_STATUSES

SAFE_SECRET_KEYS = {
    "rotated_from_secret_ref_id",
    "secret_env_var",
    "secret_hash",
    "secret_hash_prefix",
    "secret_prefix",
    "secret_ref_id",
}
SENSITIVE_KEYS = {
    "api_key",
    "api_v3_key",
    "authorization",
    "bearer",
    "client_secret",
    "endpoint_secret",
    "password",
    "private_key",
    "raw_secret",
    "secret",
    "signature",
    "token",
    "webhook_salt",
}


def data_dir() -> Path:
    configured = os.getenv("LIVEUIN_CORE_ADAPTER_SECRET_DATA_DIR", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[1] / "outputs" / "core-adapter-secret-data"


def sqlite_path() -> Path:
    configured = os.getenv("LIVEUIN_CORE_ADAPTER_SECRET_SQLITE_PATH", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return data_dir() / "liveuin-core-adapter-secret.sqlite3"


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


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _to_int(value: Any, default: int = 0) -> int:
    if value in (None, ""):
        return default
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return default


def _clean_id(value: Any, max_length: int = 160) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]", "", str(value or "").strip())[:max_length]


def _clean_slug(value: Any, default: str = "", max_length: int = 120) -> str:
    cleaned = re.sub(r"[^a-z0-9_.:-]+", "_", str(value or "").strip().lower()).strip("_")
    return (cleaned or default)[:max_length]


def _clean_env_var(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "", str(value or "").strip().upper())[:160]


def _secret_env_key(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", str(value or "").strip()).strip("_").upper()


def _hash_secret(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _hash_prefix(secret_hash: str) -> str:
    return str(secret_hash or "")[:12]


def _now() -> int:
    return int(time.time())


def _redact(value: Any) -> Any:
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if not isinstance(value, dict):
        return value
    cleaned: Dict[str, Any] = {}
    for key, item in value.items():
        normalized = str(key).lower()
        if normalized in SAFE_SECRET_KEYS:
            cleaned[str(key)] = _redact(item)
        elif normalized in SENSITIVE_KEYS or normalized.endswith("_secret") or normalized.endswith("_token"):
            cleaned[str(key)] = "[redacted]"
        else:
            cleaned[str(key)] = _redact(item)
    return cleaned


def _provider_slug(value: Any) -> str:
    raw = _clean_slug(value, "", 80).replace("-", "_")
    if raw in {"wechat", "wechatpay", "wechat_pay"}:
        return "wechat_pay"
    return raw


def _purpose_slug(value: Any, provider: str = "") -> str:
    raw = _clean_slug(value, "", 120).replace("-", "_")
    provider = _provider_slug(provider)
    if raw in {"", "webhook", "webhook_signature", "endpoint_secret"}:
        if provider == "stripe":
            return "stripe_webhook_signature"
        if provider == "hitpay":
            return "hitpay_webhook_signature"
        if provider == "alipay":
            return "alipay_webhook_signature"
    if raw in {"api_v3", "api_v3_key"} and provider == "wechat_pay":
        return "wechat_pay_api_v3_key"
    return raw or "adapter_signature"


def _secret_ref_id(payload: Dict[str, Any]) -> str:
    explicit = _clean_id(payload.get("secret_ref_id") or payload.get("new_secret_ref_id"), 160)
    if explicit:
        return explicit
    provider = _provider_slug(payload.get("provider"))
    purpose = _purpose_slug(payload.get("purpose"), provider)
    adapter_id = _clean_id(payload.get("adapter_id"), 80)
    seed = "-".join(part for part in (provider or adapter_id or "adapter", purpose, uuid.uuid4().hex[:12]) if part)
    return _clean_id("secret_" + seed, 160)


def _status(value: Any) -> str:
    status = _clean_slug(value, "active", 40)
    return status if status in ALL_STATUSES else "active"


def _env(*names: str) -> Dict[str, str]:
    for name in names:
        env_name = _clean_env_var(name)
        if not env_name:
            continue
        value = str(os.getenv(env_name) or "").strip()
        if value:
            return {"secret": value, "secret_env_var": env_name}
    return {"secret": "", "secret_env_var": ""}


def _runtime_secret(secret_env_var: str) -> Dict[str, str]:
    env_var = _clean_env_var(secret_env_var)
    empty = {
        "secret": "",
        "secret_source": "",
        "secret_env_var": env_var,
        "secret_credential_name": "",
    }
    if not env_var:
        return empty

    env_value = str(os.getenv(env_var) or "").strip()
    if env_value:
        return {
            "secret": env_value,
            "secret_source": "registered_secret_environment",
            "secret_env_var": env_var,
            "secret_credential_name": "",
        }

    for directory_key in ("CREDENTIALS_DIRECTORY", "LIVEUIN_SECRET_CREDENTIALS_DIR"):
        directory_value = str(os.getenv(directory_key) or "").strip()
        if not directory_value:
            continue
        directory = Path(directory_value).expanduser().resolve()
        candidate = (directory / env_var).resolve()
        try:
            candidate.relative_to(directory)
        except ValueError:
            continue
        if not candidate.is_file() or candidate.stat().st_size > 65536:
            continue
        secret_value = candidate.read_text(encoding="utf-8").strip()
        if secret_value:
            return {
                "secret": secret_value,
                "secret_source": "registered_systemd_credential",
                "secret_env_var": env_var,
                "secret_credential_name": env_var,
            }

    return empty


def _secrets_map() -> Dict[str, str]:
    raw = str(os.getenv("LIVEUIN_ADAPTER_SIGNATURE_SECRETS") or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(key): str(value) for key, value in parsed.items() if str(value)}


def _adapter_env_fallback(adapter_id: str, source_family: str) -> Dict[str, str]:
    secrets_map = _secrets_map()
    for key in (adapter_id, source_family, "default"):
        if key and secrets_map.get(key):
            return {
                "secret": secrets_map[key],
                "secret_source": "LIVEUIN_ADAPTER_SIGNATURE_SECRETS",
                "secret_env_var": "LIVEUIN_ADAPTER_SIGNATURE_SECRETS",
                "secret_map_key": key,
            }
    for key in (adapter_id, source_family):
        env_key = _secret_env_key(key)
        if env_key:
            resolved = _env("LIVEUIN_ADAPTER_SIGNATURE_SECRET_" + env_key)
            if resolved.get("secret"):
                return {
                    **resolved,
                    "secret_source": "adapter_signature_env",
                    "secret_map_key": key,
                }
    resolved = _env("LIVEUIN_ADAPTER_SIGNATURE_SECRET")
    if resolved.get("secret"):
        return {**resolved, "secret_source": "adapter_signature_env_default", "secret_map_key": "default"}
    return {"secret": "", "secret_source": "", "secret_env_var": "", "secret_map_key": ""}


def _provider_env_fallback(provider: str, purpose: str) -> Dict[str, str]:
    provider = _provider_slug(provider)
    purpose = _purpose_slug(purpose, provider)
    if provider == "stripe" and purpose == "stripe_webhook_signature":
        candidates = (
            "STRIPE_WEBHOOK_ENDPOINT_SECRET",
            "LIVEUIN_STRIPE_WEBHOOK_ENDPOINT_SECRET",
            "LIVEUIN_PROVIDER_SECRET_STRIPE_WEBHOOK",
            "LIVEUIN_PROVIDER_SECRET_STRIPE",
        )
        for candidate in candidates:
            # Supports both the legacy environment fallback and protected systemd credentials.
            resolved = _runtime_secret(candidate)
            if resolved.get("secret"):
                return {**resolved, "secret_source": str(resolved.get("secret_source") or "provider_edge_env")}
        return {"secret": "", "secret_env_var": "", "secret_source": ""}
    if provider == "hitpay" and purpose == "hitpay_webhook_signature":
        resolved = _env(
            "HITPAY_WEBHOOK_SALT",
            "LIVEUIN_HITPAY_WEBHOOK_SALT",
            "LIVEUIN_PROVIDER_SECRET_HITPAY_WEBHOOK",
            "LIVEUIN_PROVIDER_SECRET_HITPAY",
        )
        return {**resolved, "secret_source": "provider_edge_env"} if resolved.get("secret") else {**resolved, "secret_source": ""}
    if provider == "wechat_pay" and purpose == "wechat_pay_api_v3_key":
        resolved = _env(
            "WECHAT_PAY_API_V3_KEY",
            "LIVEUIN_WECHAT_PAY_API_V3_KEY",
            "LIVEUIN_PROVIDER_SECRET_WECHAT_PAY_API_V3_KEY",
            "LIVEUIN_PROVIDER_SECRET_WECHAT_PAY",
        )
        return {**resolved, "secret_source": "provider_edge_env"} if resolved.get("secret") else {**resolved, "secret_source": ""}
    if provider == "alipay" and purpose == "alipay_webhook_signature":
        resolved = _env(
            "ALIPAY_WEBHOOK_PUBLIC_KEY",
            "LIVEUIN_ALIPAY_WEBHOOK_PUBLIC_KEY",
            "LIVEUIN_PROVIDER_SECRET_ALIPAY_WEBHOOK",
            "LIVEUIN_PROVIDER_SECRET_ALIPAY",
        )
        return {**resolved, "secret_source": "provider_edge_env"} if resolved.get("secret") else {**resolved, "secret_source": ""}
    return {"secret": "", "secret_source": "", "secret_env_var": ""}


def connection(registry_path: str | Path | None = None) -> sqlite3.Connection:
    target = Path(registry_path).expanduser().resolve() if registry_path else sqlite_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    ensure_schema(conn)
    return conn


def readonly_connection(registry_path: str | Path | None = None) -> sqlite3.Connection:
    target = Path(registry_path).expanduser().resolve() if registry_path else sqlite_path()
    immutable = "&immutable=1" if not os.access(target.parent, os.W_OK) else ""
    conn = sqlite3.connect(f"{target.as_uri()}?mode=ro{immutable}", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA query_only=ON;")
    return conn


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS adapter_secret_references (
            secret_ref_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            adapter_id TEXT NOT NULL DEFAULT '',
            source_family TEXT NOT NULL DEFAULT '',
            provider TEXT NOT NULL DEFAULT '',
            purpose TEXT NOT NULL DEFAULT '',
            secret_env_var TEXT NOT NULL DEFAULT '',
            secret_hash TEXT NOT NULL DEFAULT '',
            secret_prefix TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            valid_from INTEGER NOT NULL DEFAULT 0,
            expires_at INTEGER NOT NULL DEFAULT 0,
            rotated_at INTEGER NOT NULL DEFAULT 0,
            revoked_at INTEGER NOT NULL DEFAULT 0,
            rotated_from_secret_ref_id TEXT NOT NULL DEFAULT '',
            rotation_generation INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            last_resolved_at INTEGER NOT NULL DEFAULT 0,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(workspace_id, secret_ref_id)
        );

        CREATE INDEX IF NOT EXISTS idx_adapter_secret_scope
            ON adapter_secret_references(
                workspace_id, status, provider, purpose, adapter_id, source_family, updated_at DESC
            );

        CREATE INDEX IF NOT EXISTS idx_adapter_secret_rotation
            ON adapter_secret_references(workspace_id, rotated_from_secret_ref_id, rotation_generation DESC);

        CREATE TABLE IF NOT EXISTS adapter_secret_audit_events (
            event_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL DEFAULT 'laijuzhu',
            secret_ref_id TEXT NOT NULL DEFAULT '',
            event_type TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL DEFAULT '{}',
            request_meta_json TEXT NOT NULL DEFAULT '{}',
            recorded_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_adapter_secret_audit_workspace_time
            ON adapter_secret_audit_events(workspace_id, recorded_at DESC);

        CREATE INDEX IF NOT EXISTS idx_adapter_secret_audit_ref
            ON adapter_secret_audit_events(workspace_id, secret_ref_id, recorded_at DESC);
        """
    )
    conn.commit()


def _row_to_reference(row: sqlite3.Row | Dict[str, Any] | None) -> Dict[str, Any]:
    if not row:
        return {}
    data = dict(row)
    secret_hash = str(data.get("secret_hash") or "")
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "secret_ref_id": str(data.get("secret_ref_id") or ""),
        "workspace_id": str(data.get("workspace_id") or DEFAULT_WORKSPACE_ID),
        "adapter_id": str(data.get("adapter_id") or ""),
        "source_family": str(data.get("source_family") or ""),
        "provider": str(data.get("provider") or ""),
        "purpose": str(data.get("purpose") or ""),
        "secret_env_var": str(data.get("secret_env_var") or ""),
        "secret_hash_prefix": _hash_prefix(secret_hash),
        "secret_prefix": str(data.get("secret_prefix") or _hash_prefix(secret_hash)),
        "status": str(data.get("status") or "active"),
        "valid_from": _to_int(data.get("valid_from")),
        "expires_at": _to_int(data.get("expires_at")),
        "rotated_at": _to_int(data.get("rotated_at")),
        "revoked_at": _to_int(data.get("revoked_at")),
        "rotated_from_secret_ref_id": str(data.get("rotated_from_secret_ref_id") or ""),
        "rotation_generation": _to_int(data.get("rotation_generation"), 1),
        "created_at": _to_int(data.get("created_at")),
        "updated_at": _to_int(data.get("updated_at")),
        "last_resolved_at": _to_int(data.get("last_resolved_at")),
        "metadata": decode_json(data.get("metadata_json"), {}),
        "raw_secret_stored": False,
        "canonical_owner": CANONICAL_OWNER,
    }


def _record_audit(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    secret_ref_id: str,
    event_type: str,
    payload: Dict[str, Any] | None = None,
    request_meta: Dict[str, Any] | None = None,
) -> None:
    event_seed = f"{workspace_id}:{secret_ref_id}:{event_type}:{time.time_ns()}:{uuid.uuid4().hex}"
    event_id = hashlib.sha256(event_seed.encode("utf-8")).hexdigest()[:32]
    conn.execute(
        """
        INSERT INTO adapter_secret_audit_events (
            event_id, workspace_id, secret_ref_id, event_type, payload_json, request_meta_json, recorded_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """,
        (
            event_id,
            workspace_id or DEFAULT_WORKSPACE_ID,
            secret_ref_id,
            event_type,
            encode_json(_redact(payload or {})),
            encode_json(_redact(request_meta or {})),
            _now(),
        ),
    )


def _record_payload(payload: Dict[str, Any], secret_hash: str, now: int) -> Dict[str, Any]:
    provider = _provider_slug(payload.get("provider"))
    purpose = _purpose_slug(payload.get("purpose"), provider)
    return {
        "secret_ref_id": _secret_ref_id(payload),
        "workspace_id": _clean_id(payload.get("workspace_id"), 96) or DEFAULT_WORKSPACE_ID,
        "adapter_id": _clean_id(payload.get("adapter_id"), 120),
        "source_family": _clean_slug(payload.get("source_family"), "", 120),
        "provider": provider,
        "purpose": purpose,
        "secret_env_var": _clean_env_var(payload.get("secret_env_var")),
        "secret_hash": secret_hash,
        "secret_prefix": _hash_prefix(secret_hash),
        "status": _status(payload.get("status") or "active"),
        "valid_from": _to_int(payload.get("valid_from"), now),
        "expires_at": _to_int(payload.get("expires_at"), 0),
        "rotated_at": _to_int(payload.get("rotated_at"), 0),
        "revoked_at": _to_int(payload.get("revoked_at"), 0),
        "rotated_from_secret_ref_id": _clean_id(payload.get("rotated_from_secret_ref_id"), 160),
        "rotation_generation": max(1, _to_int(payload.get("rotation_generation"), 1)),
        "created_at": _to_int(payload.get("created_at"), now),
        "updated_at": now,
        "last_resolved_at": _to_int(payload.get("last_resolved_at"), 0),
        "metadata": _redact(_as_dict(payload.get("metadata"))),
    }


def _insert_reference(conn: sqlite3.Connection, record: Dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO adapter_secret_references (
            secret_ref_id, workspace_id, adapter_id, source_family, provider, purpose,
            secret_env_var, secret_hash, secret_prefix, status, valid_from, expires_at,
            rotated_at, revoked_at, rotated_from_secret_ref_id, rotation_generation,
            created_at, updated_at, last_resolved_at, metadata_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
        (
            record["secret_ref_id"],
            record["workspace_id"],
            record["adapter_id"],
            record["source_family"],
            record["provider"],
            record["purpose"],
            record["secret_env_var"],
            record["secret_hash"],
            record["secret_prefix"],
            record["status"],
            record["valid_from"],
            record["expires_at"],
            record["rotated_at"],
            record["revoked_at"],
            record["rotated_from_secret_ref_id"],
            record["rotation_generation"],
            record["created_at"],
            record["updated_at"],
            record["last_resolved_at"],
            encode_json(record.get("metadata") or {}),
        ),
    )


def _error(detail: str, status_code: int = 400, **extra: Any) -> Dict[str, Any]:
    return {
        "ok": False,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "detail": detail,
        "status_code": status_code,
        "canonical_owner": CANONICAL_OWNER,
        "raw_secret_stored": False,
        **extra,
    }


def register_secret_reference(
    payload: Dict[str, Any],
    raw_secret: str = "",
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    payload = _as_dict(payload)
    secret_env_var = _clean_env_var(payload.get("secret_env_var"))
    secret_value = str(raw_secret or _runtime_secret(secret_env_var).get("secret") or "").strip()
    if not secret_value:
        return _error("adapter_secret_material_required", 422, secret_env_var=secret_env_var)
    secret_hash = _hash_secret(secret_value)
    now = _now()
    record = _record_payload({**payload, "secret_env_var": secret_env_var}, secret_hash, now)

    with connection() as conn:
        _insert_reference(conn, record)
        _record_audit(
            conn,
            workspace_id=record["workspace_id"],
            secret_ref_id=record["secret_ref_id"],
            event_type="secret_reference_registered",
            payload={**payload, "secret_hash_prefix": _hash_prefix(secret_hash), "raw_secret": raw_secret},
            request_meta=request_meta,
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM adapter_secret_references WHERE workspace_id = ? AND secret_ref_id = ? LIMIT 1;",
            (record["workspace_id"], record["secret_ref_id"]),
        ).fetchone()
    return {"ok": True, "reference": _row_to_reference(row)}


def get_secret_reference(secret_ref_id: str, workspace_id: str = DEFAULT_WORKSPACE_ID) -> Dict[str, Any]:
    secret_ref_id = _clean_id(secret_ref_id, 160)
    workspace_id = _clean_id(workspace_id, 96) or DEFAULT_WORKSPACE_ID
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM adapter_secret_references WHERE workspace_id = ? AND secret_ref_id = ? LIMIT 1;",
            (workspace_id, secret_ref_id),
        ).fetchone()
    return _row_to_reference(row)


def _lookup_reference(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    adapter_id: str = "",
    source_family: str = "",
    provider: str = "",
    purpose: str = "",
    secret_ref_id: str = "",
    active_only: bool = True,
) -> sqlite3.Row | None:
    now = _now()
    if secret_ref_id:
        clauses = ["workspace_id = ?", "secret_ref_id = ?"]
        args: List[Any] = [workspace_id, secret_ref_id]
    else:
        clauses = ["workspace_id = ?", "provider = ?", "purpose = ?"]
        args = [workspace_id, provider, purpose]
        if adapter_id:
            clauses.append("adapter_id = ?")
            args.append(adapter_id)
        if source_family:
            clauses.append("source_family = ?")
            args.append(source_family)
    if active_only:
        clauses.extend(["status = 'active'", "(valid_from = 0 OR valid_from <= ?)", "(expires_at = 0 OR expires_at > ?)"])
        args.extend([now, now])
    query = f"""
        SELECT *
        FROM adapter_secret_references
        WHERE {' AND '.join(clauses)}
        ORDER BY rotation_generation DESC, valid_from DESC, updated_at DESC
        LIMIT 1;
    """
    return conn.execute(query, tuple(args)).fetchone()


def _matching_inactive_exists(
    conn: sqlite3.Connection,
    *,
    workspace_id: str,
    adapter_id: str,
    source_family: str,
    provider: str,
    purpose: str,
    secret_ref_id: str,
) -> bool:
    row = _lookup_reference(
        conn,
        workspace_id=workspace_id,
        adapter_id=adapter_id,
        source_family=source_family,
        provider=provider,
        purpose=purpose,
        secret_ref_id=secret_ref_id,
        active_only=False,
    )
    if not row:
        return False
    data = dict(row)
    now = _now()
    return (
        str(data.get("status") or "") != "active"
        or (_to_int(data.get("valid_from")) and _to_int(data.get("valid_from")) > now)
        or (_to_int(data.get("expires_at")) and _to_int(data.get("expires_at")) <= now)
    )


def _safe_secret_context(
    *,
    secret_source: str,
    secret_hash: str,
    secret_env_var: str = "",
    secret_credential_name: str = "",
    secret_ref: Dict[str, Any] | None = None,
    secret_map_key: str = "",
) -> Dict[str, Any]:
    reference = _as_dict(secret_ref)
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "secret_source": secret_source,
        "secret_ref_id": reference.get("secret_ref_id", ""),
        "workspace_id": reference.get("workspace_id", ""),
        "adapter_id": reference.get("adapter_id", ""),
        "source_family": reference.get("source_family", ""),
        "provider": reference.get("provider", ""),
        "purpose": reference.get("purpose", ""),
        "secret_env_var": secret_env_var or str(reference.get("secret_env_var") or ""),
        "secret_credential_name": secret_credential_name,
        "secret_map_key": secret_map_key,
        "secret_hash_prefix": _hash_prefix(secret_hash),
        "status": reference.get("status", "active") if reference else "active",
        "rotation_generation": reference.get("rotation_generation", 0) if reference else 0,
        "raw_secret_echoed": False,
        "raw_secret_stored": False,
        "canonical_owner": CANONICAL_OWNER,
    }


def resolve_secret_reference(
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    adapter_id: str = "",
    source_family: str = "",
    provider: str = "",
    purpose: str = "",
    secret_ref_id: str = "",
    explicit_secret: str = "",
    request_meta: Dict[str, Any] | None = None,
    read_only: bool = False,
    registry_path: str | Path | None = None,
) -> Dict[str, Any]:
    workspace_id = _clean_id(workspace_id, 96) or DEFAULT_WORKSPACE_ID
    adapter_id = _clean_id(adapter_id, 120)
    source_family = _clean_slug(source_family, "", 120)
    provider = _provider_slug(provider)
    purpose = _purpose_slug(purpose, provider)
    secret_ref_id = _clean_id(secret_ref_id, 160)

    if explicit_secret:
        secret_hash = _hash_secret(explicit_secret)
        return {
            "ok": True,
            "secret": str(explicit_secret),
            "secret_context": _safe_secret_context(
                secret_source="explicit_route_secret",
                secret_hash=secret_hash,
                secret_ref={
                    "workspace_id": workspace_id,
                    "adapter_id": adapter_id,
                    "source_family": source_family,
                    "provider": provider,
                    "purpose": purpose,
                },
            ),
        }

    with (readonly_connection(registry_path) if read_only else connection(registry_path)) as conn:
        row = _lookup_reference(
            conn,
            workspace_id=workspace_id,
            adapter_id=adapter_id,
            source_family=source_family,
            provider=provider,
            purpose=purpose,
            secret_ref_id=secret_ref_id,
            active_only=True,
        )
        if row:
            data = dict(row)
            reference = _row_to_reference(row)
            env_var = _clean_env_var(data.get("secret_env_var"))
            runtime_secret = _runtime_secret(env_var)
            secret_value = str(runtime_secret.get("secret") or "").strip()
            if not secret_value:
                return _error(
                    "adapter_secret_env_value_missing",
                    500,
                    secret_context=_safe_secret_context(
                        secret_source="registered_secret_reference",
                        secret_hash=str(data.get("secret_hash") or ""),
                        secret_env_var=env_var,
                        secret_credential_name=str(runtime_secret.get("secret_credential_name") or ""),
                        secret_ref=reference,
                    ),
                )
            secret_hash = _hash_secret(secret_value)
            if secret_hash != str(data.get("secret_hash") or ""):
                return _error(
                    "adapter_secret_env_hash_mismatch",
                    500,
                    secret_context=_safe_secret_context(
                        secret_source="registered_secret_reference",
                        secret_hash=str(data.get("secret_hash") or ""),
                        secret_env_var=env_var,
                        secret_credential_name=str(runtime_secret.get("secret_credential_name") or ""),
                        secret_ref=reference,
                    ),
                )
            if not read_only:
                resolved_at = _now()
                conn.execute(
                    """
                    UPDATE adapter_secret_references
                    SET last_resolved_at = ?, updated_at = ?
                    WHERE workspace_id = ? AND secret_ref_id = ?;
                    """,
                    (resolved_at, resolved_at, workspace_id, str(data.get("secret_ref_id") or "")),
                )
                _record_audit(
                    conn,
                    workspace_id=workspace_id,
                    secret_ref_id=str(data.get("secret_ref_id") or ""),
                    event_type="secret_reference_resolved",
                    payload={
                        "adapter_id": adapter_id,
                        "source_family": source_family,
                        "provider": provider,
                        "purpose": purpose,
                        "secret_hash_prefix": _hash_prefix(secret_hash),
                    },
                    request_meta=request_meta,
                )
                conn.commit()
            return {
                "ok": True,
                "secret": secret_value,
                "secret_context": _safe_secret_context(
                    secret_source=str(runtime_secret.get("secret_source") or "registered_secret_reference"),
                    secret_hash=secret_hash,
                    secret_env_var=env_var,
                    secret_credential_name=str(runtime_secret.get("secret_credential_name") or ""),
                    secret_ref=reference,
                ),
            }

        inactive = _matching_inactive_exists(
            conn,
            workspace_id=workspace_id,
            adapter_id=adapter_id,
            source_family=source_family,
            provider=provider,
            purpose=purpose,
            secret_ref_id=secret_ref_id,
        )

    if inactive:
        return _error(
            "adapter_secret_reference_inactive",
            403,
            secret_context=_safe_secret_context(
                secret_source="registered_secret_reference_inactive",
                secret_hash="",
                secret_ref={
                    "workspace_id": workspace_id,
                    "adapter_id": adapter_id,
                    "source_family": source_family,
                    "provider": provider,
                    "purpose": purpose,
                    "secret_ref_id": secret_ref_id,
                    "status": "inactive",
                },
            ),
        )

    fallback = (
        _provider_env_fallback(provider, purpose)
        if provider
        else _adapter_env_fallback(adapter_id=adapter_id, source_family=source_family)
    )
    fallback_secret = str(fallback.get("secret") or "").strip()
    if fallback_secret:
        secret_hash = _hash_secret(fallback_secret)
        return {
            "ok": True,
            "secret": fallback_secret,
            "secret_context": _safe_secret_context(
                secret_source=str(fallback.get("secret_source") or "legacy_env_secret"),
                secret_hash=secret_hash,
                secret_env_var=str(fallback.get("secret_env_var") or ""),
                secret_ref={
                    "workspace_id": workspace_id,
                    "adapter_id": adapter_id,
                    "source_family": source_family,
                    "provider": provider,
                    "purpose": purpose,
                },
                secret_map_key=str(fallback.get("secret_map_key") or ""),
            ),
        }

    return _error(
        "adapter_secret_reference_missing",
        403,
        secret_context=_safe_secret_context(
            secret_source="missing",
            secret_hash="",
            secret_ref={
                "workspace_id": workspace_id,
                "adapter_id": adapter_id,
                "source_family": source_family,
                "provider": provider,
                "purpose": purpose,
                "secret_ref_id": secret_ref_id,
            },
        ),
    )


def resolve_adapter_signature_secret(
    adapter_id: str,
    source_family: str,
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    explicit_secret: str = "",
    secret_ref_id: str = "",
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return resolve_secret_reference(
        workspace_id=workspace_id,
        adapter_id=adapter_id,
        source_family=source_family,
        purpose="adapter_signature",
        secret_ref_id=secret_ref_id,
        explicit_secret=explicit_secret,
        request_meta=request_meta,
    )


def resolve_provider_edge_secret(
    provider: str,
    purpose: str = "",
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    explicit_secret: str = "",
    secret_ref_id: str = "",
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    provider = _provider_slug(provider)
    return resolve_secret_reference(
        workspace_id=workspace_id,
        provider=provider,
        purpose=_purpose_slug(purpose, provider),
        secret_ref_id=secret_ref_id,
        explicit_secret=explicit_secret,
        request_meta=request_meta,
    )


def rotate_secret_reference(
    payload: Dict[str, Any],
    raw_secret: str = "",
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    payload = _as_dict(payload)
    workspace_id = _clean_id(payload.get("workspace_id"), 96) or DEFAULT_WORKSPACE_ID
    old_ref_id = _clean_id(payload.get("secret_ref_id") or payload.get("from_secret_ref_id"), 160)
    if not old_ref_id:
        return _error("adapter_secret_ref_id_required", 422)

    now = _now()
    with connection() as conn:
        old_row = conn.execute(
            "SELECT * FROM adapter_secret_references WHERE workspace_id = ? AND secret_ref_id = ? LIMIT 1;",
            (workspace_id, old_ref_id),
        ).fetchone()
        if not old_row:
            return _error("adapter_secret_reference_not_found", 404, secret_ref_id=old_ref_id)
        old = dict(old_row)
        if str(old.get("status") or "") != "active":
            return _error("adapter_secret_reference_not_active", 403, secret_ref_id=old_ref_id, status=str(old.get("status") or ""))

        secret_env_var = _clean_env_var(payload.get("secret_env_var") or old.get("secret_env_var"))
        secret_value = str(raw_secret or _runtime_secret(secret_env_var).get("secret") or "").strip()
        if not secret_value:
            return _error("adapter_secret_material_required", 422, secret_env_var=secret_env_var)
        secret_hash = _hash_secret(secret_value)
        new_payload = {
            "secret_ref_id": _clean_id(payload.get("new_secret_ref_id"), 160)
            or _secret_ref_id({**old, "secret_ref_id": "", "purpose": old.get("purpose")}),
            "workspace_id": workspace_id,
            "adapter_id": old.get("adapter_id"),
            "source_family": old.get("source_family"),
            "provider": old.get("provider"),
            "purpose": old.get("purpose"),
            "secret_env_var": secret_env_var,
            "status": "active",
            "valid_from": _to_int(payload.get("valid_from"), now),
            "expires_at": _to_int(payload.get("expires_at"), 0),
            "rotated_from_secret_ref_id": old_ref_id,
            "rotation_generation": _to_int(old.get("rotation_generation"), 1) + 1,
            "created_at": now,
            "metadata": _redact(_as_dict(payload.get("metadata"))),
        }
        new_record = _record_payload(new_payload, secret_hash, now)
        conn.execute(
            """
            UPDATE adapter_secret_references
            SET status = 'rotated', rotated_at = ?, updated_at = ?
            WHERE workspace_id = ? AND secret_ref_id = ?;
            """,
            (now, now, workspace_id, old_ref_id),
        )
        _insert_reference(conn, new_record)
        _record_audit(
            conn,
            workspace_id=workspace_id,
            secret_ref_id=old_ref_id,
            event_type="secret_reference_rotated_out",
            payload={"new_secret_ref_id": new_record["secret_ref_id"], "raw_secret": raw_secret},
            request_meta=request_meta,
        )
        _record_audit(
            conn,
            workspace_id=workspace_id,
            secret_ref_id=new_record["secret_ref_id"],
            event_type="secret_reference_rotated_in",
            payload={"rotated_from_secret_ref_id": old_ref_id, "secret_hash_prefix": _hash_prefix(secret_hash), "raw_secret": raw_secret},
            request_meta=request_meta,
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM adapter_secret_references WHERE workspace_id = ? AND secret_ref_id = ? LIMIT 1;",
            (workspace_id, new_record["secret_ref_id"]),
        ).fetchone()
    return {"ok": True, "reference": _row_to_reference(row)}


def revoke_secret_reference(
    payload: Dict[str, Any] | str,
    request_meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    if isinstance(payload, str):
        payload = {"secret_ref_id": payload}
    payload = _as_dict(payload)
    workspace_id = _clean_id(payload.get("workspace_id"), 96) or DEFAULT_WORKSPACE_ID
    secret_ref_id = _clean_id(payload.get("secret_ref_id"), 160)
    if not secret_ref_id:
        return _error("adapter_secret_ref_id_required", 422)
    now = _now()
    with connection() as conn:
        row = conn.execute(
            "SELECT * FROM adapter_secret_references WHERE workspace_id = ? AND secret_ref_id = ? LIMIT 1;",
            (workspace_id, secret_ref_id),
        ).fetchone()
        if not row:
            return _error("adapter_secret_reference_not_found", 404, secret_ref_id=secret_ref_id)
        conn.execute(
            """
            UPDATE adapter_secret_references
            SET status = 'revoked', revoked_at = ?, updated_at = ?
            WHERE workspace_id = ? AND secret_ref_id = ?;
            """,
            (now, now, workspace_id, secret_ref_id),
        )
        _record_audit(
            conn,
            workspace_id=workspace_id,
            secret_ref_id=secret_ref_id,
            event_type="secret_reference_revoked",
            payload={"reason": payload.get("reason", ""), "raw_secret": payload.get("raw_secret", "")},
            request_meta=request_meta,
        )
        conn.commit()
        updated = conn.execute(
            "SELECT * FROM adapter_secret_references WHERE workspace_id = ? AND secret_ref_id = ? LIMIT 1;",
            (workspace_id, secret_ref_id),
        ).fetchone()
    return {"ok": True, "reference": _row_to_reference(updated)}


def list_secret_references(
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    provider: str = "",
    purpose: str = "",
    include_inactive: bool = True,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    workspace_id = _clean_id(workspace_id, 96) or DEFAULT_WORKSPACE_ID
    provider = _provider_slug(provider)
    purpose = _purpose_slug(purpose, provider) if purpose or provider else ""
    limit = max(1, min(500, int(limit or 100)))
    clauses = ["workspace_id = ?"]
    args: List[Any] = [workspace_id]
    if provider:
        clauses.append("provider = ?")
        args.append(provider)
    if purpose:
        clauses.append("purpose = ?")
        args.append(purpose)
    if not include_inactive:
        now = _now()
        clauses.extend(["status = 'active'", "(valid_from = 0 OR valid_from <= ?)", "(expires_at = 0 OR expires_at > ?)"])
        args.extend([now, now])
    args.append(limit)
    query = f"""
        SELECT *
        FROM adapter_secret_references
        WHERE {' AND '.join(clauses)}
        ORDER BY updated_at DESC, rotation_generation DESC
        LIMIT ?;
    """
    with connection() as conn:
        rows = conn.execute(query, tuple(args)).fetchall()
    return [_row_to_reference(row) for row in rows]


def list_audit_events(workspace_id: str = DEFAULT_WORKSPACE_ID, limit: int = 100) -> List[Dict[str, Any]]:
    workspace_id = _clean_id(workspace_id, 96) or DEFAULT_WORKSPACE_ID
    limit = max(1, min(500, int(limit or 100)))
    with connection() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM adapter_secret_audit_events
            WHERE workspace_id = ?
            ORDER BY recorded_at DESC
            LIMIT ?;
            """,
            (workspace_id, limit),
        ).fetchall()
    events: List[Dict[str, Any]] = []
    for row in rows:
        data = dict(row)
        events.append(
            {
                "event_id": str(data.get("event_id") or ""),
                "workspace_id": str(data.get("workspace_id") or DEFAULT_WORKSPACE_ID),
                "secret_ref_id": str(data.get("secret_ref_id") or ""),
                "event_type": str(data.get("event_type") or ""),
                "payload": decode_json(data.get("payload_json"), {}),
                "request_meta": decode_json(data.get("request_meta_json"), {}),
                "recorded_at": _to_int(data.get("recorded_at")),
            }
        )
    return events


def status() -> Dict[str, Any]:
    with connection() as conn:
        reference_count = conn.execute("SELECT COUNT(*) AS count FROM adapter_secret_references;").fetchone()["count"]
        active_count = conn.execute(
            "SELECT COUNT(*) AS count FROM adapter_secret_references WHERE status = 'active';"
        ).fetchone()["count"]
        audit_count = conn.execute("SELECT COUNT(*) AS count FROM adapter_secret_audit_events;").fetchone()["count"]
    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "service": "liveuin-core-adapter-secret-registry",
        "canonical_owner": CANONICAL_OWNER,
        "sqlite_path": str(sqlite_path()),
        "tables": {
            "adapter_secret_references": int(reference_count),
            "adapter_secret_references_active": int(active_count),
            "adapter_secret_audit_events": int(audit_count),
        },
        "secret_storage": "hash_only_local_preview",
        "raw_secret_stored": False,
        "supported_purposes": [
            "adapter_signature",
            "stripe_webhook_signature",
            "hitpay_webhook_signature",
            "wechat_pay_api_v3_key",
            "alipay_webhook_signature",
        ],
        "boundary": {
            "surface": "private adapter/provider secret reference registry",
            "layer": "edge credential reference and rotation contract",
            "owner": CANONICAL_OWNER,
            "does_not_create_product_truth": True,
            "raw_secret_role": "Raw secrets remain in environment variables or a production vault; this registry stores hashes, refs, status, and rotation lineage only.",
        },
        "production_requirements": [
            "Replace local SQLite/env secret resolution with the production vault backend using the same secret reference contract.",
            "Keep adapter/provider secret rotation under LiveUIN Core/Admin Access governance.",
            "Never let connectors, WeChat, PSP dashboards, or channel bridges own LiveUIN payment, case, proof, ticket, inventory, or SLA truth.",
        ],
    }
