from __future__ import annotations

import importlib
import os
from typing import Any, Dict, List

try:
    from . import core_access_store as sqlite_store
except ImportError:  # pragma: no cover - supports direct script execution.
    import core_access_store as sqlite_store

postgres_store = None
_POSTGRES_ATTEMPTED = False

_POSTGRES_DSN_ENV_NAMES = (
    "LIVEUIN_ADAPTER_REPLAY_POSTGRES_DSN",
    "LIVEUIN_ADAPTER_REPLAY_STORE_DSN",
    "LIVEUIN_CORE_ACCESS_REPLAY_POSTGRES_DSN",
    "LIVEUIN_CORE_ACCESS_POSTGRES_DSN",
    "DATABASE_URL",
)


def _postgres_store():
    global postgres_store, _POSTGRES_ATTEMPTED
    if _POSTGRES_ATTEMPTED:
        return postgres_store
    _POSTGRES_ATTEMPTED = True
    for name in ("deploy.core_adapter_replay_postgres_store", "core_adapter_replay_postgres_store"):
        try:
            postgres_store = importlib.import_module(name)
            return postgres_store
        except Exception:
            continue
    postgres_store = None
    return None


def _postgres_dsn_configured() -> bool:
    return any(str(os.getenv(name, "")).strip() for name in _POSTGRES_DSN_ENV_NAMES)


SCHEMA_VERSION = "liveuin-adapter-replay-store-v1"
PHASE = "phase29-shared-adapter-replay-store-contract"
DEFAULT_WORKSPACE_ID = "laijuzhu"
CANONICAL_OWNER = "LiveUIN Core/Admin Access Governance"


def store_driver() -> str:
    configured = os.getenv("LIVEUIN_ADAPTER_REPLAY_STORE_DRIVER", "").strip().lower()
    if configured:
        return configured
    if _postgres_dsn_configured():
        return "postgres"
    return "sqlite"


def using_postgres() -> bool:
    return store_driver() in {"postgres", "postgresql"}


def _postgres_ready() -> bool:
    if not _postgres_dsn_configured():
        return False
    postgres = _postgres_store()
    return bool(postgres is not None and postgres.dsn() and postgres.driver_available())


def _store() -> Any:
    if using_postgres():
        postgres = _postgres_store()
        if postgres is None:
            raise RuntimeError("core_adapter_replay_postgres_store_not_loaded")
        return postgres
    return sqlite_store


def _context(extra: Dict[str, Any] | None = None) -> Dict[str, Any]:
    driver = store_driver()
    postgres_dsn_configured = _postgres_dsn_configured()
    postgres = _postgres_store() if postgres_dsn_configured else None
    postgres_driver_available = bool(postgres is not None and postgres.driver_available())
    claim_supported = (not using_postgres()) or (postgres_dsn_configured and postgres_driver_available)
    return {
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "store_driver": driver,
        "canonical_owner": CANONICAL_OWNER,
        "shared_replay_store": driver in {"postgres", "postgresql"},
        "postgres_dsn_configured": postgres_dsn_configured,
        "postgres_driver_available": postgres_driver_available,
        "claim_supported": claim_supported,
        "raw_signature_stored": False,
        **(extra or {}),
    }


def _decorate(result: Dict[str, Any]) -> Dict[str, Any]:
    result = result if isinstance(result, dict) else {}
    replay_context = _context()
    replay = result.get("replay") if isinstance(result.get("replay"), dict) else {}
    if replay:
        replay = {**replay, "replay_store": replay_context}
    return {
        **result,
        "schema_version": result.get("schema_version", SCHEMA_VERSION),
        "phase": result.get("phase", PHASE),
        "replay_store": replay_context,
        "replay": replay,
    }


def claim_adapter_replay_nonce(record: Dict[str, Any], request_meta: Dict[str, str] | None = None) -> Dict[str, Any]:
    try:
        return _decorate(_store().claim_adapter_replay_nonce(record, request_meta))
    except Exception as exc:
        return {
            "ok": False,
            "schema_version": SCHEMA_VERSION,
            "phase": PHASE,
            "detail": "adapter_replay_store_unavailable",
            "status_code": 503,
            "error_type": exc.__class__.__name__,
            "replay_store": _context(),
        }


def get_adapter_replay_nonce(
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    adapter_id: str,
    nonce: str,
) -> Dict[str, Any]:
    return _store().get_adapter_replay_nonce(
        workspace_id=workspace_id,
        adapter_id=adapter_id,
        nonce=nonce,
    )


def list_adapter_replay_nonces(
    *,
    workspace_id: str = DEFAULT_WORKSPACE_ID,
    adapter_id: str = "",
    source_family: str = "",
    limit: int = 50,
) -> List[Dict[str, Any]]:
    rows = _store().list_adapter_replay_nonces(
        workspace_id=workspace_id,
        adapter_id=adapter_id,
        source_family=source_family,
        limit=limit,
    )
    replay_context = _context()
    return [{**row, "replay_store": replay_context} for row in rows]


def stats(workspace_id: str = DEFAULT_WORKSPACE_ID) -> Dict[str, Any]:
    if using_postgres():
        if not _postgres_ready():
            return {
                "store_driver": store_driver(),
                "adapter_replay_nonce_count": 0,
                "shared_replay_store": True,
                "postgres_dsn_configured": _postgres_dsn_configured(),
                "postgres_driver_available": False,
                "claim_supported": False,
            }
        stats_payload = _postgres_store().stats(workspace_id)
        return {
            **stats_payload,
            "postgres_dsn_configured": bool(stats_payload.get("dsn_configured")),
            "postgres_driver_available": bool(stats_payload.get("driver_available")),
            "claim_supported": True,
        }

    sqlite_stats = sqlite_store.stats(workspace_id)
    return {
        "store_driver": "sqlite",
        "sqlite_path": sqlite_stats.get("sqlite_path", ""),
        "adapter_replay_nonce_count": int(sqlite_stats.get("adapter_replay_nonce_count") or 0),
        "shared_replay_store": False,
        "postgres_dsn_configured": False,
        "postgres_driver_available": False,
        "claim_supported": True,
    }


def status(workspace_id: str = DEFAULT_WORKSPACE_ID) -> Dict[str, Any]:
    driver = store_driver()
    store_stats = stats(workspace_id)
    claim_supported = bool(store_stats.get("claim_supported"))
    return {
        "ok": claim_supported,
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE,
        "service": "liveuin-adapter-replay-store",
        "canonical_owner": CANONICAL_OWNER,
        "store_driver": driver,
        "workspace_id": workspace_id,
        "detail": "adapter_replay_store_ready" if claim_supported else "adapter_replay_store_unavailable",
        "shared_replay_store": bool(store_stats.get("shared_replay_store")),
        "postgres_dsn_configured": bool(store_stats.get("postgres_dsn_configured")),
        "postgres_driver_available": bool(store_stats.get("postgres_driver_available")),
        "claim_supported": claim_supported,
        "adapter_replay_nonce_count": int(store_stats.get("adapter_replay_nonce_count") or 0),
        "sqlite_path": store_stats.get("sqlite_path", ""),
        "postgres_table": store_stats.get("table", "ops.access_adapter_replay_nonces") if using_postgres() else "",
        "raw_signature_stored": False,
        "boundary": {
            "surface": "Core gateway and adapter ingress replay protection",
            "layer": "adapter replay nonce reservation contract",
            "owner": CANONICAL_OWNER,
            "does_not_create_product_truth": True,
            "provider_role": "PSP/provider callbacks remain transport evidence; replay storage only prevents duplicate signed envelopes.",
        },
        "production_requirements": [
            "Use a shared transactional store such as Postgres for all adapter verifier instances.",
            "Keep replay nonce rows under LiveUIN Core/Admin Access Governance.",
            "Do not store raw adapter secrets or raw provider payloads in replay rows.",
        ],
    }
