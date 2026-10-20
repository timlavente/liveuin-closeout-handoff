from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping


MANIFEST_PATH = Path(__file__).with_name("p2a1_identity_required_routes.json")


def load_route_manifest() -> dict[str, Any]:
    with MANIFEST_PATH.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    if not isinstance(manifest, dict):
        raise ValueError("identity route manifest must be an object")
    return manifest


def _route_pairs(entries: Iterable[Mapping[str, Any]]) -> set[tuple[str, str]]:
    return {
        (str(entry.get("method") or "").upper(), str(entry.get("path") or ""))
        for entry in entries
        if str(entry.get("method") or "") and str(entry.get("path") or "")
    }


def expected_route_pairs() -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    manifest = load_route_manifest()
    return (
        _route_pairs(manifest.get("public_routes") or []),
        _route_pairs(manifest.get("internal_routes") or []),
    )


def _collect_route_pairs(routes: Iterable[Any], pairs: set[tuple[str, str]]) -> None:
    for route in routes:
        path = str(getattr(route, "path", "") or "")
        methods = getattr(route, "methods", set()) or set()
        for method in methods:
            pairs.add((str(method).upper(), path))
        nested_router = getattr(route, "original_router", None)
        if nested_router is not None:
            _collect_route_pairs(getattr(nested_router, "routes", []) or [], pairs)


def actual_route_pairs(app: Any) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    _collect_route_pairs(getattr(app, "routes", []) or [], pairs)
    return pairs


def openapi_route_pairs(document: Mapping[str, Any]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for path, operations in (document.get("paths") or {}).items():
        if not isinstance(operations, Mapping):
            continue
        for method in operations:
            if str(method).lower() in {"get", "post", "put", "patch", "delete", "options", "head", "trace"}:
                pairs.add((str(method).upper(), str(path)))
    return pairs


def route_contract_status(app: Any) -> dict[str, Any]:
    expected_public, expected_internal = expected_route_pairs()
    actual = actual_route_pairs(app)
    missing_public = sorted(expected_public - actual)
    missing_internal = sorted(expected_internal - actual)
    password_reset_status = public_schema_status(app.openapi())
    return {
        "ok": not missing_public and not missing_internal and bool(password_reset_status["password_reset_contract_ready"]),
        "missing_public": missing_public,
        "missing_internal": missing_internal,
        "expected_public_count": len(expected_public),
        "expected_internal_count": len(expected_internal),
        "password_reset_contract_ready": bool(password_reset_status["password_reset_contract_ready"]),
        "password_reset_contract_missing_fields": password_reset_status["password_reset_contract_missing_fields"],
    }


def public_schema_status(document: Mapping[str, Any]) -> dict[str, Any]:
    expected_public, expected_internal = expected_route_pairs()
    actual = openapi_route_pairs(document)
    missing_public = sorted(expected_public - actual)
    leaked_internal = sorted(expected_internal & actual)
    password_reset_contract_missing_fields = _password_reset_contract_missing_fields(document)
    return {
        "ok": not missing_public and not leaked_internal and not password_reset_contract_missing_fields,
        "missing_public": missing_public,
        "leaked_internal": leaked_internal,
        "password_reset_contract_ready": not password_reset_contract_missing_fields,
        "password_reset_contract_missing_fields": password_reset_contract_missing_fields,
    }


def _password_reset_contract_missing_fields(document: Mapping[str, Any]) -> list[str]:
    operation = ((document.get("paths") or {}).get("/api/core/identity/password-resets/request") or {}).get("post")
    response = (operation or {}).get("responses", {}).get("202", {}) if isinstance(operation, Mapping) else {}
    if isinstance(response, Mapping) and str(response.get("$ref") or "").startswith("#/"):
        response = _resolve_openapi_ref(document, str(response["$ref"]))
    content = response.get("content", {}) if isinstance(response, Mapping) else {}
    media = content.get("application/json", {}) if isinstance(content, Mapping) else {}
    schema = media.get("schema", {}) if isinstance(media, Mapping) else {}
    if isinstance(schema, Mapping) and str(schema.get("$ref") or "").startswith("#/"):
        schema = _resolve_openapi_ref(document, str(schema["$ref"]))
    required = set(schema.get("required") or []) if isinstance(schema, Mapping) else set()
    properties = schema.get("properties") or {} if isinstance(schema, Mapping) else {}
    missing = sorted({"ok", "status", "message", "reset_id", "next_action", "expires_in_seconds", "verification_expiry", "request_id"} - required)
    for field, expected_type in {
        "reset_id": "string",
        "next_action": "string",
        "expires_in_seconds": "integer",
        "verification_expiry": "integer",
        "request_id": "string",
    }.items():
        if not isinstance(properties.get(field), Mapping) or properties[field].get("type") != expected_type:
            missing.append(f"{field}:type")
    return sorted(set(missing))


def _resolve_openapi_ref(document: Mapping[str, Any], reference: str) -> Mapping[str, Any]:
    resolved: Any = document
    for part in reference[2:].split("/"):
        resolved = resolved.get(part, {}) if isinstance(resolved, Mapping) else {}
    return resolved if isinstance(resolved, Mapping) else {}
