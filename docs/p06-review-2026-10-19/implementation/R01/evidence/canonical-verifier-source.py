def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}

def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []

def _clean_id(value: Any, max_length: int = 120) -> str:
    return re.sub(r"[^A-Za-z0-9_.:-]", "", str(value or "").strip())[:max_length]

def _clean_slug(value: Any, default: str = "", max_length: int = 120) -> str:
    cleaned = re.sub(r"[^a-z0-9_.:-]+", "_", str(value or "").strip().lower()).strip("_")
    return (cleaned or default)[:max_length]

def _header(headers: Mapping[str, str] | None, key: str) -> str:
    if not headers:
        return ""
    target = key.lower()
    for header_key, value in headers.items():
        if str(header_key).lower() == target and value:
            return str(value).strip()
    return ""

def _hash(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def _signing_secret() -> str:
    return str(os.getenv("LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET") or "").strip()

def _session_max_age_seconds() -> int:
    raw = str(os.getenv("LIVEUIN_IDENTITY_SESSION_MAX_AGE_SECONDS") or "").strip()
    if not raw:
        return DEFAULT_SESSION_MAX_AGE_SECONDS
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_SESSION_MAX_AGE_SECONDS

def _credential_store_enforcement() -> bool:
    raw = str(os.getenv("LIVEUIN_IDENTITY_CREDENTIAL_STORE_ENFORCEMENT") or "").strip().lower()
    if not raw:
        return True
    return raw in {"1", "true", "yes", "on", "required", "require", "enforced"}

def _signature_payload(values: Dict[str, Any]) -> str:
    return json.dumps(
        {
            "workspace_id": str(values.get("workspace_id") or DEFAULT_WORKSPACE_ID),
            "actor_id": str(values.get("actor_id") or ""),
            "role": str(values.get("role") or ""),
            "scopes": _as_list(values.get("scopes")),
            "session_id": str(values.get("session_id") or ""),
            "issued_at": str(values.get("issued_at") or ""),
            "auth_method": str(values.get("auth_method") or ""),
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )

def _session_signature(values: Dict[str, Any]) -> str:
    secret = _signing_secret()
    if not secret:
        return ""
    return hmac.new(secret.encode("utf-8"), _signature_payload(values).encode("utf-8"), hashlib.sha256).hexdigest()

def sign_session_headers(values: Dict[str, Any]) -> Dict[str, str]:
    workspace_id = _clean_id(values.get("workspace_id") or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID
    actor_id = _clean_id(values.get("actor_id"), 120)
    role = _clean_slug(values.get("role"), "", 80)
    scopes = [_clean_slug(scope, "", 120) for scope in _as_list(values.get("scopes")) if _clean_slug(scope, "", 120)]
    issued_at = str(values.get("issued_at") or int(time.time()))
    auth_method = _clean_slug(values.get("auth_method"), "signed_internal_session", 80)
    session_id = _clean_id(values.get("session_id"), 160)
    signature_values = {
        "workspace_id": workspace_id,
        "actor_id": actor_id,
        "role": role,
        "scopes": scopes,
        "session_id": session_id,
        "issued_at": issued_at,
        "auth_method": auth_method,
    }
    return {
        "X-LiveUIN-Workspace-Id": workspace_id,
        "X-LiveUIN-Actor-Id": actor_id,
        "X-LiveUIN-Role": role,
        "X-LiveUIN-Scopes": ",".join(scopes),
        "X-LiveUIN-Session-Id": session_id,
        "X-LiveUIN-Session-Issued-At": issued_at,
        "X-LiveUIN-Auth-Method": auth_method,
        "X-LiveUIN-Session-Signature": _session_signature(signature_values),
    }

def _session_header_values(headers: Mapping[str, str] | None) -> Dict[str, Any]:
    return {
        "workspace_id": _header(headers, "X-LiveUIN-Workspace-Id") or DEFAULT_WORKSPACE_ID,
        "actor_id": _header(headers, "X-LiveUIN-Actor-Id"),
        "role": _header(headers, "X-LiveUIN-Role"),
        "scopes": _as_list(_header(headers, "X-LiveUIN-Scopes")),
        "session_id": _header(headers, "X-LiveUIN-Session-Id"),
        "issued_at": _header(headers, "X-LiveUIN-Session-Issued-At"),
        "auth_method": _header(headers, "X-LiveUIN-Auth-Method"),
    }

def _session_header_validation(headers: Mapping[str, str] | None) -> Dict[str, Any]:
    values = _session_header_values(headers)
    session_id = str(values.get("session_id") or "")
    signature = _header(headers, "X-LiveUIN-Session-Signature")
    if not session_id or not signature or not _signing_secret():
        return {"verified": False, "validation": "session_signature_required"}

    expected = _session_signature(values)
    if not expected or not hmac.compare_digest(expected, signature):
        return {"verified": False, "validation": "session_signature_invalid"}

    issued_at = str(values.get("issued_at") or "").strip()
    try:
        issued_seconds = float(issued_at)
    except ValueError:
        return {"verified": False, "validation": "session_issued_at_invalid"}

    now = time.time()
    if issued_seconds > now + 300:
        return {"verified": False, "validation": "session_issued_at_in_future"}

    max_age_seconds = _session_max_age_seconds()
    if max_age_seconds and now - issued_seconds > max_age_seconds:
        return {"verified": False, "validation": "session_signature_expired"}

    workspace_hint = _clean_id(values.get("workspace_id") or DEFAULT_WORKSPACE_ID, 96) or DEFAULT_WORKSPACE_ID
    session_id_hash = _hash(session_id)
    store_result = credential_store.validate_session_hash(session_id_hash, workspace_id=workspace_hint)
    if not store_result.get("found"):
        store_result = credential_store.validate_session_hash(session_id_hash)
    store_record = _as_dict(store_result.get("record"))
    if store_result.get("active"):
        if _session_store_claim_mismatch(store_record, values):
            return {
                "verified": False,
                "validation": "session_store_claim_mismatch",
                "store_record": store_record,
            }
        return {
            "verified": True,
            "validation": "signed_session_verified_store_active",
            "store_record": store_record,
        }
    if _credential_store_enforcement():
        return {
            "verified": False,
            "validation": str(store_result.get("validation") or "session_store_missing"),
            "store_record": store_record,
        }

    return {"verified": True, "validation": "signed_session_verified", "store_record": store_record}

def _normalized_scope_set(value: Any) -> set[str]:
    return {str(item).strip() for item in _as_list(value) if str(item).strip()}

def _session_store_claim_mismatch(record: Dict[str, Any], values: Dict[str, Any]) -> bool:
    if not record:
        return False
    comparisons = (
        ("workspace_id", DEFAULT_WORKSPACE_ID),
        ("actor_id", ""),
        ("role", ""),
        ("auth_method", ""),
    )
    for key, default in comparisons:
        record_value = str(record.get(key) or default)
        signed_value = str(values.get(key) or default)
        if record_value and signed_value and record_value != signed_value:
            return True
    record_scopes = _normalized_scope_set(record.get("scopes"))
    signed_scopes = _normalized_scope_set(values.get("scopes"))
    return bool(record_scopes and signed_scopes and record_scopes != signed_scopes)
