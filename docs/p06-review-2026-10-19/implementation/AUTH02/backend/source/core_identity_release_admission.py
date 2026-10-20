"""AUTH02 closed-pilot admission ACL. No identities, roles or grants are created here.

The deployment supplies exact SHA256 hashes of approved canonical email identifiers.
Missing, malformed, empty or mismatched configuration fails closed. Existing Identity
records and normal authentication remain authoritative after this release gate.
"""
from __future__ import annotations
import json
import os
import re
from typing import Any, Mapping

COHORT_ENV = "LIVEUIN_PUBLIC_ADMISSION_COHORT_JSON"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_WORKSPACE = re.compile(r"[A-Za-z0-9_.:-]{1,96}\Z")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate admission configuration key")
        result[key] = value
    return result


def policy() -> tuple[str, frozenset[str]]:
    raw = os.getenv(COHORT_ENV, "")
    if not raw or len(raw) > 131072:
        return "", frozenset()
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object)
        if not isinstance(value, dict) or set(value) != {"schema_version", "workspace_id", "allowed_email_sha256"}:
            return "", frozenset()
        workspace = value["workspace_id"]
        hashes = value["allowed_email_sha256"]
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            return "", frozenset()
        if not isinstance(workspace, str) or not _WORKSPACE.fullmatch(workspace):
            return "", frozenset()
        if not isinstance(hashes, list) or not 1 <= len(hashes) <= 1000:
            return "", frozenset()
        if any(not isinstance(item, str) or not _HASH.fullmatch(item) for item in hashes):
            return "", frozenset()
        if len(set(hashes)) != len(hashes):
            return "", frozenset()
        return workspace, frozenset(hashes)
    except (ValueError, TypeError, RecursionError):
        return "", frozenset()


def permits_email_hash(email_hash: Any, workspace_id: Any) -> bool:
    configured_workspace = os.getenv("LIVEUIN_PUBLIC_WORKSPACE_ID", "").strip()
    workspace, hashes = policy()
    return bool(workspace and workspace == configured_workspace == workspace_id
                and isinstance(email_hash, str) and email_hash in hashes)


def permits_account(account: Mapping[str, Any]) -> bool:
    if not isinstance(account, Mapping):
        return False
    verified = account.get("email_verified_at")
    return bool(type(verified) is int and verified > 0
                and isinstance(account.get("account_id"), str) and account["account_id"]
                and isinstance(account.get("person_id"), str) and account["person_id"]
                and permits_email_hash(account.get("email_hash"), account.get("workspace_id")))
