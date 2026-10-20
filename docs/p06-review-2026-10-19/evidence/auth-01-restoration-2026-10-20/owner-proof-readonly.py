"""Read only the named owner's exact delivered-factor challenge/session proof.

No product imports; no secrets, hashes, identifiers or cookies printed.
No schema initialization, provider calls, email or mutation.
"""
from __future__ import annotations

import ast
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time

SERVICE = "ops-backend@liveuin.service"
OWNER_EMAIL = "timlavente@gmail.com"
CHALLENGE = "lch_08d1aa652f740cb29882"
START = int(dt.datetime(2026, 10, 19, 16, 34, 0, tzinfo=dt.timezone.utc).timestamp())
END = int(dt.datetime(2026, 10, 19, 16, 39, 0, tzinfo=dt.timezone.utc).timestamp())
EXPECTED = {
    "core_identity_api.py": "fcf8c612f2442ab05a8950523890806af7b89f88e9cbf801fcc5561ec1d6acc4",
    "core_identity_login.py": "f7f3d8b6fe5c52d4e6401afebda4f238b851261e64c83c129cb36095883c36fd",
    "core_identity_login_store.py": "e8b369634c1875519e7883f439388f5b02a062849569fbb1a4663160baf95d94",
    "core_identity_store.py": "8435560b88230df6737ff3dca8dc52bafd881dd7ebb01c3b961356ae9cf04f36",
    "core_identity_session.py": "11b7ab17300c3a2ea8a0294470f9872496c6e4f8308598edad97f680ea9fefdb",
    "core_identity_session_store.py": "c0f2a07b7778aef761deee03b32adc61bfa257cb1edeae933416438508a265c3",
    "core_identity_workspace_access.py": "729531a7a562dd0fc7d53f300b2664d462593024163264230e188aba4ab6493d",
}

def pid() -> str:
    return subprocess.check_output(["systemctl", "show", SERVICE, "--value", "-p", "MainPID"], text=True).strip()

def utc(epoch: int) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat()

def checked_sources() -> dict[str, bool]:
    return {name: hashlib.sha256((Path("/opt/liveuin/deploy") / name).read_bytes()).hexdigest() == expected
            for name, expected in EXPECTED.items()}

def one(rows: list[sqlite3.Row], label: str) -> sqlite3.Row:
    if len(rows) != 1:
        raise ValueError(label + "_missing_or_ambiguous")
    return rows[0]

def readonly(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise ValueError("bound_store_missing")
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    # Queries below select only the exact owner's challenge/membership/session.
    allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
    connection.set_authorizer(lambda action, *_: sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY)
    return connection

output: dict[str, object] = {"observed_at_utc": utc(int(time.time())), "service": SERVICE,
    "scope": "one named owner and exact delivered-factor challenge; role/workspace/status only",
    "read_only": True, "product_modules_imported": False,
    "credential_values_or_hashes_output": False, "unrelated_rows_output": False}
connections = []
try:
    before = pid()
    if not before.isdigit() or before == "0":
        raise ValueError("service_not_running")
    start_tick = Path("/proc/" + before + "/stat").read_text().split(") ", 1)[1].split()[19]
    matches = checked_sources()
    output.update(pid=int(before), source_versions_match=matches)
    if not all(matches.values()):
        raise ValueError("deployed_source_drift")
    raw_env = Path("/proc/" + before + "/environ").read_bytes()
    selected_keys = {"LIVEUIN_CORE_IDENTITY_SQLITE_PATH", "LIVEUIN_CORE_IDENTITY_DATA_DIR",
        "LIVEUIN_CORE_IDENTITY_LOGIN_SQLITE_PATH", "LIVEUIN_CORE_IDENTITY_LOGIN_DATA_DIR",
        "LIVEUIN_CORE_IDENTITY_SESSION_SQLITE_PATH", "LIVEUIN_CORE_IDENTITY_SESSION_DATA_DIR"}
    env = {}
    for item in raw_env.split(b"\0"):
        if b"=" in item:
            key, value = item.split(b"=", 1)
            name = key.decode(errors="replace")
            if name in selected_keys:
                env[name] = value.decode(errors="strict").strip()
    del raw_env
    base = Path("/opt/liveuin/runtime")
    paths = {}
    for label, prefix, directory, filename in [
        ("identity", "LIVEUIN_CORE_IDENTITY", "core-identity-data", "liveuin-core-identity.sqlite3"),
        ("login", "LIVEUIN_CORE_IDENTITY_LOGIN", "core-identity-login-data", "liveuin-core-identity-login.sqlite3"),
        ("session", "LIVEUIN_CORE_IDENTITY_SESSION", "core-identity-session-data", "liveuin-core-identity-session.sqlite3"),
    ]:
        configured_path = env.get(prefix + "_SQLITE_PATH", "")
        configured_dir = env.get(prefix + "_DATA_DIR", "")
        path = Path(configured_path) if configured_path else Path(configured_dir) / filename if configured_dir else base / directory / filename
        if not path.is_absolute() or "~" in str(path):
            raise ValueError("relative_or_home_bound_store_requires_review")
        paths[label] = path.resolve()
    output["selected_runtime_store_bindings"] = {k: str(p) for k, p in paths.items()}
    identity, login, sessions = [readonly(paths[name]) for name in ["identity", "login", "session"]]
    connections.extend([identity, login, sessions])
    owner_hash = hashlib.sha256(OWNER_EMAIL.strip().lower().encode()).hexdigest()
    challenge = one(login.execute(
        "SELECT workspace_id, actor_id, role, scopes_json, status, issued_at, expires_at, verified_at "
        "FROM identity_login_challenges WHERE challenge_id=? AND subject_hash=? "
        "AND channel='email' AND purpose='operator_portal' AND issued_at BETWEEN ? AND ? LIMIT 2",
        (CHALLENGE, owner_hash, START, END)).fetchall(), "exact_owner_challenge")
    membership = one(identity.execute(
        "SELECT access_role, workspace_role, status FROM identity_workspace_memberships "
        "WHERE workspace_id=? AND email_hash=? LIMIT 2",
        (challenge["workspace_id"], owner_hash)).fetchall(), "exact_owner_membership")
    session = one(sessions.execute(
        "SELECT workspace_id, role, scopes_json, status, auth_method, issued_at, expires_at, revoked_at "
        "FROM identity_session_credentials WHERE workspace_id=? AND actor_id=? "
        "AND auth_method='liveuin_login_challenge' AND issued_at BETWEEN ? AND ? "
        "AND json_extract(metadata_json, '$.challenge_id')=? LIMIT 2",
        (challenge["workspace_id"], challenge["actor_id"], START, END, CHALLENGE)).fetchall(), "exact_owner_session")
    # Read the static role-default mapping through AST only; no product imports.
    tree = ast.parse(Path("/opt/liveuin/deploy/core_identity_session.py").read_text())
    role_defaults = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "ROLE_DEFAULT_SCOPES" for target in node.targets))
    role = str(membership["access_role"] or membership["workspace_role"])
    challenge_scopes = json.loads(challenge["scopes_json"])
    issued_scopes = json.loads(session["scopes_json"])
    role_match = role == challenge["role"] == session["role"] and role in {"operator", "ops", "ops_manager", "super_admin"}
    scopes_match = set(challenge_scopes) == set(issued_scopes) == set(role_defaults.get(role, []))
    active = session["status"] == "active" and not session["revoked_at"] and session["expires_at"] > time.time()
    verified = challenge["status"] == "verified" and START <= challenge["verified_at"] <= END
    after = pid()
    stable = before == after and start_tick == Path("/proc/" + after + "/stat").read_text().split(") ", 1)[1].split()[19]
    unchanged = all(checked_sources().values())
    output.update(
        owner_email_match=True, exact_challenge_match=True,
        challenge={"status": challenge["status"], "issued_at_utc": utc(challenge["issued_at"]),
                   "verified_at_utc": utc(challenge["verified_at"]), "verified_in_browser_window": verified},
        membership={"status": membership["status"], "trusted_role": role, "workspace": challenge["workspace_id"]},
        session={"status": session["status"], "active": active, "role": session["role"],
                 "workspace": session["workspace_id"], "scopes": sorted(issued_scopes),
                 "issued_at_utc": utc(session["issued_at"]), "expires_at_utc": utc(session["expires_at"])},
        role_matches_membership=role_match, scopes_match_existing_role=scopes_match,
        pid_and_start_stable=stable, source_versions_unchanged=unchanged,
        passed=bool(verified and active and membership["status"] == "active" and role_match and scopes_match and stable and unchanged))
except Exception as exc:
    # Deliberately avoid exceptions containing SQL, paths, records or identifier values.
    output.update(passed=False, failure_class=type(exc).__name__,
                  failure_reason=str(exc) if isinstance(exc, ValueError) else "selected_owner_read_unavailable")
finally:
    for connection in connections:
        connection.close()
print(json.dumps(output, indent=2, sort_keys=True))
