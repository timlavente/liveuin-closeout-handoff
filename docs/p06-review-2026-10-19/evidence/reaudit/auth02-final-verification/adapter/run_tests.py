"""Isolated AUTH-01 tests: execute pinned deployed verification code, no HTTP."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import time
import types
from typing import Any, Dict, List
from http.cookies import SimpleCookie
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "source"
RESULT = ROOT / "result.json"
MANIFEST = json.loads((ROOT / "source-manifest.json").read_text())
for row in MANIFEST["files"]:
    assert hashlib.sha256((SOURCE / row["name"]).read_bytes()).hexdigest() == row["sha256"], row["name"]

# Set explicit synthetic stores before importing any product module.
fixture = Path(tempfile.mkdtemp(prefix="auth02-adapter-fixture-", dir=ROOT)).resolve()
for key in list(os.environ):
    if key.startswith(("LIVEUIN_", "OTP_", "PG", "DATABASE_")):
        os.environ.pop(key)
store_names = {
    "LIVEUIN_CORE_IDENTITY_SQLITE_PATH": "identity.sqlite3",
    "LIVEUIN_CORE_IDENTITY_SESSION_SQLITE_PATH": "session.sqlite3",
    "LIVEUIN_CORE_IDENTITY_LOGIN_SQLITE_PATH": "login.sqlite3",
    "LIVEUIN_CORE_ACCESS_SQLITE_PATH": "access.sqlite3",
    "LIVEUIN_CORE_ADAPTER_SECRET_SQLITE_PATH": "adapter-secret.sqlite3",
}
for key, value in store_names.items():
    os.environ[key] = str(fixture / value)
os.environ["LIVEUIN_ENVIRONMENT"] = "staging"
os.environ["LIVEUIN_IDENTITY_CREDENTIAL_STORE_ENFORCEMENT"] = "true"
os.environ["LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET"] = "AUTH02_adapter-isolated-fixture-signing-only"
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True

events = {"sqlite_connections": 0, "network_attempts": 0, "blocked_external_files": 0}
database_paths: set[str] = set()

def audit(event: str, args: tuple[Any, ...]) -> None:
    if event.startswith("socket.") and event not in {"socket.__new__", "socket.gethostname"}:
        events["network_attempts"] += 1
        raise RuntimeError("network_forbidden_in_AUTH02_adapter_isolation")
    if event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        raise RuntimeError("child_process_forbidden_in_AUTH02_adapter_isolation")
    if event == "sqlite3.connect":
        p = Path(str(args[0])).resolve()
        if fixture not in p.parents:
            raise RuntimeError("nonfixture_database_forbidden")
        events["sqlite_connections"] += 1
        database_paths.add(str(p))
    if event == "open" and isinstance(args[0], (str, bytes)):
        p = Path(os.fsdecode(args[0])).resolve()
        flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        if writing and fixture not in p.parents and p != RESULT:
            raise RuntimeError("nonfixture_write_forbidden")
        if str(p).startswith(("/opt/liveuin", "/srv/", "/var/lib/", "/etc/liveuin", "/Users/Vivian/Documents/")):
            events["blocked_external_files"] += 1
            raise RuntimeError("production_or_cloud_path_forbidden")

sys.addaudithook(audit)
sys.path.insert(0, str(SOURCE))
import core_identity_login as login
import core_identity_session as session
import core_identity_workspace_access as workspace

assert login.store.sqlite_path() == fixture / "login.sqlite3"
assert session.credential_store.sqlite_path() == fixture / "session.sqlite3"
assert workspace.store.sqlite_path() == fixture / "identity.sqlite3"

extracted: list[dict[str, Any]] = []

def exact_functions(name: str, names: set[str], globals_: dict[str, Any]) -> types.SimpleNamespace:
    """Compile unchanged selected AST nodes, avoiding unrelated route imports."""
    path = SOURCE / name
    content = path.read_text()
    tree = ast.parse(content, filename=str(path))
    selected = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names]
    assert {n.name for n in selected} == names
    for n in selected:
        assert not n.decorator_list
        extracted.append({"file": name, "function": n.name, "start_line": n.lineno,
                          "end_line": n.end_lineno,
                          "ast_sha256": hashlib.sha256(ast.dump(n, include_attributes=False).encode()).hexdigest()})
    module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *selected], type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(path), "exec"), globals_)
    return types.SimpleNamespace(**{n: globals_[n] for n in names})

# Cookie and destination helpers are also exact deployed functions, not stubs.
google_tree = ast.parse((SOURCE / "core_identity_google_oauth.py").read_text())
constants = {}
for node in google_tree.body:
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        if node.targets[0].id in {"ALLOWED_NATIVE_RETURN_TO_SCHEMES", "ALLOWED_NATIVE_RETURN_TO_HOSTS", "DEFAULT_SESSION_TTL_SECONDS"}:
            assert not any(isinstance(x, (ast.Call, ast.Attribute)) for x in ast.walk(node.value))
            exec(compile(ast.Module(body=[node], type_ignores=[]), "deployed-cookie-constants", "exec"), constants)
google = exact_functions("core_identity_google_oauth.py", {
    "_safe_return_to", "_cookie_header", "_session_cookie_domain", "_session_cookie_headers",
    "_as_dict", "_claim_int", "_now", "_env_bool"
}, {"os": os, "time": time, "SimpleCookie": SimpleCookie, "urlparse": urlparse, **constants})
api_globals = {"os": os, "hashlib": hashlib, "identity_login": login, "workspace_access": workspace,
               "google_oauth": google, "LOCAL_PREVIEW_HOSTS": {"127.0.0.1", "localhost", "host.docker.internal"}}
api = exact_functions("core_identity_api.py", {
    "_clean_email", "_looks_like_email", "_local_preview_request", "_host_workspace_request_context",
    "_host_membership_access", "_otp_gateway_deliver", "browser_auth_request_code", "browser_auth_verify_code"
}, api_globals)

rows: list[dict[str, Any]] = []
secrets: list[str] = []
def expect(name: str, condition: bool, **evidence: Any) -> None:
    rows.append({"test": name, "passed": bool(condition), **evidence})
    if not condition:
        raise AssertionError(name)

workspace_id = "auth01_isolated_ops"
other_workspace = "auth01_isolated_other"
email = "auth01.operator@example.test"
context = {"host": "localhost:4188", "scheme": "http", "path": "/api/ops/auth/request_code"}
payload = {"email": email, "workspace_id": workspace_id, "surface": "ops_command",
           "purpose": "operator_portal", "liveuin_role": "super_admin"}

def count_sessions() -> int:
    with session.credential_store.connection() as conn:
        return int(conn.execute("SELECT COUNT(*) FROM identity_session_credentials").fetchone()[0])

def request() -> tuple[str, str]:
    result = api.browser_auth_request_code(payload, request_context=context)
    assert result.get("ok") is True
    code = str(result["preview_code"])
    secrets.append(code)
    return str(result["challenge_id"]), code

def verify(challenge: str, code: str, **overrides: Any) -> dict[str, Any]:
    return api.browser_auth_verify_code({"challenge_id": challenge, "verification_code": code,
                                        "return_to": "/ops/command", **overrides}, request_context=context)

def negative(name: str, result: dict[str, Any], expected: str, status: int, before: int) -> None:
    expect(name, result.get("ok") is False and result.get("detail") == expected
           and result.get("status_code") == status and count_sessions() == before,
           detail=result.get("detail"), status_code=result.get("status_code"),
           session_count_unchanged=count_sessions() == before)

failure = None
try:
    workspace.store.upsert_workspace_record({"workspace_id": workspace_id, "source": "AUTH02_adapter_isolated_test",
        "product_line": "ops", "plan_type": "starter", "status": "active",
        "metadata": {"feature_limits": {"team_seats": 2}}})
    denied = api.browser_auth_request_code(payload, request_context=context)
    expect("unapproved_fixture_email_denied", denied.get("ok") is False
           and denied.get("detail") == "ops_workspace_membership_required", detail=denied.get("detail"))
    granted = workspace.grant_workspace_membership({"workspace_id": workspace_id, "email": email,
        "workspace_role": "operator", "access_role": "ops_manager", "status": "active"},
        authenticated_approver_id="AUTH02_adapter-fixture-admin")
    assert granted.get("ok") is True
    approved = workspace.resolve_ops_workspace_access(hashlib.sha256(email.encode()).hexdigest(), workspace_id)
    expected_scopes = approved["role_context"]["scopes"]

    cid, code = request()
    challenge = login.store.get_challenge(cid)
    expect("requested_super_admin_cannot_override_membership", challenge.get("role") == "ops_manager"
           and challenge.get("workspace_id") == workspace_id and challenge.get("scopes") == expected_scopes,
           issued_role=challenge.get("role"), issued_workspace=challenge.get("workspace_id"))
    wrong = "000000" if code != "000000" else "000001"
    before = count_sessions()
    invalid = verify(cid, wrong)
    negative("invalid_code_refused", invalid, "identity_login_challenge_invalid_code", 403, before)
    saved = login.store.get_challenge(cid)
    expect("invalid_attempt_recorded_without_consuming_valid_code", saved.get("attempts") == 1 and saved.get("status") == "pending")

    cid_expired, expired_code = request()
    # Fixture-only persisted expiry; verification and production clock functions stay unchanged.
    with sqlite3.connect(str(login.store.sqlite_path())) as conn:
        conn.execute("UPDATE identity_login_challenges SET expires_at=? WHERE challenge_id=?", (int(time.time()) - 1, cid_expired))
        conn.commit()
    expired = verify(cid_expired, expired_code)
    negative("expired_code_refused", expired, "identity_login_challenge_expired", 410, before)
    expect("expired_state_recorded", login.store.get_challenge(cid_expired).get("status") == "expired")

    good = verify(cid, code, workspace_id=other_workspace, role="super_admin", scopes=["identity.admin"])
    actual = good.get("session") or {}
    expect("valid_control_uses_existing_role_workspace_scopes", good.get("ok") is True
           and actual.get("role") == "ops_manager" and actual.get("workspace_id") == workspace_id
           and actual.get("scopes") == expected_scopes and count_sessions() == before + 1,
           issued_role=actual.get("role"), issued_workspace=actual.get("workspace_id"),
           requested_foreign_workspace_ignored=actual.get("workspace_id") != other_workspace)
    cookies = SimpleCookie()
    for cookie in good.get("set_cookie_headers") or []:
        cookies.load(cookie)
    cookie_header = "; ".join(f"{key}={item.value}" for key, item in cookies.items())
    resolved = session.resolve_access_context({}, {"Cookie": cookie_header},
        method="POST", path="/api/core/identity/session/resolve", require_identity=True)
    expect("issued_session_canonically_resolves_without_claim_escalation", resolved.get("ok") is True
           and resolved.get("workspace_id") == workspace_id and resolved.get("actor", {}).get("role") == "ops_manager"
           and resolved.get("identity_session", {}).get("credential_validation") == "signed_session_verified_store_active",
           credential_validation=resolved.get("identity_session", {}).get("credential_validation"),
           detail=resolved.get("detail"), resolved_workspace=resolved.get("workspace_id"),
           resolved_role=resolved.get("actor", {}).get("role"))
    hostile_payload = session.resolve_access_context({"workspace_id": other_workspace,
        "actor": {"role": "super_admin", "scopes": ["identity.admin"]}}, {"Cookie": cookie_header},
        method="POST", path="/api/core/identity/session/resolve", require_identity=True)
    expect("foreign_workspace_or_role_payload_cannot_escalate", hostile_payload.get("ok") is False
           or (hostile_payload.get("workspace_id") == workspace_id and hostile_payload.get("actor", {}).get("role") == "ops_manager"
               and "identity.admin" not in hostile_payload.get("actor", {}).get("scopes", [])),
           refused=hostile_payload.get("ok") is False, detail=hostile_payload.get("detail"))
    forged = session.resolve_access_context({}, {"Cookie": cookie_header, "X-LiveUIN-Role": "super_admin"},
        method="POST", path="/api/core/identity/session/resolve", require_identity=True)
    expect("forged_role_header_refused", forged.get("ok") is False, detail=forged.get("detail"))
    before = count_sessions()
    replay = verify(cid, code)
    negative("reused_code_refused", replay, "identity_login_challenge_not_pending", 409, before)

    outside = api.browser_auth_request_code({**payload, "workspace_id": other_workspace}, request_context=context)
    expect("unapproved_workspace_request_refused", outside.get("ok") is False, detail=outside.get("detail"))
    cid_revoked, revoked_code = request()
    membership = workspace.store.get_workspace_membership_by_email(workspace_id, workspace._email_hash(email))
    membership["status"] = "revoked"
    workspace.store.upsert_workspace_membership(membership)
    revoked = verify(cid_revoked, revoked_code)
    negative("membership_revoked_after_request_refused", revoked, "ops_workspace_membership_required", 403, before)
    # Approved Host must retain server workspace and membership role authority.
    host_workspace = "auth02_isolated_host"
    host_email = "auth02.host@example.test"
    os.environ["LIVEUIN_HOST_WORKSPACE_ID"] = host_workspace
    workspace.store.upsert_workspace_record({"workspace_id": host_workspace, "source":"AUTH02_fixture", "product_line":"host", "plan_type":"starter", "status":"active", "metadata":{"feature_limits":{"team_seats":2}}})
    host_grant=workspace.grant_workspace_membership({"workspace_id":host_workspace,"email":host_email,"workspace_role":"owner","access_role":"owner","status":"active"},authenticated_approver_id="AUTH02-fixture-admin")
    assert host_grant.get("ok") is True
    host_req=api.browser_auth_request_code({"email":host_email,"surface":"host_workspace","purpose":"connect_admin","role":"super_admin","workspace_id":"attacker-workspace"},request_context=context)
    expect("approved_host_request_preserves_trusted_membership",host_req.get("ok") is True,detail=host_req.get("detail"))
    hcode=host_req['preview_code'];secrets.append(hcode)
    host_verified=api.browser_auth_verify_code({"challenge_id":host_req['challenge_id'],"verification_code":hcode,"workspace_id":"attacker-workspace","role":"super_admin","return_to":"/host/onboarding"},request_context=context)
    expect("approved_host_verify_preserves_role_workspace",host_verified.get('ok') is True and host_verified.get('session',{}).get('role')=='owner' and host_verified.get('session',{}).get('workspace_id')==host_workspace,role=host_verified.get('session',{}).get('role'),workspace=host_verified.get('session',{}).get('workspace_id'))
    host_denied=api.browser_auth_request_code({"email":"unapproved.host@example.test","surface":"host_workspace","role":"super_admin"},request_context=context)
    expect("unapproved_host_membership_denied",host_denied.get('ok') is False and host_denied.get('status_code')==403,detail=host_denied.get('detail'))
    host_req2=api.browser_auth_request_code({"email":host_email,"surface":"host_workspace"},request_context=context);hc2=host_req2['preview_code'];secrets.append(hc2)
    hm=workspace.store.get_workspace_membership_by_email(host_workspace,workspace._email_hash(host_email));hm['status']='revoked';workspace.store.upsert_workspace_membership(hm)
    hv2=api.browser_auth_verify_code({"challenge_id":host_req2['challenge_id'],"verification_code":hc2},request_context=context)
    expect("host_membership_revoked_before_verify_denied",hv2.get('ok') is False and hv2.get('status_code')==403,detail=hv2.get('detail'))
    # No membership exists for these synthetic identities. Actual challenge creation,
    # code verification, session issuer and stores execute unchanged local code.
    attacks=[('unknown_surface','unknown_surface','operator_portal'),('empty_surface','','connect_admin'),('ops_connect_purpose','ops_command','connect_admin'),('partner_unapproved','partner_workspace','connect_admin')]
    for name,surface,purpose in attacks:
        prior=count_sessions()
        attack_payload={'email':name+'@auth02.example.test','workspace_id':workspace_id,'surface':surface,'purpose':purpose,'role':'super_admin'}
        requested=api.browser_auth_request_code(attack_payload,request_context=context)
        issued=False;role='';scopes=[];verify_detail='not_requested';verify_status=None
        if requested.get('ok') is True:
            token=requested.get('preview_code','');secrets.append(token)
            accepted=api.browser_auth_verify_code({'challenge_id':requested['challenge_id'],'verification_code':token,'surface':'ops_command','purpose':'operator_portal','role':'ops_manager','workspace_id':workspace_id},request_context=context)
            issued=accepted.get('ok') is True
            role=accepted.get('session',{}).get('role','');scopes=accepted.get('session',{}).get('scopes',[])
            verify_detail=accepted.get('detail');verify_status=accepted.get('status_code',200 if issued else None)
        rows.append({'test':'adapter_'+name+'_must_deny_before_create','passed':requested.get('ok') is False and requested.get('status_code') in {403,404},'request_ok':requested.get('ok'),'request_status':requested.get('status_code',200 if requested.get('ok') else None),'request_detail':requested.get('detail'),'verified_session_issued':issued,'session_delta':count_sessions()-prior,'issued_role':role,'issued_scopes':scopes,'verify_status':verify_status,'verify_detail':verify_detail})
    # Old pending challenges can exist from before the repair. Seed them using the
    # actual lower-level local service, then prove the browser adapter rejects their
    # canonical metadata regardless of payload labels (no mail or direct DB mutation).
    for name,surface,purpose in attacks:
        email_hash=hashlib.sha256(("historical-"+name+"@auth02.example.test").encode()).hexdigest()
        oldchallenge=login.create_login_challenge({'workspace_id':workspace_id,'channel':'email','purpose':purpose,'surface':surface or 'ops_command','target_hash':email_hash,'role':'super_admin'})
        assert oldchallenge.get('ok') is True
        oc=oldchallenge['one_time_challenge'];secrets.append(oc['verification_code']);prior=count_sessions()
        denied_old=api.browser_auth_verify_code({'challenge_id':oc['challenge_id'],'verification_code':oc['verification_code'],'surface':'ops_command','purpose':'operator_portal','role':'ops_manager','email':email},request_context=context)
        expect('historical_'+name+'_metadata_cannot_be_overridden',denied_old.get('ok') is False and denied_old.get('status_code')==403 and count_sessions()==prior,detail=denied_old.get('detail'),session_count_unchanged=count_sessions()==prior)
    outsider=login.create_login_challenge({'workspace_id':workspace_id,'channel':'email','purpose':'operator_portal','surface':'ops_command','target_hash':hashlib.sha256(b'nonmember@auth02.example.test').hexdigest(),'role':'super_admin'})
    oc=outsider['one_time_challenge'];secrets.append(oc['verification_code']);prior=count_sessions()
    unknownmember=api.browser_auth_verify_code({'challenge_id':oc['challenge_id'],'verification_code':oc['verification_code'],'email':email,'role':'ops_manager'},request_context=context)
    expect('known_ops_metadata_still_requires_actual_subject_membership',unknownmember.get('ok') is False and unknownmember.get('status_code')==403 and count_sessions()==prior,detail=unknownmember.get('detail'))
    # Preserve the real owner's observed role class (ops), without touching his account.
    ops_email='auth02.ops-role@example.test'
    og=workspace.grant_workspace_membership({'workspace_id':workspace_id,'email':ops_email,'workspace_role':'operator','access_role':'ops','status':'active'},authenticated_approver_id='AUTH02-fixture-admin')
    assert og.get('ok') is True
    orq=api.browser_auth_request_code({'email':ops_email,'workspace_id':workspace_id,'surface':'ops_command','purpose':'operator_portal','role':'super_admin'},request_context=context)
    expect('existing_ops_role_request_preserved',orq.get('ok') is True,detail=orq.get('detail'))
    code_ops=orq['preview_code'];secrets.append(code_ops)
    ov=api.browser_auth_verify_code({'challenge_id':orq['challenge_id'],'verification_code':code_ops,'role':'super_admin'},request_context=context)
    expect('existing_ops_role_not_promoted',ov.get('ok') is True and ov.get('session',{}).get('role')=='ops',role=ov.get('session',{}).get('role'))
    # Raw-code response preview is explicitly nonproduction, including trusted host hints.
    for label,env in [('unset',{}),('production',{'LIVEUIN_ENVIRONMENT':'production'}),('unknown',{'LIVEUIN_ENVIRONMENT':'pilot'}),('conflicting',{'LIVEUIN_ENVIRONMENT':'staging','ENVIRONMENT':'production'})]:
        for k in ['LIVEUIN_ENVIRONMENT','ENVIRONMENT','LIVEUIN_ENV']:os.environ.pop(k,None)
        os.environ.update(env)
        os.environ['LIVEUIN_IDENTITY_TRUSTED_PREVIEW_HOSTS']='ops.liveuin.com'
        expect('preview_echo_'+label+'_denied',not api._local_preview_request(context) and not api._local_preview_request({'host':'ops.liveuin.com'}))
    for k in ['LIVEUIN_ENVIRONMENT','ENVIRONMENT','LIVEUIN_ENV']:os.environ.pop(k,None)
    os.environ['LIVEUIN_ENVIRONMENT']='staging'
    expect('explicit_local_nonproduction_preview_retained',api._local_preview_request(context) is True)
    # Deployment-safe empty-body denial: no identifier, challenge, delivery, or session.
    original_create=login.create_login_challenge
    create_markers=[]
    def forbidden_empty_create(*args,**kwargs):
        create_markers.append(True)
        raise AssertionError("empty body reached challenge creation")
    login.create_login_challenge=forbidden_empty_create
    prior=count_sessions()
    try:
        empty=api.browser_auth_request_code({},request_context={"host":"ops.liveuin.com","client_host":"127.0.0.1"})
    finally:
        login.create_login_challenge=original_create
    expect("empty_body_denied_before_identifier_or_challenge",empty.get("ok") is False and empty.get("status_code")==403 and not create_markers and count_sessions()==prior,detail=empty.get("detail"),status=empty.get("status_code"),challenge_creation_called=bool(create_markers),session_count_unchanged=count_sessions()==prior)
    expect("no_network_or_outside_file_access", events["network_attempts"] == 0 and events["blocked_external_files"] == 0)
except Exception as exc:
    failure = {"class": type(exc).__name__, "message": str(exc)[:180]}

result = {"ok": failure is None and all(r["passed"] for r in rows),
          "run_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
          "scope": "isolated deployed9095 browser-code adapter authority: approved Ops/Host and invalid surface/purpose; no live HTTP/email",
          "python": sys.version.split()[0], "tests": rows, "failure": failure,
          "isolation": {**events, "database_paths": sorted(database_paths), "fixture_only": True,
                        "production_records_used": False, "email_sent": False},
          "source_manifest_sha256": hashlib.sha256((ROOT / "source-manifest.json").read_bytes()).hexdigest(),
          "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
          "extracted_unchanged_functions": extracted}
serialized = json.dumps(result, indent=2, sort_keys=True)
for secret in secrets:
    # Short numeric codes can coincide with a hash; assert against quoted values only.
    assert json.dumps(secret) not in serialized
RESULT.write_text(serialized + "\n")
print(json.dumps({"ok": result["ok"], "test_count": len(rows), "passed": sum(r["passed"] for r in rows),
                  "failure": failure, "result": str(RESULT)}))
raise SystemExit(0 if result["ok"] else 1)
