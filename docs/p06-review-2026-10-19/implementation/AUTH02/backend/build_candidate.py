from pathlib import Path
import ast, difflib, hashlib, json, shutil
ROOT=Path(__file__).resolve().parent
SRC=Path('/private/tmp/liveuin-p06-audit-20261019/reaudit/auth-repair-map')
EXPECTED={
'core_identity_public.py':'11077e9fed401168683d5c8c31117dd2a57bd5f403ed6cfa379f58ad55f8a1b8',
'core_identity_social.py':'d181bcadd104229ca04eb941fb745a7dab209387bfefebfea3009d7b88994903',
'core_identity_api.py':'35cb1b2ed434eec9bce941eb0f4a6642d28a88ffb005cbec8cd4d4662f436132',
'core_identity_session.py':'cfaf971913f6a49960f5cc54c8877641cc5db1b00de4c42fa8259c673cc82f7e',
}
texts={}
for name, digest in EXPECTED.items():
    data=(SRC/name).read_bytes()
    assert hashlib.sha256(data).hexdigest()==digest, name
    texts[name]=data.decode()

def replace(text,old,new,count=1):
    assert text.count(old)==count, (old[:90],text.count(old),count)
    return text.replace(old,new)

def function(text,name,transform):
    tree=ast.parse(text)
    node=next(n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name)
    lines=text.splitlines(keepends=True)
    fragment=''.join(lines[node.lineno-1:node.end_lineno])
    return ''.join(lines[:node.lineno-1])+transform(fragment)+''.join(lines[node.end_lineno:])

p=texts['core_identity_public.py']
p=replace(p,'    from . import core_identity_service as identity_svc','    from . import core_identity_release_admission as release_admission\n    from . import core_identity_service as identity_svc')
p=replace(p,'    import core_identity_service as identity_svc','    import core_identity_release_admission as release_admission\n    import core_identity_service as identity_svc')
anchor='def _issue_session(\n'
helpers='''def _admission_failure(request_meta=None):
    return error("pilot_admission_required", 403,
                 "LiveUIN access is limited to approved pilot accounts.",
                 request_meta=request_meta, next_action="contact_support")


def _admission_for_hash(email_hash, workspace_id, request_meta=None):
    return {} if release_admission.permits_email_hash(email_hash, workspace_id) else _admission_failure(request_meta)


def _admission_for_account(account, request_meta=None):
    return {} if release_admission.permits_account(account) else _admission_failure(request_meta)


'''
p=replace(p,anchor,helpers+anchor)
p=function(p,'_issue_session',lambda t:replace(t,'    scopes = ["identity.session"]','    admission_failure = _admission_for_account(account, request_meta)\n    if admission_failure:\n        return admission_failure\n    scopes = ["identity.session"]'))
for name in ['start_registration','password_sign_in']:
    p=function(p,name,lambda t:replace(t,'    email_hash = _email_hash(email)','    email_hash = _email_hash(email)\n    admission_failure = _admission_for_hash(email_hash, workspace_id, request_meta)\n    if admission_failure:\n        return admission_failure'))
for name in ['verify_registration','resend_registration']:
    marker='    if registration.get("status")'
    p=function(p,name,lambda t:t.replace(marker,'    admission_failure = _admission_for_hash(registration.get("email_hash"), workspace_id, request_meta)\n    if admission_failure:\n        return admission_failure\n'+marker,1))
p=function(p,'session_bootstrap_projection_result',lambda t:replace(t,'    person = identity_store.get_person(person_id, workspace_id)','    if _admission_for_account(account):\n        return {"ok": False, "detail": "pilot_admission_required", "status_code": 403}\n    person = identity_store.get_person(person_id, workspace_id)'))
p=function(p,'_session_account',lambda t:replace(replace(t,'request_meta: Mapping[str, Any] | None) ->','request_meta: Mapping[str, Any] | None, *, require_admission: bool = False) ->'),'    return account, {}','    if require_admission:\n        admission_failure = _admission_for_account(account, request_meta)\n        if admission_failure:\n            return {}, admission_failure\n    return account, {}'))
for name in ['onboarding_status','update_profile','complete_onboarding']:
    p=function(p,name,lambda t:replace(t,'_session_account(headers, request_meta)','_session_account(headers, request_meta, require_admission=True)'))
# /ready already runs isolated synthetic projections. Choose a configured ACL identifier
# only for its existing mocked record; never modify configuration or create a grant.
p=function(p,'session_public_account_projection_ready',lambda t:replace(replace(t,'    account = {','    cohort_workspace, cohort_hashes = release_admission.policy()\n    if not cohort_hashes or cohort_workspace != str(os.getenv(PUBLIC_WORKSPACE_ENV) or "").strip():\n        return False\n    account = {',1),'        "workspace_id": "workspace_contract",','        "workspace_id": cohort_workspace,\n        "email_hash": sorted(cohort_hashes)[0],'))
p=function(p,'revoke_current_session',lambda t:replace(t,'    values = {str(key).lower(): str(value) for key, value in (headers or {}).items()}','    effective_headers = identity_session._headers_with_cookie_session(headers)\n    values = {str(key).lower(): str(value) for key, value in effective_headers.items()}'))
p=function(p,'revoke_current_session',lambda t:replace(t,'    return store.revoke_refresh_for_session(store.hash_value(session_id), "logout") if session_id else 0','''    if not session_id:
        return 0
    session_hash = store.hash_value(session_id)
    revoked = store.revoke_refresh_for_session(session_hash, "logout")
    # Exact current-session check only; do not acknowledge a partial durable logout.
    with store.connection() as conn:
        remaining = conn.execute(
            "SELECT 1 FROM identity_public_refresh_credentials WHERE session_id_hash = ? AND status = 'active' LIMIT 1",
            (session_hash,),
        ).fetchone()
    if remaining:
        raise RuntimeError("identity_refresh_logout_incomplete")
    return revoked'''))
texts['core_identity_public.py']=p
s=texts['core_identity_social.py']
s=function(s,'_new_social_account',lambda t:replace(t,'    terms = _clean(payload.get("accepted_terms_version"), 80)','    admission_failure = public_identity._admission_for_hash(claims.get("verified_email_hash") if claims.get("email_verified") is True else None, workspace_id, request_meta)\n    if admission_failure:\n        return admission_failure\n    terms = _clean(payload.get("accepted_terms_version"), 80)'))
s=function(s,'exchange',lambda t:replace(t,'        graph = _identity_graph_check(provider, account, linked)','        admission_failure = public_identity._admission_for_account(account, request_meta)\n        if admission_failure:\n            return admission_failure\n        graph = _identity_graph_check(provider, account, linked)'))
s=function(s,'exchange',lambda t:replace(t,'    existing = store.get_account_by_email_hash(claims["verified_email_hash"], workspace_id)','    admission_failure = public_identity._admission_for_hash(claims["verified_email_hash"], workspace_id, request_meta)\n    if admission_failure:\n        return admission_failure\n    existing = store.get_account_by_email_hash(claims["verified_email_hash"], workspace_id)'))
s=function(s,'_recent_authenticated_account',lambda t:replace(t,'public_identity._session_account(headers, request_meta)','public_identity._session_account(headers, request_meta, require_admission=True)'))
texts['core_identity_social.py']=s
s=texts['core_identity_session.py']
s=function(s,'logout_session',lambda t:replace(t,'        revoked = bool(result.get("ok"))','''        # Read back the current credential only. Unknown/already inactive logout
        # remains idempotent, while failed durable revocation cannot report success.
        validation = credential_store.validate_session_hash(credential_store.hash_secret(session_id))
        if validation.get("active") is not False:
            return error("identity_session_logout_incomplete", 503)
        revoked = bool(result.get("ok"))'''))
texts['core_identity_session.py']=s
s=texts['core_identity_api.py']
s=function(s,'core_identity_logout',lambda t:replace(t,'    result["public_refresh_credentials_revoked"]', '    _raise_if_error(result)\n    result["public_refresh_credentials_revoked"]'))
s=function(s,'core_identity_session_resolve',lambda t:replace(t,'                        int(projection_result.get("status_code") or 403),','                        int(projection_result.get("status_code") or 403),\n                        "Sign in with an approved LiveUIN pilot account.",'))
# The same raw preview door exists in both deployed Identity assemblies.
guard=(ROOT/'source/preview_route_guard.txt').read_text()
def guard_preview(api):
    api=replace(api,'@router.post("/api/core/identity/login/challenges")',guard+'@router.post("/api/core/identity/login/challenges")')
    for name in ['core_identity_login_create','core_identity_login_verify']:
        api=function(api,name,lambda t:replace(t,'    return _raise_if_error(identity_login.','    _require_local_identity_preview(request)\n    return _raise_if_error(identity_login.'))
    return api
texts['core_identity_api.py']=guard_preview(s)
# This older9098 compatibility adapter has no canonical Ops/Host membership
# resolver. Actual approved browser adapters are served by9095 only.
for name in ['ops_auth_request_code_compat','ops_auth_verify_code_compat']:
    if name=='ops_auth_request_code_compat':
        texts['core_identity_api.py']=function(texts['core_identity_api.py'],name,lambda t:replace(t,'    return _raise_if_error(browser_auth_request_code','    _require_local_identity_preview(request)\n    return _raise_if_error(browser_auth_request_code'))
    else:
        texts['core_identity_api.py']=function(texts['core_identity_api.py'],name,lambda t:replace(t,'    result = _raise_if_error(browser_auth_verify_code','    _require_local_identity_preview(request)\n    result = _raise_if_error(browser_auth_verify_code'))
legacy_source=Path('/private/tmp/liveuin-p06-audit-20261019/reaudit/auth01-negative-tests/source/core_identity_api.py')
legacy_bytes=legacy_source.read_bytes()
legacy_sha='fcf8c612f2442ab05a8950523890806af7b89f88e9cbf801fcc5561ec1d6acc4'
assert hashlib.sha256(legacy_bytes).hexdigest()==legacy_sha
legacy_candidate=guard_preview(legacy_bytes.decode())
# A missing production environment must not enable raw preview codes on any host.
legacy_candidate=function(legacy_candidate,'_local_preview_request',lambda t:replace(t,'    if environment in {"prod", "production"}:','''    environments = {str(os.getenv(name) or "").strip().lower()
                    for name in ("LIVEUIN_ENVIRONMENT", "ENVIRONMENT", "LIVEUIN_ENV")
                    if str(os.getenv(name) or "").strip()}
    if not environments or not environments.issubset({"dev", "development", "test", "testing", "staging"}):'''))
legacy_candidate=function(legacy_candidate,'browser_auth_request_code',lambda t:replace(t,'    payload = payload if isinstance(payload, dict) else {}','''    payload = payload if isinstance(payload, dict) else {}
    declared_surface = str(payload.get("surface") or "").strip().lower()
    declared_role = str(payload.get("liveuin_role") or payload.get("role") or "").strip().lower()
    declared_purpose = str(payload.get("purpose") or "").strip().lower()
    if not declared_purpose:
        declared_purpose = "connect_admin" if declared_role in {"agent", "connector_admin"} else "operator_portal"
    if declared_surface not in {"ops_command", "operator_portal", "host_workspace"} or (declared_surface != "host_workspace" and declared_purpose != "operator_portal"):
        return {"ok": False, "status_code": 403, "detail": "browser_sign_in_unavailable"}'''))
legacy_candidate=function(legacy_candidate,'browser_auth_request_code',lambda t:replace(t,'    ops_login_surface = surface in {"ops_command", "operator_portal"}',
'''    # Only existing membership-bound browser flows may issue a production code.
    # Connect/Partner and caller-selected roles have no admission authority here.
    if surface not in {"ops_command", "operator_portal", "host_workspace"} or purpose != "operator_portal":
        return {"ok": False, "status_code": 403, "detail": "browser_sign_in_unavailable"}
    ops_login_surface = surface in {"ops_command", "operator_portal"}'''))
legacy_candidate=function(legacy_candidate,'browser_auth_request_code',lambda t:replace(t,'    created = identity_login.create_login_challenge(',
'''    if not workspace_id or not requested_role or not scopes:
        return {"ok": False, "status_code": 403, "detail": "browser_sign_in_unavailable"}

    created = identity_login.create_login_challenge('''))
legacy_candidate=function(legacy_candidate,'browser_auth_verify_code',lambda t:replace(t,'    host_login = str(metadata.get("surface") or "").strip().lower() == "host_workspace"',
'''    canonical_surface = str(metadata.get("surface") or "").strip().lower()
    canonical_purpose = str(challenge.get("purpose") or "").strip().lower() if isinstance(challenge, dict) else ""
    if canonical_surface not in {"ops_command", "operator_portal", "host_workspace"} or canonical_purpose != "operator_portal":
        return {"ok": False, "status_code": 403, "detail": "browser_sign_in_unavailable"}
    host_login = canonical_surface == "host_workspace"'''))
legacy_candidate=function(legacy_candidate,'browser_auth_verify_code',lambda t:replace(t,'    verification_options = (',
'''    if not trusted_role or not trusted_scopes or not verification_payload.get("workspace_id"):
        return {"ok": False, "status_code": 403, "detail": "browser_sign_in_unavailable"}
    verification_options = ('''))
# Fail-closed recovery keeps existing signed sessions/resolution available but
# temporarily refuses all new compatibility email-code logins.
legacy_fallback=guard_preview(legacy_bytes.decode())
def closed_adapter(fragment):
    node=ast.parse(fragment).body[0]
    header=''.join(fragment.splitlines(keepends=True)[:node.body[0].lineno-1])
    return header+'    return {"ok": False, "status_code": 503, "detail": "browser_sign_in_temporarily_locked"}\n'
for name in ['browser_auth_request_code','browser_auth_verify_code']:
    legacy_fallback=function(legacy_fallback,name,closed_adapter)
ast.parse(legacy_fallback,feature_version=(3,10))
(ROOT/'fallback-9095/deploy').mkdir(parents=True,exist_ok=True)
(ROOT/'fallback-9095/deploy/core_identity_api.py').write_text(legacy_fallback)
(ROOT/'fallback-9095-manifest.json').write_text(json.dumps({'status':'closed recovery only; existing session resolution preserved; new email-code logins refused','file':'core_identity_api.py','baseline_sha256':legacy_sha,'candidate_sha256':hashlib.sha256(legacy_fallback.encode()).hexdigest()},indent=2)+'\n')
ast.parse(legacy_candidate,feature_version=(3,10))
(ROOT/'baseline-9095').mkdir(exist_ok=True)
(ROOT/'candidate-9095/deploy').mkdir(parents=True,exist_ok=True)
(ROOT/'baseline-9095/core_identity_api.py').write_bytes(legacy_bytes)
(ROOT/'candidate-9095/deploy/core_identity_api.py').write_text(legacy_candidate)
(ROOT/'candidate-9095.diff').write_text(''.join(difflib.unified_diff(legacy_bytes.decode().splitlines(keepends=True),legacy_candidate.splitlines(keepends=True),fromfile='baseline-9095/core_identity_api.py',tofile='candidate-9095/core_identity_api.py')))
(ROOT/'candidate-9095-manifest.json').write_text(json.dumps({'status':'local candidate only; raw HTTP preview guarded; browser adapters restricted to existing membership-bound Ops/Host paths','file':'core_identity_api.py','baseline_sha256':legacy_sha,'candidate_sha256':hashlib.sha256(legacy_candidate.encode()).hexdigest()},indent=2)+'\n')
helper=ROOT/'source/core_identity_release_admission.py'
texts[helper.name]=helper.read_text()
for name,text in texts.items(): ast.parse(text,filename=name,feature_version=(3,10))
rows=[];diff=[]
for name,text in texts.items():
    old=(SRC/name).read_text() if name in EXPECTED else ''
    if name in EXPECTED:(ROOT/'baseline'/name).write_text(old)
    (ROOT/'candidate/deploy'/name).write_text(text)
    rows.append({'file':name,'baseline_sha256':EXPECTED.get(name),'candidate_sha256':hashlib.sha256(text.encode()).hexdigest()})
    diff.extend(difflib.unified_diff(old.splitlines(keepends=True),text.splitlines(keepends=True),fromfile='baseline/'+name,tofile='candidate/'+name))
(ROOT/'candidate.diff').write_text(''.join(diff))
(ROOT/'candidate-manifest.json').write_text(json.dumps({'status':'local candidate only; activation held pending confirmed approved cohort and proofs','files':rows},indent=2)+'\n')
print(json.dumps({'files':len(rows),'diff_lines':len(diff),'manifest_sha256':hashlib.sha256((ROOT/'candidate-manifest.json').read_bytes()).hexdigest()}))
