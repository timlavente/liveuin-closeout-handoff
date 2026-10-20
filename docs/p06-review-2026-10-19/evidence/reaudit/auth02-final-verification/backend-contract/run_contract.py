"""Exact deployed AUTH-02 source contract, isolated stores, no live calls/mail."""
from __future__ import annotations
import ast, asyncio, hashlib, importlib.metadata, json, os, sqlite3, sys, tempfile, time
from unittest.mock import patch
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'
RESULT = ROOT / 'result.json'
MANIFEST = json.loads((ROOT / 'source-manifest.json').read_text())
for row in MANIFEST['files']:
    assert hashlib.sha256((SOURCE / row['name']).read_bytes()).hexdigest() == row['sha256']
fixture = Path(tempfile.mkdtemp(prefix='auth02-fixture-',dir=ROOT)).resolve()
os.chmod(fixture,0o700)
for key in list(os.environ):
    if key.startswith(('LIVEUIN_','OTP_','PG','DATABASE_')): os.environ.pop(key)
for suffix,filename in {
    'IDENTITY':'identity.sqlite3','IDENTITY_PUBLIC':'public.sqlite3','IDENTITY_SESSION':'session.sqlite3',
    'IDENTITY_LOGIN':'login.sqlite3','ACCESS':'access.sqlite3','ADAPTER_SECRET':'adapter-secret.sqlite3',
    'EXCEPTIONAL_AUTHORITY':'exceptional.sqlite3','IDENTITY_PROVIDER_CREDENTIAL':'provider.sqlite3',
}.items():
    os.environ[f'LIVEUIN_CORE_{suffix}_SQLITE_PATH']=str(fixture/filename)
    os.environ[f'LIVEUIN_CORE_{suffix}_DATA_DIR']=str(fixture/(suffix.lower()+'-data'))
sink=fixture/'delivery.jsonl'
os.environ.update({
    'LIVEUIN_ENVIRONMENT':'staging','LIVEUIN_PUBLIC_REGISTRATION_ENABLED':'true',
    'LIVEUIN_PUBLIC_WORKSPACE_ID':'auth02-isolated-public','LIVEUIN_PUBLIC_TERMS_VERSION':'AUTH02-NONBINDING-FIXTURE-TERMS',
    'LIVEUIN_IDENTITY_TEST_MODE':'true','LIVEUIN_IDENTITY_EMAIL_DELIVERY_MODE':'test_sink',
    'LIVEUIN_IDENTITY_TEST_SINK_PATH':str(sink),'LIVEUIN_CORE_IDENTITY_PUBLIC_BACKUP_DIR':str(fixture/'backups'),
    'LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET':'AUTH02-isolated-signing-only-0123456789',
    'LIVEUIN_IDENTITY_VERIFICATION_PEPPER':'AUTH02-isolated-verification-only-0123456789',
    'LIVEUIN_IDENTITY_EMAIL_PROVIDER_PEPPER':'AUTH02-isolated-email-only-0123456789',
    'LIVEUIN_IDENTITY_CREDENTIAL_STORE_ENFORCEMENT':'true',
})
sys.dont_write_bytecode=True
import httpx
from fastapi import APIRouter, FastAPI, Body, HTTPException, Request, Response
from fastapi.responses import JSONResponse
versions={k:importlib.metadata.version(k) for k in ['bcrypt','fastapi','httpx','starlette']}
events={'network_attempts':0,'blocked_external_files':0,'sqlite_connections':0}
db_paths=set()
def audit(event,args):
    if event.startswith('socket.') and event not in {'socket.__new__','socket.gethostname'}:
        events['network_attempts']+=1
        raise RuntimeError('network_forbidden_AUTH02')
    if event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn'}:raise RuntimeError('subprocess_forbidden_AUTH02')
    if event=='sqlite3.connect':
        p=Path(str(args[0])).resolve()
        if fixture not in p.parents:raise RuntimeError('nonfixture_database_forbidden_AUTH02')
        db_paths.add(str(p));events['sqlite_connections']+=1
    if event=='open' and isinstance(args[0],(str,bytes)):
        p=Path(os.fsdecode(args[0])).resolve()
        flags=args[2] if len(args)>2 and isinstance(args[2],int) else 0
        writing=bool(flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
        if writing and fixture not in p.parents and p!=RESULT:raise RuntimeError('nonfixture_write_forbidden_AUTH02')
        if str(p).startswith(('/opt/liveuin','/srv/','/var/lib/','/etc/liveuin','/Users/Vivian/Documents/')):
            events['blocked_external_files']+=1;raise RuntimeError('production_or_cloud_read_forbidden_AUTH02')
sys.addaudithook(audit)
sys.path.insert(0,str(SOURCE))
import core_identity_public as public
import core_identity_session as session
import core_service_secret_resolver as service_secrets
import core_identity_release_admission as admission
import core_identity_social as social
assert public.store.sqlite_path()==fixture/'public.sqlite3'
assert public.identity_store.sqlite_path()==fixture/'identity.sqlite3'
assert session.credential_store.sqlite_path()==fixture/'session.sqlite3'

# Select unchanged deployed API AST nodes; retain route decorators and actual guards.
# Avoid importing unrelated providers, guests, case projection or notification APIs.
names={'_request_meta','_request_context','_raise_if_error','_public_http','_public_call',
       '_require_authenticated_identity','_require_identity_admin',
       'core_identity_public_registration','core_identity_public_registration_verify',
       'core_identity_public_password_sign_in','core_identity_public_session_refresh',
       'core_identity_public_registration_resend','core_identity_public_profile','core_identity_public_onboarding_complete','core_identity_public_onboarding_status',
       'core_identity_session_resolve','core_identity_logout','core_identity_session_issue'}
path=SOURCE/'core_identity_api.py';tree=ast.parse(path.read_text(),filename=str(path))
selected=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in names]
assert {n.name for n in selected}==names
extracted=[{'file':path.name,'function':n.name,'start_line':n.lineno,'end_line':n.end_lineno,
    'ast_sha256':hashlib.sha256(ast.dump(n,include_attributes=False).encode()).hexdigest()} for n in selected]
router=APIRouter()
g={'Any':Any,'Dict':Dict,'APIRouter':APIRouter,'Body':Body,'HTTPException':HTTPException,'Request':Request,
   'Response':Response,'JSONResponse':JSONResponse,'router':router,'identity_session':session,'public_identity':public,
   'service_secrets':service_secrets}
module=ast.Module(body=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0),*selected],type_ignores=[])
ast.fix_missing_locations(module);exec(compile(module,str(path),'exec'),g)
app=FastAPI();app.include_router(router)
rows=[]
secrets=[]
fixture_projection={}
def expect(name,condition,*,required=True,**evidence):
    rows.append({'test':name,'passed':bool(condition),'stop_immediately_on_failure':required,**evidence})
    if required and not condition:raise AssertionError(name)
def code(result):return result.get('error',{}).get('code') or result.get('detail')
def set_cohort(emails):
    os.environ['LIVEUIN_PUBLIC_ADMISSION_COHORT_JSON']=json.dumps({'schema_version':1,'workspace_id':'auth02-isolated-public','allowed_email_sha256':[hashlib.sha256(e.lower().encode()).hexdigest() for e in emails]})
def deliveries():return [json.loads(x) for x in sink.read_text().splitlines()] if sink.exists() else []
def credential(result):
    secret=result['one_time_credential'];secrets.extend([secret['session_id'],result['refresh_token']])
    return secret['session_headers'],result['refresh_token']
async def run():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,raise_app_exceptions=False),base_url='http://localhost') as client:
        base='/api/core/identity'
        email='test.parent@auth02.example.test'
        password='AUTH02-local-parent-Password-2026';secrets.append(password)
        payload={'email':email,'password':password,'accepted_terms_version':'AUTH02-NONBINDING-FIXTURE-TERMS',
                 'requested_default_profile':'tenant','workspace_id':'attacker-workspace','role':'super_admin',
                 'idempotency_key':'AUTH02-fixture-parent-registration'}
        os.environ['LIVEUIN_PUBLIC_REGISTRATION_ENABLED']='false'
        disabled=await client.post(base+'/registrations',json=payload)
        expect('registration_switch_false_denies_before_delivery',disabled.status_code==503 and code(disabled.json())=='public_registration_disabled' and not deliveries(),status=disabled.status_code)
        os.environ['LIVEUIN_PUBLIC_REGISTRATION_ENABLED']='true'
        absent=await client.post(base+'/registrations',json=payload)
        expect('cohort_missing_denies_before_account_or_email',absent.status_code==403 and code(absent.json())=='pilot_admission_required' and not deliveries() and not (fixture/'public.sqlite3').exists(),status=absent.status_code)
        invalids=['{}','null','[]','{"schema_version":1,"schema_version":1,"workspace_id":"auth02-isolated-public","allowed_email_sha256":[]}',
                  json.dumps({'schema_version':True,'workspace_id':'auth02-isolated-public','allowed_email_sha256':['a'*64]}),
                  json.dumps({'schema_version':1,'workspace_id':'wrong','allowed_email_sha256':['a'*64]}),
                  json.dumps({'schema_version':1,'workspace_id':'auth02-isolated-public','allowed_email_sha256':['a'*64,'a'*64]}),
                  json.dumps({'schema_version':1,'workspace_id':'auth02-isolated-public','allowed_email_sha256':['A'*64]})]
        for raw in invalids:
            os.environ['LIVEUIN_PUBLIC_ADMISSION_COHORT_JSON']=raw
            denied=await client.post(base+'/registrations',json=payload)
            expect('malformed_or_mismatched_cohort_denies_'+str(invalids.index(raw)),denied.status_code==403 and not deliveries(),status=denied.status_code)
        set_cohort([email,'unknown@auth02.example.test'])
        unapproved=await client.post(base+'/registrations',json={**payload,'email':'outsider@auth02.example.test','idempotency_key':'outsider-fixture'})
        expect('noncohort_registration_denied_without_account_or_delivery',unapproved.status_code==403 and code(unapproved.json())=='pilot_admission_required' and not deliveries() and not (fixture/'public.sqlite3').exists(),status=unapproved.status_code)
        started=await client.post(base+'/registrations',json=payload);sb=started.json()
        expect('real_registration_contract_creates_pending_fixture',started.status_code==201 and sb.get('status')=='registration_started',status=started.status_code,error=code(sb))
        rid=sb['registration_id'];d=deliveries();otp=d[-1]['code'];secrets.append(otp)
        expect('test_sink_only_no_raw_code_in_response',len(d)==1 and sb.get('raw_verification_code_returned') is False and 'verification_code' not in sb)
        retry=await client.post(base+'/registrations',json=payload)
        expect('idempotent_registration_does_not_resend',retry.status_code==201 and retry.json()['registration_id']==rid and len(deliveries())==1)
        blocked=await client.post(base+'/sessions/password',json={'email':email,'password':password})
        expect('unverified_account_cannot_password_login',blocked.status_code==403 and code(blocked.json())=='email_unverified',status=blocked.status_code)
        wrongotp='000000' if otp!='000000' else '000001'
        wrong=await client.post(base+f'/registrations/{rid}/verify',json={'verification_code':wrongotp})
        expect('incorrect_code_refused',wrong.status_code==403 and code(wrong.json())=='invalid_verification_code',status=wrong.status_code)
        set_cohort(['unknown@auth02.example.test'])
        heldverify=await client.post(base+f'/registrations/{rid}/verify',json={'verification_code':otp})
        heldresend=await client.post(base+f'/registrations/{rid}/resend',json={'email':email,'idempotency_key':'held-resend'})
        expect('removed_pending_identity_cannot_verify_or_resend',heldverify.status_code==heldresend.status_code==403 and code(heldverify.json())==code(heldresend.json())=='pilot_admission_required' and len(deliveries())==1,verify_status=heldverify.status_code,resend_status=heldresend.status_code)
        set_cohort([email,'unknown@auth02.example.test'])
        verified=await client.post(base+f'/registrations/{rid}/verify',json={'verification_code':otp});vb=verified.json()
        expect('code_verified_without_manual_verified_store_write',verified.status_code==200 and vb.get('status')=='authenticated' and vb.get('authorized_profiles')==[],status=verified.status_code,error=code(vb))
        vh,vr=credential(vb)
        replay=await client.post(base+f'/registrations/{rid}/verify',json={'verification_code':otp})
        expect('reused_registration_code_refused',replay.status_code==409 and code(replay.json())=='verification_not_pending',status=replay.status_code)
        firstout=await client.post(base+'/logout',headers=vh)
        expect('registration_session_explicit_logout_revokes_refresh',firstout.status_code==200 and firstout.json().get('revoked') is True and firstout.json().get('public_refresh_credentials_revoked')==1)
        wrongpw=await client.post(base+'/sessions/password',json={'email':email,'password':'AUTH02-Wrong-Password-2026'})
        unknown=await client.post(base+'/sessions/password',json={'email':'unknown@auth02.example.test','password':password})
        expect('wrong_and_unknown_password_credentials_refused',wrongpw.status_code==unknown.status_code==401 and code(wrongpw.json())==code(unknown.json())=='invalid_credentials',status=wrongpw.status_code)
        # Password login remains available to existing accounts with registration disabled.
        # This is baseline behavior, not an assertion of owner-approved admission.
        os.environ['LIVEUIN_PUBLIC_REGISTRATION_ENABLED']='false'
        signed=await client.post(base+'/sessions/password',json={'email':email,'password':password,'workspace_id':'attacker-workspace','role':'super_admin'})
        body=signed.json();expect('real_password_signin_success',signed.status_code==200 and body.get('status')=='authenticated',status=signed.status_code,error=code(body))
        headers,refresh=credential(body)
        resolved=await client.post(base+'/session/resolve',headers=headers,json={});rb=resolved.json()
        expect('reload_resolves_same_member_in_configured_workspace',resolved.status_code==200 and rb.get('workspace_id')=='auth02-isolated-public' and rb.get('actor',{}).get('role')=='member' and rb.get('account_id') and rb.get('person_id'),status=resolved.status_code,role=rb.get('actor',{}).get('role'),workspace=rb.get('workspace_id'))
        expect('no_tenant_staff_case_or_host_grant_needed',rb.get('authorized_profiles')==[] and rb.get('actor',{}).get('scopes')==['identity.session'],scopes=rb.get('actor',{}).get('scopes'),profile_state=rb.get('profile_state'))
        again=await client.post(base+'/session/resolve',headers=headers,json={})
        expect('second_resolve_preserves_account_person',again.status_code==200 and again.json().get('account_id')==rb['account_id'] and again.json().get('person_id')==rb['person_id'])
        admin=await client.post(base+'/session/issue',headers=headers,json={})
        expect('member_refused_identity_admin_operation',admin.status_code==403 and code(admin.json())=='identity_admin_authorization_required',status=admin.status_code)
        forgery=await client.post(base+'/session/resolve',headers=headers,json={'workspace_id':'attacker-workspace','actor':{'role':'super_admin'}})
        expect('client_workspace_role_cannot_override_verified_identity',forgery.status_code==403,status=forgery.status_code)
        set_cohort(['unknown@auth02.example.test'])
        heldpw=await client.post(base+'/sessions/password',json={'email':email,'password':password})
        heldresolve=await client.post(base+'/session/resolve',headers=headers,json={})
        heldrefresh=await client.post(base+'/sessions/refresh',json={'refresh_token':refresh})
        heldprofile=await client.patch(base+'/profile',headers=headers,json={'display_name':'Synthetic Parent','locale':'en'})
        heldonboarding=await client.post(base+'/onboarding/complete',headers=headers,json={})
        heldstatus=await client.get(base+'/onboarding/status',headers=headers)
        expect('removed_cohort_cannot_signin_bootstrap_refresh_or_onboard',all(r.status_code==403 for r in [heldpw,heldresolve,heldrefresh,heldprofile,heldonboarding,heldstatus]),statuses=[r.status_code for r in [heldpw,heldresolve,heldrefresh,heldprofile,heldonboarding,heldstatus]])
        before=public.store.get_account_by_email_hash(public._email_hash(email),'auth02-isolated-public')
        expect('admission_denials_do_not_grant_or_complete_profile',before['tenant_entitlement_state']=='not_issued' and before['profile_completion_state']=='incomplete')
        # Logout remains available even after admission is withdrawn.
        out=await client.post(base+'/logout',headers=headers);ob=out.json()
        expect('explicit_header_logout_revokes_server_session_and_refresh',out.status_code==200 and ob.get('revoked') is True and ob.get('public_refresh_credentials_revoked')==1 and len(out.headers.get_list('set-cookie'))>=6,status=out.status_code)
        old=await client.post(base+'/session/resolve',headers=headers,json={})
        refreshold=await client.post(base+'/sessions/refresh',json={'refresh_token':refresh})
        expect('logged_out_explicit_session_and_refresh_cannot_restore',old.status_code in {401,403} and refreshold.status_code==401,resolve_status=old.status_code,refresh_status=refreshold.status_code)
        anon=await client.post(base+'/session/resolve',json={})
        expect('signed_out_bootstrap_denied',anon.status_code in {401,403},status=anon.status_code)
        set_cohort([email,'unknown@auth02.example.test'])
        # Re-test cookie-only server logout separately; do not mask failure.
        cookie_sign=await client.post(base+'/sessions/password',json={'email':email,'password':password});ch,cr=credential(cookie_sign.json())
        cookie_header='; '.join(f'{cookie_name}={ch[header_name]}' for cookie_name,header_name in session.COOKIE_TO_HEADER.items() if header_name in ch)
        cookies={'Cookie':cookie_header}
        ckresolve=await client.post(base+'/session/resolve',headers=cookies,json={})
        expect('cookie_only_session_resolves_before_logout',ckresolve.status_code==200,status=ckresolve.status_code)
        ckout=await client.post(base+'/logout',headers=cookies)
        ckold=await client.post(base+'/session/resolve',headers=cookies,json={})
        ckrefresh=await client.post(base+'/sessions/refresh',json={'refresh_token':cr})
        expect('cookie_only_logout_must_revoke_refresh',ckout.status_code==200 and ckout.json().get('revoked') is True and ckold.status_code in {401,403} and ckrefresh.status_code==401,required=False,
            logout_status=ckout.status_code,session_revoked=ckout.json().get('revoked'),refresh_revoked_count=ckout.json().get('public_refresh_credentials_revoked'),old_session_status=ckold.status_code,refresh_status=ckrefresh.status_code,refresh_result=ckrefresh.json().get('status') or code(ckrefresh.json()))
        if ckrefresh.status_code==200:
            h,_=credential(ckrefresh.json());await client.post(base+'/logout',headers=h)
        # Fault-injected empty storage revocation on a known active fixture session.
        # The production verifier stays actual; only its store-failure outcome is injected.
        fs=await client.post(base+'/sessions/password',json={'email':email,'password':password});fh,fr=credential(fs.json())
        with patch.object(session.credential_store,'revoke_session',return_value={}):
            failedout=await client.post(base+'/logout',headers=fh)
        stillactive=await client.post(base+'/session/resolve',headers=fh,json={})
        expect('active_session_revoke_failure_must_not_ack_logout',failedout.status_code>=400 and stillactive.status_code==200,required=False,
            injected_failure='session credential store returned no revocation for known active fixture',logout_status=failedout.status_code,
            logout_ack=failedout.json().get('ok'),revoked=failedout.json().get('revoked'),remaining_session_status=stillactive.status_code)
        await client.post(base+'/logout',headers=fh)
        ss=await client.post(base+'/sessions/password',json={'email':email,'password':password});sh,sr=credential(ss.json())
        with patch.object(public.store,'revoke_refresh_for_session',side_effect=sqlite3.OperationalError('isolated injected refresh write failure')):
            storefailed=await client.post(base+'/logout',headers=sh)
        expect('refresh_storage_exception_does_not_ack_success',storefailed.status_code>=500,status=storefailed.status_code)
        await client.post(base+'/logout',headers=sh)
        unknownout=await client.post(base+'/logout',headers={'X-LiveUIN-Session-Id':'isolated-nonexistent-session'})
        expect('already_absent_session_logout_idempotent',unknownout.status_code==200 and unknownout.json().get('ok') is True,status=unknownout.status_code)
        ps=await client.post(base+'/sessions/password',json={'email':email,'password':password});ph,pr=credential(ps.json())
        pf=await client.patch(base+'/profile',headers=ph,json={'display_name':'test.parent — synthetic fixture','locale':'en'})
        onboard=await client.post(base+'/onboarding/complete',headers=ph,json={});onboardbody=onboard.json()
        expect('admitted_named_fixture_can_complete_normal_tenant_onboarding',pf.status_code==200 and onboard.status_code==200 and onboardbody.get('profile_state')=='tenant_active',profile_status=pf.status_code,onboarding_status=onboard.status_code)
        th,tr=credential(onboardbody)
        tenant=await client.post(base+'/session/resolve',headers=th,json={});tb=tenant.json()
        fixture_projection.update(tb)
        expect('normal_onboarding_scopes_tenant_only_no_admin',tenant.status_code==200 and tb.get('actor',{}).get('role') in {'member','tenant'} and set(tb.get('actor',{}).get('scopes',[]))=={'tenant'} and len(tb.get('authorized_profiles',[]))==1 and tb['authorized_profiles'][0]['profile_key']=='tenant',status=tenant.status_code,role=tb.get('actor',{}).get('role'),scopes=tb.get('actor',{}).get('scopes'))
        await client.post(base+'/logout',headers=th)
        # A false/zero refresh-store acknowledgement must also fail durable readback.
        zs=await client.post(base+'/sessions/password',json={'email':email,'password':password});zh,zr=credential(zs.json())
        with patch.object(public.store,'revoke_refresh_for_session',return_value=0):
            zeroout=await client.post(base+'/logout',headers=zh)
        expect('silent_refresh_revocation_failure_cannot_ack_logout',zeroout.status_code>=500,status=zeroout.status_code)
        await client.post(base+'/logout',headers=zh)
        # Admission happens after trusted provider verification; fixture stub below is
        # ONLY the IdP boundary, not a claim of Google/OAuth proof.
        os.environ['LIVEUIN_PUBLIC_GOOGLE_IDENTITY_ENABLED']='true'
        os.environ['LIVEUIN_GOOGLE_CLIENT_ID']='AUTH02-fixture-client'
        os.environ['LIVEUIN_GOOGLE_NATIVE_ID_TOKEN_READY']='true'
        claims={'ok':True,'provider':'google','subject':'isolated-outsider-provider','subject_hash':'b'*64,
                'email_verified':True,'verified_email_hash':hashlib.sha256(b'outsider@auth02.example.test').hexdigest(),
                'email_hint':'o***@auth02.example.test','display_name':'fixture','locale':'en'}
        with patch.object(social,'_verified_claims',return_value=claims):
            socialheld=social.exchange('google',{'id_token':'fixture-only','email':email,'accepted_terms_version':'AUTH02-NONBINDING-FIXTURE-TERMS'},{'host':'localhost','ip':'127.0.0.1'})
        expect('verified_noncohort_provider_subject_cannot_create_account',socialheld.get('ok') is False and socialheld.get('status_code')==403 and socialheld.get('error',{}).get('code')=='pilot_admission_required',status=socialheld.get('status_code'),error=socialheld.get('error',{}).get('code'))
        os.environ['LIVEUIN_ENVIRONMENT']='production'
        forbidden=public._deliver_verification_code(email=email,code='123456',registration_id='fixture_only',expires_at=int(time.time())+60,locale='en',request_meta={'host':'localhost','ip':'127.0.0.1'},idempotency_key='fixture')
        expect('production_rejects_test_sink',forbidden.get('ok') is False and forbidden.get('status_code')==503 and forbidden.get('error',{}).get('code')=='email_delivery_unavailable')
        os.environ['LIVEUIN_ENVIRONMENT']='staging'
    expect('isolation_no_network_or_external_files',events['network_attempts']==0 and events['blocked_external_files']==0)
failure=None
try:asyncio.run(run())
except Exception as exc:failure={'class':type(exc).__name__,'message':str(exc)[:180]}
result={'ok':failure is None and all(r['passed'] for r in rows),'baseline_contract_completed':failure is None,
    'fixture_projection':fixture_projection,'run_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'tests':rows,'failure':failure,
    'source_manifest_sha256':hashlib.sha256((ROOT/'source-manifest.json').read_bytes()).hexdigest(),'python':sys.version.split()[0],
    'dependency_versions':versions,'selected_api_functions':extracted,'isolation':{**events,'database_paths':sorted(db_paths),
    'production_records_used':False,'live_email_sent':False,'http_transport':'in-process ASGI only','manual_verified_record_write':False},
    'limits':['Local exact deployed-source contract; not a browser or live runtime pass.','Admission cohort contains local fixture identities only; no production config/account activity.','Dependencies recorded; local runtime is not claimed identical to server.']}
serialized=json.dumps(result,indent=2)+'\n'
assert not any(x and x in serialized for x in secrets)
RESULT.write_text(serialized)
print(json.dumps({'ok':result['ok'],'baseline_contract_completed':result['baseline_contract_completed'],'passed':sum(r['passed'] for r in rows),'total':len(rows),'failure':failure,'result':str(RESULT)}))
raise SystemExit(0 if result['ok'] else 1)
