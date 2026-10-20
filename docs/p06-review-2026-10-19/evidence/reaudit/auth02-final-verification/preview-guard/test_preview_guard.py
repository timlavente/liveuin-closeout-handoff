"""HTTP preview admission-only check. No OTP verifier/provider/store is imported."""
import ast,hashlib,json,os,sys,types
from pathlib import Path
from typing import Any,Dict
from fastapi import APIRouter,Body,Request,HTTPException
ROOT=Path(__file__).resolve().parent
BASE=ROOT.parent/'source/core_identity_api.py'
BASE95=Path('/private/tmp/liveuin-p06-audit-20261019/reaudit/auth01-negative-tests/source/core_identity_api.py')
MANIFEST=json.loads((ROOT/'candidate-9095-manifest.json').read_text())
assert hashlib.sha256(BASE95.read_bytes()).hexdigest()==MANIFEST['baseline_sha256']
assert hashlib.sha256((ROOT/'core_identity_api-9095-candidate.py').read_bytes()).hexdigest()==MANIFEST['candidate_sha256']
rows=[]
def record(name,ok,**more):rows.append({'test':name,'passed':bool(ok),**more})
def functions(path):return {n.name:n for n in ast.parse(path.read_text()).body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
fields=['LIVEUIN_ENVIRONMENT','ENVIRONMENT','LIVEUIN_ENV']
saved={k:os.environ.get(k) for k in fields}
class Delegate:
    def __init__(self):self.calls=[]
    def create_login_challenge(self,*args):self.calls.append('create');return {'ok':True,'only_guard_delegate_marker':True}
    def verify_login_challenge(self,*args):self.calls.append('verify');return {'ok':True,'only_guard_delegate_marker':True}
for label,path,base in [('9095',ROOT/'core_identity_api-9095-candidate.py',BASE95),('9098',ROOT/'source/core_identity_api.py',BASE)]:
    fs=functions(path);old=functions(base)
    for name in (['browser_auth_request_code','browser_auth_verify_code'] if label=='9098' else []):
        record(label+'_'+name+'_unchanged',ast.dump(fs[name],include_attributes=False)==ast.dump(old[name],include_attributes=False))
    if label=='9095':
        untouched=[name for name in old if name not in {'core_identity_login_create','core_identity_login_verify','browser_auth_request_code','browser_auth_verify_code','_local_preview_request'}]
        record('9095_all_other_functions_ast_unchanged',all(ast.dump(fs[name],include_attributes=False)==ast.dump(old[name],include_attributes=False) for name in untouched),functions=len(untouched))
    delegate=Delegate();router=APIRouter()
    names={'_require_local_identity_preview','_request_meta','_raise_if_error','core_identity_login_create','core_identity_login_verify'}
    if label=='9098': names.update({'_request_context','ops_auth_request_code_compat','ops_auth_verify_code_compat'})
    selected=[fs[n] for n in names]
    ns={'os':os,'Request':Request,'Body':Body,'Dict':Dict,'Any':Any,'HTTPException':HTTPException,'router':router,'identity_login':delegate,'browser_auth_request_code':lambda *a,**kw:delegate.create_login_challenge(*a),'browser_auth_verify_code':lambda *a,**kw:delegate.verify_login_challenge(*a)}
    module=ast.Module(body=[ast.ImportFrom(module='__future__',names=[ast.alias(name='annotations')],level=0),*selected],type_ignores=[]);ast.fix_missing_locations(module);exec(compile(module,str(path),'exec'),ns)
    matrix=[
        ('unset_environment',{},'localhost','127.0.0.1',False),
        ('production',{'LIVEUIN_ENVIRONMENT':'production'},'localhost','127.0.0.1',False),
        ('prod',{'LIVEUIN_ENVIRONMENT':'prod'},'localhost','127.0.0.1',False),
        ('unknown_environment',{'LIVEUIN_ENVIRONMENT':'pilot'},'localhost','127.0.0.1',False),
        ('conflicting_prod_env',{'LIVEUIN_ENVIRONMENT':'staging','ENVIRONMENT':'production'},'localhost','127.0.0.1',False),
        ('conflicting_unknown_env',{'LIVEUIN_ENVIRONMENT':'staging','LIVEUIN_ENV':'pilot'},'localhost','127.0.0.1',False),
        ('public_host',{'LIVEUIN_ENVIRONMENT':'staging'},'app.liveuin.com','127.0.0.1',False),
        ('remote_client_forwarded_local',{'LIVEUIN_ENVIRONMENT':'staging'},'localhost','203.0.113.10',False),
        ('non_ip_client',{'LIVEUIN_ENVIRONMENT':'staging'},'localhost','localhost',False),
        ('lookalike_host',{'LIVEUIN_ENVIRONMENT':'staging'},'localhost.evil.example','127.0.0.1',False),
        ('public_prod_spoofed_payload',{'LIVEUIN_ENVIRONMENT':'production'},'app.liveuin.com','203.0.113.10',False),
        ('explicit_dev_loopback',{'LIVEUIN_ENVIRONMENT':'development'},'localhost','127.0.0.1',True),
        ('explicit_staging_loopback',{'ENVIRONMENT':'staging'},'127.0.0.1','127.0.0.1',True),
        ('explicit_test_ipv6_loopback',{'LIVEUIN_ENV':'test'},'[::1]','::1',True),
    ]
    for name,env,host,client,allow in matrix:
        for key in fields:os.environ.pop(key,None)
        os.environ.update(env)
        for operation in (['create','verify','compat_create','compat_verify'] if label=='9098' else ['create','verify']):
            endpoint='/api/core/identity/login/challenges'+('/fixture/verify' if operation=='verify' else '')
            request=Request({'type':'http','http_version':'1.1','method':'POST','scheme':'http','path':endpoint,'raw_path':endpoint.encode(),'query_string':b'',
                'headers':[(b'host',host.encode()),(b'x-forwarded-for',b'127.0.0.1'),(b'x-forwarded-host',b'localhost')],
                'client':(client,12345),'server':('127.0.0.1',9095)})
            payload={'environment':'staging','local_preview':True,'host':'localhost','ip':'127.0.0.1','role':'super_admin'}
            before=len(delegate.calls);status=200;cache='';marked=False
            try:
                if operation=='create': result=ns['core_identity_login_create'](request,payload)
                elif operation=='verify': result=ns['core_identity_login_verify'](request,'fixture',payload)
                elif operation=='compat_create': result=ns['ops_auth_request_code_compat'](request,payload)
                else: result=ns['ops_auth_verify_code_compat'](request,payload)
                marked=result.get('only_guard_delegate_marker') is True
            except HTTPException as exc:status=exc.status_code;cache=(exc.headers or {}).get('Cache-Control','')
            reached=len(delegate.calls)>before
            record(label+'_'+name+'_'+operation,(allow and status==200 and reached and marked) or (not allow and status==404 and not reached and cache=='no-store'),status=status,delegate_reached=reached)
for k,v in saved.items():
    if v is None:os.environ.pop(k,None)
    else:os.environ[k]=v
out={'ok':all(r['passed'] for r in rows),'tests':rows,'scope':'exact HTTP guard and route control-flow only; delegate marker proves call boundary, not OTP/auth success','production_calls':False,'product_store_imports':False,'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [ROOT/'core_identity_api-9095-candidate.py',ROOT/'source/core_identity_api.py']}}
(ROOT/'preview-guard-result.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'ok':out['ok'],'passed':sum(r['passed'] for r in rows),'total':len(rows)}));sys.exit(0 if out['ok'] else 1)
