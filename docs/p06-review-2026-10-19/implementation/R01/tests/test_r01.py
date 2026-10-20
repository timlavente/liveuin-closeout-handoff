"""R01 tests import both actual staged gateway files; business stores are spies.

No deployment modules, customer files, credentials, databases or network are used.
The identity authority response is synthetic. Separate tests exercise its transport
and the exact deployed signed-session verifier against an in-memory credential.
"""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
import urllib.error
from email.message import Message
from http.cookies import SimpleCookie
from unittest.mock import Mock
import pytest
from fastapi import APIRouter, HTTPException
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = json.loads((ROOT / 'evidence/protected-routes.json').read_text())
ROUTES = [(op['method'].split('.')[-1].upper(), op['path']) for op in INVENTORY['operations']]
BUNDLE = {
    'X-LiveUIN-Workspace-Id': 'liveuin_first_party', 'X-LiveUIN-Actor-Id': 'fixture.platform.admin',
    'X-LiveUIN-Role': 'ops_manager', 'X-LiveUIN-Scopes': 'ops.theme.write,identity.admin',
    'X-LiveUIN-Session-Id': 'sess_SYNTHETIC_FIXTURE', 'X-LiveUIN-Session-Issued-At': '1792424100',
    'X-LiveUIN-Auth-Method': 'signed_internal_session', 'X-LiveUIN-Session-Signature': 'SYNTHETIC_NOT_A_SIGNATURE',
}
CANONICAL = {
    'ok': True, 'auth': True, 'canonical_session_verified': True,
    'claims': {'workspace_id': 'liveuin_first_party', 'actor_id': 'fixture.platform.admin',
               'role': 'ops_manager', 'scopes': ['ops.theme.write', 'identity.admin'],
               'credential_kind': 'liveuin_session'},
}
PAYLOAD = {'post': {'slug': 'synthetic-fixture', 'title': 'Synthetic fixture'},
           'page': {'route': '/synthetic-fixture'}, 'slug': 'synthetic-fixture', 'route': '/synthetic-fixture'}

class SpyService(types.ModuleType):
    def __init__(self, name, calls):
        super().__init__(name)
        self.DEFAULT_WORKSPACE_ID = 'laijuzhu'  # Regression trap: never use sibling default.
        self.SCHEMA_VERSION = 'isolated-synthetic-test'
        self.calls = calls
    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)
        def action(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return {'ok': True, 'method': name, 'args': args, **kwargs}
        return action

@pytest.fixture(params=['candidate'], scope='module')
def runtime(request):
    monkeypatch = pytest.MonkeyPatch()
    variant = request.param
    package_name = 'r01_isolated_' + variant
    package = types.ModuleType(package_name)
    package.__path__ = [str(ROOT / variant)]
    monkeypatch.setitem(sys.modules, package_name, package)
    calls = []
    for name in ('admin_control_service', 'public_china_service', 'developer_portal_service',
                 'public_help_service', 'public_trust_service', 'public_home_service', 'public_status_service'):
        monkeypatch.setitem(sys.modules, package_name + '.' + name, SpyService(name, calls))
    for name, attr in [('core_compliance_api', 'router'), ('core_marketplace_api', 'public_router')]:
        mod = types.ModuleType(name)
        setattr(mod, attr, APIRouter())
        monkeypatch.setitem(sys.modules, package_name + '.' + name, mod)
    pass_mod = types.ModuleType('public_pass_gateway')
    pass_mod.mount_public_pass_routes = lambda app, require_key: None
    monkeypatch.setitem(sys.modules, package_name + '.public_pass_gateway', pass_mod)
    modules = {}
    for name in ('home_api', 'public_home_gateway'):
        key = package_name + '.' + name
        spec = importlib.util.spec_from_file_location(key, ROOT / variant / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, key, module)
        spec.loader.exec_module(module)
        modules[name] = module
    home, gateway = modules['home_api'], modules['public_home_gateway']
    preview = SpyService('preview', calls)
    preview.public_theme_normalize_site_slug = lambda value: str(value)
    preview.normalize_path_for_public_router = lambda value: str(value)
    preview.public_theme_site_slug_from_host = lambda value: 'www'
    loads = []
    def load_preview():
        loads.append('preview')
        return preview
    monkeypatch.setattr(home, '_load_preview_module', load_preview)
    monkeypatch.setattr(gateway, 'page_route_rollout_status', lambda: (calls.append(('rollout', (), {})) or {'ok': True}))
    authority = Mock(return_value=copy.deepcopy(CANONICAL))
    monkeypatch.setattr(home, '_r01_load_authority', authority)
    client = TestClient(gateway.app)
    yield types.SimpleNamespace(home=home, gateway=gateway, client=client, calls=calls, loads=loads, authority=authority, preview=preview)
    client.close()
    monkeypatch.undo()


@pytest.fixture(autouse=True)
def reset_runtime(runtime):
    runtime.calls.clear()
    runtime.loads.clear()
    runtime.authority.reset_mock(return_value=True, side_effect=True)
    runtime.authority.return_value = copy.deepcopy(CANONICAL)


def send(runtime, method, path, *, headers=None, query='', payload=None):
    path = path.replace('{slug}', 'synthetic-fixture') + query
    args = {'headers': {} if headers is None else headers}
    if method == 'POST':
        args['json'] = copy.deepcopy(PAYLOAD if payload is None else payload)
    return runtime.client.request(method, path, **args)


def assert_denied(runtime, response, statuses=(401, 403, 503)):
    assert response.status_code in statuses, response.text
    assert response.headers['cache-control'] == 'no-store'
    assert response.headers['pragma'] == 'no-cache'
    assert not runtime.calls
    assert not runtime.loads


def test_actual_gateway_boots_and_exact_frozen_inventory(runtime):
    schema = runtime.client.get('/openapi.json').json()
    actual = {(method.upper(), path) for path, methods in schema['paths'].items() for method in methods}
    assert len(ROUTES) == 21 and len(set(ROUTES)) == 21
    assert all(route in actual for route in ROUTES)
    frozen = {(m, p) for m, p in actual if runtime.home.r01_private_family(m, p)}
    assert frozen == set(ROUTES)
    assert ('GET', '/api/core/public-cms/pages') not in frozen

@pytest.mark.parametrize('method,path', ROUTES)
def test_anonymous_denied_before_business_and_body_validation(runtime, method, path):
    response = send(runtime, method, path, payload={})
    assert_denied(runtime, response, (401,))
    runtime.authority.assert_not_called()

@pytest.mark.parametrize('method,path', ROUTES)
def test_signed_platform_fixture_all_21_operations(runtime, method, path):
    response = send(runtime, method, path, headers=BUNDLE)
    assert response.status_code == 200, response.text
    assert response.headers['cache-control'] == 'no-store'
    assert len(runtime.calls) == 1
    name, args, kwargs = runtime.calls[0]
    if '/admin/' in path or '/developers/' in path:
        assert kwargs['workspace_id'] == 'liveuin_first_party'
    elif '/public-cms/' in path:
        assert kwargs.get('site_slug', args[0] if args else None) == 'www'
    assert runtime.authority.call_args.args[0] == {'X-LiveUIN-Require-Signed-Session': '1', **BUNDLE}

@pytest.mark.parametrize('method,path', ROUTES)
@pytest.mark.parametrize('workspace', ['test.staff', 'test_liveuin', 'laijuzhu', 'igema', 'other_family'])
def test_other_workspace_never_calls_business(runtime, method, path, workspace):
    runtime.authority.return_value['claims']['workspace_id'] = workspace
    assert_denied(runtime, send(runtime, method, path, headers=BUNDLE), (403,))

@pytest.mark.parametrize('method,path', ROUTES)
@pytest.mark.parametrize('role', ['connector_admin', 'owner', 'operator', 'parent', 'agent', 'landlord', 'finance_ops'])
def test_no_generic_role_bypass(runtime, method, path, role):
    runtime.authority.return_value['claims']['role'] = role
    assert_denied(runtime, send(runtime, method, path, headers=BUNDLE), (403,))

@pytest.mark.parametrize('role', ['ops_manager', 'super_admin'])
def test_existing_platform_roles_require_verified_identity(runtime, role):
    runtime.authority.return_value['claims']['role'] = role
    assert send(runtime, 'GET', '/api/core/developers/portal', headers=BUNDLE).status_code == 200

@pytest.mark.parametrize('scope,allowed', [('ops.theme', False), ('ops.theme.write', False), ('identity.admin', False), ('ops.task.write', False), ('ops.themeEvil', False), ('identity.adminEvil', False)])
def test_unrelated_theme_scope_does_not_grant_cms_access(runtime, scope, allowed):
    runtime.authority.return_value['claims'].update(role='ops', scopes=[scope])
    response = send(runtime, 'POST', '/api/core/public-cms/pages/draft', headers=BUNDLE)
    if allowed:
        assert response.status_code == 200
    else:
        assert_denied(runtime, response, (403,))

@pytest.mark.parametrize('path', ['/api/core/developers/portal', '/api/core/ops/liveuintest-rollout-status', '/api/core/admin/control-center'])
def test_cms_ops_cannot_read_platform_aggregates(runtime, path):
    runtime.authority.return_value['claims'].update(role='ops', scopes=['ops.theme.write', 'identity.admin'])
    assert_denied(runtime, send(runtime, 'GET', path, headers=BUNDLE), (403,))

@pytest.mark.parametrize('headers', [
    {'X-LiveUIN-Role': 'super_admin', 'X-LiveUIN-Workspace-Id': 'liveuin_first_party'},
    {'X-LiveUIN-Connector-API-Key': 'not-a-key'},
    {'X-LiveUIN-API-Key': 'not-a-key'},
    {'Cookie': 'ops_session=legacy-unsigned-fixture'},
    {'Authorization': 'Bearer key_SYNTHETIC'},
    {'Authorization': 'Basic ZmFrZQ=='},
    {**BUNDLE, 'X-LiveUIN-Session-Signature': ''},
])
def test_no_unsigned_connector_legacy_or_incomplete_credential(runtime, headers):
    assert_denied(runtime, send(runtime, 'GET', '/api/core/admin/control-center', headers=headers), (401,))
    runtime.authority.assert_not_called()

@pytest.mark.parametrize('field,value', [
    ('auth', False), ('auth', 'true'), ('canonical_session_verified', False), ('canonical_session_verified', 1),
    ('claims', None), ('claims', []),
])
@pytest.mark.parametrize('method,path', ROUTES)
def test_authority_envelope_fail_closed(runtime, method, path, field, value):
    runtime.authority.return_value[field] = value
    assert_denied(runtime, send(runtime, method, path, headers=BUNDLE), (401,))

@pytest.mark.parametrize('field,value', [
    ('credential_kind', 'connector_api_key'), ('credential_kind', 'liveuin_api_key'),
    ('actor_id', ''), ('actor_id', {}), ('workspace_id', None), ('role', ['ops_manager']),
    ('scopes', 'ops.theme.write'), ('scopes', [True]), ('scopes', ['']),
])
def test_malformed_claims_fail_closed(runtime, field, value):
    runtime.authority.return_value['claims'][field] = value
    assert_denied(runtime, send(runtime, 'GET', '/api/core/admin/control-center', headers=BUNDLE), (401,))

@pytest.mark.parametrize('reason', ['session_expired', 'session_revoked', 'invalid_signature'])
@pytest.mark.parametrize('method,path', ROUTES)
def test_canonical_denial_for_expiry_revocation_or_signature(runtime, method, path, reason):
    runtime.authority.return_value = {'ok': False, 'auth': False, 'canonical_session_verified': False, 'detail': reason}
    assert_denied(runtime, send(runtime, method, path, headers=BUNDLE), (401,))
    assert reason not in send(runtime, method, path, headers=BUNDLE).text

@pytest.mark.parametrize('method,path', ROUTES)
def test_authority_outage_no_business_access(runtime, method, path):
    runtime.authority.side_effect = TimeoutError('synthetic-secret-must-not-leak')
    response = send(runtime, method, path, headers=BUNDLE)
    assert_denied(runtime, response, (503,))
    assert 'synthetic-secret' not in response.text

@pytest.mark.parametrize('query,status', [
    ('?workspace_id=laijuzhu',403), ('?workspace_id=test.staff',403),
    ('?workspace_id=liveuin_first_party&workspace_id=liveuin_first_party',400),
    ('?site=www&site=igema',400), ('?site=www&site_slug=laijuzhu',403),
    ('?site=www&host=laijuzhu.com',403), ('?site=liveuin.com',403),
    ('?host=www.liveuin.com.evil',403), ('?host=https%3A%2F%2Fwww.liveuin.com',403),
    ('?access_context=forged',403), ('?site=',403),
])
def test_every_query_scope_alias_checked(runtime, query, status):
    assert_denied(runtime, send(runtime,'GET','/api/core/public-cms/blog/posts',headers=BUNDLE,query=query),(status,))

@pytest.mark.parametrize('selector', [
    {'site':'www','site_slug':'igema'}, {'site':'www','host':'laijuzhu.com'},
    {'workspace_id':'test.staff'}, {'site':[]}, {'host':{}}, {'access':{'role':'super_admin'}},
    {'post':{'slug':'synthetic','site':'igema'}}, {'page':{'route':'/','workspace_id':'igema'}},
])
@pytest.mark.parametrize('method,path', [r for r in ROUTES if r[0]=='POST'])
def test_body_scope_denied_before_preview_loader(runtime, method, path, selector):
    payload=copy.deepcopy(PAYLOAD); payload.update(selector)
    assert_denied(runtime, send(runtime,method,path,headers=BUNDLE,payload=payload),(403,))

@pytest.mark.parametrize('query', ['?site=www&host=liveuin.com', '?site_slug=www&host=www.liveuin.com:443', '?workspace_id=liveuin_first_party'])
def test_matching_aliases_preserve_www(runtime, query):
    response=send(runtime,'GET','/api/core/public-cms/blog/posts',headers={**BUNDLE,'Host':'igema.space','X-Forwarded-Host':'laijuzhu.com'},query=query)
    assert response.status_code==200
    assert runtime.calls[0][2]['site_slug']=='www'


def cookie_headers(home):
    jar=SimpleCookie()
    for name,value in zip(home.R01_COOKIE_NAMES, BUNDLE.values()): jar[name]=value
    return {'Cookie': '; '.join(m.OutputString() for m in jar.values())}

@pytest.mark.parametrize('origin', ['', 'null', 'http://ops.liveuin.com', 'https://evil.example', 'https://ops.liveuin.com.evil'])
def test_cookie_cms_write_csrf_denied(runtime, origin):
    headers=cookie_headers(runtime.home)
    if origin: headers['Origin']=origin
    assert_denied(runtime,send(runtime,'POST','/api/core/public-cms/pages/draft',headers=headers),(403,))
    runtime.authority.assert_not_called()


def test_cookie_cms_write_known_origin_and_body_replayed(runtime):
    headers={**cookie_headers(runtime.home),'Origin':'https://ops.liveuin.com'}
    response=send(runtime,'POST','/api/core/public-cms/pages/draft',headers=headers)
    assert response.status_code==200,response.text
    assert runtime.calls[0][1][1]==PAYLOAD['page']
    forwarded=runtime.authority.call_args.args[0]
    assert set(forwarded)=={'Cookie','X-LiveUIN-Require-Signed-Session'}


def test_bearer_never_forwards_unsigned_selectors(runtime):
    headers={'Authorization':'Bearer sess_SYNTHETIC','X-LiveUIN-Requested-Workspace-Id':'laijuzhu','X-LiveUIN-Connector-API-Key':'fake'}
    assert send(runtime,'GET','/api/core/admin/control-center',headers=headers).status_code==200
    assert runtime.authority.call_args.args[0]=={'Authorization':'Bearer sess_SYNTHETIC','X-LiveUIN-Require-Signed-Session':'1'}


def test_bearer_plus_unsigned_workspace_is_refused(runtime):
    headers={'Authorization':'Bearer sess_SYNTHETIC','X-LiveUIN-Workspace-Id':'liveuin_first_party'}
    assert_denied(runtime,send(runtime,'GET','/api/core/admin/control-center',headers=headers),(401,))
    runtime.authority.assert_not_called()


def test_complete_signed_bundle_precedence_never_mixes_credentials(runtime):
    headers={**BUNDLE,**cookie_headers(runtime.home),'Authorization':'Bearer sess_OTHER','X-LiveUIN-Connector-API-Key':'fake','X-LiveUIN-Requested-Profile-Key':'fake'}
    assert send(runtime,'GET','/api/core/admin/control-center',headers=headers).status_code==200
    assert runtime.authority.call_args.args[0]=={'X-LiveUIN-Require-Signed-Session':'1',**BUNDLE}


def test_cookie_read_works_without_origin(runtime):
    assert send(runtime,'GET','/api/core/public-cms/blog/posts',headers=cookie_headers(runtime.home)).status_code==200

@pytest.mark.parametrize('extra', [{'Origin':'https://evil.example'}, {'Origin':'https://ops.liveuin.com','Sec-Fetch-Site':'cross-site'}])
def test_explicit_credentials_still_refuse_hostile_browser_origin(runtime,extra):
    assert_denied(runtime,send(runtime,'POST','/api/core/public-cms/pages/draft',headers={**BUNDLE,**extra}),(403,))

@pytest.mark.parametrize('body', ['{"site":"www","site":"igema","page":{}}', '{broken', '[]'])
def test_invalid_or_duplicate_json_never_loads_preview(runtime,body):
    response=runtime.client.post('/api/core/public-cms/pages/draft',headers={**BUNDLE,'Content-Type':'application/json'},content=body)
    assert_denied(runtime,response,(400,))


def test_validation_and_business_errors_are_not_cached(runtime,monkeypatch):
    response=send(runtime,'GET','/api/core/admin/control-center/audit',headers=BUNDLE,query='?limit=invalid')
    assert_denied(runtime,response,(422,))
    def fail(*args,**kwargs): raise RuntimeError('postgres://synthetic-secret@host/private')
    monkeypatch.setattr(runtime.home.admin_svc,'admin_control_summary',fail)
    response=send(runtime,'GET','/api/core/admin/control-center',headers=BUNDLE)
    assert_denied(runtime,response,(503,))
    assert 'postgres' not in response.text


def test_fixed_404_and_public_paths_remain_public(runtime):
    response=runtime.client.get('/api/core/public-cms/pages')
    assert response.status_code==404 and response.json()=={'ok':False,'error':'not_found'}
    assert runtime.client.get('/v1/health').status_code==200
    assert runtime.client.get('/api/public/home/bootstrap').status_code==200
    runtime.authority.assert_not_called()


def test_public_and_fixed404_function_ast_unchanged():
    before=ast.parse((ROOT/'before/home_api.py').read_text())
    after=ast.parse((ROOT/'candidate/home_api.py').read_text())
    expected={n.name:n for n in before.body if isinstance(n,ast.FunctionDef) and (n.name.startswith('public_') or n.name=='core_public_cms_pages')}
    current={n.name:n for n in after.body if isinstance(n,ast.FunctionDef)}
    for name,node in expected.items(): assert ast.dump(node)==ast.dump(current[name]),name

@pytest.mark.parametrize('runtime',['fallback'],indirect=True)
@pytest.mark.parametrize('method,path',ROUTES)
def test_closed_fallback_denies_all_21_without_authority_or_business(runtime,method,path):
    assert_denied(runtime,send(runtime,method,path,headers=BUNDLE),(503,))
    runtime.authority.assert_not_called()

@pytest.mark.parametrize('runtime',['fallback'],indirect=True)
def test_closed_fallback_keeps_public_and_fixed404(runtime):
    test_fixed_404_and_public_paths_remain_public(runtime)

class FakeResponse:
    def __init__(self,raw,status=200,content_type='application/json'):
        self.raw=raw; self.status=status; self.headers=Message(); self.headers['Content-Type']=content_type
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def read(self,n): return self.raw[:n]

@pytest.mark.parametrize('raw,ctype', [(b'[]','application/json'),(b'{bad','application/json'),(b'{"auth":true,"auth":false}','application/json'),(b'{}','text/html'),(b'x'*65537,'application/json')])
def test_authority_transport_rejects_malformed_oversize_and_wrong_type(runtime,monkeypatch,raw,ctype):
    # Restore actual transport function because runtime fixture stubs it.
    namespace={}; source=(ROOT/'candidate/home_api.py').read_text(); tree=ast.parse(source)
    fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_r01_load_authority')
    exec(compile(ast.Module(body=[fn],type_ignores=[]),'<transport>','exec'),runtime.home.__dict__,namespace)
    transport=namespace['_r01_load_authority']
    opener=Mock(); opener.open.return_value=FakeResponse(raw,content_type=ctype)
    monkeypatch.setattr(runtime.home.urllib.request,'build_opener',Mock(return_value=opener))
    with pytest.raises(HTTPException) as error: transport({'X-LiveUIN-Require-Signed-Session':'1'})
    assert error.value.status_code==503
    args=opener.open.call_args
    assert args.kwargs['timeout']==2.5
    assert args.args[0].full_url=='http://127.0.0.1:9095/api/ops/auth/whoami'


def test_authority_no_redirect_or_environment_proxy(runtime,monkeypatch):
    namespace={}; tree=ast.parse((ROOT/'candidate/home_api.py').read_text())
    fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_r01_load_authority')
    exec(compile(ast.Module(body=[fn],type_ignores=[]),'<transport>','exec'),runtime.home.__dict__,namespace)
    transport=namespace['_r01_load_authority']
    opener=Mock(); opener.open.return_value=FakeResponse(json.dumps(CANONICAL).encode())
    builder=Mock(return_value=opener)
    monkeypatch.setattr(runtime.home.urllib.request,'build_opener',builder)
    monkeypatch.setenv('HTTP_PROXY','http://never-contact.invalid:9999')
    assert transport({'X-LiveUIN-Require-Signed-Session':'1'})==CANONICAL
    proxy,redirect=builder.call_args.args
    assert proxy.proxies=={}
    assert redirect.redirect_request(None,None,302,'',{},'https://never-contact.invalid') is None
    opener.open.side_effect=urllib.error.HTTPError('http://127.0.0.1:9095/',302,'redirect',{},None)
    with pytest.raises(HTTPException) as error: transport({})
    assert error.value.status_code==503

@pytest.mark.parametrize('method,path',ROUTES)
def test_trailing_slash_cannot_bypass_guard(runtime,method,path):
    assert_denied(runtime,send(runtime,method,path+'/',payload={}),(401,))
    runtime.authority.assert_not_called()


@pytest.mark.parametrize('credential',['signed','cookie'])
def test_privileged_canonical_empty_scopes_preserves_existing_policy(runtime,credential):
    runtime.authority.return_value['claims']['scopes']=[]
    if credential=='signed':
        headers={**BUNDLE,'X-LiveUIN-Scopes':''}
    else:
        headers=cookie_headers(runtime.home)
        jar=SimpleCookie(); jar.load(headers['Cookie']); jar['LIVEUIN_SCOPES']=''
        headers={'Cookie':'; '.join(m.OutputString() for m in jar.values())}
    response=send(runtime,'GET','/api/core/admin/control-center',headers=headers)
    assert response.status_code==200,response.text

def test_cms_ops_empty_scopes_denied(runtime):
    runtime.authority.return_value['claims'].update(role='ops',scopes=[])
    assert_denied(runtime,send(runtime,'POST','/api/core/public-cms/pages/draft',headers=BUNDLE),(403,))

def test_vary_preserves_cors_origin(runtime):
    response=send(runtime,'GET','/api/core/admin/control-center',headers={**BUNDLE,'Origin':'https://www.liveuin.com'})
    assert response.status_code==200
    assert {'Origin','Cookie','Authorization'} <= set(v.strip() for v in response.headers['vary'].split(','))
