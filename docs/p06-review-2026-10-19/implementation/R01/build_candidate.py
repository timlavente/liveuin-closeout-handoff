from pathlib import Path
import ast,hashlib,difflib
root=Path(__file__).resolve().parent
expected={'home_api.py':'cab022b1055df93e27328fa74813d8ae043bb1cc387562255eed0d9b68471172','public_home_gateway.py':'67f4befdd7dbccc34bcaa79050b6c990cd3df33349ee4369f7da9838810f6fac'}
for name,digest in expected.items():
 assert hashlib.sha256((root/'before'/name).read_bytes()).hexdigest()==digest, name
home=(root/'before/home_api.py').read_text()
home=home.replace('import importlib.util\n','import importlib.util\nimport json\nimport urllib.error\nimport urllib.request\nfrom http.cookies import CookieError, SimpleCookie\n')
home=home.replace('from fastapi.responses import JSONResponse\n','from fastapi.responses import JSONResponse\nfrom starlette.concurrency import run_in_threadpool\n')
home=home.replace('@lru_cache(maxsize=1)\n',(root/'guard-fragment.py').read_text()+'@lru_cache(maxsize=1)\n',1)
# Modify only the frozen handlers, preserving every public handler verbatim.
t=ast.parse(home)
lines=home.splitlines(keepends=True)
for n in reversed(t.body):
 if not isinstance(n,ast.FunctionDef): continue
 if n.name.startswith(('admin_control_','developer_portal_')):
  fragment=''.join(lines[n.lineno-1:n.end_lineno])
  fragment=fragment.replace('def '+n.name+'(\n','def '+n.name+'(\n    request: Request,\n')
  fragment=fragment.replace('Query(admin_svc.DEFAULT_WORKSPACE_ID,','Query("",').replace('Query(developer_svc.DEFAULT_WORKSPACE_ID,','Query("",')
  fragment=fragment.replace('workspace_id=workspace_id','workspace_id=r01_private_context(request)["workspace_id"]')
  lines[n.lineno-1:n.end_lineno]=[fragment]
 elif n.name.startswith('core_public_cms_') and n.name!='core_public_cms_pages':
  fragment=''.join(lines[n.lineno-1:n.end_lineno])
  fragment=fragment.replace('    preview = _load_preview_module()\n    site_slug = _site_slug(request, site=site, host=host)','    site_slug = r01_private_site(request)\n    preview = _load_preview_module()')
  fragment=fragment.replace('    preview = _load_preview_module()\n    site_slug = _site_slug_from_payload(preview, payload, request)','    site_slug = r01_private_site(request, payload)\n    preview = _load_preview_module()')
  lines[n.lineno-1:n.end_lineno]=[fragment]
home=''.join(lines)
gateway=(root/'before/public_home_gateway.py').read_text()
gateway=gateway.replace('import time\n','import time\nfrom fastapi import Request\n')
gateway=gateway.replace('from .home_api import router as public_home_router','from .home_api import router as public_home_router, install_r01_private_guard, r01_private_context')
gateway=gateway.replace('from home_api import router as public_home_router','from home_api import router as public_home_router, install_r01_private_guard, r01_private_context')
gateway=gateway.replace('    app.include_router(public_home_router)','    install_r01_private_guard(app)\n    app.include_router(public_home_router)')
gateway=gateway.replace('    def liveuintest_rollout_status() -> Dict[str, Any]:\n        return page_route_rollout_status()','    def liveuintest_rollout_status(request: Request) -> Dict[str, Any]:\n        r01_private_context(request)\n        return page_route_rollout_status()')
for name,source in [('home_api.py',home),('public_home_gateway.py',gateway)]:
 ast.parse(source)
 (root/'candidate'/name).write_text(source)
 fallback=source.replace('R01_CLOSED_FALLBACK = False','R01_CLOSED_FALLBACK = True') if name=='home_api.py' else source
 (root/'fallback'/name).write_text(fallback)
 before=(root/'before'/name).read_text()
 (root/'evidence'/(name+'.diff')).write_text(''.join(difflib.unified_diff(before.splitlines(True),source.splitlines(True),fromfile='deployed/'+name,tofile='candidate/'+name)))
print('Built exact two-file candidate and closed fallback; no production writes.')
