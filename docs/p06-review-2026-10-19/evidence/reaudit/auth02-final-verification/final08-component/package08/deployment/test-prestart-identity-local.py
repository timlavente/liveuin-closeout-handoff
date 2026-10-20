"""Pure AST-selected identity tests. Does not run probe/main/import product code."""
import ast,hashlib,json,copy
from pathlib import Path
p=Path(__file__).with_name('prestart-fastpath-probe.py');s=p.read_text();tree=ast.parse(s)
ns={'Path':Path,'BASE':Path('/opt/liveuin/ops_backend'),'PYTHON':Path('/opt/liveuin/ops_backend/.venv/bin/python')}
selected=[x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name in {'need','prestart_identity','prestart_commands','login_defaults'}]
exec(compile(ast.Module(body=selected,type_ignores=[]),'<selected-pure-functions>','exec'),ns)
checks=[]
def check(name,f,expected=None,error=None):
 try:
  actual=f();ok=error is None and actual==expected
 except RuntimeError as e:ok=error==str(e)
 checks.append({'name':name,'passed':ok})
identity=ns['prestart_identity'];base=(998,998,[998,1005],[1005])
check('observed_root_prestart_identity',lambda:identity(*base,False,True),(0,0,[998,1005]))
check('normal_service_identity',lambda:identity(*base,False,False),(998,998,[998,1005]))
check('normal_additional_group',lambda:identity(998,998,[998],[1005],False,False),(998,998,[998,1005]))
check('root_extra_group_outside_nss_closed',lambda:identity(998,998,[998],[1005],False,True),error='prestart_supplementary_group_semantics_require_review')
check('dynamic_user_closed',lambda:identity(*base,True,True),error='dynamic_prestart_identity_not_supported')
for index,value in enumerate([0,1,'false',None]):
 check('permissions_strict_boolean_'+str(index),lambda value=value:identity(*base,False,value),error='identity_boolean_shape_invalid')
check('dynamic_strict_boolean',lambda:identity(*base,0,True),error='identity_boolean_shape_invalid')
python=str(ns['PYTHON']);commands=[['/bin/sh',['/bin/sh','-c','set -eu; /opt/liveuin/ops_backend/bin/ensure_venv.sh'],[]],['/bin/mkdir',['/bin/mkdir','-p','/var/cache/ops-backend/pycache'],[]],[python,[python,'-m','py_compile','/opt/liveuin/ops_backend/app.py'],[]],[python,[python,'-m','py_compile','/opt/liveuin/ops_backend/app/main.py'],[]]]
check('exact_four_prestart_commands',lambda:ns['prestart_commands'](commands),commands)
changed=copy.deepcopy(commands);changed[0][2]=['privileged']
check('privilege_prefix_closed',lambda:ns['prestart_commands'](changed),error='prestart_command_or_privilege_prefix_changed')
changed=copy.deepcopy(commands);changed[0][1][-1]+='; other'
check('command_drift_closed',lambda:ns['prestart_commands'](changed),error='prestart_command_or_privilege_prefix_changed')
check('missing_command_closed',lambda:ns['prestart_commands'](commands[:-1]),error='prestart_command_or_privilege_prefix_changed')
check('invalid_command_shape_closed',lambda:ns['prestart_commands'](None),error='prestart_command_shape_invalid')
defaults=ns['login_defaults']
check('normal_configured_login_defaults',lambda:defaults('liveuin_ops','/var/lib/liveuin','/bin/bash'),{'USER':'liveuin_ops','LOGNAME':'liveuin_ops','HOME':'/var/lib/liveuin','SHELL':'/bin/bash'})
check('root_home_and_nologin_omitted',lambda:defaults('liveuin_ops','/','/usr/sbin/nologin'),{'USER':'liveuin_ops','LOGNAME':'liveuin_ops'})
check('empty_home_shell_omitted',lambda:defaults('liveuin_ops','',''),{'USER':'liveuin_ops','LOGNAME':'liveuin_ops'})
check('empty_home_suppresses_shell_per_source',lambda:defaults('liveuin_ops','','/bin/bash'),{'USER':'liveuin_ops','LOGNAME':'liveuin_ops'})
check('false_shell_omitted',lambda:defaults('liveuin_ops','/var/lib/liveuin','/bin/false'),{'USER':'liveuin_ops','LOGNAME':'liveuin_ops','HOME':'/var/lib/liveuin'})
check('ambiguous_path_closed',lambda:defaults('liveuin_ops','/var/../root','/bin/bash'),error='login_path_requires_review')
check('relative_path_closed',lambda:defaults('liveuin_ops','relative','/bin/bash'),error='login_path_requires_review')
child=next(x.value.value for x in tree.body if isinstance(x,ast.Assign) and isinstance(x.targets[0],ast.Name) and x.targets[0].id=='CHILD' and isinstance(x.value,ast.Constant))
oldtree=ast.parse(p.with_name('prestart-fastpath-probe-reviewed03.py').read_text())
oldchild=next(x.value.value for x in oldtree.body if isinstance(x,ast.Assign) and isinstance(x.targets[0],ast.Name) and x.targets[0].id=='CHILD' and isinstance(x.value,ast.Constant))
checks.append({'name':'guarded_child_unchanged_from_reviewed03','passed':child==oldchild})
compile(s,str(p),'exec');compile(child,'<child>','exec')
checks.append({'name':'parent_and_child_compile_without_execution','passed':True})
result={'probe_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'passed':sum(x['passed'] for x in checks),'total':len(checks),'checks':checks,'production_calls':False,'product_imports':False,'child_probe_executed':False,'existing_guard_suite':'35/35 on unchanged reviewed03 child; retained prestart-probe-local-guard-tests.json'}
out=p.parents[1]/'evidence/prestart-probe-identity-tests-04.json';out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='checks'}));assert result['passed']==result['total']
