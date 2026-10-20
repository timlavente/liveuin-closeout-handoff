"""Reviewed-library probe ONLY. Prepare locally; root runs only after config classification.
No product imports, service actions, mail/payment calls or credential-file reads.
Exact seven imports are instrumented with Python read/write/database guards and
Linux seccomp socket denial. Normal site initialization runs after guards under -S.
This establishes a present fast-path condition, not an absolute auto-rebuild lock.
"""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,pwd,grp,re,signal,stat,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[1]
UNIT='ops-backend@liveuin.service'
MODULES=['fastapi','httpx','psycopg','psycopg2','pydantic','uvicorn','email_validator']
CONFIG_SHA='d84d9c69a8c627d1a818a1e18de697aa1223709810051d66891082886ff88f6d'
PREFLIGHT_SHA='25c5d1f8b22dd81fcc4ea07818d784dc52b70cab62170c88a2df94b8d07abb87'
CONTROLLER_SHA='af8508ff6057133cdc8d4c6829d18faf07871ec9d6fa5d8726a525afcaa1106b'
SCRIPT_SHA='bbbb3c5c44d6db48b26ca3f11972c4557d9eabe038573e12e4e6cfee56c50c4e'
BASE=Path('/opt/liveuin/ops_backend');VENV=BASE/'.venv';PYTHON=VENV/'bin/python'
SITE_CUSTOMIZE=Path('/etc/python3.10/sitecustomize.py')
SITE_CUSTOMIZE_SHA='43d81125d92376b1a69d53a71126a041cc9a18d8080e92dea0a2ae23be138b1e'
CHILD=r'''
import sys
# Builtin sys only before removing application paths from stdlib bootstrap.
original_path=list(sys.path)
sys.path=[p for p in sys.path if p and (p.startswith('/usr/') or p.startswith('/lib/'))]
import os,json,hashlib,importlib,importlib.machinery,pathlib,ctypes,errno,io,resource
module=sys.argv[1];expected=pathlib.Path('/opt/liveuin/ops_backend/.venv')
original_stdout=sys.stdout;sys.stdout=io.StringIO();sys.stderr=io.StringIO()
sys.dont_write_bytecode=True
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_FSIZE,(0,0))
resource.setrlimit(resource.RLIMIT_CPU,(4,4))
resource.setrlimit(resource.RLIMIT_AS,(768*1024*1024,768*1024*1024))
counts={'network_attempts':0,'database_attempts':0,'write_attempts':0,'forbidden_reads':0,'product_import_attempts':0,'subprocess_attempts':0}
read_files=set()
result={'module':module,'ok':False,'guards':counts,'secret_values_output':False}
def library_pycache_read(p):
 prefix='/var/cache/ops-backend/pycache/'
 if os.environ.get('PYTHONPYCACHEPREFIX')!=prefix[:-1] or not p.startswith(prefix) or not p.endswith('.pyc'):return False
 mapped=os.path.realpath('/'+p[len(prefix):])
 return mapped.startswith('/usr/') or mapped.startswith(str(expected)+'/')
def audit(event,args):
 if event.startswith('socket.'):
  counts['network_attempts']+=1;raise RuntimeError('network_forbidden')
 if event in {'sqlite3.connect','sqlite3.connect/handle'}:
  counts['database_attempts']+=1;raise RuntimeError('database_forbidden')
 if event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn','os.fork','os.forkpty'}:
  counts['subprocess_attempts']+=1;raise RuntimeError('subprocess_forbidden')
 if event=='import':
  n=str(args[0]).split('.')[0]
  if n in {'app','deploy','db','auth_db','auth_api','session_utils','autopilot_executor'} or n.startswith(('core_','auth_')):
   counts['product_import_attempts']+=1;raise RuntimeError('product_import_forbidden')
 if event in {'os.remove','os.rename','os.rmdir','os.mkdir','os.link','os.symlink','os.chmod','os.chown','os.truncate','os.utime'}:
  counts['write_attempts']+=1;raise RuntimeError('filesystem_mutation_forbidden')
 if event=='open' and isinstance(args[0],(str,bytes)):
  p=os.path.realpath(os.fsdecode(args[0]));flags=args[2] if len(args)>2 and isinstance(args[2],int) else 0
  if flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
   counts['write_attempts']+=1;raise RuntimeError('file_write_forbidden')
  allowed=(p==str(expected) or p.startswith(str(expected)+'/') or p.startswith(('/usr/','/lib/','/lib64/')) or p in {'/etc/python3.10/sitecustomize.py','/etc/ld.so.cache','/etc/localtime','/etc/resolv.conf','/etc/hosts','/etc/gai.conf','/etc/nsswitch.conf','/dev/null','/dev/urandom','/dev/random'} or p.startswith('/etc/ssl/certs/') or library_pycache_read(p))
  if not allowed:
   if 'first_forbidden_read_class' not in result:
    prefix='/var/cache/ops-backend/pycache/'
    known_cache=p.startswith(prefix) and p.endswith('.pyc')
    mapped='/'+p[len(prefix):] if known_cache else ''
    library_cache=known_cache and (mapped.startswith('/usr/') or mapped.startswith(str(expected)+'/'))
    result['first_forbidden_read_class']='known_pycache_library' if library_cache else ('known_pycache_other' if known_cache else 'other')
    result['configured_pycache_prefix_matches_known']=os.environ.get('PYTHONPYCACHEPREFIX')==prefix[:-1]
    result['first_forbidden_read_path_private']=p
   counts['forbidden_reads']+=1;raise RuntimeError('nonlibrary_read_forbidden')
  if p.endswith(('.py','.pyc','.pth','.so')):read_files.add(p)
sys.addaudithook(audit)
try:
 # Deny all socket system calls at the kernel boundary before site/package imports.
 # This also prevents native libpq from reaching either TCP or Unix-domain databases.
 arch=os.uname().machine
 if arch=='x86_64':audit_arch=0xc000003e;denied=list(range(41,56))+[288,299,307]
 elif arch in {'aarch64','arm64'}:audit_arch=0xc00000b7;denied=list(range(198,213))+[242,243,269]
 else:raise RuntimeError('unsupported_seccomp_architecture')
 class Filter(ctypes.Structure):_fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
 class Program(ctypes.Structure):_fields_=[('len',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
 instructions=[(0x20,0,0,4),(0x15,1,0,audit_arch),(0x06,0,0,0x80000000),(0x20,0,0,0)]
 for number in denied:instructions.extend([(0x15,0,1,number),(0x06,0,0,0x00050001)])
 instructions.append((0x06,0,0,0x7fff0000))
 array=(Filter*len(instructions))(*[Filter(*x) for x in instructions]);program=Program(len(array),array)
 libc=ctypes.CDLL(None,use_errno=True);libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong];libc.prctl.restype=ctypes.c_int
 if libc.prctl(38,1,0,0,0)!=0 or libc.prctl(22,2,ctypes.addressof(program),0,0)!=0:raise RuntimeError('seccomp_install_failed')
 libc.socket.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_int];libc.socket.restype=ctypes.c_int
 ctypes.set_errno(0)
 if libc.socket(2,1,0)!=-1 or ctypes.get_errno()!=errno.EPERM:raise RuntimeError('seccomp_socket_selftest_failed')
 result['kernel_socket_denial_selftest']=True
 # Restore actual cwd/PYTHONPATH and perform standard site setup behind the guards.
 sys.path=original_path
 import site
 site.main()
 spec=importlib.machinery.PathFinder.find_spec(module,sys.path)
 if spec is None or not spec.origin:raise RuntimeError('module_origin_missing')
 origin=pathlib.Path(spec.origin).resolve()
 if expected not in origin.parents:raise RuntimeError('module_origin_outside_expected_venv')
 # Exact import statement from the existing prestart list; module name is fixed by parent.
 exec('import '+module,{})
 loaded=sys.modules.get(module)
 if loaded is None or pathlib.Path(loaded.__file__).resolve()!=origin:raise RuntimeError('module_origin_changed')
 files={}
 for m in list(sys.modules.values()):
  name=getattr(m,'__file__',None)
  if isinstance(name,str) and name.endswith(('.py','.pyc','.so')):read_files.add(os.path.realpath(name))
 for name in sorted(read_files):
  p=pathlib.Path(name)
  if p.is_file():
   if p.stat().st_size>64*1024*1024:raise RuntimeError('library_file_size_out_of_bound')
   files[name]=hashlib.sha256(p.read_bytes()).hexdigest()
 if any(counts.values()):raise RuntimeError('guarded_side_effect_attempted')
 result.update(ok=True,origin=str(origin),origin_sha256=hashlib.sha256(origin.read_bytes()).hexdigest(),library_source_sha256=files)
except BaseException as exc:
 result['failure_code']=str(exc) if isinstance(exc,RuntimeError) and re_safe_code(str(exc)) else type(exc).__name__
finally:
 original_stdout.write(json.dumps(result,separators=(',',':'))+'\n');original_stdout.flush()
'''
# Add a tiny safe-error classifier before the child's guarded try; no exception text leaks.
CHILD=CHILD.replace("sys.addaudithook(audit)\ntry:","def re_safe_code(value): return bool(value) and len(value)<80 and all(c.islower() or c=='_' for c in value)\nsys.addaudithook(audit)\ntry:")

def need(ok,code):
 if not ok:raise RuntimeError(code)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def private(p):need(p.is_file() and not p.is_symlink() and p.stat().st_uid==0 and not p.stat().st_mode&0o022,'private_input_required')
def load(name,p,digest):
 private(p);need(sha(p)==digest,'reviewed_helper_drift');spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def prestart_identity(configured_uid,configured_gid,nss_groups,extra_groups,dynamic,permissions_start_only):
 # systemd v249: control commands with PermissionsStartOnly retain root UID/GID,
 # but get_supplementary_groups initializes the configured user's NSS groups first.
 need(type(dynamic) is bool and type(permissions_start_only) is bool,'identity_boolean_shape_invalid')
 need(not dynamic,'dynamic_prestart_identity_not_supported')
 nss=sorted(set(nss_groups));extra=set(extra_groups)
 if permissions_start_only:
  need(extra.issubset(set(nss)),'prestart_supplementary_group_semantics_require_review')
  return 0,0,nss
 return configured_uid,configured_gid,sorted(set(nss)|extra)

def login_defaults(name,home,shell):
 # systemd249 USER_CREDS_CLEAN omits root/empty HOME and nologin/empty SHELL.
 # Accept only simple absolute NSS paths so path normalization is unambiguous.
 for value in [home,shell]:
  need(value=='' or (isinstance(value,str) and value.startswith('/') and len(value)<4096 and '\x00' not in value and '\n' not in value and (value=='/' or all(x not in {'','.','..'} for x in value[1:].split('/')))),'login_path_requires_review')
 values={'USER':name,'LOGNAME':name}
 if home and home!='/':values['HOME']=home
 nologin={'/bin/nologin','/sbin/nologin','/usr/bin/nologin','/usr/sbin/nologin','/bin/false','/usr/bin/false','/bin/true','/usr/bin/true'}
 if home and shell and shell not in nologin:values['SHELL']=shell
 return values

def prestart_commands(value):
 need(isinstance(value,list) and all(isinstance(x,list) and len(x)>=3 for x in value),'prestart_command_shape_invalid')
 commands=[x[:3] for x in value]
 expected=[['/bin/sh',['/bin/sh','-c','set -eu; /opt/liveuin/ops_backend/bin/ensure_venv.sh'],[]],['/bin/mkdir',['/bin/mkdir','-p','/var/cache/ops-backend/pycache'],[]],[str(PYTHON),[str(PYTHON),'-m','py_compile',str(BASE/'app.py')],[]],[str(PYTHON),[str(PYTHON),'-m','py_compile',str(BASE/'app/main.py')],[]]]
 need(commands==expected,'prestart_command_or_privilege_prefix_changed')
 return commands

def alarm_handler(*_):raise RuntimeError('overall_probe_timeout')
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--configuration-result',default=str(ROOT/'evidence/auth02-restart-config-03.json'));parser.add_argument('--review');parser.add_argument('--output');args=parser.parse_args()
 result={'component':'AUTH02-9095-prestart-libraries','status':'stopped','executed_product_imports':False,'no_product_import':True,'no_dependency_install':True,'service_actions':False,'credential_files_read':False,'secret_values_output':False,'guarded_imports':[]}
 try:
  signal.signal(signal.SIGALRM,alarm_handler);signal.alarm(55)
  need(os.geteuid()==0 and str(ROOT).startswith('/root/') and ROOT.stat().st_uid==0 and not ROOT.is_symlink() and stat.S_IMODE(ROOT.stat().st_mode)==0o700,'root_private_package_required');sys.dont_write_bytecode=True
  prior=Path(args.configuration_result);private(prior);need(ROOT.resolve() in prior.resolve().parents,'configuration_result_outside_package')
  prior_bytes=prior.read_bytes();prior_result=json.loads(prior_bytes)
  need(prior_result.get('status')=='configuration_equal_startup_verdict_still_required' and prior_result.get('configured_credentials_equal_loaded') is True and prior_result.get('different_environment_names')==[],'successful_configuration_result_required')
  cfg=load('auth02_probe_config',ROOT/'deployment/classify-restart-config.py',CONFIG_SHA)
  preflight=load('auth02_probe_preflight',ROOT/'deployment/preflight-backup.py',PREFLIGHT_SHA)
  control=load('auth02_probe_control',ROOT/'deployment/activate-9095.py',CONTROLLER_SHA)
  spec_path=ROOT/'deployment/preflight-spec.json';private(spec_path);spec=next(x for x in json.loads(spec_path.read_text()) if x['unit']==UNIT)
  current=preflight.unit_state(UNIT)
  need(current.get('NeedDaemonReload')=='no','unit_reload_pending')
  for key in ['User','WorkingDirectory','FragmentPath','DropInPaths','EnvironmentFiles']:need(current.get(key,'')==spec[key],'unit_configuration_drift')
  obj=json.loads(preflight.run(['busctl','--json=short','call','org.freedesktop.systemd1','/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','GetUnit','s',UNIT]))
  need(obj.get('type')=='o' and len(obj.get('data',[]))==1,'unit_object_unavailable')
  metadata={};env,pins,_,_,manager_pin=cfg.pre_wrapper_environment(preflight,control,obj['data'][0],current,metadata)
  m=metadata['pre_wrapper_prestart'];need(m==prior_result.get('pre_wrapper_prestart'),'prestart_config_changed_since_classification')
  need(all(x['matches_expected_or_unset'] for x in m['path_bindings'].values()),'prestart_path_override')
  need(m['imports_match_default'] and m['dsn_variable_list_matches_default'] and not m['any_default_dsn_nonempty_before_wrapper'],'product_app_import_not_proven_skipped')
  need(m['enums']['ENSURE_VENV_REBUILD']['effective_classification']=='auto' and m['enums']['ENSURE_VENV_APP_IMPORT']['effective_classification']=='auto','nondefault_prestart_modes')
  script=BASE/'bin/ensure_venv.sh';req=BASE/'requirements.txt';marker=VENV/'.requirements.sha256'
  need(sha(script)==SCRIPT_SHA and PYTHON.is_file() and os.access(PYTHON,os.X_OK),'prestart_source_or_interpreter_unavailable')
  need(marker.read_text().strip()==sha(req),'requirements_hash_marker_mismatch')
  need(SITE_CUSTOMIZE.is_file() and not SITE_CUSTOMIZE.is_symlink() and sha(SITE_CUSTOMIZE)==SITE_CUSTOMIZE_SHA,'sitecustomize_source_drift')
  startup_pins={str(p):sha(p) for p in [script,req,marker,PYTHON.resolve(),SITE_CUSTOMIZE]}
  config_paths=preflight.protected_files(current)
  need({str(p):sha(p) for p in config_paths}==pins,'configuration_file_drift')
  # Recovery may have a different PID or no process. Derive ExecStartPre identity
  # from the loaded unit and NSS; do not inspect customer/application processes.
  def scalar_property(name,kind):
   value=json.loads(preflight.run(['busctl','--json=short','get-property','org.freedesktop.systemd1',obj['data'][0],'org.freedesktop.systemd1.Service',name]))
   need(value.get('type')==kind,'service_identity_property_unavailable');return value.get('data')
  account=pwd.getpwnam(spec['User'])
  group_name=scalar_property('Group','s');need(isinstance(group_name,str),'group_binding_unavailable')
  configured_gid=grp.getgrnam(group_name).gr_gid if group_name else account.pw_gid
  supplementary=cfg.property_value(preflight,obj['data'][0],'SupplementaryGroups','as')
  need(all(isinstance(x,str) and x for x in supplementary),'supplementary_group_shape_invalid')
  dynamic=scalar_property('DynamicUser','b');permissions_start_only=scalar_property('PermissionsStartOnly','b')
  need(scalar_property('RootDirectory','s')=='' and scalar_property('RootImage','s')=='','alternate_root_not_supported')
  commands=prestart_commands(scalar_property('ExecStartPreEx','a(sasasttttuii)'))
  version=preflight.run(['systemctl','--version']).splitlines()[0]
  need(version.startswith('systemd 249 '),'systemd_identity_version_requires_review')
  uid,gid,groups=prestart_identity(account.pw_uid,configured_gid,os.getgrouplist(account.pw_name,configured_gid),[grp.getgrnam(x).gr_gid for x in supplementary],dynamic,permissions_start_only)
  identity={'configured_user':account.pw_name,'configured_uid':account.pw_uid,'configured_gid':configured_gid,'effective_uid':uid,'effective_gid':gid,'supplementary_groups':groups,'group_binding':group_name,'supplementary_group_bindings':supplementary,'permissions_start_only':permissions_start_only,'systemd_major':249,'exec_start_pre_has_privilege_prefix':False}
  # systemd's generated login environment sits after manager variables and before
  # unit/files. Restrict to the observed case with no competing manager/unset keys.
  manager_env,identity_manager_pin=control.manager_environment(preflight)
  login_names={'HOME','USER','LOGNAME','SHELL'}
  need(not login_names.intersection(manager_env) and not login_names.intersection(metadata['unset_environment_names']) and identity_manager_pin==manager_pin,'login_environment_precedence_requires_review')
  if args.review:
   review_path=Path(args.review);private(review_path);need(ROOT.resolve() in review_path.resolve().parents,'review_outside_package');review=json.loads(review_path.read_text())
   need(review.get('protected_configuration_sha256')==pins and review.get('manager_configuration_fingerprint')==manager_pin,'review_configuration_pins_drift')
   for name,digest in review.get('startup_source_sha256',{}).items():need(Path(name).is_file() and sha(Path(name))==digest,'review_startup_source_drift')
  # Fill only systemd's usual service-user defaults; declared env retains precedence.
  for name,value in login_defaults(account.pw_name,account.pw_dir,account.pw_shell).items():env.setdefault(name,value)
  env['PYTHONPATH']=str(BASE);env['PYTHONDONTWRITEBYTECODE']='1'
  # No wrapper credentials are injected. DSNs remain absent/empty in the reconstructed env.
  need(not any(env.get(k) for k in ['LIVEUIN_DB_DSN','OPS_DB_DSN','DATABASE_URL']),'unexpected_prestart_dsn')
  all_library_pins={}
  for module in MODULES:
   result['last_module_attempted']=module
   run=subprocess.run([str(PYTHON),'-S','-B','-c',CHILD,module],cwd=str(BASE),env=env,user=uid,group=gid,extra_groups=groups,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=6,check=False)
   need(run.returncode==0 and len(run.stdout)<=2*1024*1024,'guarded_library_probe_failed_or_timeout')
   child=json.loads(run.stdout);need(child.get('module')==module,'probe_output_shape_invalid')
   result['guarded_imports'].append({k:child.get(k) for k in ['module','ok','origin','origin_sha256','guards','kernel_socket_denial_selftest','failure_code','first_forbidden_read_class','configured_pycache_prefix_matches_known','first_forbidden_read_path_private']})
   need(child.get('ok') is True and child.get('kernel_socket_denial_selftest') is True and not any(child.get('guards',{}).values()),'guarded_library_import_failed')
   for name,digest in child['library_source_sha256'].items():
    need(name not in all_library_pins or all_library_pins[name]==digest,'library_changed_between_probes');all_library_pins[name]=digest
  end=preflight.unit_state(UNIT)
  stable_keys=['User','WorkingDirectory','FragmentPath','DropInPaths','EnvironmentFiles','NeedDaemonReload']
  need(all(end.get(k)==current.get(k) for k in stable_keys),'unit_changed_during_probe')
  now_account=pwd.getpwnam(account.pw_name)
  need((now_account.pw_uid,now_account.pw_gid,now_account.pw_dir,now_account.pw_shell)==(account.pw_uid,account.pw_gid,account.pw_dir,account.pw_shell) and scalar_property('Group','s')==group_name and cfg.property_value(preflight,obj['data'][0],'SupplementaryGroups','as')==supplementary,'service_identity_changed_during_probe')
  need(scalar_property('DynamicUser','b') is dynamic and scalar_property('PermissionsStartOnly','b') is permissions_start_only and scalar_property('RootDirectory','s')=='' and scalar_property('RootImage','s')=='','prestart_identity_mode_changed')
  need(prestart_commands(scalar_property('ExecStartPreEx','a(sasasttttuii)'))==commands and preflight.run(['systemctl','--version']).splitlines()[0]==version,'prestart_commands_or_systemd_changed')
  need((grp.getgrnam(group_name).gr_gid if group_name else now_account.pw_gid)==configured_gid,'configured_group_id_changed')
  need(prestart_identity(now_account.pw_uid,configured_gid,os.getgrouplist(account.pw_name,configured_gid),[grp.getgrnam(x).gr_gid for x in supplementary],dynamic,permissions_start_only)==(uid,gid,groups),'service_groups_changed_during_probe')
  endmeta={};_,endpins,_,_,endmanager=cfg.pre_wrapper_environment(preflight,control,obj['data'][0],end,endmeta)
  need(pins==endpins and manager_pin==endmanager and metadata==endmeta,'prestart_environment_changed_during_probe')
  need(all(Path(n).is_file() and sha(Path(n))==v for n,v in {**startup_pins,**all_library_pins}.items()),'source_changed_during_probe')
  need(prior.read_bytes()==prior_bytes,'configuration_result_changed')
  result.update(status='prestart_fastpath_pass',at_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),service_identity=identity,prestart_app_import_skipped=True,prestart_auto_fastpath_conditions_current=True,configuration_result_sha256=hashlib.sha256(prior_bytes).hexdigest(),helper_sha256=sha(Path(__file__)),classifier_sha256=CONFIG_SHA,source_sha256=startup_pins,library_source_sha256=all_library_pins,protected_configuration_sha256=pins,manager_configuration_fingerprint=manager_pin,limitation='Instrumented -S/-B probes initialize site after guards. Same interpreter/user/cwd/PYTHONPATH and loaded configured prestart environment; no product import. Success is a current fast-path check, not a structural guarantee that auto mode cannot rebuild if a later check changes or fails.')
 except BaseException as exc:
  result['failure_code']=str(exc) if isinstance(exc,RuntimeError) and re.fullmatch('[a-z_]+',str(exc)) else type(exc).__name__
 finally:signal.alarm(0)
 out=Path(args.output) if args.output else ROOT/'evidence'/('prestart-fastpath-'+str(time.time_ns())+'.json')
 try:
  need(out.parent.is_dir() and ROOT.resolve() in out.parent.resolve().parents and out.parent.stat().st_uid==0 and not out.parent.stat().st_mode&0o022 and not out.exists(),'new_private_output_required')
  fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'w') as f:json.dump(result,f,indent=2);f.flush();os.fsync(f.fileno())
 except BaseException:
  print(json.dumps({'status':'stopped','failure_code':'private_evidence_write_failed'}));return 1
 print(json.dumps({'status':result['status'],'modules_passed':sum(x.get('ok') is True for x in result['guarded_imports']),'last_module_attempted':result.get('last_module_attempted'),'module_checks':[{k:x.get(k) for k in ['module','ok','failure_code','guards','kernel_socket_denial_selftest','first_forbidden_read_class','configured_pycache_prefix_matches_known']} for x in result['guarded_imports']],'failure_code':result.get('failure_code'),'private_evidence_written':True,'no_product_import':True,'no_dependency_install':True,'secret_values_output':False}));return 0 if result['status']=='prestart_fastpath_pass' else 1
if __name__=='__main__':sys.exit(main())
