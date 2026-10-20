"""Root-only read-only restart configuration classifier; no product import or service action.

Values are compared only in memory. It can write the root-private review packet
only with a separate explicit reviewed startup verdict. No credential/secret
value or credential digest is printed or placed in the packet.
"""
from pathlib import Path
import argparse, hashlib, hmac, importlib.util, json, os, re, stat, sys
ROOT=Path(__file__).resolve().parents[1]
PREFLIGHT_SHA='25c5d1f8b22dd81fcc4ea07818d784dc52b70cab62170c88a2df94b8d07abb87'
CONTROLLER_SHA='fb39354f610dc6e74db369453945376d37d838c00fc88f098dfae123be0a4b45'
UNIT='ops-backend@liveuin.service'
def need(value,code):
    if not value:raise RuntimeError(code)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def private(path):
    need(path.is_file() and not path.is_symlink() and path.stat().st_uid==0 and not path.stat().st_mode&0o022,'private_input_required')
def load(name,path,expected):
    private(path);need(sha(path)==expected,'reviewed_helper_hash_mismatch')
    module_spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(module);return module

def env_file(path):
    """Deliberately restricted systemd EnvironmentFile grammar, no shell evaluation.

    Complex escapes, continuation or mixed quotes stop for explicit review rather
    than approximating systemd parsing. Simple unquoted/single/double-quoted
    assignments are exact under this subset. Inline # is literal, not comment.
    """
    result={}
    for line in path.read_text().splitlines():
        line=line.strip()
        if not line or line.startswith(('#',';')):continue
        match=re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)',line)
        need(match is not None,'environment_file_syntax_requires_review')
        key,value=match.groups();value=value.strip()
        need('\\' not in value and '\x00' not in value,'environment_file_syntax_requires_review')
        if value[:1] in {'"',"'"}:
            quote=value[0];need(len(value)>=2 and value[-1]==quote and quote not in value[1:-1],'environment_file_syntax_requires_review');value=value[1:-1]
        else:need('"' not in value and "'" not in value,'environment_file_syntax_requires_review')
        result[key]=value
    return result

def property_value(preflight,obj,name,kind):
    value=json.loads(preflight.run(['busctl','--json=short','get-property','org.freedesktop.systemd1',obj,'org.freedesktop.systemd1.Service',name]))
    need(value.get('type')==kind,'environment_property_unavailable')
    data=value.get('data')
    if kind=='s':
        need(isinstance(data,str),'environment_property_unavailable')
        return [data]
    need(isinstance(data,list),'environment_property_unavailable')
    return data

def apply_unset(planned,rules):
    removed=set()
    for name,value in rules:
        if value is None or planned.get(name)==value:
            planned.pop(name,None);removed.add(name)
    return removed

def environment_differences(planned,actual,rules,removed,wrapper_exports):
    differences={key for key,value in planned.items() if actual.get(key)!=value}
    for name in removed:
        if name not in wrapper_exports and name in actual:differences.add(name)
    for name,value in rules:
        if name not in wrapper_exports and name in actual and (value is None or actual[name]==value):differences.add(name)
    return sorted(differences)

def pre_wrapper_environment(preflight,control,obj,current,result):
    need(not property_value(preflight,obj,'PassEnvironment','as'),'pass_environment_requires_review')
    unset_rules=[]
    for item in property_value(preflight,obj,'UnsetEnvironment','as'):
        need(isinstance(item,str),'unset_environment_format_unrecognized')
        name,sep,value=item.partition('=');need(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',name),'unset_environment_format_unrecognized')
        unset_rules.append((name,value if sep else None))
    result['unset_environment_names']=sorted({name for name,_ in unset_rules});result['unset_environment_rule_count']=len(unset_rules)
    planned,manager_pin=control.manager_environment(preflight)
    result['manager_environment_variable_count']=len(planned)
    pam=property_value(preflight,obj,'PAMName','s');need(pam==[''],'pam_environment_requires_review')
    for item in property_value(preflight,obj,'Environment','as'):
        need(isinstance(item,str) and '=' in item,'unit_environment_format_unrecognized')
        key,value=item.split('=',1);need(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',key),'unit_environment_format_unrecognized');planned[key]=value
    protected=preflight.protected_files(current);pins={str(path):sha(path) for path in protected}
    paths=re.findall(r'([^\s]+) \(ignore_errors=(?:yes|no)\)',current['EnvironmentFiles'])
    for name in paths:
        path=Path(name)
        if path.exists():planned.update(env_file(path))
    # systemd UnsetEnvironment is applied last, before the wrapper process.
    removed_names=apply_unset(planned,unset_rules)
    # ExecStartPre receives this configuration before the DSN wrapper runs.
    enums={}
    for key,default,allowed in [('ENSURE_VENV_REBUILD','auto',{'auto','never','always'}),('ENSURE_VENV_APP_IMPORT','auto',{'auto','never','always'}),('ENSURE_VENV_WRITE_FREEZE','0',{'0','1'}),('ENSURE_VENV_COMPILEALL','1',{'0','1'})]:
        value=planned.get(key) or default
        enums[key]={'configured':bool(planned.get(key)),'effective_classification':value if value in allowed else 'unrecognized'}
    expected_paths={'BACKEND_DIR':'/opt/liveuin/ops_backend','VENV_DIR':'/opt/liveuin/ops_backend/.venv','REQ_FILE':'/opt/liveuin/ops_backend/requirements.txt','PY_SYS':'/usr/bin/python3'}
    result['pre_wrapper_prestart']={'enums':enums,'path_bindings':{key:{'override_present':bool(planned.get(key)),'matches_expected_or_unset':not planned.get(key) or planned[key]==value} for key,value in expected_paths.items()},'imports_match_default':not planned.get('ENSURE_VENV_IMPORTS') or planned['ENSURE_VENV_IMPORTS'].split()==['fastapi','httpx','psycopg','psycopg2','pydantic','uvicorn','email_validator'],'dsn_variable_list_matches_default':not planned.get('ENSURE_VENV_DSN_VARS') or planned['ENSURE_VENV_DSN_VARS'].split()==['LIVEUIN_DB_DSN','OPS_DB_DSN','DATABASE_URL'],'any_default_dsn_nonempty_before_wrapper':any(bool(planned.get(key)) for key in ['LIVEUIN_DB_DSN','OPS_DB_DSN','DATABASE_URL'])}
    return planned,pins,unset_rules,removed_names,manager_pin

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--compare-credentials',action='store_true');parser.add_argument('--startup-verdict');parser.add_argument('--write-review',action='store_true');args=parser.parse_args()
    result={'component':'AUTH02-9095','read_only_configuration_check':True,'service_actions':False,'product_imports':False,'secret_values_output':False,'credential_digests_output':False,'customer_database_opened':False}
    try:
        need(os.geteuid()==0 and str(ROOT).startswith('/root/') and ROOT.stat().st_uid==0 and stat.S_IMODE(ROOT.stat().st_mode)==0o700,'root_private_package_required')
        sys.dont_write_bytecode=True
        preflight=load('auth02_config_preflight',ROOT/'deployment/preflight-backup.py',PREFLIGHT_SHA)
        control=load('auth02_config_controller',ROOT/'deployment/activate-9095.py',CONTROLLER_SHA)
        spec_path=ROOT/'deployment/preflight-spec.json';private(spec_path)
        spec=next(s for s in json.loads(spec_path.read_text()) if s['unit']==UNIT)
        before,_,current=preflight.process(spec)
        proc=Path('/proc')/str(before['pid'])
        process_env={}
        for entry in (proc/'environ').read_bytes().split(b'\0'):
            name,sep,value=entry.partition(b'=')
            if sep:
                key=os.fsdecode(name);need(key not in process_env,'duplicate_process_environment');process_env[key]=os.fsdecode(value)
        obj=json.loads(preflight.run(['busctl','--json=short','call','org.freedesktop.systemd1','/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','GetUnit','s',UNIT]))
        need(obj.get('type')=='o' and len(obj.get('data',[]))==1,'unit_object_unavailable');obj=obj['data'][0]
        planned,pins,unset_rules,removed_names,manager_pin=pre_wrapper_environment(preflight,control,obj,current,result)
        preflight.credential_source_continuity(spec)
        result['credential_bytes_read_in_memory']=args.compare_credentials
        need(args.compare_credentials,'credential_equality_not_checked')
        directory=Path(process_env.get('CREDENTIALS_DIRECTORY',''))
        need(directory==Path('/run/credentials')/UNIT and directory.is_dir(),'credential_directory_binding_unexpected')
        wrapper=Path('/usr/local/sbin/liveuin-ops-backend-with-dsn-credential')
        need(wrapper.is_file() and not wrapper.is_symlink() and sha(wrapper)=='c4530a73cc60d4f3caa7c6d734b017cda6dbb0e34a2b12a27349136b75b5327b','reviewed_dsn_wrapper_drift')
        credential_versions=control.credential_source_versions(spec)
        loaded={}
        for credential_id,source in spec['LoadCredential']['data']:
            path=Path(source);active=directory/credential_id
            need(path.is_file() and active.is_file() and path.stat().st_size<1048576 and active.stat().st_size<1048576,'credential_input_unavailable')
            a,b=path.read_bytes(),active.read_bytes()
            need(hmac.compare_digest(a,b),'configured_credential_differs_from_loaded')
            if credential_id in {'LIVEUIN_DB_DSN','LIVEUIN_COUNTRY_CONTEXT_DB_DSN'}:loaded[credential_id]=os.fsdecode(b).rstrip('\n')
        need(control.credential_source_versions(spec)==credential_versions,'credential_source_changed_during_comparison')
        need(bool(loaded.get('LIVEUIN_DB_DSN')),'wrapper_dsn_binding_unavailable')
        for key in ['LIVEUIN_DB_DSN','OPS_DB_DSN','DATABASE_URL','OPS_DB_URL']:planned[key]=loaded['LIVEUIN_DB_DSN']
        if 'LIVEUIN_COUNTRY_CONTEXT_DB_DSN' in loaded:
            need(bool(loaded['LIVEUIN_COUNTRY_CONTEXT_DB_DSN']),'wrapper_country_dsn_empty');planned['LIVEUIN_COUNTRY_CONTEXT_DB_DSN']=loaded['LIVEUIN_COUNTRY_CONTEXT_DB_DSN']
        wrapper_exports={'LIVEUIN_DB_DSN','OPS_DB_DSN','DATABASE_URL','OPS_DB_URL'}
        if 'LIVEUIN_COUNTRY_CONTEXT_DB_DSN' in loaded:wrapper_exports.add('LIVEUIN_COUNTRY_CONTEXT_DB_DSN')
        differences=environment_differences(planned,process_env,unset_rules,removed_names,wrapper_exports)
        result.update(configured_environment_names_checked=len(planned),different_environment_names=differences,configured_credentials_equal_loaded=True,credential_bindings_checked=len(spec['LoadCredential']['data']))
        need(not differences,'restart_environment_differs_from_running')
        after,_,end=preflight.process(spec);need(after==before and end==current,'process_or_unit_changed_during_check')
        need({str(path):sha(path) for path in preflight.protected_files(end)}==pins,'configuration_changed_during_check')
        need(control.credential_source_versions(spec)==credential_versions,'credential_source_changed_during_check')
        _,manager_after=control.manager_environment(preflight);need(manager_after==manager_pin,'manager_environment_changed_during_check')
        actions=control.restart_action_pins(preflight)
        result.update(status='configuration_equal_startup_verdict_still_required',pid=before['pid'])
        if args.write_review:
            need(args.startup_verdict is not None,'startup_verdict_required')
            verdict_path=Path(args.startup_verdict);private(verdict_path);verdict=json.loads(verdict_path.read_text())
            for key in ['startup_import_review_passed','reviewed_startup_paths_no_automatic_mail_or_customer_mutation','candidate_startup_delta_unchanged','prestart_no_dependency_install']:need(verdict.get(key) is True,'startup_verdict_incomplete')
            need(isinstance(verdict.get('startup_review_scope'),str) and verdict['startup_review_scope'].strip(),'startup_review_scope_missing')
            source_pins=verdict.get('startup_source_sha256');need(isinstance(source_pins,dict) and source_pins,'startup_source_pins_missing')
            for name,value in source_pins.items():need(Path(name).is_file() and not Path(name).is_symlink() and sha(Path(name))==value,'startup_source_drift')
            need(isinstance(verdict.get('evidence_references'),list) and verdict['evidence_references'],'startup_evidence_references_missing')
            probe=ROOT/'deployment/prestart-fastpath-probe.py';private(probe)
            need(sha(probe)==verdict.get('startup_probe_sha256'),'startup_probe_verdict_mismatch')
            review={'startup_review_scope':verdict['startup_review_scope'],'startup_probe_sha256':sha(probe),'startup_import_review_passed':True,'restart_configuration_matches_running_service':True,'preflight_sha256':PREFLIGHT_SHA,'controller_sha256':CONTROLLER_SHA,'spec_sha256':sha(spec_path),'candidate_sha256':control.CANDIDATE,'fallback_sha256':control.FALLBACK,'baseline_pid':before['pid'],'protected_configuration_sha256':pins,'startup_source_sha256':source_pins,'restart_properties_sha256':actions,'credential_source_versions':credential_versions,'manager_configuration_fingerprint':manager_pin,'startup_verdict_sha256':sha(verdict_path),'configuration_scope':'Manager-global and declared unit/EnvironmentFile variables, final UnsetEnvironment, empty PAMName, plus exact wrapper-derived DSNs; configured credential bytes equal current loaded credentials; no values or credential digests retained.'}
            control.restart_gate(preflight,review,spec)
            destination=ROOT/'deployment/restart-review-9095.json';need(not destination.exists(),'review_already_exists')
            fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as out:json.dump(review,out,indent=2);out.flush();os.fsync(out.fileno())
            result['status']='root_private_restart_review_written'
    except Exception as exc:result.update(status='stopped_no_review',failure_code=str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__)
    print(json.dumps(result,indent=2));return 0 if result['status'] in {'configuration_equal_startup_verdict_still_required','root_private_restart_review_written'} else 1
if __name__=='__main__':sys.exit(main())
