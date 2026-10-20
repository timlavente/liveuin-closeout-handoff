"""Reviewed AUTH02/9095-only activation controller. Not executed by its author.

Requires root-private package + explicit root restart review. No account/code/mail
request, config flag write, database restore, nginx edit or unrelated restart.
On any failure after replacement, install the pinned closed fallback; never restore
unsafe baseline authentication. --recover resumes that closed recovery only.
"""
from pathlib import Path
import argparse, datetime, hashlib, importlib.util, json, os, signal, stat, subprocess, sys, tempfile, time, urllib.error, urllib.request
ROOT=Path(__file__).resolve().parents[1]
TARGET=Path('/opt/liveuin/deploy/core_identity_api.py')
UNIT='ops-backend@liveuin.service'
BASELINE='aee0ce11a4ffe48242b18dbde4a67463409765d80f43f15a68c6d40facc6e143'
CANDIDATE='a0834b412c06263d1ca593de67cc2514471cf4fdd7a83c860608be998fc65fcb'
FALLBACK='aee0ce11a4ffe48242b18dbde4a67463409765d80f43f15a68c6d40facc6e143'
MARKER=ROOT/'deployment/activation-9095-state.json'
REVIEW=ROOT/'deployment/restart-review-9095.json'
PREFLIGHT=ROOT/'deployment/preflight-backup.py'
SPEC=ROOT/'deployment/preflight-spec.json'
RESTART_PROPERTIES=('ExecStartPre','ExecStartPost','ExecStop','ExecStopPost')
# The operator must pin the final reviewed preflight in restart-review too.
def need(condition,code):
    if not condition:raise RuntimeError(code)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def interrupted(signum,frame):raise RuntimeError('activation_interrupted')
def private(path):
    s=path.stat();need(not path.is_symlink() and stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'private_input_invalid')
def write_state(value):
    fd,tmp=tempfile.mkstemp(prefix='.auth02-state-',dir=MARKER.parent)
    try:
        with os.fdopen(fd,'w') as out:json.dump(value,out,indent=2);out.flush();os.fsync(out.fileno())
        os.chmod(tmp,0o600);os.replace(tmp,MARKER)
        fd=os.open(MARKER.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
def target_state(allowed):
    need(not TARGET.is_symlink() and TARGET.is_file(),'target_type_drift')
    need(digest(TARGET) in allowed,'target_source_drift')
def replace_source(source,sha,metadata):
    target_state({BASELINE,CANDIDATE,FALLBACK})
    private(source);need(digest(source)==sha,'replacement_hash_mismatch')
    checked=subprocess.run(['/usr/bin/python3','-c','import sys;compile(sys.stdin.buffer.read(),"AUTH02-reviewed","exec")'],input=source.read_bytes(),capture_output=True,timeout=10)
    need(checked.returncode==0,'replacement_compile_failed')
    fd,tmp=tempfile.mkstemp(prefix='.auth02-',suffix='.py',dir=TARGET.parent)
    try:
        with os.fdopen(fd,'wb') as out:out.write(source.read_bytes());out.flush();os.fsync(out.fileno())
        os.chown(tmp,metadata['uid'],metadata['gid']);os.chmod(tmp,metadata['mode'])
        os.replace(tmp,TARGET)
        fd=os.open(TARGET.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)
    need(digest(TARGET)==sha,'installed_hash_mismatch')
def command(action):
    need(action in {'restart','stop'},'service_action_not_allowed')
    subprocess.run(['systemctl',action,UNIT],capture_output=True,timeout=30,check=True)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
def probe(path,post=False):
    req=urllib.request.Request('http://127.0.0.1:9095'+path,data=b'{}' if post else None,headers={'Content-Type':'application/json','Host':'ops.liveuin.com'},method='POST' if post else 'GET')
    try:
        with OPENER.open(req,timeout=4) as res:status=res.status;headers=res.headers;raw=res.read(4096)
    except urllib.error.HTTPError as res:status=res.code;headers=res.headers;raw=res.read(4096)
    try:body=json.loads(raw)
    except Exception:body={}
    return {'status':status,'ok':body.get('ok') is True,'detail':body.get('detail') if body.get('detail') in {'not_found','browser_sign_in_unavailable','browser_sign_in_temporarily_locked','challenge_id_required'} else None,'no_store':'no-store' in headers.get('Cache-Control','').lower()}
def verify_runtime(preflight,spec,sha,previous_pid):
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        current=preflight.unit_state(UNIT)
        pid=int(current.get('MainPID') or 0)
        if current.get('ActiveState')=='active' and current.get('SubState')=='running' and pid and pid!=previous_pid:
            expected={**spec,'baseline_pid':pid}
            try:process,env,unit=preflight.process(expected)
            except RuntimeError as exc:
                if str(exc) not in {'listener_process_mismatch','process_argv_drift'}:raise
                time.sleep(.5);continue
            need(digest(TARGET)==sha,'post_restart_source_drift')
            preflight.credential_source_continuity(spec)
            try:health=probe('/healthz')
            except urllib.error.URLError:
                time.sleep(.5);continue
            need(health['status']==200 and health['ok'],'healthz_failed')
            return process,env
        time.sleep(.5)
    raise RuntimeError('restarted_service_not_ready')
def checks(closed=False):
    results={}
    results['healthz']=probe('/healthz');need(results['healthz']['status']==200 and results['healthz']['ok'],'healthz_failed')
    for key,path in [('raw_create','/api/core/identity/login/challenges'),('raw_verify','/api/core/identity/login/challenges/AUTH02-NONEXISTENT-DIAGNOSTIC/verify')]:
        results[key]=probe(path,True);need(results[key]['status']==404 and results[key]['no_store'],'raw_preview_not_closed')
    results['empty_request']=probe('/api/ops/auth/request_code',True)
    need(results['empty_request']['status']==(503 if closed else 403),'unsupported_surface_not_closed')
    results['empty_verify']=probe('/api/ops/auth/verify-code',True)
    need(results['empty_verify']['status']==(503 if closed else 400),'empty_verification_contract_failed')
    return results

def restart_action_pins(preflight):
    obj=json.loads(preflight.run(['busctl','--json=short','call','org.freedesktop.systemd1','/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','GetUnit','s',UNIT]))
    need(obj.get('type')=='o' and len(obj.get('data',[]))==1,'restart_action_unit_unavailable')
    result={}
    for name in RESTART_PROPERTIES:
        value=json.loads(preflight.run(['busctl','--json=short','get-property','org.freedesktop.systemd1',obj['data'][0],'org.freedesktop.systemd1.Service',name]))
        need(value.get('type')=='a(sasbttttuii)' and isinstance(value.get('data'),list),'restart_action_format_unrecognized')
        static=[]
        for row in value['data']:
            need(isinstance(row,list) and len(row)==10 and isinstance(row[0],str) and isinstance(row[1],list) and all(isinstance(arg,str) for arg in row[1]) and type(row[2]) is bool,'restart_action_format_unrecognized')
            # Only path, argv and ignore-failure are configuration. Remaining fields
            # are timestamps/PID/exit results and necessarily change on restart.
            static.append(row[:3])
        result[name]=hashlib.sha256(json.dumps(static,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    return result

def manager_environment(preflight):
    value=json.loads(preflight.run(['busctl','--json=short','get-property','org.freedesktop.systemd1','/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','Environment']))
    need(value.get('type')=='as' and isinstance(value.get('data'),list),'manager_environment_unavailable')
    env={}
    for item in value['data']:
        need(isinstance(item,str) and '=' in item,'manager_environment_format_unrecognized')
        name,text=item.split('=',1);need(name and name not in env,'manager_environment_format_unrecognized');env[name]=text
    # Aggregate configuration fingerprint stays only in root-private review.
    return env,hashlib.sha256(json.dumps(env,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()

def credential_source_versions(spec):
    versions={}
    for _,name in spec['LoadCredential']['data']:
        path=Path(name);need(path.is_file(),'credential_source_unavailable')
        info=path.stat();need(stat.S_ISREG(info.st_mode),'credential_source_not_regular')
        versions[name]={'device':info.st_dev,'inode':info.st_ino,'size':info.st_size,'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns}
    need(bool(versions),'credential_version_scope_missing')
    return versions

def restart_gate(preflight,review,spec):
    current=preflight.unit_state(UNIT)
    need(current.get('NeedDaemonReload')=='no','unit_reload_pending')
    for key in ['User','WorkingDirectory','FragmentPath','DropInPaths','EnvironmentFiles']:
        need(current.get(key,'')==spec[key],'restart_unit_configuration_drift')
    configured=preflight.protected_files(current)
    pins=review.get('protected_configuration_sha256')
    need(isinstance(pins,dict) and pins and set(pins)=={str(p) for p in configured},'protected_configuration_scope_mismatch')
    for path in configured:need(digest(path)==pins[str(path)],'protected_configuration_drift')
    source_pins=review.get('startup_source_sha256')
    need(isinstance(source_pins,dict) and '/opt/liveuin/ops_backend/app/main.py' in source_pins,'startup_source_review_missing')
    for name,sha in source_pins.items():
        path=Path(name);need(path.is_absolute() and path!=TARGET,'startup_source_scope_invalid')
        need(path.is_file() and not path.is_symlink() and digest(path)==sha,'startup_source_drift')
    property_pins=review.get('restart_properties_sha256')
    need(isinstance(property_pins,dict) and set(property_pins)==set(RESTART_PROPERTIES),'restart_actions_review_missing')
    need(restart_action_pins(preflight)==property_pins,'restart_action_drift')
    preflight.credential_source_continuity(spec)
    need(credential_source_versions(spec)==review.get('credential_source_versions'),'credential_source_version_drift')
    _,manager_pin=manager_environment(preflight)
    need(manager_pin==review.get('manager_configuration_fingerprint'),'manager_environment_drift')

def prestart_probe(review):
    path=ROOT/'deployment/prestart-fastpath-probe.py'
    private(path);need(digest(path)==review.get('startup_probe_sha256'),'startup_probe_drift')
    child=subprocess.run(['/usr/bin/python3',str(path),'--review',str(REVIEW)],capture_output=True,text=True,timeout=60)
    try:result=json.loads(child.stdout)
    except Exception:raise RuntimeError('startup_probe_invalid_reply')
    need(child.returncode==0 and result.get('status')=='prestart_fastpath_pass' and result.get('no_product_import') is True and result.get('no_dependency_install') is True,'startup_fastpath_not_proved')
    return {'passed':True,'no_product_import':True,'no_dependency_install':True}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--activate',action='store_true');parser.add_argument('--recover',action='store_true');args=parser.parse_args()
    output={'component':'AUTH02-9095','started_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'accounts_created':False,'emails_requested':False,'flags_changed':False,'database_restored':False,'public_access_opened':False}
    changed=False;state={};preflight=None;spec=None;review={}
    for sig in (signal.SIGTERM,signal.SIGHUP):signal.signal(sig,interrupted)
    try:
        need(os.geteuid()==0,'authenticated_root_required')
        need(str(ROOT).startswith('/root/') and ROOT.stat().st_uid==0 and stat.S_IMODE(ROOT.stat().st_mode)==0o700,'package_not_root_private')
        need(args.activate != args.recover,'choose_activate_or_recover')
        # Verify reviewed local helper and specification before either is executed.
        for path in (REVIEW,PREFLIGHT,SPEC):private(path)
        review=json.loads(REVIEW.read_text())
        need(review.get('startup_import_review_passed') is True and review.get('restart_configuration_matches_running_service') is True,'restart_review_incomplete')
        need(review.get('preflight_sha256')==digest(PREFLIGHT) and review.get('spec_sha256')==digest(SPEC) and review.get('candidate_sha256')==CANDIDATE and review.get('fallback_sha256')==FALLBACK,'restart_review_hash_mismatch')
        specs=json.loads(SPEC.read_text());spec=next(s for s in specs if s['unit']==UNIT)
        need(review.get('baseline_pid')==spec['baseline_pid'],'restart_review_pid_mismatch')
        module_spec=importlib.util.spec_from_file_location('auth02_preflight_helpers',PREFLIGHT)
        preflight=importlib.util.module_from_spec(module_spec);sys.dont_write_bytecode=True;module_spec.loader.exec_module(preflight)
        fallback=ROOT/'fallback-9095/deploy/core_identity_api.py';private(fallback);need(digest(fallback)==FALLBACK,'fallback_drift')
        if args.recover:
            private(MARKER);state=json.loads(MARKER.read_text())
            need(state.get('candidate_sha256')==CANDIDATE and state.get('fallback_sha256')==FALLBACK,'recovery_record_hash_mismatch')
            need(state.get('recovery_required') is True or state.get('status')=='candidate_negative_checks_passed_owner_proof_pending','no_pending_recovery')
            target_state({BASELINE,CANDIDATE,FALLBACK})
            changed=True
            raise RuntimeError('explicit_closed_recovery_requested')
        candidate=ROOT/'candidate-9095/deploy/core_identity_api.py';private(candidate);need(digest(candidate)==CANDIDATE,'candidate_drift')
        need(not MARKER.exists(),'existing_activation_record_requires_review')
        restart_gate(preflight,review,spec)
        child=subprocess.run(['/usr/bin/python3',str(PREFLIGHT),'--component','9095','--backup'],capture_output=True,text=True,timeout=180)
        report=json.loads(child.stdout);need(child.returncode==0 and report.get('status')=='preflight_pass_not_activation_authorization' and report.get('backup',{}).get('completed') is True,'preflight_or_backup_failed')
        before,environment,current=preflight.process(spec)
        target_state({BASELINE})
        restart_gate(preflight,review,spec)
        output['entry_prestart_probe']=prestart_probe(review)
        restart_gate(preflight,review,spec)
        confirmed,confirmed_environment,_=preflight.process(spec)
        need(confirmed==before and confirmed_environment==environment,'process_changed_during_startup_probe')
        target_state({BASELINE})
        meta=TARGET.stat();state={'recovery_required':True,'candidate_sha256':CANDIDATE,'fallback_sha256':FALLBACK,'backup_directory':report['backup_directory'],'original_metadata':{'uid':meta.st_uid,'gid':meta.st_gid,'mode':stat.S_IMODE(meta.st_mode)},'previous_pid':before['pid'],'status':'replacement_pending'}
        write_state(state);changed=True
        replace_source(ROOT/'candidate-9095/deploy/core_identity_api.py',CANDIDATE,state['original_metadata'])
        restart_gate(preflight,review,spec)
        output['candidate_prestart_probe']=prestart_probe(review)
        restart_gate(preflight,review,spec)
        target_state({CANDIDATE})
        command('restart')
        process,after_environment=verify_runtime(preflight,spec,CANDIDATE,before['pid'])
        need(after_environment==environment,'selected_effective_environment_changed_after_restart')
        restart_gate(preflight,review,spec)
        output['negative_checks']=checks()
        state.update(status='candidate_negative_checks_passed_owner_proof_pending',new_pid=process['pid'],recovery_required=False);write_state(state)
        output.update(status=state['status'],pid=process['pid'],backup_directory=state['backup_directory'],candidate_sha256=CANDIDATE)
    except BaseException as exc:
        output['status']='stopped_before_change' if not changed else 'recovery_required'
        output['failure_code']=str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__
        if changed:
            try:
                state['recovery_required']=True;state['status']='closed_recovery_pending';write_state(state)
                # A second termination cannot interrupt the bounded closed-recovery attempt.
                for sig in (signal.SIGTERM,signal.SIGHUP):signal.signal(sig,signal.SIG_IGN)
                target_state({BASELINE,CANDIDATE,FALLBACK})
                previous=int(preflight.unit_state(UNIT).get('MainPID') or state.get('previous_pid') or 0)
                replace_source(ROOT/'fallback-9095/deploy/core_identity_api.py',FALLBACK,state['original_metadata'])
                # Never restart when reviewed config/source has drifted.
                restart_gate(preflight,review,spec)
                output['fallback_prestart_probe']=prestart_probe(review)
                restart_gate(preflight,review,spec)
                target_state({FALLBACK})
                command('restart')
                process,_=verify_runtime(preflight,spec,FALLBACK,previous)
                output['closed_recovery_checks']=checks(closed=True)
                state.update(status='closed_fallback_active',new_pid=process['pid'],recovery_required=False);write_state(state)
                output.update(status='closed_fallback_active_new_sign_in_held',pid=process['pid'])
            except BaseException as recovery_error:
                output['recovery_failure']=str(recovery_error) if isinstance(recovery_error,RuntimeError) else type(recovery_error).__name__
                # Stopping is the only permitted action if reviewed restart inputs changed.
                try:
                    action_pins=restart_action_pins(preflight)
                    need(all(action_pins[key]==review['restart_properties_sha256'][key] for key in ('ExecStop','ExecStopPost')),'stop_action_drift')
                    command('stop');output['status']='service_stopped_for_closed_recovery'
                except BaseException:output['status']='recovery_failed_manual_root_action_required'
                try:state.update(status=output['status'],recovery_required=True);write_state(state)
                except BaseException:output['state_record_update_failed']=True
    print(json.dumps(output,indent=2))
    return 0 if output['status']=='candidate_negative_checks_passed_owner_proof_pending' else 1
if __name__=='__main__':sys.exit(main())
