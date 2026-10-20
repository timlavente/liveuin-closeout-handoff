"""One-file member retry from the proven closed fallback. No new configuration.

Uses the immutable09 package and the independently reviewed runtime-file hook.
Root owns execution. The only source change is the pure admission helper.
"""
from pathlib import Path
import contextlib,fcntl,hashlib,hmac,importlib.util,io,json,os,signal,stat,sys,types
ROOT=Path('/root/liveuin-auth02-member-20261020-09-review')
CONTROLLER_SHA='f26d9cbf5eb36a6a7dd1936edac95d36bfcef051d8e59b831d98b9221d7984ee'
RECOVERY_SHA='59feb47244c8b0881d17e28fade91041d342690cf8641c9333382cb3aabb82d8'
RECOVERY=Path('/tmp/liveuin-r01-access-check-20261020/recover-member-runtime-09.py')
EXPECTED_PID=3662305
RECONCILE=Path('/tmp/liveuin-r01-access-check-20261020/reconcile-current-ops-13.py')
RECONCILE_SHA='541770ff363515d722a87cefc495b2f3c7448dbfec5c9fa243cb8720c3d63250'
KEY='LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET'
def need(v,code):
    if not v:raise RuntimeError(code)
def load_verified(name,path,digest):
    need(path.is_file() and not path.is_symlink(),'reviewed_source_required');data=path.read_bytes()
    need(hashlib.sha256(data).hexdigest()==digest,'reviewed_source_hash_mismatch')
    module=types.ModuleType(name);module.__file__=str(path);exec(compile(data,str(path),'exec'),module.__dict__);return module

def main():
    result={'component':'AUTH02-member-one-file-retry','public_launch':False,'provider_flags_changed':False,'accounts_or_grants_created':False,'database_restore':False}
    lock=None;started=False;control=None
    try:
        need(os.geteuid()==0,'root_required');sys.dont_write_bytecode=True
        control=load_verified('reviewed_member_controller',ROOT/'deployment/activate-member-09.py',CONTROLLER_SHA)
        original_wait=control.wait_runtime;original_gate=control.static_gate
        recovery=load_verified('reviewed_runtime_recovery',RECOVERY,RECOVERY_SHA);recovery.install_hooks(control)
        # Validate the observed Ops instance under the acquired lock; every other original Ops check
        # remains in place, including the nested closed-recovery controller.
        original_ops=control.ops_unchanged;observed_ops_pid=None;reconciler=None
        def reconciled_ops(preflight,specs):
            need(type(observed_ops_pid) is int and observed_ops_pid>0,'ops_instance_not_observed')
            need(reconciler is not None,'reviewed_mobile_reconciler_required')
            updated=[reconciler.accepted_ops(preflight,s,observed_ops_pid)[0] if s['unit']=='ops-backend@liveuin.service' else s for s in specs]
            return original_ops(preflight,updated)
        control.ops_unchanged=reconciled_ops
        control.package();helper=control.load_review_helper();preflight=helper.load_preflight()
        review_path=ROOT/'runtime-review-09.json';control.private(review_path);review=json.loads(review_path.read_text())
        need(review.get('backup',{}).get('completed') is True and review.get('prestart_source_review_passed') is True,'review_and_backup_required')
        need(control.sha(ROOT/'deployment/preflight-spec.json')==review['spec_sha256'],'review_spec_drift')
        specs=json.loads((ROOT/'deployment/preflight-spec.json').read_text());spec=next(s for s in specs if s['port']==9098)
        lock=os.open('/var/lock/liveuin-resident-core-api.lock',os.O_RDWR|os.O_CREAT,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        current_ops=preflight.unit_state('ops-backend@liveuin.service')
        need(current_ops.get('ActiveState')=='active' and current_ops.get('SubState')=='running','ops_not_running')
        observed_ops_pid=int(current_ops.get('MainPID') or 0);need(observed_ops_pid>0,'ops_pid_unavailable')
        reconciler=load_verified('reviewed_ops_pid_reconciliation',RECONCILE,RECONCILE_SHA)
        captured=io.StringIO()
        with contextlib.redirect_stdout(captured):reconcile_code=reconciler.main(ops_pid=observed_ops_pid)
        reconciled=json.loads(captured.getvalue())
        need(reconcile_code==0 and reconciled.get('status')=='ops_instance_and_mobile_addition_reconciliation_pass' and reconciled.get('ops_pid')==observed_ops_pid and reconciled.get('member_pid')==EXPECTED_PID,'fresh_ops_reconciliation_failed')
        result['ops_pid_observed_and_verified']=observed_ops_pid
        result['reviewed_mobile_addition_preserved']=True
        control.private(control.STATE);prior=json.loads(control.STATE.read_text())
        need(prior.get('status')=='closed_fallback_active' and prior.get('pid')==EXPECTED_PID and prior.get('recovery_required') is True,'proven_closed_fallback_state_required')
        control.static_gate(helper,preflight,review,spec,True);control.source_state(spec,'fallback');control.ops_unchanged(preflight,specs)
        process,initial_env,_=preflight.process({**control.expected_spec(spec),'baseline_pid':EXPECTED_PID})
        need(json.loads(initial_env.get('LIVEUIN_PUBLIC_ADMISSION_COHORT_JSON',''))==json.loads((ROOT/'config/approved-cohort.json').read_text()),'active_acl_drift')
        need(initial_env.get('LIVEUIN_PUBLIC_WORKSPACE_ID')=='liveuin-public' and initial_env.get('LIVEUIN_ENVIRONMENT')=='production','member_scope_drift')
        for key,value in preflight.STORE_PATHS.items():need(initial_env.get(key)==value,'member_store_binding_drift')
        ops,_=reconciler.accepted_ops(preflight,next(s for s in specs if s['port']==9095),observed_ops_pid);_,ops_env,_=preflight.process(ops)
        a=initial_env.get(KEY,'').strip();b=ops_env.get(KEY,'').strip();need(bool(a) and bool(b) and hmac.compare_digest(a.encode(),b.encode()),'shared_signer_drift')
        need(initial_env.get('LIVEUIN_IDENTITY_CREDENTIAL_STORE_ENFORCEMENT','').strip().lower() in {'1','true','yes','on'},'durable_session_enforcement_drift')
        for sig in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):signal.signal(sig,control.interrupted)
        # Existing private backup includes all original modules/config/stores; the
        # current pure fallback bytes are pinned in the immutable package.
        result.update(status='one_file_retry_started',previous_pid=EXPECTED_PID,recovery_required=True);control.write_state(result);started=True
        control.safe_stop(helper,preflight,review)
        target=Path(spec['base'])/'core_identity_release_admission.py'
        control.install(target,ROOT/'candidate/deploy/core_identity_release_admission.py',{control.sha(ROOT/'fallback/deploy/core_identity_release_admission.py')})
        control.static_gate(helper,preflight,review,spec,True);control.source_state(spec,'candidate');control.ops_unchanged(preflight,specs)
        control.run('start')
        # Original full runtime checks accept only the exact candidate. The hook
        # gates just the reproducible missing file before start; never after it.
        process=original_wait(preflight,spec,'candidate',EXPECTED_PID,initial_env)
        original_gate(helper,preflight,review,spec,True);control.source_state(spec,'candidate');control.ops_unchanged(preflight,specs)
        result.update(status='candidate_active_normal_browser_proof_pending',pid=process['pid'],checks=control.negatives(review['public_settings']['terms_version']),recovery_required=True)
        control.write_state(result)
    except BaseException as exc:
        result.update(status='one_file_retry_stopped',failure_code=str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__)
        if started:
            for sig in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):signal.signal(sig,signal.SIG_IGN)
            control.write_state(result)
            # Release our cooperative lock before the original recovery controller
            # reacquires it. No source/config action is performed in between.
            if lock is not None:os.close(lock);lock=None
            sys.argv=[str(ROOT/'deployment/activate-member-09.py'),'recover']
            print(json.dumps({'retry_failure':result['failure_code'],'closed_recovery_follows':True}))
            try:
                recovery_code=control.main()
            except BaseException as recovery_error:
                recovery_code=1
                result['nested_recovery_failure']=str(recovery_error) if isinstance(recovery_error,RuntimeError) else type(recovery_error).__name__
            if recovery_code!=0:
                result.update(status='closed_recovery_failed',recovery_required=True)
                try:
                    # A failed recovery entry must not leave our candidate running.
                    # safe_stop independently pins ExecStop/ExecStopPost first.
                    control.safe_stop(helper,preflight,review)
                    stopped=preflight.unit_state(control.UNIT)
                    need(stopped.get('ActiveState')=='inactive' and int(stopped.get('MainPID') or 0)==0,'member_stop_not_confirmed')
                    result.update(status='member_stopped_after_failed_closed_recovery',member_service_stopped=True)
                except BaseException as stop_error:
                    result.update(manual_root_recovery_required=True,stop_failure=str(stop_error) if isinstance(stop_error,RuntimeError) else type(stop_error).__name__)
                control.write_state(result);print(json.dumps(result,indent=2))
                return 1
            return recovery_code
    finally:
        if lock is not None:os.close(lock)
    print(json.dumps(result,indent=2));return 0 if result['status']=='candidate_active_normal_browser_proof_pending' else 1
if __name__=='__main__':sys.exit(main())
