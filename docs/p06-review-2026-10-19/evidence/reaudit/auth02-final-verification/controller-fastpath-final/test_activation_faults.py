"""Local-only fault injection for the exact AUTH02/9095 activation controller.

All service, HTTP, backup and production-path operations are replaced by explicit
fixtures. Only disposable files below TemporaryDirectory are written. Root UID
and root-directory checks are adapted for an unprivileged fixture; other guards
run. This is controller logic evidence, never production restart/auth evidence.
"""
from pathlib import Path
import contextlib, hashlib, importlib.util, io, json, os, signal, stat, sys, tempfile
from types import SimpleNamespace
from unittest.mock import patch
sys.dont_write_bytecode=True

CONTROLLER = Path(__file__).resolve().parents[1] / 'deployment/activate-9095.py'
OUT = Path(__file__).with_name('activation-fault-results.json')

def sha(data):
    return hashlib.sha256(data).hexdigest()

FAKE_HELPER = '''from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[1]
def data():return json.loads((ROOT/'runtime.json').read_text())
def unit_state(unit):return data()['unit']
def protected_files(current):return [ROOT/'protected.env']
def credential_source_continuity(spec):return {'configured_sources_readable':True}
def run(args):
    if 'GetUnit' in args:return json.dumps({'type':'o','data':['/fixture/unit']})
    assert args[:4]==['busctl','--json=short','get-property','org.freedesktop.systemd1'],args
    if args[-2:] == ['org.freedesktop.systemd1.Manager','Environment']:return json.dumps({'type':'as','data':data().get('manager_environment',[])})
    return json.dumps({'type':'a(sasbttttuii)','data':data()['actions'][args[-1]]})
def process(spec):
    d=data()
    d['process_calls']=d.get('process_calls',0)+1
    (ROOT/'runtime.json').write_text(json.dumps(d))
    if int(d['unit']['MainPID'])!=int(spec['baseline_pid']):raise RuntimeError('baseline_pid_changed_reconcile_first')
    if d.get('process_drift') and int(d['unit']['MainPID'])!=101:raise RuntimeError('process_argv_drift')
    if int(d['unit']['MainPID'])!=101:
        if d.get('listener_remaining',0):
            d['listener_remaining']-=1
            (ROOT/'runtime.json').write_text(json.dumps(d))
            raise RuntimeError('listener_process_mismatch')
        if d.get('never_listens'):raise RuntimeError('listener_process_mismatch')
    return {'pid':int(d['unit']['MainPID']),'start_ticks':'fixture','source_root':'fixture'}, {'fixture':'same'},d['unit']
'''

class Fixture:
    def __init__(self, root, scenario):
        self.root=root;self.scenario=scenario;self.actions=[];self.requests=[];self.replacements=[];self.clock=0;self.startup_probes=0
        spec=importlib.util.spec_from_file_location('isolated_auth02_controller',CONTROLLER)
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        m=self.m
        self.paths={
            'baseline':root/'target.py', 'candidate':root/'candidate-9095/deploy/core_identity_api.py',
            'fallback':root/'fallback-9095/deploy/core_identity_api.py',
            'helper':root/'deployment/preflight-backup.py', 'spec':root/'deployment/preflight-spec.json',
            'review':root/'deployment/restart-review-9095.json', 'main':root/'entry-main.py',
            'startup_probe':root/'deployment/prestart-fastpath-probe.py',
        }
        for p in self.paths.values():p.parent.mkdir(parents=True,exist_ok=True)
        for key in ['baseline','candidate','fallback']:self.paths[key].write_text('VERSION='+repr(key)+'\n')
        self.paths['helper'].write_text(FAKE_HELPER)
        self.paths['main'].write_text('ENTRY="unchanged fixture"\n')
        self.paths['startup_probe'].write_text('# Mocked synthetic startup probe; never executed.\n')
        (root/'protected.env').write_text('FIXTURE=yes\n')
        (root/'fixture-credential').write_text('synthetic-only-no-production-value\n')
        m.ROOT=root;m.TARGET=self.paths['baseline'];m.PREFLIGHT=self.paths['helper'];m.SPEC=self.paths['spec'];m.REVIEW=self.paths['review'];m.MARKER=root/'deployment/activation-9095-state.json'
        m.BASELINE=sha(self.paths['baseline'].read_bytes());m.CANDIDATE=sha(self.paths['candidate'].read_bytes());m.FALLBACK=sha(self.paths['fallback'].read_bytes())
        self.initial_hash=m.BASELINE
        self.unit={'MainPID':'101','ActiveState':'active','SubState':'running','NeedDaemonReload':'no','User':'fixture','WorkingDirectory':'fixture','FragmentPath':'fixture','DropInPaths':'','EnvironmentFiles':'fixture'}
        self.unit.update({key:'' for key in m.RESTART_PROPERTIES})
        action=[['/fixture/approved', ['/fixture/approved'], False, 0, 0, 0, 0, 0, 0, 0]]
        self.runtime={'unit':self.unit,'process_calls':0,'actions':{key:json.loads(json.dumps(action)) for key in m.RESTART_PROPERTIES}}
        self.save_runtime()
        service_spec={key:self.unit[key] for key in ['User','WorkingDirectory','FragmentPath','DropInPaths','EnvironmentFiles']}
        service_spec.update(unit=m.UNIT,baseline_pid=101,LoadCredential={'type':'a(ss)','data':[['fixture',str(root/'fixture-credential')]]})
        self.paths['spec'].write_text(json.dumps([service_spec]))
        self.review={'startup_import_review_passed':True,'restart_configuration_matches_running_service':True,
            'preflight_sha256':sha(self.paths['helper'].read_bytes()),'spec_sha256':sha(self.paths['spec'].read_bytes()),
            'candidate_sha256':m.CANDIDATE,'fallback_sha256':m.FALLBACK,'baseline_pid':101,
            'startup_probe_sha256':sha(self.paths['startup_probe'].read_bytes()),
            'credential_source_versions':m.credential_source_versions(service_spec),
            'manager_configuration_fingerprint':sha(b'{}'),
            'protected_configuration_sha256':{str(root/'protected.env'):sha((root/'protected.env').read_bytes())},
            'startup_source_sha256':{'/opt/liveuin/ops_backend/app/main.py':sha(self.paths['main'].read_bytes())},
            'restart_properties_sha256':{key:sha(json.dumps([row[:3] for row in self.runtime['actions'][key]],separators=(',',':')).encode()) for key in m.RESTART_PROPERTIES}}
        self.paths['review'].write_text(json.dumps(self.review))
        original_need=m.need
        def fixture_need(condition,code):
            if code in {'authenticated_root_required','package_not_root_private'}:return
            original_need(condition,code)
        m.need=fixture_need
        def fixture_private(path):
            s=path.stat();original_need(not path.is_symlink() and stat.S_ISREG(s.st_mode) and not s.st_mode&0o022,'private_input_invalid')
        m.private=fixture_private
        m.Path=lambda name: self.paths['main'] if str(name)=='/opt/liveuin/ops_backend/app/main.py' else Path(name)
        original_replace=m.replace_source
        def replacement(source,digest,metadata):
            if self.scenario=='fallback_write_failure' and digest==m.FALLBACK:raise RuntimeError('fixture_fallback_write_failure')
            original_replace(source,digest,metadata);self.replacements.append(digest)
            if digest==m.CANDIDATE:
                if self.scenario=='config_drift_after_write':(root/'protected.env').write_text('FIXTURE=changed\n')
                if self.scenario=='startup_drift_after_write':self.paths['main'].write_text('ENTRY="changed"\n')
                if self.scenario=='target_drift_after_write':m.TARGET.write_text('UNREVIEWED=True\n')
                if self.scenario=='action_command_drift_after_write':
                    self.load_runtime();self.runtime['actions']['ExecStartPre'][0][0]='/fixture/unreviewed';self.save_runtime()
                if self.scenario=='stop_command_drift_after_write':
                    self.load_runtime();self.runtime['actions']['ExecStop'][0][0]='/fixture/unreviewed-stop';self.save_runtime()
                if self.scenario=='credential_rotation_after_write':
                    replacement=root/'rotated-credential';replacement.write_text('synthetic-rotated-value\n');replacement.replace(root/'fixture-credential')
                if self.scenario=='manager_environment_drift_after_write':
                    self.load_runtime();self.runtime['manager_environment']=['FIXTURE_MANAGER=changed'];self.save_runtime()
                if self.scenario in {'term_after_write','hup_after_write'}:signal.raise_signal(signal.SIGTERM if self.scenario.startswith('term') else signal.SIGHUP)
        m.replace_source=replacement
        m.command=self.command
        m.probe=self.probe
        if self.scenario=='bad_review':self.review['startup_import_review_passed']=False;self.paths['review'].write_text(json.dumps(self.review))
        if self.scenario=='bad_helper_pin':self.review['preflight_sha256']='0'*64;self.paths['review'].write_text(json.dumps(self.review))
        if self.scenario=='bad_spec_pin':self.review['spec_sha256']='0'*64;self.paths['review'].write_text(json.dumps(self.review))
        if self.scenario=='baseline_drift':m.TARGET.write_text('UNREVIEWED=True\n')

    def load_runtime(self):self.runtime=json.loads((self.root/'runtime.json').read_text());return self.runtime
    def save_runtime(self):(self.root/'runtime.json').write_text(json.dumps(self.runtime))
    def command(self,action):
        assert action in {'restart','stop'},action
        digest=sha(self.m.TARGET.read_bytes());self.actions.append({'action':action,'target_sha256':digest})
        self.load_runtime()
        if action=='stop':self.runtime['unit'].update(ActiveState='inactive',SubState='dead',MainPID='0');self.save_runtime();return
        if self.scenario=='restart_failure' and digest==self.m.CANDIDATE:raise RuntimeError('fixture_restart_failure')
        self.runtime['unit'].update(ActiveState='active',SubState='running',MainPID=str(int(self.runtime['unit']['MainPID'])+1))
        if self.scenario=='action_runtime_metadata_changes':
            for rows in self.runtime['actions'].values():rows[0][3:]=[11,12,13,14,202,0,0]
        self.runtime.update(listener_remaining=3 if self.scenario=='delayed_listener' and digest==self.m.CANDIDATE else 0,
                            never_listens=self.scenario=='never_listens' and digest==self.m.CANDIDATE,
                            process_drift=self.scenario=='argv_drift_after_restart' and digest==self.m.CANDIDATE)
        self.save_runtime()
    def probe(self,path,post=False):
        assert path in {'/healthz','/api/core/identity/login/challenges','/api/core/identity/login/challenges/AUTH02-NONEXISTENT-DIAGNOSTIC/verify','/api/ops/auth/request_code','/api/ops/auth/verify-code'},path
        self.requests.append({'path':path,'post':post,'payload':'{}' if post else None})
        closed=sha(self.m.TARGET.read_bytes())==self.m.FALLBACK
        if self.scenario in {'negative_failure','fallback_write_failure','fallback_startup_probe_failure'} and not closed:raise RuntimeError('fixture_negative_failure')
        if self.scenario=='fallback_checks_failure' and closed:raise RuntimeError('fixture_closed_checks_failure')
        if self.scenario=='fallback_checks_failure' and not closed:raise RuntimeError('fixture_negative_failure')
        if self.scenario=='delayed_health' and path=='/healthz' and not closed:
            count=sum(x['path']=='/healthz' for x in self.requests)
            if count<3:raise self.m.urllib.error.URLError('fixture_health_not_ready')
        if path=='/healthz':return {'status':200,'ok':True,'detail':None,'no_store':False}
        if path.startswith('/api/core/'):return {'status':404,'ok':False,'detail':'not_found','no_store':True}
        return {'status':503 if closed else (403 if 'request_code' in path else 400),'ok':False,'detail':'browser_sign_in_temporarily_locked' if closed else ('browser_sign_in_unavailable' if 'request_code' in path else 'challenge_id_required'),'no_store':False}
    def subprocess(self,args,**kwargs):
        if args[:2]==['/usr/bin/python3','-c']:
            compile(kwargs['input'],'fixture-source','exec');return SimpleNamespace(returncode=0,stdout='',stderr='')
        if args==['/usr/bin/python3',str(self.paths['startup_probe']),'--review',str(self.m.REVIEW)]:
            self.startup_probes+=1
            digest=sha(self.m.TARGET.read_bytes())
            report={'status':'prestart_fastpath_pass','no_product_import':True,'no_dependency_install':True}
            fail=(self.scenario=='entry_startup_probe_failure' or
                  self.scenario=='postwrite_startup_probe_failure' and self.startup_probes>=2 or
                  self.scenario=='fallback_startup_probe_failure' and digest==self.m.FALLBACK)
            if fail:report['status']='stopped'
            if self.scenario=='startup_probe_missing_safety_claim':report.pop('no_dependency_install')
            if self.scenario=='startup_probe_malformed_reply':return SimpleNamespace(returncode=0,stdout='not-json',stderr='')
            return SimpleNamespace(returncode=1 if fail else 0,stdout=json.dumps(report),stderr='')
        assert args==['/usr/bin/python3',str(self.m.PREFLIGHT),'--component','9095','--backup'],args
        report={'status':'preflight_pass_not_activation_authorization','backup':{'completed':True},'backup_directory':str(self.root/'fixture-private-backup')}
        if self.scenario=='backup_failure':report['backup']['completed']=False
        return SimpleNamespace(returncode=0,stdout=json.dumps(report),stderr='')
    def monotonic(self):self.clock+=.25;return self.clock
    def sleep(self,seconds):self.clock+=seconds
    def run(self,recover=False):
        previous={sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGHUP)}
        stream=io.StringIO()
        try:
            with patch.object(sys,'argv',['controller','--recover' if recover else '--activate']),patch.object(self.m.subprocess,'run',self.subprocess),patch.object(self.m.time,'sleep',self.sleep),patch.object(self.m.time,'monotonic',self.monotonic),contextlib.redirect_stdout(stream):
                code=self.m.main()
        finally:
            for sig,handler in previous.items():signal.signal(sig,handler)
        return code,json.loads(stream.getvalue())

def main():
    cases=['happy','bad_review','bad_helper_pin','bad_spec_pin','backup_failure','baseline_drift','restart_failure','negative_failure','config_drift_after_write','startup_drift_after_write','target_drift_after_write','fallback_write_failure','fallback_checks_failure','term_after_write','hup_after_write','owner_pending_recovery','delayed_listener','never_listens','argv_drift_after_restart','delayed_health','action_runtime_metadata_changes','action_command_drift_after_write','stop_command_drift_after_write','credential_rotation_after_write','manager_environment_drift_after_write','entry_startup_probe_failure','postwrite_startup_probe_failure','fallback_startup_probe_failure','startup_probe_missing_safety_claim','startup_probe_malformed_reply']
    rows=[]
    for case in cases:
        with tempfile.TemporaryDirectory(prefix='auth02-controller-fixture-') as tmp:
            f=Fixture(Path(tmp).resolve(),case)
            try:
                code,result=f.run()
                if case=='owner_pending_recovery':
                    assert code==0 and result['status']=='candidate_negative_checks_passed_owner_proof_pending'
                    code,result=f.run(recover=True)
                if case in {'happy','delayed_listener','delayed_health','action_runtime_metadata_changes'}:
                    assert code==0 and result['status']=='candidate_negative_checks_passed_owner_proof_pending',result
                    assert f.replacements==[f.m.CANDIDATE] and [x['action'] for x in f.actions]==['restart']
                elif case in {'bad_review','bad_helper_pin','bad_spec_pin','backup_failure','baseline_drift','entry_startup_probe_failure','startup_probe_missing_safety_claim','startup_probe_malformed_reply'}:
                    assert code==1 and result['status']=='stopped_before_change',result
                    assert not f.replacements and not f.actions
                elif case in {'config_drift_after_write','startup_drift_after_write','target_drift_after_write','fallback_write_failure','fallback_checks_failure','action_command_drift_after_write','credential_rotation_after_write','manager_environment_drift_after_write','postwrite_startup_probe_failure','fallback_startup_probe_failure'}:
                    assert code==1 and result['status']=='service_stopped_for_closed_recovery',result
                    assert f.actions[-1]['action']=='stop'
                    if case in {'config_drift_after_write','startup_drift_after_write','target_drift_after_write','action_command_drift_after_write','credential_rotation_after_write','manager_environment_drift_after_write','postwrite_startup_probe_failure'}:assert not any(x['action']=='restart' for x in f.actions)
                    if case=='fallback_startup_probe_failure':assert [x['action'] for x in f.actions]==['restart','stop']
                elif case=='stop_command_drift_after_write':
                    assert code==1 and result['status']=='recovery_failed_manual_root_action_required',result
                    assert not f.actions,f.actions
                    assert sha(f.m.TARGET.read_bytes())==f.m.FALLBACK
                else:
                    assert code==1 and result['status']=='closed_fallback_active_new_sign_in_held',result
                    assert sha(f.m.TARGET.read_bytes())==f.m.FALLBACK
                assert not any(x==f.m.BASELINE for x in f.replacements)
                rows.append({'name':case,'passed':True,'result_status':result['status'],'replacements':len(f.replacements),'service_actions':[x['action'] for x in f.actions],'mock_http_requests':len(f.requests),'process_checks':f.load_runtime().get('process_calls',0),'mock_startup_probes':f.startup_probes})
            except Exception as error:
                rows.append({'name':case,'passed':False,'error':str(error),'service_actions':[x['action'] for x in f.actions]})
    result={'controller_path':str(CONTROLLER),'controller_sha256':sha(CONTROLLER.read_bytes()),'test_script_sha256':sha(Path(__file__).read_bytes()),'scope':'local disposable source files; fake service/process/HTTP/backup; no production operations','root_fixture_adaptations':['UID/root-directory checks adapted for unprivileged fixture','file ownership check uses fixture owner','one startup-source path maps to temporary file'],'test_count':len(rows),'passed_count':sum(x['passed'] for x in rows),'cases':rows}
    OUT.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return 0 if all(x['passed'] for x in rows) else 1

if __name__=='__main__':raise SystemExit(main())
