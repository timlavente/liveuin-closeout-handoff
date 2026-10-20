"""AUTH-01 only: restore the existing private delivery service with closed recovery.

No message, challenge, account, permission, database write or payment action.
The authenticated empty /send proof must fail before storage/SMTP.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

UNIT = 'otp-gateway.service'
EXPECTED = {
    '/etc/systemd/system/otp-gateway.service': 'd2ecd65e7581c6aa019a56e637fdded337ffd4f720c826479371a85ff80bc272',
    '/etc/systemd/system/ops-backend@liveuin.service.d/82-identity-otp-gateway.conf': '6746a5b8da9cf9965ae1730ee67ba3fc5cbdd1fe4d32af5ccfc962534a9a9609',
    '/opt/liveuin/otp_service/app.py': '24542a1052dda9723591e1e068c0a446183b643768cf6ccda134a4f2f8e7fe87',
    '/opt/liveuin/deploy/core_identity_api.py': 'fcf8c612f2442ab05a8950523890806af7b89f88e9cbf801fcc5561ec1d6acc4',
}

def state(unit):
    r = subprocess.run(['systemctl','show',unit,'--property=ActiveState,SubState,MainPID,UnitFileState,User,WorkingDirectory,DropInPaths,ExecStart,EnvironmentFiles'],capture_output=True,text=True,timeout=8,check=True)
    return dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)

def selected(pid):
    result = {}
    for item in Path('/proc/%s/environ' % pid).read_bytes().split(b'\0'):
        key,sep,value = item.partition(b'=')
        if sep and key in {b'OTP_GATEWAY_URL',b'OTP_INTERNAL_TOKEN'}:
            result[key] = value.decode()
    return result

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())

def port_open():
    with socket.socket() as connection:
        connection.settimeout(.4)
        return connection.connect_ex(('127.0.0.1',9094))==0

def verify_process():
    current=state(UNIT)
    pid=int(current.get('MainPID') or 0)
    assert current.get('ActiveState')=='active' and pid>0,'started_process_missing'
    proc=Path('/proc')/str(pid)
    argv=[x.decode() for x in (proc/'cmdline').read_bytes().split(b'\0') if x]
    assert argv==['/opt/liveuin/otp_service/venv/bin/python','-m','uvicorn','app:APP','--host','127.0.0.1','--port','9094'],'started_command_mismatch'
    assert (proc/'cwd').resolve()==Path('/opt/liveuin/otp_service'),'started_cwd_mismatch'
    assert (proc/'exe').resolve()==Path('/opt/liveuin/otp_service/venv/bin/python').resolve(),'started_executable_mismatch'
    listener_inodes=set()
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        parts=line.split()
        if parts[1]=='0100007F:2386' and parts[3]=='0A': listener_inodes.add(parts[9])
    owned={os.readlink(p) for p in (proc/'fd').iterdir()}
    assert len(listener_inodes)==1 and all('socket:[%s]'%n in owned for n in listener_inodes),'listener_not_owned_by_service'
    return current

def probe(path, token=None, body=None):
    headers = {'Content-Type':'application/json'}
    if token is not None:
        headers['X-OTP-Internal-Token'] = token
    request = urllib.request.Request('http://127.0.0.1:9094'+path, data=body, headers=headers, method='POST' if body is not None else 'GET')
    try:
        with OPENER.open(request,timeout=4) as response:
            status, raw = response.status, response.read(2048)
    except urllib.error.HTTPError as error:
        status,raw = error.code,error.read(2048)
    payload = json.loads(raw)
    # Return only exact known contract names, never an arbitrary response value.
    known = {'internal_authentication_required','email_and_challenge_id_required','not_ready'}
    return {'status':status,'ok':payload.get('ok') is True,'ready':payload.get('ready') is True,
            'error':payload.get('error') if payload.get('error') in known else None,
            'expected_service':payload.get('service')=='liveuin-otp-smtp-pg'}

def main():
    result = {'row':'AUTH-01','started_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'script_sent_message':False,'customer_records_read':False,'payment_settings_changed':False}
    activated = False
    try:
        assert os.geteuid()==0, 'root_required'
        for name,digest in EXPECTED.items():
            path=Path(name)
            assert path.is_file() and not path.is_symlink(), 'unexpected_source_type'
            assert hashlib.sha256(path.read_bytes()).hexdigest()==digest, 'source_drift'
        before=state(UNIT)
        assert before.get('ActiveState')=='inactive' and before.get('MainPID')=='0', 'state_drift'
        assert before.get('UnitFileState')=='enabled' and before.get('User')=='liveuin', 'unit_drift'
        assert before.get('WorkingDirectory')=='/opt/liveuin/otp_service', 'directory_drift'
        assert before.get('DropInPaths','')=='','unit_dropin_drift'
        assert before.get('EnvironmentFiles')=='/etc/liveuin/otp-prod.env (ignore_errors=no)','environment_binding_drift'
        assert 'argv[]=/opt/liveuin/otp_service/venv/bin/python -m uvicorn app:APP --host 127.0.0.1 --port 9094 ;' in before.get('ExecStart',''),'start_command_drift'
        assert not port_open(),'preexisting_gateway_listener'
        ops=state('ops-backend@liveuin.service')
        assert ops.get('ActiveState')=='active', 'ops_not_active'
        env=selected(int(ops['MainPID']))
        assert state('ops-backend@liveuin.service')['MainPID']==ops['MainPID'],'ops_process_changed'
        assert env.get(b'OTP_GATEWAY_URL','').rstrip('/')=='http://127.0.0.1:9094', 'gateway_binding_drift'
        token=env.get(b'OTP_INTERNAL_TOKEN','')
        assert token, 'missing_internal_token'
        env.clear()
        parent=Path('/var/backups/liveuin-p06')
        if not parent.exists(): parent.mkdir(mode=0o700)
        assert parent.is_dir() and not parent.is_symlink() and parent.stat().st_uid==0, 'backup_parent'
        assert parent.stat().st_mode & 0o077 == 0, 'backup_parent_permissions'
        backup=parent/'auth-01-20261020-attempt-01'
        backup.mkdir(mode=0o700)
        for name in EXPECTED:
            shutil.copy2(name,backup/Path(name).name)
        # Preserve the existing private configuration inside a root-only directory.
        config=Path('/etc/liveuin/otp-prod.env')
        assert config.is_file() and not config.is_symlink(), 'config_type'
        shutil.copy2(config,backup/'otp-prod.env')
        (backup/'before-state.json').write_text(json.dumps(before,indent=2)+'\n')
        (backup/'source-digests.json').write_text(json.dumps(EXPECTED,indent=2)+'\n')
        result.update(backup=str(backup),before=before,source_versions_verified=True)
        # Source review confirms no startup mail, queue, DB write or migration.
        activated=True
        started=subprocess.run(['systemctl','start',UNIT],capture_output=True,text=True,timeout=20)
        assert started.returncode==0, 'start_failed'
        deadline=time.monotonic()+12
        health=None
        while time.monotonic()<deadline:
            try:
                health=probe('/healthz')
                if health['status']==200: break
            except (OSError,ValueError): pass
            time.sleep(.25)
        result['health']=health
        assert health and health['status']==200 and health['expected_service'], 'health_failed'
        verified=verify_process()
        result['verified_service_pid']=verified['MainPID']
        denied=probe('/send',body=b'{}')
        result['anonymous_empty_send']=denied
        assert denied['status']==401 and denied['error']=='internal_authentication_required','anonymous_gate_failed'
        authenticated=probe('/send',token=token,body=b'{}')
        token=''
        result['authenticated_empty_send']=authenticated
        assert authenticated['status']==400 and authenticated['error']=='email_and_challenge_id_required','token_gate_failed'
        ready=probe('/readyz')
        result['database_connection_check']=ready
        assert ready['status']==200 and ready['ready'], 'database_not_ready'
        result['after']=verify_process()
        assert result['after']['ActiveState']=='active','service_not_active'
        result['result']='restored_ready_actual_delivery_and_signin_still_unproved'
    except Exception as error:
        result['result']='failed_no_row_pass'
        result['failure_type']=type(error).__name__
        if isinstance(error,AssertionError): result['failure_check']=str(error)
        if activated:
            try:
                stopped=subprocess.run(['systemctl','stop',UNIT],capture_output=True,text=True,timeout=15)
                result['recovery_stop_exit']=stopped.returncode
                restored=state(UNIT)
                result['recovery_state']=restored
                result['recovery_confirmed']=stopped.returncode==0 and restored.get('ActiveState')=='inactive' and restored.get('MainPID')=='0' and not port_open()
            except Exception as recovery_error:
                result['recovery_error_type']=type(recovery_error).__name__
                result['recovery_confirmed']=False
    result['finished_at_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
