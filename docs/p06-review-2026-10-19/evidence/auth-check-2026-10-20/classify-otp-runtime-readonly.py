"""Root-only, read-only classifier. No mail, /send, DB, logs, or service writes.
Only selected presence bits and sanitized URL fields leave process memory.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
from urllib.parse import urlsplit

PROPERTIES = ('Id','LoadState','ActiveState','SubState','Result','MainPID','ExecMainCode','ExecMainStatus','ExecMainExitTimestamp','FragmentPath')

def state(unit):
    r=subprocess.run(['systemctl','show',unit,'--no-pager','--property='+','.join(PROPERTIES)],capture_output=True,text=True,timeout=8)
    return dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)

def fingerprint(path):
    p=Path(path)
    try:
        st=p.stat()
        return {'path':path,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':st.st_size,'mode':oct(st.st_mode & 0o777),'uid':st.st_uid}
    except OSError as e:return {'path':path,'error':type(e).__name__}

out={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'mode':'read_only_no_mail_no_customer_database_no_logs','uid_is_root':os.geteuid()==0}
if os.geteuid()!=0:
    out['error']='authenticated_root_session_required'
    print(json.dumps(out,indent=2));raise SystemExit(1)
ops=state('ops-backend@liveuin.service');gateway=state('otp-gateway.service')
out['ops_service']=ops;out['gateway_service']=gateway
out['file_fingerprints']=[fingerprint(p) for p in ['/etc/systemd/system/otp-gateway.service','/etc/systemd/system/ops-backend@liveuin.service.d/82-identity-otp-gateway.conf','/opt/liveuin/otp_service/app.py','/opt/liveuin/deploy/core_identity_api.py']]
pid=int(ops.get('MainPID') or 0)
if pid<=0:
    out['classification']='ops_service_not_running'
else:
    proc=Path('/proc')/str(pid)
    try:
        argv=(proc/'cmdline').read_bytes().split(b'\0')
        out['expected_ops_process']=b'app.main:app' in argv and b'9095' in argv
        if not out['expected_ops_process']:
            out['classification']='ops_process_mismatch_no_environment_read'
        else:
            selected={}
            for record in (proc/'environ').read_bytes().split(b'\0'):
                name,sep,value=record.partition(b'=')
                if sep and name in {b'OTP_GATEWAY_URL',b'OTP_INTERNAL_TOKEN'}:
                    selected[name]=value
            raw_url=selected.get(b'OTP_GATEWAY_URL',b'').decode('utf-8','replace').strip()
            out['effective_presence']={'OTP_GATEWAY_URL':bool(raw_url),'OTP_INTERNAL_TOKEN':bool(selected.get(b'OTP_INTERNAL_TOKEN',b''))}
            parsed=urlsplit(raw_url)
            try:port=parsed.port or (443 if parsed.scheme=='https' else 80 if parsed.scheme=='http' else None)
            except ValueError:port=None
            # Path names are not needed to prove a binding to the known gateway;
            # report root path vs custom path, never arbitrary query/userinfo.
            out['gateway_binding']={'scheme':parsed.scheme,'host':parsed.hostname,'port':port,'root_path':parsed.path in ('','/'),'userinfo_present':parsed.username is not None or parsed.password is not None,'query_present':bool(parsed.query),'fragment_present':bool(parsed.fragment)}
            selected.clear();raw_url=''
            present=out['effective_presence']
            if not all(present.values()):
                out['classification']='missing_effective_gateway_configuration'
            elif parsed.scheme=='http' and parsed.hostname in {'127.0.0.1','localhost','::1'} and port==9094 and parsed.path in ('','/'):
                try:
                    with socket.create_connection(('127.0.0.1',9094),timeout=2):
                        out['tcp_9094']='connected_no_payload_sent'
                    out['classification']='configured_gateway_listening_delivery_result_unproved'
                except OSError as e:
                    out['tcp_9094']=type(e).__name__
                    out['classification']='configured_gateway_unreachable'
            else:
                out['classification']='configured_other_gateway_not_probed'
            # No SMTP or /send request: listening/health is not email delivery.
    except OSError as e:
        out['classification']='effective_process_metadata_unreadable';out['error']=type(e).__name__
print(json.dumps(out,indent=2))
