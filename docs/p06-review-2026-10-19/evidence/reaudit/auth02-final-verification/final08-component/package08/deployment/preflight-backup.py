"""AUTH02 root preflight. Default: read-only metadata; --backup: server-private backup.

Never installs files, changes flags, reloads/restarts services, imports application
code, creates an identity, sends mail, or calls an authentication endpoint.
Backup bytes stay on this server; neither secrets nor record contents are printed.
"""
from pathlib import Path
import argparse, datetime, hashlib, hmac, json, os, re, shutil, sqlite3, stat, subprocess, sys, time

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / 'deployment/preflight-spec.json'
BACKUP_PARENT = Path('/root/liveuin-closeout-backups')
STORE_PATHS = {
    'LIVEUIN_CORE_IDENTITY_SESSION_SQLITE_PATH':'/var/lib/liveuin/core-identity-session-data/liveuin-core-identity-session.sqlite3',
    'LIVEUIN_CORE_IDENTITY_SQLITE_PATH':'/var/lib/liveuin/identity-public-prod/core-identity.sqlite3',
    'LIVEUIN_CORE_IDENTITY_PUBLIC_SQLITE_PATH':'/var/lib/liveuin/identity-public-prod/liveuin-core-identity-public.sqlite3',
}
OPS_STORE_PATHS = {
    'LIVEUIN_CORE_IDENTITY_SQLITE_PATH':'/srv/liveuin/core-identity-data/liveuin-core-identity.sqlite3',
    'LIVEUIN_CORE_IDENTITY_LOGIN_SQLITE_PATH':'/var/lib/liveuin/core-identity-login-data/liveuin-core-identity-login.sqlite3',
    'LIVEUIN_CORE_IDENTITY_SESSION_SQLITE_PATH':STORE_PATHS['LIVEUIN_CORE_IDENTITY_SESSION_SQLITE_PATH'],
}
ENV_KEYS = set(STORE_PATHS) | set(OPS_STORE_PATHS) | {key.replace('_SQLITE_PATH','_DATA_DIR') for key in OPS_STORE_PATHS} | {'LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET','LIVEUIN_IDENTITY_CREDENTIAL_STORE_ENFORCEMENT','LIVEUIN_PUBLIC_ADMISSION_COHORT_JSON','LIVEUIN_PUBLIC_WORKSPACE_ID','LIVEUIN_ENVIRONMENT','ENVIRONMENT','LIVEUIN_ENV','LIVEUIN_PUBLIC_REGISTRATION_ENABLED'}

def require(condition, code):
    if not condition: raise RuntimeError(code)


def run(args):
    return subprocess.run(args,capture_output=True,text=True,timeout=10,check=True).stdout


def unit_state(unit):
    raw=run(['systemctl','show',unit,'--property=Id,User,ActiveState,SubState,MainPID,WorkingDirectory,FragmentPath,DropInPaths,EnvironmentFiles,LoadCredential,LoadCredentialEncrypted,NeedDaemonReload,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost'])
    result = {}
    for line in raw.splitlines():
        if '=' not in line: continue
        key,value=line.split('=',1)
        result[key]=result[key]+' '+value if key in {'EnvironmentFiles','LoadCredential','LoadCredentialEncrypted'} and key in result else value
    return result


def process(spec):
    current=unit_state(spec['unit'])
    require(current.get('NeedDaemonReload')=='no','unit_reload_pending')
    require(current.get('ActiveState')=='active' and current.get('SubState')=='running','service_not_running')
    require(current.get('MainPID')==str(spec['baseline_pid']),'baseline_pid_changed_reconcile_first')
    for key in ['User','WorkingDirectory','FragmentPath','DropInPaths','EnvironmentFiles']:
        require(current.get(key,'')==spec[key],'unit_configuration_drift')
    proc=Path('/proc')/current['MainPID']
    argv=[os.fsdecode(item) for item in (proc/'cmdline').read_bytes().split(b'\0') if item]
    require(argv==spec['argv'],'process_argv_drift')
    require(str((proc/'cwd').resolve(strict=True))==spec['cwd'],'process_cwd_drift')
    require((proc/'exe').resolve(strict=True)==Path(spec['argv'][0]).resolve(strict=True),'process_executable_drift')
    expected_root=Path(spec['cwd'])/'deploy' if spec['port']==9098 else Path('/opt/liveuin/deploy')
    require(Path(spec['base']).resolve(strict=True)==expected_root,'source_root_drift')
    start=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
    env={}
    for entry in (proc/'environ').read_bytes().split(b'\0'):
        key,sep,value=entry.partition(b'=');name=os.fsdecode(key)
        if sep and name in ENV_KEYS:
            require(name not in env,'duplicate_selected_environment')
            env[name]=os.fsdecode(value)
    # Bind each existing listener to this process, no packet or auth request.
    expected='0100007F:%04X'%spec['port']
    inodes={line.split()[9] for line in Path('/proc/net/tcp').read_text().splitlines()[1:] if line.split()[1]==expected and line.split()[3]=='0A'}
    owned={os.readlink(path) for path in (proc/'fd').iterdir()}
    require(len(inodes)==1 and all('socket:[%s]'%inode in owned for inode in inodes),'listener_process_mismatch')
    return {'pid':int(current['MainPID']),'start_ticks':start,'source_root':str(Path(spec['base']).resolve())},env,current


def regular_root_file(path):
    require(not path.is_symlink() and path.is_file(),'protected_file_type_invalid')
    mode=path.stat()
    require(mode.st_uid==0 and not mode.st_mode & 0o022,'protected_file_owner_or_mode_invalid')


def protected_files(current):
    paths=[Path(current['FragmentPath'])]+[Path(value) for value in current['DropInPaths'].split()]
    env_text=current.get('EnvironmentFiles','')
    found=list(re.finditer(r'([^\s]+) \(ignore_errors=(yes|no)\)',env_text))
    require(' '.join(match.group(0) for match in found)==env_text,'environment_file_format_unrecognized')
    for match in found:
        path=Path(match.group(1))
        require(path.is_absolute() and (str(path).startswith('/etc/') or path==Path('/run/liveuin-identity-public-prod/secrets.env')),'environment_file_location_unexpected')
        if not path.exists():
            require(match.group(2)=='yes','required_environment_file_missing')
            continue
        paths.append(path)
    for path in paths:
        require(str(path).startswith('/etc/') or path==Path('/run/liveuin-identity-public-prod/secrets.env'),'protected_configuration_location_unexpected')
        regular_root_file(path)
    return paths


def credential_bindings(unit):
    object_result=json.loads(run(['busctl','--json=short','call','org.freedesktop.systemd1','/org/freedesktop/systemd1','org.freedesktop.systemd1.Manager','GetUnit','s',unit]))
    require(object_result.get('type')=='o' and len(object_result.get('data',[]))==1,'unit_dbus_object_unavailable')
    obj=object_result['data'][0]
    result={}
    for property_name in ['LoadCredential','LoadCredentialEncrypted']:
        try:
            value=json.loads(run(['busctl','--json=short','get-property','org.freedesktop.systemd1',obj,'org.freedesktop.systemd1.Service',property_name]))
        except subprocess.CalledProcessError:
            require(property_name=='LoadCredentialEncrypted','credential_metadata_unavailable')
            value={'unavailable':True}
        require(value.get('unavailable') is True or (value.get('type')=='a(ss)' and isinstance(value.get('data'),list)),'credential_binding_format_unrecognized')
        result[property_name]=value
    return result


def credential_source_continuity(spec):
    bindings=credential_bindings(spec['unit'])
    counts={"plain":0,"encrypted":0}
    for property_name,label in [("LoadCredential","plain"),("LoadCredentialEncrypted","encrypted")]:
        require(bindings[property_name]==spec[property_name],'credential_binding_drift')
        if bindings[property_name].get('unavailable'):
            # Older systemd exposes plain bindings but lacks this D-Bus property.
            # Refuse restart if any loaded unit source declares encrypted input.
            current=unit_state(spec['unit'])
            source_files=[Path(current['FragmentPath'])]+[Path(p) for p in current['DropInPaths'].split()]
            for source_file in source_files:
                for line in source_file.read_text().splitlines():
                    require(not re.match(r'^\s*LoadCredentialEncrypted\s*=\s*[^#\s]',line),'encrypted_credential_metadata_unavailable')
            continue
        for binding in bindings[property_name]['data']:
            require(isinstance(binding,list) and len(binding)==2,'credential_binding_format_unrecognized')
            credential_id,source=binding
            require(isinstance(credential_id,str) and re.fullmatch(r"[A-Za-z0-9_.-]+",credential_id),'credential_name_unrecognized')
            path=Path(source)
            require(path.is_absolute() and path.is_file(),'configured_credential_source_unavailable')
            require(stat.S_ISREG(path.stat().st_mode),'credential_source_not_regular')
            # Open and close only; no value, digest or credential contents read.
            fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC);os.close(fd)
            counts[label]+=1
    return {"configured_sources_readable":True,"counts":counts,
            "credential_bytes_read":False,"credential_contents_backed_up":False,
            "encrypted_source_decryption_proved":False}


def source_checks(spec):
    rows=[]
    for entry in spec['files']:
        name=entry['file'];target=Path(spec['base'])/name;candidate=ROOT/spec['package_subdir']/name
        regular_root_file(candidate)
        data=candidate.read_bytes()
        require(hashlib.sha256(data).hexdigest()==entry['candidate_sha256'],'candidate_hash_mismatch')
        # Compile only, on the production Python interpreter. No import/execution/cache file.
        checked=subprocess.run(['/usr/bin/python3','-c','import sys; compile(sys.stdin.buffer.read(), "AUTH02-candidate", "exec")'],input=data,capture_output=True,timeout=8)
        require(checked.returncode==0,'production_python_compile_failed')
        if entry['baseline_sha256'] is None:
            require(not target.exists() and not target.is_symlink(),'new_helper_already_exists')
        else:
            require(target.is_file() and not target.is_symlink(),'source_file_type_drift')
            require(hashlib.sha256(target.read_bytes()).hexdigest()==entry['baseline_sha256'],'deployed_source_hash_drift')
        rows.append({'file':name,'baseline_matches':True,'candidate_sha256':entry['candidate_sha256'],'python_compile':True})
    return rows


def private_write(path,data):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with path.open('xb') as out:out.write(data)
    os.chmod(path,0o600)


def private_backup(specs,states,stores,root_result):
    if not BACKUP_PARENT.exists():BACKUP_PARENT.mkdir(mode=0o700)
    require(not BACKUP_PARENT.is_symlink() and BACKUP_PARENT.stat().st_uid==0 and stat.S_IMODE(BACKUP_PARENT.stat().st_mode)==0o700,'backup_parent_not_private')
    dest=BACKUP_PARENT/('AUTH02-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+str(os.getpid()))
    dest.mkdir(mode=0o700)
    root_result['backup_directory']=str(dest)
    protected=[]
    restore_metadata=[]
    for spec,current in zip(specs,states):
        for path in protected_files(current):
            if path not in protected:protected.append(path)
        for entry in spec['files']:
            if entry['baseline_sha256'] is not None:
                source=Path(spec['base'])/entry['file']
                private_write(dest/'source'/str(spec['port'])/entry['file'],source.read_bytes())
                meta=source.stat();restore_metadata.append({'path':str(source),'uid':meta.st_uid,'gid':meta.st_gid,'mode':stat.S_IMODE(meta.st_mode),'baseline_sha256':entry['baseline_sha256']})
    for source in protected:
        private_write(dest/'protected-config'/source.relative_to('/'),source.read_bytes())
    total=sum(path.stat().st_size for path in stores)
    require(shutil.disk_usage(dest).free>total*2+100*1024*1024,'insufficient_backup_space')
    backed=[]
    for number,source in enumerate(stores):
        target=dest/'sqlite'/('%02d.sqlite3'%number);target.parent.mkdir(mode=0o700,exist_ok=True)
        deadline=time.monotonic()+45
        def progress(status,remaining,total):
            require(time.monotonic()<deadline,'sqlite_backup_deadline')
        with sqlite3.connect(source.as_uri()+'?mode=ro',uri=True,timeout=4) as origin, sqlite3.connect(target,timeout=4) as copy:
            origin.backup(copy,pages=256,progress=progress,sleep=.05)
            require(copy.execute('PRAGMA quick_check').fetchall()==[('ok',)],'sqlite_backup_check_failed')
        os.chmod(target,0o600)
        backed.append({'source_path':str(source),'backup_file':target.name,'sqlite_backup_consistent':True,'quick_check_ok':True})
    # Protected on-server restore metadata; no config contents or database data exported.
    private_write(dest/'restore-manifest.json',json.dumps({'source_specs':specs,'source_restore_metadata':restore_metadata,'protected_configuration_files':[str(p) for p in protected],'sqlite_backups':backed,'database_restore_not_automatic':True,'cross_database_snapshot_not_claimed':True},indent=2).encode())
    return {'completed':True,'source_files':sum(x['baseline_sha256'] is not None for s in specs for x in s['files']),'protected_config_files':len(protected),'sqlite_backups':len(backed),'server_only':True,'cross_database_snapshot':False,'encryption_claimed':False}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--backup',action='store_true');parser.add_argument('--component',choices=['9095','9098','all'],default='all');args=parser.parse_args()
    result={'row':'AUTH02','checked_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'mode':'metadata_only' if not args.backup else 'metadata_and_root_private_server_backup','production_code_or_settings_modified':False,'services_changed':False,'auth_or_mail_requests':False,'customer_rows_queried':False,'database_bytes_exported_from_server':False}
    try:
        require(os.geteuid()==0,'authenticated_root_required')
        require(str(ROOT).startswith('/root/') and not ROOT.is_symlink() and ROOT.stat().st_uid==0 and stat.S_IMODE(ROOT.stat().st_mode)==0o700,'package_not_root_private')
        regular_root_file(SPEC);specs=json.loads(SPEC.read_text())
        require(len(specs)==2 and {s['unit'] for s in specs}=={'liveuin-identity-public-prod.service','ops-backend@liveuin.service'},'spec_scope_invalid')
        selected_specs=[spec for spec in specs if args.component=='all' or str(spec['port'])==args.component]
        result['component']=args.component
        before=[];envs=[];states=[];rows=[]
        for spec in specs:
            process_state,env,current=process(spec)
            before.append(process_state);envs.append(env);states.append(current)
            config=protected_files(current)
            if spec not in selected_specs: continue
            rows.append({'unit':spec['unit'],'pid':process_state['pid'],'source_root':process_state['source_root'],'source_files':source_checks(spec),'protected_config_files_present':len(config),'restart_credential_continuity':credential_source_continuity(spec),'admission_config_present':bool(env.get('LIVEUIN_PUBLIC_ADMISSION_COHORT_JSON'))})
        require(envs[0].get('LIVEUIN_PUBLIC_WORKSPACE_ID')=='liveuin-public','public_workspace_drift')
        require(envs[0].get('LIVEUIN_ENVIRONMENT')=='production','identity_environment_drift')
        require(not any(e.get('LIVEUIN_PUBLIC_ADMISSION_COHORT_JSON') for e in envs),'admission_setting_already_present_reconcile_first')
        signers=[env.get('LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET','').strip() for env in envs]
        require(all(signers) and hmac.compare_digest(signers[0],signers[1]),'signer_binding_drift')
        require(all(env.get('LIVEUIN_IDENTITY_CREDENTIAL_STORE_ENFORCEMENT','').strip().lower() in {'1','true','yes','on'} for env in envs),'store_enforcement_drift')
        stores=[]
        for index,binding in [(0,STORE_PATHS),(1,OPS_STORE_PATHS)]:
            if specs[index] not in selected_specs:continue
            for key,expected in binding.items():
                configured=envs[index].get(key,'').strip()
                if not configured:
                    directory=envs[index].get(key.replace('_SQLITE_PATH','_DATA_DIR'),'').strip()
                    configured=str(Path(directory)/Path(expected).name) if directory else ''
                require(configured==expected,'identity_store_binding_drift')
                path=Path(expected);require(path.is_file() and not path.is_symlink(),'identity_store_type_drift')
                require((Path('/proc')/str(before[index]['pid'])/'root'/expected.lstrip('/')).samefile(path),'process_store_namespace_drift')
                if path not in stores:stores.append(path)
        require(envs[1].get('LIVEUIN_CORE_IDENTITY_SESSION_SQLITE_PATH')==STORE_PATHS['LIVEUIN_CORE_IDENTITY_SESSION_SQLITE_PATH'],'shared_session_binding_drift')
        result.update({'services':rows,'direct_signer_present_and_equal':True,'store_bindings_match':True,'source_tree_loaded_version_not_claimed':True,'database_content_opened':False})
        if args.backup:
            result['database_content_opened']=True
            selected_states=[state for spec,state in zip(specs,states) if spec in selected_specs]
            result['backup']=private_backup(selected_specs,selected_states,stores,result)
        for i,spec in enumerate(specs):
            after,env,current=process(spec)
            require(after==before[i] and env==envs[i] and current==states[i],'process_or_configuration_changed_during_preflight')
            if spec in selected_specs:
                source_checks(spec)
                credential_source_continuity(spec)
        result['status']='preflight_pass_not_activation_authorization'
    except Exception as exc:
        result['status']='stopped_no_activation'
        result['failure_code']=str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__
        result['backup_may_be_partial']=bool(result.get('backup_directory'))
    print(json.dumps(result,indent=2))
    return 0 if result['status']=='preflight_pass_not_activation_authorization' else 1

if __name__=='__main__':sys.exit(main())
