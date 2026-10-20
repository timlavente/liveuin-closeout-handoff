"""Count only the named synthetic parent's canonical sessions/refresh records.
No token/hash/password/metadata/body columns are read; no product code is imported.
"""
from pathlib import Path
import datetime,hashlib,json,os,re,signal,sqlite3,subprocess,time
EMAIL='timlavente+liveuin-test-parent@gmail.com'
WORKSPACE='liveuin-public'
UNIT='liveuin-identity-public-prod.service'
EXPECTED_PID=3675726
PUBLIC=Path('/var/lib/liveuin/identity-public-prod/liveuin-core-identity-public.sqlite3')
SESSIONS=Path('/var/lib/liveuin/core-identity-session-data/liveuin-core-identity-session.sqlite3')
SOURCE_ROOT=Path('/opt/liveuin-identity-public/current/deploy')
SOURCES={'core_identity_session_store.py':'c0f2a07b7778aef761deee03b32adc61bfa257cb1edeae933416438508a265c3','core_identity_public_schema.py':'ea82232ef0229076e73e6bdd372465da9b4a0ef420f0e2e251877ba7711186ea','core_identity_public_store.py':'98414fa04c72281edca3f399a40c1c2e731e1a367f7a74b794fcf09d60b908d4','core_identity_public.py':'8340f026f68f5048bbe2e5fc4744f17366dcf134730d4349213c549319630019','core_identity_session.py':'a3f4cedfc79003abebbdaacc12e59eb82086b0b6e5534ed08eb817a54989585c'}
COLUMNS={'identity_public_accounts':{'email_hash','workspace_id','account_id','person_id','status','email_verified_at'},'identity_session_credentials':{'workspace_id','actor_id','status','expires_at','revoked_at'},'identity_public_refresh_credentials':{'account_id','workspace_id','status','expires_at','revoked_at'}}
def need(value,code):
 if not value:raise ValueError(code)
def authorizer(action,a,b,*_):
 if action==sqlite3.SQLITE_SELECT:return sqlite3.SQLITE_OK
 if action==sqlite3.SQLITE_READ:return sqlite3.SQLITE_OK if a in COLUMNS and (not b or b in COLUMNS[a]) else sqlite3.SQLITE_DENY
 if action==sqlite3.SQLITE_FUNCTION:return sqlite3.SQLITE_OK if (b or a) in {'count','sum','coalesce'} else sqlite3.SQLITE_DENY
 return sqlite3.SQLITE_DENY

def readonly(path):
 need(path.is_file() and not path.is_symlink(),'canonical_store_unavailable')
 c=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=2);c.row_factory=sqlite3.Row
 c.execute('PRAGMA query_only=ON');c.set_authorizer(authorizer);return c

COUNT_FIELDS="""COUNT(*) AS total,
 COALESCE(SUM(CASE WHEN status='active' AND (expires_at=0 OR expires_at>?) THEN 1 ELSE 0 END),0) AS active_unexpired,
 COALESCE(SUM(CASE WHEN status='revoked' THEN 1 ELSE 0 END),0) AS revoked,
 COALESCE(SUM(CASE WHEN status='revoked' AND revoked_at>0 THEN 1 ELSE 0 END),0) AS revoked_with_timestamp,
 COALESCE(SUM(CASE WHEN status='active' AND expires_at>0 AND expires_at<=? THEN 1 ELSE 0 END),0) AS expired,
 COALESCE(SUM(CASE WHEN status='rotated' THEN 1 ELSE 0 END),0) AS rotated,
 COALESCE(SUM(CASE WHEN status NOT IN ('active','revoked','rotated') THEN 1 ELSE 0 END),0) AS other_status"""
def scan(public,sessions,now):
 # Account IDs are used only in memory as exact query bindings and never printed.
 email_hash=hashlib.sha256(EMAIL.encode()).hexdigest()
 found=public.execute('SELECT account_id,person_id,status,email_verified_at FROM identity_public_accounts WHERE workspace_id=? AND email_hash=? LIMIT 2',(WORKSPACE,email_hash)).fetchall()
 need(len(found)==1,'exact_synthetic_parent_account_required');account=found[0]
 for key in ('account_id','person_id'):need(isinstance(account[key],str) and re.fullmatch(r'[A-Za-z0-9_-]{1,160}',account[key]),'synthetic_parent_binding_unavailable')
 need(account['status']=='tenant_active' and account['email_verified_at']>0,'synthetic_parent_not_verified_tenant_active')
 canonical=sessions.execute('SELECT '+COUNT_FIELDS+' FROM identity_session_credentials WHERE workspace_id=? AND actor_id=?',(now,now,WORKSPACE,account['person_id'])).fetchone()
 refresh=public.execute('SELECT '+COUNT_FIELDS+' FROM identity_public_refresh_credentials WHERE workspace_id=? AND account_id=?',(now,now,WORKSPACE,account['account_id'])).fetchone()
 result={'canonical_sessions':dict(canonical),'refresh_credentials':dict(refresh)}
 need(all(type(n) is int and 0<=n<=2000 for counts in result.values() for n in counts.values()),'synthetic_parent_count_out_of_bound')
 return result

def process():
 raw=subprocess.run(['systemctl','show',UNIT,'--property=MainPID,ActiveState,SubState'],capture_output=True,text=True,timeout=5,check=True).stdout
 state=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
 need(state.get('ActiveState')=='active' and state.get('SubState')=='running' and state.get('MainPID')==str(EXPECTED_PID),'member_process_changed')
 proc=Path('/proc')/str(EXPECTED_PID);ticks=(proc/'stat').read_text().rsplit(')',1)[1].split()[19]
 keys={'LIVEUIN_CORE_IDENTITY_PUBLIC_SQLITE_PATH','LIVEUIN_CORE_IDENTITY_PUBLIC_DATA_DIR','LIVEUIN_CORE_IDENTITY_SESSION_SQLITE_PATH','LIVEUIN_CORE_IDENTITY_SESSION_DATA_DIR'};env={}
 for entry in (proc/'environ').read_bytes().split(b'\0'):
  key,sep,value=entry.partition(b'=');name=os.fsdecode(key)
  if sep and name in keys:need(name not in env,'duplicate_store_binding');env[name]=os.fsdecode(value).strip()
 for prefix,path in [('LIVEUIN_CORE_IDENTITY_PUBLIC',PUBLIC),('LIVEUIN_CORE_IDENTITY_SESSION',SESSIONS)]:
  binding=env.get(prefix+'_SQLITE_PATH') or str(Path(env.get(prefix+'_DATA_DIR',''))/path.name)
  need(binding==str(path) and (proc/'root'/str(path).lstrip('/')).samefile(path),'canonical_store_binding_changed')
 return ticks

def sources():
 need(all(hashlib.sha256((SOURCE_ROOT/name).read_bytes()).hexdigest()==expected for name,expected in SOURCES.items()),'identity_source_changed')
def main():
 out={'read_only':True,'synthetic_parent_only':True,'token_password_metadata_or_body_columns_read':False,'customer_records_read':False,'product_imports':False,'account_or_session_mutations':False};connections=[]
 try:
  need(os.geteuid()==0,'root_required');signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(ValueError('snapshot_timeout')));signal.alarm(20)
  sources();ticks=process();now=int(time.time())
  for path in (PUBLIC,SESSIONS):connections.append(readonly(path))
  counts=scan(*connections,now);need(scan(*connections,now)==counts,'parent_counts_changed_during_snapshot')
  need(process()==ticks,'member_process_changed_during_snapshot');sources()
  out.update(status='synthetic_parent_session_counts',observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),as_of_epoch_seconds=now,member_pid=EXPECTED_PID,account_verified_active=True,**counts,limitations='Counts require visible browser sign-in/sign-out evidence and before/after comparison. A zero-to-zero snapshot alone proves no logout; multiple concurrent sessions prevent attributing a change to one control.')
 except Exception as exc:out.update(status='snapshot_stopped',failure_code=str(exc) if isinstance(exc,ValueError) and re.fullmatch(r'[a-z_]+',str(exc)) else type(exc).__name__)
 finally:
  signal.alarm(0)
  for c in connections:c.close()
 print(json.dumps(out,indent=2));return 0 if out['status']=='synthetic_parent_session_counts' else 1
if __name__=='__main__':raise SystemExit(main())
