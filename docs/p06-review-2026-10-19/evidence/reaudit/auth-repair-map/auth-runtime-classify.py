from pathlib import Path
import json,subprocess,datetime,urllib.request
plain=['LIVEUIN_DEPLOYED_COMMIT','LIVEUIN_ENVIRONMENT','LIVEUIN_PUBLIC_WORKSPACE_ID','LIVEUIN_IDENTITY_EMAIL_DELIVERY_MODE','LIVEUIN_CORE_IDENTITY_SESSION_DATA_DIR','LIVEUIN_CORE_IDENTITY_SESSION_SQLITE_PATH','LIVEUIN_CORE_IDENTITY_PUBLIC_DATA_DIR','LIVEUIN_CORE_IDENTITY_PUBLIC_SQLITE_PATH','LIVEUIN_CORE_IDENTITY_DATA_DIR','LIVEUIN_CORE_IDENTITY_SQLITE_PATH']
flags=['LIVEUIN_PUBLIC_REGISTRATION_ENABLED','LIVEUIN_IDENTITY_EMAIL_READY','LIVEUIN_GOOGLE_NATIVE_ID_TOKEN_READY','LIVEUIN_GOOGLE_OIDC_TOKEN_EXCHANGE_READY','LIVEUIN_GOOGLE_OIDC_CALLBACK_VALIDATION_READY','LIVEUIN_PUBLIC_GOOGLE_IDENTITY_ENABLED','LIVEUIN_IDENTITY_CREDENTIAL_STORE_ENFORCEMENT']
presence=['LIVEUIN_GOOGLE_CLIENT_ID','LIVEUIN_GOOGLE_REDIRECT_URI','LIVEUIN_GOOGLE_CLIENT_SECRET_REF','LIVEUIN_IDENTITY_PROVIDER_SUBJECT_PEPPER_REF','LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET_REF','LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET','LIVEUIN_PUBLIC_TERMS_VERSION']
out={'at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'services':[]}
for service in ['liveuin-identity-public-prod.service','ops-backend@liveuin.service']:
 pid=subprocess.check_output(['systemctl','show',service,'--value','-p','MainPID'],text=True).strip();row={'service':service,'pid':pid}
 try:
  raw=Path('/proc/'+pid+'/environ').read_bytes();env=dict(x.decode(errors='replace').split('=',1) for x in raw.split(b'\0') if b'=' in x)
  row['nonsecret']={k:env.get(k,'') for k in plain};row['flags']={k:{'present':k in env,'enabled':env.get(k,'').strip().lower() in ['true','1','yes','on']} for k in flags};row['configured']={k:bool(env.get(k,'').strip()) for k in presence}
 except Exception as e:row['environment_read_error']=type(e).__name__
 row['environment_file_names']=subprocess.check_output(['systemctl','show',service,'--value','-p','EnvironmentFiles'],text=True).strip()
 out['services'].append(row)
for route in ['version','health']:
 try:
  with urllib.request.urlopen('http://127.0.0.1:9098/'+route,timeout=10) as r:out[route]={'http_status':r.status,'body':json.load(r)}
 except Exception as e:out[route]={'error':type(e).__name__}
print(json.dumps(out,indent=2))
