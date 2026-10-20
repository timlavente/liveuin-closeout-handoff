"""Read only fixed prestart source and whitelisted nonsecret mode metadata.
No product import, shell execution, DB access, env dump or credential reads.
Only expected boolean/enum/import names and fixed-file match booleans leave process.
"""
from pathlib import Path
import hashlib,json,re,os,signal
signal.alarm(8)
P=Path('/opt/liveuin/ops_backend/bin/ensure_venv.sh');BASE=Path('/opt/liveuin/ops_backend')
EXPECTED='bbbb3c5c44d6db48b26ca3f11972c4557d9eabe038573e12e4e6cfee56c50c4e'
s=P.read_text();assert hashlib.sha256(s.encode()).hexdigest()==EXPECTED
lines=s.splitlines();ranges=[(37,59),(64,76),(93,111),(126,189),(227,267),(284,317)]
# Exclude index URLs and message literals. Preserve only explicitly nonsecret literals.
SAFE={'auto','always','never','off','on','skip','0','1','2','app','r','rb','%s\\n','requirements.txt','.requirements.sha256','/usr/bin/python3','python3','fastapi','uvicorn','psycopg2','jwt','requests','httpx','pydantic','sqlalchemy','dotenv','email_validator','setuptools','wheel'}
def allowed_literal(body,source_line):
 if body in SAFE or body.isdigit():return True
 # These substitutions are linear and never evaluate shell syntax.
 t=re.sub(r'\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9*]', 'VAR',body)
 if t and all(c in set('VAR bin.pythonrequirements_sha256/.-') for c in t):return True
 if body=='import app' or (body.startswith('import $') and body[8:].isidentifier()):return True
 if ('DEFAULT_IMPORTS' in source_line or 'DSN_VARS' in source_line) and body and all(x.replace('.','_').isidentifier() for x in body.split()):return True
 # The existing indirect variable lookup is syntax only, not evaluated here.
 if source_line.lstrip().startswith('eval ') and set(re.findall(r'[A-Za-z_][A-Za-z0-9_]*',body)) <= {'val','v'} and not any(x in body for x in ['`','$(',';','\n']):return True
 return False
def clean_line(line):
 out=[];i=0
 while i<len(line):
  if line[i] not in ('"',"'"):out.append(line[i]);i+=1;continue
  q=line[i];i+=1;body=[];closed=False
  while i<len(line):
   c=line[i]
   if c=='\\' and i+1<len(line):body.extend([c,line[i+1]]);i+=2;continue
   if c==q:closed=True;i+=1;break
   body.append(c);i+=1
  body=''.join(body)
  out.append(q+(body if allowed_literal(body,line) else '<literal-redacted>')+(q if closed else '<unterminated-on-this-line>'))
 return ''.join(out)
listing=[]
for first,last in ranges:
 for i in range(first,last+1):
  current_line=lines[i-1]
  if current_line.lstrip().startswith('#'):continue
  clean=clean_line(current_line)
  # No runtime substitutions occur; source-only selected mode/default lines are nonsecret.
  listing.append({'line':i,'source':clean})
# Read process environment only in memory; emit strictly whitelisted flags, never other values.
raw=Path('/proc/1298408/environ').read_bytes();env={}
for bit in raw.split(b'\0'):
 if b'=' in bit:
  k,v=bit.split(b'=',1);env[k.decode(errors='replace')]=v.decode(errors='replace')
flags={}
for key,allowed in {'ENSURE_VENV_REBUILD':{'auto','always','never'},'ENSURE_VENV_APP_IMPORT':{'auto','always','never','0','1','off','on','skip'},'ENSURE_VENV_WRITE_FREEZE':{'0','1'},'ENSURE_VENV_COMPILEALL':{'0','1'}}.items():
 v=env.get(key);flags[key]={'present':v is not None,'classification':v if v in allowed else ('unset' if v is None else 'unsupported_value_redacted')}
for key in ['ENSURE_VENV_IMPORTS','ENSURE_VENV_DSN_VARS']:
 v=env.get(key);flags[key]={'present':v is not None,'whitelisted_name_list':v.split() if v is not None and all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*',x) for x in v.split()) else None}
# Defaults anchored in reviewed script location; refuse unexpected path overrides.
paths={'BACKEND_DIR':str(BASE),'VENV_DIR':str(BASE/'.venv'),'REQ_FILE':str(BASE/'requirements.txt')}
path_binding={k:{'override_present':k in env,'matches_expected_or_unset':env.get(k,v)==v} for k,v in paths.items()}
checks={'expected_path_bindings':all(v['matches_expected_or_unset'] for v in path_binding.values())}
if checks['expected_path_bindings']:
 req=BASE/'requirements.txt';marker=BASE/'.venv/.requirements.sha256';py=BASE/'.venv/bin/python'
 checks.update(venv_python_exists=py.is_file(),venv_python_executable=os.access(py,os.X_OK),requirements_exists=req.is_file(),requirements_marker_exists=marker.is_file())
 if req.is_file() and marker.is_file():
  value=marker.read_text().strip();checks.update(marker_is_sha256=bool(re.fullmatch('[0-9a-f]{64}',value)),requirements_hash_matches_marker=value==hashlib.sha256(req.read_bytes()).hexdigest())
signal.alarm(0)
print(json.dumps({'mode':'source_and_whitelisted_nonsecret_process_metadata_only','source_sha256':EXPECTED,'pid':1298408,'selected_source':listing,'process_nonsecret_flags':flags,'expected_path_bindings':path_binding,'fixed_path_checks':checks,'limitation':'Running process environment is not proof of newly loaded systemd prestart environment. Auto mode can still rebuild if its import checks fail; this tool executes no import checks.'},indent=2))
