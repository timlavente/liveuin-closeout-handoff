"""Source-only ensure_venv review: fixed file/hash, no execution/env/config/records.
Shell listing preserves control words, approved command/flag names, variable references,
assignment names, punctuation; all other literal words and quoted text are redacted.
Python heredoc bodies are parsed, never run, with every string/number literal replaced.
"""
import ast,hashlib,json,re
from pathlib import Path
P=Path('/opt/liveuin/ops_backend/bin/ensure_venv.sh')
EXPECTED='bbbb3c5c44d6db48b26ca3f11972c4557d9eabe038573e12e4e6cfee56c50c4e'
raw=P.read_bytes();assert hashlib.sha256(raw).hexdigest()==EXPECTED
source=raw.decode();lines=source.splitlines()
SAFE=set('if then elif else fi for while until do done case esac in function return exit set unset export local readonly declare typeset eval exec command test true false source printf echo read cat head tail sed awk grep cut tr sort uniq find xargs dirname basename readlink realpath mkdir rm mv cp chmod chown touch install mktemp flock sleep date id env bash sh python python3 pip pip3 uvicorn venv ensurepip importlib metadata sysconfig os sys json hashlib pathlib import from as def class with try except finally raise assert print len bool str int list dict set tuple any all open exists is_file is_dir read_bytes read_text write_text subprocess run check_call check_output Popen compile execfile requirements requirement wheel wheels pip_version python_version get_bootstrap_python build_venv ensure_venv ensure_dependencies log warn die'.split())
TOKEN=re.compile(r'\$\{[^}\n]*\}|\$[A-Za-z_][A-Za-z0-9_]*|--?[A-Za-z][A-Za-z0-9_-]*|[A-Za-z_][A-Za-z0-9_]*|[^A-Za-z_\s]')
def safe_line(line):
    # Comments are not source operations. A hash inside a shell expansion is retained only as punctuation.
    if line.lstrip().startswith('#'):return '<comment>'
    assignments={m.group(1) for m in re.finditer(r'(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)=',line)}
    out=[]
    for m in TOKEN.finditer(line):
        t=m.group(0)
        if t.startswith('${'):
            refs=re.findall(r'[A-Za-z_][A-Za-z0-9_]*',t[2:-1]);t='${'+(refs[0] if refs else '<expr>')+(':<redacted-expansion>' if len(refs)>1 or any(x in t for x in ':-=?') else '')+'}'
        elif t.startswith('$'):pass
        elif t in SAFE or t in assignments or (t.startswith('-') and len(t)>1):pass
        elif re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',t):t='<literal>'
        elif t.isdigit():t='<number>'
        elif t in ['@',':','/','.']:t='<literal-punctuation>'
        out.append(t)
    return ' '.join(out)
class Redact(ast.NodeTransformer):
    def visit_Constant(self,n):
        if n.value is None or isinstance(n.value,bool):return n
        return ast.copy_location(ast.Constant(value='<literal>'),n)
heredocs=[];listing=[];i=0
while i<len(lines):
    line=lines[i];m=re.search(r'<<-?\s*[\'\"]?([A-Za-z_][A-Za-z0-9_]*)[\'\"]?',line)
    listing.append({'line':i+1,'source_structure':safe_line(line)})
    if m:
        end=i+1
        while end<len(lines) and lines[end].strip()!=m.group(1):end+=1
        body='\n'.join(lines[i+1:end]);row={'start_line':i+2,'end_line':end,'bytes':len(body.encode())}
        try:
            tree=ast.parse(body);row['python_ast_parsed']=True
            row['literal_redacted_python']=ast.unparse(Redact().visit(tree))
        except SyntaxError:row['python_ast_parsed']=False;row['literal_redacted_lines']=[safe_line(s) for s in body.splitlines()]
        heredocs.append(row);listing.append({'line':end+1,'source_structure':'<heredoc delimiter>'});i=end+1
    else:i+=1
print(json.dumps({'mode':'fixed_source_read_only_no_execution_no_env','path':str(P),'sha256':EXPECTED,'shell_listing':listing,'heredocs':heredocs,'limitation':'Shell token listing is a literal-redacted aid, not a shell parser. Python bodies are exact AST structure with constants removed; no body or shell was executed.'},indent=2))
