"""Bounded source-only import/startup inventory. Never imports product code or reads env/records.
Output whitelist: source paths/hashes, Python identifiers, line numbers, booleans/counts.
No source literals, credentials, query data, logs or runtime configuration are printed.
"""
import ast,hashlib,json,re
from pathlib import Path
ROOT=Path('/opt/liveuin/ops_backend')
INITIAL=['app.py','app/__init__.py','app/main.py','auth_email_otp.py','ui_nav_api.py','autopilot_executor.py','api_aliases.py','app/autopilot_generated/__init__.py','db.py','auth_db.py','session_utils.py']
MAX_FILES=64

def label(n):
    if isinstance(n,ast.Name):return n.id
    if isinstance(n,ast.Attribute):return label(n.value)+'.'+n.attr
    if isinstance(n,ast.Call):return label(n.func)+'(...)'
    return type(n).__name__
def main_guard(n):
    if not isinstance(n,ast.Compare) or len(n.ops)!=1 or not isinstance(n.ops[0],ast.Eq) or len(n.comparators)!=1:return False
    a,b=n.left,n.comparators[0]
    return ((isinstance(a,ast.Name) and a.id=='__name__' and isinstance(b,ast.Constant) and b.value=='__main__') or (isinstance(b,ast.Name) and b.id=='__name__' and isinstance(a,ast.Constant) and a.value=='__main__'))
class Scan(ast.NodeVisitor):
    def __init__(self,annotations=False):self.calls=[];self.imports=[];self.main=[];self.annotations=annotations
    def visit_Call(self,n):
        self.calls.append({'line':n.lineno,'function':label(n.func),'keyword_names':[k.arg for k in n.keywords if k.arg]});self.generic_visit(n)
    def visit_Import(self,n):self.imports.extend({'line':n.lineno,'module':a.name,'names':[],'asname':a.asname,'level':0,'kind':'import'} for a in n.names)
    def visit_ImportFrom(self,n):self.imports.append({'line':n.lineno,'module':n.module or '', 'names':[{'name':a.name,'asname':a.asname} for a in n.names],'level':n.level,'kind':'from'})
    def visit_FunctionDef(self,n):
        for d in n.decorator_list:self.visit(d)
        for d in [*n.args.defaults,*n.args.kw_defaults]:
            if d:self.visit(d)
        if not self.annotations:
            for a in [*n.args.posonlyargs,*n.args.args,*n.args.kwonlyargs,n.args.vararg,n.args.kwarg]:
                if a and a.annotation:self.visit(a.annotation)
            if n.returns:self.visit(n.returns)
        for t in getattr(n,'type_params',[]):self.visit(t)
    visit_AsyncFunctionDef=visit_FunctionDef
    def visit_Lambda(self,n):
        for d in [*n.args.defaults,*n.args.kw_defaults]:
            if d:self.visit(d)
    def visit_ClassDef(self,n):
        for d in [*n.decorator_list,*n.bases,*[k.value for k in n.keywords],*getattr(n,'type_params',[])]:self.visit(d)
        for d in n.body:self.visit(d)
    def visit_If(self,n):
        self.visit(n.test)
        if main_guard(n.test):
            x=Scan(self.annotations)
            for b in n.body:x.visit(b)
            self.main.append({'line':n.lineno,'is_exact_name_main_guard':True,'not_executed_by_import':True,'guarded_calls':x.calls})
            for b in n.orelse:self.visit(b)
        else:
            for b in [*n.body,*n.orelse]:self.visit(b)
    def visit_AnnAssign(self,n):
        self.visit(n.target)
        if n.value:self.visit(n.value)
        if not self.annotations:self.visit(n.annotation)

def resolve_local(path,imp):
    parts=imp['module'].split('.') if imp['module'] else []
    if imp['level']:
        base=path.parent
        for _ in range(imp['level']-1):base=base.parent
    else:base=ROOT
    candidates=[base.joinpath(*parts)]
    if imp['kind']=='from':candidates += [base.joinpath(*parts,a['name']) for a in imp['names'] if a['name']!='*']
    out=[]
    for c in candidates:
        for q in [c.with_suffix('.py'),c/'__init__.py']:
            if q.is_file() and ROOT in q.resolve().parents:out.append(q.resolve())
    return out
queue=[ROOT/n for n in INITIAL];seen=set();rows=[]
while queue and len(seen)<MAX_FILES:
    p=queue.pop(0)
    if str(p) in seen:continue
    seen.add(str(p));row={'path':str(p)}
    try:
        raw=p.read_bytes();tree=ast.parse(raw);ann=any(isinstance(n,ast.ImportFrom) and n.module=='__future__' and any(a.name=='annotations' for a in n.names) for n in tree.body)
        scan=Scan(ann);scan.visit(tree)
        fs=[]
        for n in tree.body:
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
                s=Scan(ann)
                for b in n.body:s.visit(b)
                fs.append({'name':n.name,'line':n.lineno,'calls':s.calls,'imports':s.imports})
        row.update(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),postponed_annotations=ann,import_time_calls=scan.calls,import_time_imports=scan.imports,excluded_main_guards=scan.main,function_body_call_map=fs)
        for i in scan.imports:
            for q in resolve_local(p,i):
                if str(q) not in seen and q not in queue:queue.append(q)
    except Exception as e:row['unreadable_or_parse_error']=type(e).__name__
    rows.append(row)
# The pre-start shell script is described only by safe command categories.
p=ROOT/'bin/ensure_venv.sh';shell={'path':str(p)}
try:
    raw=p.read_bytes();s=raw.decode();shell.update(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),line_count=len(s.splitlines()),contains_venv_creation=bool(re.search(r'\bvenv\b',s)),contains_pip=bool(re.search(r'\bpip\b',s)),contains_curl=bool(re.search(r'\bcurl\b',s)),contains_wget=bool(re.search(r'\bwget\b',s)),contains_eval=bool(re.search(r'\beval\b',s)),contains_product_script_invocation=bool(re.search(r'python[^\n]*\b(?:app|deploy|mail|payment|tenan|queue)[^\n]*\.py',s,re.I)))
except Exception as e:shell['unreadable_or_parse_error']=type(e).__name__
print(json.dumps({'mode':'source_read_only_no_imports_no_records_no_env','file_limit':MAX_FILES,'traversal_complete_within_selected_local_import_graph':not queue,'unvisited_count':len(queue),'files':rows,'prestart_shell_categories':shell},indent=2))
