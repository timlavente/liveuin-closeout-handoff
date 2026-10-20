"""Read-only source AST inventory for the existing9095 startup import boundary.
No product imports, environment reads, service calls, records, logs or execution.
Never emits literal values from source; only filenames, source hashes and call names.
"""
import ast,hashlib,json
from pathlib import Path
ROOT=Path('/opt/liveuin/ops_backend')
NAMES=['auth_email_otp.py','ui_nav_api.py','autopilot_executor.py','api_aliases.py','app/autopilot_generated/__init__.py','db.py']
SELECTED_FUNCTIONS={'register_alias_routers','register_autopilot_routers'}
def label(node):
    if isinstance(node,ast.Name):return node.id
    if isinstance(node,ast.Attribute):return label(node.value)+'.'+node.attr
    if isinstance(node,ast.Call):return label(node.func)+'(...)'
    return type(node).__name__
class Calls(ast.NodeVisitor):
    def __init__(self):self.calls=[];self.imports=[];self.hooks=[];self.selected=[]
    def visit_Call(self,node):self.calls.append({'line':node.lineno,'function':label(node.func)});self.generic_visit(node)
    def visit_Import(self,node):self.imports.extend({'line':node.lineno,'module':n.name} for n in node.names)
    def visit_ImportFrom(self,node):self.imports.append({'line':node.lineno,'module':'.'*node.level+(node.module or '')})
    def visit_FunctionDef(self,node):
        for d in node.decorator_list:
            if isinstance(d,ast.Call) and label(d.func).endswith(('.on_event','.lifespan')):
                self.hooks.append({'line':node.lineno,'function':node.name,'hook':label(d.func)})
        if node.name in SELECTED_FUNCTIONS:
            collector=Calls()
            for n in node.body:collector.visit(n)
            self.selected.append({'line':node.lineno,'function':node.name,'calls':collector.calls,'imports':collector.imports})
    visit_AsyncFunctionDef=visit_FunctionDef
    def visit_Lambda(self,node):pass
rows=[]
for name in NAMES:
    path=ROOT/name;row={'path':str(path)}
    try:
        raw=path.read_bytes();tree=ast.parse(raw);scan=Calls();scan.visit(tree)
        row.update(sha256=hashlib.sha256(raw).hexdigest(),top_level_calls=scan.calls,top_level_imports=scan.imports,startup_hooks=scan.hooks,selected_registration_functions=scan.selected)
    except Exception as error:row['unreadable_or_parse_error']=type(error).__name__
    rows.append(row)
print(json.dumps({'mode':'source_read_only_no_product_imports','files':rows},indent=2))
