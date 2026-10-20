"""Read source AST for the exact31 direct deployed modules; never import product code.
No constants, environment, database, transaction, customer record or transitive read.
"""
from pathlib import Path
import ast,hashlib,json
PATHS=['/opt/liveuin/deploy/connect_api.py', '/opt/liveuin/deploy/core_access_api.py', '/opt/liveuin/deploy/core_account_deletion_api.py', '/opt/liveuin/deploy/core_ai_ops_route_adapter.py', '/opt/liveuin/deploy/core_ai_provider_api.py', '/opt/liveuin/deploy/core_analytics_api.py', '/opt/liveuin/deploy/core_booking_api.py', '/opt/liveuin/deploy/core_case_api.py', '/opt/liveuin/deploy/core_country_context_api.py', '/opt/liveuin/deploy/core_demand_api.py', '/opt/liveuin/deploy/core_identity_api.py', '/opt/liveuin/deploy/core_improvement_api.py', '/opt/liveuin/deploy/core_intelligence_api.py', '/opt/liveuin/deploy/core_inventory_api.py', '/opt/liveuin/deploy/core_ledger_api.py', '/opt/liveuin/deploy/core_lifecycle_api.py', '/opt/liveuin/deploy/core_mail_readiness_api.py', '/opt/liveuin/deploy/core_marketing_publication_runtime.py', '/opt/liveuin/deploy/core_media_api.py', '/opt/liveuin/deploy/core_movein_api.py', '/opt/liveuin/deploy/core_ops_spine_api.py', '/opt/liveuin/deploy/core_ops_task_api.py', '/opt/liveuin/deploy/core_ops_ticket_api.py', '/opt/liveuin/deploy/core_payment_api.py', '/opt/liveuin/deploy/core_remediation_api.py', '/opt/liveuin/deploy/core_resolution_api.py', '/opt/liveuin/deploy/core_support_api.py', '/opt/liveuin/deploy/core_trust_api.py', '/opt/liveuin/deploy/core_vendor_api.py', '/opt/liveuin/deploy/core_verification_api.py', '/opt/liveuin/deploy/core_viewing_api.py']
def name(node):
    if isinstance(node,ast.Name):return node.id
    if isinstance(node,ast.Attribute):return name(node.value)+'.'+node.attr
    if isinstance(node,ast.Call):return name(node.func)+'(...)'
    return '<dynamic>'
class Declarations(ast.NodeVisitor):
    def __init__(self,postponed):self.calls=[];self.imports=[];self.excluded_main=[];self.postponed=postponed
    def visit_Call(self,node):
        self.calls.append({'line':node.lineno,'function':name(node.func),'keyword_names':[k.arg for k in node.keywords if k.arg]});self.generic_visit(node)
    def visit_FunctionDef(self,node):
        for x in node.decorator_list+node.args.defaults+[x for x in node.args.kw_defaults if x is not None]:self.visit(x)
        if not self.postponed:
            for x in node.args.posonlyargs+node.args.args+node.args.kwonlyargs+[x for x in [node.args.vararg,node.args.kwarg] if x is not None]:
                if x.annotation:self.visit(x.annotation)
            if node.returns:self.visit(node.returns)
    visit_AsyncFunctionDef=visit_FunctionDef
    def visit_Lambda(self,node):
        for x in node.args.defaults+[x for x in node.args.kw_defaults if x is not None]:self.visit(x)
    def visit_AnnAssign(self,node):
        if not self.postponed:self.visit(node.annotation)
        if node.value:self.visit(node.value)
    def visit_If(self,node):
        t=node.test
        main=isinstance(t,ast.Compare) and isinstance(t.left,ast.Name) and t.left.id=='__name__' and len(t.ops)==1 and isinstance(t.ops[0],ast.Eq) and len(t.comparators)==1 and isinstance(t.comparators[0],ast.Constant) and t.comparators[0].value=='__main__'
        if main:
            self.excluded_main.append(node.lineno)
            for x in node.orelse:self.visit(x)
        else:self.generic_visit(node)
    def visit_Import(self,node):
        for x in node.names:self.imports.append({'line':node.lineno,'module':x.name})
    def visit_ImportFrom(self,node):self.imports.append({'line':node.lineno,'module':node.module,'level':node.level})
rows=[]
for filename in PATHS:
    row={'path':filename}
    try:
        path=Path(filename)
        if path.is_symlink():raise RuntimeError('source_symlink')
        data=path.read_bytes();tree=ast.parse(data)
        postponed=any(isinstance(x,ast.ImportFrom) and x.module=='__future__' and any(y.name=='annotations' for y in x.names) for x in tree.body)
        visitor=Declarations(postponed);visitor.visit(tree)
        row.update(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),postponed_annotations=postponed,module_or_definition_time_calls=visitor.calls,import_names_only=visitor.imports,excluded_main_guards=visitor.excluded_main)
    except Exception as exc:row['error_type']=type(exc).__name__
    rows.append(row)
print(json.dumps({'scope':'exact31 direct deployed modules, conservative conditional declaration calls; no transitive expansion','product_imported':False,'environment_or_record_read':False,'files':rows},indent=2))
