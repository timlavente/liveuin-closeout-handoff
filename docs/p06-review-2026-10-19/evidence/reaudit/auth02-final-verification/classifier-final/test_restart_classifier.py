"""Independent local environment-semantics tests; no service, credentials or proc reads."""
from pathlib import Path
from types import SimpleNamespace
import hashlib, importlib.util, json, sys, tempfile
sys.dont_write_bytecode=True
SOURCE=Path(__file__).resolve().parents[1]/'deployment/classify-restart-config.py'
spec=importlib.util.spec_from_file_location('isolated_restart_classifier',SOURCE)
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
rows=[]
def test(name,fn):
    try:fn();rows.append({'name':name,'passed':True})
    except Exception as error:rows.append({'name':name,'passed':False,'error':str(error)})
def compare(planned,rules,actual,exports=None):
    planned=dict(planned);removed=c.apply_unset(planned,rules)
    if exports:planned.update(exports)
    return c.environment_differences(planned,actual,rules,removed,set(exports or {}))
def equal(actual,expected):assert actual==expected,(actual,expected)
test('exact_unset_rejects_stale_different_running_value',lambda:equal(compare({'FOO':'bar'},[('FOO','bar')],{'FOO':'baz'}),['FOO']))
test('exact_unset_rejects_stale_equal_running_value',lambda:equal(compare({'FOO':'bar'},[('FOO','bar')],{'FOO':'bar'}),['FOO']))
test('exact_unset_accepts_actual_absence',lambda:equal(compare({'FOO':'bar'},[('FOO','bar')],{}),[]))
test('nonmatching_exact_unset_preserves_value',lambda:equal(compare({'FOO':'baz'},[('FOO','bar')],{'FOO':'baz'}),[]))
test('bare_unset_rejects_any_old_presence',lambda:equal(compare({},[('FOO',None)],{'FOO':'anything'}),['FOO']))
test('empty_exact_assignment_is_specific',lambda:equal(compare({'FOO':'nonempty'},[('FOO','')],{'FOO':'nonempty'}),[]))
test('wrapper_reintroduction_is_compared_after_unset',lambda:equal(compare({'DATABASE_URL':'old'},[('DATABASE_URL',None)],{'DATABASE_URL':'new'},{'DATABASE_URL':'new'}),[]))
test('wrapper_reintroduction_still_rejects_wrong_value',lambda:equal(compare({'DATABASE_URL':'old'},[('DATABASE_URL',None)],{'DATABASE_URL':'wrong'},{'DATABASE_URL':'new'}),['DATABASE_URL']))
with tempfile.TemporaryDirectory(prefix='auth02-env-fixture-') as temporary:
    root=Path(temporary).resolve();a=root/'a.env';b=root/'b.env'
    a.write_text('FOO=file-one\nHASH=part#literal\nQUOTED=" space preserved "\n')
    b.write_text('FOO=file-two\n')
    properties={'PassEnvironment':{'type':'as','data':[]},'UnsetEnvironment':{'type':'as','data':['FOO=file-two']},'PAMName':{'type':'s','data':['']},'Environment':{'type':'as','data':['FOO=unit']}}
    p=SimpleNamespace(run=lambda args:json.dumps(properties[args[-1]]),protected_files=lambda current:[a,b])
    control=SimpleNamespace(manager_environment=lambda preflight:({'FOO':'manager','MANAGER_ONLY':'fixture'},'private-fixture-fingerprint'))
    current={'EnvironmentFiles':str(a)+' (ignore_errors=no) '+str(b)+' (ignore_errors=no)'}
    def precedence():
        report={};planned,pins,rules,removed,fingerprint=c.pre_wrapper_environment(p,control,'/fixture',current,report)
        equal(planned,{'MANAGER_ONLY':'fixture','HASH':'part#literal','QUOTED':' space preserved '});equal(removed,{'FOO'});equal(len(pins),2)
        equal(report['manager_environment_variable_count'],2)
    test('manager_unit_files_unset_precedence_and_literal_grammar',precedence)
    def refused(property_name,data):
        original=properties[property_name];properties[property_name]={'type':original['type'],'data':data}
        try:
            try:c.pre_wrapper_environment(p,control,'/fixture',current,{})
            except RuntimeError:return
            raise AssertionError('unmodelled environment was accepted')
        finally:properties[property_name]=original
    test('PassEnvironment_requires_separate_review',lambda:refused('PassEnvironment',['FOO']))
    test('PAM_environment_requires_separate_review',lambda:refused('PAMName',['fixture-pam']))
    def complex_refused():
        q=root/'complex.env';q.write_text('FOO=continued\\\nnext\n')
        try:c.env_file(q)
        except RuntimeError:return
        raise AssertionError('unsupported continuation accepted')
    test('unsupported_complex_env_grammar_fails_closed',complex_refused)
result={'classifier_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'test_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope':'Exact classifier pure helpers; synthetic temporary EnvironmentFiles and D-Bus property fixtures only; no production or real secret reads','test_count':len(rows),'passed_count':sum(x['passed'] for x in rows),'cases':rows}
Path(__file__).with_name('restart-classifier-results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));raise SystemExit(0 if all(x['passed'] for x in rows) else 1)
