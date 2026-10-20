"""Create the bounded root-private startup verdict only after initial fastpath proof.
No application import, environment read, credential read, database or service action.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,stat,sys
ROOT=Path(__file__).resolve().parents[1]
TARGET='/opt/liveuin/deploy/core_identity_api.py'
SOURCES=[('evidence/auth02-startup-declarations.json',20),('evidence/auth02-direct-deploy-startup-ast.json',31),('evidence/auth02-concrete-startup-constructors.json',6)]
def need(value,code):
 if not value:raise RuntimeError(code)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def private(path):
 need(path.is_file() and not path.is_symlink() and path.stat().st_uid==0 and not path.stat().st_mode&0o022,'private_file_required')
def within(path):
 private(path);need(ROOT in path.resolve().parents,'evidence_outside_package')
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--expected-package-manifest-sha256',required=True);parser.add_argument('--probe-result',required=True);parser.add_argument('--configuration-result',default=str(ROOT/'evidence/auth02-restart-config-03.json'));args=parser.parse_args()
 result={'component':'AUTH02-9095','service_actions':False,'product_imports':False,'credential_reads':False,'customer_database_reads':False}
 try:
  need(os.geteuid()==0 and str(ROOT).startswith('/root/') and ROOT.stat().st_uid==0 and stat.S_IMODE(ROOT.stat().st_mode)==0o700,'root_private_package_required')
  manifest=ROOT/'deployment/package-manifest-9095.json';private(manifest);need(sha(manifest)==args.expected_package_manifest_sha256,'package_manifest_mismatch')
  rows=json.loads(manifest.read_text())['files']
  for row in rows:
   p=ROOT/row['path'];within(p);need(sha(p)==row['sha256'],'package_file_drift')
  proof_path=Path(args.probe_result);config_path=Path(args.configuration_result);within(proof_path);within(config_path)
  proof=json.loads(proof_path.read_text());config=json.loads(config_path.read_text())
  need(config.get('status')=='configuration_equal_startup_verdict_still_required' and config.get('configured_credentials_equal_loaded') is True and config.get('different_environment_names')==[],'configuration_proof_required')
  need(proof.get('status')=='prestart_fastpath_pass' and proof.get('no_product_import') is True and proof.get('no_dependency_install') is True and proof.get('prestart_app_import_skipped') is True and proof.get('prestart_auto_fastpath_conditions_current') is True,'fastpath_proof_required')
  probe=ROOT/'deployment/prestart-fastpath-probe.py';classifier=ROOT/'deployment/classify-restart-config.py'
  need(proof.get('helper_sha256')==sha(probe) and proof.get('classifier_sha256')==sha(classifier) and proof.get('configuration_result_sha256')==sha(config_path),'fastpath_proof_version_mismatch')
  checks=proof.get('guarded_imports');need(isinstance(checks,list) and len(checks)==7 and all(row.get('ok') is True for row in checks),'seven_library_proofs_required')
  pins={};evidence=[]
  def pin(name,digest):
   need(isinstance(name,str) and Path(name).is_absolute() and isinstance(digest,str) and re.fullmatch('[0-9a-f]{64}',digest),'source_pin_format_invalid')
   if name==TARGET:return
   need(name not in pins or pins[name]==digest,'conflicting_source_evidence')
   path=Path(name);need(path.is_file() and not path.is_symlink() and sha(path)==digest,'reviewed_source_drift');pins[name]=digest
  for relative,count in SOURCES:
   path=ROOT/relative;within(path);data=json.loads(path.read_text());files=data.get('files')
   need(isinstance(files,list) and len(files)==count,'source_evidence_scope_mismatch')
   for row in files:need(not row.get('error_type'),'source_evidence_unreadable');pin(row['path'],row['sha256'])
   evidence.append({'path':relative,'sha256':sha(path)})
  for key in ['source_sha256','library_source_sha256']:
   mapping=proof.get(key);need(isinstance(mapping,dict) and mapping,'fastpath_source_pins_missing')
   for name,digest in mapping.items():pin(name,digest)
  # Exact reviewed wrapper; credential contents are not part of this source pin.
  pin('/usr/local/sbin/liveuin-ops-backend-with-dsn-credential','c4530a73cc60d4f3caa7c6d734b017cda6dbb0e34a2b12a27349136b75b5327b')
  evidence.extend([{'path':str(proof_path.relative_to(ROOT)),'sha256':sha(proof_path)},{'path':str(config_path.relative_to(ROOT)),'sha256':sha(config_path)}])
  scope='Bounded review of20 Ops entry/local modules,31 direct deployed modules, named Connect loader and marketing constructors/path getters, and unchanged candidate module-level startup. Current seven-library prestart fast-path proof uses reviewed execution identity/environment. No exhaustive recursive product-import guarantee or owner authentication proof is claimed.'
  verdict={'startup_import_review_passed':True,'reviewed_startup_paths_no_automatic_mail_or_customer_mutation':True,'candidate_startup_delta_unchanged':True,'prestart_no_dependency_install':True,'startup_review_scope':scope,'startup_probe_sha256':sha(probe),'startup_source_sha256':pins,'evidence_references':evidence,'automatic_database_restore':False}
  destination=ROOT/'deployment/startup-verdict-9095.json';need(not destination.exists(),'startup_verdict_already_exists')
  fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'w') as out:json.dump(verdict,out,indent=2);out.flush();os.fsync(out.fileno())
  result.update(status='root_private_bounded_startup_verdict_written',reviewed_source_count=len(pins),secret_values_output=False)
 except Exception as exc:result.update(status='stopped_no_verdict',failure_code=str(exc) if isinstance(exc,RuntimeError) else type(exc).__name__)
 print(json.dumps(result,indent=2));return 0 if result['status']=='root_private_bounded_startup_verdict_written' else 1
if __name__=='__main__':sys.exit(main())
