from pathlib import Path
import hashlib,tarfile,os,stat,json
archive=Path('/tmp/liveuin-r01-access-check-20261020/auth02-9095-reviewed-06.tar')
expected='7f98821882455a05266f24957e15040f8492a2e9b25761248abc5953582180ca'
expected_manifest='58cd328054a8dff231370a5ea0e73129db25722d887f891afe1637ba67a89c2e'
assert os.geteuid()==0
assert archive.is_file() and not archive.is_symlink()
assert hashlib.sha256(archive.read_bytes()).hexdigest()==expected
root=Path('/root/liveuin-auth02-9095-20261020-06')
assert not root.exists()
root.mkdir(mode=0o700)
with tarfile.open(archive) as tf:
 members=tf.getmembers();names=set()
 for m in members:
  p=Path(m.name);assert m.isfile() and not p.is_absolute() and '..' not in p.parts and m.name not in names
  names.add(m.name);out=root/p;out.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
  with out.open('xb') as f:f.write(tf.extractfile(m).read())
  os.chmod(out,0o600)
manifest_path=root/'deployment/package-manifest-9095.json'
assert hashlib.sha256(manifest_path.read_bytes()).hexdigest()==expected_manifest
manifest=json.loads(manifest_path.read_text())
assert names=={row['path'] for row in manifest['files']}|{'deployment/package-manifest-9095.json'}
for row in manifest['files']:assert hashlib.sha256((root/row['path']).read_bytes()).hexdigest()==row['sha256']
print(json.dumps({'private_package_staged':str(root),'files_verified':len(manifest['files']),'production_changed':False}))
