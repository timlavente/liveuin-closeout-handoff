from pathlib import Path
import hashlib,tarfile,os,stat,json
archive=Path('/tmp/liveuin-r01-access-check-20261020/auth02-9095-reviewed-07.tar')
expected='c80640af3068dba06656238125674ea7bf86f4b48d311c55b42ed240a4e2df09'
expected_manifest='8019023d6f981118c622fb9ee6839e29480b8b9fcd183078838f3b119336fc86'
assert os.geteuid()==0
assert archive.is_file() and not archive.is_symlink()
assert hashlib.sha256(archive.read_bytes()).hexdigest()==expected
root=Path('/root/liveuin-auth02-9095-20261020-07')
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
