from pathlib import Path
import hashlib,tarfile,os,stat,json
archive=Path('/tmp/liveuin-r01-access-check-20261020/auth02-9095-reviewed-08.tar')
expected='1fe1bf8f4e310f8a66577115001fab17d62d2ec4b9fde1199733e524942e869d'
expected_manifest='403e97cbc90893402427dfd304358271d619c23babb452a1a20ff2f33aece21b'
assert os.geteuid()==0
assert archive.is_file() and not archive.is_symlink()
assert hashlib.sha256(archive.read_bytes()).hexdigest()==expected
root=Path('/root/liveuin-auth02-9095-20261020-08')
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
