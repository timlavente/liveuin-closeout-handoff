"""Finite local-only deterministic replay and rejection checks."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parent.parent
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
before = digest(root / "candidate-manifest.json")
subprocess.run([sys.executable, str(root / "generate.py")], check=True, capture_output=True)
after = digest(root / "candidate-manifest.json")
assert before == after, "Non-deterministic candidate output"
checks = ["byte-identical repeat generation"]
for variant in ["manifest-tamper", "baseline-tamper", "anchor-mismatch"]:
    with tempfile.TemporaryDirectory(prefix="auth02-rejection-") as temporary:
        case = Path(temporary)
        for name in ["generate.py", "baseline-manifest.json", "baseline-boundaries.json"]:
            shutil.copy2(root / name, case / name)
        shutil.copytree(root / "baseline", case / "baseline")
        shutil.copytree(root / "source", case / "source")
        if variant == "manifest-tamper":
            p = case / "baseline-manifest.json"
            p.write_bytes(p.read_bytes() + b" ")
        elif variant == "baseline-tamper":
            p = case / "baseline/assets/index-DPZwxwE9.js"
            p.write_bytes(p.read_bytes() + b"\n")
        else:
            p = case / "source/ui-edits.json"
            edits = json.loads(p.read_text())
            edits[0]["old"] = "not-an-existing-anchor"
            p.write_text(json.dumps(edits))
        result = subprocess.run([sys.executable, str(case / "generate.py")], capture_output=True)
        assert result.returncode != 0, variant
        assert not (case / "candidate").exists(), "Rejection happened after output mutation"
        checks.append(variant + " rejected before output write")
assert digest(root / "candidate-manifest.json") == before
result = {"status": "pass", "manifest_sha256": before, "checks": checks}
(root / "tests/reproducibility-results.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result))
