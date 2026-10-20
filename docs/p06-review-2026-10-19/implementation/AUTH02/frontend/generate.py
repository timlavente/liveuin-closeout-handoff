#!/usr/bin/env python3
"""Build only AUTH02, from a complete SHA-pinned deployed asset graph.

No npm build, network, source reconstruction, deployment or secret access.
Every original byte outside listed splice ranges remains unchanged.
Output namespace depends on the complete reviewed patch source and generator.
"""
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parent
MANIFEST_SHA = "3a72d117bbcf597dbc0087ce23c060ed14f99fbd1f9839a82a8b769e1800bc1d"
BOUNDARIES_SHA = "4fee8e5791cfc134bb01ec3c0091af49aaee6184d5ede654b27e93fdae90b698"
INDEX = "index-DPZwxwE9.js"
ALLOWED_CHANGED = {INDEX, "auth.sign-in-CQBkq3x9.js", "welcome-BD_1iI7g.js",
                   "AppAccount-HBgL4SnG.js", "ResidentAppShell-CQOxnRFw.js"}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def pinned(path, expected):
    data = path.read_bytes()
    if sha(data) != expected:
        raise RuntimeError(f"Pinned input hash mismatch: {path.name}")
    return data

def main():
    manifest = json.loads(pinned(ROOT / "baseline-manifest.json", MANIFEST_SHA))
    bounds = json.loads(pinned(ROOT / "baseline-boundaries.json", BOUNDARIES_SHA))
    expected_paths = {entry["path"] for entry in manifest}
    actual_paths = {str(p.relative_to(ROOT / "baseline")) for p in (ROOT / "baseline").rglob("*") if p.is_file()}
    if expected_paths != actual_paths:
        raise RuntimeError("Unexpected/missing baseline file")
    original = {}
    for entry in manifest:
        data = pinned(ROOT / "baseline" / entry["path"], entry["sha256"])
        if len(data) != entry["bytes"]:
            raise RuntimeError("Input length mismatch")
        original[entry["path"]] = data
    sources = {str(p.relative_to(ROOT)): p.read_bytes() for p in sorted((ROOT / "source").glob("*")) if p.is_file()}
    sources["generate.py"] = Path(__file__).read_bytes()
    source_hashes = {name: sha(data) for name, data in sources.items()}
    release_id = "auth02-" + sha(json.dumps({"baseline": MANIFEST_SHA, "sources": source_hashes}, sort_keys=True).encode())[:16]
    boundary_by_label = {item["label"]: item for item in bounds["files"][0]["spans"]}
    edits = {name: [] for name in ALLOWED_CHANGED}

    def span(label, replacement):
        item = boundary_by_label[label]
        start, end = item["byte_start"], item["byte_end"]
        data = original["assets/" + INDEX]
        if sha(data[start:end]) != item["sha256"] or data[start:end].decode() != item["source"]:
            raise RuntimeError("AST boundary does not match: " + label)
        edits[INDEX].append((start, end, replacement.encode(), label))

    span("Rj", sources["source/auth02-runtime.js"].decode().rstrip())
    span("qx", sources["source/bootstrap.js"].decode().rstrip())
    span("ZR", sources["source/entry-routes.js"].decode().rstrip())
    span("lA", sources["source/signin-entry.js"].decode().rstrip())
    span("mk", 'mk=function(e){return new URL(e.replace(/^assets\\//,""),import.meta.url).href}')
    extra_exports = '\nexport{auth02LogoutFromControl,auth02LoginHref,auth02HasLogoutLock};\n'
    edits[INDEX].append((len(original["assets/"+INDEX]), len(original["assets/"+INDEX]), extra_exports.encode(), "explicit-auth02-exports"))
    for item in json.loads(sources["source/ui-edits.json"]):
        name, needle = item["file"], item["old"].encode()
        if name not in ALLOWED_CHANGED:
            raise RuntimeError("Unapproved file edit")
        data = original["assets/" + name]
        if data.count(needle) != item["count"]:
            raise RuntimeError("Absent or duplicated anchor: " + item["label"])
        cursor = 0
        for number in range(item["count"]):
            start = data.index(needle, cursor)
            edits[name].append((start, start + len(needle), item["new"].encode(), item["label"] + f"-{number+1}"))
            cursor = start + len(needle)
    for name, symbol in [("AppAccount-HBgL4SnG.js", "auth02LogoutFromControl"),
                         ("ResidentAppShell-CQOxnRFw.js", "auth02LogoutFromControl"),
                         ("auth.sign-in-CQBkq3x9.js", "auth02HasLogoutLock,auth02LogoutFromControl"),
                         ("welcome-BD_1iI7g.js", "auth02LoginHref")]:
        edits[name].append((0, 0, f'import{{{symbol}}}from"./{INDEX}";\n'.encode(), "auth02-helper-import"))

    changed = {}
    audit = []
    for name, ranges in sorted(edits.items()):
        data = original["assets/" + name]
        cursor, chunks = 0, []
        for start, end, replacement, label in sorted(ranges):
            if start < cursor or end < start:
                raise RuntimeError("Overlapping splice")
            chunks.append(data[cursor:start])
            chunks.append(replacement)
            audit.append({"file": name, "label": label, "old_start": start, "old_end": end,
                          "old_sha256": sha(data[start:end]), "new_sha256": sha(replacement),
                          "unchanged_before_sha256": sha(data[cursor:start])})
            cursor = end
        chunks.append(data[cursor:])
        changed[name] = b"".join(chunks)
    # HTML is otherwise unchanged. Do not copy .well-known or replace shared App/Partner index.
    html = original["index.html"]
    for old in [f'/assets/{INDEX}', '/assets/index-X00jwp5b.css']:
        needle = old.encode()
        if html.count(needle) != 1:
            raise RuntimeError("HTML entry anchor mismatch")
        html = html.replace(needle, old.replace('/assets/', '/assets/' + release_id + '/').encode())
    out = ROOT / "candidate"
    if out.exists():
        shutil.rmtree(out)
    asset_out = out / "assets" / release_id
    asset_out.mkdir(parents=True)
    output_manifest = []
    for name, data in sorted(original.items()):
        if not name.startswith("assets/"):
            continue
        relative = name.removeprefix("assets/")
        result = changed.get(relative, data)
        target = asset_out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(result)
        output_manifest.append({"path": str(target.relative_to(out)), "bytes": len(result), "sha256": sha(result),
                                "baseline_path": name, "baseline_sha256": sha(data), "changed": result != data})
    for name in ["public-entry.html", "app-entry.html"]:
        (out / name).write_bytes(html)
        output_manifest.append({"path": name, "bytes": len(html), "sha256": sha(html), "baseline_path": "index.html", "baseline_sha256": sha(original["index.html"]), "changed": True})
    if {Path(item["path"]).name for item in output_manifest if item["changed"] and item["path"].endswith(".js")} != ALLOWED_CHANGED:
        raise RuntimeError("Unexpected changed JavaScript set")
    result = {"release_id": release_id, "baseline_manifest_sha256": MANIFEST_SHA,
              "source_sha256": source_hashes, "splices": audit, "files": output_manifest,
              "status": "LOCAL CANDIDATE ONLY; no production/account/payment changes or proof claim"}
    (ROOT / "candidate-manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"release_id": release_id, "files": len(output_manifest), "changed_js": sorted(ALLOWED_CHANGED), "manifest_sha256": sha((ROOT / 'candidate-manifest.json').read_bytes())}))

if __name__ == "__main__":
    main()
