#!/usr/bin/env python3
"""Local-only, temporary-files and mocks. Does not call main or server commands."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
module_spec = importlib.util.spec_from_file_location("release11", HERE / "release.py")
m = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(m)
original_spec = json.loads((HERE / "release-spec.json").read_bytes())
results = []


def check(name, fn):
    fn()
    results.append({"name": name, "passed": True})


def expect_stop(fn, code):
    try:
        fn()
    except m.Stop as exc:
        assert str(exc) == code, (str(exc), code)
    else:
        raise AssertionError("expected stop")


check("source compiles without executing main",
      lambda: compile(ast.parse((HERE / "release.py").read_text()), "release.py", "exec"))
check("spec and manifest pins",
      lambda: (m.pin(HERE / "release-spec.json", m.SPEC_SHA),
               m.pin(HERE / "candidate-manifest.json",
                     original_spec["candidate_manifest_sha256"])))
check("exact 364 candidate artifacts",
      lambda: m.check_tree(HERE / "payload", original_spec["candidate_files"]))
assert len(original_spec["candidate_files"]) == 364

with tempfile.TemporaryDirectory(prefix="auth02-release09-check-") as temp:
    t = Path(temp).resolve()
    config = t / "app.conf"
    baseline = (HERE / "app-before.conf").read_bytes()
    block = (HERE / "app-alias.block").read_bytes()
    old_block = (HERE / "app-old-alias.block").read_bytes()
    original = dict(original_spec)
    original["app_config"] = str(config)
    m.S = original
    config.write_bytes(baseline)
    config.chmod(0o640)
    nginx_prefix = b"# full nginx fixture\n"
    state = {"nginx_before_sha256": m.digest(nginx_prefix + baseline),
             "old_public_target": "/old", "app_activated": False}
    args = SimpleNamespace(state=str(t / "state.json"), gate="fixture", gate_sha256="fixture")
    checks = {"reloads": 0, "other": b""}

    def nginx():
        return nginx_prefix + config.read_bytes() + checks["other"]

    def reload():
        checks["reloads"] += 1

    def reset():
        config.write_bytes(baseline)
        config.chmod(0o640)
        checks.update(reloads=0, other=b"")
        state["app_activated"] = False

    with patch.object(m, "nginx_config", nginx), \
         patch.object(m, "reload_nginx", reload), \
         patch.object(m, "unchanged", lambda: None), \
         patch.object(m, "staged", lambda: None), \
         patch.object(m, "pointer_is", lambda target: True), \
         patch.object(m, "gate", lambda *a: None), \
         patch.object(m, "static_entry", lambda *a, **kw: None), \
         patch.object(m, "state_save", lambda *a: None):
        def success():
            reset()
            result = m.app_activate(state, args)
            assert result["status"] == "app_alias_active_browser_proof_required"
            assert config.read_bytes().replace(block, old_block, 1) == baseline
            assert config.stat().st_mode & 0o777 == 0o640
            assert checks["reloads"] == 1
        check("current App alias replaced exactly; mobile additions and mode retained", success)

        def recover():
            result = m.app_recover(state, args.state)
            assert config.read_bytes() == baseline
            assert result["browser_recovery_proof_required"] is True
            assert checks["reloads"] == 2
        check("App explicit recovery restores the prior AUTH02 alias", recover)

        def other_drift():
            reset()
            checks["other"] = b"# changed other vhost\n"
            expect_stop(lambda: m.app_activate(state, args),
                        "nginx_configuration_changed_since_stage")
            assert config.read_bytes() == baseline and checks["reloads"] == 0
        check("other nginx drift stops before mutation", other_drift)

        def smoke_failure():
            reset()
            with patch.object(m, "static_entry",
                              side_effect=m.Stop("served_entry_hash_mismatch")):
                expect_stop(lambda: m.app_activate(state, args),
                            "app_activation_failed_exact_alias_recovered")
            assert config.read_bytes() == baseline and checks["reloads"] == 2
        check("failed App static smoke restores prior AUTH02 alias and reloads baseline", smoke_failure)

        def syntax_failure():
            reset()
            def syntax_check():
                if block in config.read_bytes():
                    raise m.Stop("full_nginx_configuration_test_failed")
                return nginx()
            with patch.object(m, "nginx_config", syntax_check):
                expect_stop(lambda: m.app_activate(state, args),
                            "app_activation_failed_exact_alias_recovered")
            assert config.read_bytes() == baseline and checks["reloads"] == 1
        check("post-edit nginx syntax failure restores prior alias before testing recovery",
              syntax_failure)

        def after_write_failure():
            reset()
            original_write = m.write_atomic
            calls = 0
            def write(path, data, **kw):
                nonlocal calls
                calls += 1
                original_write(path, data, **kw)
                if calls == 1:
                    raise OSError("simulated post-replace fsync failure")
            with patch.object(m, "write_atomic", write):
                expect_stop(lambda: m.app_activate(state, args),
                            "app_activation_failed_exact_alias_recovered")
            assert config.read_bytes() == baseline and checks["reloads"] == 1
        check("failure after first atomic write still recovers", after_write_failure)

        def recovery_drift():
            reset()
            m.app_edit(True)
            changed = config.read_bytes()
            checks["other"] = b"# unreviewed other vhost\n"
            expect_stop(lambda: m.app_recover(state, args.state),
                        "other_nginx_drift_recovery_reload_refused")
            assert config.read_bytes() == baseline and checks["reloads"] == 0
        check("recovery never reloads unrelated changed config", recovery_drift)

    old_root = t / "old"
    new_root = t / "new"
    old_root.mkdir()
    new_root.mkdir()
    (old_root / "index.html").write_bytes(b"old")
    link = t / "current"
    link.symlink_to(old_root)
    m.S.update(public_pointer=str(link), public_release=str(new_root),
               public_baseline_files={"index.html": m.digest(b"old")})
    public_state = {"old_public_target": str(old_root), "old_public_link": str(old_root),
                    "public_activated": False, "app_activated": True,
                    "nginx_before_sha256": state["nginx_before_sha256"]}
    def pointer_roundtrip():
        m.pointer_replace(str(new_root))
        assert link.resolve() == new_root
        with patch.object(m, "state_save", lambda *a: None):
            m.public_recover(public_state, args.state)
        assert link.resolve() == old_root
    check("atomic public pointer and exact original restoration", pointer_roundtrip)

    def third_party_pointer():
        link.unlink()
        other = t / "other"
        other.mkdir()
        link.symlink_to(other)
        expect_stop(lambda: m.public_recover(public_state, args.state),
                    "public_pointer_changed_by_other_work")
        assert link.resolve() == other
    check("public recovery refuses someone else's pointer", third_party_pointer)

with patch.object(m, "private_json", return_value={
        "phase": "app_browser_pass",
        "candidate_manifest_sha256": original_spec["candidate_manifest_sha256"],
        "named_account_signed_in": False}):
    m.S = original_spec
    check("incomplete browser proof cannot activate public pointer",
          lambda: expect_stop(lambda: m.gate("proof", "sha", "app_browser_pass",
                                            ["named_account_signed_in"]),
                              "proof_checks_incomplete"))

output = {"status": "local_mock_checks_passed", "checks": len(results),
          "release_script_sha256": hashlib.sha256((HERE / "release.py").read_bytes()).hexdigest(),
          "production_execution": False, "tests": results}
(HERE / "local-checks.json").write_text(json.dumps(output, indent=2) + "\n")
print(json.dumps({k: v for k, v in output.items() if k != "tests"}, indent=2))
