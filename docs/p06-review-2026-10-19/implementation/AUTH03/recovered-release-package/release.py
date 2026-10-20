#!/usr/bin/env python3
"""AUTH03 browser Google unavailability; recover to the passed AUTH02 release."""
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent
SPEC_SHA = "aed2435048570988db4fb90c4def6e630f71645a2f88a80d44ee104fb514be56"


class Stop(Exception):
    pass


def need(condition, code):
    if not condition:
        raise Stop(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), "regular_file_required")
    return path.read_bytes()


def pin(path, expected):
    need(digest(regular(path)) == expected, "file_version_changed")


def inventory(root):
    root = Path(root)
    need(root.is_dir() and not root.is_symlink(), "regular_directory_required")
    result = {}
    for p in sorted(root.rglob("*")):
        need(not p.is_symlink(), "symlink_in_static_tree")
        if p.is_file():
            result[str(p.relative_to(root))] = digest(p.read_bytes())
        else:
            need(p.is_dir(), "special_file_in_static_tree")
    return result


def check_tree(root, expected):
    need(inventory(root) == expected, "static_tree_changed_or_incomplete")


def write_atomic(path, data, *, mode=0o600, owner=None):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + "-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        if owner:
            os.fchown(fd, *owner)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def private_json(path, expected_sha=None):
    p = Path(path)
    b = regular(p)
    st = p.stat()
    need(st.st_uid == 0 and not (st.st_mode & 0o077), "root_private_file_required")
    if expected_sha:
        need(digest(b) == expected_sha, "proof_hash_changed")
    return json.loads(b)


def state_load(path):
    state = private_json(path)
    need(state["release_id"] == S["release_id"] and state["spec_sha256"] == SPEC_SHA,
         "state_version_mismatch")
    return state


def state_save(path, state):
    write_atomic(path, (json.dumps(state, indent=2) + "\n").encode())


def unchanged():
    for path, expected in S["preserve_files"].items():
        pin(path, expected)


def pointer_is(target):
    p = Path(S["public_pointer"])
    return p.is_symlink() and p.resolve() == Path(target)


def public_expected():
    result = dict(S["public_baseline_files"])
    result["index.html"] = S["candidate_files"]["public-entry.html"]
    result.update({p: h for p, h in S["candidate_files"].items() if p.startswith("assets/")})
    need(len(result) == S["expected_public_file_count"], "public_manifest_count_mismatch")
    return result


def staged():
    asset_prefix = "assets/" + S["release_id"] + "/"
    assets = {p[len(asset_prefix):]: h for p, h in S["candidate_files"].items()
              if p.startswith(asset_prefix)}
    check_tree(Path(S["shared_root"]) / asset_prefix, assets)
    pin(Path(S["app_release"]) / "app-entry.html", S["candidate_files"]["app-entry.html"])
    check_tree(S["public_release"], public_expected())


def install_tree(destination, populate, expected):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        check_tree(destination, expected)
        return
    tmp = Path(tempfile.mkdtemp(prefix=".auth02-inert-", dir=destination.parent))
    try:
        populate(tmp)
        for p in [tmp, *tmp.rglob("*")]:
            need(not p.is_symlink(), "staged_symlink_forbidden")
            p.chmod(0o755 if p.is_dir() else 0o644)
        check_tree(tmp, expected)
        need(not destination.exists(), "new_release_destination_changed")
        os.rename(tmp, destination)
    finally:
        if tmp.exists():
            shutil.rmtree(tmp)


def stage():
    unchanged()
    pin(S["app_config"], S["app_baseline_sha256"])
    need(pointer_is(S["public_baseline_target"]), "public_pointer_changed")
    check_tree(S["public_baseline_target"], S["public_baseline_files"])
    check_tree(ROOT / "payload", S["candidate_files"])
    nginx_before = nginx_config()
    backup = Path("/root/liveuin-closeout-backups") / (
        "AUTH03-FRONTEND-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-" + str(os.getpid()))
    backup.mkdir(mode=0o700, parents=True)
    current = Path(S["app_config"])
    st = current.stat()
    write_atomic(backup / "app.before.conf", regular(current))
    state = {"release_id": S["release_id"], "spec_sha256": SPEC_SHA,
             "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
             "app_before_sha256": S["app_baseline_sha256"],
             "app_owner": [st.st_uid, st.st_gid], "app_mode": stat.S_IMODE(st.st_mode),
             "old_public_target": S["public_baseline_target"],
             "old_public_link": os.readlink(S["public_pointer"]),
             "nginx_before_sha256": digest(nginx_before),
             "app_activated": False, "public_activated": False}
    asset_prefix = "assets/" + S["release_id"] + "/"
    assets = {p[len(asset_prefix):]: h for p, h in S["candidate_files"].items()
              if p.startswith(asset_prefix)}
    install_tree(Path(S["shared_root"]) / asset_prefix,
                 lambda tmp: shutil.copytree(ROOT / "payload" / asset_prefix, tmp, dirs_exist_ok=True),
                 assets)
    install_tree(S["app_release"],
                 lambda tmp: shutil.copy2(ROOT / "payload/app-entry.html", tmp / "app-entry.html"),
                 {"app-entry.html": S["candidate_files"]["app-entry.html"]})

    def clone_public(tmp):
        shutil.copytree(S["public_baseline_target"], tmp, dirs_exist_ok=True)
        shutil.copytree(ROOT / "payload/assets", tmp / "assets", dirs_exist_ok=True)
        shutil.copy2(ROOT / "payload/public-entry.html", tmp / "index.html")

    install_tree(S["public_release"], clone_public, public_expected())
    unchanged()
    pin(S["app_config"], S["app_baseline_sha256"])
    need(pointer_is(S["public_baseline_target"]), "public_pointer_changed_during_stage")
    check_tree(S["public_baseline_target"], S["public_baseline_files"])
    need(nginx_config() == nginx_before, "nginx_configuration_changed_during_stage")
    state_save(backup / "state.json", state)
    return {"status": "inert_static_stage_complete", "state": str(backup / "state.json"),
            "active_configuration_or_pointer_changed": False}


def command(args, failure):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    need(result.returncode == 0, failure)
    return result.stdout


def nginx_config():
    # Includes the complete loaded configuration tree. Never print its contents.
    return command(["nginx", "-T"], "full_nginx_configuration_test_failed")


def reload_nginx():
    command(["systemctl", "reload", "nginx"], "nginx_reload_failed")


def app_edit(add):
    p = Path(S["app_config"])
    old = regular(p)
    st = p.stat()
    block = regular(ROOT / "app-alias.block")
    old_block = regular(ROOT / "app-old-alias.block")
    if add:
        need(digest(old) == S["app_baseline_sha256"], "app_baseline_changed")
        need(old.count(old_block) == 1 and block not in old, "app_alias_anchor_changed")
        new = old.replace(old_block, block, 1)
        need(digest(new) == S["app_activated_sha256"], "unexpected_app_diff")
    else:
        need(old.count(block) == 1, "exact_app_alias_not_found_for_recovery")
        new = old.replace(block, old_block, 1)
        need(S["app_release"].encode() not in new, "other_app_alias_reference_present")
    need(regular(p) == old, "app_changed_before_atomic_edit")
    write_atomic(p, new, mode=stat.S_IMODE(st.st_mode), owner=(st.st_uid, st.st_gid))
    return old, new


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def static_entry(url, expected, no_store=False):
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(urllib.request.Request(url, headers={"Cache-Control": "no-cache"}),
                     timeout=15) as response:
        body = response.read(1024 * 1024 + 1)
        need(response.status == 200 and digest(body) == expected, "served_entry_hash_mismatch")
        if no_store:
            need("no-store" in response.headers.get("Cache-Control", "").lower(),
                 "app_entry_cache_control_missing")


def gate(path, expected, phase, checks):
    need(path and expected, "explicit_hashed_proof_required")
    proof = private_json(path, expected)
    need(proof.get("phase") == phase
         and proof.get("candidate_manifest_sha256") == S["candidate_manifest_sha256"],
         "proof_phase_or_candidate_mismatch")
    need(all(proof.get(key) is True for key in checks), "proof_checks_incomplete")


def app_recover(state, state_path):
    before = regular(S["app_config"])
    block = regular(ROOT / "app-alias.block")
    old_block = regular(ROOT / "app-old-alias.block")
    unchanged()
    if block in before:
        _, restored = app_edit(False)
    else:
        need(S["app_release"].encode() not in before and before.count(old_block) == 1,
             "ambiguous_app_recovery")
        restored = before
    need(digest(nginx_config()) == state["nginx_before_sha256"],
         "other_nginx_drift_recovery_reload_refused")
    need(regular(S["app_config"]) == restored, "app_changed_before_recovery_reload")
    unchanged()
    reload_nginx()
    state["app_activated"] = False
    state["app_recovery"] = "prior_auth02_alias_restored_and_nginx_reloaded"
    state_save(state_path, state)
    return {"status": "app_alias_recovered", "browser_recovery_proof_required": True}


def app_activate(state, args):
    gate(args.gate, args.gate_sha256, "backend_ready_for_app",
         ["backend_candidate_verified", "pilot_admission_closed",
          "logout_revocation_proven", "approved_named_account_ready", "public_live_charging_off",
          "auth02_frozen", "google_browser_unavailable_approved"])
    unchanged()
    staged()
    need(pointer_is(state["old_public_target"]), "public_pointer_already_changed")
    before_all = nginx_config()
    need(digest(before_all) == state["nginx_before_sha256"],
         "nginx_configuration_changed_since_stage")
    try:
        old, new = app_edit(True)
        after_all = nginx_config()
        block = regular(ROOT / "app-alias.block")
        old_block = regular(ROOT / "app-old-alias.block")
        need(after_all.count(block) == 1 and after_all.replace(block, old_block, 1) == before_all,
             "other_nginx_configuration_changed")
        unchanged()
        need(regular(S["app_config"]) == new, "app_changed_before_reload")
        reload_nginx()
        static_entry("https://app.liveuin.com/index.html",
                     S["candidate_files"]["app-entry.html"], no_store=True)
        unchanged()
        state.update(app_activated=True, app_gate_sha256=args.gate_sha256)
        state_save(args.state, state)
        return {"status": "app_alias_active_browser_proof_required",
                "app_config_sha256": digest(new), "public_pointer_changed": False}
    except BaseException:
        app_recover(state, args.state)
        raise Stop("app_activation_failed_exact_alias_recovered")


def pointer_replace(target):
    pointer = Path(S["public_pointer"])
    tmp = pointer.with_name(pointer.name + ".auth02-" + str(os.getpid()))
    need(not tmp.exists() and not tmp.is_symlink(), "pointer_temporary_path_exists")
    try:
        os.symlink(target, tmp)
        os.replace(tmp, pointer)
        fd = os.open(pointer.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if tmp.is_symlink():
            tmp.unlink()


def public_recover(state, state_path):
    need(pointer_is(S["public_release"]) or pointer_is(state["old_public_target"]),
         "public_pointer_changed_by_other_work")
    check_tree(state["old_public_target"], S["public_baseline_files"])
    pointer_replace(state["old_public_link"])
    need(pointer_is(state["old_public_target"]), "public_pointer_recovery_failed")
    state["public_activated"] = False
    state_save(state_path, state)
    return {"status": "old_public_pointer_restored", "browser_recovery_proof_required": True}


def public_activate(state, args):
    gate(args.gate, args.gate_sha256, "app_browser_pass",
         ["wrong_password_refused", "named_account_signed_in", "canonical_profile_reload_passed",
          "allowed_screen_passed", "allowed_return_preserved", "wrong_role_refused", "both_logout_controls_passed",
          "stale_session_refused", "pilot_admission_closed", "public_live_charging_off",
          "google_notice_visible", "no_active_google_control"])
    need(state.get("app_activated") is True, "app_activation_not_recorded")
    unchanged()
    staged()
    pin(S["app_config"], S["app_activated_sha256"])
    config = nginx_config()
    block = regular(ROOT / "app-alias.block")
    old_block = regular(ROOT / "app-old-alias.block")
    need(config.count(block) == 1
         and digest(config.replace(block, old_block, 1)) == state["nginx_before_sha256"],
         "nginx_configuration_changed_since_app_proof")
    need(pointer_is(state["old_public_target"]), "public_pointer_changed")
    try:
        pointer_replace(S["public_release"])
        for host in ("liveuin.com", "www.liveuin.com"):
            static_entry("https://" + host + "/index.html",
                         S["candidate_files"]["public-entry.html"])
        unchanged()
        state.update(public_activated=True, app_browser_proof_sha256=args.gate_sha256)
        state_save(args.state, state)
        return {"status": "public_entry_active_browser_smoke_required",
                "public_access_or_payment_switch_changed": False}
    except BaseException:
        public_recover(state, args.state)
        raise Stop("public_activation_failed_old_pointer_restored")


def main():
    global S
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["stage", "app-activate", "app-recover",
                                         "public-activate", "public-recover"])
    parser.add_argument("--state")
    parser.add_argument("--gate")
    parser.add_argument("--gate-sha256")
    args = parser.parse_args()
    need(os.geteuid() == 0, "root_required")
    pin(ROOT / "release-spec.json", SPEC_SHA)
    S = json.loads(regular(ROOT / "release-spec.json"))
    pin(ROOT / "candidate-manifest.json", S["candidate_manifest_sha256"])
    pin(ROOT / "app-alias.block", S["app_alias_block_sha256"])
    pin(ROOT / "app-old-alias.block", S["app_old_alias_block_sha256"])
    def interrupted(signum, frame):
        raise Stop("interrupted")
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    with contextlib.ExitStack() as stack:
        for lock_path in ("/var/lock/liveuin-resident-core-api.lock",
                          "/var/lock/liveuin-auth02-frontend.lock"):
            lock = stack.enter_context(open(lock_path, "a"))
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.phase == "stage":
            return stage()
        need(args.state, "stage_state_required")
        state = state_load(args.state)
        if args.phase == "app-activate":
            return app_activate(state, args)
        if args.phase == "app-recover":
            return app_recover(state, args.state)
        if args.phase == "public-activate":
            return public_activate(state, args)
        return public_recover(state, args.state)


if __name__ == "__main__":
    try:
        print(json.dumps(main(), indent=2))
    except BaseException as exc:
        print(json.dumps({"status": "stopped", "reason": str(exc) if isinstance(exc, Stop)
                          else type(exc).__name__, "no_auth_or_product_completion_claim": True}))
        sys.exit(1)
