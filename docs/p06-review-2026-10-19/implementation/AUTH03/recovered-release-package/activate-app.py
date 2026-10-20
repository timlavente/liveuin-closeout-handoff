#!/usr/bin/env python3
"""One App activation attempt; retry only a proven old entry during reload readiness."""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path("/root/liveuin-auth03-frontend-20261020-01")
RELEASE_SHA = "599c047e4bc8650bae0556da7c98bfa354123a90d9f5143923f5a3ec93caaa19"
OUTPUT = Path("/tmp/liveuin-r01-access-check-20261020/frontend-auth03-app-activation-01.json")
PROVIDER = Path("/opt/liveuin/deploy/core_customer_card_provider.py")
OLD_ENTRY_SHA = "d64151e0728796b61d396cb8c38d00f7bd8dc9c563975b42aa5caad86b02e268"
READINESS_SECONDS = 8.0
PROVIDER_SHA = "a2034f5d0990719d39cbf378c92a87e7b72011b31a99483ccb75cecab06ba2dc"


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def current_backend_pins():
    gate = BACKEND_PROOF
    for unit, expected in gate["continuity_services"].items():
        raw = subprocess.check_output([
            "systemctl", "show", unit, "--property=MainPID", "--property=ActiveState",
            "--property=NeedDaemonReload", "--property=ExecMainStartTimestampMonotonic"
        ], text=True, timeout=5)
        actual = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
        require(int(actual["MainPID"]) == expected["pid"]
             and actual["ExecMainStartTimestampMonotonic"] == expected["start_monotonic"]
             and actual["ActiveState"] == "active" and actual["NeedDaemonReload"] == "no",
             "backend_continuity_changed")
    for path, expected in gate["continuity_sources"].items():
        require(hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected,
             "reviewed_source_changed")


def safe_chain(exc, stop_class):
    """Never expose exception messages, URLs, command output or response bodies."""
    rows, seen = [], set()
    while exc is not None and id(exc) not in seen and len(rows) < 8:
        seen.add(id(exc))
        row = {"type": type(exc).__name__}
        if isinstance(exc, stop_class) and re.fullmatch(r"[a-z_]{1,100}", str(exc)):
            row["reason"] = str(exc)
        if isinstance(exc, urllib.error.HTTPError):
            row["http"] = int(exc.code)
        rows.append(row)
        exc = exc.__cause__ or exc.__context__
    return rows


def instrument(m, events):
    """Observe existing operations; preserve rollback and each success criterion."""
    phase = ["activation"]
    original_app_activate = m.app_activate
    original_app_recover = m.app_recover
    original_command = m.command
    original_app_edit = m.app_edit

    def record(stage, status, **safe):
        events.append({"phase": phase[0], "stage": stage, "status": status, **safe})

    def observed(stage, call):
        record(stage, "entered")
        try:
            result = call()
        except BaseException as exc:
            record(stage, "failed", exceptions=safe_chain(exc, m.Stop))
            raise
        record(stage, "passed")
        return result

    def command(args, failure):
        label = {
            ("nginx", "-T"): "full_nginx_configuration_test",
            ("systemctl", "reload", "nginx"): "nginx_reload",
        }.get(tuple(args), "reviewed_command")
        return observed(label, lambda: original_command(args, failure))

    def app_edit(add):
        return observed("add_exact_app_alias" if add else "remove_exact_app_alias",
                        lambda: original_app_edit(add))

    def app_recover(state, state_path):
        phase[0] = "recovery"
        return observed("exact_alias_recovery", lambda: original_app_recover(state, state_path))

    def static_entry(url, expected, no_store=False):
        # Only exact old entry bytes may wait for the reload to become visible.
        m.need(url == "https://app.liveuin.com/index.html", "unexpected_static_probe_url")
        m.need(expected == m.S["candidate_files"]["app-entry.html"] and no_store is True,
               "unexpected_static_probe_expectation")
        m.need(m.S["prior_app_entry_sha256"] == OLD_ENTRY_SHA,
               "old_static_entry_pin_changed")
        record("static_entry", "entered")
        deadline = time.monotonic() + READINESS_SECONDS
        attempts = 0
        m.need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
               "unexpected_existing_readiness_timer")
        prior_alarm_handler = signal.getsignal(signal.SIGALRM)
        def deadline_alarm(signum, frame):
            raise m.Stop("app_entry_readiness_deadline_exceeded")
        signal.signal(signal.SIGALRM, deadline_alarm)
        signal.setitimer(signal.ITIMER_REAL, READINESS_SECONDS)
        try:
            while True:
                remaining = deadline - time.monotonic()
                m.need(remaining > 0, "app_entry_old_baseline_readiness_timeout")
                # Revalidate the existing boundaries before every request.
                m.unchanged()
                m.need(m.digest(m.regular(m.S["app_config"])) == m.S["app_activated_sha256"],
                       "app_changed_during_readiness")
                remaining = deadline - time.monotonic()
                m.need(remaining > 0, "app_entry_old_baseline_readiness_timeout")
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}), m.NoRedirect)
                with opener.open(urllib.request.Request(
                        url, headers={"Cache-Control": "no-cache", "Connection": "close"}),
                        timeout=min(2.0, remaining)) as response:
                    body = response.read(1024 * 1024 + 1)
                    actual = m.digest(body)
                    no_store_seen = "no-store" in response.headers.get("Cache-Control", "").lower()
                    attempts += 1
                    record("static_entry", "observed",
                           attempt=attempts, http=int(response.status), bytes=len(body), sha256=actual,
                           expected_sha256=expected, no_store=no_store_seen,
                           old_baseline=actual == OLD_ENTRY_SHA)
                    m.need(response.status == 200, "served_entry_http_not_ok")
                    if actual == expected:
                        m.need(no_store_seen, "app_entry_cache_control_missing")
                        m.unchanged()
                        m.need(m.digest(m.regular(m.S["app_config"])) == m.S["app_activated_sha256"],
                               "app_changed_during_readiness")
                        m.need(time.monotonic() <= deadline, "app_entry_readiness_deadline_exceeded")
                        break
                    m.need(actual == OLD_ENTRY_SHA, "served_entry_hash_mismatch")
                remaining = deadline - time.monotonic()
                m.need(remaining > 0, "app_entry_old_baseline_readiness_timeout")
                time.sleep(min(0.25, remaining))
        except BaseException as exc:
            record("static_entry", "failed", exceptions=safe_chain(exc, m.Stop))
            raise
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
            signal.signal(signal.SIGALRM, prior_alarm_handler)
        record("static_entry", "passed")

    def app_activate(state, args):
        # Called by pinned release.main after both cooperative locks are held.
        observed("locked_backend_pins", current_backend_pins)
        return observed("app_activation", lambda: original_app_activate(state, args))

    m.command = command
    m.app_edit = app_edit
    m.app_recover = app_recover
    m.static_entry = static_entry
    m.app_activate = app_activate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--gate-sha256", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{64}", args.gate_sha256), "invalid_gate_hash")
    require(os.geteuid() == 0, "root_required")
    require(hashlib.sha256((ROOT / "release.py").read_bytes()).hexdigest() == RELEASE_SHA,
            "release_helper_changed")
    with os.fdopen(os.open(args.gate, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
        info = os.fstat(handle.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and stat.S_IMODE(info.st_mode) == 0o600, "root_private_gate_required")
        raw = handle.read(100_001)
    require(len(raw) <= 100_000 and hashlib.sha256(raw).hexdigest() == args.gate_sha256,
            "backend_gate_changed")
    global BACKEND_PROOF
    proof = json.loads(raw)
    BACKEND_PROOF = proof
    current_backend_pins()
    require(proof["phase"] == "backend_ready_for_app", "wrong_gate_phase")
    require(all(proof[k] is True for k in [
        "backend_candidate_verified", "pilot_admission_closed", "logout_revocation_proven",
        "approved_named_account_ready", "public_live_charging_off",
        "auth02_frozen", "google_browser_unavailable_approved",
    ]), "backend_proof_incomplete")
    spec = importlib.util.spec_from_file_location("reviewed_frontend_release", ROOT / "release.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    events = []
    instrument(m, events)
    sys.argv = [str(ROOT / "release.py"), "app-activate", "--state", args.state,
                "--gate", args.gate, "--gate-sha256", args.gate_sha256]
    with os.fdopen(os.open(
            OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644), "w") as output:
        with contextlib.redirect_stdout(output):
            try:
                result = m.main()
                print(json.dumps({"result": result, "events": events,
                                  "no_auth_or_product_completion_claim": True}, indent=2))
                return 0
            except BaseException as exc:
                print(json.dumps({"status": "stopped", "exceptions": safe_chain(exc, m.Stop),
                                  "events": events,
                                  "no_auth_or_product_completion_claim": True}, indent=2))
                return 1


if __name__ == "__main__":
    raise SystemExit(main())
