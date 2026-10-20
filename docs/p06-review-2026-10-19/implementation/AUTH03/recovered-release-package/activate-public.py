#!/usr/bin/env python3
"""Invoke only the pinned public-entry phase after the actual App browser gate."""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

ROOT = Path("/root/liveuin-auth03-frontend-20261020-01")
RELEASE_SHA = '599c047e4bc8650bae0556da7c98bfa354123a90d9f5143923f5a3ec93caaa19'
OUTPUT = Path("/tmp/liveuin-r01-access-check-20261020/frontend-auth03-public-activation-01.json")


def need(condition, code):
    if not condition:
        raise RuntimeError(code)


def private_gate():
    with os.fdopen(os.open(GATE, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
        info = os.fstat(handle.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0
             and stat.S_IMODE(info.st_mode) == 0o600, "root_private_gate_required")
        raw = handle.read(100_001)
    need(len(raw) <= 100_000 and hashlib.sha256(raw).hexdigest() == GATE_SHA,
         "browser_gate_changed")
    gate = json.loads(raw)
    need(gate["phase"] == "app_browser_pass", "browser_gate_phase_changed")
    return gate


def continuity(gate):
    for unit, expected in gate["continuity_services"].items():
        raw = subprocess.check_output([
            "systemctl", "show", unit, "--property=MainPID", "--property=ActiveState",
            "--property=NeedDaemonReload", "--property=ExecMainStartTimestampMonotonic"
        ], text=True, timeout=5)
        actual = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
        need(int(actual["MainPID"]) == expected["pid"]
             and actual["ExecMainStartTimestampMonotonic"] == expected["start_monotonic"]
             and actual["ActiveState"] == "active" and actual["NeedDaemonReload"] == "no",
             "backend_continuity_changed")
    for path, expected in gate["continuity_sources"].items():
        need(hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected,
             "reviewed_source_changed")


def safe_chain(exc, stop_class):
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


def origin_static_entry(m, events, url, expected, no_store=False):
    allowed = {
        "https://liveuin.com/index.html": "liveuin.com",
        "https://www.liveuin.com/index.html": "www.liveuin.com",
    }
    m.need(url in allowed and no_store is False, "unexpected_public_static_probe")
    host = allowed[url]
    # This proves the selected nginx origin, not Cloudflare or the browser journey.
    # URL host still controls SNI and normal certificate verification.
    with tempfile.TemporaryDirectory(prefix="auth02-origin-only-") as temp:
        body_path = Path(temp) / "entry.html"
        command = [
            "/usr/bin/curl", "-q", "--silent", "--show-error", "--noproxy", "*",
            "--proto", "=https", "--connect-timeout", "5", "--max-time", "15",
            "--max-filesize", "1048576", "--resolve", host + ":443:127.0.0.1",
            "--header", "Cache-Control: no-cache", "--output", str(body_path),
            "--write-out", "%{http_code}\n%{ssl_verify_result}\n%{remote_ip}\n%{num_redirects}\n%{url_effective}\n",
            url,
        ]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=20, check=False)
        m.need(result.returncode == 0, "origin_tls_transport_failed")
        m.need(len(result.stdout) <= 4096, "origin_transport_metadata_invalid")
        fields = result.stdout.decode("ascii", errors="strict").splitlines()
        m.need(len(fields) == 5, "origin_transport_metadata_invalid")
        http, ssl_result, remote, redirects, effective_url = fields
        m.need(http == "200" and ssl_result == "0" and remote == "127.0.0.1"
               and redirects == "0" and effective_url == url,
               "origin_http_tls_or_destination_mismatch")
        with body_path.open("rb") as stream:
            body = stream.read(1048577)
        m.need(len(body) <= 1048576, "origin_entry_too_large")
        actual = m.digest(body)
        events.append({"stage": "public_origin_static_entry", "verification_scope": "origin_only",
                       "url": url, "http": 200, "tls_certificate_verified": True,
                       "remote_ip": remote, "bytes": len(body), "sha256": actual,
                       "expected_sha256": expected})
        m.need(actual == expected, "served_entry_hash_mismatch")


def main():
    global GATE, GATE_SHA, STATE
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True)
    parser.add_argument("--gate", required=True)
    parser.add_argument("--gate-sha256", required=True)
    args = parser.parse_args()
    need(re.fullmatch(r"[0-9a-f]{64}", args.gate_sha256), "invalid_gate_hash")
    GATE, GATE_SHA, STATE = Path(args.gate), args.gate_sha256, args.state
    need(os.geteuid() == 0, "root_required")
    need(hashlib.sha256((ROOT / "release.py").read_bytes()).hexdigest() == RELEASE_SHA,
         "release_helper_changed")
    proof = private_gate()
    continuity(proof)
    spec = importlib.util.spec_from_file_location("reviewed_public_release", ROOT / "release.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    events = []
    original_activate, original_recover = m.public_activate, m.public_recover

    def public_activate(state, args):
        # Pinned release.main holds both cooperative locks at this point.
        continuity(private_gate())
        events.append({"stage": "locked_backend_continuity", "passed": True})
        return original_activate(state, args)

    def public_recover(state, state_path):
        events.append({"stage": "original_public_pointer_recovery", "status": "entered"})
        result = original_recover(state, state_path)
        events.append({"stage": "original_public_pointer_recovery", "status": "passed"})
        return result

    def static_entry(url, expected, no_store=False):
        return origin_static_entry(m, events, url, expected, no_store)

    m.public_activate = public_activate
    m.public_recover = public_recover
    m.static_entry = static_entry
    sys.argv = [str(ROOT / "release.py"), "public-activate", "--state", STATE,
                "--gate", str(GATE), "--gate-sha256", GATE_SHA]
    with os.fdopen(os.open(
            OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644), "w") as output:
        with contextlib.redirect_stdout(output):
            try:
                result = m.main()
                print(json.dumps({"result": result, "events": events,
                                  "normal_public_browser_handoff_still_required": True,
                                  "normal_browser_hosts_required": ["liveuin.com", "www.liveuin.com"],
                                  "automated_verification_scope": "origin_only",
                                  "public_access_or_payment_switch_changed": False}, indent=2))
                return 0
            except BaseException as exc:
                print(json.dumps({"status": "stopped", "events": events,
                                  "exceptions": safe_chain(exc, m.Stop),
                                  "no_auth_or_product_completion_claim": True}, indent=2))
                return 1


if __name__ == "__main__":
    raise SystemExit(main())
