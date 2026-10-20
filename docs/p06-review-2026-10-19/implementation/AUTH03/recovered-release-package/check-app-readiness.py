"""Local fixtures: no production execution, network or product modules."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import signal
import socket
import ssl
from types import SimpleNamespace
import urllib.error
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
source = HERE / "activate-app.py"
spec = importlib.util.spec_from_file_location("app_readiness", source)
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)
checks = []
OLD, NEW, OTHER = b"old reviewed entry", b"new reviewed entry", b"unexpected entry"
sha = lambda body: hashlib.sha256(body).hexdigest()


class Stop(Exception):
    pass


def need(condition, code):
    if not condition:
        raise Stop(code)


def run(sequence, *, no_store=True, http=200, config_drift=False, slow=0):
    clock, requests, events, handlers, timers = [0.0], [], [], {}, []
    m = SimpleNamespace(
        Stop=Stop, need=need, digest=sha, NoRedirect=d.urllib.request.HTTPRedirectHandler,
        command=lambda *args: b"private config", app_edit=lambda add: (b"old", b"new"),
        app_recover=lambda *args: {"recovered": True}, app_activate=lambda *args: {"activated": True},
        unchanged=lambda: None, regular=lambda path: b"config",
        S={"candidate_files": {"app-entry.html": sha(NEW)},
           "prior_app_entry_sha256": sha(OLD),
           "app_config": "fixture", "app_activated_sha256": sha(b"bad" if config_drift else b"config")},
    )
    body_sequence = iter(sequence)
    class Response:
        status = http
        headers = {"Cache-Control": "no-store"} if no_store else {}
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self, count):
            assert count == 1048577
            clock[0] += slow
            return self.body
    class Opener:
        def open(self, request, timeout):
            requests.append((request, timeout))
            assert 0 < timeout <= 2.0
            current = next(body_sequence)
            if isinstance(current, BaseException):
                raise current
            r = Response()
            r.body = current
            return r
    def set_handler(sig, handler):
        previous = handlers.get(sig, signal.SIG_DFL)
        handlers[sig] = handler
        return previous
    def set_timer(kind, value):
        timers.append(value)
        return (0.0, 0.0)
    d.instrument(m, events)
    failure = None
    with patch.object(d, "OLD_ENTRY_SHA", sha(OLD)), \
         patch.object(d.time, "monotonic", side_effect=lambda: clock[0]), \
         patch.object(d.time, "sleep", side_effect=lambda secs: clock.__setitem__(0, clock[0] + secs)), \
         patch.object(d.signal, "getitimer", return_value=(0.0, 0.0)), \
         patch.object(d.signal, "getsignal", return_value=signal.SIG_DFL), \
         patch.object(d.signal, "signal", side_effect=set_handler), \
         patch.object(d.signal, "setitimer", side_effect=set_timer), \
         patch.object(d.urllib.request, "build_opener", return_value=Opener()):
        try:
            m.static_entry("https://app.liveuin.com/index.html", sha(NEW), no_store=True)
        except BaseException as exc:
            failure = exc
    assert timers == [8.0, 0.0]
    assert handlers[signal.SIGALRM] == signal.SIG_DFL
    assert all("reviewed entry" not in json.dumps(e) for e in events)
    return failure, requests, events, clock[0], m


with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")):
    compile(ast.parse(source.read_text()), str(source), "exec")
    assert sha((HERE / "release.py").read_bytes()) == d.RELEASE_SHA
    checks.append("source_compiles_and_original_helper_unchanged")

    failure, requests, events, elapsed, _ = run([OLD, OLD, NEW])
    assert failure is None and len(requests) == 3 and elapsed == 0.5
    checks.append("only_exact_old_entry_retries_then_new_hash_and_no_store_pass")

    failure, requests, events, elapsed, _ = run([OLD] * 40)
    assert str(failure) == "app_entry_old_baseline_readiness_timeout" and elapsed == 8.0
    assert len(requests) == 32
    checks.append("persistent_old_entry_stops_at_eight_seconds")

    for sequence, http, no_store, expected in [
        ([OTHER], 200, True, "served_entry_hash_mismatch"),
        ([NEW], 403, True, "served_entry_http_not_ok"),
        ([NEW], 200, False, "app_entry_cache_control_missing"),
    ]:
        failure, requests, *_ = run(sequence, http=http, no_store=no_store)
        assert str(failure) == expected and len(requests) == 1
    checks.append("unexpected_body_status_or_missing_no_store_fails_immediately")

    for error in [
        urllib.error.HTTPError("PRIVATE", 302, "PRIVATE", {}, None),
        urllib.error.HTTPError("PRIVATE", 500, "PRIVATE", {}, None),
        urllib.error.URLError(ssl.SSLCertVerificationError("PRIVATE")),
    ]:
        failure, requests, *_ = run([error])
        assert failure is error and len(requests) == 1
    checks.append("redirect_http_error_and_tls_failure_never_retry")

    failure, requests, *_ = run([NEW], config_drift=True)
    assert str(failure) == "app_changed_during_readiness" and not requests
    checks.append("changed_alias_configuration_stops_before_request")

    failure, requests, *_ = run([NEW], slow=9)
    assert str(failure) == "app_entry_readiness_deadline_exceeded"
    checks.append("late_expected_response_cannot_pass")

    try:
        try:
            raise urllib.error.HTTPError("PRIVATE_URL", 403, "PRIVATE_BODY", {}, None)
        except Exception:
            raise Stop("app_activation_failed_exact_alias_recovered")
    except Exception as exc:
        chain = d.safe_chain(exc, Stop)
    assert chain == [
        {"type": "Stop", "reason": "app_activation_failed_exact_alias_recovered"},
        {"type": "HTTPError", "http": 403},
    ]
    assert "PRIVATE" not in json.dumps(chain)
    checks.append("exception_context_preserved_without_urls_bodies_or_config")

    _, _, _, _, m = run([NEW])
    assert m.app_recover(None, None) == {"recovered": True}
    with patch.object(d, "current_backend_pins"):
        assert m.app_activate(None, None) == {"activated": True}
    checks.append("original_activation_and_recovery_still_called")

    # Verify the real timer interrupts a stalled read before the wrapper returns.
    m = SimpleNamespace(
        Stop=Stop, need=need, digest=sha, NoRedirect=lambda: None,
        command=lambda *a: b"", app_edit=lambda *a: None, app_recover=lambda *a: None,
        app_activate=lambda *a: None, unchanged=lambda: None, regular=lambda *a: b"config",
        S={"candidate_files": {"app-entry.html": sha(NEW)},
           "prior_app_entry_sha256": sha(OLD),
           "app_config": "fixture", "app_activated_sha256": sha(b"config")},
    )
    class Stalled:
        def open(self, *args, **kwargs):
            d.time.sleep(2)
            raise AssertionError("alarm did not interrupt stalled request")
    d.instrument(m, [])
    prior = signal.getsignal(signal.SIGALRM)
    with patch.object(d, "OLD_ENTRY_SHA", sha(OLD)), patch.object(d, "READINESS_SECONDS", 0.02), \
         patch.object(d.urllib.request, "build_opener", return_value=Stalled()):
        try:
            m.static_entry("https://app.liveuin.com/index.html", sha(NEW), no_store=True)
        except Stop as exc:
            assert str(exc) == "app_entry_readiness_deadline_exceeded"
        else:
            raise AssertionError("expected hard deadline")
    assert signal.getsignal(signal.SIGALRM) == prior
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    checks.append("real_alarm_interrupts_stalled_request_and_restores_handler")

report = {"status": "isolated_checks_passed", "checks": len(checks), "tests": checks,
          "wrapper_sha256": sha(source.read_bytes()), "release_sha256": d.RELEASE_SHA,
          "production_execution": False, "network_blocked": True,
          "readiness_limit_seconds": 8, "retry_only_exact_reviewed_old_hash": True}
(HERE / "app-readiness-local-checks.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
