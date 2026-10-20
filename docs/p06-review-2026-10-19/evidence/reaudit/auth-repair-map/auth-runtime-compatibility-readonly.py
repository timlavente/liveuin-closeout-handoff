"""Root-only AUTH02 metadata classifier; never imports product code or opens a DB.

No HTTP calls, customer records, provider/ready checks, service changes, credential
outputs or credential hashes. A signing-secret comparison exists only in memory.
Source hashes are public-code fingerprints, not credential fingerprints.
"""
from pathlib import Path
import datetime
import hashlib
import hmac
import json
import os
import pwd
import re
import subprocess

SPECS = {
    "identity_9098": {
        "unit": "liveuin-identity-public-prod.service",
        "cwd": "/opt/liveuin-identity-public/current",
        "base": "/opt/liveuin-identity-public/current/deploy",
        "argv": ["/opt/liveuin-identity-public/current/.venv/bin/python", "-m", "uvicorn", "prod_app:app", "--host", "127.0.0.1", "--port", "9098", "--proxy-headers", "--forwarded-allow-ips=127.0.0.1", "--timeout-keep-alive", "30"],
        "hashes": {
            "core_identity_session.py": "cfaf971913f6a49960f5cc54c8877641cc5db1b00de4c42fa8259c673cc82f7e",
            "core_identity_session_store.py": "c0f2a07b7778aef761deee03b32adc61bfa257cb1edeae933416438508a265c3",
            "core_identity_store.py": "e9556e964c6e7a1a5dc07d199a2a2f12cdf2034e491a28f7d70399bb908764c5",
            "core_identity_public_store.py": "98414fa04c72281edca3f399a40c1c2e731e1a367f7a74b794fcf09d60b908d4",
        },
    },
    "ops_9095": {
        "unit": "ops-backend@liveuin.service",
        "cwd": "/opt/liveuin/ops_backend",
        "base": "/opt/liveuin/deploy",
        "argv": ["/opt/liveuin/ops_backend/.venv/bin/python", "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "9095", "--proxy-headers", "--forwarded-allow-ips=*", "--timeout-keep-alive", "65"],
        "hashes": {
            "core_identity_session.py": "11b7ab17300c3a2ea8a0294470f9872496c6e4f8308598edad97f680ea9fefdb",
            "core_identity_session_store.py": "c0f2a07b7778aef761deee03b32adc61bfa257cb1edeae933416438508a265c3",
            "core_identity_store.py": "8435560b88230df6737ff3dca8dc52bafd881dd7ebb01c3b961356ae9cf04f36",
        },
    },
}
PATH_KEYS = {
    "session": ("LIVEUIN_CORE_IDENTITY_SESSION_DATA_DIR", "LIVEUIN_CORE_IDENTITY_SESSION_SQLITE_PATH", "core_identity_session_store.py", ("runtime", "core-identity-session-data"), "liveuin-core-identity-session.sqlite3"),
    "identity": ("LIVEUIN_CORE_IDENTITY_DATA_DIR", "LIVEUIN_CORE_IDENTITY_SQLITE_PATH", "core_identity_store.py", ("runtime", "core-identity-data"), "liveuin-core-identity.sqlite3"),
    "public_account": ("LIVEUIN_CORE_IDENTITY_PUBLIC_DATA_DIR", "LIVEUIN_CORE_IDENTITY_PUBLIC_SQLITE_PATH", "core_identity_public_store.py", ("runtime", "staging", "core-identity-public"), "liveuin-core-identity-public.sqlite3"),
}
FLAG_KEYS = ["LIVEUIN_PUBLIC_REGISTRATION_ENABLED", "LIVEUIN_IDENTITY_EMAIL_READY", "LIVEUIN_GOOGLE_NATIVE_ID_TOKEN_READY", "LIVEUIN_GOOGLE_OIDC_TOKEN_EXCHANGE_READY", "LIVEUIN_GOOGLE_OIDC_CALLBACK_VALIDATION_READY", "LIVEUIN_PUBLIC_GOOGLE_IDENTITY_ENABLED"]
PRESENCE_KEYS = ["LIVEUIN_GOOGLE_CLIENT_ID", "LIVEUIN_GOOGLE_REDIRECT_URI", "LIVEUIN_GOOGLE_CLIENT_SECRET_REF", "LIVEUIN_IDENTITY_PROVIDER_SUBJECT_PEPPER_REF", "LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET_REF", "LIVEUIN_PUBLIC_TERMS_VERSION"]
PLAIN_KEYS = ["LIVEUIN_DEPLOYED_COMMIT", "LIVEUIN_ENVIRONMENT", "LIVEUIN_PUBLIC_WORKSPACE_ID", "LIVEUIN_IDENTITY_EMAIL_DELIVERY_MODE"]
SECRET_KEY = "LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET"
SELECTED = set(FLAG_KEYS + PRESENCE_KEYS + PLAIN_KEYS + [SECRET_KEY, "LIVEUIN_IDENTITY_CREDENTIAL_STORE_ENFORCEMENT", "LIVEUIN_IDENTITY_SESSION_MAX_AGE_SECONDS", "HOME"])
for _spec in PATH_KEYS.values():
    SELECTED.update(_spec[:2])


def require(condition, name):
    if not condition:
        raise RuntimeError(name)


def state(unit):
    output = subprocess.check_output(["systemctl", "show", unit, "--property=Id,ActiveState,SubState,MainPID,WorkingDirectory"], text=True, timeout=8)
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def snapshot(spec):
    unit = state(spec["unit"])
    require(unit.get("ActiveState") == "active" and unit.get("SubState") == "running", "expected_service_not_running")
    pid = int(unit.get("MainPID") or 0)
    require(pid > 0, "invalid_pid")
    proc = Path("/proc") / str(pid)
    # Field22 remains correctly located even if the parenthesized comm has spaces.
    start_ticks = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
    argv = [os.fsdecode(value) for value in (proc / "cmdline").read_bytes().split(b"\0") if value]
    require(argv == spec["argv"], "process_command_drift")
    cwd = (proc / "cwd").resolve(strict=True)
    require(cwd == Path(spec["cwd"]).resolve(strict=True), "process_cwd_drift")
    require((proc / "exe").resolve(strict=True) == Path(spec["argv"][0]).resolve(strict=True), "process_executable_drift")
    return {"pid": pid, "start_ticks": start_ticks, "cwd": str(cwd)}, unit


def selected_environment(pid):
    selected = {}
    for item in (Path("/proc") / str(pid) / "environ").read_bytes().split(b"\0"):
        key, separator, value = item.partition(b"=")
        name = os.fsdecode(key)
        if separator and name in SELECTED:
            require(name not in selected, "duplicate_selected_environment_key")
            selected[name] = os.fsdecode(value)
    return selected


def nonsecret_scalar(value):
    value = value.strip()
    return value if re.fullmatch(r"[A-Za-z0-9_.:-]{0,160}", value) else "[unexpected_format_not_disclosed]"


def flag_class(value):
    normalized = value.strip().lower()
    return normalized if normalized in {"", "true", "false", "1", "0", "yes", "no", "on", "off", "required", "require", "enforced", "disabled", "enabled"} else "unexpected_value_not_disclosed"


def path_from_setting(value, process, env):
    # These named settings are filesystem paths; reject URI/credential-like forms.
    value = value.strip()
    require(bool(value) and re.fullmatch(r"[A-Za-z0-9_./ ~-]+", value) is not None, "unexpected_store_path_format")
    if value == "~" or value.startswith("~/"):
        home = env.get("HOME", "").strip() or pwd.getpwuid(Path("/proc/%s" % process["pid"]).stat().st_uid).pw_dir
        require(home.startswith("/") and re.fullmatch(r"[A-Za-z0-9_./ -]+", home) is not None, "unexpected_process_home_format")
        value = home + value[1:]
    require(not value.startswith("~"), "unsupported_named_home_path")
    path = Path(value)
    if not path.is_absolute():
        path = Path(process["cwd"]) / path
    return path


def store_binding(kind, spec, process, env):
    data_key, file_key, module, default_parts, filename = PATH_KEYS[kind]
    module_path = Path(spec["base"]) / module
    data = env.get(data_key, "").strip()
    configured = env.get(file_key, "").strip()
    if configured:
        logical = path_from_setting(configured, process, env)
        source = file_key
    elif data:
        logical = path_from_setting(data, process, env) / filename
        source = data_key
    else:
        logical = module_path.resolve(strict=True).parents[1].joinpath(*default_parts, filename)
        source = "source_default"
    process_path = Path("/proc/%s/root" % process["pid"]) / str(logical).lstrip("/")
    record = {"binding_source": source, "logical_path": str(logical), "host_realpath": str(logical.resolve()), "contents_opened": False}
    try:
        metadata = process_path.stat()
        record.update(exists_in_process_root=True, device=metadata.st_dev, inode=metadata.st_ino, regular_file=process_path.is_file())
        host_metadata = logical.stat()
        record["host_and_process_target_same"] = (metadata.st_dev, metadata.st_ino) == (host_metadata.st_dev, host_metadata.st_ino)
    except FileNotFoundError:
        record["exists_in_process_root"] = False
    return record


def source_check(spec):
    records = []
    for name, expected in spec["hashes"].items():
        path = Path(spec["base"]) / name
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        require(digest == expected, "source_hash_drift")
        records.append({"path": str(path), "resolved_path": str(path.resolve(strict=True)), "sha256": digest})
    return records


def compare_store(left, right):
    exists = left.get("exists_in_process_root") and right.get("exists_in_process_root")
    same_target = (left.get("device"), left.get("inode")) == (right.get("device"), right.get("inode")) if exists else None
    return {"same_host_realpath": left["host_realpath"] == right["host_realpath"], "both_exist": bool(exists), "same_process_root_file_identity": same_target}


def main():
    result = {"checked_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "mode": "read_only_metadata_no_http_no_database_import_or_customer_record", "services": {}}
    secrets = []
    environments = []
    try:
        require(os.geteuid() == 0, "root_required")
        starts = {}
        for label, spec in SPECS.items():
            process, unit = snapshot(spec)
            starts[label] = process
            hashes = source_check(spec)
            env = selected_environment(process["pid"])
            environments.append(env)
            # Both pinned modules implement exactly str(os.getenv(KEY) or '').strip().
            secret = str(env.get(SECRET_KEY) or "").strip()
            secrets.append(secret)
            enforcement = str(env.get("LIVEUIN_IDENTITY_CREDENTIAL_STORE_ENFORCEMENT") or "").strip().lower()
            row = {"unit": spec["unit"], "pid": process["pid"], "process_and_source_verified": True, "cwd": process["cwd"], "source_files": hashes,
                   "nonsecret": {key: nonsecret_scalar(env.get(key, "")) for key in PLAIN_KEYS},
                   "configured": {key: bool(env.get(key, "").strip()) for key in PRESENCE_KEYS},
                   "flags": {key: {"present": key in env, "normalized": flag_class(env.get(key, ""))} for key in FLAG_KEYS},
                   "direct_signing_secret_present": bool(secret),
                   "credential_store_enforcement": {"configured": bool(enforcement), "effective": not enforcement or enforcement in {"1", "true", "yes", "on", "required", "require", "enforced"}},
                   "session_max_age_setting": nonsecret_scalar(env.get("LIVEUIN_IDENTITY_SESSION_MAX_AGE_SECONDS", "")),
                   "stores": {}}
            for kind in ("session", "identity"):
                row["stores"][kind] = store_binding(kind, spec, process, env)
            if label == "identity_9098":
                row["stores"]["public_account"] = store_binding("public_account", spec, process, env)
            else:
                row["public_account_projection"] = "legacy session module has no public_account_id mapping; store unification is not inferred"
            result["services"][label] = row
        for label, spec in SPECS.items():
            end, _ = snapshot(spec)
            require(end == starts[label], "process_changed_during_check")
            require(source_check(spec) == result["services"][label]["source_files"], "source_changed_during_check")
            after_env = selected_environment(end["pid"])
            require(after_env == environments[list(SPECS).index(label)], "selected_environment_changed_during_check")
            after_env.clear()
        left = result["services"]["identity_9098"]["stores"]
        right = result["services"]["ops_9095"]["stores"]
        result["comparison"] = {
            "pid_and_selected_environment_stable": True,
            "both_direct_signers_present": all(bool(value) for value in secrets),
            "direct_signers_equal_after_source_normalization": hmac.compare_digest(secrets[0].encode(), secrets[1].encode()) if all(secrets) else None,
            "session_store": compare_store(left["session"], right["session"]),
            "identity_store": compare_store(left["identity"], right["identity"]),
        }
        result["result"] = "metadata_classified_not_session_compatibility_proof"
        result["limits"] = ["On-disk source fingerprints plus active process environment do not inspect loaded Python objects.", "Same signer/store cannot prove correct account/profile mapping, case authorization, revocation or browser behaviour.", "No password, OTP, logout, reset, ready or provider-status operation was called."]
    except Exception as error:
        result["result"] = "classification_incomplete_no_compatibility_claim"
        result["error_type"] = type(error).__name__
        if type(error) is RuntimeError:
            result["failed_check"] = str(error)
    finally:
        secrets.clear()
        for environment in environments:
            environment.clear()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
