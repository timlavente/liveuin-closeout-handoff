#!/usr/bin/env python3
"""READ ONLY. Run on the audited Linux host as root. Prints allowlisted JSON only.

No app imports, HTTP, provider calls, customer stores, writes, restarts or flags.
/proc/<PID>/environ is the process's startup environment, not a promise that
application code has never changed os.environ afterwards. Unlisted entries are
discarded; selected secrets are reduced to presence/key kind, never printed/hashed.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
from urllib.parse import urlparse

TRUTHY = {"1", "true", "yes", "on"}
CUSTOMER_CARD_FLAG = "LIVEUIN_CUSTOMER_CARDS_SANDBOX_ENABLED"
RAIL_FLAGS = (
    "LIVEUIN_STRIPE_LIVE_VALIDATION_READY",
    "LIVEUIN_HITPAY_LIVE_VALIDATION_READY",
    "LIVEUIN_WECHAT_PAY_LIVE_VALIDATION_READY",
    "LIVEUIN_SALTEDGE_PAYMENT_INITIATION_APPROVED",
)
CONNECT_FLAGS = (
    "LIVEUIN_CONNECT_SANDBOX_CHECKOUT_ENABLED", "LIVEUIN_CONNECT_ENV",
    "LIVEUIN_ENV", "APP_ENV", "ENVIRONMENT", "LIVEUIN_CONNECT_DB_MODE",
    "LIVEUIN_CONNECT_BILLING_PROVIDER", "LIVEUIN_CONNECT_PROVIDER_CHECKOUT_STRICT",
    "LIVEUIN_CONNECT_STRIPE_CHECKOUT_MODE", "LIVEUIN_CONNECT_HITPAY_ENV",
    "LIVEUIN_CONNECT_HITPAY_API_BASE", "LIVEUIN_CONNECT_AIRWALLEX_ENV",
    "LIVEUIN_CONNECT_AIRWALLEX_API_BASE",
)
SECRETS = {
    "LIVEUIN_CONNECT_STRIPE_SECRET_KEY", "LIVEUIN_CONNECT_HITPAY_API_KEY",
    "LIVEUIN_CONNECT_AIRWALLEX_ACCESS_TOKEN",
}
ALLOW = set(RAIL_FLAGS) | set(CONNECT_FLAGS) | SECRETS | {CUSTOMER_CARD_FLAG} | {
    "CREDENTIALS_DIRECTORY", "LIVEUIN_PREVIEW_INTERNAL_AUTH_REQUIRED",
}
SERVICES = (
    ("ops-backend@liveuin.service", "ops_9095", True),
    ("liveuin-public-preview-ui.service", "preview_9081", False),
    ("liveuin-public-api.service", "public_api_9080", False),
)
SOURCES = {
    "/opt/liveuin/deploy/core_payment_rail.py": "20ca0cb4a6f4325047bb67da5ec7ecb3fe302cee80351f030a27079f71d64c44",
    "/opt/liveuin/deploy/core_stripe_sandbox_api.py": "2eb20cb1dd95e48ce25df0844e838c458a218f0290518657bd8f2c66099f30c6",
    "/opt/liveuin/ops_backend/app.py": "fcecabe419ce5aa080155f0e29e34eee79596d05f3838a6180dad2ce9795bbf2",
    "/opt/liveuin/public-home-preview.py": "e523924bac421433ad34ea6587353b0448bd42aeba950e27029d654ffb063099",
    # Reconciled mobile source, observed in root metadata05; no store content read.
    "/opt/liveuin/ops_backend/app/main.py": "b8f00791b71b11e93c72980ad31fa0eac3d18d0b03a0e4e4dd5f172620c85c2a",
    "/opt/liveuin/deploy/core_resident_gateway.py": "676d3de8f87b3929ab13cd03759e58748419e4fb5548ca1209e4ce2069348210",
    "/opt/liveuin/deploy/core_customer_card_api.py": "cb04159dd5d6e5ddc13e19f1a2e9c7f41d0eff15591d1b61bb68d67d3a4efb91",
    "/opt/liveuin/deploy/core_customer_card_provider.py": "5945fd77f52036844b5921b71b07f44cc652f77e67ce40bd25f77ebd90d4dd87",
    "/opt/liveuin/deploy/core_customer_card_service.py": "def3ce375d9d3adc769dc6501d5f5ce51bc081127ff875859b0d8a4abe190983",
    "/opt/liveuin/deploy/core_customer_card_contract.py": "7684c0a0ba9edacc51fb15df245e628e579f1c69ac30604ea31be21c8bd53d83",
    "/opt/liveuin/deploy/core_customer_card_store.py": "b479055e65c9a571b2a3f86d4e893d1bc5c9fdc940929bd13597ff8d2339b175",
    "/opt/liveuin/deploy/core_resident_customer_scope.py": "da3049098f62c53faa134e5c24cc230e72ef69d7a6276688b7611d21d951e4fe",
    "/opt/liveuin/deploy/core_resident_bills_api.py": "97e3ff343daa1b5dcd977edb02b0cfe6049cbf3aefef81351880ffcb919a6c72",
}


def key_kind(value):
    value = value.strip()
    if not value:
        return "absent_or_empty"
    for prefix, label in (("sk_test_", "secret_test"), ("sk_live_", "secret_live"),
                          ("rk_test_", "restricted_test"), ("rk_live_", "restricted_live")):
        if value.startswith(prefix):
            return label
    return "present_unrecognized"


def selected_environment(pid, allow_names=ALLOW):
    # Read one NUL-delimited entry at a time; never retain unselected values.
    result, key, value = {}, bytearray(), bytearray()
    reading_key, selected, oversized = True, False, False
    with open(f"/proc/{pid}/environ", "rb", buffering=0) as handle:
        while True:
            block = handle.read(4096)
            if not block:
                break
            for byte in block:
                if byte == 0:
                    if selected:
                        name = key.decode("ascii")
                        text = value.decode("utf-8", "replace") if not oversized else "[unclassified]"
                        result[name] = key_kind(text) if name.endswith("STRIPE_SECRET_KEY") else (
                            bool(text.strip()) if name in SECRETS else text)
                    key, value = bytearray(), bytearray()
                    reading_key, selected, oversized = True, False, False
                elif reading_key and byte == 61:
                    reading_key = False
                    selected = key.decode("ascii", "ignore") in allow_names
                elif reading_key:
                    if len(key) < 200:
                        key.append(byte)
                elif selected:
                    if len(value) < 65536:
                        value.append(byte)
                    else:
                        oversized = True
    return result


def classify_customer_cards(env):
    # Exact source condition; do not trim/casefold or reuse generic truthy flags.
    return {"present": CUSTOMER_CARD_FLAG in env,
            "enabled_exact_true": env.get(CUSTOMER_CARD_FLAG) == "true"}


def clean(env, name):
    return str(env.get(name, "")).strip().lower()


def endpoint_class(env, provider):
    if provider == "hitpay":
        live = clean(env, "LIVEUIN_CONNECT_HITPAY_ENV") == "production"
        default = "https://api.hit-pay.com" if live else "https://api.sandbox.hit-pay.com"
        known = {"api.hit-pay.com": "live", "api.sandbox.hit-pay.com": "sandbox"}
        name = "LIVEUIN_CONNECT_HITPAY_API_BASE"
    else:
        live = clean(env, "LIVEUIN_CONNECT_AIRWALLEX_ENV") in {"production", "prod", "live"}
        default = "https://api.airwallex.com" if live else "https://api-demo.airwallex.com"
        known = {"api.airwallex.com": "live", "api-demo.airwallex.com": "demo"}
        name = "LIVEUIN_CONNECT_AIRWALLEX_API_BASE"
    raw = str(env.get(name, "")).strip() or default
    try:
        parsed = urlparse(raw)
        accepted = raw.startswith("https://") or (
            parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1", "host.docker.internal"})
        effective = parsed if accepted else urlparse(default)
        label = known.get(effective.hostname, "other_endpoint_unproved")
        if effective.username or effective.password:
            label = "other_endpoint_unproved"
        return label
    except Exception:
        return "unclassified"


def classify_connect(env):
    explicit = clean(env, "LIVEUIN_CONNECT_SANDBOX_CHECKOUT_ENABLED")
    selected_env = next((env.get(k) for k in ("LIVEUIN_CONNECT_ENV", "LIVEUIN_ENV", "APP_ENV", "ENVIRONMENT") if env.get(k)), "")
    sandbox = explicit in TRUTHY if explicit else (
        False if str(selected_env).strip().lower() in {"production", "prod"}
        else clean(env, "LIVEUIN_CONNECT_DB_MODE") == "registry")
    raw_provider = clean(env, "LIVEUIN_CONNECT_BILLING_PROVIDER")
    provider = {"sandbox": "liveuin_sandbox", "liveuin": "liveuin_sandbox",
                "liveuin-sandbox": "liveuin_sandbox", "test": "liveuin_sandbox"}.get(raw_provider, raw_provider)
    if provider not in {"stripe", "hitpay", "airwallex", "liveuin_sandbox", "reference", "none"}:
        provider = "liveuin_sandbox" if sandbox else "reference"
    strict_flag = clean(env, "LIVEUIN_CONNECT_PROVIDER_CHECKOUT_STRICT")
    kind = env.get("LIVEUIN_CONNECT_STRIPE_SECRET_KEY", "absent_or_empty")
    hitpay = endpoint_class(env, "hitpay")
    airwallex = endpoint_class(env, "airwallex")
    mode = clean(env, "LIVEUIN_CONNECT_STRIPE_CHECKOUT_MODE")
    selected_path = "no_external_provider_dispatch"
    if provider == "stripe":
        selected_path = {"absent_or_empty": "blocked_missing_key", "secret_test": "test_key_selected",
                         "restricted_test": "test_key_selected", "secret_live": "live_key_selected",
                         "restricted_live": "live_key_selected"}.get(kind, "unknown_key_unproved")
    elif provider in {"hitpay", "airwallex"}:
        secret_name = "LIVEUIN_CONNECT_HITPAY_API_KEY" if provider == "hitpay" else "LIVEUIN_CONNECT_AIRWALLEX_ACCESS_TOKEN"
        selected_path = "blocked_missing_key" if not env.get(secret_name, False) else (
            "live_endpoint_key_present" if (hitpay if provider == "hitpay" else airwallex) == "live"
            else "nonlive_or_unknown_endpoint_key_present")
    return {
        "sandbox_enabled": sandbox, "provider": provider,
        "strict": strict_flag in TRUTHY if strict_flag else not sandbox,
        "stripe_key_kind": kind,
        "stripe_checkout_mode": mode if mode in {"payment", "subscription"} else "subscription",
        "hitpay_key_present": bool(env.get("LIVEUIN_CONNECT_HITPAY_API_KEY", False)),
        "hitpay_endpoint": hitpay,
        "airwallex_token_present": bool(env.get("LIVEUIN_CONNECT_AIRWALLEX_ACCESS_TOKEN", False)),
        "airwallex_endpoint": airwallex, "selected_dispatch_class": selected_path,
    }


def credential_kind(pid, unit, env):
    # Read the one named adapter credential only; never enumerate credentials.
    directory = str(env.get("CREDENTIALS_DIRECTORY", "")).strip()
    expected = "/run/credentials/" + unit
    if not directory:
        return "no_credential_directory"
    if directory != expected:
        return "nonstandard_directory_unread"
    try:
        path = Path(f"/proc/{pid}/root") / directory.lstrip("/") / "STRIPE_SECRET_KEY"
        if not path.is_file():
            return "absent_or_empty"
        if path.stat().st_size > 65536:
            return "oversized_adapter_rejects"
        return key_kind(path.read_text(encoding="utf-8").strip())
    except Exception:
        return "unreadable"


def start_id(pid):
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def inspect_service(unit, label, connect):
    row = {"unit": unit, "source_mapping": label}
    try:
        p = subprocess.run(["systemctl", "show", unit, "--property=MainPID,ActiveState"],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=8, check=True)
        props = dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)
        pid = int(props.get("MainPID", "0"))
        row.update(pid=pid, active=props.get("ActiveState") == "active")
        if pid <= 0 or not row["active"]:
            row["result"] = "not_active_unproved"
            return row
        before = start_id(pid)
        names = ALLOW if connect else set(RAIL_FLAGS) | (
            {"CREDENTIALS_DIRECTORY", "LIVEUIN_PREVIEW_INTERNAL_AUTH_REQUIRED"} if label == "preview_9081" else set())
        env = selected_environment(pid, names)
        row["core_live_rail_flags"] = {k: {"present": k in env, "enabled": clean(env, k) in TRUTHY} for k in RAIL_FLAGS}
        if label in {"ops_9095", "preview_9081"}:
            kind = credential_kind(pid, unit, env)
            row["core_stripe_credential_kind"] = kind
            row["core_sandbox_adapter_accepts_key_kind"] = kind == "secret_test"
        if connect:
            row["legacy_connect"] = classify_connect(env)
            row["customer_card_sandbox_flag"] = classify_customer_cards(env)
        if label == "preview_9081":
            row["preview_internal_auth_required"] = clean(env, "LIVEUIN_PREVIEW_INTERNAL_AUTH_REQUIRED") in TRUTHY
        children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
        row["child_processes_present"] = bool(children)
        current = subprocess.run(["systemctl", "show", unit, "--property=MainPID", "--value"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=8, check=True)
        row["same_process_during_read"] = start_id(pid) == before and int(current.stdout.strip()) == pid
        row["result"] = ("process_changed_unproved" if not row["same_process_during_read"] else
                         "children_not_classified_unproved" if children else "startup_environment_classified")
    except Exception:
        row["result"] = "read_failed_unproved"
    return row


def main():
    source_matches = {}
    for path, expected in SOURCES.items():
        try:
            source_matches[path] = hashlib.sha256(Path(path).read_bytes()).hexdigest() == expected
        except Exception:
            source_matches[path] = None
    result = {
        "classifier_revision": "05",
        "previous_helper_sha256": "5770559c614ba0eaad53667d62d33a2997a6f2471848452d0d32ea4665b68316",
        "observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "read_only": True, "running_as_root": os.geteuid() == 0,
        "reviewed_source_matches": source_matches,
        "services": [inspect_service(*s) for s in SERVICES],
        "limits": ["No HTTP/provider/customer-data actions or writes.",
                   "Startup environment classification; no in-process introspection.",
                   "Source mismatch/null or failed/stale process read requires review.",
                   "Combine with domain-routing/guard evidence; this is not a universal payment-lock PASS.",
                   "Separate Pay service not inspected; its prior health is separate evidence.",
                   "Customer-card flag uses exact string true; it enables sandbox setup only, not live charging.",
                   "Match current Ops PID to activation evidence; no old PID is treated as current proof."],
    }
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
