"""Server-only Stripe TEST adapter. Fixed endpoints; no raw card or charge API."""
import json
import re
import time
from urllib.parse import urlencode
from urllib.request import Request, HTTPRedirectHandler, build_opener
try:
    from .core_customer_card_contract import CardError, identifier
    from .core_stripe_sandbox_api import _secret
except ImportError:
    from core_customer_card_contract import CardError, identifier
    from core_stripe_sandbox_api import _secret

API_VERSION = "2026-09-30.endive"
MAX_BYTES = 256 * 1024

class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CardError("test_provider_unavailable", 503)

def _open_no_redirect(request, timeout):
    return build_opener(_NoRedirect()).open(request, timeout=timeout)

class StripeTestCards:
    def __init__(self, expected_account, opener=_open_no_redirect, clock=time.monotonic):
        self.expected_account = identifier(expected_account, "acct_")
        self.opener = opener
        self.clock = clock
        self.deadline = clock() + 24

    def _request(self, method, path, fields=None, key=None):
        # Each public method constructs a fixed path from strictly validated IDs.
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise CardError("test_provider_unavailable", 503)
        secret = _secret()
        if not secret or not secret.startswith("sk_test_"):
            raise CardError("test_provider_unavailable", 503)
        headers = {"Authorization": "Bearer " + secret, "Stripe-Version": API_VERSION,
                   "Content-Type": "application/x-www-form-urlencoded"}
        if method == "POST":
            if not key or not re.fullmatch(r"liveuin_card_[A-Za-z0-9_-]{1,180}", key):
                raise CardError("provider_idempotency_required", 500)
            headers["Idempotency-Key"] = key
        req = Request("https://api.stripe.com/v1" + path,
                      data=urlencode(fields or {}, doseq=True).encode() if method == "POST" else None,
                      headers=headers, method=method)
        try:
            with self.opener(req, timeout=min(8, remaining)) as response:
                if response.status != 200 or "application/json" not in response.headers.get("Content-Type", ""):
                    raise CardError("test_provider_unavailable", 503)
                body = response.read(MAX_BYTES + 1)
                if self.clock() >= self.deadline:
                    raise CardError("test_provider_unavailable", 503)
                if len(body) > MAX_BYTES:
                    raise CardError("invalid_provider_response", 502)
                data = json.loads(body)
        except CardError:
            raise
        except Exception:
            # Never include upstream body, request headers, secret or raw error text.
            raise CardError("test_provider_unavailable", 503) from None
        if not isinstance(data, dict):
            raise CardError("invalid_provider_response", 502)
        return data

    def check_account(self):
        data = self._request("GET", "/account")
        if data.get("id") != self.expected_account or data.get("object") != "account":
            raise CardError("test_provider_account_mismatch", 503)
        return self.expected_account

    def create_customer(self, customer_id, key):
        return self._request("POST", "/customers", {"metadata[liveuin_customer_id]": customer_id,
            "metadata[liveuin_environment]": "sandbox"}, key)

    def customer(self, ref):
        return self._request("GET", "/customers/" + identifier(ref, "cus_"))

    def create_setup(self, customer, setup_id, key):
        return self._request("POST", "/setup_intents", {"customer": identifier(customer, "cus_"),
            # Endive accepts an allowlist; payment_method_types is response-only.
            # Keep the service's exact returned ["card"] validation unchanged.
            "usage": "on_session", "allowed_payment_method_types[]": "card",
            "metadata[liveuin_setup_id]": setup_id, "metadata[liveuin_environment]": "sandbox"}, key)

    def setup(self, ref):
        return self._request("GET", "/setup_intents/" + identifier(ref, "seti_"))

    def method(self, ref):
        return self._request("GET", "/payment_methods/" + identifier(ref, "pm_"))

    def methods(self, customer):
        # One bounded page, never up to fifty sequential provider calls.
        return self._request("GET", "/customers/" + identifier(customer, "cus_") + "/payment_methods?type=card&limit=100")

    def detach(self, ref, key):
        return self._request("POST", "/payment_methods/" + identifier(ref, "pm_") + "/detach", {}, key)
