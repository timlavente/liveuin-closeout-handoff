"""Additive customer TEST-card router; mount explicitly after deployment review."""
import json
import os
import re
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
try:
    from .core_resident_customer_scope import resolve_customer_scope, CustomerScopeError
    from .core_customer_card_contract import CardError
    from .core_customer_card_provider import StripeTestCards
    from .core_customer_card_service import CustomerCards
except ImportError:
    from core_resident_customer_scope import resolve_customer_scope, CustomerScopeError
    from core_customer_card_contract import CardError
    from core_customer_card_provider import StripeTestCards
    from core_customer_card_service import CustomerCards

router = APIRouter()
HEADERS = {"Cache-Control": "private, no-store, max-age=0", "Pragma": "no-cache", "Expires": "0",
    "Vary": "Authorization, Cookie, X-LiveUIN-Session-Id, X-LiveUIN-Session-Signature, X-LiveUIN-Requested-Profile-Key, X-LiveUIN-Requested-Workspace-Id, X-LiveUIN-Expected-Account-Id, X-LiveUIN-Expected-Person-Id"}
PREFIX = "/api/core/payments/customer/sandbox"
WEBHOOK_PURPOSE = "stripe_customer_setup_webhook_signature"

def configuration():
    if os.getenv("LIVEUIN_CUSTOMER_CARDS_SANDBOX_ENABLED") != "true":
        raise CardError("test_card_setup_unavailable", 503)
    account = os.getenv("LIVEUIN_CUSTOMER_CARDS_STRIPE_ACCOUNT_ID", "")
    workspace = os.getenv("LIVEUIN_CUSTOMER_CARDS_WORKSPACE_ID", "")
    public_key = os.getenv("LIVEUIN_CUSTOMER_CARDS_STRIPE_PUBLISHABLE_KEY", "")
    secret_ref = os.getenv("LIVEUIN_CUSTOMER_CARDS_WEBHOOK_SECRET_REF", "")
    if not re.fullmatch(r"acct_[A-Za-z0-9]+", account) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", workspace) or not re.fullmatch(r"pk_test_[A-Za-z0-9]{8,240}", public_key) or not secret_ref:
        raise CardError("test_card_setup_unavailable", 503)
    return account, workspace, public_key, secret_ref

def context(request):
    scope = resolve_customer_scope(request, required_scope="payment.intent.write")
    # Preconditions detect stale UI/new session, never grant authority themselves.
    if (request.headers.get("x-liveuin-expected-account-id") != scope.account_id
            or request.headers.get("x-liveuin-expected-person-id") != scope.person_id):
        raise CardError("customer_scope_mismatch", 403)
    account, workspace, public_key, _ = configuration()
    if scope.workspace_id != workspace:
        raise CardError("customer_scope_mismatch", 403)
    return scope, CustomerCards(StripeTestCards(account), workspace), public_key

def respond(operation):
    try:
        return JSONResponse(operation(), headers=HEADERS)
    except (CardError, CustomerScopeError) as error:
        return JSONResponse({"ok": False, "error": {"code": error.code}, "notice": "Test mode. No live charge."}, status_code=error.status, headers=HEADERS)
    except Exception:
        # Do not echo SQL/provider errors, raw credentials, client secrets or card fields.
        return JSONResponse({"ok": False, "error": {"code": "test_card_setup_unavailable"}}, status_code=503, headers=HEADERS)

async def bounded_json(request, limit=4096):
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > limit:
            raise CardError("invalid_request", 422)
    try:
        value = json.loads(raw)
    except Exception:
        raise CardError("invalid_request", 422) from None
    if not isinstance(value, dict):
        raise CardError("invalid_request", 422)
    return value

@router.post(PREFIX + "/setup-intents")
async def create_setup(request: Request):
    try:
        payload = await bounded_json(request)
    except CardError as error:
        return respond(lambda: (_ for _ in ()).throw(error))
    def operation():
        scope, service, public_key = context(request)
        resume = request.headers.get("x-liveuin-resume-card-setup", "")
        if resume not in {"", "true"}:
            raise CardError("invalid_request", 422)
        result = service.create_setup(scope, payload, request.headers.get("idempotency-key", ""),
            resume_only=resume == "true", expected_setup_id=request.headers.get("x-liveuin-expected-setup-id", ""))
        if "client_secret" in result["setup"]:
            result["publishable_key"] = public_key
        return result
    return await run_in_threadpool(respond, operation)

@router.get(PREFIX + "/setup-intents/{setup_id}")
def get_setup(request: Request, setup_id: str):
    def operation():
        scope, service, _ = context(request)
        return service.get_setup(scope, setup_id)
    return respond(operation)

@router.get(PREFIX + "/payment-methods")
def list_methods(request: Request):
    def operation():
        scope, service, _ = context(request)
        return service.list_methods(scope)
    return respond(operation)

@router.delete(PREFIX + "/payment-methods/{method_id}")
async def remove_method(request: Request, method_id: str):
    # No arbitrary provider/customer IDs, raw card data or payment fields accepted.
    async for chunk in request.stream():
        if chunk:
            return JSONResponse({"ok": False, "error": {"code": "invalid_request"}}, status_code=422, headers=HEADERS)
    def operation():
        scope, service, _ = context(request)
        return service.remove_method(scope, method_id, request.headers.get("idempotency-key", ""))
    return await run_in_threadpool(respond, operation)

def verify_setup_webhook(raw, signature, workspace, secret_ref):
    try:
        from . import core_adapter_secret_registry as registry
        from . import core_payment_provider_edge as edge
    except ImportError:
        import core_adapter_secret_registry as registry
        import core_payment_provider_edge as edge
    # Explicit configured reference only. Never trust caller-selected workspace/ref,
    # and never fall back to a global webhook secret when registry lookup fails.
    # A distinct registry purpose keeps this destination out of generic payment
    # webhook lookup. Explicit-ref lookup itself does not validate purpose/provider.
    resolved = registry.resolve_provider_edge_secret("stripe", WEBHOOK_PURPOSE, workspace_id=workspace, secret_ref_id=secret_ref)
    context = resolved.get("secret_context")
    if (resolved.get("ok") is not True or not resolved.get("secret") or not isinstance(context, dict)
            or any(context.get(key) != value for key, value in {
                "provider": "stripe", "purpose": WEBHOOK_PURPOSE, "workspace_id": workspace,
                "secret_ref_id": secret_ref, "status": "active"}.items())
            or context.get("secret_source") not in {"registered_systemd_credential", "registered_secret_environment", "registered_secret_reference"}):
        raise CardError("test_webhook_unavailable", 503)
    verified = edge.verify_stripe_signature(raw, signature, resolved["secret"], workspace_id=workspace, secret_ref_id=secret_ref)
    if verified.get("ok") is not True or verified.get("transport_signature_verified") is not True:
        raise CardError("invalid_provider_signature", 401)

@router.post("/api/core/payments/provider-webhooks/stripe/customer-sandbox")
async def setup_webhook(request: Request):
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > 256 * 1024:
            return JSONResponse({"ok": False, "error": {"code": "invalid_request"}}, status_code=422, headers=HEADERS)
    def operation():
        account, workspace, _, secret_ref = configuration()
        verify_setup_webhook(bytes(raw), request.headers.get("stripe-signature", ""), workspace, secret_ref)
        try:
            event = json.loads(raw)
        except Exception:
            raise CardError("invalid_request", 422) from None
        return CustomerCards(StripeTestCards(account), workspace).verified_setup_event(event)
    return await run_in_threadpool(respond, operation)
