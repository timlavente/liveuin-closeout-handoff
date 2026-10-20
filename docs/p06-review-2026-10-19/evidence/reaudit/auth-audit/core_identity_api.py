from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import os
from typing import Any, Dict, List
from urllib import error as urlerror
from urllib import request as urlrequest

from fastapi import APIRouter, Body, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse

try:
    from . import core_identity_auth_policy as auth_policy
    from . import core_identity_google_oauth as google_oauth
    from . import core_identity_login as identity_login
    from . import core_identity_profile_authorization as profile_authorization
    from . import core_identity_service as identity_svc
    from . import core_identity_session as identity_session
    from . import core_identity_workspace_access as workspace_access
    from . import core_ps05_permitted_guest_projection_service as ps05_guest_projection
    from . import core_service_secret_resolver as service_secrets
except ImportError:  # pragma: no cover - supports direct app-folder deployment.
    import core_identity_auth_policy as auth_policy
    import core_identity_google_oauth as google_oauth
    import core_identity_login as identity_login
    import core_identity_profile_authorization as profile_authorization
    import core_identity_service as identity_svc
    import core_identity_session as identity_session
    import core_identity_workspace_access as workspace_access
    import core_ps05_permitted_guest_projection_service as ps05_guest_projection
    import core_service_secret_resolver as service_secrets


router = APIRouter()

LOCAL_PREVIEW_HOSTS = {"127.0.0.1", "localhost", "host.docker.internal"}


def _request_meta(request: Request) -> Dict[str, str]:
    return {
        "ip": request.client.host if request.client else "",
        "user_agent": str(request.headers.get("user-agent") or "")[:500],
        "referer": str(request.headers.get("referer") or "")[:500],
    }


def _request_context(request: Request) -> Dict[str, str]:
    return {
        "host": str(request.headers.get("host") or "")[:240],
        "scheme": str(request.url.scheme or "")[:24],
        "path": str(request.url.path or "")[:240],
        "liveuin_test_preview": str(request.headers.get("x-liveuin-test-preview") or "")[:8],
    }


def _query_map(request: Request) -> Dict[str, List[str]]:
    mapped: Dict[str, List[str]] = defaultdict(list)
    for key, value in request.query_params.multi_items():
        mapped[str(key)].append(str(value))
    return dict(mapped)


def _raise_if_error(response: Dict[str, Any]) -> Dict[str, Any]:
    if response.get("ok") is not False:
        return response
    raise HTTPException(
        status_code=int(response.get("status_code") or 400),
        detail=str(response.get("detail") or "core_identity_error"),
    )


def _require_authenticated_identity(request: Request) -> Dict[str, Any]:
    resolved = identity_session.resolve_access_context(
        headers=request.headers,
        method=request.method,
        path=request.url.path,
        request_meta=_request_meta(request),
        require_identity=True,
    )
    if resolved.get("ok") is False:
        raise HTTPException(
            status_code=int(resolved.get("status_code") or 401),
            detail=str(resolved.get("detail") or "identity_session_required"),
        )
    identity = resolved.get("identity_session")
    if not isinstance(identity, dict) or identity.get("resolved") is not True:
        raise HTTPException(status_code=401, detail="identity_session_required")
    return resolved


def _clean_email(value: Any) -> str:
    return str(value or "").strip().lower()


def _looks_like_email(value: str) -> bool:
    return "@" in value and "." in value.rsplit("@", 1)[-1]


def _local_preview_request(request_context: Dict[str, Any] | None = None) -> bool:
    context = request_context if isinstance(request_context, dict) else {}
    host = str(context.get("host") or "").split(":", 1)[0].strip().lower()
    environment = str(
        os.getenv("LIVEUIN_ENVIRONMENT")
        or os.getenv("ENVIRONMENT")
        or os.getenv("LIVEUIN_ENV")
        or ""
    ).strip().lower()
    if environment in {"prod", "production"}:
        return False
    trusted_hosts = {
        item.strip().lower()
        for item in str(os.getenv("LIVEUIN_IDENTITY_TRUSTED_PREVIEW_HOSTS") or "").split(",")
        if item.strip()
    }
    configured_host = str(os.getenv("LIVEUIN_IDENTITY_TEST_PREVIEW_HOST") or "").strip().lower()
    return host in LOCAL_PREVIEW_HOSTS or host in trusted_hosts or (configured_host and host == configured_host)


def _otp_gateway_deliver(email: str, challenge_id: str, verification_code: str) -> Dict[str, Any]:
    """Send a Core-owned code through the separately authenticated SMTP gateway."""
    gateway_url = str(os.getenv("OTP_GATEWAY_URL") or "").strip().rstrip("/")
    internal_token = str(os.getenv("OTP_INTERNAL_TOKEN") or "")
    if not gateway_url or not internal_token:
        return {"ok": False, "detail": "email_code_delivery_unavailable"}

    body = json.dumps(
        {
            "email": email,
            "challenge_id": challenge_id,
            "verification_code": verification_code,
        }
    ).encode("utf-8")
    request = urlrequest.Request(
        gateway_url + "/send",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-OTP-Internal-Token": internal_token,
        },
        method="POST",
    )
    try:
        with urlrequest.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8") or "{}")
    except (OSError, ValueError, urlerror.HTTPError, urlerror.URLError):
        return {"ok": False, "detail": "email_code_delivery_unavailable"}

    if not isinstance(payload, dict) or payload.get("ok") is not True or payload.get("sent") is not True:
        return {"ok": False, "detail": "email_code_delivery_unavailable"}
    return {"ok": True, "delivery_status": "sent"}


def _host_workspace_request_context(
    request_context: Dict[str, Any] | None,
) -> Dict[str, Any]:
    """Resolve the isolated Host pilot tenant from server config and trusted origin."""
    context = request_context if isinstance(request_context, dict) else {}
    host = str(context.get("host") or "").split(":", 1)[0].strip().lower()
    staging_preview = host == "liveuin-test.liveuin.com" and str(context.get("liveuin_test_preview") or "") == "1"
    if host != "host.liveuin.com" and not _local_preview_request(context) and not staging_preview:
        return {"ok": False, "status_code": 403, "detail": "host_auth_surface_not_allowed"}

    workspace_id = str(os.getenv("LIVEUIN_HOST_WORKSPACE_ID") or "").strip()
    if not workspace_id:
        return {"ok": False, "status_code": 503, "detail": "host_workspace_not_configured"}
    return {"ok": True, "workspace_id": workspace_id}


def _host_membership_access(workspace_id: str, email_hash: str) -> Dict[str, Any]:
    """Return access only for the sole active owner of an isolated Host pilot workspace."""
    workspace = workspace_access._workspace_record(workspace_id)
    product_line = str(workspace.get("product_line") or "").strip().lower()
    if (
        product_line not in {"host", "owner"}
        or not workspace_access._workspace_active(workspace)
    ):
        return {}

    result = workspace_access._access_from_existing_membership(workspace_id, email_hash)
    if not isinstance(result, dict) or result.get("ok") is not True:
        return {}
    membership = result.get("membership") if isinstance(result.get("membership"), dict) else {}
    role_context = result.get("role_context") if isinstance(result.get("role_context"), dict) else {}
    role = str(role_context.get("role") or "").strip().lower()
    scopes = [str(scope).strip() for scope in role_context.get("scopes") or [] if str(scope).strip()]
    workspace_role = str(membership.get("workspace_role") or "").strip().lower()
    if role not in {"owner", "landlord"} or workspace_role not in {"owner", "landlord"} or not scopes:
        return {}

    # This is a controlled single-owner pilot binding, not the eventual multi-host
    # account resolver. Fail closed if the configured tenant gains another owner.
    active_owners = [
        item
        for item in workspace_access.store.list_workspace_memberships(workspace_id, limit=500)
        if str(item.get("status") or "").strip().lower() == "active"
        and str(item.get("workspace_role") or "").strip().lower() in {"owner", "landlord"}
        and str(item.get("access_role") or "").strip().lower() in {"owner", "landlord"}
    ]
    if len(active_owners) != 1 or str(active_owners[0].get("email_hash") or "") != email_hash:
        return {}
    return {"role": role, "scopes": scopes}


def browser_auth_request_code(
    payload: Dict[str, Any] | None = None,
    request_meta: Dict[str, str] | None = None,
    request_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    raw_identifier = (
        payload.get("email")
        or payload.get("identifier")
        or payload.get("username")
        or payload.get("phone")
        or ""
    )
    email = _clean_email(raw_identifier)
    if not email:
        return {
            "ok": False,
            "status_code": 400,
            "detail": "email_required",
        }
    if not _looks_like_email(email):
        return {
            "ok": False,
            "status_code": 400,
            "detail": "valid_email_required",
        }

    surface = str(payload.get("surface") or "").strip().lower()
    requested_role = str(payload.get("liveuin_role") or payload.get("role") or "").strip().lower()
    purpose = str(payload.get("purpose") or "").strip().lower()
    requested_workspace_id = str(payload.get("workspace_id") or "").strip()
    workspace_id = requested_workspace_id or identity_login.DEFAULT_WORKSPACE_ID
    scopes: List[str] = []
    if surface == "host_workspace":
        host_context = _host_workspace_request_context(request_context)
        if host_context.get("ok") is not True:
            return host_context
        workspace_id = str(host_context.get("workspace_id") or "")
        email_hash = hashlib.sha256(email.encode("utf-8")).hexdigest()
        membership_access = _host_membership_access(workspace_id, email_hash)
        if not membership_access:
            # Keep the response generic; do not disclose membership lookup results.
            return {"ok": False, "status_code": 403, "detail": "host_sign_in_unavailable"}
        requested_role = str(membership_access["role"])
        scopes = list(membership_access["scopes"])
        purpose = "operator_portal"
    if not purpose:
        if requested_role in {"agent", "connector_admin"} or surface.startswith("connect") or surface.startswith("partner"):
            purpose = "connect_admin"
        else:
            purpose = "operator_portal"

    ops_login_surface = surface in {"ops_command", "operator_portal"}
    if surface != "host_workspace" and ops_login_surface and purpose == "operator_portal":
        operator_access = workspace_access.resolve_ops_workspace_access(
            hashlib.sha256(email.encode("utf-8")).hexdigest(),
            requested_workspace_id,
        )
        if operator_access.get("ok") is not True:
            return operator_access
        workspace_id = str(operator_access.get("workspace_id") or "")
        role_context = operator_access.get("role_context") if isinstance(operator_access.get("role_context"), dict) else {}
        requested_role = str(role_context.get("role") or "").strip().lower()
        scopes = [str(scope).strip() for scope in role_context.get("scopes") or [] if str(scope).strip()]

    created = identity_login.create_login_challenge(
        {
            "workspace_id": workspace_id,
            "channel": "email",
            "purpose": purpose,
            "surface": payload.get("surface") or "ops_command",
            "target_hash": hashlib.sha256(email.encode("utf-8")).hexdigest(),
            "role": requested_role or ("agent" if purpose == "connect_admin" else "operator"),
            **({"scopes": scopes} if surface == "host_workspace" or purpose == "operator_portal" else {}),
            "source": payload.get("source") or "ops_auth_shell_email_code",
            "metadata": {
                "browser_safe_email_code": True,
                "raw_email_stored": False,
            },
        },
        request_meta,
    )
    if created.get("ok") is not True:
        return created

    challenge = created.get("challenge") if isinstance(created.get("challenge"), dict) else {}
    one_time = created.get("one_time_challenge") if isinstance(created.get("one_time_challenge"), dict) else {}
    challenge_id = str(challenge.get("challenge_id") or one_time.get("challenge_id") or "")
    verification_code = str(one_time.get("verification_code") or "")
    if not _local_preview_request(request_context):
        delivery = _otp_gateway_deliver(email, challenge_id, verification_code)
        if delivery.get("ok") is not True:
            identity_login.cancel_login_challenge(
                challenge_id,
                {"workspace_id": workspace_id},
                request_meta,
            )
            return {
                "ok": False,
                "status_code": 503,
                "detail": "email_code_delivery_unavailable",
                "status": "hold",
                "delivery_status": "not_confirmed",
                "canonical_owner": "LiveUIN Identity",
                "raw_secret_echoed": False,
            }
    response = {
        "ok": True,
        "challenge_id": challenge_id,
        "expires_at": int(one_time.get("expires_at") or 0),
        "expires_at_iso": str(one_time.get("expires_at_iso") or ""),
        "local_preview_only": False,
        "delivery_status": "sent" if not _local_preview_request(request_context) else "preview_only",
        "raw_secret_echoed": False,
    }
    if _local_preview_request(request_context):
        response["local_preview_only"] = True
        response["preview_code"] = str(one_time.get("verification_code") or "")
    return response


def browser_auth_verify_code(
    payload: Dict[str, Any] | None = None,
    request_meta: Dict[str, str] | None = None,
    request_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    payload = payload if isinstance(payload, dict) else {}
    challenge_id = str(payload.get("challenge_id") or "").strip()
    if not challenge_id:
        return {
            "ok": False,
            "status_code": 400,
            "detail": "challenge_id_required",
        }

    return_to = google_oauth._safe_return_to(payload.get("return_to") or "/ops/command")
    challenge = identity_login.store.get_challenge(challenge_id)
    metadata = challenge.get("metadata") if isinstance(challenge, dict) and isinstance(challenge.get("metadata"), dict) else {}
    host_login = str(metadata.get("surface") or "").strip().lower() == "host_workspace"
    verification_payload: Dict[str, Any] = {
        "workspace_id": payload.get("workspace_id") or challenge.get("workspace_id") or identity_login.DEFAULT_WORKSPACE_ID,
        "verification_code": payload.get("verification_code") or payload.get("code") or "",
        "session_ttl_seconds": payload.get("session_ttl_seconds") or payload.get("ttl_seconds"),
    }
    trusted_role = ""
    trusted_scopes: List[str] = []
    if host_login:
        host_context = _host_workspace_request_context(request_context)
        if host_context.get("ok") is not True:
            return host_context
        challenge_workspace_id = str(challenge.get("workspace_id") or "")
        if not challenge_workspace_id or challenge_workspace_id != str(host_context.get("workspace_id") or ""):
            return {"ok": False, "status_code": 403, "detail": "host_workspace_access_changed"}
        email_hash = str(challenge.get("subject_hash") or "")
        membership_access = _host_membership_access(challenge_workspace_id, email_hash)
        if not membership_access:
            return {"ok": False, "status_code": 403, "detail": "host_sign_in_unavailable"}
        verification_payload["workspace_id"] = challenge_workspace_id
        trusted_role = str(membership_access["role"])
        trusted_scopes = list(membership_access["scopes"])
    elif (
        str(challenge.get("purpose") or "").strip().lower() == "operator_portal"
        and str(metadata.get("surface") or "").strip().lower() in {"ops_command", "operator_portal"}
    ):
        challenge_workspace_id = str(challenge.get("workspace_id") or "").strip()
        operator_access = workspace_access.resolve_ops_workspace_access(
            str(challenge.get("subject_hash") or ""),
            challenge_workspace_id,
        )
        if operator_access.get("ok") is not True:
            return operator_access
        role_context = operator_access.get("role_context") if isinstance(operator_access.get("role_context"), dict) else {}
        verification_payload["workspace_id"] = challenge_workspace_id
        trusted_role = str(role_context.get("role") or "").strip().lower()
        trusted_scopes = [str(scope).strip() for scope in role_context.get("scopes") or [] if str(scope).strip()]
    verification_options = (
        {"trusted_role": trusted_role, "trusted_scopes": trusted_scopes}
        if host_login
        or (
            str(challenge.get("purpose") or "").strip().lower() == "operator_portal"
            and str(metadata.get("surface") or "").strip().lower() in {"ops_command", "operator_portal"}
        )
        else {}
    )
    verified = identity_login.verify_login_challenge(
        challenge_id,
        verification_payload,
        request_meta,
        **verification_options,
    )
    if verified.get("ok") is not True:
        return verified

    return {
        "ok": True,
        "redirect": return_to,
        "challenge": verified.get("challenge", {}),
        "session": verified.get("session", {}),
        "set_cookie_headers": google_oauth._session_cookie_headers(
            verified,
            request_context=request_context,
            return_to=return_to,
        ),
        "raw_secret_echoed": False,
    }


def _require_identity_admin(request: Request) -> Dict[str, Any]:
    resolved = identity_session.resolve_access_context(
        {},
        request.headers,
        method=request.method,
        path=request.url.path,
        request_meta=_request_meta(request),
        require_identity=True,
    )
    if resolved.get("ok") is True:
        actor = resolved.get("actor") if isinstance(resolved.get("actor"), dict) else {}
        role = str(actor.get("role") or "").strip().lower()
        scopes = {str(scope).strip().lower() for scope in actor.get("scopes", []) if str(scope).strip()}
        if role in {"admin", "super_admin", "ops_manager"} or "identity.admin" in scopes:
            return {
                "ok": True,
                "auth_mode": "signed_liveuin_session",
                "identity_session": identity_session.public_context(resolved),
            }
        raise HTTPException(
            status_code=403,
            detail="identity_admin_authorization_required",
        )

    bootstrap = service_secrets.authorize_identity_admin_bootstrap(request.headers)
    if bootstrap.get("ok") is True:
        return bootstrap
    raise HTTPException(
        status_code=int(bootstrap.get("status_code") or 401),
        detail=str(bootstrap.get("detail") or "identity_admin_authorization_required"),
    )


def _redirect_with_cookies(response: Dict[str, Any]) -> RedirectResponse:
    redirect_url = str(response.get("redirect_url") or "/ops/auth-pending")
    status_code = int(response.get("status_code") or 302)
    redirect = RedirectResponse(url=redirect_url, status_code=status_code)

    for cookie_header in response.get("set_cookie_headers") or []:
        cookie_value = str(cookie_header or "").strip()
        if cookie_value:
            redirect.headers.append("set-cookie", cookie_value)

    return redirect


def _identity_admin_actor_id(admin_context: Dict[str, Any]) -> str:
    identity_context = admin_context.get("identity_session") if isinstance(admin_context.get("identity_session"), dict) else {}
    actor = identity_context.get("actor") if isinstance(identity_context.get("actor"), dict) else {}
    actor_id = str(actor.get("actor_id") or "").strip()
    if actor_id:
        return actor_id
    # Bootstrap-token admin access has no signed session actor, so continuity writes
    # stamp the shared bootstrap actor label instead of dropping the actor entirely.
    if str(admin_context.get("auth_mode") or "").strip() == "protected_admin_bootstrap_token":
        return "ops:identity_admin"
    return ""


# LIVEUIN-CORE-READ-GUARD-20261008 (upgrade-bot): signed, workspace-bound private reads
try:
    from . import core_private_read_scope as private_read
except ImportError:  # pragma: no cover - supports direct app-folder deployment.
    import core_private_read_scope as private_read
IDENTITY_STATUS_READ_ROLES = {"admin", "identity_admin", "ops_manager", "super_admin"}  # LIVEUIN-CORE-READ-GUARD-20261008
IDENTITY_STATUS_READ_SCOPES = ("identity.", "ops.")  # LIVEUIN-CORE-READ-GUARD-20261008


def _liveuin_private_read(request, *, path, requested_workspace_id, allowed_roles, scope_prefixes):
    """LIVEUIN-CORE-READ-GUARD-20261008: private_read.require_private_read (unchanged shared module), except that a VERIFIED
    liveuin_session whose role is ('admin', 'super_admin') counts as holding every read scope this guard checks
    (support., demand., viewing, trust., identity., ops.). Other roles (incl. trust_reviewer) are unchanged."""
    result = private_read.require_private_read(
        request, path=path, requested_workspace_id=requested_workspace_id,
        allowed_roles=allowed_roles, scope_prefixes=scope_prefixes,
    )
    if not isinstance(result, dict) or result.get("ok") is not False or result.get("detail") != "private_reader_forbidden":
        return result
    resolved = private_read.identity_session.resolve_access_context(
        headers=request.headers,
        method=request.method,
        path=path,
        request_meta={
            "ip": request.client.host if request.client else "",
            "user_agent": str(request.headers.get("user-agent") or "")[:500],
            "referer": str(request.headers.get("referer") or "")[:500],
        },
        require_identity=True,
    )
    if not isinstance(resolved, dict) or resolved.get("ok") is False:
        return result
    identity = resolved.get("identity_session") if isinstance(resolved.get("identity_session"), dict) else {}
    if identity.get("credential_kind") != "liveuin_session" or identity.get("verified") is not True:
        return result
    access = resolved.get("access") if isinstance(resolved.get("access"), dict) else {}
    actor = access.get("actor") if isinstance(access.get("actor"), dict) else resolved.get("actor") if isinstance(resolved.get("actor"), dict) else {}
    role = str(actor.get("role") or "").strip().lower()
    actor_id = str(actor.get("actor_id") or "").strip()
    if role not in ('admin', 'super_admin') or not actor_id:
        return result
    workspace_id = str(access.get("workspace_id") or resolved.get("workspace_id") or "").strip()
    if not workspace_id or (requested_workspace_id and requested_workspace_id != workspace_id):
        return {"ok": False, "detail": "identity_session_workspace_mismatch", "status_code": 403}
    return {"ok": True, "workspace_id": workspace_id, "actor_id": actor_id, "role": role}


@router.get("/api/core/identity/status")
def core_identity_status(request: Request, response: Response) -> Dict[str, Any]:
    # LIVEUIN-CORE-READ-GUARD-20261008
    response.headers.update(private_read.PRIVATE_NO_STORE_HEADERS)
    scope = _raise_if_error(_liveuin_private_read(
        request, path="/api/core/identity/status", requested_workspace_id=request.query_params.get("workspace_id", ""),
        allowed_roles=IDENTITY_STATUS_READ_ROLES, scope_prefixes=IDENTITY_STATUS_READ_SCOPES,
    ))
    return identity_svc.identity_status()


@router.get("/api/core/identity/auth-policy/status")
def core_identity_auth_policy_status(
    workspace_id: str = Query(auth_policy.DEFAULT_WORKSPACE_ID, max_length=96),
    locale_mode: str = Query("auto", max_length=40),
) -> Dict[str, Any]:
    return auth_policy.auth_policy_status(workspace_id, locale_mode)


@router.get("/api/ops/auth/google/status")
def core_identity_google_status(
    workspace_id: str = Query(google_oauth.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    return google_oauth.google_oauth_status(workspace_id)


@router.get("/api/ops/auth/google")
def core_identity_google_start(request: Request) -> Dict[str, Any]:
    result = _raise_if_error(google_oauth.google_authorization_start(_query_map(request), _request_meta(request)))
    if result.get("redirect_url"):
        return _redirect_with_cookies(result)
    return result


@router.get("/api/ops/auth/google/callback")
def core_identity_google_callback(request: Request) -> Dict[str, Any]:
    result = _raise_if_error(google_oauth.google_callback_response(_query_map(request), _request_meta(request)))
    if result.get("redirect_url"):
        return _redirect_with_cookies(result)
    return result


@router.post("/api/core/identity/links")
def core_identity_link(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return _raise_if_error(identity_svc.link_identity(payload, _request_meta(request)))


@router.get("/api/core/identity/resolve")
def core_identity_resolve(
    request: Request,
    provider: str = Query("", max_length=80),
    provider_user_id: str = Query("", max_length=256),
    unionid: str = Query("", max_length=256),
    workspace_id: str = Query(identity_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return _raise_if_error(
        identity_svc.resolve_identity(
            provider=provider,
            provider_user_id=provider_user_id,
            unionid=unionid,
            workspace_id=workspace_id,
        )
    )


@router.get("/api/core/identity/persons/{person_id}")
def core_identity_person(
    request: Request,
    person_id: str,
    workspace_id: str = Query(identity_svc.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return _raise_if_error(identity_svc.get_person(person_id, workspace_id))


@router.get("/api/core/identity/persons/{person_id}/primestay-guest-projection")
def core_identity_primestay_guest_projection(
    request: Request,
    person_id: str,
    case_id: str = Query("", max_length=120),
    request_id: str = Query("", max_length=120),
) -> Dict[str, Any]:
    path = f"/api/core/identity/persons/{person_id}/primestay-guest-projection"
    context = _raise_if_error(
        ps05_guest_projection.resolve_verified_context(
            headers=request.headers,
            method=request.method,
            path=path,
            request_meta=_request_meta(request),
        )
    )
    return _raise_if_error(
        ps05_guest_projection.get_primestay_guest_projection(
            person_id,
            context,
            requested_case_id=case_id,
            requested_request_id=request_id,
        )
    )


@router.post("/api/core/identity/continuity/provider-link")
def core_identity_continuity_provider_link(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    admin = _require_identity_admin(request)
    actor_id = _identity_admin_actor_id(admin)
    return _raise_if_error(identity_svc.continuity_provider_link({**payload, "actor_id": actor_id}, _request_meta(request)))


@router.post("/api/core/identity/continuity/merge")
def core_identity_continuity_merge(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    admin = _require_identity_admin(request)
    actor_id = _identity_admin_actor_id(admin)
    return _raise_if_error(identity_svc.continuity_merge({**payload, "actor_id": actor_id}, _request_meta(request)))


@router.post("/api/core/identity/continuity/split")
def core_identity_continuity_split(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    admin = _require_identity_admin(request)
    actor_id = _identity_admin_actor_id(admin)
    return _raise_if_error(identity_svc.continuity_split({**payload, "actor_id": actor_id}, _request_meta(request)))


@router.post("/api/core/identity/continuity/unlink")
def core_identity_continuity_unlink(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    admin = _require_identity_admin(request)
    actor_id = _identity_admin_actor_id(admin)
    return _raise_if_error(identity_svc.continuity_unlink({**payload, "actor_id": actor_id}, _request_meta(request)))


@router.post("/api/core/identity/continuity/quarantine")
def core_identity_continuity_quarantine(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    admin = _require_identity_admin(request)
    actor_id = _identity_admin_actor_id(admin)
    return _raise_if_error(identity_svc.continuity_quarantine({**payload, "actor_id": actor_id}, _request_meta(request)))


@router.post("/api/core/identity/continuity/recover")
def core_identity_continuity_recover(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    admin = _require_identity_admin(request)
    actor_id = _identity_admin_actor_id(admin)
    return _raise_if_error(identity_svc.continuity_recover({**payload, "actor_id": actor_id}, _request_meta(request)))


@router.get("/api/core/identity/continuity/decisions")
def core_identity_continuity_decisions(
    request: Request,
    workspace_id: str = Query(identity_svc.DEFAULT_WORKSPACE_ID, max_length=96),
    person_id: str = Query("", max_length=96),
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return _raise_if_error(identity_svc.list_continuity_decisions(workspace_id, person_id, limit))


@router.get("/api/core/identity/login/status")
def core_identity_login_status(request: Request) -> Dict[str, Any]:
    _require_identity_admin(request)
    return identity_login.login_status()


@router.post("/api/ops/auth/request_code")
def ops_auth_request_code_compat(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(browser_auth_request_code(payload, _request_meta(request), _request_context(request)))


@router.post("/api/ops/auth/verify-code")
def ops_auth_verify_code_compat(
    request: Request,
    response: Response,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    result = _raise_if_error(browser_auth_verify_code(payload, _request_meta(request), _request_context(request)))
    for cookie_header in result.get("set_cookie_headers") or []:
        cookie_value = str(cookie_header or "").strip()
        if cookie_value:
            response.headers.append("set-cookie", cookie_value)
    return result


@router.get("/api/core/identity/workspace-access/status")
def core_identity_workspace_access_status(
    request: Request,
    workspace_id: str = Query(workspace_access.DEFAULT_WORKSPACE_ID, max_length=96),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return workspace_access.workspace_access_status(workspace_id)


@router.post("/api/core/identity/workspaces/host-pilot")
def core_identity_host_pilot_workspace_provision(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    admin = _require_identity_admin(request)
    return _raise_if_error(
        workspace_access.provision_host_pilot_workspace(
            payload,
            actor_id=_identity_admin_actor_id(admin),
            idempotency_key=str(request.headers.get("idempotency-key") or ""),
            request_meta=_request_meta(request),
        )
    )


@router.get("/api/core/identity/workspace-memberships")
def core_identity_workspace_memberships(
    request: Request,
    workspace_id: str = Query(workspace_access.DEFAULT_WORKSPACE_ID, max_length=96),
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return workspace_access.list_workspace_memberships(workspace_id, limit)


@router.get("/api/core/identity/workspace-invites")
def core_identity_workspace_invites(
    request: Request,
    workspace_id: str = Query(workspace_access.DEFAULT_WORKSPACE_ID, max_length=96),
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return workspace_access.list_workspace_invites(workspace_id, limit)


@router.post("/api/core/identity/workspace-memberships")
def core_identity_workspace_membership_grant(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    admin_context = _require_identity_admin(request)
    authenticated_approver_id = _identity_admin_actor_id(admin_context)
    return _raise_if_error(
        workspace_access.grant_workspace_membership(
            payload,
            _request_meta(request),
            authenticated_approver_id=authenticated_approver_id,
        )
    )


@router.post("/api/core/identity/workspace-invites")
def core_identity_workspace_invite(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    admin_context = _require_identity_admin(request)
    authenticated_approver_id = _identity_admin_actor_id(admin_context)
    return _raise_if_error(
        workspace_access.invite_workspace_member(
            payload,
            _request_meta(request),
            authenticated_approver_id=authenticated_approver_id,
        )
    )


@router.get("/api/core/identity/profile-authorizations")
def core_identity_profile_authorizations(
    request: Request,
    workspace_id: str = Query(profile_authorization.DEFAULT_WORKSPACE_ID, max_length=96),
    person_id: str = Query("", max_length=120),
    account_id: str = Query("", max_length=120),
    profile_key: str = Query("", max_length=80),
    include_history: bool = Query(False),
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return _raise_if_error(
        profile_authorization.list_profile_authorizations(
            workspace_id=workspace_id,
            person_id=person_id,
            account_id=account_id,
            profile_key=profile_key,
            include_history=include_history,
            limit=limit,
        )
    )


@router.post("/api/core/identity/profile-authorizations/tenant/sync")
def core_identity_tenant_profile_authorization_sync(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    admin = _require_identity_admin(request)
    actor_id = _identity_admin_actor_id(admin)
    return _raise_if_error(
        profile_authorization.sync_tenant_authorization_from_case(
            {**payload, "changed_by": str(payload.get("changed_by") or actor_id or "ops:identity_admin")},
            _request_meta(request),
        )
    )


@router.post("/api/core/identity/profile-authorizations/localpro/sync")
def core_identity_localpro_profile_authorization_sync(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    admin = _require_identity_admin(request)
    actor_id = _identity_admin_actor_id(admin)
    return _raise_if_error(
        profile_authorization.sync_localpro_authorization_from_vendor(
            {**payload, "changed_by": str(payload.get("changed_by") or actor_id or "ops:identity_admin")},
            _request_meta(request),
        )
    )


@router.post("/api/core/identity/profile-authorizations/{entitlement_id}/transition")
def core_identity_profile_authorization_transition(
    entitlement_id: str,
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    admin = _require_identity_admin(request)
    actor_id = _identity_admin_actor_id(admin)
    return _raise_if_error(
        profile_authorization.transition_profile_authorization(
            entitlement_id,
            {**payload, "changed_by": str(payload.get("changed_by") or actor_id or "ops:identity_admin")},
            _request_meta(request),
        )
    )


@router.post("/api/core/identity/login/challenges")
def core_identity_login_create(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(identity_login.create_login_challenge(payload, _request_meta(request)))


@router.get("/api/core/identity/login/challenges")
def core_identity_login_list(
    request: Request,
    workspace_id: str = Query(identity_login.DEFAULT_WORKSPACE_ID, max_length=96),
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return _raise_if_error(identity_login.list_login_challenges(workspace_id, limit))


@router.post("/api/core/identity/login/challenges/{challenge_id}/verify")
def core_identity_login_verify(
    request: Request,
    challenge_id: str,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(identity_login.verify_login_challenge(challenge_id, payload, _request_meta(request)))


@router.post("/api/core/identity/login/challenges/{challenge_id}/cancel")
def core_identity_login_cancel(
    request: Request,
    challenge_id: str,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    return _raise_if_error(identity_login.cancel_login_challenge(challenge_id, payload, _request_meta(request)))


@router.get("/api/core/identity/session/status")
def core_identity_session_status(request: Request) -> Dict[str, Any]:
    _require_identity_admin(request)
    return identity_session.status()


@router.post("/api/core/identity/session/resolve")
def core_identity_session_resolve(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    _require_authenticated_identity(request)
    return _raise_if_error(
        identity_session.resolve_access_context(
            payload,
            request.headers,
            method=request.method,
            path=request.url.path,
            request_meta=_request_meta(request),
        )
    )


@router.post("/api/core/identity/session/issue")
def core_identity_session_issue(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return _raise_if_error(identity_session.issue_session(payload, _request_meta(request)))


@router.post("/api/core/identity/session/revoke")
def core_identity_session_revoke(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return _raise_if_error(identity_session.revoke_session(payload, _request_meta(request)))


@router.post("/api/core/identity/logout")
def core_identity_logout(
    request: Request,
    response: Response,
) -> Dict[str, Any]:
    result = identity_session.logout_session(
        request.headers,
        request_context=_request_context(request),
        request_meta=_request_meta(request),
    )
    for cookie_header in result.get("set_cookie_headers") or []:
        response.headers.append("set-cookie", str(cookie_header))
    result.pop("set_cookie_headers", None)
    return result


@router.get("/api/core/identity/credentials")
def core_identity_credentials(
    request: Request,
    workspace_id: str = Query(identity_session.DEFAULT_WORKSPACE_ID, max_length=96),
    limit: int = Query(100, ge=1, le=500),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return _raise_if_error(identity_session.list_credentials(workspace_id, limit))


@router.post("/api/core/identity/api-keys")
def core_identity_api_keys_issue(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return _raise_if_error(identity_session.issue_api_key(payload, _request_meta(request)))


@router.post("/api/core/identity/api-keys/revoke")
def core_identity_api_keys_revoke(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return _raise_if_error(identity_session.revoke_api_key(payload, _request_meta(request)))


@router.post("/api/core/identity/api-keys/rotate")
def core_identity_api_keys_rotate(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return _raise_if_error(identity_session.rotate_api_key(payload, _request_meta(request)))
