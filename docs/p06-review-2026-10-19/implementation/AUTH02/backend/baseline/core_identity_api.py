from __future__ import annotations

from collections import defaultdict
import hashlib
import os
from typing import Any, Dict, List

from fastapi import APIRouter, Body, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

try:
    from . import core_identity_auth_policy as auth_policy
    from . import core_identity_google_oauth as google_oauth
    from . import core_identity_login as identity_login
    from . import core_identity_public as public_identity
    from . import core_identity_profile_authorization as profile_authorization
    from . import core_identity_service as identity_svc
    from . import core_identity_social as identity_social
    from . import core_identity_account_deletion as account_deletion
    from . import core_identity_session as identity_session
    from . import core_identity_workspace_access as workspace_access
    from . import core_service_secret_resolver as service_secrets
except ImportError:  # pragma: no cover - supports direct app-folder deployment.
    import core_identity_auth_policy as auth_policy
    import core_identity_google_oauth as google_oauth
    import core_identity_login as identity_login
    import core_identity_public as public_identity
    import core_identity_profile_authorization as profile_authorization
    import core_identity_service as identity_svc
    import core_identity_social as identity_social
    import core_identity_account_deletion as account_deletion
    import core_identity_session as identity_session
    import core_identity_workspace_access as workspace_access
    import core_service_secret_resolver as service_secrets


router = APIRouter()

LOCAL_PREVIEW_HOSTS = {"127.0.0.1", "localhost", "host.docker.internal"}


def _request_meta(request: Request) -> Dict[str, str]:
    return {
        "ip": request.client.host if request.client else "",
        "host": str(request.headers.get("host") or "")[:240],
        "user_agent": str(request.headers.get("user-agent") or "")[:500],
        "referer": str(request.headers.get("referer") or "")[:500],
        "request_id": str(request.headers.get("x-request-id") or "")[:80],
    }


def _request_context(request: Request) -> Dict[str, str]:
    return {
        "host": str(request.headers.get("host") or "")[:240],
        "client_ip": request.client.host if request.client else "",
        "scheme": str(request.url.scheme or "")[:24],
        "path": str(request.url.path or "")[:240],
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


def _public_http(response: Dict[str, Any]) -> Any:
    if response.get("ok") is not False:
        return response
    return JSONResponse(
        status_code=int(response.get("status_code") or 400),
        content={
            "ok": False,
            "error": response.get("error") or {
                "code": "identity_error",
                "message": "LiveUIN could not complete that request.",
                "field": None,
                "recoverable": True,
                "next_action": "retry_or_contact_support",
            },
            "request_id": str(response.get("request_id") or ""),
        },
    )


def _public_call(operation: Any, request_meta: Dict[str, Any]) -> Any:
    try:
        return _public_http(operation())
    except Exception:
        return _public_http(public_identity.internal_error(request_meta))


def _public_admin_guard(request: Request) -> Any:
    request_meta = _request_meta(request)
    try:
        _require_identity_admin(request)
    except HTTPException:
        return _public_http(
            public_identity.error(
                "identity_admin_authorization_required",
                403,
                "This identity operation requires LiveUIN administrative authorization.",
                request_meta=request_meta,
                next_action="contact_support",
            )
        )
    return None


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


def _local_preview_request(request_context: Dict[str, Any] | None = None, request_meta: Dict[str, Any] | None = None) -> bool:
    context = request_context if isinstance(request_context, dict) else {}
    host = str(context.get("host") or "").split(":", 1)[0].strip().lower()
    client_ip = str((request_meta or {}).get("ip") or context.get("client_ip") or "").strip()
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
    if host in trusted_hosts or (configured_host and host == configured_host):
        return True
    if host not in LOCAL_PREVIEW_HOSTS:
        return False
    try:
        import ipaddress
        return ipaddress.ip_address(client_ip).is_loopback
    except ValueError:
        return False


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
    if not purpose:
        if requested_role in {"agent", "connector_admin"} or surface.startswith("connect") or surface.startswith("partner"):
            purpose = "connect_admin"
        else:
            purpose = "operator_portal"

    created = identity_login.create_login_challenge(
        {
            "workspace_id": payload.get("workspace_id") or identity_login.DEFAULT_WORKSPACE_ID,
            "channel": "email",
            "purpose": purpose,
            "surface": payload.get("surface") or "ops_command",
            "target_hash": hashlib.sha256(email.encode("utf-8")).hexdigest(),
            "role": requested_role or ("agent" if purpose == "connect_admin" else "operator"),
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
    response = {
        "ok": True,
        "challenge_id": str(challenge.get("challenge_id") or one_time.get("challenge_id") or ""),
        "expires_at": int(one_time.get("expires_at") or 0),
        "expires_at_iso": str(one_time.get("expires_at_iso") or ""),
        "local_preview_only": False,
        "raw_secret_echoed": False,
    }
    if _local_preview_request(request_context, request_meta):
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
    verified = identity_login.verify_login_challenge(
        challenge_id,
        {
            "workspace_id": payload.get("workspace_id") or identity_login.DEFAULT_WORKSPACE_ID,
            "verification_code": payload.get("verification_code") or payload.get("code") or "",
            "session_ttl_seconds": payload.get("session_ttl_seconds") or payload.get("ttl_seconds"),
        },
        request_meta,
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


@router.get("/api/core/identity/status")
def core_identity_status() -> Dict[str, Any]:
    return identity_svc.identity_status()


@router.get("/api/core/identity/auth-policy/status")
def core_identity_auth_policy_status(
    workspace_id: str = Query(auth_policy.DEFAULT_WORKSPACE_ID, max_length=96),
    locale_mode: str = Query("auto", max_length=40),
) -> Dict[str, Any]:
    return auth_policy.auth_policy_status(workspace_id, locale_mode)


@router.get("/api/core/identity/providers/status")
def core_identity_provider_status(
    request: Request,
    workspace_id: str = Query("", max_length=96),
) -> Dict[str, Any]:
    return identity_social.provider_status(workspace_id, _request_meta(request))


@router.post("/api/core/identity/providers/{provider}/exchange")
def core_identity_provider_exchange(
    request: Request,
    provider: str,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: identity_social.exchange(provider, payload, request_meta), request_meta)


@router.post("/api/core/identity/providers/{provider}/link")
def core_identity_provider_link(
    request: Request,
    provider: str,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: identity_social.link(provider, payload, request.headers, request_meta), request_meta)


@router.get("/api/core/identity/account-deletion/status")
def core_identity_account_deletion_status(request: Request) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: account_deletion.status_for_session(request.headers, request_meta), request_meta)


@router.post("/api/core/identity/account-deletion/request", status_code=202)
def core_identity_account_deletion_request(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: account_deletion.request_deletion(request.headers, payload, request_meta), request_meta)


@router.post("/api/core/identity/account-deletion/confirm", status_code=202)
def core_identity_account_deletion_confirm(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: account_deletion.confirm_deletion(request.headers, payload, request_meta), request_meta)


@router.post("/api/core/identity/account-deletion/cancel")
def core_identity_account_deletion_cancel(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: account_deletion.cancel_deletion(request.headers, payload, request_meta), request_meta)


@router.post("/api/core/identity/account-deletion/finalize", include_in_schema=False)
def core_identity_account_deletion_finalize(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    denied = _public_admin_guard(request)
    if denied is not None:
        return denied
    request_meta = _request_meta(request)
    deletion_request_id = str(payload.get("deletion_request_id") or "")
    return _public_call(
        lambda: account_deletion.finalize_deletion(deletion_request_id, request_meta, bool(payload.get("force"))),
        request_meta,
    )


@router.post("/api/core/identity/providers/apple/notifications", status_code=202)
def core_identity_apple_server_notification(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: account_deletion.apple_notification(payload, request_meta), request_meta)


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
    denied = _public_admin_guard(request)
    if denied is not None:
        return denied
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
    _require_identity_admin(request)
    return _raise_if_error(workspace_access.grant_workspace_membership(payload, _request_meta(request)))


@router.post("/api/core/identity/workspace-invites")
def core_identity_workspace_invite(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Dict[str, Any]:
    _require_identity_admin(request)
    return _raise_if_error(workspace_access.invite_workspace_member(payload, _request_meta(request)))


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
    denied = _public_admin_guard(request)
    if denied is not None:
        return denied
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


@router.post("/api/core/identity/registrations", status_code=201)
def core_identity_public_registration(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: public_identity.start_registration(payload, request_meta), request_meta)


@router.post("/api/core/identity/registrations/{registration_id}/verify")
def core_identity_public_registration_verify(
    request: Request,
    registration_id: str,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: public_identity.verify_registration(registration_id, payload, request_meta), request_meta)


@router.post("/api/core/identity/registrations/{registration_id}/resend")
def core_identity_public_registration_resend(
    request: Request,
    registration_id: str,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: public_identity.resend_registration(registration_id, payload, request_meta), request_meta)


@router.post("/api/core/identity/sessions/password")
def core_identity_public_password_sign_in(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: public_identity.password_sign_in(payload, request_meta), request_meta)


@router.post("/api/core/identity/founder-qa/access")
def core_identity_founder_qa_access(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: public_identity.founder_qa_access(payload, request_meta), request_meta)


@router.post(
    "/api/core/identity/password-resets/request",
    status_code=202,
    responses={
        202: {
            "description": "Enumeration-safe recovery acknowledgement.",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "required": ["ok", "status", "message", "reset_id", "next_action", "expires_in_seconds", "verification_expiry", "request_id"],
                        "properties": {
                            "ok": {"type": "boolean", "enum": [True]},
                            "status": {"type": "string", "enum": ["recovery_requested"]},
                            "message": {"type": "string"},
                            "reset_id": {"type": "string", "pattern": "^pwr_[0-9a-f]{32}$"},
                            "next_action": {"type": "string", "enum": ["verify_code"]},
                            "expires_in_seconds": {"type": "integer", "minimum": 0},
                            "verification_expiry": {"type": "integer", "minimum": 0},
                            "request_id": {"type": "string"},
                            "enumeration_safe": {"type": "boolean", "enum": [True]},
                        },
                    },
                    "examples": {
                        "known_account": {"value": {"ok": True, "status": "recovery_requested", "message": "If the account is eligible, recovery instructions will be delivered.", "reset_id": "pwr_0123456789abcdef0123456789abcdef", "next_action": "verify_code", "expires_in_seconds": 900, "verification_expiry": 1700000900, "request_id": "req_example_known", "enumeration_safe": True}},
                        "unknown_account": {"value": {"ok": True, "status": "recovery_requested", "message": "If the account is eligible, recovery instructions will be delivered.", "reset_id": "pwr_fedcba9876543210fedcba9876543210", "next_action": "verify_code", "expires_in_seconds": 900, "verification_expiry": 1700000900, "request_id": "req_example_unknown", "enumeration_safe": True}},
                    },
                }
            },
        }
    },
)
def core_identity_public_password_reset_request(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: public_identity.password_reset_request(payload, request_meta), request_meta)


@router.post("/api/core/identity/password-resets/{reset_id}/verify")
def core_identity_public_password_reset_verify(
    request: Request,
    reset_id: str,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: public_identity.password_reset_verify(reset_id, payload, request_meta), request_meta)


@router.post("/api/core/identity/password-resets/complete")
def core_identity_public_password_reset_complete(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: public_identity.password_reset_complete(payload, request_meta), request_meta)


@router.post("/api/core/identity/sessions/refresh")
def core_identity_public_session_refresh(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: public_identity.refresh_session(payload, request_meta), request_meta)


@router.get("/api/core/identity/onboarding/status")
def core_identity_public_onboarding_status(request: Request) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: public_identity.onboarding_status(request.headers, request_meta), request_meta)


@router.patch("/api/core/identity/profile")
def core_identity_public_profile(
    request: Request,
    payload: Dict[str, Any] = Body(default={}),
) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: public_identity.update_profile(request.headers, payload, request_meta), request_meta)


@router.post("/api/core/identity/onboarding/complete")
def core_identity_public_onboarding_complete(request: Request) -> Any:
    request_meta = _request_meta(request)
    return _public_call(lambda: public_identity.complete_onboarding(request.headers, request_meta), request_meta)


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
    resolved = _raise_if_error(
        identity_session.resolve_access_context(
            payload,
            request.headers,
            method=request.method,
            path=request.url.path,
            request_meta=_request_meta(request),
        )
    )
    if resolved.get("ok") is True:
        actor = resolved.get("actor") if isinstance(resolved.get("actor"), dict) else {}
        identity = resolved.get("identity_session") if isinstance(resolved.get("identity_session"), dict) else {}
        if identity.get("public_identity_session"):
            projection_result = public_identity.session_bootstrap_projection_result(
                resolved.get("account_id") or actor.get("account_id"),
                resolved.get("person_id") or actor.get("person_id") or actor.get("actor_id"),
                resolved.get("workspace_id"),
            )
            if projection_result.get("ok") is not True:
                _raise_if_error(
                    public_identity.error(
                        str(projection_result.get("detail") or "session_public_account_projection_unavailable"),
                        int(projection_result.get("status_code") or 403),
                        workspace_id=resolved.get("workspace_id") or "",
                        identity_session={
                            **identity,
                            "resolved": False,
                            "public_identity_session": True,
                            "raw_secret_echoed": False,
                        },
                    )
                )
            projection = projection_result.get("projection") or {}
        else:
            projection = public_identity.session_bootstrap_projection(
                resolved.get("account_id") or actor.get("account_id"),
                resolved.get("person_id") or actor.get("person_id") or actor.get("actor_id"),
                resolved.get("workspace_id"),
            )
        if projection:
            resolved.update(projection)
    return resolved


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
    result["public_refresh_credentials_revoked"] = public_identity.revoke_current_session(request.headers)
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
