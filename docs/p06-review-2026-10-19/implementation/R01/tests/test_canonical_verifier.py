"""Exact deployed verifier functions with a synthetic in-memory store.
Never import the live Identity module or open its real store.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import time
from typing import Any, Dict, Mapping
from types import SimpleNamespace
import pytest

ROOT=Path(__file__).resolve().parents[1]

@pytest.fixture
def verifier(monkeypatch):
    monkeypatch.setenv('LIVEUIN_IDENTITY_SESSION_SIGNING_SECRET','SYNTHETIC-ISOLATED-TEST-SECRET-NOT-A-PRODUCTION-KEY')
    monkeypatch.setenv('LIVEUIN_IDENTITY_SESSION_MAX_AGE_SECONDS','300')
    monkeypatch.setenv('LIVEUIN_IDENTITY_CREDENTIAL_STORE_ENFORCEMENT','1')
    record={'workspace_id':'liveuin_first_party','actor_id':'fixture.platform.admin','role':'ops_manager','auth_method':'signed_internal_session','scopes':['ops.theme.write']}
    state={'active':True,'found':True,'validation':'session_active','record':record}
    calls=[]
    def validate(key,workspace_id=''):
        calls.append((key,workspace_id))
        return state
    ns={**globals(),'DEFAULT_WORKSPACE_ID':'laijuzhu','DEFAULT_SESSION_MAX_AGE_SECONDS':300,'credential_store':SimpleNamespace(validate_session_hash=validate)}
    exec(compile((ROOT/'evidence/canonical-verifier-source.py').read_text(),'<deployed-verifier-functions>','exec'),ns)
    headers=ns['sign_session_headers']({**record,'session_id':'sess_SYNTHETIC_ISOLATED','issued_at':str(int(time.time()))})
    return SimpleNamespace(ns=ns,headers=headers,state=state,calls=calls)


def test_signed_canonical_fixture_passes_actual_verifier(verifier):
    result=verifier.ns['_session_header_validation'](verifier.headers)
    assert result['verified'] is True
    assert result['validation']=='signed_session_verified_store_active'
    assert verifier.calls[0][1]=='liveuin_first_party'

@pytest.mark.parametrize('field,value', [
    ('X-LiveUIN-Role','super_admin'), ('X-LiveUIN-Workspace-Id','test.staff'),
    ('X-LiveUIN-Actor-Id','another_actor'), ('X-LiveUIN-Scopes','identity.admin'),
    ('X-LiveUIN-Session-Signature','invalid'),
])
def test_tampered_claims_refused_before_store(verifier,field,value):
    headers={**verifier.headers,field:value}
    assert verifier.ns['_session_header_validation'](headers)['verified'] is False
    assert not verifier.calls


def test_expired_signature_refused(verifier):
    values=verifier.ns['_session_header_values'](verifier.headers)
    headers=verifier.ns['sign_session_headers']({**values,'issued_at':str(int(time.time())-1000)})
    result=verifier.ns['_session_header_validation'](headers)
    assert result['verified'] is False and result['validation']=='session_signature_expired'
    assert not verifier.calls

@pytest.mark.parametrize('reason',['session_revoked','session_expired','session_rotated','session_inactive','session_store_missing'])
def test_canonical_store_refusal_is_enforced(verifier,reason):
    verifier.state.update(active=False,validation=reason)
    result=verifier.ns['_session_header_validation'](verifier.headers)
    assert result['verified'] is False and result['validation']==reason


def test_signed_store_workspace_mismatch_is_refused(verifier):
    verifier.state['record']['workspace_id']='test.staff'
    result=verifier.ns['_session_header_validation'](verifier.headers)
    assert result['verified'] is False and result['validation']=='session_store_claim_mismatch'
