"""Isolated AUTH02 policy/side-effect tests; no network or database access allowed."""
import hashlib, importlib.util, json, os, pathlib, sys, unittest
from unittest.mock import MagicMock, patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path[:0]=[str(ROOT/'candidate/deploy'),'/private/tmp/liveuin-p06-audit-20261019/reaudit/auth02-contract-tests/source']
for key in list(os.environ):
    if key.startswith(('LIVEUIN_','OTP_','PG','DATABASE_')):os.environ.pop(key)
# Tests use synthetic identifiers; the owner and named account are never contacted.
EMAIL='fixture.parent@example.invalid';OTHER='unapproved@example.invalid';WORKSPACE='auth02-fixture'
H=lambda value:hashlib.sha256(value.encode()).hexdigest()
GOOD={'schema_version':1,'workspace_id':WORKSPACE,'allowed_email_sha256':[H(EMAIL)]}
BASE={'LIVEUIN_PUBLIC_WORKSPACE_ID':WORKSPACE,'LIVEUIN_PUBLIC_ADMISSION_COHORT_JSON':json.dumps(GOOD),'LIVEUIN_PUBLIC_REGISTRATION_ENABLED':'true','LIVEUIN_PUBLIC_TERMS_VERSION':'fixture-terms'}
os.environ.update(BASE)
blocked={'network':0,'database':0}
def audit(event,args):
    if event=='sqlite3.connect':blocked['database']+=1;raise AssertionError('database access forbidden')
    if event.startswith('socket.') and event not in {'socket.__new__','socket.gethostname'}:blocked['network']+=1;raise AssertionError('network forbidden')
    if event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn'}:raise AssertionError('process forbidden')
sys.addaudithook(audit)
import core_identity_release_admission as admission
import core_identity_public as public
import core_identity_social as social
import core_identity_session as session

ACCOUNT={'account_id':'acct_fixture','person_id':'per_fixture','workspace_id':WORKSPACE,'email_hash':H(EMAIL),'email_verified_at':1,'status':'profile_incomplete','tenant_entitlement_state':'not_issued','profile_completion_state':'incomplete'}
UNAPPROVED={**ACCOUNT,'email_hash':H(OTHER)}
RESOLVED={'ok':True,'actor':{'actor_id':ACCOUNT['person_id']},'workspace_id':WORKSPACE}

class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.env=patch.dict(os.environ,BASE,clear=False);self.env.start();self.addCleanup(self.env.stop)
        profiles=patch.object(public.identity_store,"list_profile_entitlements",return_value=[]);profiles.start();self.addCleanup(profiles.stop)
    def deny(self,result):
        self.assertIs(result.get('ok'),False)
        self.assertEqual(result.get('status_code'),403)
        self.assertEqual(result.get('error',{}).get('code'),'pilot_admission_required')
    def test_valid_acl_is_not_authentication(self):
        self.assertTrue(admission.permits_email_hash(H(EMAIL),WORKSPACE))
        self.assertTrue(admission.permits_account(ACCOUNT))
        for change in [{'email_verified_at':0},{'email_verified_at':True},{'email_verified_at':'1'},{'person_id':''},{'account_id':''},{'workspace_id':'other'},{'email_hash':H(OTHER)}]:
            with self.subTest(change=change):self.assertFalse(admission.permits_account({**ACCOUNT,**change}))
    def test_invalid_configuration_always_closed(self):
        raw_values=['','null','[]','1','"x"','{','{"schema_version":1,"schema_version":1}',json.dumps({**GOOD,'schema_version':True}),json.dumps({**GOOD,'schema_version':2}),json.dumps({**GOOD,'workspace_id':'*'}),json.dumps({**GOOD,'workspace_id':'other'}),json.dumps({**GOOD,'allowed_email_sha256':[]}),json.dumps({**GOOD,'allowed_email_sha256':[H(EMAIL).upper()]}),json.dumps({**GOOD,'allowed_email_sha256':[H(EMAIL),H(EMAIL)]}),json.dumps({**GOOD,'allowed_email_sha256':[None]}),json.dumps({**GOOD,'extra':True})]
        for raw in raw_values:
            with self.subTest(raw=raw),patch.dict(os.environ,{admission.COHORT_ENV:raw}):self.assertFalse(admission.permits_email_hash(H(EMAIL),WORKSPACE))
    def test_no_plus_alias_or_dot_collapsing(self):
        self.assertEqual(public._email('  Fixture.Parent+pilot@Example.invalid '),'fixture.parent+pilot@example.invalid')
        self.assertNotEqual(public._email_hash('fixture.parent+pilot@example.invalid'),public._email_hash('fixtureparent@example.invalid'))
    def test_registration_denied_before_store_hash_password_or_mail(self):
        with patch.object(public,'store') as store,patch.object(public,'_password_hash') as hash_pw,patch.object(public,'_registration_delivery') as mail:
            self.deny(public.start_registration({'email':OTHER,'password':'Fixture-password-1234','accepted_terms_version':'fixture-terms'}))
            self.assertEqual(store.mock_calls,[]);hash_pw.assert_not_called();mail.assert_not_called()
    def test_password_denied_before_store_or_verifier(self):
        with patch.object(public,'store') as store,patch.object(public,'_password_matches') as verifier:
            self.deny(public.password_sign_in({'email':OTHER,'password':'Fixture-password-1234'}))
            self.assertEqual(store.mock_calls,[]);verifier.assert_not_called()
    def test_allowed_email_still_requires_password(self):
        with patch.object(public.store,'allow_rate',return_value=True),patch.object(public.store,'get_account_by_email_hash',return_value=ACCOUNT),patch.object(public,'_password_matches',return_value=False) as check,patch.object(public,'_issue_session') as issued:
            result=public.password_sign_in({'email':EMAIL,'password':'wrong'})
            self.assertFalse(result['ok']);self.assertEqual(result['status_code'],401);check.assert_called_once();issued.assert_not_called()
    def test_existing_pending_registration_cannot_bypass_hold(self):
        for name in ['verify_registration','resend_registration']:
            with self.subTest(name=name),patch.object(public,'store') as store,patch.object(public,'_registration_delivery') as mail:
                store.get_registration.return_value={'workspace_id':WORKSPACE,'email_hash':H(OTHER),'status':'email_verification_pending'}
                self.deny(getattr(public,name)('reg_fixture',{'email':EMAIL,'code':'000000'}))
                self.assertEqual([c[0] for c in store.mock_calls],['get_registration']);mail.assert_not_called()
    def test_all_session_issuance_auth_methods_denied_before_any_write(self):
        for method in ['public_password','public_email_registration','public_google','public_apple','public_tenant_onboarding','public_session_refresh']:
            with self.subTest(method=method),patch.object(public.identity_session,'issue_session') as issue,patch.object(public,'store') as store:
                self.deny(public._issue_session(UNAPPROVED,{},method));issue.assert_not_called();self.assertEqual(store.mock_calls,[])
    def test_approved_issue_retains_member_and_existing_scopes(self):
        with patch.object(public.identity_session,'issue_session',return_value={'ok':True,'one_time_credential':{'session_id':'fixture','expires_at':1}}) as issue,patch.object(public.store,'hash_value',side_effect=H):
            result=public._issue_session(ACCOUNT,{},'public_password',persist_refresh=False)
            self.assertNotEqual(result.get('ok'),False)
            payload=issue.call_args.args[0];self.assertEqual(payload['role'],'member');self.assertEqual(payload['scopes'],['identity.session']);self.assertEqual(payload['workspace_id'],WORKSPACE)
    def test_bootstrap_binds_account_then_denies_without_profile_read(self):
        with patch.object(public.store,'get_account',return_value=UNAPPROVED),patch.object(public.identity_store,'get_person') as person,patch.object(public,'_account_payload') as profile:
            result=public.session_bootstrap_projection_result(ACCOUNT['account_id'],ACCOUNT['person_id'],WORKSPACE)
            self.assertEqual(result,{'ok':False,'detail':'pilot_admission_required','status_code':403});person.assert_not_called();profile.assert_not_called()
    def test_cohort_cannot_override_canonical_binding(self):
        with patch.object(public.store,'get_account',return_value=ACCOUNT):
            result=public.session_bootstrap_projection_result('different_account',ACCOUNT['person_id'],WORKSPACE)
            self.assertFalse(result['ok']);self.assertEqual(result['detail'],'session_public_account_projection_unavailable')
    def test_profile_and_onboarding_deny_before_mutation(self):
        for name,args in [('onboarding_status',({},)),('update_profile',({}, {'display_name':'Fixture'})),('complete_onboarding',({},))]:
            with self.subTest(name=name),patch.object(public.identity_session,'resolve_access_context',return_value=RESOLVED),patch.object(public,'store') as store,patch.object(public,'identity_store') as canonical:
                store.get_account_by_person_id.return_value=UNAPPROVED
                self.deny(getattr(public,name)(*args));self.assertEqual([c[0] for c in store.mock_calls],['get_account_by_person_id']);self.assertTrue(all(call[0].startswith("list_profile_entitlements") for call in canonical.mock_calls))
    def test_refresh_denied_before_rotation_or_new_session(self):
        with patch.object(public,'store') as store,patch.object(public.identity_session,'issue_session') as issue:
            store.get_refresh_by_hash.return_value={'status':'active','expires_at':9999999999,'account_id':ACCOUNT['account_id'],'workspace_id':WORKSPACE}
            store.get_account.return_value=UNAPPROVED
            self.deny(public.refresh_session({'refresh_token':'fixture'}));store.rotate_refresh_atomic.assert_not_called();issue.assert_not_called()
    def test_social_existing_link_uses_canonical_account_not_claim_email(self):
        claims={'ok':True,'subject_hash':'verified-subject','email_verified':True,'verified_email_hash':H(EMAIL)}
        with patch.object(social,'_verified_claims',return_value=claims),patch.object(social,'store') as store,patch.object(social,'_store_provider_credential') as cred:
            store.get_provider_identity.return_value={'account_id':ACCOUNT['account_id']};store.get_account.return_value=UNAPPROVED
            self.deny(social.exchange('google',{}));cred.assert_not_called()
    def test_social_unknown_verified_email_denied_before_lookup_or_creation(self):
        claims={'ok':True,'subject_hash':'verified-subject','email_verified':True,'verified_email_hash':H(OTHER)}
        with patch.object(social,'_verified_claims',return_value=claims),patch.object(social,'store') as store,patch.object(social,'_new_social_account') as new:
            store.get_provider_identity.return_value={}
            self.deny(social.exchange('google',{'email':EMAIL}));store.get_account_by_email_hash.assert_not_called();new.assert_not_called()
    def test_social_claim_validation_not_bypassed_by_caller_email(self):
        fail={'ok':False,'status_code':403,'detail':'invalid_provider_token'}
        with patch.object(social,'_verified_claims',return_value=fail) as verify,patch.object(social,'store') as store:
            self.assertEqual(social.exchange('google',{'email':EMAIL}),fail);verify.assert_called_once();self.assertEqual(store.mock_calls,[])
    def test_social_creation_requires_verified_admitted_claims_before_writes(self):
        for claims in [{'email_verified':False,'verified_email_hash':H(EMAIL)},{'email_verified':True,'verified_email_hash':H(OTHER)}]:
            with self.subTest(claims=claims),patch.object(social,'store') as store,patch.object(social,'identity_store') as identity:
                self.deny(social._new_social_account('google',claims,WORKSPACE,{},{}));self.assertEqual(store.mock_calls,[]);self.assertEqual(identity.mock_calls,[])
    def test_provider_link_denied_before_provider_exchange(self):
        with patch.object(public.identity_session,'resolve_access_context',return_value=RESOLVED),patch.object(public.store,'get_account_by_person_id',return_value=UNAPPROVED),patch.object(social,'_verified_claims') as verify:
            self.deny(social.link('google',{},{}));verify.assert_not_called()
    def test_privacy_account_lookup_not_blanket_disabled(self):
        with patch.object(public.identity_session,'resolve_access_context',return_value=RESOLVED),patch.object(public.store,'get_account_by_person_id',return_value=UNAPPROVED):
            account,failure=public._session_account({},{});self.assertEqual(account,UNAPPROVED);self.assertFalse(failure)
    def test_logout_remains_available_with_missing_cohort(self):
        with patch.dict(os.environ,{admission.COHORT_ENV:''}),patch.object(session,'revoke_session',return_value={'ok':True}),patch.object(session.credential_store,'validate_session_hash',return_value={'active':False}):
            self.assertTrue(session.logout_session({'X-LiveUIN-Session-Id':'fixture'})['ok'])
    def test_failed_durable_session_revoke_not_acknowledged(self):
        with patch.object(session,'revoke_session',return_value={'ok':False}),patch.object(session.credential_store,'validate_session_hash',return_value={'active':True}):
            result=session.logout_session({'X-LiveUIN-Session-Id':'fixture'});self.assertFalse(result['ok']);self.assertEqual(result['status_code'],503)
    def test_failed_refresh_revoke_not_acknowledged(self):
        with patch.object(public,'store') as store:
            store.revoke_refresh_for_session.return_value=0
            store.connection.return_value.__enter__.return_value.execute.return_value.fetchone.return_value=(1,)
            with self.assertRaisesRegex(RuntimeError,'identity_refresh_logout_incomplete'):public.revoke_current_session({'X-LiveUIN-Session-Id':'fixture'})
    def test_cookie_refresh_logout_uses_same_canonical_parser(self):
        with patch.object(public,'store') as store:
            store.hash_value.side_effect=H;store.revoke_refresh_for_session.return_value=1
            store.connection.return_value.__enter__.return_value.execute.return_value.fetchone.return_value=None
            self.assertEqual(public.revoke_current_session({'Cookie':'LIVEUIN_SESSION_ID=fixture'}),1)
            store.revoke_refresh_for_session.assert_called_once_with(H('fixture'),'logout')
    def test_readiness_contract_uses_only_mocked_fixture_and_current_acl(self):
        with patch.object(public.identity_store,'list_profile_entitlements',return_value=[]):self.assertTrue(public.session_public_account_projection_ready())
        with patch.dict(os.environ,{admission.COHORT_ENV:''}):self.assertFalse(public.session_public_account_projection_ready())

if __name__=='__main__':
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AdmissionTests))
    print(json.dumps({'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'blocked_io':blocked}))
    sys.exit(not result.wasSuccessful())
