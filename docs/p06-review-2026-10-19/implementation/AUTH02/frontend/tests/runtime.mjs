import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const code = fs.readFileSync(path.join(root, 'source/auth02-runtime.js'), 'utf8') +
  '\n' + fs.readFileSync(path.join(root, 'source/bootstrap.js'), 'utf8');
let passed = 0;
const results = [];
function storage() { const data = new Map(); return { getItem:k=>data.get(k)??null, setItem:(k,v)=>data.set(k,String(v)), removeItem:k=>data.delete(k) }; }
function fixture() {
  const row={entitlement_id:'ent_test',account_id:'account_test',person_id:'person_test',workspace_id:'wsp_test',profile_key:'tenant',status:'active',effective_to:0,effective_from:0,expires_at:'',subject_id:'person_test',subject_role:'tenant',allowed_actions:['tenant'],permissions:['tenant'],route_restrictions:[]};
  return {ok:true,account_id:'account_test',person_id:'person_test',workspace_id:'wsp_test',actor:{account_id:'account_test',person_id:'person_test',actor_id:'person_test',role:'tenant',scopes:['tenant'],active_profile_key:'tenant',active_workspace_id:'wsp_test'},identity_session:{resolved:true,verified:true,credential_kind:'liveuin_session',public_identity_session:true},authorized_profiles:[structuredClone(row)],profile_entitlements:[structuredClone(row)],profile_state:'tenant_active',next_action:'tenant_home',access:{case_ids:['case_test'],active_case_id:'case_test'}};
}
function credential() { return {ok:true,status:'authenticated',refresh_token:'synthetic_never_store',one_time_credential:{session_id:'session_test',credential_kind:'liveuin_session',expires_at:Math.floor(Date.now()/1000)+3600,session_headers:{'X-LiveUIN-Workspace-Id':'wsp_test','X-LiveUIN-Actor-Id':'person_test','X-LiveUIN-Role':'member','X-LiveUIN-Session-Id':'session_test','X-LiveUIN-Session-Issued-At':String(Math.floor(Date.now()/1000)),'X-LiveUIN-Auth-Method':'public_password','X-LiveUIN-Session-Signature':'synthetic_signature'}}}; }
function reply(payload,status=200,type='application/json') { return {ok:status>=200&&status<300,status,headers:{get:()=>type},json:async()=>payload}; }
function environment(handler) {
  const calls=[], events=[];
  let saved=null;
  const query={cancelQueries:async()=>events.push('cancel'),clear:()=>events.push('clear'),setQueryData:(key,value)=>{query.value=value;events.push(value.authRequired?'closed':'resolved');}};
  const context={URL,URLSearchParams,AbortController,setTimeout,clearTimeout,Date,console,
    window:{location:{hostname:'app.liveuin.com',protocol:'https:',search:'',replace:target=>events.push('redirect:'+target)},sessionStorage:storage(),alert:()=>events.push('alert')},
    fetch:async(url,options)=>{calls.push({url,options});return handler(url,options,calls.length);},
    ha:()=>saved?.sessionHeaders||{},_x:value=>{saved=structuredClone(value);events.push('store');return saved;},io:()=>{saved=null;events.push('io');},Pu:()=>events.push('selection-clear')};
  vm.createContext(context);vm.runInContext(code,context);
  return {c:context,calls,events,query,get saved(){return saved;}};
}
async function test(name,fn) { await fn();passed++;results.push({name,status:'pass'}); }

await test('canonical active and authorized profiles pass without invented roles',()=>{
  const e=environment(); const f=fixture();
  assert.equal(e.c.auth02Project(f).authRequired,false);
  f.authorized_profiles[0].status=f.profile_entitlements[0].status='authorized';
  assert.equal(e.c.auth02Project(f).authRequired,false);
  assert.deepEqual(Array.from(e.c.auth02Project(f).profileEntitlements,x=>x.profile_key),['tenant']);
});
await test('empty or conflicting canonical projections stay closed',()=>{
  const e=environment();
  for(const mutate of [f=>f.authorized_profiles=[],f=>f.profile_entitlements=[],f=>delete f.authorized_profiles,f=>f.authorized_profiles[0].account_id='other',f=>f.profile_entitlements[0].workspace_id='other',f=>f.profile_entitlements[0].person_id='other',f=>f.authorized_profiles[0].entitlement_id='other',f=>f.actor.account_id='other',f=>delete f.account_id,f=>f.actor.role='']){
    const f=fixture();mutate(f);assert.equal(e.c.auth02Project(f).authRequired,true);
  }
});
await test('unverified, preview, blocked and incomplete identities stay closed',()=>{
  const e=environment();
  for(const mutate of [f=>f.identity_session.verified=false,f=>f.identity_session.verified='true',f=>f.identity_session.resolved=false,f=>f.identity_session.credential_kind='upstream_access_context',f=>f.next_action='complete_onboarding',f=>f.profile_state='deletion_pending',f=>f.authorized_profiles[0].status='pending',f=>f.profile_entitlements[0].status='revoked',f=>f.profile_entitlements[0].profile_key='operator']){
    const f=fixture();mutate(f);assert.equal(e.c.auth02Project(f).authRequired,true);
  }
});
await test('expired/future/malformed entitlement bounds stay closed',()=>{
  const e=environment();
  for(const mutate of [r=>r.effective_to=1,r=>r.effective_to='0',r=>delete r.effective_to,r=>r.effective_from=Math.floor(Date.now()/1000)+100,r=>r.expires_at='invalid',r=>r.expires_at='2000-01-01T00:00:00Z']){
    const f=fixture();mutate(f.profile_entitlements[0]);assert.equal(e.c.auth02Project(f).authRequired,true);
  }
});
await test('selected actor and per-entitlement permissions must agree',()=>{
  const e=environment();
  for(const mutate of [f=>f.actor.scopes=[],f=>f.actor.scopes=['localpro'],f=>f.actor.scopes=['identity.admin'],f=>f.actor.role='super_admin',f=>f.profile_entitlements[0].allowed_actions=['localpro'],f=>f.authorized_profiles[0].permissions=['localpro'],f=>f.actor.active_profile_key='localpro',f=>f.actor.active_workspace_id='another_workspace',f=>f.next_action='localpro_home',f=>f.continuation={state:'tenant_active',next_action:'localpro_home',route:'/localpro/home'}]){
    const f=fixture();mutate(f);assert.equal(e.c.auth02Project(f).authRequired,true);
  }
});
await test('legitimate dual-profile actor retains independent grants and canonical active selection',()=>{
  const e=environment(), f=fixture();
  const pro={...structuredClone(f.profile_entitlements[0]),entitlement_id:'ent_localpro',profile_key:'localpro',subject_role:'vendor',allowed_actions:['localpro'],permissions:['localpro']};
  f.profile_entitlements.push(structuredClone(pro));f.authorized_profiles.push(structuredClone(pro));
  assert.equal(e.c.auth02Project(f).authRequired,false);
  assert.equal(e.c.auth02Project(f).profileEntitlements.length,2);
  f.actor.role='vendor';f.actor.scopes=['localpro'];f.actor.active_profile_key='localpro';
  const projected=e.c.auth02Project(f);
  assert.equal(projected.authRequired,false);assert.equal(projected.defaultProfileKey,'localpro');
  assert.equal(projected.profileEntitlements.length,2);
  assert.equal(e.c.auth02Destination(projected,'?returnTo=%2Ftenant%2Fhome').path,'/localpro/home');
});
await test('safe continuation rejects open redirects, controls, role switches and nested URLs',()=>{
  const e=environment();
  for(const input of ['https://evil.example','//evil.example','/\\evil','/tenant/../ops/login','/%2f%2fevil','/tenant/home%0aX','/tenant/home#fragment','/ops/control','/host/finance','/partner/dashboard','/auth/sign-up','/tenant/home?case_id=a&case_id=b']) assert.equal(e.c.auth02SafeReturn(input),null,input);
  assert.equal(e.c.auth02SafeReturn('/tenant/payments?case_id=case_test&token=secret&returnTo=https://evil').path,'/tenant/payments?case_id=case_test');
  assert.equal(e.c.auth02RequestedReturn('?returnTo=%2Ftenant%2Fhome&return_to=%2Flocalpro%2Fhome'),null);
  assert.equal(e.c.auth02LoginHref('?returnTo=%2Ftenant%2Fpayments%3Fcase_id%3Dcase_test'),'/auth/sign-in?returnTo=%2Ftenant%2Fpayments%3Fcase_id%3Dcase_test');
  const b=e.c.auth02Project(fixture());
  assert.equal(e.c.auth02Destination(b,'?returnTo=%2Flocalpro%2Fhome').path,'/tenant/home');
  assert.equal(e.c.auth02Destination(b,'?returnTo=%2Ftenant%2Fhome%3Fworkspace_id%3Dother').path,'/tenant/home');
});
await test('real password contract uses only email/password then strict resolve',async()=>{
  const e=environment(url=>reply(url.endsWith('/password')?credential():fixture()));
  e.c.window.location.search='?returnTo=%2Ftenant%2Fpayments%3Fcase_id%3Dcase_test';
  const result=await e.c.auth02Password(' TEST@EXAMPLE.INVALID ','password_test',e.query);
  assert.equal(result.destination,'/tenant/payments?case_id=case_test');
  assert.deepEqual(Array.from(result.roles),['tenant']);
  assert.deepEqual(JSON.parse(e.calls[0].options.body),{email:'test@example.invalid',password:'password_test'});
  assert.equal(e.calls[1].url,'/api/core/identity/session/resolve');
  assert.equal(e.calls[1].options.headers['X-LiveUIN-Session-Signature'],'synthetic_signature');
  for(const call of e.calls){assert.equal(call.options.credentials,'include');assert.equal(call.options.cache,'no-store');assert.equal(call.options.redirect,'error');}
  assert.equal(JSON.stringify(e.saved).includes('synthetic_never_store'),false);
  assert.equal(e.query.value.authRequired,false);
});
await test('invalid password never stores credential or calls preview challenge',async()=>{
  const e=environment(()=>reply({ok:false,error:{code:'invalid_credentials'}},401));
  await assert.rejects(e.c.auth02Password('test@example.invalid','wrong',e.query));
  assert.equal(e.saved,null);assert.equal(e.calls.length,1);assert.equal(e.calls[0].url,'/api/core/identity/sessions/password');
});
await test('old account is revoked before a new password attempt and cannot rehydrate on failure',async()=>{
  let release;
  const pending = new Promise(resolve=>release=resolve);
  const e=environment(url=>url.endsWith('/logout')?Promise.resolve(reply({ok:true,status:'identity_session_logged_out'})):url.endsWith('/password')?pending:Promise.resolve(reply(fixture())));
  const old=credential().one_time_credential;
  e.c._x({sessionId:old.session_id,sessionHeaders:old.session_headers,expiresAt:old.expires_at,credentialKind:old.credential_kind});
  const signing=e.c.auth02Password('another@example.invalid','wrong',e.query);
  const rejected=assert.rejects(signing);
  await new Promise(resolve=>setTimeout(resolve,0));
  assert.equal(e.calls[0].url,'/api/core/identity/logout');
  assert.equal(e.calls[1].url,'/api/core/identity/sessions/password');
  const before=e.calls.length;
  assert.equal((await e.c.qx()).authRequired,true);assert.equal(e.calls.length,before);
  assert.equal(e.saved,null);assert.equal(e.query.value.authRequired,true);
  release(reply({ok:false},401));await rejected;
  assert.equal(e.saved,null);assert.equal(e.query.value.authRequired,true);
});
await test('failed old-account revocation preserves retry credential and prevents new password exchange',async()=>{
  const e=environment(()=>reply({ok:false},503));
  const old=credential().one_time_credential;
  e.c._x({sessionId:old.session_id,sessionHeaders:old.session_headers,expiresAt:old.expires_at,credentialKind:old.credential_kind});
  await assert.rejects(e.c.auth02Password('another@example.invalid','password_test',e.query),/Sign out was not confirmed/);
  assert.ok(e.saved);assert.equal(e.c.auth02HasLogoutLock(),true);
  assert.equal(e.calls.length,1);assert.equal(e.calls[0].url,'/api/core/identity/logout');
  assert.equal((await e.c.qx()).authRequired,true);
});
await test('credential storage failure revokes the issued credential using its explicit headers',async()=>{
  const e=environment(url=>reply(url.endsWith('/password')?credential():{ok:true,status:'identity_session_logged_out'}));
  e.c._x=()=>null;
  await assert.rejects(e.c.auth02Password('test@example.invalid','password_test',e.query));
  assert.equal(e.calls.length,2);assert.equal(e.calls[1].url,'/api/core/identity/logout');
  assert.equal(e.calls[1].options.headers['X-LiveUIN-Session-Signature'],'synthetic_signature');
  assert.equal(e.saved,null);assert.equal(e.c.auth02HasLogoutLock(),false);
});
await test('malformed credential or ambiguous response cannot authenticate',async()=>{
  for(const mutate of [p=>p.one_time_credential.session_id='',p=>p.one_time_credential.expires_at=1,p=>p.one_time_credential.session_headers['X-LiveUIN-Session-Signature']='',p=>p.status='preview',p=>delete p.ok]){
    const p=credential();mutate(p);const e=environment(()=>reply(p));
    await assert.rejects(e.c.auth02Password('test@example.invalid','password_test',e.query));assert.equal(e.saved,null);
  }
  for(const [status,type] of [[201,'application/json'],[200,'text/html']]){
    const e=environment(()=>reply(credential(),status,type));
    await assert.rejects(e.c.auth02Password('test@example.invalid','password_test',e.query));assert.equal(e.saved,null);
  }
  for(const malformed of [null,[],true,'not-an-object']){
    const e=environment(()=>reply(malformed));
    await assert.rejects(e.c.auth02Password('test@example.invalid','password_test',e.query),/We could not sign you in/);
    assert.equal(e.saved,null);
  }
});
await test('incomplete profile revokes newly issued session before clearing locally',async()=>{
  const f=fixture();f.authorized_profiles=[];
  const e=environment(url=>reply(url.endsWith('/password')?credential():url.endsWith('/logout')?{ok:true,status:'identity_session_logged_out'}:f));
  await assert.rejects(e.c.auth02Password('test@example.invalid','password_test',e.query));
  assert.equal(e.calls.at(-1).url,'/api/core/identity/logout');assert.equal(e.saved,null);
});
await test('acknowledged server logout clears bridge, selection and all private caches',async()=>{
  const e=environment(url=>reply(url.endsWith('/password')?credential():url.endsWith('/logout')?{ok:true,status:'identity_session_logged_out',public_refresh_credentials_revoked:1}:fixture()));
  await e.c.auth02Password('test@example.invalid','password_test',e.query);
  await e.c.auth02Logout();
  assert.equal(e.saved,null);assert.equal(e.c.auth02HasLogoutLock(),false);
  assert.ok(e.events.includes('selection-clear'));assert.equal(e.events.at(-1),'redirect:/welcome');
  assert.equal(e.calls.at(-1).options.headers['X-LiveUIN-Session-Id'],'session_test');
});
await test('ambiguous logout keeps credentials for retry but closes cache and reload bootstrap',async()=>{
  let fail=true;
  const e=environment(url=>reply(url.endsWith('/password')?credential():url.endsWith('/logout')?(fail?{status:'identity_session_logged_out'}:{ok:true,status:'identity_session_logged_out'}):fixture()));
  await e.c.auth02Password('test@example.invalid','password_test',e.query);
  await assert.rejects(e.c.auth02Logout());
  assert.ok(e.saved);assert.equal(e.c.auth02HasLogoutLock(),true);assert.equal(e.query.value.authRequired,true);
  const before=e.calls.length;assert.equal((await e.c.qx()).authRequired,true);assert.equal(e.calls.length,before);
  await assert.rejects(e.c.auth02Password('test@example.invalid','password_test',e.query));
  fail=false;await e.c.auth02Logout();assert.equal(e.saved,null);assert.equal(e.c.auth02HasLogoutLock(),false);
});
await test('post-password revocation failure remains closed and retryable',async()=>{
  const f=fixture();f.authorized_profiles=[];
  const e=environment(url=>reply(url.endsWith('/password')?credential():url.endsWith('/logout')?{ok:false}:f));
  await assert.rejects(e.c.auth02Password('test@example.invalid','password_test',e.query));
  assert.ok(e.saved);assert.equal(e.c.auth02HasLogoutLock(),true);assert.equal((await e.c.qx()).authRequired,true);
});
await test('logout serializes pending password exchange and prevents late session hydration',async()=>{
  let release;
  const pending=new Promise(resolve=>release=resolve);
  const e=environment(url=>url.endsWith('/password')?pending:Promise.resolve(reply({ok:true,status:'identity_session_logged_out'})));
  const signing=e.c.auth02Password('test@example.invalid','password_test',e.query);
  const rejected=assert.rejects(signing);
  await new Promise(resolve=>setTimeout(resolve,0));
  const logout=e.c.auth02Logout();
  release(reply(credential()));
  await rejected;await logout;
  assert.equal(e.saved,null);assert.equal(e.calls.filter(x=>x.url.endsWith('/resolve')).length,0);
  assert.equal(e.calls.at(-1).url,'/api/core/identity/logout');
});
await test('old bootstrap response cannot reopen a logged-out UI',async()=>{
  let release;
  const e=environment(url=>url.endsWith('/resolve')?new Promise(resolve=>release=resolve):Promise.resolve(reply({ok:true,status:'identity_session_logged_out'})));
  const bootstrap=e.c.qx();await e.c.auth02Logout();release(reply(fixture()));
  assert.equal((await bootstrap).authRequired,true);
});
await test('public host never posts password or attempts resident resolution',async()=>{
  const e=environment(()=>{throw new Error('must not fetch');});e.c.window.location.hostname='liveuin.com';
  await assert.rejects(e.c.auth02Password('test@example.invalid','password_test',e.query));
  assert.equal((await e.c.qx()).authRequired,true);assert.equal(e.calls.length,0);
});

const report={suite:'AUTH02 local synthetic contract tests; no live account or API calls',passed,results};
fs.writeFileSync(path.join(root,'tests/runtime-results.json'),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({passed,status:'pass'}));
