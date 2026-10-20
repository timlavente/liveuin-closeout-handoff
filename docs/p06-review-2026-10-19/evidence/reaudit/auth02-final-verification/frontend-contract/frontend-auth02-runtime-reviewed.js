// AUTH02: readable replacement source for the pinned browser distribution.
// Identity/Core remains authoritative. This module creates no account or grant.
const auth02QueryClients = new Set();
let auth02Epoch = 0;
let auth02LoggingOut = false;
let auth02LoginFlow = null;
let auth02LogoutFlow = null;
let auth02SessionLocked = false;
let auth02PendingIssuedHeaders = null;
let auth02ConfirmedRevocations = 0;

// This is only a local retry lock, never an identity or entitlement grant.
function auth02HasLogoutLock() {
  try { return auth02SessionLocked || window.sessionStorage.getItem("liveuin.auth02.signout-pending") === "1"; }
  catch { return auth02SessionLocked; }
}

function auth02SetLogoutLock(value) {
  auth02SessionLocked = value;
  try {
    if (value) window.sessionStorage.setItem("liveuin.auth02.signout-pending", "1");
    else window.sessionStorage.removeItem("liveuin.auth02.signout-pending");
  } catch {}
}

async function auth02CloseCachedViews() {
  for (const client of auth02QueryClients) {
    await client.cancelQueries();
    client.clear();
    client.setQueryData(["resident-session-bootstrap"], auth02Closed("sign_out_pending"));
  }
}

function auth02IsApp() {
  return typeof window !== "undefined" &&
    window.location.protocol === "https:" &&
    window.location.hostname === "app.liveuin.com";
}

function auth02Closed(reason, continuation = {}) {
  return {
    accountId: "", accountLabel: "", workspaceId: "", actorId: "",
    actorName: "LiveUIN member", role: "", scopes: [],
    sourceFamily: "liveuin_core", countryCode: "", locale: "", channel: "",
    activeCaseId: "", caseIds: [], sessionState: "auth_required",
    identityResolved: false, identityVerified: false, credentialKind: "none",
    previewMode: false, authRequired: true, reasonCode: reason,
    defaultProfileKey: "", defaultWorkspaceId: "", profileEntitlements: [],
    profileState: String(continuation.profile_state || ""),
    nextAction: String(continuation.next_action || "")
  };
}

function auth02String(value) {
  return typeof value === "string" ? value.trim() : "";
}

function auth02Scopes(value) {
  if (!Array.isArray(value) || value.some(item => !auth02String(item))) return [];
  return [...new Set(value.map(auth02String))];
}

// These aliases match canonical Identity _normalize_profile_key; they do not
// issue a role or supply missing permissions.
function auth02RoleProfile(role) {
  if (["tenant", "member", "resident", "student", "parent", "guardian"].includes(role)) return "tenant";
  if (["localpro", "vendor", "earn"].includes(role)) return "localpro";
  return "";
}

function auth02Project(payload) {
  if (!payload || payload.ok !== true) return auth02Closed("identity_session_required");
  const identity = payload.identity_session || {};
  const actor = payload.actor || {};
  const access = payload.access || {};
  const accountId = auth02String(payload.account_id);
  const personId = auth02String(payload.person_id);
  const workspaceId = auth02String(payload.workspace_id);
  if (identity.resolved !== true ||
      !(identity.verified === true || identity.credential_verified === true) ||
      identity.credential_kind !== "liveuin_session" ||
      !accountId || !personId || !workspaceId ||
      actor.account_id !== accountId || actor.person_id !== personId ||
      !auth02String(actor.actor_id) || !auth02String(actor.role)) {
    return auth02Closed("identity_session_not_verified", payload);
  }
  // Both projections must agree. The session projection retains expiry and
  // route restrictions that the public account projection does not include.
  const publicRows = Array.isArray(payload.authorized_profiles) ? payload.authorized_profiles : [];
  const rows = Array.isArray(payload.profile_entitlements) ? payload.profile_entitlements : [];
  const profiles = rows.filter(row => row && typeof row === "object" &&
    auth02String(row.entitlement_id) &&
    row.account_id === accountId && row.person_id === personId &&
    row.workspace_id === workspaceId &&
    ["active", "authorized"].includes(row.status) &&
    ["tenant", "localpro"].includes(row.profile_key) &&
    Number.isInteger(row.effective_to) && row.effective_to >= 0 &&
    (!row.effective_to || row.effective_to > Math.floor(Date.now() / 1000)) &&
    (!row.effective_from || Number.isInteger(row.effective_from) && row.effective_from <= Math.floor(Date.now() / 1000)) &&
    (!row.expires_at || Number.isFinite(Date.parse(row.expires_at)) && Date.parse(row.expires_at) > Date.now())
  ).flatMap(row => {
    const grants = publicRows.filter(grant => grant && grant.entitlement_id === row.entitlement_id &&
      grant.account_id === accountId && grant.person_id === personId &&
      grant.workspace_id === workspaceId && grant.profile_key === row.profile_key &&
      auth02String(grant.subject_id) === auth02String(row.subject_id) &&
      auth02String(grant.subject_role) === auth02String(row.subject_role) &&
      ["active", "authorized"].includes(grant.status));
    if (grants.length !== 1) return [];
    const publicActions = new Set(auth02Scopes(grants[0].permissions));
    const actions = auth02Scopes(row.allowed_actions).filter(action => publicActions.has(action));
    if (!actions.length) return [];
    return [{ ...row, allowed_actions: actions,
      default_route: row.profile_key === "tenant" ? "/tenant/home" : "/localpro/home" }];
  });
  const action = auth02String(payload.next_action);
  const expectedProfile = action === "tenant_home" ? "tenant" :
    action === "localpro_home" ? "localpro" : "";
  const state = auth02String(payload.profile_state);
  const validState = state === "tenant_active" && action === "tenant_home" ||
    state === "localpro_approved" && action === "localpro_home";
  const continuation = payload.continuation;
  if (!profiles.length || !expectedProfile || !validState ||
      !profiles.some(row => row.profile_key === expectedProfile) ||
      continuation && (continuation.state !== state || continuation.next_action !== action ||
        continuation.route !== (expectedProfile === "tenant" ? "/tenant/home" : "/localpro/home"))) {
    return auth02Closed("approved_profile_required", payload);
  }
  // Actor permissions describe the selected profile, not every separately
  // approved profile. Account continuation can independently prefer Tenant.
  const activeProfile = auth02String(actor.active_profile_key || access.active_profile_key) || expectedProfile;
  const selected = profiles.find(row => row.profile_key === activeProfile);
  const actorScopes = auth02Scopes(actor.scopes);
  if (!selected || auth02RoleProfile(actor.role) !== activeProfile ||
      selected.subject_role && selected.subject_role !== actor.role ||
      selected.subject_id && selected.subject_id !== actor.actor_id ||
      actor.active_workspace_id && actor.active_workspace_id !== workspaceId ||
      access.active_workspace_id && access.active_workspace_id !== workspaceId ||
      access.active_profile_key && access.active_profile_key !== activeProfile ||
      !actorScopes.length || actorScopes.length !== selected.allowed_actions.length ||
      actorScopes.some(scope => !selected.allowed_actions.includes(scope))) {
    return auth02Closed("selected_profile_authority_inconsistent", payload);
  }
  const caseIds = Array.isArray(access.case_ids)
    ? access.case_ids.filter(value => typeof value === "string" && value) : [];
  return {
    accountId, personId, workspaceId,
    accountLabel: auth02String(actor.account_label || actor.display_name) || "LiveUIN member",
    actorId: actor.actor_id, actorName: auth02String(actor.display_name || actor.name) || "LiveUIN member",
    role: actor.role, scopes: actorScopes,
    sourceFamily: auth02String(payload.source_family) || "liveuin_core",
    countryCode: auth02String(access.country_code), locale: auth02String(access.locale),
    channel: auth02String(access.channel),
    activeCaseId: caseIds.includes(access.active_case_id) ? access.active_case_id : caseIds[0] || "",
    caseIds, sessionState: "resolved", identityResolved: true, identityVerified: true,
    credentialKind: "liveuin_session", previewMode: false, authRequired: false,
    reasonCode: "identity_session_resolved", defaultProfileKey: activeProfile,
    defaultWorkspaceId: workspaceId, profileEntitlements: profiles,
    profileState: state, nextAction: action
  };
}

function auth02SafeReturn(value) {
  const raw = auth02String(value);
  if (!raw || !raw.startsWith("/") || raw.startsWith("//") ||
      /[\\\x00-\x20\x7f]/.test(raw) || /%(?:2f|5c|00|0a|0d|25)/i.test(raw)) return null;
  let url;
  try { url = new URL(raw, "https://app.liveuin.com"); } catch { return null; }
  if (url.origin !== "https://app.liveuin.com" || url.hash ||
      url.pathname !== raw.split(/[?#]/)[0] || /\.{2}/.test(url.pathname)) return null;
  const path = url.pathname;
  let profile = "";
  if (/^\/localpro(?:\/[a-zA-Z0-9_-]+)*\/?$/.test(path) || /^\/app\/earn(?:\/[a-zA-Z0-9_-]+)*\/?$/.test(path)) profile = "localpro";
  else if (/^\/(?:tenant|pass|account)(?:\/[a-zA-Z0-9_-]+)*\/?$/.test(path) ||
      /^\/(?:messages|journey)(?:\/[a-zA-Z0-9_-]+)*\/?$/.test(path) ||
      /^\/app\/(?:member|explore|wallet|support|utilities|documents|verification|renewal|move-in|bookings|notifications|rewards|saved|insurance|claims|messages|account)(?:\/[a-zA-Z0-9_-]+)*\/?$/.test(path)) profile = "tenant";
  if (!profile) return null;
  const clean = new URLSearchParams();
  for (const key of ["case_id", "booking_id", "stay_id", "mission_id", "workspace_id", "profile_key"]) {
    const values = url.searchParams.getAll(key);
    if (values.length > 1) return null;
    if (values.length && /^[a-zA-Z0-9_.:-]{1,160}$/.test(values[0])) clean.set(key, values[0]);
  }
  return { path: path + (clean.size ? "?" + clean.toString() : ""), profile, query: clean };
}

function auth02RequestedReturn(search) {
  const query = new URLSearchParams(search || "");
  if (query.getAll("returnTo").length > 1 || query.getAll("return_to").length > 1) return null;
  const first = query.get("returnTo"), second = query.get("return_to");
  if (first && second && first !== second) return null;
  return auth02SafeReturn(first || second || "");
}

function auth02LoginHref(search = typeof window !== "undefined" ? window.location.search : "") {
  const destination = auth02RequestedReturn(search);
  return "/auth/sign-in" + (destination ? "?returnTo=" + encodeURIComponent(destination.path) : "");
}

function auth02Destination(bootstrap, search) {
  if (bootstrap.authRequired || !bootstrap.identityVerified) throw new Error("Your approved LiveUIN profile is not ready. Please contact the LiveUIN team.");
  const requested = auth02RequestedReturn(search);
  const available = new Set(bootstrap.profileEntitlements.map(row => row.profile_key));
  if (requested && requested.profile === bootstrap.defaultProfileKey && available.has(requested.profile) &&
      (!requested.query.has("workspace_id") || requested.query.get("workspace_id") === bootstrap.workspaceId) &&
      (!requested.query.has("profile_key") || requested.query.get("profile_key") === requested.profile)) {
    return { path: requested.path, profile: requested.profile };
  }
  const profile = bootstrap.defaultProfileKey;
  if (!available.has(profile)) throw new Error("Your approved LiveUIN profile is not ready.");
  return { path: profile === "tenant" ? "/tenant/home" : "/localpro/home", profile };
}

async function auth02Request(path, body, signed = false, issuedHeaders = null) {
  if (!auth02IsApp()) throw new Error("Please sign in on app.liveuin.com.");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch(path, {
      method: "POST", credentials: "include", cache: "no-store", redirect: "error", signal: controller.signal,
      headers: { Accept: "application/json", "Content-Type": "application/json", ...(signed ? issuedHeaders || ha() : {}) },
      body: JSON.stringify(body || {})
    });
    if (!(response.headers.get("content-type") || "").toLowerCase().startsWith("application/json"))
      throw new Error("LiveUIN could not confirm this request. Please try again.");
    let payload;
    try { payload = await response.json(); } catch { throw new Error("LiveUIN could not confirm this request. Please try again."); }
    if (response.status !== 200 || !payload || typeof payload !== "object" ||
        Array.isArray(payload) || payload.ok !== true) {
      const error = new Error(path.endsWith("/sessions/password")
        ? "We could not sign you in. Check your email and password or contact the LiveUIN team."
        : "LiveUIN could not confirm this request. Please try again.");
      error.status = response.status;
      throw error;
    }
    return payload;
  } finally { clearTimeout(timer); }
}

async function auth02Revoke(headers) {
  const result = await auth02Request("/api/core/identity/logout", {}, true, headers);
  if (result.status !== "identity_session_logged_out") throw new Error("LiveUIN did not confirm sign out.");
  ++auth02ConfirmedRevocations;
  return result;
}

function auth02Credential(payload) {
  const value = payload && payload.one_time_credential;
  if (!value || payload.ok !== true || payload.status !== "authenticated" ||
      value.credential_kind !== "liveuin_session" || !auth02String(value.session_id) ||
      !Number.isFinite(value.expires_at) || value.expires_at <= Math.floor(Date.now() / 1000) ||
      !value.session_headers || typeof value.session_headers !== "object" || Array.isArray(value.session_headers)) {
    throw new Error("LiveUIN did not issue a valid session.");
  }
  const headers = value.session_headers;
  for (const key of ["X-LiveUIN-Workspace-Id", "X-LiveUIN-Actor-Id", "X-LiveUIN-Role", "X-LiveUIN-Session-Id", "X-LiveUIN-Session-Issued-At", "X-LiveUIN-Auth-Method", "X-LiveUIN-Session-Signature"]) {
    if (!auth02String(headers[key]) || /[\r\n]/.test(headers[key])) throw new Error("LiveUIN did not issue a valid session.");
  }
  if (headers["X-LiveUIN-Session-Id"] !== value.session_id) throw new Error("LiveUIN did not issue a valid session.");
  return { sessionId: value.session_id, sessionHeaders: { ...headers }, expiresAt: value.expires_at, credentialKind: "liveuin_session" };
}

async function auth02Password(email, password, queryClient) {
  if (auth02HasLogoutLock()) throw new Error("Sign out was not confirmed. Use Retry sign out before signing in again.");
  if (auth02LoginFlow || auth02LoggingOut) throw new Error("Please wait for your current account request to finish.");
  if (!auth02IsApp()) throw new Error("Please sign in on app.liveuin.com.");
  const normalizedEmail = auth02String(email).toLowerCase();
  if (!normalizedEmail || typeof password !== "string" || !password) throw new Error("Enter your email and password.");
  const epoch = ++auth02Epoch;
  let issued = null;
  auth02QueryClients.add(queryClient);
  auth02LoginFlow = (async () => {
    await queryClient.cancelQueries();
    queryClient.clear();
    queryClient.setQueryData(["resident-session-bootstrap"], auth02Closed("sign_in_pending"));
    // An account switch must not leave the old identity available to a
    // bootstrap triggered by cache clearing or a failed new password.
    const previousHeaders = ha();
    if (previousHeaders["X-LiveUIN-Session-Id"]) {
      try { await auth02Revoke(previousHeaders); }
      catch {
        auth02SetLogoutLock(true);
        throw new Error("Sign out was not confirmed. Use Retry sign out before signing in again.");
      }
      io(); Pu(null);
    }
    if (auth02LoggingOut || epoch !== auth02Epoch) throw new Error("Your account request was cancelled.");
    const payload = await auth02Request("/api/core/identity/sessions/password", { email: normalizedEmail, password });
    const credential = auth02Credential(payload);
    issued = credential;
    auth02PendingIssuedHeaders = credential.sessionHeaders;
    // If logout started during password exchange it waits for this flow and
    // revokes this issued session. No late exchange can repopulate the screen.
    if (!_x(credential)) throw new Error("LiveUIN could not retain your session.");
    if (auth02LoggingOut || epoch !== auth02Epoch) throw new Error("Your account request was cancelled.");
    const bootstrap = auth02Project(await auth02Request("/api/core/identity/session/resolve", {}, true));
    if (auth02LoggingOut || epoch !== auth02Epoch) throw new Error("Your account request was cancelled.");
    const destination = auth02Destination(bootstrap, window.location.search);
    Pu({ profileKey: destination.profile, workspaceId: bootstrap.workspaceId });
    queryClient.setQueryData(["resident-session-bootstrap"], bootstrap);
    auth02PendingIssuedHeaders = null;
    return { name: bootstrap.actorName, email: normalizedEmail,
      roles: [...new Set(bootstrap.profileEntitlements.map(row => row.profile_key))],
      destination: destination.path, profile: destination.profile,
      profileState: bootstrap.profileState, nextAction: bootstrap.nextAction };
  })();
  try { return await auth02LoginFlow; }
  catch (error) {
    if (!auth02LoggingOut && issued) {
      try {
        await auth02Revoke(issued.sessionHeaders);
        auth02PendingIssuedHeaders = null;
        io(); Pu(null);
      } catch {
        auth02SetLogoutLock(true);
        await auth02CloseCachedViews();
        queryClient.setQueryData(["resident-session-bootstrap"], auth02Closed("sign_out_not_confirmed"));
        throw new Error("Sign-in did not finish, and sign out was not confirmed. Please try again before leaving this shared device.");
      }
      queryClient.clear();
    }
    throw error;
  } finally { auth02LoginFlow = null; }
}

async function auth02Logout() {
  if (auth02LogoutFlow) return auth02LogoutFlow;
  auth02LoggingOut = true;
  auth02SetLogoutLock(true);
  ++auth02Epoch;
  auth02LogoutFlow = (async () => {
    const priorRevocations = auth02ConfirmedRevocations;
    await auth02CloseCachedViews();
    if (auth02LoginFlow) { try { await auth02LoginFlow; } catch {} }
    const headers = auth02PendingIssuedHeaders || ha();
    if (headers["X-LiveUIN-Session-Id"] || auth02ConfirmedRevocations === priorRevocations)
      await auth02Revoke(headers);
    auth02PendingIssuedHeaders = null;
    io(); Pu(null);
    auth02SetLogoutLock(false);
    for (const client of auth02QueryClients) client.clear();
    window.location.replace("/welcome");
  })();
  try { return await auth02LogoutFlow; }
  finally { auth02LoggingOut = false; auth02LogoutFlow = null; }
}

function auth02LogoutFromControl() {
  return auth02Logout().catch(() => {
    window.alert("Sign out was not confirmed. Please try again before leaving this shared device.");
    window.location.replace("/auth/sign-in?signout_pending=1");
  });
}

function auth02PublicHandoff() {
  const target = "https://app.liveuin.com" + auth02LoginHref();
  d.useEffect(() => { window.location.replace(target); }, [target]);
  return a.jsx("a", { href: target, children: "Continue to LiveUIN sign in" });
}

function Rj({ children }) {
  const queryClient = yc(), resident = Kx();
  auth02QueryClients.add(queryClient);
  const roles = resident.authorizedProfiles.map(profile => profile.profileKey)
    .filter(profile => profile === "tenant" || profile === "localpro");
  const user = auth02HasLogoutLock() || resident.authRequired || resident.sessionState !== "resolved" || !roles.length ? null : {
    name: resident.actorName || resident.accountLabel || "LiveUIN member", email: "", roles
  };
  const signIn = (email, password) => auth02Password(email, password, queryClient);
  // Existing unavailable actions stay unchanged: their separate rows remain open.
  const signUp = async () => { throw new Error("Account access is available for approved LiveUIN accounts. Please sign in with the email connected to your profile."); };
  const signInWithGoogle = async () => { throw new Error("Google sign-in is available only for Google accounts already connected to LiveUIN."); };
  return a.jsx(Qx.Provider, { value: {
    user, hydrated: !resident.isLoading, signIn, signUp, signInWithGoogle,
    signOut: auth02LogoutFromControl, addRole: () => {}
  }, children });
}
