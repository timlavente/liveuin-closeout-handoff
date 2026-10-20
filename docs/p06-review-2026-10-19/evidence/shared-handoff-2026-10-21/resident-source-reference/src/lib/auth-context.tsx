import { createContext, useContext, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useResidentApp } from "@/components/resident/ResidentAppContext";
import { useNavigate } from "@/native-lovable/router";
import {
  recordResidentDiagnostic,
  ResidentApiError,
  residentFetchJsonResponse,
  type JsonPayload,
  type ResidentJsonResponse,
} from "@/lib/residentNativeHttp";
import { clearResidentProfileSelection, clearResidentSignedSession, setResidentSignedSession } from "@/lib/residentSessionBridge";
import { PASSWORD_RULES_MESSAGE, passwordMeetsRules } from "@/lib/residentPasswordRules";
import { logoutResidentSession } from "@/lib/residentLogout";
import { awaitResidentAuthBootstrap } from "@/lib/residentAuthBootstrap";
import {
  beginNativeSocialSignIn,
  clearNativeSocialCredential,
  type NativeSocialCredential,
  type SocialProvider,
} from "@/lib/residentSocialAuth";
import type { Profile } from "@/lib/profile-context";

export type AuthUser = {
  name: string;
  email: string;
  roles: Profile[];
  profileState?: string;
  nextAction?: string;
  provider?: SocialProvider;
  providerLinked?: boolean;
  status?: string;
};

type AuthorizedProfile = {
  profile_key?: string;
  status?: string;
  is_default?: boolean;
};

export type IdentityPayload = JsonPayload & {
  status?: string;
  provider?: string;
  provider_linked?: boolean;
  account_state?: string;
  profile_state?: string;
  next_action?: string;
  display_name?: string;
  locale?: string;
  registration_id?: string;
  reset_id?: string;
  reset_token?: string;
  verification_expiry?: number;
  authorized_profiles?: AuthorizedProfile[];
  session?: SessionCredential;
  one_time_credential?: SessionCredential;
};

type SessionCredential = {
  credential_kind?: string;
  session_id?: string;
  session_headers?: Record<string, string>;
  expires_at?: number;
};

type Ctx = {
  user: AuthUser | null;
  hydrated: boolean;
  signIn: (email: string, password: string) => Promise<AuthUser>;
  signInWithProvider: (provider: SocialProvider) => Promise<AuthUser>;
  linkProvider: (provider: SocialProvider) => Promise<AuthUser>;
  startRegistration: (input: { email: string; password: string; acceptedTermsVersion: string; locale?: string }) => Promise<{
    registrationId: string;
    expiresAt: number;
  }>;
  verifyRegistration: (registrationId: string, verificationCode: string, email: string) => Promise<AuthUser>;
  resendRegistration: (registrationId: string, email: string) => Promise<void>;
  getOnboardingStatus: () => Promise<IdentityPayload>;
  completeProfile: (displayName: string, locale?: string) => Promise<void>;
  completeTenantOnboarding: () => Promise<AuthUser>;
  requestPasswordReset: (email: string, idempotencyKey?: string) => Promise<PasswordResetRequestResult>;
  verifyPasswordReset: (resetId: string, verificationCode: string) => Promise<PasswordResetVerificationResult>;
  completePasswordReset: (resetToken: string, newPassword: string) => Promise<{ requestId?: string }>;
  signOut: () => Promise<void>;
  /** Wipe local credentials like logout does after the server accepted an account deletion, then show the signed-out screen. */
  afterAccountDeletion: () => Promise<void>;
  addRole: (role: Profile) => void;
};

const AuthContext = createContext<Ctx | null>(null);

export const publicTermsVersion = String(import.meta.env.VITE_LIVEUIN_PUBLIC_TERMS_VERSION || "").trim();

const responseErrorMessages: Record<string, string> = {
  invalid_email: "Enter a valid email address.",
  credentials_required: "Enter your email and password.",
  duplicate_email: "An account already exists for this email. Sign in instead.",
  weak_password: PASSWORD_RULES_MESSAGE,
  terms_required: "Accept the LiveUIN terms to continue.",
  terms_version_not_current: "The LiveUIN terms have been updated. Please update the app and try again.",
  default_profile_invalid: "Account creation is temporarily unavailable. Please try again later.",
  registration_not_found: "That sign-up is no longer available. Start again.",
  verification_not_pending: "This email is already verified. Sign in instead.",
  registration_resume_unavailable: "Account creation is temporarily unavailable. Please try again later.",
  rate_limited: "Too many attempts. Please wait a few minutes and try again.",
  server_error: "LiveUIN could not complete that request. Please try again later.",
  request_validation_error: "LiveUIN could not complete that request. Please check what you entered and try again.",
  account_unavailable: "Your account is scheduled for deletion, or is not available right now.",
  invalid_credentials: "Incorrect email or password. Check them and try again.",
  email_unverified: "Verify your email before signing in.",
  verification_expired: "That verification code has expired. Start again to get a new one.",
  verification_locked: "Too many wrong codes. Start again to get a new one.",
  invalid_verification_code: "That verification code is not valid. Check it and try again.",
  public_registration_disabled: "Account creation is temporarily unavailable. Please try again later.",
  registration_disabled: "Account creation is temporarily unavailable. Please try again later.",
  registration_unavailable: "Account creation is temporarily unavailable. Please try again later.",
  public_workspace_not_configured: "LiveUIN is temporarily unavailable. Please try again later.",
  public_terms_not_configured: "Account creation is temporarily unavailable. Please try again later.",
  email_delivery_unavailable: "We couldn't send the verification email. Please try again later.",
  identity_security_not_ready: "Account creation is temporarily unavailable. Please try again later.",
  identity_unavailable: "LiveUIN could not complete that request. Please try again later.",
  profile_incomplete: "Complete your profile before continuing.",
  session_required: "Your session has expired. Sign in again.",
  session_expired: "Your session has expired. Sign in again.",
  session_refresh_expired: "Your session has expired. Sign in again.",
  password_reset_required: "Reset your password before signing in.",
  recovery_not_available: "That recovery request is no longer available. Start again.",
  recovery_expired: "That recovery code has expired. Start again.",
  recovery_locked: "For your security, start a new recovery request.",
  recovery_rate_limited: "Too many recovery attempts. Please wait and try again.",
  recovery_contract_incomplete: "Password recovery is temporarily unavailable. Please try again later.",
  provider_not_ready: "This sign-in method is not available yet. Use email and password instead.",
  provider_unavailable: "This sign-in method is temporarily unavailable. Please try again later.",
  provider_email_required: "This sign-in method could not be verified. Please try again later.",
  provider_token_invalid: "This sign-in method could not be verified. Please try again later.",
  provider_token_required: "This sign-in method could not be completed. Please try again later.",
  provider_token_replay: "This sign-in attempt has expired. Start again.",
  link_required: "This sign-in method needs to be connected to your existing LiveUIN account. Sign in with email first.",
  provider_identity_conflict: "This sign-in method could not be connected safely. Please contact LiveUIN support.",
  recent_authentication_required: "Sign in again before connecting a new sign-in method.",
};

export type PasswordResetRequestResult = {
  resetId: string;
  requestId?: string;
  expiresAt: number;
};

export type PasswordResetVerificationResult = {
  resetToken: string;
  requestId?: string;
};

export function safeResponseMessage(response: ResidentJsonResponse<IdentityPayload>, fallback: string) {
  const code = response.errorCode || String(response.payload.error?.code || "").trim();
  const base = responseErrorMessages[code] ||
    (response.responseClass === "html" || response.responseClass === "non_json" || response.responseClass === "malformed_json"
      ? "LiveUIN could not complete that request. Please try again later."
      : response.status === 401
        ? "Your sign-in details could not be verified. Check them and try again."
        : response.status === 503
          ? "LiveUIN is temporarily unavailable. Please try again later."
          : fallback);
  return base;
}

export function residentResponseError(response: ResidentJsonResponse<IdentityPayload>, fallback: string) {
  const message = safeResponseMessage(response, fallback);
  recordResidentDiagnostic({
    phase: "mapped_error",
    operation: response.url.includes("/registrations")
      ? "registration"
      : response.url.includes("/password-resets")
        ? "password_recovery"
        : undefined,
    route: typeof window === "undefined" ? "unknown" : window.location.pathname,
    url: response.url,
    method: response.method,
    webViewOrigin: typeof window === "undefined" ? "unknown" : window.location.origin,
    transport: response.transport,
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    receivedResponse: true,
    status: response.status,
    contentType: response.contentType,
    responseClass: response.responseClass,
    parse: response.parse,
    requestId: response.requestId,
    errorCode: response.errorCode,
    userMessage: message,
  });
  return new ResidentApiError(message, response.responseClass, response.requestId, undefined, response.status, response.errorCode);
}

function throwForResponse(response: ResidentJsonResponse<IdentityPayload>, fallback: string): never {
  throw residentResponseError(response, fallback);
}

function profileRoles(payload: IdentityPayload): Profile[] {
  const roles = (payload.authorized_profiles || [])
    .filter((profile) => !profile.status || profile.status === "active")
    .map((profile) => profile.profile_key)
    .filter((profile): profile is Profile => profile === "tenant" || profile === "localpro");
  return roles;
}

function sessionFromPayload(payload: IdentityPayload) {
  const credential = payload.one_time_credential || payload.session;
  const sessionHeaders = credential?.session_headers || {};
  const sessionId = String(credential?.session_id || sessionHeaders["X-LiveUIN-Session-Id"] || sessionHeaders["x-liveuin-session-id"] || "").trim();
  if (!sessionId || !Object.keys(sessionHeaders).length) return null;
  return setResidentSignedSession({
    sessionId,
    sessionHeaders,
    expiresAt: Number(credential?.expires_at || 0),
    credentialKind: String(credential?.credential_kind || "liveuin_session"),
  });
}

function authUserFrom(payload: IdentityPayload, email: string): AuthUser {
  return {
    name: String(payload.display_name || "LiveUIN member"),
    email,
    roles: profileRoles(payload),
    profileState: String(payload.profile_state || payload.account_state || "").trim() || undefined,
    nextAction: String(payload.next_action || "").trim() || undefined,
    provider: payload.provider === "google" || payload.provider === "apple" ? payload.provider : undefined,
    providerLinked: typeof payload.provider_linked === "boolean" ? payload.provider_linked : undefined,
    status: String(payload.status || "").trim() || undefined,
  };
}

function jsonHeaders() {
  return { "Content-Type": "application/json", Accept: "application/json" };
}

async function identityRequest<T extends IdentityPayload>(path: string, init?: RequestInit) {
  return residentFetchJsonResponse<T>(path, { ...init, headers: { ...jsonHeaders(), ...(init?.headers || {}) } }, { timeoutMs: 20_000 });
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const resident = useResidentApp();
  const navigate = useNavigate();
  const [profileDisplayName, setProfileDisplayName] = useState("");
  const roles = resident.authorizedProfiles
    .map((profile) => profile.profileKey)
    .filter((profile): profile is Profile => profile === "tenant" || profile === "localpro");
  const user =
    resident.authRequired || resident.sessionState === "auth_required"
      ? null
      : {
          name: profileDisplayName || resident.actorName || resident.accountLabel || "LiveUIN member",
          email: "",
          roles,
        };

  const signIn = async (email: string, password: string): Promise<AuthUser> => {
    const normalizedEmail = String(email || "").trim().toLowerCase();
    if (!normalizedEmail || !password) throw new Error("Enter your email and password.");

    const response = await identityRequest<IdentityPayload>("/api/core/identity/sessions/password", {
      method: "POST",
      body: JSON.stringify({ email: normalizedEmail, password }),
    });
    if (!response.ok || response.responseClass !== "json") {
      throwForResponse(response, "Your sign-in details could not be verified. Check them and try again.");
    }
    const session = sessionFromPayload(response.payload);
    if (!session) throw new Error("LiveUIN could not complete sign-in. Please try again later.");
    if (String(response.payload.display_name || "").trim()) setProfileDisplayName(String(response.payload.display_name).trim());
    await awaitResidentAuthBootstrap(queryClient);
    return authUserFrom(response.payload, normalizedEmail);
  };

  const exchangeProviderCredential = async (
    provider: SocialProvider,
    credential: NativeSocialCredential,
    mode: "exchange" | "link",
  ): Promise<AuthUser> => {
    const response = await identityRequest<IdentityPayload>(`/api/core/identity/providers/${provider}/${mode}`, {
      method: "POST",
      body: JSON.stringify({
        ...(credential.id_token ? { id_token: credential.id_token } : {}),
        ...(credential.authorization_code ? { authorization_code: credential.authorization_code } : {}),
        nonce: credential.nonce,
        ...(credential.state ? { state: credential.state } : {}),
        ...(publicTermsVersion ? { accepted_terms_version: publicTermsVersion } : {}),
      }),
    });
    if (!response.ok || response.responseClass !== "json") {
      throwForResponse(response, "This sign-in method could not be completed. Please try again later.");
    }
    const session = sessionFromPayload(response.payload);
    if (!session) throw new Error("LiveUIN could not complete sign-in. Please try again later.");
    if (String(response.payload.display_name || "").trim()) setProfileDisplayName(String(response.payload.display_name).trim());
    await queryClient.invalidateQueries({ queryKey: ["resident-session-bootstrap"] });
    return authUserFrom(response.payload, "");
  };

  const signInWithProvider = async (provider: SocialProvider) => {
    const credential = await beginNativeSocialSignIn(provider);
    try {
      return await exchangeProviderCredential(provider, credential, "exchange");
    } finally {
      clearNativeSocialCredential(credential);
    }
  };

  const linkProvider = async (provider: SocialProvider) => {
    const credential = await beginNativeSocialSignIn(provider);
    try {
      return await exchangeProviderCredential(provider, credential, "link");
    } finally {
      clearNativeSocialCredential(credential);
    }
  };

  const startRegistration = async (input: { email: string; password: string; acceptedTermsVersion: string; locale?: string }) => {
    const normalizedEmail = String(input.email || "").trim().toLowerCase();
    if (!normalizedEmail) throw new Error("Enter a valid email address.");
    if (!passwordMeetsRules(input.password)) throw new Error(PASSWORD_RULES_MESSAGE);
    if (!input.acceptedTermsVersion) throw new Error("Account creation is temporarily unavailable. Please try again later.");

    const response = await identityRequest<IdentityPayload>("/api/core/identity/registrations", {
      method: "POST",
      body: JSON.stringify({
        email: normalizedEmail,
        password: input.password,
        accepted_terms_version: input.acceptedTermsVersion,
        locale: input.locale || "en",
        requested_default_profile: "tenant",
        idempotency_key: `native-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
      }),
    });
    if (!response.ok || response.responseClass !== "json") {
      throwForResponse(response, "Account creation is temporarily unavailable. Please try again later.");
    }
    const registrationId = String(response.payload.registration_id || "").trim();
    if (!registrationId) throw new Error("Account creation is temporarily unavailable. Please try again later.");
    return { registrationId, expiresAt: Number(response.payload.verification_expiry || 0) };
  };

  const verifyRegistration = async (registrationId: string, verificationCode: string, email: string) => {
    const response = await identityRequest<IdentityPayload>(`/api/core/identity/registrations/${encodeURIComponent(registrationId)}/verify`, {
      method: "POST",
      body: JSON.stringify({ verification_code: verificationCode.trim() }),
    });
    if (!response.ok || response.responseClass !== "json") {
      throwForResponse(response, "That verification code is not valid. Check it and try again.");
    }
    const session = sessionFromPayload(response.payload);
    if (!session) throw new Error("LiveUIN could not complete verification. Please try again later.");
    await queryClient.invalidateQueries({ queryKey: ["resident-session-bootstrap"] });
    return authUserFrom(response.payload, email);
  };

  const resendRegistration = async (registrationId: string, email: string) => {
    const response = await identityRequest<IdentityPayload>(`/api/core/identity/registrations/${encodeURIComponent(registrationId)}/resend`, {
      method: "POST",
      body: JSON.stringify({ email: email.trim().toLowerCase(), idempotency_key: `native-resend-${Date.now()}` }),
    });
    if (!response.ok || response.responseClass !== "json") {
      throwForResponse(response, "We couldn't send the verification email. Please try again later.");
    }
  };

  const getOnboardingStatus = async () => {
    const response = await identityRequest<IdentityPayload>("/api/core/identity/onboarding/status");
    if (!response.ok || response.responseClass !== "json") throwForResponse(response, "LiveUIN could not load your account setup. Please try again later.");
    return response.payload;
  };

  const completeProfile = async (displayName: string, locale = "en") => {
    const normalizedDisplayName = displayName.trim();
    const response = await identityRequest<IdentityPayload>("/api/core/identity/profile", {
      method: "PATCH",
      body: JSON.stringify({ display_name: normalizedDisplayName, locale }),
    });
    if (!response.ok || response.responseClass !== "json") throwForResponse(response, "Add your name to continue.");
    setProfileDisplayName(normalizedDisplayName);
  };

  const completeTenantOnboarding = async () => {
    const response = await identityRequest<IdentityPayload>("/api/core/identity/onboarding/complete", { method: "POST" });
    if (!response.ok || response.responseClass !== "json") throwForResponse(response, "LiveUIN could not finish your account setup. Please try again later.");
    const session = sessionFromPayload(response.payload);
    if (!session) throw new Error("LiveUIN could not finish your account setup. Please try again later.");
    if (String(response.payload.display_name || "").trim()) setProfileDisplayName(String(response.payload.display_name).trim());
    await queryClient.invalidateQueries({ queryKey: ["resident-session-bootstrap"] });
    return authUserFrom(response.payload, "");
  };

  const requestPasswordReset = async (email: string, idempotencyKey?: string): Promise<PasswordResetRequestResult> => {
    const normalizedEmail = email.trim().toLowerCase();
    const response = await identityRequest<IdentityPayload>("/api/core/identity/password-resets/request", {
      method: "POST",
      body: JSON.stringify({
        email: normalizedEmail,
        idempotency_key: idempotencyKey || `native-password-reset-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
      }),
    });
    if (!response.ok || response.responseClass !== "json") throwForResponse(response, "We couldn't start password recovery. Please try again later.");
    const resetId = String(response.payload.reset_id || "").trim();
    const requestId = response.requestId || String(response.payload.request_id || "").trim() || undefined;
    if (!resetId) {
      throw new ResidentApiError(
        responseErrorMessages.recovery_contract_incomplete,
        response.responseClass,
        requestId,
        undefined,
        response.status,
        "recovery_contract_incomplete",
      );
    }
    return { resetId, requestId, expiresAt: Number(response.payload.verification_expiry || 0) };
  };

  const verifyPasswordReset = async (resetId: string, verificationCode: string): Promise<PasswordResetVerificationResult> => {
    const response = await identityRequest<IdentityPayload>(`/api/core/identity/password-resets/${encodeURIComponent(resetId)}/verify`, {
      method: "POST",
      body: JSON.stringify({ verification_code: verificationCode.trim() }),
    });
    if (!response.ok || response.responseClass !== "json") {
      throwForResponse(response, "That recovery code is not valid. Check it and try again.");
    }
    const resetToken = String(response.payload.reset_token || "").trim();
    const requestId = response.requestId || String(response.payload.request_id || "").trim() || undefined;
    if (!resetToken) {
      throw new ResidentApiError(
        "Password recovery is temporarily unavailable. Please start again later.",
        response.responseClass,
        requestId,
        undefined,
        response.status,
        "recovery_contract_incomplete",
      );
    }
    return { resetToken, requestId };
  };

  const completePasswordReset = async (resetToken: string, newPassword: string) => {
    const response = await identityRequest<IdentityPayload>("/api/core/identity/password-resets/complete", {
      method: "POST",
      body: JSON.stringify({ reset_token: resetToken, new_password: newPassword }),
    });
    if (!response.ok || response.responseClass !== "json") {
      throwForResponse(response, "We couldn't update your password. Please try again later.");
    }
    return { requestId: response.requestId || String(response.payload.request_id || "").trim() || undefined };
  };

  const signOut = async () => {
    await logoutResidentSession();
    setProfileDisplayName("");
    queryClient.clear();
    await navigate({ to: "/welcome", replace: true });
  };

  const afterAccountDeletion = async () => {
    clearResidentSignedSession();
    clearResidentProfileSelection();
    setProfileDisplayName("");
    queryClient.clear();
    await navigate({ to: "/auth/sign-in", replace: true });
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        hydrated: !resident.isLoading,
        signIn,
        signInWithProvider,
        linkProvider,
        startRegistration,
        verifyRegistration,
        resendRegistration,
        getOnboardingStatus,
        completeProfile,
        completeTenantOnboarding,
        requestPasswordReset,
        verifyPasswordReset,
        completePasswordReset,
        signOut,
        afterAccountDeletion,
        addRole: () => undefined,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}

export function describeAuthError(error: unknown, fallback: string) {
  if (error instanceof ResidentApiError) return error.message;
  return error instanceof Error ? error.message : fallback;
}
