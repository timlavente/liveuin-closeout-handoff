import { Capacitor, WebPlugin, registerPlugin } from "@capacitor/core";
import { residentFetchJsonResponse, type JsonPayload } from "@/lib/residentNativeHttp";

export type SocialProvider = "google" | "apple";

export const RESIDENT_SOCIAL_PROVIDER_STATUS_WORKSPACE_ID =
  String(import.meta.env.VITE_LIVEUIN_PUBLIC_WORKSPACE_ID || "").trim() || "liveuin-public";
export const RESIDENT_SOCIAL_PROVIDER_STATUS_PATH =
  `/api/core/identity/providers/status?workspace_id=${encodeURIComponent(RESIDENT_SOCIAL_PROVIDER_STATUS_WORKSPACE_ID)}`;

type ResidentSocialProviderStatusPayload = JsonPayload & {
  workspace_id?: unknown;
  providers?: Partial<Record<SocialProvider, { public_enabled?: unknown }>>;
};

export type ResidentSocialProviderPublicStatus = {
  workspaceId: string;
  google: boolean;
  apple: boolean;
};

export type NativeSocialCredential = {
  id_token?: string;
  authorization_code?: string;
  nonce: string;
  state?: string;
};

export function clearNativeSocialCredential(credential: NativeSocialCredential | null | undefined) {
  if (!credential || typeof credential !== "object") return;
  const mutable = credential as Partial<Record<keyof NativeSocialCredential, unknown>>;
  delete mutable.id_token;
  delete mutable.authorization_code;
  delete mutable.nonce;
  delete mutable.state;
}

interface ResidentSocialAuthPlugin {
  signInWithGoogle(): Promise<NativeSocialCredential>;
  signInWithApple(): Promise<NativeSocialCredential>;
}

class ResidentSocialAuthWeb extends WebPlugin implements ResidentSocialAuthPlugin {
  async signInWithGoogle(): Promise<NativeSocialCredential> {
    throw socialAuthError("provider_unavailable");
  }

  async signInWithApple(): Promise<NativeSocialCredential> {
    throw socialAuthError("provider_unavailable");
  }
}

export const ResidentSocialAuth = registerPlugin<ResidentSocialAuthPlugin>("ResidentSocialAuth", {
  web: async () => new ResidentSocialAuthWeb(),
});

const env = import.meta.env;

export const residentSocialAuthConfig = {
  buildProfile: String(env.VITE_LIVEUIN_RESIDENT_BUILD_ENV || env.VITE_LIVEUIN_BUILD_PROFILE || "").trim(),
  stagingEnabled: String(env.VITE_LIVEUIN_SOCIAL_AUTH_ENABLED || "").trim() === "1",
  googleIosClientId: String(env.VITE_LIVEUIN_GOOGLE_IOS_CLIENT_ID || "").trim(),
  appleNativeEnabled: String(env.VITE_LIVEUIN_APPLE_NATIVE_ENABLED || "").trim() === "1",
  googlePublicEnabled: String(env.VITE_LIVEUIN_PUBLIC_GOOGLE_IDENTITY_ENABLED || "").trim() === "1",
  applePublicEnabled: String(env.VITE_LIVEUIN_PUBLIC_APPLE_IDENTITY_ENABLED || "").trim() === "1",
};

export function isSocialProviderButtonVisibleFor(
  config: typeof residentSocialAuthConfig,
  provider: SocialProvider,
) {
  const configured = provider === "google" ? Boolean(config.googleIosClientId) : config.appleNativeEnabled;
  if (!configured) return false;
  if (config.buildProfile === "staging_e2e") return config.stagingEnabled;
  if (config.buildProfile === "production") {
    return provider === "google" ? config.googlePublicEnabled : config.applePublicEnabled;
  }
  return false;
}

export function isSocialProviderButtonVisible(provider: SocialProvider) {
  return isSocialProviderButtonVisibleFor(residentSocialAuthConfig, provider);
}

export function isSocialProviderButtonVisibleWithPublicStatusFor(
  config: typeof residentSocialAuthConfig,
  provider: SocialProvider,
  status: ResidentSocialProviderPublicStatus | null | undefined,
) {
  return isSocialProviderButtonVisibleFor(config, provider) && status?.[provider] === true;
}

export function isSocialProviderButtonVisibleWithPublicStatus(
  provider: SocialProvider,
  status: ResidentSocialProviderPublicStatus | null | undefined,
) {
  return isSocialProviderButtonVisibleWithPublicStatusFor(residentSocialAuthConfig, provider, status);
}

export function resolveResidentSocialProviderPublicStatus(payload: ResidentSocialProviderStatusPayload) {
  const workspaceId = String(payload.workspace_id || "").trim();
  const google = payload.providers?.google;
  const apple = payload.providers?.apple;
  if (
    workspaceId !== RESIDENT_SOCIAL_PROVIDER_STATUS_WORKSPACE_ID ||
    !google ||
    !apple ||
    typeof google !== "object" ||
    typeof apple !== "object"
  ) {
    return null;
  }
  return {
    workspaceId,
    google: google.public_enabled === true,
    apple: apple.public_enabled === true,
  } satisfies ResidentSocialProviderPublicStatus;
}

export async function fetchResidentSocialProviderPublicStatus() {
  const response = await residentFetchJsonResponse<ResidentSocialProviderStatusPayload>(RESIDENT_SOCIAL_PROVIDER_STATUS_PATH);
  if (!response.ok || response.responseClass !== "json") {
    throw socialAuthError("provider_not_ready");
  }
  const status = resolveResidentSocialProviderPublicStatus(response.payload);
  if (!status) throw socialAuthError("provider_not_ready");
  return status;
}

export function socialAuthError(code: string) {
  const error = new Error(code);
  Object.assign(error, { code });
  return error;
}

export function socialAuthErrorCode(error: unknown) {
  if (!error || typeof error !== "object") return "";
  const candidate = error as { code?: unknown; errorCode?: unknown };
  return String(candidate.code || candidate.errorCode || "").trim();
}

export function isSocialAuthCancellation(error: unknown) {
  return socialAuthErrorCode(error) === "user_cancelled";
}

export async function beginNativeSocialSignIn(provider: SocialProvider) {
  if (!Capacitor.isNativePlatform()) throw socialAuthError("provider_unavailable");
  if (!isSocialProviderButtonVisible(provider)) throw socialAuthError("provider_not_ready");
  if (residentSocialAuthConfig.buildProfile === "staging_e2e") {
    try {
      const status = await fetchResidentSocialProviderPublicStatus();
      if (!isSocialProviderButtonVisibleWithPublicStatus(provider, status)) {
        throw socialAuthError("provider_not_ready");
      }
    } catch {
      throw socialAuthError("provider_not_ready");
    }
  }
  return provider === "google" ? ResidentSocialAuth.signInWithGoogle() : ResidentSocialAuth.signInWithApple();
}
