import type { LiveuinAuthorizedProfile } from "@/lib/mobileProfileScope";
import type { ResidentSessionState } from "@/lib/residentAppRuntime";

export type CanonicalResidentContinuation =
  | "profile"
  | "tenant_onboarding"
  | "tenant"
  | "localpro"
  | "link_required"
  | "deletion_pending"
  | "action_required";

const INCOMPLETE_STATES = new Set(["incomplete", "profile_incomplete", "incomplete_profile"]);
const PROFILE_COMPLETION_ACTIONS = new Set(["complete_profile", "profile_completion", "profile"]);
const TENANT_ONBOARDING_ACTIONS = new Set(["complete_onboarding", "tenant_onboarding"]);

function normalizeState(value: unknown) {
  return String(value || "").trim().toLowerCase();
}

export function requiresCanonicalProfileCompletion(input: {
  profileState?: unknown;
  accountState?: unknown;
  nextAction?: unknown;
  continuationRoute?: unknown;
}) {
  return [input.profileState, input.accountState].some((value) => INCOMPLETE_STATES.has(normalizeState(value))) ||
    PROFILE_COMPLETION_ACTIONS.has(normalizeState(input.nextAction)) ||
    normalizeState(input.continuationRoute) === "/auth/complete-profile";
}

function requiresTenantOnboarding(input: { nextAction?: unknown; continuationRoute?: unknown }) {
  return TENANT_ONBOARDING_ACTIONS.has(normalizeState(input.nextAction)) ||
    normalizeState(input.continuationRoute) === "/auth/continue-tenant";
}

export function resolveCanonicalAuthContinuation(input: {
  roles: string[];
  profileState?: unknown;
  accountState?: unknown;
  status?: unknown;
  nextAction?: unknown;
  continuationRoute?: unknown;
}) {
  const profileState = normalizeState(input.profileState || input.accountState);
  const status = normalizeState(input.status);
  const nextAction = normalizeState(input.nextAction);
  if (INCOMPLETE_STATES.has(profileState) || INCOMPLETE_STATES.has(status) || PROFILE_COMPLETION_ACTIONS.has(nextAction)) return "profile" as const;
  if (TENANT_ONBOARDING_ACTIONS.has(nextAction) || normalizeState(input.continuationRoute) === "/auth/continue-tenant") return "tenant_onboarding" as const;
  if (nextAction === "link_required") return "link_required" as const;
  if (["deletion_pending", "wait_for_deletion"].includes(nextAction) || ["deletion_pending", "wait_for_deletion"].includes(status)) return "deletion_pending" as const;
  if (nextAction === "localpro_home" || (input.roles.includes("localpro") && !input.roles.includes("tenant"))) return "localpro" as const;
  if (nextAction === "tenant_home" || input.roles.includes("tenant") || input.roles.includes("resident") || input.roles.includes("member")) return "tenant" as const;
  if (nextAction === "landlord_home" || nextAction === "host_home" || input.roles.includes("landlord") || input.roles.includes("host") || input.roles.includes("owner")) return "landlord" as const;
  if (nextAction === "partner_home" || input.roles.includes("partner") || input.roles.includes("agent")) return "partner" as const;
  if (nextAction === "operator_home" || nextAction === "ops_home" || input.roles.includes("operator") || input.roles.includes("ops")) return "operator" as const;
  if (nextAction === "family_home" || input.roles.includes("family")) return "family" as const;
  return "action_required" as const;
}

function hasProfile(profiles: Pick<LiveuinAuthorizedProfile, "profileKey">[], profileKey: unknown) {
  const normalized = normalizeState(profileKey);
  return Boolean(normalized && profiles.some((profile) => profile.profileKey === normalized));
}

export function resolveCanonicalResidentContinuation(input: {
  sessionState: ResidentSessionState;
  identityResolved: boolean;
  identityVerified: boolean;
  canonicalStateReady?: boolean;
  previewMode: boolean;
  profileState?: unknown;
  accountState?: unknown;
  nextAction?: unknown;
  continuationRoute?: unknown;
  canonicalConflict?: boolean;
  profiles: Pick<LiveuinAuthorizedProfile, "profileKey">[];
  preferredProfileKey?: unknown;
  defaultProfileKey?: unknown;
}): CanonicalResidentContinuation {
  if (input.previewMode) {
    if (hasProfile(input.profiles, input.preferredProfileKey)) return normalizeState(input.preferredProfileKey) as CanonicalResidentContinuation;
    if (hasProfile(input.profiles, input.defaultProfileKey)) return normalizeState(input.defaultProfileKey) as CanonicalResidentContinuation;
    if (hasProfile(input.profiles, "tenant")) return "tenant";
    if (hasProfile(input.profiles, "localpro")) return "localpro";
    return "action_required";
  }
  if (input.sessionState !== "resolved" || !input.identityResolved || !input.identityVerified || input.canonicalStateReady === false) return "action_required";
  if (input.canonicalConflict) return "action_required";
  if (requiresCanonicalProfileCompletion(input)) return "profile";
  if (requiresTenantOnboarding(input)) return "tenant_onboarding";
  const nextAction = normalizeState(input.nextAction);
  if (nextAction === "link_required") return "link_required";
  if (["deletion_pending", "wait_for_deletion"].includes(nextAction)) return "deletion_pending";
  if (hasProfile(input.profiles, input.preferredProfileKey)) return normalizeState(input.preferredProfileKey) as CanonicalResidentContinuation;
  if (hasProfile(input.profiles, input.defaultProfileKey)) return normalizeState(input.defaultProfileKey) as CanonicalResidentContinuation;
  if (hasProfile(input.profiles, "tenant")) return "tenant";
  if (hasProfile(input.profiles, "localpro")) return "localpro";
  return "action_required";
}
