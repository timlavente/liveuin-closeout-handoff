import type { ResidentSessionBootstrap } from "@/lib/residentAppRuntime";

export type LiveuinProfileKey = "tenant" | "localpro" | "landlord" | "partner" | "operator";

export type LiveuinEntitlementStatus = "active" | "authorized" | "pending" | "expired" | "blocked";

export interface LiveuinProfileWorkspaceEntitlement {
  profileKey: LiveuinProfileKey;
  workspaceId: string;
  workspaceLabel: string;
  workspaceType: string;
  entitlementStatus: LiveuinEntitlementStatus;
  allowedActions: string[];
  defaultRoute: string;
  expiresAt: string;
  isDefault: boolean;
}

export interface LiveuinAuthorizedProfile {
  profileKey: LiveuinProfileKey;
  label: string;
  workspaces: LiveuinProfileWorkspaceEntitlement[];
  defaultWorkspaceId: string;
  defaultRoute: string;
  source: "identity_entitlements" | "tenant_bootstrap_fallback";
}

export interface LiveuinProfileSelection {
  profileKey: LiveuinProfileKey;
  workspaceId: string;
}

export interface LiveuinProfileShellState {
  profiles: LiveuinAuthorizedProfile[];
  activeProfile: LiveuinAuthorizedProfile | null;
  activeWorkspace: LiveuinProfileWorkspaceEntitlement | null;
  activeSelection: LiveuinProfileSelection | null;
  source: "identity_entitlements" | "tenant_bootstrap_fallback" | "none";
}

type RawEntitlementRecord = Record<string, unknown>;

const ACTIVE_STATUSES = new Set<LiveuinEntitlementStatus>(["active", "authorized"]);

function normalizeText(value: unknown) {
  return String(value || "").trim();
}

function profileLabel(profileKey: LiveuinProfileKey) {
  if (profileKey === "tenant") return "Tenant / My Home";
  if (profileKey === "localpro") return "LocalPro / Earn with LiveUIN";
  if (profileKey === "landlord") return "Landlord";
  if (profileKey === "partner") return "Partner";
  return "Operator";
}

function defaultRouteForProfile(profileKey: LiveuinProfileKey) {
  if (profileKey === "tenant") return "/tenant/home";
  if (profileKey === "localpro") return "/localpro/home";
  if (profileKey === "landlord") return "/host/onboarding";
  if (profileKey === "partner") return "/partner/dashboard";
  return "/ops/control-tower";
}

export function normalizeLiveuinProfileKey(value: unknown): LiveuinProfileKey | null {
  const normalized = normalizeText(value).toLowerCase();
  if (!normalized) return null;
  if (normalized === "tenant" || normalized === "member" || normalized === "resident") return "tenant";
  if (normalized === "localpro" || normalized === "vendor" || normalized === "earn") return "localpro";
  if (normalized === "landlord" || normalized === "host" || normalized === "owner") return "landlord";
  if (normalized === "partner" || normalized === "agent") return "partner";
  if (normalized === "operator" || normalized === "ops") return "operator";
  return null;
}

export function inferLiveuinProfileSelectionFromRoute(input: {
  pathname: string;
  search?: string;
  fallbackWorkspaceId: string;
}): LiveuinProfileSelection | null {
  const pathname = normalizeText(input.pathname);
  const params = new URLSearchParams(input.search || "");
  const explicitProfile = normalizeLiveuinProfileKey(params.get("profile_key") || params.get("profile"));
  const explicitWorkspaceId = normalizeText(params.get("workspace_id") || params.get("workspaceId"));
  const fallbackWorkspaceId = normalizeText(input.fallbackWorkspaceId);

  const inferredProfile =
    explicitProfile ||
    (pathname.startsWith("/localpro")
      ? "localpro"
      : pathname.startsWith("/host")
        ? "landlord"
        : pathname.startsWith("/partner")
          ? "partner"
        : pathname.startsWith("/ops")
            ? "operator"
            : pathname.startsWith("/tenant") || pathname.startsWith("/pass")
              ? "tenant"
              : null);
  if (!inferredProfile) return null;
  return {
    profileKey: inferredProfile,
    workspaceId: explicitWorkspaceId || fallbackWorkspaceId,
  };
}

export function buildLiveuinProfileRouteTarget(input: {
  profileKey: LiveuinProfileKey;
  workspaceId: string;
  caseId?: string;
  missionId?: string;
  surface?: "resident" | "pass";
}) {
  const workspaceId = normalizeText(input.workspaceId);
  const caseId = normalizeText(input.caseId);
  const missionId = normalizeText(input.missionId);
  const params = new URLSearchParams();
  if (workspaceId) params.set("workspace_id", workspaceId);

  if (input.profileKey === "tenant") {
    if (input.surface === "pass" && caseId) {
      const query = params.toString();
      return `/pass/${encodeURIComponent(caseId)}${query ? `?${query}` : ""}`;
    }
    if (caseId) params.set("case_id", caseId);
    const query = params.toString();
    return `/tenant/home${query ? `?${query}` : ""}`;
  }

  const basePath =
    input.profileKey === "localpro"
      ? missionId
        ? `/localpro/jobs/${encodeURIComponent(missionId)}`
        : "/localpro/home"
      : input.profileKey === "landlord"
        ? "/host/onboarding"
        : input.profileKey === "partner"
        ? "/partner/dashboard"
        : "/ops/control-tower";
  if (input.profileKey === "localpro" && missionId) {
    params.set("mission_id", missionId);
  }
  const query = params.toString();
  return `${basePath}${query ? `?${query}` : ""}`;
}

function normalizeEntitlementStatus(value: unknown): LiveuinEntitlementStatus {
  const normalized = normalizeText(value).toLowerCase();
  if (normalized === "active" || normalized === "authorized" || normalized === "pending" || normalized === "expired" || normalized === "blocked") {
    return normalized;
  }
  return "blocked";
}

function normalizeAllowedActions(value: unknown) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => normalizeText(item)).filter(Boolean);
}

function normalizeEntitlementRecord(record: RawEntitlementRecord): LiveuinProfileWorkspaceEntitlement | null {
  const profileKey = normalizeLiveuinProfileKey(record.profile_key || record.profile || record.role);
  const workspaceId = normalizeText(record.workspace_id || record.workspaceId || record.id);
  if (!profileKey || !workspaceId) return null;
  const entitlementStatus = normalizeEntitlementStatus(record.status || record.entitlement_status);
  if (!ACTIVE_STATUSES.has(entitlementStatus)) return null;
  return {
    profileKey,
    workspaceId,
    workspaceLabel: normalizeText(record.workspace_label || record.workspace_name || workspaceId),
    workspaceType: normalizeText(record.workspace_type || record.type || "workspace"),
    entitlementStatus,
    allowedActions: normalizeAllowedActions(record.allowed_actions || record.actions),
    defaultRoute: normalizeText(record.default_route) || defaultRouteForProfile(profileKey),
    expiresAt: normalizeText(record.expires_at || record.effective_to),
    isDefault: Boolean(record.is_default || record.default_selected),
  };
}

function buildProfilesFromEntitlements(records: RawEntitlementRecord[]): LiveuinAuthorizedProfile[] {
  const grouped = new Map<LiveuinProfileKey, LiveuinProfileWorkspaceEntitlement[]>();
  for (const record of records) {
    const normalized = normalizeEntitlementRecord(record);
    if (!normalized) continue;
    const current = grouped.get(normalized.profileKey) || [];
    current.push(normalized);
    grouped.set(normalized.profileKey, current);
  }

  return Array.from(grouped.entries()).map(([profileKey, workspaces]) => {
    const defaultWorkspace = workspaces.find((workspace) => workspace.isDefault) || workspaces[0];
    return {
      profileKey,
      label: profileLabel(profileKey),
      workspaces,
      defaultWorkspaceId: defaultWorkspace?.workspaceId || "",
      defaultRoute: defaultWorkspace?.defaultRoute || defaultRouteForProfile(profileKey),
      source: "identity_entitlements",
    };
  });
}

function buildTenantFallbackProfile(bootstrap: ResidentSessionBootstrap): LiveuinAuthorizedProfile[] {
  const tenantProfileKey = normalizeLiveuinProfileKey(bootstrap.role);
  if (bootstrap.authRequired || bootstrap.sessionState === "auth_required" || tenantProfileKey !== "tenant" || !bootstrap.workspaceId) {
    return [];
  }
  return [
    {
      profileKey: "tenant",
      label: profileLabel("tenant"),
      workspaces: [
        {
          profileKey: "tenant",
          workspaceId: bootstrap.workspaceId,
          workspaceLabel: bootstrap.workspaceId,
          workspaceType: "tenant_workspace",
          entitlementStatus: bootstrap.sessionState === "preview" ? "authorized" : "active",
          allowedActions: bootstrap.scopes,
          defaultRoute: "/tenant/home",
          expiresAt: "",
          isDefault: true,
        },
      ],
      defaultWorkspaceId: bootstrap.workspaceId,
      defaultRoute: "/tenant/home",
      source: "tenant_bootstrap_fallback",
    },
  ];
}

function resolveSelection(
  profiles: LiveuinAuthorizedProfile[],
  requestedSelection?: LiveuinProfileSelection | null,
  rememberedSelection?: LiveuinProfileSelection | null,
) {
  const candidates = [requestedSelection, rememberedSelection].filter(Boolean) as LiveuinProfileSelection[];
  for (const candidate of candidates) {
    const profile = profiles.find((item) => item.profileKey === candidate.profileKey);
    if (!profile) continue;
    const workspace =
      profile.workspaces.find((item) => item.workspaceId === candidate.workspaceId) ||
      profile.workspaces.find((item) => item.workspaceId === profile.defaultWorkspaceId) ||
      profile.workspaces[0];
    if (workspace) {
      return {
        activeProfile: profile,
        activeWorkspace: workspace,
        activeSelection: {
          profileKey: profile.profileKey,
          workspaceId: workspace.workspaceId,
        },
      };
    }
  }

  const activeProfile = profiles[0] || null;
  if (!activeProfile) {
    return {
      activeProfile: null,
      activeWorkspace: null,
      activeSelection: null,
    };
  }
  const activeWorkspace =
    activeProfile.workspaces.find((workspace) => workspace.workspaceId === activeProfile.defaultWorkspaceId) ||
    activeProfile.workspaces[0] ||
    null;
  return {
    activeProfile,
    activeWorkspace,
    activeSelection: activeWorkspace
      ? {
          profileKey: activeProfile.profileKey,
          workspaceId: activeWorkspace.workspaceId,
        }
      : null,
  };
}

export function buildLiveuinProfileShellState(input: {
  bootstrap: ResidentSessionBootstrap;
  entitlements?: unknown;
  requestedSelection?: LiveuinProfileSelection | null;
  rememberedSelection?: LiveuinProfileSelection | null;
}): LiveuinProfileShellState {
  const entitlementRecords = Array.isArray(input.entitlements)
    ? (input.entitlements.filter((record): record is RawEntitlementRecord => Boolean(record) && typeof record === "object") as RawEntitlementRecord[])
    : [];
  const profiles = entitlementRecords.length
    ? buildProfilesFromEntitlements(entitlementRecords)
    : buildTenantFallbackProfile(input.bootstrap);
  const resolved = resolveSelection(profiles, input.requestedSelection, input.rememberedSelection);

  return {
    profiles,
    activeProfile: resolved.activeProfile,
    activeWorkspace: resolved.activeWorkspace,
    activeSelection: resolved.activeSelection,
    source:
      profiles[0]?.source ||
      "none",
  };
}
