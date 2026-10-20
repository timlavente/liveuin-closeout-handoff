import { createContext, useContext, useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useLocation, useNavigate } from "react-router-dom";
import { deriveDeviceResidentMarketplaceFocus, resolveResidentMarketplaceFocus, type ResidentMarketplaceFocus } from "@/lib/residentMarketplaceShelf";
import {
  buildLiveuinProfileRouteTarget,
  buildLiveuinProfileShellState,
  inferLiveuinProfileSelectionFromRoute,
  normalizeLiveuinProfileKey,
  type LiveuinAuthorizedProfile,
  type LiveuinProfileSelection,
  type LiveuinProfileWorkspaceEntitlement,
} from "@/lib/mobileProfileScope";
import { requestResidentNearbyPosition } from "@/lib/residentNearbyLocation";
import { clearResidentSignedSession } from "@/lib/residentSessionBridge";
import {
  PREVIEW_RESIDENT_CASE_ID,
  PREVIEW_SECONDARY_CASE_ID,
  PREVIEW_TERTIARY_CASE_ID,
  PREVIEW_WORKSPACE_ID,
  RESIDENT_AUTH_REQUIRED_EVENT,
  type ResidentCaseRecord,
  type ResidentFinanceRuntime,
  type ResidentPassPayload,
  type ResidentPaymentStatus,
  type ResidentRuntime,
  type ResidentSessionBootstrap,
  type ResidentSessionState,
  type ResidentViewerScope,
  fetchResidentCase,
  fetchResidentFinanceRuntime,
  fetchResidentPass,
  fetchResidentPaymentStatus,
  fetchResidentRuntime,
  fetchResidentSessionBootstrap,
  isResidentAuthError,
} from "@/lib/residentAppRuntime";

type ResidentSurface = "resident" | "pass";

type ResidentCaseOption = {
  caseId: string;
  label: string;
  subtitle: string;
};

type ResidentRequestedAnchor = {
  routeCaseId: string;
  caseId: string;
  bookingId: string;
  stayId: string;
};

type ResidentNearbyPermissionState = "idle" | "requesting" | "granted" | "denied" | "unavailable" | "error";

const RESIDENT_PROFILE_SELECTION_STORAGE_KEY = "liveuin.mobile.profile-selection.v1";

export interface ResidentNearbyContextState extends ResidentMarketplaceFocus {
  permissionState: ResidentNearbyPermissionState;
  lastUpdatedAt: string;
  errorDetail: string;
}

export interface ResidentAppState {
  surface: ResidentSurface;
  viewerScope: ResidentViewerScope;
  bootstrap: ResidentSessionBootstrap;
  sessionState: ResidentSessionState;
  previewMode: boolean;
  authRequired: boolean;
  accountId: string;
  accountLabel: string;
  workspaceId: string;
  actorName: string;
  actorRole: string;
  authorizedProfiles: LiveuinAuthorizedProfile[];
  activeProfile: LiveuinAuthorizedProfile | null;
  activeWorkspace: LiveuinProfileWorkspaceEntitlement | null;
  activeProfileKey: string;
  activeWorkspaceId: string;
  canAccessLocalpro: boolean;
  activeCaseId: string;
  activeCase: ResidentCaseRecord;
  caseOptions: ResidentCaseOption[];
  runtime: ResidentRuntime;
  financeRuntime: ResidentFinanceRuntime;
  paymentStatus: ResidentPaymentStatus;
  passPayload: ResidentPassPayload | null;
  entryMode: string;
  resolvedFrom: string;
  requestedAnchor: ResidentRequestedAnchor;
  nearbyContext: ResidentNearbyContextState;
  isLoading: boolean;
  switchCase: (caseId: string) => void;
  switchProfileWorkspace: (selection: LiveuinProfileSelection) => void;
  requestNearbyDeviceHint: () => Promise<void>;
  clearNearbyDeviceHint: () => void;
}

const ResidentAppContext = createContext<ResidentAppState | null>(null);

function readRememberedProfileSelection(): LiveuinProfileSelection | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(RESIDENT_PROFILE_SELECTION_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as { profileKey?: unknown; workspaceId?: unknown };
    const profileKey = normalizeLiveuinProfileKey(parsed.profileKey);
    const workspaceId = String(parsed.workspaceId || "").trim();
    if (!profileKey || !workspaceId) return null;
    return { profileKey, workspaceId };
  } catch {
    return null;
  }
}

function rememberProfileSelection(selection: LiveuinProfileSelection | null) {
  if (typeof window === "undefined") return;
  try {
    if (!selection) {
      window.localStorage.removeItem(RESIDENT_PROFILE_SELECTION_STORAGE_KEY);
      return;
    }
    window.localStorage.setItem(RESIDENT_PROFILE_SELECTION_STORAGE_KEY, JSON.stringify(selection));
  } catch {
    // Local storage is only a client hint.
  }
}

function replaceCaseInPath(pathname: string, caseId: string) {
  const scopedRoutes = [
    "/tenant/bookings",
    "/tenant/move-in",
    "/tenant/utilities",
    "/tenant/documents",
    "/tenant/verification",
    "/tenant/renewal",
    "/tenant/claims",
  ];
  for (const route of scopedRoutes) {
    if (pathname === route || pathname.startsWith(`${route}/`)) {
      return `${route}/${caseId}`;
    }
  }
  if (pathname === "/pass/case" || pathname.startsWith("/pass/case/payments") || pathname.startsWith("/pass/case/support")) {
    if (pathname.endsWith("/payments")) return `/pass/${caseId}/payments`;
    if (pathname.endsWith("/support")) return `/pass/${caseId}/support`;
    return `/pass/${caseId}`;
  }
  if (pathname.startsWith("/pass/") && pathname.endsWith("/payments")) return `/pass/${caseId}/payments`;
  if (pathname.startsWith("/pass/") && pathname.endsWith("/support")) return `/pass/${caseId}/support`;
  if (pathname.startsWith("/pass/")) return `/pass/${caseId}`;
  return pathname;
}

function findRouteCaseId(pathname: string) {
  return (
    pathname.match(/^\/tenant\/(?:bookings|move-in|utilities|documents|verification|renewal|claims)\/([^/]+)/)?.[1] ||
    pathname.match(/^\/pass\/(?!case(?:\/|$))([^/]+)/)?.[1] ||
    ""
  );
}

function requestedAnchorFromLocation(pathname: string, search: string): ResidentRequestedAnchor {
  const routeCaseId = findRouteCaseId(pathname);
  const params = new URLSearchParams(search);
  return {
    routeCaseId,
    caseId: routeCaseId || params.get("case_id") || "",
    bookingId: params.get("booking_id") || "",
    stayId: params.get("stay_id") || "",
  };
}

function pathUsesCaseQuery(pathname: string) {
  return (
    pathname === "/tenant/home" ||
    pathname === "/tenant/explore" ||
    pathname === "/tenant/payments" ||
    pathname === "/tenant/payments/receipts" ||
    pathname === "/tenant/support" ||
    pathname === "/tenant/account" ||
    pathname === "/tenant/documents" ||
    pathname === "/tenant/messages" ||
    pathname.startsWith("/tenant/messages/") ||
    pathname === "/tenant/notifications" ||
    pathname === "/tenant/saved" ||
    pathname === "/tenant/bookings" ||
    pathname === "/tenant/move-in" ||
    pathname === "/tenant/marketplace" ||
    pathname.startsWith("/tenant/marketplace/") ||
    pathname === "/tenant/wallet" ||
    pathname === "/tenant/wallet/receipts" ||
    pathname === "/tenant/support" ||
    pathname === "/tenant/rewards" ||
    pathname === "/tenant/notifications" ||
    pathname === "/tenant/saved" ||
    pathname === "/tenant/insurance" ||
    pathname === "/tenant/claims"
  );
}

function defaultPathForSurface(surface: ResidentSurface, caseId: string) {
  if (surface === "pass") {
    return `/pass/${caseId}`;
  }
  return `/tenant/home?case_id=${encodeURIComponent(caseId)}`;
}

function buildCaseOptions(bootstrap: ResidentSessionBootstrap, activeCase: ResidentCaseRecord) {
  const previewCaseIds = bootstrap.previewMode
    ? [PREVIEW_RESIDENT_CASE_ID, PREVIEW_SECONDARY_CASE_ID, PREVIEW_TERTIARY_CASE_ID]
    : [];
  const orderedIds = Array.from(new Set([activeCase.caseId, ...bootstrap.caseIds, ...previewCaseIds])).filter(Boolean);
  return orderedIds.map((caseId) => {
    if (caseId === activeCase.caseId) {
      return {
        caseId,
        label: activeCase.propertyLabel || activeCase.roomLabel || caseId,
        subtitle: `${activeCase.school || "Resident"} · ${activeCase.moveIn || "Move-in ready"}`,
      };
    }
    return {
      caseId,
      label:
        caseId === PREVIEW_SECONDARY_CASE_ID
          ? "Canvas Coliving Bugis"
          : caseId === PREVIEW_TERTIARY_CASE_ID
            ? "Harbourfront Suites Residences"
            : "Resident case",
      subtitle:
        caseId === PREVIEW_SECONDARY_CASE_ID
          ? "SMU · Shared utilities"
          : caseId === PREVIEW_TERTIARY_CASE_ID
            ? "SMU Academy · Utilities included"
            : "NUS · Monthly billing",
    };
  });
}

function pendingCase(workspaceId: string): ResidentCaseRecord {
  return {
    caseId: "",
    workspaceId,
    statusGroup: "pending_review",
    studentName: "Resident member",
    parentName: "",
    school: "",
    moveIn: "",
    budgetBand: "",
    roomLabel: "Case review pending",
    propertyLabel: "Resident case review",
    timeline: [
      {
        label: "Home match in progress",
        detail: "This link is still being matched to the right home.",
        state: "pending_review",
      },
    ],
    shortlist: [],
    routes: {},
  };
}

function emptyRuntime(workspaceId: string, viewerScope: ResidentViewerScope, requestedAnchor: ResidentRequestedAnchor): ResidentRuntime {
  return {
    caseId: "",
    workspaceId,
    activeState: "pending_review",
    viewerScope,
    resolvedFrom: requestedAnchor.bookingId ? "booking_id" : requestedAnchor.stayId ? "stay_id" : requestedAnchor.caseId ? "case_id" : "",
    bookingId: requestedAnchor.bookingId,
    stayId: requestedAnchor.stayId,
    allowedActions: [],
    lockedActions: [],
    hiddenActions: [],
    reasonCodes: [],
    visibleFinanceBehavior: { wallet_mode: "hidden" },
    visibleSupportBehavior: { support_enabled: false },
    visibleMoveinBehavior: { move_in_enabled: false },
    visibleRenewalBehavior: { renewal_enabled: false },
    liablePayerMetadata: {},
    billingBehaviorMetadata: {},
    financeRuntime: {
      caseId: "",
      workspaceId,
      activeState: "pending_review",
      walletMode: "hidden",
      runtimeActivationRecordId: "",
      reasonCodes: [],
      liablePayer: {},
      billingBehavior: {},
      mandateBehavior: {},
      approvedFinanceSnapshot: {},
    },
    references: {},
  };
}

function emptyPayments(activeCaseId: string, workspaceId: string): ResidentPaymentStatus {
  return {
    caseId: activeCaseId,
    workspaceId,
    summary: {
      amountDue: 0,
      amountPaid: 0,
      amountRefunded: 0,
      paymentCount: 0,
    },
    bills: [],
    normalizedPayments: [],
    refunds: [],
    exceptions: [],
  };
}

function entryModeForSurface(surface: ResidentSurface, bootstrap: ResidentSessionBootstrap, requestedAnchor: ResidentRequestedAnchor) {
  const channel = String(bootstrap.channel || "").toLowerCase();
  if (surface === "pass") return requestedAnchor.bookingId ? "pass_booking_link" : "pass_case_link";
  if (channel.includes("wechat") || channel.includes("corridor")) return "identity_broker";
  if (requestedAnchor.bookingId) return "booking_deep_link";
  if (requestedAnchor.stayId) return "stay_deep_link";
  if (requestedAnchor.caseId) return "case_deep_link";
  return "direct_login";
}

function clearProfileScopedQueryState(queryClient: ReturnType<typeof useQueryClient>) {
  const scopedPrefixes = [
    "resident-runtime",
    "resident-case",
    "resident-finance-runtime",
    "resident-payments",
    "resident-pass",
    "resident-support-status",
    "resident-lifecycle-status",
    "resident-renewal-status",
  ];
  for (const prefix of scopedPrefixes) {
    queryClient.removeQueries({ queryKey: [prefix] });
  }
}

export function ResidentAppProvider({
  children,
  surface,
}: {
  children: React.ReactNode;
  surface: ResidentSurface;
}) {
  const queryClient = useQueryClient();
  const location = useLocation();
  const navigate = useNavigate();
  const viewerScope: ResidentViewerScope = surface === "pass" ? "pass" : "holder";
  const requestedAnchor = requestedAnchorFromLocation(location.pathname, location.search);
  const [deviceNearbyHint, setDeviceNearbyHint] = useState<ResidentMarketplaceFocus | null>(null);
  const [nearbyPermissionState, setNearbyPermissionState] = useState<ResidentNearbyPermissionState>("idle");
  const [nearbyErrorDetail, setNearbyErrorDetail] = useState("");
  const [nearbyUpdatedAt, setNearbyUpdatedAt] = useState("");
  const [forcedAuthReasonCode, setForcedAuthReasonCode] = useState("");
  const [rememberedProfileSelection, setRememberedProfileSelection] = useState<LiveuinProfileSelection | null>(() => readRememberedProfileSelection());

  const bootstrapQuery = useQuery({
    queryKey: ["resident-session-bootstrap"],
    queryFn: fetchResidentSessionBootstrap,
    staleTime: 60_000,
  });

  const bootstrapReady = Boolean(bootstrapQuery.data);
  const bootstrap =
    bootstrapQuery.data || {
      accountId: "",
      accountLabel: "Resident member",
      workspaceId: PREVIEW_WORKSPACE_ID,
      actorId: "",
      actorName: "Resident member",
      role: "tenant",
      scopes: [],
      sourceFamily: "liveuin_core",
      countryCode: "SG",
      locale: "en-SG",
      channel: "",
      activeCaseId: "",
      caseIds: [],
      sessionState: "auth_required" as const,
      identityResolved: false,
      identityVerified: false,
      credentialKind: "none",
      previewMode: false,
      authRequired: false,
      reasonCode: "bootstrap_loading",
      defaultProfileKey: "",
      defaultWorkspaceId: "",
      profileEntitlements: [],
    };

  const bootstrapProfileSelection = inferLiveuinProfileSelectionFromRoute({
    pathname: location.pathname,
    search: location.search,
    fallbackWorkspaceId: bootstrap.defaultWorkspaceId || bootstrap.workspaceId || PREVIEW_WORKSPACE_ID,
  });
  const bootstrapProfileShellState = buildLiveuinProfileShellState({
    bootstrap,
    entitlements: bootstrap.profileEntitlements,
    requestedSelection: bootstrapProfileSelection,
    rememberedSelection: rememberedProfileSelection,
  });
  const bootstrapActiveProfileKey = bootstrapProfileShellState.activeProfile?.profileKey || normalizeLiveuinProfileKey(bootstrap.role) || "tenant";
  const bootstrapActiveWorkspaceId =
    bootstrapProfileShellState.activeWorkspace?.workspaceId || bootstrap.defaultWorkspaceId || bootstrap.workspaceId || PREVIEW_WORKSPACE_ID;
  const bootstrapTenantWorkspaceId = bootstrap.workspaceId || bootstrapActiveWorkspaceId || PREVIEW_WORKSPACE_ID;
  const bootstrapBlocksResidentQueries =
    bootstrapReady && (bootstrap.authRequired || Boolean(forcedAuthReasonCode) || bootstrapActiveProfileKey !== "tenant");

  const runtimeRequestedCaseId =
    bootstrapReady && bootstrapActiveProfileKey === "tenant"
      ? requestedAnchor.caseId ||
        (!requestedAnchor.bookingId && !requestedAnchor.stayId
          ? bootstrap.activeCaseId || (bootstrap.previewMode ? PREVIEW_RESIDENT_CASE_ID : "")
          : "")
      : "";

  const runtimeQuery = useQuery({
    queryKey: [
      "resident-runtime",
      bootstrapTenantWorkspaceId,
      runtimeRequestedCaseId,
      requestedAnchor.bookingId,
      requestedAnchor.stayId,
      viewerScope,
    ],
    queryFn: () =>
      fetchResidentRuntime({
        workspaceId: bootstrapTenantWorkspaceId,
        viewerScope,
        caseId: runtimeRequestedCaseId,
        bookingId: requestedAnchor.bookingId,
        stayId: requestedAnchor.stayId,
      }),
    enabled: !bootstrapBlocksResidentQueries && bootstrapReady && Boolean(runtimeRequestedCaseId || requestedAnchor.bookingId || requestedAnchor.stayId),
    staleTime: 30_000,
  });

  const runtime = runtimeQuery.data || emptyRuntime(bootstrapActiveWorkspaceId, viewerScope, requestedAnchor);
  const runtimeActiveCaseId =
    bootstrapActiveProfileKey === "tenant"
      ? runtime.caseId ||
        (bootstrapReady && bootstrap.previewMode && !requestedAnchor.bookingId && !requestedAnchor.stayId
          ? requestedAnchor.caseId || bootstrap.activeCaseId || PREVIEW_RESIDENT_CASE_ID
          : "")
      : "";
  const runtimeWorkspaceId = runtime.workspaceId || bootstrapTenantWorkspaceId;

  const caseQuery = useQuery({
    queryKey: ["resident-case", runtimeWorkspaceId, runtimeActiveCaseId],
    queryFn: () => fetchResidentCase(runtimeActiveCaseId, runtimeWorkspaceId),
    enabled: !bootstrapBlocksResidentQueries && bootstrapReady && Boolean(runtimeActiveCaseId),
    staleTime: 60_000,
  });
  const financeRuntimeQuery = useQuery({
    queryKey: ["resident-finance-runtime", runtimeWorkspaceId, runtimeActiveCaseId],
    queryFn: () => fetchResidentFinanceRuntime(runtimeActiveCaseId, runtimeWorkspaceId),
    enabled: !bootstrapBlocksResidentQueries && bootstrapReady && Boolean(runtimeActiveCaseId),
    staleTime: 30_000,
  });
  const paymentStatusQuery = useQuery({
    queryKey: ["resident-payments", runtimeWorkspaceId, runtimeActiveCaseId],
    queryFn: () => fetchResidentPaymentStatus(runtimeActiveCaseId, runtimeWorkspaceId),
    enabled: !bootstrapBlocksResidentQueries && bootstrapReady && Boolean(runtimeActiveCaseId),
    staleTime: 30_000,
  });
  const passQuery = useQuery({
    queryKey: ["resident-pass", runtimeWorkspaceId, runtimeActiveCaseId],
    queryFn: () => fetchResidentPass(runtimeActiveCaseId, runtimeWorkspaceId),
    enabled: !bootstrapBlocksResidentQueries && bootstrapReady && surface === "pass" && Boolean(runtimeActiveCaseId),
    staleTime: 30_000,
  });

  const residentAuthFailure = [
    forcedAuthReasonCode,
    isResidentAuthError(bootstrapQuery.error) ? "identity_session_required" : "",
    isResidentAuthError(runtimeQuery.error) ? "identity_session_required" : "",
    isResidentAuthError(caseQuery.error) ? "identity_session_required" : "",
    isResidentAuthError(financeRuntimeQuery.error) ? "identity_session_required" : "",
    isResidentAuthError(paymentStatusQuery.error) ? "identity_session_required" : "",
    isResidentAuthError(passQuery.error) ? "identity_session_required" : "",
  ].find(Boolean) || "";

  const effectiveBootstrap =
    residentAuthFailure && !bootstrap.previewMode
      ? {
          ...bootstrap,
          activeCaseId: "",
          caseIds: [],
          sessionState: "auth_required" as const,
          identityVerified: false,
          previewMode: false,
          authRequired: true,
          reasonCode: residentAuthFailure,
        }
      : bootstrap;

  const finalProfileSelection = inferLiveuinProfileSelectionFromRoute({
    pathname: location.pathname,
    search: location.search,
    fallbackWorkspaceId: effectiveBootstrap.defaultWorkspaceId || effectiveBootstrap.workspaceId || PREVIEW_WORKSPACE_ID,
  });
  const profileShellState = buildLiveuinProfileShellState({
    bootstrap: effectiveBootstrap,
    entitlements: effectiveBootstrap.profileEntitlements,
    requestedSelection: finalProfileSelection,
    rememberedSelection: rememberedProfileSelection,
  });
  const activeProfile = profileShellState.activeProfile;
  const activeWorkspace = profileShellState.activeWorkspace;
  const activeProfileKey = activeProfile?.profileKey || normalizeLiveuinProfileKey(effectiveBootstrap.role) || "tenant";
  const activeWorkspaceId =
    activeWorkspace?.workspaceId || effectiveBootstrap.defaultWorkspaceId || effectiveBootstrap.workspaceId || PREVIEW_WORKSPACE_ID;
  const canAccessLocalpro = profileShellState.profiles.some((profile) => profile.profileKey === "localpro");

  const tenantWorkspaceId =
    runtime.workspaceId ||
    caseQuery.data?.workspaceId ||
    financeRuntimeQuery.data?.workspaceId ||
    paymentStatusQuery.data?.workspaceId ||
    effectiveBootstrap.workspaceId ||
    activeWorkspaceId ||
    bootstrapTenantWorkspaceId;
  const activeCaseId = activeProfileKey === "tenant" ? runtimeActiveCaseId : "";
  const activeCase =
    activeProfileKey === "tenant" ? caseQuery.data || pendingCase(tenantWorkspaceId) : pendingCase(activeWorkspaceId || tenantWorkspaceId);
  const financeRuntime =
    activeProfileKey === "tenant" ? financeRuntimeQuery.data || runtime.financeRuntime : emptyRuntime(activeWorkspaceId, viewerScope, requestedAnchor).financeRuntime;
  const paymentStatus =
    activeProfileKey === "tenant" ? paymentStatusQuery.data || emptyPayments(activeCaseId, tenantWorkspaceId) : emptyPayments("", activeWorkspaceId);
  const passPayload = activeProfileKey === "tenant" && surface === "pass" ? passQuery.data || null : null;
  const caseOptions =
    activeProfileKey === "tenant" && bootstrapReady && (effectiveBootstrap.previewMode || activeCase.caseId || effectiveBootstrap.caseIds.length)
      ? buildCaseOptions(effectiveBootstrap, activeCase)
      : [];
  const activeLocalProMissionId =
    activeProfileKey === "localpro"
      ? String(new URLSearchParams(location.search).get("mission_id") || "").trim()
      : "";
  const entryMode = entryModeForSurface(surface, effectiveBootstrap, requestedAnchor);
  const resolvedNearbyFocus = resolveResidentMarketplaceFocus(activeCase, deviceNearbyHint);
  const nearbyContext: ResidentNearbyContextState = {
    ...resolvedNearbyFocus,
    permissionState: nearbyPermissionState,
    lastUpdatedAt: nearbyUpdatedAt,
    errorDetail: nearbyErrorDetail,
  };

  useEffect(() => {
    if (typeof window === "undefined") return undefined;

    const handleResidentAuthRequired = (event: Event) => {
      const detail = (event as CustomEvent<{ reasonCode?: string }>).detail;
      const reasonCode = String(detail?.reasonCode || "identity_session_required");
      clearResidentSignedSession();
      setForcedAuthReasonCode(reasonCode);
      void queryClient.invalidateQueries({ queryKey: ["resident-session-bootstrap"] });
    };

    window.addEventListener(RESIDENT_AUTH_REQUIRED_EVENT, handleResidentAuthRequired);
    return () => {
      window.removeEventListener(RESIDENT_AUTH_REQUIRED_EVENT, handleResidentAuthRequired);
    };
  }, [queryClient]);

  useEffect(() => {
    if (effectiveBootstrap.sessionState === "resolved" && forcedAuthReasonCode) {
      setForcedAuthReasonCode("");
    }
  }, [effectiveBootstrap.sessionState, forcedAuthReasonCode]);

  useEffect(() => {
    if (!profileShellState.activeSelection) {
      rememberProfileSelection(null);
      return;
    }
    rememberProfileSelection(profileShellState.activeSelection);
    setRememberedProfileSelection((current) => {
      if (
        current?.profileKey === profileShellState.activeSelection?.profileKey &&
        current?.workspaceId === profileShellState.activeSelection?.workspaceId
      ) {
        return current;
      }
      return profileShellState.activeSelection;
    });
  }, [profileShellState.activeSelection]);

  useEffect(() => {
    if (!bootstrapReady || effectiveBootstrap.authRequired || activeProfileKey === "tenant") return;
    const activeRouteSelection = inferLiveuinProfileSelectionFromRoute({
      pathname: location.pathname,
      search: location.search,
      fallbackWorkspaceId: activeWorkspaceId,
    });
    if (
      activeRouteSelection?.profileKey === activeProfileKey &&
      activeRouteSelection.workspaceId === activeWorkspaceId
    ) {
      return;
    }
    const target = buildLiveuinProfileRouteTarget({
      profileKey: activeProfileKey as never,
      workspaceId: activeWorkspaceId,
      caseId: effectiveBootstrap.activeCaseId,
      missionId: activeLocalProMissionId,
      surface,
    });
    navigate(target, { replace: true });
  }, [
    activeLocalProMissionId,
    activeProfileKey,
    activeWorkspaceId,
    bootstrapReady,
    effectiveBootstrap.activeCaseId,
    effectiveBootstrap.authRequired,
    location.pathname,
    location.search,
    navigate,
    surface,
  ]);

  useEffect(() => {
    if (activeProfileKey !== "tenant" || !runtime.caseId) return;
    const nextPath = replaceCaseInPath(location.pathname, runtime.caseId);
    const params = new URLSearchParams(location.search);
    let changed = false;

    if (pathUsesCaseQuery(nextPath)) {
      if (params.get("case_id") !== runtime.caseId) {
        params.set("case_id", runtime.caseId);
        changed = true;
      }
    } else if (params.has("case_id")) {
      params.delete("case_id");
      changed = true;
    }

    if (params.get("workspace_id") !== tenantWorkspaceId) {
      params.set("workspace_id", tenantWorkspaceId);
      changed = true;
    }

    if (params.has("booking_id")) {
      params.delete("booking_id");
      changed = true;
    }

    if (params.has("stay_id") && runtime.resolvedFrom !== "stay_id") {
      params.delete("stay_id");
      changed = true;
    }

    const nextSearch = params.toString();
    const normalizedSearch = location.search.startsWith("?") ? location.search.slice(1) : location.search;
    if (nextPath === location.pathname && nextSearch === normalizedSearch) return;
    navigate({ pathname: nextPath, search: nextSearch ? `?${nextSearch}` : "" }, { replace: true });
  }, [activeProfileKey, location.pathname, location.search, navigate, runtime.caseId, runtime.resolvedFrom, tenantWorkspaceId]);

  const switchCase = (caseId: string) => {
    if (activeProfileKey !== "tenant") return;
    const nextPath = replaceCaseInPath(location.pathname, caseId);
    if (surface === "pass") {
      const target = buildLiveuinProfileRouteTarget({
        profileKey: "tenant",
        workspaceId: tenantWorkspaceId,
        caseId,
        surface,
      });
      navigate(nextPath === location.pathname ? target : `${nextPath}?workspace_id=${encodeURIComponent(tenantWorkspaceId)}`, { replace: false });
      return;
    }
    const params = new URLSearchParams(location.search);
    params.delete("booking_id");
    params.delete("stay_id");
    params.set("workspace_id", tenantWorkspaceId);
    if (pathUsesCaseQuery(nextPath)) {
      params.set("case_id", caseId);
    } else {
      params.delete("case_id");
    }
    navigate({ pathname: nextPath, search: params.toString() ? `?${params.toString()}` : "" }, { replace: false });
  };

  const switchProfileWorkspace = (selection: LiveuinProfileSelection) => {
    const profile = profileShellState.profiles.find((item) => item.profileKey === selection.profileKey);
    const workspace = profile?.workspaces.find((item) => item.workspaceId === selection.workspaceId);
    if (!profile || !workspace) return;
    if (selection.profileKey !== activeProfileKey || selection.workspaceId !== activeWorkspaceId) {
      clearProfileScopedQueryState(queryClient);
    }
    setRememberedProfileSelection(selection);
    rememberProfileSelection(selection);
    const target = buildLiveuinProfileRouteTarget({
      profileKey: selection.profileKey,
      workspaceId: selection.workspaceId,
      caseId: selection.profileKey === "tenant" ? activeCaseId || effectiveBootstrap.activeCaseId : "",
      surface,
    });
    navigate(target, { replace: false });
  };

  const requestNearbyDeviceHint = async () => {
    setNearbyPermissionState("requesting");
    setNearbyErrorDetail("");
    try {
      const position = await requestResidentNearbyPosition();
      setDeviceNearbyHint(deriveDeviceResidentMarketplaceFocus(position.latitude, position.longitude));
      setNearbyPermissionState("granted");
      setNearbyUpdatedAt(new Date().toISOString());
    } catch (error) {
      const message = error instanceof Error ? error.message : "geolocation_unavailable";
      setDeviceNearbyHint(null);
      setNearbyPermissionState(message === "geolocation_denied" ? "denied" : message === "geolocation_unavailable" ? "unavailable" : "error");
      setNearbyErrorDetail(message.replaceAll("_", " "));
      setNearbyUpdatedAt(new Date().toISOString());
    }
  };

  const clearNearbyDeviceHint = () => {
    setDeviceNearbyHint(null);
    setNearbyPermissionState("idle");
    setNearbyErrorDetail("");
    setNearbyUpdatedAt(new Date().toISOString());
  };

  return (
    <ResidentAppContext.Provider
      value={{
        surface,
        viewerScope,
        bootstrap: effectiveBootstrap,
        sessionState: effectiveBootstrap.sessionState,
        previewMode: effectiveBootstrap.previewMode,
        authRequired: effectiveBootstrap.authRequired,
        accountId: effectiveBootstrap.accountId,
        accountLabel: effectiveBootstrap.accountLabel,
        workspaceId: activeProfileKey === "tenant" ? tenantWorkspaceId : activeWorkspaceId || tenantWorkspaceId,
        actorName: effectiveBootstrap.actorName,
        actorRole: activeProfileKey === "tenant" ? effectiveBootstrap.role : activeProfileKey,
        authorizedProfiles: profileShellState.profiles,
        activeProfile,
        activeWorkspace,
        activeProfileKey,
        activeWorkspaceId,
        canAccessLocalpro,
        activeCaseId,
        activeCase,
        caseOptions,
        runtime: activeProfileKey === "tenant" ? runtime : emptyRuntime(activeWorkspaceId, viewerScope, requestedAnchor),
        financeRuntime,
        paymentStatus,
        passPayload,
        entryMode,
        resolvedFrom: activeProfileKey === "tenant" ? runtime.resolvedFrom : "",
        requestedAnchor,
        nearbyContext,
        isLoading:
          !effectiveBootstrap.authRequired &&
          (bootstrapQuery.isLoading ||
            (bootstrapReady &&
              activeProfileKey === "tenant" &&
              (runtimeQuery.isLoading ||
                caseQuery.isLoading ||
                financeRuntimeQuery.isLoading ||
                paymentStatusQuery.isLoading ||
                passQuery.isLoading))),
        switchCase,
        switchProfileWorkspace,
        requestNearbyDeviceHint,
        clearNearbyDeviceHint,
      }}
    >
      {children}
    </ResidentAppContext.Provider>
  );
}

export function useResidentApp() {
  const value = useContext(ResidentAppContext);
  if (!value) {
    throw new Error("useResidentApp must be used inside ResidentAppProvider");
  }
  return value;
}
