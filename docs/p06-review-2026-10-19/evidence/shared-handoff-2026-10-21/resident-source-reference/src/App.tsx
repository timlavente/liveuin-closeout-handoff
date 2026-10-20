import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Component, Suspense, lazy, useEffect } from "react";
import type { ErrorInfo, ReactNode } from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation, useSearchParams } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { PublicThemeBootstrap } from "@/components/PublicThemeBootstrap";
import { ChinesePublicMirror } from "@/components/ChinesePublicMirror";
import { getResidentSignedSession } from "./lib/residentSessionBridge";
import {
  buildAppHref,
  buildAiHref,
  buildConnectHref,
  buildHostHref,
  buildOpsHref,
  buildPassHref,
  buildPartnerHref,
  buildVendorHref,
  isCorePreviewHost,
  isAnyPassHost,
  isAppHost,
  isAiHost,
  isCnHost,
  isConnectHost,
  isHostHost,
  isNativeRuntimeShell,
  isOpsLovablePreviewPath,
  isOpsHost,
  isPartnerHost,
  isPreviewHost,
  isStagingHostSurfacePreview,
  runtimeHostname,
  isVendorHost,
} from "./lib/runtimeHost";
import { ResidentNativeEntryBridge } from "./components/resident/ResidentNativeEntryBridge";
import { ResidentNativeAppRouteLock } from "./components/resident/ResidentNativeAppRouteLock";
import { ResidentNativeRouteGate } from "./components/resident/ResidentNativeRouteGate";
import { OpsAuthGate } from "./components/opsui/OpsAuthGate";
import { WorkspaceIdentityGate } from "./components/opsui/WorkspaceIdentityGate";
import { AuthorizedProfileRoute } from "./components/resident/AuthorizedProfileRoute";
import { ResidentRouteAlias } from "./components/resident/ResidentRouteAlias";
import { ResidentAppProvider } from "./components/resident/ResidentAppContext";
import { AuthProvider } from "./lib/auth-context";
import { LanguageProvider } from "./lib/language-context";
import { ProfileProvider } from "./lib/profile-context";
import { cn } from "./lib/utils";

const Index = lazy(() => import("./pages/Index"));
const PublicProductPage = lazy(() => import("./pages/PublicProductPage"));
const ChineseHome = lazy(() =>
  import("./pages/Index").then(({ PublicHome }) => ({
    default: () => <PublicHome locale="zh-CN" />,
  })),
);
const Explore = lazy(() => import("./pages/Explore"));
const Cities = lazy(() => import("./pages/Cities"));
const Services = lazy(() => import("./pages/Services"));
const Deals = lazy(() => import("./pages/Deals"));
const Community = lazy(() => import("./pages/Community"));
const CommunityEvent = lazy(() => import("./pages/CommunityEvent"));
const Promotions = lazy(() => import("./pages/Promotions"));
const HowItWorks = lazy(() => import("./pages/HowItWorks"));
const Trust = lazy(() => import("./pages/Trust"));
const SharedHousingPolicyDraft = lazy(() => import("./pages/SharedHousingPolicyDraft"));
const Help = lazy(() => import("./pages/Help"));
const PublicHelpDetail = lazy(() => import("./pages/PublicHelpDetail"));
const Legal = lazy(() => import("./pages/Legal"));
const LegalPolicy = lazy(() => import("./pages/LegalPolicy"));
const Solutions = lazy(() => import("./pages/Solutions"));
const Pricing = lazy(() => import("./pages/Pricing"));
const Blog = lazy(() => import("./pages/Blog"));
const BlogArticle = lazy(() => import("./pages/BlogArticle"));
const Contact = lazy(() => import("./pages/Contact"));
const GetStarted = lazy(() => import("./pages/GetStarted"));
const ListProperty = lazy(() => import("./pages/ListProperty"));
const SearchResults = lazy(() => import("./pages/SearchResults"));
const StayDetail = lazy(() => import("./pages/StayDetail"));
const CityPage = lazy(() => import("./pages/CityPage"));
const Checkout = lazy(() => import("./pages/Checkout"));
const About = lazy(() => import("./pages/About"));
const Careers = lazy(() => import("./pages/Careers"));
const Newsroom = lazy(() => import("./pages/Newsroom"));
const Press = lazy(() => import("./pages/Press"));
const Login = lazy(() => import("./pages/Login"));
const OpsPreviewSignIn = lazy(() => import("./pages/OpsPreviewSignIn"));
const OpsLogin = lazy(() => import("./pages/OpsLogin"));
const LovableWelcome = lazy(() =>
  import("./native-lovable/routes/welcome").then((module) => ({
    default: module.Route.options.component!,
  })),
);
const LovableAuthSignIn = lazy(() =>
  import("./native-lovable/routes/auth.sign-in").then((module) => ({
    default: module.Route.options.component!,
  })),
);
const Assessment = lazy(() => import("./pages/Assessment"));
const MoveInSupport = lazy(() => import("./pages/MoveInSupport"));
const Investors = lazy(() => import("./pages/Investors"));
const Api = lazy(() => import("./pages/Api"));
const Developers = lazy(() => import("./pages/Developers"));
const DeveloperPortalDetail = lazy(() => import("./pages/DeveloperPortalDetail"));
const Guides = lazy(() => import("./pages/Guides"));
const Sitemap = lazy(() => import("./pages/Sitemap"));
const PartnerProgram = lazy(() => import("./pages/PartnerProgram"));
const AgentTools = lazy(() => import("./pages/AgentTools"));
const SchoolPartnerships = lazy(() => import("./pages/SchoolPartnerships"));
const OwnerBenefits = lazy(() => import("./pages/OwnerBenefits"));
const RelocationPartners = lazy(() => import("./pages/RelocationPartners"));
const ApiIntegrations = lazy(() => import("./pages/ApiIntegrations"));
const DataRoom = lazy(() => import("./pages/DataRoom"));
const Status = lazy(() => import("./pages/Status"));
const SolutionsTenants = lazy(() => import("./pages/SolutionsTenants"));
const SolutionsLandlords = lazy(() => import("./pages/SolutionsLandlords"));
const SolutionsOperators = lazy(() => import("./pages/SolutionsOperators"));
const SolutionsAgents = lazy(() => import("./pages/SolutionsAgents"));
const SolutionsSchools = lazy(() => import("./pages/SolutionsSchools"));
const SolutionsVendors = lazy(() => import("./pages/SolutionsVendors"));
const SolutionsEnterprise = lazy(() => import("./pages/SolutionsEnterprise"));
const PartnerWorkspace = lazy(() => import("./pages/PartnerWorkspace"));
const PartnerLeadsPreview = lazy(() => import("./pages/PartnerLeadsPreview"));
const PartnerSharePreview = lazy(() => import("./pages/PartnerSharePreview"));
const PartnerEntitlementsPreview = lazy(() => import("./pages/PartnerEntitlementsPreview"));
const PartnerInventoryMedia = lazy(() => import("./pages/PartnerInventoryMedia"));
const ConnectSitesPreview = lazy(() => import("./pages/ConnectSitesPreview"));
const ConnectBrandingPreview = lazy(() => import("./pages/ConnectBrandingPreview"));
const ConnectDomainsPreview = lazy(() => import("./pages/ConnectDomainsPreview"));
const ConnectOnboardingPreview = lazy(() => import("./pages/ConnectOnboardingPreview"));
const ConnectPublicRoute = lazy(() => import("./pages/ConnectPublicRoute"));
const VendorWorkspace = lazy(() => import("./pages/VendorWorkspace"));
const VendorJobsPreview = lazy(() => import("./pages/VendorJobsPreview"));
const VendorProofPreview = lazy(() => import("./pages/VendorProofPreview"));
const VendorEarningsPreview = lazy(() => import("./pages/VendorEarningsPreview"));
const VendorFounderTask = lazy(() => import("./pages/VendorFounderTask"));
const FounderOpsConsole = lazy(() => import("./pages/FounderOpsConsole"));
const FounderJourney = lazy(() => import("./pages/FounderJourney"));
const OperatorSelfView = lazy(() => import("./pages/OperatorSelfView"));
const OpsThemeStudio = lazy(() => import("./pages/OpsThemeStudio"));
const Studio = lazy(() => import("./pages/Studio"));
const NotFound = lazy(() => import("./pages/NotFound"));
const AppMemberHome = lazy(() => import("./pages/AppMemberHome"));
const AppAccount = lazy(() => import("./pages/AppAccount"));
const AppAccountPrivacy = lazy(() => import("./pages/AppAccountPrivacy"));
const AppAccountProfile = lazy(() => import("./pages/AppAccountProfile"));
const AppAccountSecurity = lazy(() => import("./pages/AppAccountSecurity"));
const AppAccountSettings = lazy(() => import("./pages/AppAccountSettings"));
const AppSavedHomes = lazy(() => import("./pages/AppSavedHomes"));
const AppInsurance = lazy(() => import("./pages/AppInsurance"));
const AppClaimsPreview = lazy(() => import("./pages/AppClaimsPreview"));
const AppNotifications = lazy(() => import("./pages/AppNotifications"));
const AppMessages = lazy(() => import("./pages/AppMessages"));
const AppMessageThread = lazy(() => import("./pages/AppMessageThread"));
const AppJourney = lazy(() => import("./pages/AppJourney"));
const AppBookingStatus = lazy(() => import("./pages/AppBookingStatus"));
const AppMoveInStatus = lazy(() => import("./pages/AppMoveInStatus"));
const AppMarketplace = lazy(() => import("./pages/AppMarketplace"));
const AppMarketplaceOffer = lazy(() => import("./pages/AppMarketplaceOffer"));
const AppEarn = lazy(() => import("./pages/AppEarn"));
const AppEarnVerification = lazy(() => import("./pages/AppEarnVerification"));
const AppLocalProLovableScreen = lazy(() => import("./pages/AppLocalProLovableScreen"));
const AppResidentLovableScreen = lazy(() => import("./pages/AppResidentLovableScreen"));
const TenantHome = lazy(() => import("./pages/TenantHome"));
const AppRewards = lazy(() => import("./pages/AppRewards"));
const AppSupportNew = lazy(() => import("./pages/AppSupportNew"));
const HostOnboarding = lazy(() => import("./pages/HostOnboarding"));
const HostPropertiesPreview = lazy(() => import("./pages/HostPropertiesPreview"));
const HostBookingsPreview = lazy(() => import("./pages/HostBookingsPreview"));
const HostBookingDetail = lazy(() => import("./pages/HostBookingDetail"));
const Marketplace = lazy(() => import("./pages/Marketplace"));
const MarketplaceOffer = lazy(() => import("./pages/MarketplaceOffer"));
const OpsMarketplace = lazy(() => import("./pages/OpsMarketplace"));
const OpsControlTower = lazy(() => import("./pages/OpsControlTower"));
const OpsCommand = lazy(() => import("./pages/OpsCommand"));
const OpsPayments = lazy(() => import("./pages/OpsPayments"));
const OpsReview = lazy(() => import("./pages/OpsReview"));
const OpsChangeControl = lazy(() => import("./pages/OpsChangeControl").then(({ OpsChangeControl }) => ({ default: OpsChangeControl })));
const OpsAiGovernance = lazy(() => import("./pages/OpsAiGovernance"));
const SourceOwnerManagement = lazy(() => import("./pages/SourceOwnerManagement"));
const OpsSourceIntake = lazy(() => import("./pages/OpsSourceIntake"));
const OpsPropertyMedia = lazy(() => import("./pages/OpsPropertyMedia"));
const OpsDemand = lazy(() => import("./pages/OpsDemand"));
const OpsDemandNew = lazy(() => import("./pages/OpsDemandNew"));
const OpsDemandDetail = lazy(() => import("./pages/OpsDemandDetail"));
const OpsDemandQueue = lazy(() => import("./pages/OpsDemandQueue"));
const HostFinance = lazy(() => import("./pages/HostFinance"));
const FinanceSettlements = lazy(() => import("./pages/FinanceSettlements"));
const FinanceExports = lazy(() => import("./pages/FinanceExports"));
const Wallet = lazy(() => import("./pages/Wallet"));
const WalletReceipts = lazy(() => import("./pages/WalletReceipts"));
const PassCaseOverview = lazy(() => import("./pages/PassCaseOverview"));
const PassPayments = lazy(() => import("./pages/PassPayments"));
const PassSupport = lazy(() => import("./pages/PassSupport"));
const AppResidentExplore = lazy(() => import("./pages/AppResidentExplore"));
const AppResidentSupport = lazy(() => import("./pages/AppResidentSupport"));
const AppResidentCaseModule = lazy(() => import("./pages/AppResidentCaseModule"));
const PartnerOfferNew = lazy(() => import("./pages/PartnerOfferNew"));
const WorkspaceSignIn = lazy(() => import("./pages/WorkspaceSignIn"));
const HandoverRewards = lazy(() => import("./pages/HandoverRewards"));
const CnPublicRoute = lazy(() => import("./pages/CnPublicRoute"));
const Pass = lazy(() => import("./pages/Pass"));
const ResidentLayoutRoute = lazy(() => import("./components/resident/ResidentLayoutRoute"));
const PassLayoutRoute = lazy(() => import("./components/resident/PassLayoutRoute"));

const RoleAwareLogin = () => {
  const [searchParams] = useSearchParams();
  const requestedRole = searchParams.get("role") || "";
  const returnTo = searchParams.get("return_to") || searchParams.get("returnTo") || "";
  const isOpsLogin = ["ops", "ops_manager", "super_admin"].includes(requestedRole) || returnTo.startsWith("/ops/");

  if (isOpsLogin) {
    const params = new URLSearchParams();
    if (requestedRole) params.set("role", requestedRole);
    params.set("return_to", returnTo || "/ops/command");
    return <Navigate replace to={`/ops/login?${params.toString()}`} />;
  }

  const workspaceRole = requestedRole === "host" || requestedRole === "owner" || requestedRole === "landlord"
    ? "host"
    : requestedRole === "partner" || requestedRole === "agent"
      ? "partner"
      : requestedRole === "connect" || requestedRole === "connector_admin"
        ? "connect"
        : "";
  if (workspaceRole) return <WorkspaceSignIn role={workspaceRole} />;

  return <Login />;
};

const LegacyGetStartedRedirect = () => {
  const { search, hash } = useLocation();
  return <Navigate replace to={{ pathname: "/start", search, hash }} />;
};

type ChinesePublicProductKey = "stay" | "grow" | "earn" | "host" | "operate" | "partner" | "connect" | "campus" | "enterprise";

const ChinesePublicProduct = ({ product, variant }: { product: ChinesePublicProductKey; variant?: "solo" }) => (
  <PublicProductPage product={product} variant={variant} />
);

const PublicAliasRedirect = ({ to }: { to: string }) => {
  const { search, hash } = useLocation();
  return <Navigate to={{ pathname: to, search, hash }} replace />;
};

const ChinesePublicSearch = () => <SearchResults />;

const runtimeBasePath = () => {
  const base = String(import.meta.env.BASE_URL || "/").replace(/\/$/, "");
  return base === "/" ? "" : base;
};

const isStandaloneOpsLoginPath = () => {
  if (typeof window === "undefined") return false;
  const basePath = runtimeBasePath();
  const pathname = window.location.pathname;
  if (basePath === "/ops/login") return pathname === basePath || pathname === `${basePath}/`;
  const routePath = basePath && pathname.startsWith(`${basePath}/`)
    ? pathname.slice(basePath.length) || "/"
    : pathname;
  return routePath === "/ops/login";
};

const StandaloneOpsLoginFallback = () => (
  <main className="flex min-h-screen items-center justify-center bg-slate-950 px-6 text-white">
    <p className="text-sm text-slate-300">Opening Core Identity staging...</p>
  </main>
);

const chinesePublicMirrorRoutes = [
  ["/careers", Careers],
  ["/connect/request", ConnectPublicRoute],
  ["/connect/checkout/return", ConnectPublicRoute],
  ["/connect/setup/complete", ConnectPublicRoute],
  ["/data-room", DataRoom],
  ["/developers", Developers],
  ["/developers/docs", DeveloperPortalDetail],
  ["/developers/docs/api", DeveloperPortalDetail],
  ["/developers/docs/webhooks", DeveloperPortalDetail],
  ["/developers/docs/sdks", DeveloperPortalDetail],
  ["/developers/keys", DeveloperPortalDetail],
  ["/developers/sandbox", DeveloperPortalDetail],
  ["/developers/marketplace", DeveloperPortalDetail],
  ["/developers/limits", DeveloperPortalDetail],
  ["/developers/changelog", DeveloperPortalDetail],
  ["/guides", Guides],
  ["/help", Help],
  ["/help/contact", PublicHelpDetail],
  ["/help/tickets/new", PublicHelpDetail],
  ["/help/stay", PublicHelpDetail],
  ["/help/grow", PublicHelpDetail],
  ["/help/earn", PublicHelpDetail],
  ["/help/billing", PublicHelpDetail],
  ["/help/emergency", PublicHelpDetail],
  ["/how-it-works", HowItWorks],
  ["/investors", Investors],
  ["/legal", Legal],
  ["/legal/:slug", LegalPolicy],
  ["/newsroom", Newsroom],
  ["/partner-program", PartnerProgram],
  ["/pass", Pass],
  ["/press", Press],
  ["/pricing", Pricing],
  ["/services", Services],
  ["/solutions", Solutions],
  ["/solutions/agents", SolutionsAgents],
  ["/solutions/enterprise", SolutionsEnterprise],
  ["/solutions/landlords", SolutionsLandlords],
  ["/solutions/operators", SolutionsOperators],
  ["/solutions/schools", SolutionsSchools],
  ["/solutions/tenants", SolutionsTenants],
  ["/solutions/vendors", SolutionsVendors],
  ["/status", Status],
  ["/trust", Trust],
  ["/trust/shared-housing-policy-draft", SharedHousingPolicyDraft],
] as const;

const legacyPublicSolutionRedirects = [
  ["/solutions/tenants", "/stay"],
  ["/solutions/landlords", "/host"],
  ["/solutions/operators", "/operate"],
  ["/solutions/agents", "/partner"],
  ["/solutions/schools", "/campus"],
  ["/solutions/vendors", "/earn"],
  ["/solutions/enterprise", "/enterprise"],
] as const;

const founderRuntimeEnv = String(import.meta.env.VITE_LIVEUIN_RUNTIME_ENV || "").trim().toLowerCase();
const founderTestModeEnabled = isPreviewHost() && (
  import.meta.env.DEV || (
    import.meta.env.VITE_LIVEUIN_FOUNDER_SANDBOX_ENABLED === "true"
    && ["local", "staging"].includes(founderRuntimeEnv)
  )
);
export const appQueryClient = new QueryClient();

const OpsRouteFallback = () => (
  <main className="flex min-h-screen items-center justify-center bg-slate-950 px-6 text-white">
    <div className="text-center">
      <div className="text-xs font-semibold uppercase tracking-[0.24em] text-cyan-300">Core/Trust/Ops</div>
      <p className="mt-3 text-sm text-slate-300">Opening governed Ops workspace...</p>
    </div>
  </main>
);

const RouteFallback = () => {
  if (typeof window !== "undefined" && window.location.pathname.startsWith("/ops/")) {
    return <OpsRouteFallback />;
  }

  const nativeShell = isNativeRuntimeShell();

  return (
  <main className={cn("w-full bg-slate-100 text-slate-950", nativeShell ? "min-h-[var(--liveuin-app-height,100dvh)]" : "min-h-screen px-4 py-6 md:px-8 md:py-8")}>
    <section
      className={cn(
        "mx-auto flex w-full flex-col overflow-hidden bg-[#F8F7FF]",
        nativeShell
          ? "min-h-[var(--liveuin-app-height,100dvh)]"
          : "min-h-[min(844px,calc(100vh-48px))] max-w-[390px] rounded-[44px] border border-slate-200 shadow-2xl",
      )}
    >
      <div
        className="rounded-b-[36px] bg-[#0B1222] px-7 pb-10 text-white"
        style={{ paddingTop: "max(4rem, env(safe-area-inset-top))" }}
      >
        <div className="text-[10px] font-semibold uppercase tracking-[0.32em] text-white/60">LiveUIN</div>
        <div className="mt-8 font-sora text-3xl font-semibold leading-tight tracking-tight" role="status" aria-live="polite">
          Opening LiveUIN
        </div>
        <p className="mt-3 max-w-[320px] text-sm leading-6 text-white/72">
          Your page is loading. This should only take a moment.
        </p>
      </div>
      <section className="flex-1 px-6 pb-8 pt-6">
        <div className="space-y-3">
          <div className="h-24 animate-pulse rounded-[24px] bg-white shadow-sm" />
          <div className="h-24 animate-pulse rounded-[24px] bg-white shadow-sm" />
          <div className="h-24 animate-pulse rounded-[24px] bg-white shadow-sm" />
        </div>
      </section>
    </section>
  </main>
  );
};

type RouteLoadRecoveryState = { hasError: boolean };

class RouteLoadRecoveryBoundary extends Component<{ children: ReactNode }, RouteLoadRecoveryState> {
  state: RouteLoadRecoveryState = { hasError: false };

  static getDerivedStateFromError(): RouteLoadRecoveryState {
    return { hasError: true };
  }

  componentDidCatch(error: unknown, info: ErrorInfo) {
    // Keep technical detail in the console without exposing bundle paths or
    // internals in a public-facing recovery surface.
    console.error("LiveUIN route failed to load", error, info.componentStack);
  }

  render() {
    if (!this.state.hasError) return this.props.children;

    return (
      <main className="flex min-h-screen items-center justify-center bg-[hsl(var(--surface-2))] px-6 py-12">
        <section className="w-full max-w-lg rounded-2xl border border-border bg-card p-7 text-center shadow-[var(--shadow-editorial)]">
          <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">LiveUIN</p>
          <h1 className="mt-3 text-2xl font-semibold text-foreground">This workspace was updated</h1>
          <p className="mt-3 text-sm leading-6 text-muted-foreground">
            The page was opened while a new release was being published. Reload once to continue with the current workspace.
          </p>
          <button
            type="button"
            className="mt-6 inline-flex h-10 items-center justify-center rounded-md bg-primary px-5 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90"
            onClick={() => window.location.reload()}
          >
            Reload workspace
          </button>
        </section>
      </main>
    );
  }
}

function LovablePublicAuthRoute() {
  return (
    <ResidentAppProvider surface="resident">
      <ProfileProvider>
        <AuthProvider>
          <LanguageProvider>
            <LovableAuthSignIn />
          </LanguageProvider>
        </AuthProvider>
      </ProfileProvider>
    </ResidentAppProvider>
  );
}

const runtimeRoutePath = () => {
  if (typeof window === "undefined") return "/";
  return `${window.location.pathname}${window.location.search}${window.location.hash}`;
};

const SurfaceRedirect = ({ to }: { to: string }) => {
  const externalTarget = /^https?:\/\//i.test(to);

  useEffect(() => {
    if (externalTarget && typeof window !== "undefined" && window.location.href !== to) {
      window.location.replace(to);
    }
  }, [externalTarget, to]);

  if (externalTarget) return <RouteFallback />;
  return <Navigate to={to} replace />;
};

const SurfaceHostGate = ({
  allow,
  hrefBuilder,
  children,
}: {
  allow: boolean;
  hrefBuilder: (path: string) => string;
  children: ReactNode;
}) => {
  const stagingHostSurfacePreview = isStagingHostSurfacePreview();
  if (allow || isPreviewHost() || stagingHostSurfacePreview) return <>{children}</>;
  return <SurfaceRedirect to={hrefBuilder(runtimeRoutePath())} />;
};

const PublicProductRoute = ({
  product,
  privateTarget,
  privateHost,
}: {
  product: "stay" | "earn" | "operate";
  privateTarget: string;
  privateHost: boolean;
}) => {
  if (privateHost) return <Navigate to={privateTarget} replace />;
  return <PublicProductPage product={product} />;
};

const OpsPrivate = ({ children }: { children: ReactNode }) => (
  <SurfaceHostGate allow={isOpsHost()} hrefBuilder={buildOpsHref}>
    <OpsAuthGate>{children}</OpsAuthGate>
  </SurfaceHostGate>
);

const AiPrivate = ({ children }: { children: ReactNode }) => (
  <SurfaceHostGate allow={isAiHost() || isOpsHost()} hrefBuilder={buildAiHref}>
    <OpsAuthGate>{children}</OpsAuthGate>
  </SurfaceHostGate>
);

const RootRoute = () => {
  if (isNativeRuntimeShell() && !getResidentSignedSession()) return <Navigate to="/welcome" replace />;
  if (isAppHost()) return <Navigate to="/tenant/home" replace />;
  if (isCnHost()) return <Navigate to="/cn" replace />;
  if (isAnyPassHost()) return <Navigate to="/pass" replace />;
  if (isHostHost()) return <Navigate to="/host/onboarding" replace />;
  if (isOpsHost()) return <Navigate to="/ops/control-tower" replace />;
  if (isConnectHost()) return <Navigate to="/connect/sites" replace />;
  if (isPartnerHost()) return <Navigate to="/partner/dashboard" replace />;
  if (isVendorHost()) return <Navigate to="/vendor/dashboard" replace />;
  return <Index />;
};

const configuredBasePath = runtimeBasePath();
// Page-only mounts can serve the bundle from an asset prefix while exposing
// the actual route at a clean host path (for example /host/properties/new).
// Only apply BrowserRouter's basename when the browser URL really includes it.
const appBaseName = configuredBasePath &&
  typeof window !== "undefined" &&
  (window.location.pathname === configuredBasePath || window.location.pathname.startsWith(`${configuredBasePath}/`))
  ? configuredBasePath
  : undefined;
const standaloneStudioBuild = runtimeBasePath() === "/studio";
const standaloneOpsLoginBuild = runtimeBasePath() === "/ops/login";

const App = () => (
  <QueryClientProvider client={appQueryClient}>
    <TooltipProvider>
      <PublicThemeBootstrap />
      <Toaster />
      <Sonner />
      <RouteLoadRecoveryBoundary>
        <BrowserRouter basename={appBaseName} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        {isStandaloneOpsLoginPath() ? (
          <Suspense fallback={<StandaloneOpsLoginFallback />}>
            <Routes>
              <Route
                path={standaloneOpsLoginBuild ? "/" : "/ops/login"}
                element={<OpsLogin standalone />}
              />
            </Routes>
          </Suspense>
        ) : (
          <>
            <ResidentNativeEntryBridge />
            <Suspense fallback={<RouteFallback />}>
              <ResidentNativeRouteGate fallback={<RouteFallback />}>
                <ResidentNativeAppRouteLock>
                <Routes>
              <Route
                path="/"
                element={standaloneStudioBuild ? <OpsPrivate><Studio /></OpsPrivate> : <RootRoute />}
              />
              <Route path="/stay" element={<PublicProductRoute product="stay" privateTarget="/tenant/home" privateHost={isAppHost()} />} />
              <Route path="/grow" element={<PublicProductPage product="grow" />} />
              <Route path="/earn" element={<PublicProductRoute product="earn" privateTarget="/localpro/home" privateHost={isAppHost()} />} />
              <Route path="/operate" element={<PublicProductRoute product="operate" privateTarget="/ops/control-tower" privateHost={isOpsHost()} />} />
              <Route path="/campus" element={<PublicProductPage product="campus" />} />
              <Route path="/enterprise" element={<PublicProductPage product="enterprise" />} />
              <Route path="/partner/solo" element={<PublicProductPage product="partner" variant="solo" />} />
              <Route path="/connect/wordpress" element={<PublicProductPage product="connect" />} />
              <Route path="/for-tenants" element={<Navigate to="/stay" replace />} />
              <Route path="/tenants" element={<Navigate to="/stay" replace />} />
              <Route path="/for-tenants/*" element={<Navigate to="/stay" replace />} />
              <Route path="/tenants/*" element={<Navigate to="/stay" replace />} />
              <Route path="/for-owners" element={<Navigate to="/grow" replace />} />
              <Route path="/owners" element={<Navigate to="/grow" replace />} />
              <Route path="/for-partners" element={<Navigate to="/partner" replace />} />
              <Route path="/partners" element={<Navigate to="/partner" replace />} />
              <Route path="/explore" element={<Explore />} />
              <Route path="/cities" element={<Cities />} />
              <Route path="/community" element={<Community />} />
              <Route path="/community/events/:eventId" element={<CommunityEvent />} />
              <Route path="/promotions" element={<Promotions />} />
              <Route path="/how-it-works" element={<HowItWorks />} />
              <Route path="/trust" element={<Trust />} />
              <Route path="/trust/verified-properties" element={<PublicAliasRedirect to="/trust" />} />
              <Route path="/trust/insurance" element={<PublicAliasRedirect to="/trust" />} />
              <Route path="/trust/shared-housing-policy-draft" element={<SharedHousingPolicyDraft />} />
              <Route path="/help" element={<Help />} />
              <Route path="/help/contact" element={<PublicHelpDetail />} />
              <Route path="/help/tickets/new" element={<PublicHelpDetail />} />
              <Route path="/help/stay" element={<PublicHelpDetail />} />
              <Route path="/help/grow" element={<PublicHelpDetail />} />
              <Route path="/help/earn" element={<PublicHelpDetail />} />
              <Route path="/help/tenants" element={<Navigate to="/help/stay" replace />} />
              <Route path="/help/owners" element={<Navigate to="/help/grow" replace />} />
              <Route path="/help/vendors" element={<Navigate to="/help/earn" replace />} />
              <Route path="/help/billing" element={<PublicHelpDetail />} />
              <Route path="/help/emergency" element={<PublicHelpDetail />} />
              <Route path="/legal" element={<Legal />} />
              <Route path="/legal/:slug" element={<LegalPolicy />} />
              <Route path="/solutions" element={<Solutions />} />
              {legacyPublicSolutionRedirects.map(([from, to]) => (
                <Route key={from} path={`${from}/*`} element={<Navigate to={to} replace />} />
              ))}
              <Route path="/pricing" element={<Pricing />} />
              <Route path="/blog" element={<Blog />} />
              <Route path="/blog/:slug" element={<BlogArticle />} />
              <Route path="/marketplace" element={<Marketplace />} />
              <Route path="/marketplace/:slug" element={<MarketplaceOffer />} />
              <Route path="/contact" element={<Contact />} />
              <Route
                path="/get-started"
                element={
                  isNativeRuntimeShell()
                    ? <Navigate to="/auth/sign-in?role=member&returnTo=%2Ftenant%2Fhome" replace />
                    : <LegacyGetStartedRedirect />
                }
              />
              <Route
                path="/start"
                element={
                  isNativeRuntimeShell()
                    ? <Navigate to="/auth/sign-in?role=member&returnTo=%2Ftenant%2Fhome" replace />
                    : <GetStarted />
                }
              />
              <Route path="/about" element={<About />} />
              <Route
                path="/cn"
                element={(
                  <ChinesePublicMirror>
                    <ChineseHome />
                  </ChinesePublicMirror>
                )}
              />
              <Route path="/cn/stay" element={<ChinesePublicProduct product="stay" />} />
              <Route path="/cn/grow" element={<ChinesePublicProduct product="grow" />} />
              <Route path="/cn/earn" element={<ChinesePublicProduct product="earn" />} />
              <Route path="/cn/host" element={<ChinesePublicProduct product="host" />} />
              <Route path="/cn/operate" element={<ChinesePublicProduct product="operate" />} />
              <Route path="/cn/partner" element={<ChinesePublicProduct product="partner" />} />
              <Route path="/cn/connect" element={<ChinesePublicProduct product="connect" />} />
              <Route path="/cn/connect/wordpress" element={<ChinesePublicProduct product="connect" />} />
              <Route path="/cn/campus" element={<ChinesePublicProduct product="campus" />} />
              <Route path="/cn/enterprise" element={<ChinesePublicProduct product="enterprise" />} />
              <Route path="/cn/partner/solo" element={<ChinesePublicProduct product="partner" variant="solo" />} />
              <Route path="/cn/api" element={<Api />} />
              <Route path="/cn/api/integrations" element={<ApiIntegrations />} />
              <Route path="/cn/blog" element={<Blog />} />
              <Route path="/cn/start" element={<GetStarted />} />
              <Route path="/cn/about" element={<About />} />
              <Route path="/cn/assessment" element={<Assessment />} />
              <Route path="/cn/contact" element={<Contact />} />
              <Route path="/cn/sitemap" element={<Sitemap />} />
              <Route path="/cn/support/move-in" element={<MoveInSupport />} />
              <Route path="/cn/relocation-partners" element={<RelocationPartners />} />
              <Route path="/cn/school-partnerships" element={<SchoolPartnerships />} />
              <Route path="/cn/agent-tools" element={<AgentTools />} />
              <Route path="/cn/deals" element={<Deals />} />
              <Route path="/cn/promotions" element={<Promotions />} />
              <Route path="/cn/explore" element={<Explore />} />
              <Route path="/cn/cities" element={<Cities />} />
              <Route path="/cn/community" element={<Community />} />
              <Route path="/cn/marketplace" element={<Marketplace />} />
              <Route path="/cn/trust/verified-properties" element={<PublicAliasRedirect to="/cn/trust" />} />
              <Route path="/cn/trust/insurance" element={<PublicAliasRedirect to="/cn/trust" />} />
              <Route
                path="/cn/community/events/:eventId"
                element={(
                  <ChinesePublicMirror>
                    <CommunityEvent />
                  </ChinesePublicMirror>
                )}
              />
              <Route
                path="/cn/blog/:slug"
                element={(
                  <ChinesePublicMirror>
                    <BlogArticle />
                  </ChinesePublicMirror>
                )}
              />
              <Route
                path="/cn/marketplace/:slug"
                element={<MarketplaceOffer />}
              />
              <Route path="/cn/search" element={<ChinesePublicSearch />} />
              <Route path="/cn/stays/:slug" element={<StayDetail />} />
              <Route path="/cn/for-tenants" element={<Navigate to="/cn/stay" replace />} />
              <Route path="/cn/for-tenants/*" element={<Navigate to="/cn/stay" replace />} />
              <Route path="/cn/for-owners" element={<Navigate to="/cn/host" replace />} />
              <Route path="/cn/for-owners/*" element={<Navigate to="/cn/host" replace />} />
              <Route path="/cn/for-partners" element={<Navigate to="/cn/partner" replace />} />
              <Route path="/cn/for-partners/*" element={<Navigate to="/cn/partner" replace />} />
              {chinesePublicMirrorRoutes.map(([path, Component]) => (
                <Route
                  key={path}
                  path={`/cn${path}`}
                  element={(
                    <ChinesePublicMirror>
                      <Component />
                    </ChinesePublicMirror>
                  )}
                />
              ))}
              <Route path="/cn/help/tenants" element={<Navigate to="/cn/help/stay" replace />} />
              <Route path="/cn/help/owners" element={<Navigate to="/cn/help/grow" replace />} />
              <Route path="/cn/help/vendors" element={<Navigate to="/cn/help/earn" replace />} />
              <Route
                path="/cn/explore/:citySlug"
                element={<CityPage />}
              />
              <Route
                path="/cn/cities/:citySlug"
                element={<CityPage />}
              />
              <Route path="/cn/list-property" element={<Navigate to="/cn/host" replace />} />
              <Route path="/cn/list-property/*" element={<Navigate to="/cn/host" replace />} />
              <Route path="/cn/list-your-property" element={<Navigate to="/cn/host" replace />} />
              <Route path="/cn/list-your-property/*" element={<Navigate to="/cn/host" replace />} />
              <Route path="/cn/*" element={<CnPublicRoute />} />
              <Route path="/careers" element={<Careers />} />
              <Route path="/newsroom" element={<Newsroom />} />
              <Route path="/press" element={<Press />} />
              <Route
                path="/login"
                element={<RoleAwareLogin />}
              />
              {/*
               * Keep the private Ops handoff address available even when a
               * host-specific standalone detector cannot run (for example,
               * after a staging proxy or base-path rewrite). The Ops login
               * still performs the Core Identity membership and OTP checks;
               * this route only guarantees that the supported sign-in screen
               * is reachable.
               */}
              <Route path="/ops/login" element={<OpsLogin standalone />} />
              <Route path="/ops/preview-sign-in" element={<OpsPreviewSignIn />} />
              <Route path="/welcome" element={<LovableWelcome />} />
              <Route path="/auth/sign-in" element={<LovablePublicAuthRoute />} />
              <Route path="/assessment" element={<Assessment />} />
              <Route
                path="/journey"
                element={(
                  <SurfaceHostGate allow={isAppHost() || isNativeRuntimeShell()} hrefBuilder={buildAppHref}>
                    <ResidentLayoutRoute />
                  </SurfaceHostGate>
                )}
              >
                <Route index element={<AppJourney />} />
              </Route>
              <Route
                path="/messages"
                element={(
                  <SurfaceHostGate allow={isAppHost() || isNativeRuntimeShell()} hrefBuilder={buildAppHref}>
                    <ResidentLayoutRoute />
                  </SurfaceHostGate>
                )}
              >
                <Route index element={<AppMessages />} />
                <Route path=":threadId" element={<AppMessageThread />} />
              </Route>
              <Route path="/offline" element={<LovableWelcome />} />
              <Route path="/account" element={<ResidentRouteAlias to="/tenant/account" />} />
              <Route path="/account/profile" element={<ResidentRouteAlias to="/tenant/account/profile" />} />
              <Route path="/account/privacy" element={<ResidentRouteAlias to="/tenant/account/privacy" />} />
              <Route path="/account/security" element={<ResidentRouteAlias to="/tenant/account/security" />} />
              <Route path="/account/settings" element={<ResidentRouteAlias to="/tenant/account/settings" />} />
              <Route path="/account/language" element={<ResidentRouteAlias to="/tenant/account/settings" />} />
              <Route path="/account/notifications" element={<ResidentRouteAlias to="/tenant/notifications" />} />
              <Route path="/app/member" element={<ResidentRouteAlias to="/tenant/home" />} />
              <Route path="/app/explore" element={<ResidentRouteAlias to="/tenant/explore" />} />
              <Route path="/app/wallet" element={<ResidentRouteAlias to="/tenant/payments" />} />
              <Route path="/app/wallet/receipts" element={<ResidentRouteAlias to="/tenant/payments/receipts" />} />
              <Route path="/app/support" element={<ResidentRouteAlias to="/tenant/support" />} />
              <Route path="/app/utilities" element={<ResidentRouteAlias to="/tenant/utilities" />} />
              <Route path="/app/documents" element={<ResidentRouteAlias to="/tenant/documents" />} />
              <Route path="/app/verification" element={<ResidentRouteAlias to="/tenant/verification" />} />
              <Route path="/app/renewal" element={<ResidentRouteAlias to="/tenant/renewal" />} />
              <Route path="/app/move-in" element={<ResidentRouteAlias to="/tenant/move-in" />} />
              <Route path="/app/move-in/:caseId" element={<ResidentRouteAlias to={({ caseId }) => `/tenant/move-in/${caseId || ""}`} />} />
              <Route path="/app/bookings" element={<ResidentRouteAlias to="/tenant/bookings" />} />
              <Route path="/app/bookings/:caseId" element={<ResidentRouteAlias to={({ caseId }) => `/tenant/bookings/${caseId || ""}`} />} />
              <Route path="/app/notifications" element={<ResidentRouteAlias to="/tenant/notifications" />} />
              <Route path="/app/rewards" element={<ResidentRouteAlias to="/tenant/rewards" />} />
              <Route path="/app/saved" element={<ResidentRouteAlias to="/tenant/saved" />} />
              <Route path="/app/insurance" element={<ResidentRouteAlias to="/tenant/insurance" />} />
              <Route path="/app/claims/:caseId" element={<ResidentRouteAlias to={({ caseId }) => `/tenant/claims/${caseId || ""}`} />} />
              <Route path="/app/messages" element={<ResidentRouteAlias to="/tenant/messages" />} />
              <Route path="/app/messages/:threadId" element={<ResidentRouteAlias to={({ threadId }) => `/tenant/messages/${threadId || ""}`} />} />
              <Route path="/app/account" element={<ResidentRouteAlias to="/tenant/account" />} />
              <Route path="/app/earn" element={<ResidentRouteAlias to="/localpro/home" />} />
              <Route path="/app/earn/verification" element={<ResidentRouteAlias to="/localpro/verification" />} />
              <Route path="/app/earn/jobs" element={<ResidentRouteAlias to="/localpro/jobs" />} />
              <Route path="/app/earn/jobs/:jobId" element={<ResidentRouteAlias to={({ jobId }) => `/localpro/jobs/${jobId || ""}`} />} />
              <Route path="/app/earn/jobs/:jobId/active" element={<ResidentRouteAlias to={({ jobId }) => `/localpro/jobs/${jobId || ""}/active`} />} />
              <Route path="/app/earn/jobs/:jobId/proof" element={<ResidentRouteAlias to={({ jobId }) => `/localpro/jobs/${jobId || ""}/proof`} />} />
              <Route path="/app/earn/history" element={<ResidentRouteAlias to="/localpro/history" />} />
              <Route path="/app/earn/history/:jobId" element={<ResidentRouteAlias to={({ jobId }) => `/localpro/history/${jobId || ""}`} />} />
              <Route path="/app/earn/earnings" element={<ResidentRouteAlias to="/localpro/earnings" />} />
              <Route path="/app/earn/earnings/:payoutId" element={<ResidentRouteAlias to={({ payoutId }) => `/localpro/earnings/${payoutId || ""}`} />} />
              <Route path="/app/earn/messages" element={<ResidentRouteAlias to="/localpro/messages" />} />
              <Route path="/app/earn/messages/:threadId" element={<ResidentRouteAlias to={({ threadId }) => `/localpro/messages/${threadId || ""}`} />} />
              <Route path="/app/earn/account" element={<ResidentRouteAlias to="/localpro/account" />} />
              <Route path="/app/marketplace" element={<ResidentRouteAlias to="/tenant/marketplace" />} />
              <Route path="/app/marketplace/:slug" element={<ResidentRouteAlias to={({ slug }) => `/tenant/marketplace/${slug || ""}`} />} />
              <Route path="/wallet" element={<ResidentRouteAlias to="/tenant/payments" />} />
              <Route path="/wallet/receipts" element={<ResidentRouteAlias to="/tenant/payments/receipts" />} />
              <Route path="/member" element={<ResidentRouteAlias to="/tenant/home" />} />
              <Route path="/notifications" element={<ResidentRouteAlias to="/tenant/notifications" />} />
              <Route path="/support" element={<ResidentRouteAlias to="/tenant/support" />} />
              <Route path="/utilities" element={<ResidentRouteAlias to="/tenant/utilities" />} />
              <Route path="/renewal" element={<ResidentRouteAlias to="/tenant/renewal" />} />
              <Route path="/insurance" element={<ResidentRouteAlias to="/tenant/insurance" />} />
              <Route path="/move-in" element={<ResidentRouteAlias to="/tenant/move-in" />} />
              <Route path="/move-in/:caseId" element={<ResidentRouteAlias to={({ caseId }) => `/tenant/move-in/${caseId || ""}`} />} />
              <Route path="/support/move-in" element={<MoveInSupport />} />
              <Route path="/guides" element={<Guides />} />
              <Route path="/services" element={<Services />} />
              <Route path="/deals" element={<Deals />} />
              <Route path="/api" element={<Api />} />
              <Route path="/developers" element={<Developers />} />
              <Route path="/developers/docs" element={<DeveloperPortalDetail />} />
              <Route path="/developers/docs/api" element={<DeveloperPortalDetail />} />
              <Route path="/developers/docs/webhooks" element={<DeveloperPortalDetail />} />
              <Route path="/developers/docs/sdks" element={<DeveloperPortalDetail />} />
              <Route path="/developers/keys" element={<DeveloperPortalDetail />} />
              <Route path="/developers/sandbox" element={<DeveloperPortalDetail />} />
              <Route path="/developers/marketplace" element={<DeveloperPortalDetail />} />
              <Route path="/developers/limits" element={<DeveloperPortalDetail />} />
              <Route path="/developers/changelog" element={<DeveloperPortalDetail />} />
              <Route path="/status" element={<Status />} />
              <Route path="/investors" element={<Investors />} />
              <Route path="/sitemap" element={<Sitemap />} />
              <Route path="/partner-program" element={<PartnerProgram />} />
              <Route path="/agent-tools" element={<AgentTools />} />
              <Route path="/school-partnerships" element={<SchoolPartnerships />} />
              <Route path="/list-property" element={<Navigate to="/host" replace />} />
              <Route path="/owner-benefits" element={<OwnerBenefits />} />
              <Route path="/relocation-partners" element={<RelocationPartners />} />
              <Route path="/api/integrations" element={<ApiIntegrations />} />
              <Route path="/data-room" element={<DataRoom />} />
              <Route path="/list-your-property" element={<Navigate to="/host" replace />} />
              <Route path="/pass" element={<Pass />} />
              <Route
                path="/connect"
                element={(
                  isConnectHost()
                    ? <SurfaceHostGate allow hrefBuilder={buildConnectHref}><Navigate to="/connect/sites" replace /></SurfaceHostGate>
                    : <PublicProductPage product="connect" />
                )}
              />
              <Route
                path="/connect/sites"
                element={(
                  <SurfaceHostGate allow={isConnectHost()} hrefBuilder={buildConnectHref}>
                    <WorkspaceIdentityGate expectedRole="connect"><ConnectSitesPreview /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/connect/branding"
                element={(
                  <SurfaceHostGate allow={isConnectHost()} hrefBuilder={buildConnectHref}>
                    <WorkspaceIdentityGate expectedRole="connect"><ConnectBrandingPreview /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/connect/domains"
                element={(
                  <SurfaceHostGate allow={isConnectHost()} hrefBuilder={buildConnectHref}>
                    <WorkspaceIdentityGate expectedRole="connect"><ConnectDomainsPreview /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/connect/onboarding"
                element={(
                  <SurfaceHostGate allow={isConnectHost()} hrefBuilder={buildConnectHref}>
                    <WorkspaceIdentityGate expectedRole="connect"><ConnectOnboardingPreview /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/connect/request"
                element={<ConnectPublicRoute />}
              />
              <Route
                path="/connect/checkout/return"
                element={<ConnectPublicRoute />}
              />
              <Route
                path="/connect/setup/complete"
                element={<ConnectPublicRoute />}
              />
              <Route
                path="/connect/install"
                element={(
                  <SurfaceHostGate allow={isConnectHost()} hrefBuilder={buildConnectHref}>
                    <WorkspaceIdentityGate expectedRole="connect"><ConnectOnboardingPreview /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/connect/workspace/config"
                element={(
                  <SurfaceHostGate allow={isConnectHost()} hrefBuilder={buildConnectHref}>
                    <WorkspaceIdentityGate expectedRole="connect"><ConnectOnboardingPreview /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route path="/explore/:citySlug" element={<CityPage />} />
              <Route path="/cities/:citySlug" element={<CityPage />} />
              <Route path="/search" element={<SearchResults />} />
              <Route path="/stays/:slug" element={<StayDetail />} />
              <Route path="/checkout/:slug" element={<Checkout />} />
              <Route
                path="/tenant"
                element={(
                  <SurfaceHostGate allow={isAppHost() || isNativeRuntimeShell()} hrefBuilder={buildAppHref}>
                    <ResidentLayoutRoute />
                  </SurfaceHostGate>
                )}
              >
                <Route index element={<Navigate to="/tenant/home" replace />} />
                <Route path="home" element={<TenantHome />} />
                <Route path="explore" element={<AppResidentExplore />} />
                <Route path="payments" element={<Wallet />} />
                <Route path="payments/autopay" element={<AppResidentLovableScreen />} />
                <Route path="payments/bill/:billId" element={<AppResidentLovableScreen />} />
                <Route path="payments/failed" element={<AppResidentLovableScreen />} />
                <Route path="payments/methods" element={<AppResidentLovableScreen />} />
                <Route path="payments/receipt/:receiptId" element={<AppResidentLovableScreen />} />
                <Route path="payments/receipts" element={<WalletReceipts />} />
                <Route path="payments/refund" element={<AppResidentLovableScreen />} />
                <Route path="payments/success" element={<AppResidentLovableScreen />} />
                <Route path="support" element={<AppResidentSupport />} />
                <Route path="support/new" element={<AppSupportNew />} />
                <Route path="support/history" element={<AppResidentLovableScreen />} />
                <Route path="support/dispute" element={<AppResidentLovableScreen />} />
                <Route path="support/:ticketId" element={<AppResidentLovableScreen />} />
                <Route path="account" element={<AppAccount />} />
                <Route path="account/profile" element={<AppAccountProfile />} />
                <Route path="account/privacy" element={<AppAccountPrivacy />} />
                <Route path="account/security" element={<AppAccountSecurity />} />
                <Route path="account/settings" element={<AppAccountSettings />} />
                <Route path="address-reveal" element={<AppResidentLovableScreen />} />
                <Route path="agreement" element={<AppResidentLovableScreen />} />
                <Route path="agreement/pending" element={<AppResidentLovableScreen />} />
                <Route path="alerts" element={<AppResidentLovableScreen />} />
                <Route path="applications/new" element={<AppResidentLovableScreen />} />
                <Route path="applications/:appId" element={<AppResidentLovableScreen />} />
                <Route path="bookings/:caseId" element={<AppBookingStatus />} />
                <Route path="compare" element={<AppResidentLovableScreen />} />
                <Route path="documents" element={<AppResidentCaseModule />} />
                <Route path="documents/:docId" element={<AppResidentCaseModule />} />
                <Route path="family" element={<AppResidentLovableScreen />} />
                <Route path="family/revoke" element={<AppResidentLovableScreen />} />
                <Route path="first72" element={<AppResidentLovableScreen />} />
                <Route path="handover" element={<AppResidentLovableScreen />} />
                <Route path="listings/:listingId" element={<AppResidentLovableScreen />} />
                <Route path="locker" element={<AppResidentLovableScreen />} />
                <Route path="movein" element={<AppResidentLovableScreen />} />
                <Route path="pass/share" element={<AppResidentLovableScreen />} />
                <Route path="search" element={<AppResidentLovableScreen />} />
                <Route path="search/filters" element={<AppResidentLovableScreen />} />
                <Route path="utilities" element={<AppResidentCaseModule />} />
                <Route path="utilities/dispute" element={<AppResidentCaseModule />} />
                <Route path="utilities/:chargeId" element={<AppResidentCaseModule />} />
                <Route path="viewings" element={<AppResidentLovableScreen />} />
                <Route path="viewings/request" element={<AppResidentLovableScreen />} />
                <Route path="verification" element={<AppResidentCaseModule />} />
                <Route path="verification/:caseId" element={<AppResidentCaseModule />} />
                <Route path="renewal" element={<AppResidentCaseModule />} />
                <Route path="renewal/:caseId" element={<AppResidentCaseModule />} />
                <Route path="messages" element={<AppMessages />} />
                <Route path="messages/:threadId" element={<AppMessageThread />} />
                <Route path="notifications" element={<AppNotifications />} />
                <Route path="notifications/:notifId" element={<AppResidentLovableScreen />} />
                <Route path="rewards" element={<AppRewards />} />
                <Route path="saved" element={<AppSavedHomes />} />
                <Route path="insurance" element={<AppInsurance />} />
                <Route path="claims/:caseId" element={<AppClaimsPreview />} />
                <Route path="bookings" element={<AppBookingStatus />} />
                <Route path="bookings/:caseId" element={<AppBookingStatus />} />
                <Route path="move-in" element={<AppMoveInStatus />} />
                <Route path="move-in/:caseId" element={<AppMoveInStatus />} />
                <Route path="marketplace" element={<AppMarketplace />} />
                <Route path="marketplace/:slug" element={<AppMarketplaceOffer />} />
                <Route path="marketplace/book/:serviceId" element={<AppResidentLovableScreen />} />
                <Route path="marketplace/bundle/:bundleId" element={<AppResidentLovableScreen />} />
                <Route path="marketplace/dispute" element={<AppResidentLovableScreen />} />
                <Route path="marketplace/order/:orderId" element={<AppResidentLovableScreen />} />
                <Route path="marketplace/provider/:providerId" element={<AppResidentLovableScreen />} />
                <Route path="marketplace/rewards" element={<AppRewards />} />
                <Route path="marketplace/service/:serviceId" element={<AppResidentLovableScreen />} />
                <Route path="marketplace/terms" element={<AppResidentLovableScreen />} />
              </Route>
              <Route
                path="/localpro"
                element={(
                  <SurfaceHostGate allow={isAppHost() || isNativeRuntimeShell()} hrefBuilder={buildAppHref}>
                    <ResidentLayoutRoute />
                  </SurfaceHostGate>
                )}
              >
                <Route index element={<Navigate to="/localpro/home" replace />} />
                <Route
                  path="availability"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Your work profile is not ready for this account yet."
                      lockedDetail="This page opens here after LocalPro access is turned on."
                    >
                      <AppLocalProLovableScreen />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="eligibility"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Your work profile is not ready for this account yet."
                      lockedDetail="This page opens here after LocalPro access is turned on."
                    >
                      <AppLocalProLovableScreen />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="compliance"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Your work profile is not ready for this account yet."
                      lockedDetail="This page opens here after LocalPro access is turned on."
                    >
                      <AppLocalProLovableScreen />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="home"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Earn with LiveUIN is locked for this account."
                      lockedDetail="Earn opens here after LocalPro access is turned on for this account."
                    >
                      <AppEarn />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="jobs"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Earn with LiveUIN is locked for this account."
                      lockedDetail="Earn opens here after LocalPro access is turned on for this account."
                    >
                      <AppEarn />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="jobs/:jobId"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="This task is not available for this account."
                      lockedDetail="Open a LocalPro profile that has access to this task."
                    >
                      <AppEarn />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="jobs/:jobId/accepted"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="This task is not available for this account."
                      lockedDetail="Open a LocalPro profile that has access to this task."
                    >
                      <AppLocalProLovableScreen />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="jobs/:jobId/active"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="This task is not available for this account."
                      lockedDetail="Open a LocalPro profile that has access to this task."
                    >
                      <AppEarn />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="jobs/:jobId/address"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="This task is not available for this account."
                      lockedDetail="Open a LocalPro profile that has access to this task."
                    >
                      <AppLocalProLovableScreen />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="jobs/:jobId/incident"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="This task is not available for this account."
                      lockedDetail="Open a LocalPro profile that has access to this task."
                    >
                      <AppLocalProLovableScreen />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="jobs/:jobId/proof"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="This task is not available for this account."
                      lockedDetail="Open a LocalPro profile that has access to this task."
                    >
                      <AppEarn />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="jobs/:jobId/proof/approved"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="This task is not available for this account."
                      lockedDetail="Open a LocalPro profile that has access to this task."
                    >
                      <AppLocalProLovableScreen />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="jobs/:jobId/proof/pending"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="This task is not available for this account."
                      lockedDetail="Open a LocalPro profile that has access to this task."
                    >
                      <AppLocalProLovableScreen />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="jobs/:jobId/proof/rejected"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="This task is not available for this account."
                      lockedDetail="Open a LocalPro profile that has access to this task."
                    >
                      <AppLocalProLovableScreen />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="history"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Earn history is locked for this account."
                      lockedDetail="History opens here after LocalPro access is turned on."
                    >
                      <AppEarn />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="history/:jobId"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="This task history is not available for this account."
                      lockedDetail="Open a LocalPro profile that has access to this task."
                    >
                      <AppEarn />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="earnings"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Payout updates are locked for this account."
                      lockedDetail="Payout updates appear here after LocalPro access is turned on."
                    >
                      <AppEarn />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="earnings/:payoutId"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Payout updates are locked for this account."
                      lockedDetail="Payout updates appear here after LocalPro access is turned on."
                    >
                      <AppEarn />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="earnings/settlement/:settlementId"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Payout updates are locked for this account."
                      lockedDetail="Payout updates appear here after LocalPro access is turned on."
                    >
                      <AppLocalProLovableScreen />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="payouts/method"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Payout updates are locked for this account."
                      lockedDetail="Payout updates appear here after LocalPro access is turned on."
                    >
                      <AppLocalProLovableScreen />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="payouts/history"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Payout updates are locked for this account."
                      lockedDetail="Payout updates appear here after LocalPro access is turned on."
                    >
                      <AppLocalProLovableScreen />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="account"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Your work profile is not ready for this account yet."
                      lockedDetail="This page opens here after LocalPro access is turned on."
                    >
                      <AppAccount />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="messages"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Messages are not ready for this account yet."
                      lockedDetail="This page opens here after LocalPro access is turned on."
                    >
                      <AppMessages />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="messages/:threadId"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Messages are not ready for this account yet."
                      lockedDetail="This page opens here after LocalPro access is turned on."
                    >
                      <AppMessageThread />
                    </AuthorizedProfileRoute>
                  }
                />
                <Route
                  path="verification"
                  element={
                    <AuthorizedProfileRoute
                      requiredProfileKey="localpro"
                      lockedHeading="Verification is not ready for this account yet."
                      lockedDetail="This page opens here after LocalPro access is turned on."
                    >
                      <AppEarnVerification />
                    </AuthorizedProfileRoute>
                  }
                />
              </Route>
              <Route
                path="/host"
                element={(
                  isHostHost()
                    ? <SurfaceHostGate allow hrefBuilder={buildHostHref}><Navigate to="/host/onboarding" replace /></SurfaceHostGate>
                    : <PublicProductPage product="host" />
                )}
              />
              <Route
                path="/host/onboarding"
                element={(
                  <SurfaceHostGate allow={isHostHost()} hrefBuilder={buildHostHref}>
                    <WorkspaceIdentityGate expectedRole="host"><HostOnboarding /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/host/properties"
                element={(
                  <SurfaceHostGate allow={isHostHost()} hrefBuilder={buildHostHref}>
                    <WorkspaceIdentityGate expectedRole="host"><HostPropertiesPreview /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/host/properties/new"
                element={(
                  <SurfaceHostGate allow={isHostHost()} hrefBuilder={buildHostHref}>
                    <WorkspaceIdentityGate expectedRole="host"><ListProperty /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/host/listing-wizard"
                element={(
                  <SurfaceHostGate allow={isHostHost()} hrefBuilder={buildHostHref}>
                    <WorkspaceIdentityGate expectedRole="host"><ListProperty /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/host/bookings"
                element={(
                  <SurfaceHostGate allow={isHostHost()} hrefBuilder={buildHostHref}>
                    <WorkspaceIdentityGate expectedRole="host"><HostBookingsPreview /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/host/bookings/:caseId"
                element={(
                  <SurfaceHostGate allow={isHostHost()} hrefBuilder={buildHostHref}>
                    <WorkspaceIdentityGate expectedRole="host"><HostBookingDetail /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/host/finance"
                element={(
                  <SurfaceHostGate allow={isHostHost()} hrefBuilder={buildHostHref}>
                    <WorkspaceIdentityGate expectedRole="host"><HostFinance /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/finance/settlements"
                element={(
                  <OpsPrivate>
                    <FinanceSettlements />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/finance/exports"
                element={(
                  <OpsPrivate>
                    <FinanceExports />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/partner"
                element={(
                  isPartnerHost()
                    ? <SurfaceHostGate allow hrefBuilder={buildPartnerHref}><Navigate to="/partner/dashboard" replace /></SurfaceHostGate>
                    : <PublicProductPage product="partner" />
                )}
              />
              <Route
                path="/partner/dashboard"
                element={(
                  <SurfaceHostGate allow={isPartnerHost()} hrefBuilder={buildPartnerHref}>
                    <WorkspaceIdentityGate expectedRole="partner"><PartnerWorkspace /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/partner/leads"
                element={(
                  <SurfaceHostGate allow={isPartnerHost()} hrefBuilder={buildPartnerHref}>
                    <WorkspaceIdentityGate expectedRole="partner"><PartnerLeadsPreview /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/partner/share"
                element={(
                  <SurfaceHostGate allow={isPartnerHost()} hrefBuilder={buildPartnerHref}>
                    <WorkspaceIdentityGate expectedRole="partner"><PartnerSharePreview /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/partner/entitlements"
                element={(
                  <SurfaceHostGate allow={isPartnerHost()} hrefBuilder={buildPartnerHref}>
                    <WorkspaceIdentityGate expectedRole="partner"><PartnerEntitlementsPreview /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/partner/inventory/media"
                element={(
                  <SurfaceHostGate allow={isPartnerHost()} hrefBuilder={buildPartnerHref}>
                    <WorkspaceIdentityGate expectedRole="partner"><PartnerInventoryMedia /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/partner/offers/new"
                element={(
                  <SurfaceHostGate allow={isPartnerHost()} hrefBuilder={buildPartnerHref}>
                    <WorkspaceIdentityGate expectedRole="partner"><Navigate to="/partners/offers/new" replace /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/partners/offers/new"
                element={(
                  <SurfaceHostGate allow={isPartnerHost()} hrefBuilder={buildPartnerHref}>
                    <WorkspaceIdentityGate expectedRole="partner"><PartnerOfferNew /></WorkspaceIdentityGate>
                  </SurfaceHostGate>
                )}
              />
              <Route path="/rewards" element={<HandoverRewards />} />
              <Route path="/handover-rewards" element={<HandoverRewards />} />
              <Route
                path="/studio"
                element={(
                  <OpsPrivate>
                    <Studio />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/control-tower"
                element={(
                  <OpsPrivate>
                    <OpsControlTower />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/property-media"
                element={(
                  <OpsPrivate>
                    <OpsPropertyMedia />
                  </OpsPrivate>
                )}
              />
            {founderTestModeEnabled && <Route path="/ops/founder-test" element={<FounderOpsConsole />} />}
            {founderTestModeEnabled && <Route path="/ops/founder-journey" element={<FounderJourney />} />}
            <Route
              path="/app/self-view/:selfViewId"
              element={(
                <OpsPrivate>
                  <OperatorSelfView />
                </OpsPrivate>
              )}
            />
              <Route
                path="/ops/operator-control-tower"
                element={(
                  <OpsPrivate>
                    <Navigate to="/ops/control-tower" replace />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/daily-control-tower"
                element={(
                  <OpsPrivate>
                    <Navigate to="/ops/control-tower" replace />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/command"
                element={(
                  <OpsPrivate>
                    <OpsCommand />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/payments"
                element={(
                  <OpsPrivate>
                    <OpsPayments />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/marketplace"
                element={(
                  <OpsPrivate>
                    <OpsMarketplace />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/marketplace/review"
                element={(
                  <OpsPrivate>
                    <OpsMarketplace />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/marketplace/review-queue"
                element={(
                  <OpsPrivate>
                    <OpsMarketplace />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/demand"
                element={(
                  <OpsPrivate>
                    <OpsDemand />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/demand/queue"
                element={(
                  <OpsPrivate>
                    <OpsDemandQueue />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/demand/new"
                element={(
                  <OpsPrivate>
                    <OpsDemandNew />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/demand/:id"
                element={(
                  <OpsPrivate>
                    <OpsDemandDetail />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/ai"
                element={(
                  <AiPrivate>
                    <OpsAiGovernance />
                  </AiPrivate>
                )}
              />
              <Route
                path="/ops/ai-reviews"
                element={(
                  <AiPrivate>
                    <OpsAiGovernance />
                  </AiPrivate>
                )}
              />
              <Route
                path="/ops/ai/reviews"
                element={(
                  <AiPrivate>
                    <OpsAiGovernance />
                  </AiPrivate>
                )}
              />
              <Route
                path="/ops/ai-readiness"
                element={(
                  <AiPrivate>
                    <OpsAiGovernance />
                  </AiPrivate>
                )}
              />
              <Route
                path="/ops/source-owners"
                element={(
                  <AiPrivate>
                    <SourceOwnerManagement />
                  </AiPrivate>
                )}
              />
              <Route
                path="/reviews"
                element={(
                  <AiPrivate>
                    <OpsAiGovernance />
                  </AiPrivate>
                )}
              />
              <Route
                path="/ops/rollout-review"
                element={(
                  <OpsPrivate>
                    <OpsReview />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/change-control"
                element={(
                  <OpsPrivate>
                    <OpsChangeControl />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/source-intake"
                element={(
                  <OpsPrivate>
                    <OpsSourceIntake />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/liveuintest-review"
                element={(
                  <OpsPrivate>
                    <Navigate to="/ops/rollout-review" replace />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/liveuin-test-review"
                element={(
                  <OpsPrivate>
                    <Navigate to="/ops/rollout-review" replace />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/ops/theme"
                element={(
                  <OpsPrivate>
                    <OpsThemeStudio />
                  </OpsPrivate>
                )}
              />
              <Route
                path="/pass/:caseId"
                element={(
                  <SurfaceHostGate allow={isAnyPassHost()} hrefBuilder={buildPassHref}>
                    <PassLayoutRoute />
                  </SurfaceHostGate>
                )}
              >
                <Route index element={<PassCaseOverview />} />
                <Route path="payments" element={<PassPayments />} />
                <Route path="support" element={<PassSupport />} />
              </Route>
              <Route
                path="/pass/case"
                element={(
                  <SurfaceHostGate allow={isAnyPassHost()} hrefBuilder={buildPassHref}>
                    <PassLayoutRoute />
                  </SurfaceHostGate>
                )}
              >
                <Route index element={<PassCaseOverview />} />
                <Route path="payments" element={<PassPayments />} />
                <Route path="support" element={<PassSupport />} />
              </Route>
              <Route
                path="/vendor"
                element={(
                  <SurfaceHostGate allow={isVendorHost()} hrefBuilder={buildVendorHref}>
                    <Navigate to="/vendor/dashboard" replace />
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/vendor/dashboard"
                element={(
                  <SurfaceHostGate allow={isVendorHost()} hrefBuilder={buildVendorHref}>
                    <VendorWorkspace />
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/vendor/jobs"
                element={(
                  <SurfaceHostGate allow={isVendorHost()} hrefBuilder={buildVendorHref}>
                    <VendorJobsPreview />
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/vendor/jobs/:jobId"
                element={(
                  <SurfaceHostGate allow={isVendorHost()} hrefBuilder={buildVendorHref}>
                    <VendorFounderTask />
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/vendor/proof"
                element={(
                  <SurfaceHostGate allow={isVendorHost()} hrefBuilder={buildVendorHref}>
                    <VendorProofPreview />
                  </SurfaceHostGate>
                )}
              />
              <Route
                path="/vendor/earnings"
                element={(
                  <SurfaceHostGate allow={isVendorHost()} hrefBuilder={buildVendorHref}>
                    <VendorEarningsPreview />
                  </SurfaceHostGate>
                )}
              />
              <Route path="*" element={<NotFound />} />
                </Routes>
                </ResidentNativeAppRouteLock>
              </ResidentNativeRouteGate>
            </Suspense>
          </>
        )}
        </BrowserRouter>
      </RouteLoadRecoveryBoundary>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
