import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Suspense, type ComponentType, type ReactNode } from "react";
import { BrowserRouter, Navigate, Outlet, Route, Routes, useLocation } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ResidentAppProvider, useResidentApp } from "@/components/resident/ResidentAppContext";
import { ResidentNativeEntryBridge } from "@/components/resident/ResidentNativeEntryBridge";
import { ResidentNativeRouteGate } from "@/components/resident/ResidentNativeRouteGate";
import { ScreenCard } from "@/components/liveuin/ScreenCard";
import { SubHeader } from "@/components/liveuin/SubHeader";
import { PhoneShell } from "@/components/liveuin/PhoneShell";
import { MenuDrawerProvider } from "@/components/liveuin/MenuDrawer";
import { AuthProvider } from "@/lib/auth-context";
import { LanguageProvider } from "@/lib/language-context";
import { ProfileProvider } from "@/lib/profile-context";
import { RegionProvider } from "@/lib/region-context";
import { getResidentSignedSession } from "@/lib/residentSessionBridge";
import { nativeLovableRoutes } from "@/native-lovable/routeRegistry";
import { nativeR6Routes } from "@/native-r6/routeRegistry";
import { NativeR6Providers, NativeFeatureSessionBoundary } from "@/native-r6/NativeR6Providers";
import { NativeFeatureRoute } from "@/native-r6/NativeFeatureRoute";
import { NativeFeatureScopeBridge } from "@/native-r6/featureRouteScope";

const appQueryClient = new QueryClient();

const RouteFallback = () => (
  <main className="min-h-[var(--liveuin-app-height,100dvh)] w-full max-w-full overflow-hidden bg-[#F8F7FF] text-slate-950">
    <section className="flex min-h-[var(--liveuin-app-height,100dvh)] w-full max-w-full flex-col overflow-hidden bg-[#F8F7FF]">
      <div
        className="rounded-b-[36px] bg-[#0B1222] px-7 pb-10 text-white"
        style={{ paddingTop: "max(4rem, env(safe-area-inset-top))" }}
      >
        <div className="text-[10px] font-semibold uppercase tracking-[0.32em] text-white/60">LiveUIN</div>
        <h1 className="mt-8 font-sora text-3xl font-semibold leading-tight tracking-tight">Opening LiveUIN</h1>
        <p className="mt-3 max-w-[320px] text-sm leading-6 text-white/72">Your page is loading. This should only take a moment.</p>
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

const RootRoute = () => {
  if (!getResidentSignedSession()) return <Navigate to="/welcome" replace />;
  return <Navigate to="/tenant/home" replace />;
};

function PublicNativeProviders({ children }: { children: ReactNode }) {
  return <LanguageProvider>{children}</LanguageProvider>;
}

function PublicAuthProviders({ children }: { children: ReactNode }) {
  return (
    <ResidentAppProvider surface="resident">
      <ProfileProvider>
        <AuthProvider>
          <LanguageProvider>{children}</LanguageProvider>
        </AuthProvider>
      </ProfileProvider>
    </ResidentAppProvider>
  );
}

function ProtectedNativeProviders() {
  return (
    <ResidentAppProvider surface="resident">
      <ProfileProvider>
        <AuthProvider>
          <LanguageProvider>
            <RegionProvider>
              <MenuDrawerProvider>
                <SignedAppGate>
                  <Outlet />
                </SignedAppGate>
              </MenuDrawerProvider>
            </RegionProvider>
          </LanguageProvider>
        </AuthProvider>
      </ProfileProvider>
    </ResidentAppProvider>
  );
}

export function SignedAppGate({ children }: { children: ReactNode }) {
  const location = useLocation();
  const resident = useResidentApp();
  if (resident.isLoading) {
    return <RouteFallback />;
  }
  if (resident.authRequired || resident.sessionState === "auth_required") {
    const returnTo = `${location.pathname}${location.search}${location.hash}`;
    return <Navigate to={`/auth/sign-in?returnTo=${encodeURIComponent(returnTo)}`} replace />;
  }
  return <>{children}</>;
}

function NativeProfileGate({
  requiredProfile,
  children,
}: {
  requiredProfile: "tenant" | "localpro" | "landlord" | "partner" | "operator" | "family" | null;
  children: ReactNode;
}) {
  const resident = useResidentApp();
  if (!requiredProfile) return <>{children}</>;
  const hasProfile = resident.authorizedProfiles.some((profile) => String(profile.profileKey) === requiredProfile);
  if (hasProfile) return <>{children}</>;
  return (
    <PhoneShell header={<SubHeader title="This profile is not available" backTo="/tenant/home" />}>
      <div className="px-5 pt-5">
        <ScreenCard title="Choose another profile">
          <p className="text-sm leading-6 text-slate-600">Only profiles connected to your LiveUIN account appear in this app.</p>
          <a
            href="/tenant/home"
            className="mt-4 block rounded-full bg-[#0B1222] px-4 py-3 text-center text-sm font-bold text-white"
          >
            Back to LiveUIN
          </a>
        </ScreenCard>
      </div>
    </PhoneShell>
  );
}

function requiredProfileForPath(path: string): "tenant" | "localpro" | "landlord" | "partner" | "operator" | "family" | null {
  if (path === "/tenant" || path.startsWith("/tenant/")) return "tenant";
  if (path === "/localpro" || path.startsWith("/localpro/")) return "localpro";
  if (path === "/landlord" || path.startsWith("/landlord/")) return "landlord";
  if (path === "/partner" || path.startsWith("/partner/")) return "partner";
  if (path === "/operator" || path.startsWith("/operator/")) return "operator";
  if (path === "/family" || path.startsWith("/family/")) return "family";
  return null;
}

function NativeLovableRoute({
  component: Component,
  requiredProfile,
}: {
  component: ComponentType;
  requiredProfile: "tenant" | "localpro" | "landlord" | "partner" | "operator" | "family" | null;
}) {
  return (
    <NativeProfileGate requiredProfile={requiredProfile}>
      <Component />
    </NativeProfileGate>
  );
}

const protectedLovableRoutes = nativeLovableRoutes.filter(
  (route) => !["/welcome", "/offline", "/auth/sign-in", "/auth/sign-up", "/auth/forgot-password", "/auth/cancel-deletion"].includes(route.path),
);
const welcomeRoute = nativeLovableRoutes.find((route) => route.path === "/welcome");
const WelcomeComponent = (welcomeRoute?.component || (() => <Navigate to="/auth/sign-in" replace />)) as ComponentType;
const authSignInRoute = nativeLovableRoutes.find((route) => route.path === "/auth/sign-in");
const AuthSignInComponent = (authSignInRoute?.component || (() => <Navigate to="/welcome" replace />)) as ComponentType;
const OfflineComponent = nativeLovableRoutes.find((route) => route.path === "/offline")?.component as ComponentType | undefined;
const publicAuthRoutes = nativeLovableRoutes.filter((route) =>
  ["/auth/sign-in", "/auth/sign-up", "/auth/forgot-password", "/auth/cancel-deletion"].includes(route.path),
);


const NativeApp = () => (
    <QueryClientProvider client={appQueryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <ResidentNativeEntryBridge />
          <Suspense fallback={<RouteFallback />}>
            <ResidentNativeRouteGate fallback={<RouteFallback />}>
              <Routes>
                <Route path="/" element={<RootRoute />} />
                <Route
                  path="/welcome"
                  element={
                    <PublicNativeProviders>
                      <WelcomeComponent />
                    </PublicNativeProviders>
                  }
                />
                {publicAuthRoutes.map((route) => (
                  <Route
                    key={route.source}
                    path={route.path}
                    element={
                      <PublicAuthProviders>
                        <NativeLovableRoute component={route.component as ComponentType} requiredProfile={null} />
                      </PublicAuthProviders>
                    }
                  />
                ))}
                <Route element={<NativeFeatureScopeBridge />}>
                <Route element={<ProtectedNativeProviders />}>
                  <Route element={<NativeFeatureSessionBoundary />}>
                  <Route element={<NativeR6Providers />}>
                    {nativeR6Routes.map(({ path, component: Component, source }) => (
                      <Route key={source} path={path} element={<NativeFeatureRoute component={Component} />} />
                    ))}
                  </Route>
                  {OfflineComponent && <Route path="/offline" element={<OfflineComponent />} />}
                  {protectedLovableRoutes.map((route) => (
                    <Route
                      key={route.source}
                      path={route.path}
                      element={
                        <NativeLovableRoute
                          component={route.component as ComponentType}
                          requiredProfile={requiredProfileForPath(route.path)}
                        />
                      }
                    />
                  ))}
                  <Route path="/tenant" element={<Navigate to="/tenant/home" replace />} />
                  <Route path="/localpro" element={<Navigate to="/localpro/home" replace />} />
                  </Route>
                </Route>
                </Route>
                <Route path="*" element={<Navigate to="/welcome" replace />} />
              </Routes>
            </ResidentNativeRouteGate>
          </Suspense>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
);

export default NativeApp;
