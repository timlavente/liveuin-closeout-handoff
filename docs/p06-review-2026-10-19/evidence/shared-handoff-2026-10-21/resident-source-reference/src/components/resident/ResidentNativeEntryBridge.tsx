import { useEffect, useRef } from "react";
import { Capacitor } from "@capacitor/core";
import { useQueryClient } from "@tanstack/react-query";
import { useLocation, useNavigate } from "react-router-dom";
import { extractResidentAppUrlTransport } from "@/lib/residentAppDeepLinks";
import { markResidentNativeLaunchContextReady } from "@/lib/residentNativeLaunch";
import { shouldRefreshResidentQuery } from "@/lib/residentNativeShell";
import { consumeResidentSimulatedLaunchUrl } from "@/lib/residentNativeSmokeLaunch";
import { isNativeRuntimeShell, rememberResidentNativeSourceHostFromUrl, setResidentNativeSourceHost } from "@/lib/runtimeHost";
import { setResidentSignedSession } from "@/lib/residentSessionBridge";

export const ResidentNativeEntryBridge = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const currentPathRef = useRef(`${location.pathname}${location.search}${location.hash}`);
  const handledLaunchRouteTargetsRef = useRef(new Set<string>());
  const splashHidePromiseRef = useRef<Promise<void> | null>(null);

  useEffect(() => {
    currentPathRef.current = `${location.pathname}${location.search}${location.hash}`;
  }, [location.hash, location.pathname, location.search]);

  useEffect(() => {
    let cancelled = false;
    let removeListener: (() => Promise<void>) | null = null;

    const hideNativeSplashScreen = async () => {
      if (splashHidePromiseRef.current) {
        return splashHidePromiseRef.current;
      }
      splashHidePromiseRef.current = (async () => {
        try {
          const { SplashScreen } = await import("@capacitor/splash-screen");
          await SplashScreen.hide();
        } catch {
          // Keep the native bridge fail-closed if the splash plugin is unavailable.
        }
      })();
      return splashHidePromiseRef.current;
    };

    const routeToNativeTargetFromLaunchOnce = (rawTarget: string, replace = false) => {
      const normalizedTarget = String(rawTarget || "").trim();
      if (!normalizedTarget) return;
      if (handledLaunchRouteTargetsRef.current.has(normalizedTarget)) return;
      handledLaunchRouteTargetsRef.current.add(normalizedTarget);
      routeToNativeTarget(normalizedTarget, replace);
    };

    const routeToNativeTargetFromLaunch = (rawTarget: string) => {
      routeToNativeTargetFromLaunchOnce(rawTarget, false);
    };

    const shouldOpenProfileSwitcher = (rawTarget: string, normalizedPath: string | null) => {
      return [rawTarget, normalizedPath || ""].some((candidate) => {
        if (!candidate.includes("liveuin_open_profile_switcher")) return false;
        try {
          const parsed = candidate.startsWith("/")
            ? new URL(candidate, "https://app.liveuin.com")
            : new URL(candidate);
          return parsed.searchParams.get("liveuin_open_profile_switcher") === "1";
        } catch {
          return /(?:^|[?&])liveuin_open_profile_switcher=1(?:&|$)/.test(candidate);
        }
      });
    };

    const openProfileSwitcherFromNativeRoute = () => {
      (window as typeof window & { __LIVEUIN_OPEN_PROFILE_SWITCHER_UNTIL__?: number }).__LIVEUIN_OPEN_PROFILE_SWITCHER_UNTIL__ =
        Date.now() + 5_000;
      window.dispatchEvent(new CustomEvent("liveuin:open-profile-switcher"));
    };

    const routeToNativeTarget = (rawTarget: string, replace = false) => {
      const transport = extractResidentAppUrlTransport(rawTarget);

      if (transport.sourceHost) {
        setResidentNativeSourceHost(transport.sourceHost);
      } else {
        rememberResidentNativeSourceHostFromUrl(rawTarget);
      }

      if (transport.signedSession) {
        setResidentSignedSession(transport.signedSession);
        void queryClient.invalidateQueries({
          predicate: (query) => shouldRefreshResidentQuery(query.queryKey),
        });
      }

      const nextPath = transport.path;
      const openProfileSwitcher = shouldOpenProfileSwitcher(rawTarget, nextPath);
      if (!nextPath || nextPath === currentPathRef.current) {
        if (openProfileSwitcher) openProfileSwitcherFromNativeRoute();
        return;
      }
      navigate(nextPath, { replace });
      if (openProfileSwitcher) {
        [0, 250, 750, 1_500, 2_500].forEach((delay) => {
          window.setTimeout(openProfileSwitcherFromNativeRoute, delay);
        });
      }
    };

    const routeToNativeTargetFromEvent = (rawTarget: string) => {
      routeToNativeTargetFromLaunchOnce(rawTarget, false);
    };

    const routeToNativeTargetFromWindowEvent = (event: Event) => {
      const rawTarget = String((event as CustomEvent<{ url?: string }>).detail?.url || "").trim();
      routeToNativeTargetFromEvent(rawTarget);
    };
    const initialWindowLaunchUrl = String(
      (window as typeof window & { __LIVEUIN_NATIVE_LAUNCH_URL__?: string }).__LIVEUIN_NATIVE_LAUNCH_URL__ || "",
    ).trim();
    routeToNativeTargetFromEvent(initialWindowLaunchUrl);
    if (!initialWindowLaunchUrl) {
      const initialWindowPath = `${window.location.pathname}${window.location.search}${window.location.hash}`;
      if (/^\/(?:tenant|localpro|messages|journey)(?:\/|$|\?)/.test(initialWindowPath)) {
        routeToNativeTargetFromEvent(initialWindowPath);
      }
    }

    const routeToNativeTargetFromSimulatedOrLaunch = (rawTarget: string) => {
      routeToNativeTargetFromLaunch(rawTarget);
    };

    const handleLaunchTargets = async (App: { getLaunchUrl: () => Promise<{ url?: string } | null> }) => {
      const simulatedLaunchUrl = await consumeResidentSimulatedLaunchUrl();
      if (simulatedLaunchUrl) routeToNativeTargetFromSimulatedOrLaunch(simulatedLaunchUrl);

      const launchUrl = await App.getLaunchUrl();
      if (launchUrl?.url) routeToNativeTargetFromSimulatedOrLaunch(launchUrl.url);
    };

    const hideSplashAndFinalizeLaunch = async (App: { getLaunchUrl: () => Promise<{ url?: string } | null> }) => {
      try {
        await handleLaunchTargets(App);
      } finally {
        markResidentNativeLaunchContextReady();
        await hideNativeSplashScreen();
      }
    };

    async function bindNativeDeepLinks() {
      if (typeof window === "undefined") return;

      try {
        const { App } = await import("@capacitor/app");

        if (cancelled || !isNativeRuntimeShell()) {
          markResidentNativeLaunchContextReady();
          return;
        }

        const listener = await App.addListener("appUrlOpen", ({ url }) => {
          routeToNativeTargetFromEvent(url);
        });
        removeListener = () => listener.remove();

        void hideSplashAndFinalizeLaunch(App).catch(() => undefined);
      } catch {
        markResidentNativeLaunchContextReady();
        removeListener = null;
        void hideNativeSplashScreen();
      } finally {
      }
    }

    window.addEventListener("liveuin:native-launch-url", routeToNativeTargetFromWindowEvent);

    void bindNativeDeepLinks();

    return () => {
      cancelled = true;
      window.removeEventListener("liveuin:native-launch-url", routeToNativeTargetFromWindowEvent);
      if (removeListener) void removeListener();
    };
  }, [navigate]);

  return null;
};
