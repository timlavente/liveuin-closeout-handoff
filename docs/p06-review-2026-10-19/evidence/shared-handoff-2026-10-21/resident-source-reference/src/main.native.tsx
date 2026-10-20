import { createRoot } from "react-dom/client";
import NativeApp from "./NativeApp.tsx";
import { NativeErrorBoundary } from "@/components/resident/NativeErrorBoundary";
import "./index.css";
import { extractResidentAppUrlTransport } from "@/lib/residentAppDeepLinks";
import { rememberResidentNativeSourceHostFromUrl, setResidentNativeSourceHost } from "@/lib/runtimeHost";
import { installNativeFieldFocusLock } from "@/lib/nativeFieldFocus";
import { setResidentSignedSession } from "@/lib/residentSessionBridge";

document.documentElement.dataset.liveuinNativeAppOnly = "true";

const applyNativeViewportSize = () => {
  const fallbackWidth = document.documentElement.clientWidth || window.innerWidth || 0;
  const fallbackHeight = document.documentElement.clientHeight || window.innerHeight || 0;
  const visualWidth = window.visualViewport?.width || fallbackWidth;
  const visualHeight = window.visualViewport?.height || fallbackHeight;
  const viewportHeight = Math.max(Math.floor(visualHeight || fallbackHeight), 0);
  const viewportWidth = Math.max(Math.floor(Math.min(visualWidth || fallbackWidth, fallbackWidth || visualWidth)), 0);
  document.documentElement.style.setProperty("--liveuin-app-height", `${viewportHeight}px`);
  document.documentElement.style.setProperty("--liveuin-app-width", viewportWidth ? `${viewportWidth}px` : "100%");
  document.documentElement.style.overflowX = "hidden";
  document.body.style.overflowX = "hidden";
};

applyNativeViewportSize();
installNativeFieldFocusLock();
window.visualViewport?.addEventListener("resize", applyNativeViewportSize);
window.addEventListener("resize", applyNativeViewportSize);

const initialNativeLaunchUrl = String(
  (window as typeof window & { __LIVEUIN_NATIVE_LAUNCH_URL__?: string }).__LIVEUIN_NATIVE_LAUNCH_URL__ || "",
).trim();
const initialNativePath = `${window.location.pathname}${window.location.search}${window.location.hash}`;
const initialNativeTarget =
  initialNativeLaunchUrl || (/^\/(?:tenant|localpro|messages|journey)(?:\/|$|\?)/.test(initialNativePath) ? initialNativePath : "");

if (initialNativeTarget) {
  const transport = extractResidentAppUrlTransport(initialNativeTarget);
  if (transport.sourceHost) {
    setResidentNativeSourceHost(transport.sourceHost);
  } else {
    rememberResidentNativeSourceHostFromUrl(initialNativeTarget);
  }
  if (transport.signedSession) {
    setResidentSignedSession(transport.signedSession);
  }
}

createRoot(document.getElementById("root")!).render(
  <NativeErrorBoundary homeHref="/">
    <NativeApp />
  </NativeErrorBoundary>,
);
