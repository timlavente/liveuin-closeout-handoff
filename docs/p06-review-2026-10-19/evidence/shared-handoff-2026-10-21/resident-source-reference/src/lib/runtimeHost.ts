import { Capacitor } from "@capacitor/core";

export const APP_HOST = "app.liveuin.com";
export const AI_HOST = "ai.liveuin.com";
const HOST_HOST = "host.liveuin.com";
const PARTNER_HOST = "partner.liveuin.com";
const VENDOR_HOST = "vendor.liveuin.com";
const CN_HOST = "cn.liveuin.com";
export const PASS_HOST = "pass.liveuin.com";
export const LAIJUZHU_PASS_HOST = "pass.laijuzhu.com";
const OPS_HOST = "ops.liveuin.com";
export const CORE_PREVIEW_HOST = "core-preview.liveuin.com";
const CONNECT_HOST = "connect.liveuin.com";
const LIVEUIN_ROOT_HOST = APP_HOST.replace(/^app\./, "");
const LIVEUIN_WWW_HOST = ["www", LIVEUIN_ROOT_HOST].join(".");
const RESIDENT_NATIVE_SOURCE_HOST_STORAGE_KEY = "liveuin.resident.native-source-host";

// LiveUIN owns canonical Pass truth. `pass.liveuin.com` is the neutral/global Pass host,
// while `pass.laijuzhu.com` is a China-corridor branded shell over the same Pass continuity.
export const isLaijuzhuPassHost = (hostname = runtimeHostname()) => hostname === LAIJUZHU_PASS_HOST;
export const isAnyPassHost = (hostname = runtimeHostname()) => isPassHost(hostname) || isLaijuzhuPassHost(hostname);

function loadResidentNativeSourceHost() {
  if (typeof window === "undefined") return "";
  try {
    return String(window.localStorage.getItem(RESIDENT_NATIVE_SOURCE_HOST_STORAGE_KEY) || "").trim().toLowerCase();
  } catch {
    return "";
  }
}

let residentNativeSourceHost = loadResidentNativeSourceHost();

const normalizedPath = (path: string) => {
  if (!path) return "/";
  return path.startsWith("/") ? path : `/${path}`;
};

const normalizedOrigin = (origin: string) => origin.replace(/\/+$/, "");

const sanitizeResidentNativeSourceHost = (value: string) => {
  const host = String(value || "").trim().toLowerCase();
  if (!host) return "";
  if (isLocalPreviewHost(host)) return "";
  if (host === LIVEUIN_ROOT_HOST || host === LIVEUIN_WWW_HOST) return APP_HOST;
  if (host.endsWith(".liveuin.com") || host.endsWith(".laijuzhu.com")) return host;
  return "";
};

export const isNativeRuntimeShell = () => {
  if (typeof window === "undefined") return false;
  if (document.documentElement.hasAttribute("data-liveuin-native-app-only")) return true;
  if (Capacitor.isNativePlatform()) return true;
  const capacitor = (window as Window & {
    Capacitor?: { isNativePlatform?: () => boolean; getPlatform?: () => string };
  }).Capacitor;
  if (!capacitor) return false;
  if (typeof capacitor.isNativePlatform === "function") {
    return Boolean(capacitor.isNativePlatform());
  }
  if (typeof capacitor.getPlatform === "function") {
    const platform = String(capacitor.getPlatform() || "").toLowerCase();
    return Boolean(platform && platform !== "web");
  }
  return false;
};

export const setResidentNativeSourceHost = (host: string) => {
  residentNativeSourceHost = sanitizeResidentNativeSourceHost(host);
  if (typeof window !== "undefined") {
    try {
      if (residentNativeSourceHost) {
        window.localStorage.setItem(RESIDENT_NATIVE_SOURCE_HOST_STORAGE_KEY, residentNativeSourceHost);
      } else {
        window.localStorage.removeItem(RESIDENT_NATIVE_SOURCE_HOST_STORAGE_KEY);
      }
    } catch {
      // Local storage is optional in the wrapper.
    }
  }
  return residentNativeSourceHost;
};

export const clearResidentNativeSourceHost = () => {
  residentNativeSourceHost = "";
  if (typeof window !== "undefined") {
    try {
      window.localStorage.removeItem(RESIDENT_NATIVE_SOURCE_HOST_STORAGE_KEY);
    } catch {
      // Local storage is optional in browser tests and native shells.
    }
  }
};

export const getResidentNativeSourceHost = () => residentNativeSourceHost;

export const rememberResidentNativeSourceHostFromUrl = (rawUrl: string) => {
  if (!rawUrl) return residentNativeSourceHost;
  try {
    const parsed = new URL(rawUrl);
    const protocol = parsed.protocol.replace(":", "").toLowerCase();
    if (protocol === "http" || protocol === "https") {
      return setResidentNativeSourceHost(parsed.hostname);
    }
  } catch {
    return residentNativeSourceHost;
  }
  return residentNativeSourceHost;
};

export const rawRuntimeHostname = () =>
  typeof window === "undefined" ? "" : String(window.location.hostname || "").toLowerCase();

export const isLocalPreviewHost = (hostname = rawRuntimeHostname()) => {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
};

export const runtimeHostname = () => {
  const hostname = rawRuntimeHostname();
  if (typeof window === "undefined") {
    return hostname;
  }
  if (!isLocalPreviewHost(hostname)) {
    return hostname;
  }
  const params = new URLSearchParams(window.location.search || "");
  const previewHost = String(params.get("preview_host") || params.get("previewHost") || "").toLowerCase().trim();
  if (previewHost) {
    return previewHost;
  }
  return hostname;
};

// Staging is a real browser origin, so it must not be treated as a local
// preview. It may render the private shell, but OpsAuthGate must still verify
// the signed operator session against the staging backend.
export const isStagingHost = (hostname = runtimeHostname()) => {
  const normalized = String(hostname || "").trim().toLowerCase().replace(/\.$/, "");
  return normalized === "liveuin-test.liveuin.com" || normalized.endsWith(".liveuin-test.liveuin.com");
};

export const isStagingHostSurfacePreview = (hostname = runtimeHostname()) =>
  isStagingHost(hostname) && String(import.meta.env.VITE_LIVEUIN_HOST_SURFACE_PREVIEW || "") === "1";

export const isLiveuinTestHost = (hostname = runtimeHostname()) => {
  if (!import.meta.env.DEV) return false;
  return hostname.includes("liveuin-test");
};
export const isCorePreviewHost = (hostname = runtimeHostname()) => hostname === CORE_PREVIEW_HOST;
export const isOpsLovablePreviewPath = (pathname = typeof window === "undefined" ? "" : window.location.pathname) =>
  /^\/ops-[^/]*preview-[^/]+(?:\/|$)/.test(pathname);
export const isPreviewHost = (hostname = runtimeHostname()) =>
  isLocalPreviewHost(hostname) || isLiveuinTestHost(hostname) || isCorePreviewHost(hostname);
export const isAppHost = (hostname = runtimeHostname()) => hostname === APP_HOST;
export const isAiHost = (hostname = runtimeHostname()) => hostname === AI_HOST;
export const isHostHost = (hostname = runtimeHostname()) => hostname === HOST_HOST;
export const isPartnerHost = (hostname = runtimeHostname()) => hostname === PARTNER_HOST;
export const isVendorHost = (hostname = runtimeHostname()) => hostname === VENDOR_HOST;
export const isCnHost = (hostname = runtimeHostname()) => hostname === CN_HOST;
export const isPassHost = (hostname = runtimeHostname()) => hostname === PASS_HOST;
export const isOpsHost = (hostname = runtimeHostname()) => hostname === OPS_HOST;
export const isConnectHost = (hostname = runtimeHostname()) => hostname === CONNECT_HOST;

export const isLaijuzhuCorridorSourceHost = (hostname: string) => {
  const normalized = sanitizeResidentNativeSourceHost(hostname);
  if (!normalized) return false;
  return (
    normalized === LAIJUZHU_PASS_HOST ||
    normalized === CN_HOST ||
    normalized === "laijuzhu.com" ||
    normalized.endsWith(".laijuzhu.com")
  );
};

export const resolvePassShellHost = (sourceHost = "", fallbackHost = runtimeHostname()) => {
  if (isLaijuzhuCorridorSourceHost(sourceHost)) return LAIJUZHU_PASS_HOST;
  if (isLaijuzhuCorridorSourceHost(fallbackHost)) return LAIJUZHU_PASS_HOST;
  return PASS_HOST;
};

export const resolveResidentApiHost = (sourceHost = "", fallbackHost = runtimeHostname()) => {
  const normalizedSourceHost = sanitizeResidentNativeSourceHost(sourceHost);
  const normalizedFallbackHost = sanitizeResidentNativeSourceHost(fallbackHost);

  if (normalizedSourceHost && isLiveuinTestHost(normalizedSourceHost)) {
    return normalizedSourceHost;
  }
  if (normalizedFallbackHost && isLiveuinTestHost(normalizedFallbackHost)) {
    return normalizedFallbackHost;
  }

  return APP_HOST;
};

export const buildResidentApiUrl = (path: string) => {
  const nextPath = normalizedPath(path);
  const explicitOrigin = normalizedOrigin(String(import.meta.env.VITE_LIVEUIN_RESIDENT_API_ORIGIN || "").trim());
  if (explicitOrigin) return `${explicitOrigin}${nextPath}`;
  if (!isNativeRuntimeShell()) return nextPath;

  const host = runtimeHostname();
  const resolvedHost = resolveResidentApiHost(residentNativeSourceHost || host, host);
  return `https://${resolvedHost}${nextPath}`;
};

export const buildAppHref = (path = "/tenant/home", hostname = runtimeHostname()) => {
  const nextPath = normalizedPath(path);
  if (!hostname) return nextPath;
  if (isLiveuinTestHost(hostname)) return nextPath;
  if (isAppHost(hostname)) return nextPath;
  if (hostname === "liveuin.com" || hostname === "www.liveuin.com" || hostname.endsWith(".liveuin.com")) {
    return `https://${APP_HOST}${nextPath}`;
  }
  return nextPath;
};

export const buildAiHref = (path = "/ops/ai", hostname = runtimeHostname()) => {
  const nextPath = normalizedPath(path);
  if (!hostname) return nextPath;
  if (hostname === AI_HOST) return nextPath;
  if (hostname === "liveuin.com" || hostname === "www.liveuin.com") {
    return `https://${AI_HOST}${nextPath}`;
  }
  return nextPath;
};

export const buildHostHref = (path = "/host/onboarding", hostname = runtimeHostname()) => {
  const nextPath = normalizedPath(path);
  if (!hostname) return nextPath;
  if (isLiveuinTestHost(hostname)) return nextPath;
  if (isHostHost(hostname)) return nextPath;
  if (hostname === "liveuin.com" || hostname === "www.liveuin.com" || hostname.endsWith(".liveuin.com")) {
    return `https://${HOST_HOST}${nextPath}`;
  }
  return nextPath;
};

export const buildPartnerHref = (path = "/partner/dashboard", hostname = runtimeHostname()) => {
  const nextPath = normalizedPath(path);
  if (!hostname) return nextPath;
  if (isLiveuinTestHost(hostname)) return nextPath;
  if (isPartnerHost(hostname)) return nextPath;
  if (hostname === "liveuin.com" || hostname === "www.liveuin.com" || hostname.endsWith(".liveuin.com")) {
    return `https://${PARTNER_HOST}${nextPath}`;
  }
  return nextPath;
};

export const buildVendorHref = (path = "/vendor/dashboard", hostname = runtimeHostname()) => {
  const nextPath = normalizedPath(path);
  if (!hostname) return nextPath;
  if (isLiveuinTestHost(hostname)) return nextPath;
  if (isVendorHost(hostname)) return nextPath;
  if (hostname === "liveuin.com" || hostname === "www.liveuin.com" || hostname.endsWith(".liveuin.com")) {
    return `https://${VENDOR_HOST}${nextPath}`;
  }
  return nextPath;
};

export const buildCnHref = (path = "/cn", hostname = runtimeHostname()) => {
  const nextPath = normalizedPath(path);
  if (!hostname) return nextPath;
  if (isLiveuinTestHost(hostname)) return nextPath;
  if (isCnHost(hostname)) return nextPath;
  if (hostname === "liveuin.com" || hostname === "www.liveuin.com" || hostname.endsWith(".liveuin.com")) {
    return `https://${CN_HOST}${nextPath}`;
  }
  return nextPath;
};

export const buildPassHref = (path = "/pass", hostname = runtimeHostname()) => {
  const nextPath = normalizedPath(path);
  if (!hostname) return nextPath;
  if (isLiveuinTestHost(hostname)) return nextPath;
  if (isAnyPassHost(hostname)) return nextPath;
  if (hostname === "liveuin.com" || hostname === "www.liveuin.com" || hostname.endsWith(".liveuin.com")) {
    return `https://${resolvePassShellHost(hostname, hostname)}${nextPath}`;
  }
  return nextPath;
};

export const buildOpsHref = (path = "/ops/control-tower", hostname = runtimeHostname()) => {
  const nextPath = normalizedPath(path);
  if (!hostname) return nextPath;
  if (isLiveuinTestHost(hostname)) return nextPath;
  if (isOpsHost(hostname)) return nextPath;
  if (hostname === "liveuin.com" || hostname === "www.liveuin.com" || hostname.endsWith(".liveuin.com")) {
    return `https://${OPS_HOST}${nextPath}`;
  }
  return nextPath;
};

export const buildConnectHref = (path = "/connect/sites", hostname = runtimeHostname()) => {
  const nextPath = normalizedPath(path);
  if (!hostname) return nextPath;
  if (isLiveuinTestHost(hostname)) return nextPath;
  if (isConnectHost(hostname)) return nextPath;
  if (hostname === "liveuin.com" || hostname === "www.liveuin.com" || hostname.endsWith(".liveuin.com")) {
    return `https://${CONNECT_HOST}${nextPath}`;
  }
  return nextPath;
};
