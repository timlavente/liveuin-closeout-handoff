import { normalizeResidentAppUrlToPath } from "@/lib/residentAppDeepLinks";
import { APP_HOST, LAIJUZHU_PASS_HOST, PASS_HOST, isLiveuinTestHost, isLocalPreviewHost } from "@/lib/runtimeHost";

const DIRECT_ALLOWED_RETURN_HOSTS = new Set([
  APP_HOST,
  PASS_HOST,
  LAIJUZHU_PASS_HOST,
  "www.liveuin.com",
  "liveuin.com",
]);

function isAllowedResidentReturnHost(hostname: string) {
  const normalized = String(hostname || "").trim().toLowerCase();
  return DIRECT_ALLOWED_RETURN_HOSTS.has(normalized) || isLocalPreviewHost(normalized) || isLiveuinTestHost(normalized);
}

function isSafeResidentRelativeReturnTo(value: string) {
  if (!value.startsWith("/")) return false;
  return Boolean(normalizeResidentAppUrlToPath(`https://app.liveuin.com${value}`));
}

export function buildResidentAuthReturnTo(input?: {
  href?: string;
  pathname?: string;
  search?: string;
  hash?: string;
}) {
  const href = input?.href || (typeof window === "undefined" ? "" : window.location.href || "");
  if (href) {
    const normalizedResidentPath = normalizeResidentAppUrlToPath(href);
    if (normalizedResidentPath) {
      try {
        const parsed = new URL(href);
        if (isAllowedResidentReturnHost(parsed.hostname)) {
          return parsed.href;
        }
        if (parsed.protocol.replace(":", "").toLowerCase() === "liveuinresident") {
          return href;
        }
      } catch {
        return href;
      }
    }
  }

  const pathname = input?.pathname || (typeof window === "undefined" ? "/" : window.location.pathname || "/");
  const search = input?.search || (typeof window === "undefined" ? "" : window.location.search || "");
  const hash = input?.hash || (typeof window === "undefined" ? "" : window.location.hash || "");
  return `${pathname}${search}${hash}`;
}

export function resolveResidentAuthDestination(returnTo: string | null | undefined, fallback: string) {
  const candidate = String(returnTo || "").trim();
  if (!candidate) return fallback;

  if (candidate.startsWith("/")) {
    return isSafeResidentRelativeReturnTo(candidate) ? candidate : fallback;
  }

  try {
    const parsed = new URL(candidate);
    const protocol = parsed.protocol.replace(":", "").toLowerCase();
    if (protocol === "liveuinresident") {
      return normalizeResidentAppUrlToPath(parsed.href) || fallback;
    }
    if (!isAllowedResidentReturnHost(parsed.hostname)) return fallback;
    return normalizeResidentAppUrlToPath(parsed.href) ? parsed.href : fallback;
  } catch {
    return fallback;
  }
}
