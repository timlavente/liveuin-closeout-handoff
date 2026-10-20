import { resolveResidentAuthDestination } from "@/lib/residentAuthRedirect";

/**
 * After sign-in, return the person to the screen they were trying to open.
 * Each profile may only land on its own screens, plus shared account screens.
 * Staff founder and studio paths stay closed. A live charge is never started here.
 */
export type NativeAuthProfile = "tenant" | "localpro" | "landlord" | "partner" | "operator" | "family";

const PROFILE_PREFIXES: Record<NativeAuthProfile, readonly string[]> = {
  tenant: ["/tenant", "/pass"],
  localpro: ["/localpro"],
  landlord: ["/landlord"],
  partner: ["/partner"],
  operator: ["/operator"],
  family: ["/family"],
};

const SHARED_PREFIXES = ["/messages", "/account", "/journey"];

export function nativeAuthHome(profile: NativeAuthProfile) {
  if (profile === "tenant") return "/tenant/home";
  if (profile === "localpro") return "/localpro/home";
  if (profile === "landlord") return "/landlord/home";
  if (profile === "partner") return "/partner/home";
  if (profile === "operator") return "/operator/home";
  return "/family/home";
}

export function resolveNativeAuthLandingPath(
  profile: NativeAuthProfile,
  returnTo: string | null | undefined,
  fallback: string,
) {
  const destination = resolveResidentAuthDestination(returnTo, fallback);
  if (!destination || destination === fallback) return fallback;

  let path = destination;
  if (!destination.startsWith("/")) {
    try {
      const parsed = new URL(destination);
      const protocol = parsed.protocol.replace(":", "").toLowerCase();
      const sameAppHost = parsed.hostname.toLowerCase() === "app.liveuin.com";
      if (protocol !== "https" && protocol !== "http" && protocol !== "capacitor") return fallback;
      if (!sameAppHost && protocol !== "capacitor") return fallback;
      path = `${parsed.pathname}${parsed.search}${parsed.hash}`;
    } catch {
      return fallback;
    }
  }

  const pathname = path.split(/[?#]/)[0] || "/";
  if (pathname === "/welcome" || pathname.startsWith("/auth/")) return fallback;
  if (pathname.startsWith("/studio") || pathname.startsWith("/founder") || pathname.startsWith("/ops")) return fallback;

  const onProfile = PROFILE_PREFIXES[profile].some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
  const shared = SHARED_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
  return onProfile || shared ? path : fallback;
}
