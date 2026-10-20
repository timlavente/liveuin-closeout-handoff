import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useResidentApp } from "@/components/resident/ResidentAppContext";

export type Profile = "tenant" | "localpro" | "landlord" | "partner" | "operator" | "family";

type Ctx = {
  activeProfile: Profile;
  profiles: Profile[];
  switchProfile: (profile: Profile) => void;
  switcherOpen: boolean;
  setSwitcherOpen: (open: boolean) => void;
};

const ProfileContext = createContext<Ctx | null>(null);

function normalizeProfile(value: string): Profile | null {
  if (value === "tenant" || value === "localpro" || value === "landlord" || value === "partner" || value === "operator" || value === "family") {
    return value;
  }
  return null;
}

export function ProfileProvider({ children }: { children: ReactNode }) {
  const resident = useResidentApp();
  const [switcherOpen, setSwitcherOpen] = useState(false);
  const profiles = useMemo(
    () => resident.authorizedProfiles.map((profile) => normalizeProfile(profile.profileKey)).filter(Boolean) as Profile[],
    [resident.authorizedProfiles],
  );
  const activeProfile = normalizeProfile(resident.activeProfileKey) || profiles[0] || "tenant";

  const switchProfile = (profile: Profile) => {
    const authorized = resident.authorizedProfiles.find((item) => item.profileKey === profile);
    const workspace =
      authorized?.workspaces.find((item) => item.workspaceId === authorized.defaultWorkspaceId) ||
      authorized?.workspaces[0];
    if (!authorized || !workspace) return;
    setSwitcherOpen(false);
    resident.switchProfileWorkspace({ profileKey: profile, workspaceId: workspace.workspaceId });
  };

  useEffect(() => {
    const openSwitcher = () => {
      setSwitcherOpen(true);
    };
    window.addEventListener("liveuin:open-profile-switcher", openSwitcher);
    const pendingOpenUntil =
      (window as typeof window & { __LIVEUIN_OPEN_PROFILE_SWITCHER_UNTIL__?: number }).__LIVEUIN_OPEN_PROFILE_SWITCHER_UNTIL__ || 0;
    if (pendingOpenUntil > Date.now()) {
      openSwitcher();
    }
    return () => window.removeEventListener("liveuin:open-profile-switcher", openSwitcher);
  }, []);

  return (
    <ProfileContext.Provider value={{ activeProfile, profiles, switchProfile, switcherOpen, setSwitcherOpen }}>
      {children}
    </ProfileContext.Provider>
  );
}

export function useProfile() {
  const ctx = useContext(ProfileContext);
  if (!ctx) throw new Error("useProfile must be used inside ProfileProvider");
  return ctx;
}
