import { createFileRoute, useNavigate } from "@/native-lovable/router";
import { useState } from "react";
import { AuthShell } from "@/components/liveuin/AuthShell";
import { CompleteProfileForm } from "@/native-lovable/components/CompleteProfileForm";
import { describeAuthError, useAuth } from "@/lib/auth-context";
import { useLanguage } from "@/lib/language-context";

export const Route = createFileRoute("/auth/complete-profile")({
  head: () => ({ meta: [{ title: "Complete your LiveUIN profile" }] }),
  component: CompleteProfile,
});

export function CompleteProfile() {
  const { completeProfile, completeTenantOnboarding, signOut } = useAuth();
  const { language } = useLanguage();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const finish = async (displayName: string) => {
    setBusy(true);
    setErr(null);
    try {
      await completeProfile(displayName, language.code);
      await completeTenantOnboarding();
      await navigate({ to: "/tenant/home", replace: true });
    } catch (cause) {
      setErr(describeAuthError(cause, "LiveUIN could not finish your profile. Please try again later."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell
      title="Complete your LiveUIN profile"
      subtitle="Add the minimum details needed to continue."
      footer={
        <button type="button" onClick={() => void signOut()} className="font-semibold text-indigo-600">
          Sign out
        </button>
      }
    >
      <CompleteProfileForm busy={busy} onComplete={finish} />
      {err ? <p className="mt-4 max-w-full break-words text-xs leading-5 text-red-600">{err}</p> : null}
    </AuthShell>
  );
}
