import { createFileRoute, useNavigate } from "@/native-lovable/router";
import { useState } from "react";
import { AuthShell } from "@/components/liveuin/AuthShell";
import { describeAuthError, useAuth } from "@/lib/auth-context";
import { Loader2 } from "lucide-react";

export const Route = createFileRoute("/auth/continue-tenant")({
  head: () => ({ meta: [{ title: "Continue your LiveUIN setup" }] }),
  component: ContinueTenant,
});

function ContinueTenant() {
  const { completeTenantOnboarding, signOut } = useAuth();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const continueSetup = async () => {
    setBusy(true);
    setErr(null);
    try {
      await completeTenantOnboarding();
      await navigate({ to: "/tenant/home", replace: true });
    } catch (cause) {
      setErr(describeAuthError(cause, "LiveUIN could not finish your account setup. Please try again later."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell
      title="Continue your LiveUIN setup"
      subtitle="Your profile is ready. Confirm Tenant access to open your home workspace."
      footer={<button type="button" onClick={() => void signOut()} className="font-semibold text-indigo-600">Sign out</button>}
    >
      <button
        type="button"
        onClick={() => void continueSetup()}
        disabled={busy}
        className="flex h-13 w-full items-center justify-center gap-2 rounded-2xl bg-gradient-to-r from-indigo-600 to-purple-600 py-3.5 font-sora text-base font-semibold text-white shadow-lg shadow-indigo-500/20 transition disabled:opacity-70"
      >
        {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
        Continue to Tenant
      </button>
      {err ? <p className="mt-4 max-w-full break-words text-xs leading-5 text-red-600">{err}</p> : null}
    </AuthShell>
  );
}
