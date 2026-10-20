import { createFileRoute, Link, useLocation, useNavigate } from "@/native-lovable/router";
import { useQuery } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { AuthShell } from "@/components/liveuin/AuthShell";
import { AuthFeedback } from "@/components/liveuin/AuthFeedback";
import { describeAuthError, publicTermsVersion, useAuth } from "@/lib/auth-context";
import { ResidentApiError } from "@/lib/residentNativeHttp";
import { pendingDeletionMessage, readPendingAccountDeletion } from "@/lib/residentPendingDeletion";
import { buildSupportMailto } from "@/lib/residentSupportContact";
import { useProfile } from "@/lib/profile-context";
import { resolveAuthenticatedContinuation } from "@/lib/residentSocialContinuation";
import { nativeAuthHome, resolveNativeAuthLandingPath } from "@/lib/nativeAuthLanding";
import {
  isSocialAuthCancellation,
  fetchResidentSocialProviderPublicStatus,
  isSocialProviderButtonVisible,
  isSocialProviderButtonVisibleWithPublicStatusFor,
  residentSocialAuthConfig,
  socialAuthErrorCode,
  type SocialProvider,
} from "@/lib/residentSocialAuth";
import { Eye, EyeOff, Loader2 } from "lucide-react";

export const Route = createFileRoute("/auth/sign-in")({
  head: () => ({ meta: [{ title: "Sign in — LiveUIN" }] }),
  component: SignIn,
});

function SignIn() {
  const { signIn, signInWithProvider, startRegistration } = useAuth();
  const { switchProfile } = useProfile();
  const navigate = useNavigate();
  const requestedReturnTo = new URLSearchParams(useLocation().search).get("returnTo");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [socialBusy, setSocialBusy] = useState<SocialProvider | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [accountState, setAccountState] = useState<"deletion_pending" | "email_unverified" | null>(null);
  const [pendingDeletion] = useState(() => readPendingAccountDeletion());
  const socialProviderStatusQuery = useQuery({
    queryKey: ["resident-public-social-provider-status", residentSocialAuthConfig.buildProfile],
    queryFn: fetchResidentSocialProviderPublicStatus,
    enabled: residentSocialAuthConfig.buildProfile === "staging_e2e" && residentSocialAuthConfig.stagingEnabled,
    retry: false,
    staleTime: 0,
    refetchOnMount: "always",
    refetchOnWindowFocus: true,
  });
  const isProviderVisible = (provider: SocialProvider) =>
    residentSocialAuthConfig.buildProfile === "staging_e2e"
      ? isSocialProviderButtonVisibleWithPublicStatusFor(residentSocialAuthConfig, provider, socialProviderStatusQuery.data)
      : isSocialProviderButtonVisible(provider);

  const continueAfterAuth = async (user: Awaited<ReturnType<typeof signIn>>) => {
    const target = resolveAuthenticatedContinuation(user);
    if (target === "action_required") {
      setErr("LiveUIN could not confirm your profile access right now. Please try again later.");
      return;
    }
    if (target === "profile") {
      await navigate({ to: "/auth/complete-profile", replace: true });
      return;
    }
    if (target === "tenant_onboarding") {
      await navigate({ to: "/auth/continue-tenant", replace: true });
      return;
    }
    if (target === "link_required" || target === "deletion_pending") {
      setErr("LiveUIN could not continue this sign-in method right now. Please try again later.");
      return;
    }
    switchProfile(target);
    const fallback = nativeAuthHome(target);
    await navigate(resolveNativeAuthLandingPath(target, requestedReturnTo, fallback), { replace: true });
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    setErr(null);
    setAccountState(null);
    if (!email.trim() || !password) {
      setErr("Enter your email and password.");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      setErr("Enter a valid email address.");
      return;
    }
    setBusy(true);
    try {
      const u = await signIn(email, password);
      await continueAfterAuth(u);
    } catch (error) {
      const code = error instanceof ResidentApiError ? error.errorCode : undefined;
      if (code === "account_unavailable") {
        // The account is disabled or deletion-pending; the person who asked for deletion can cancel it.
        setAccountState("deletion_pending");
      } else if (code === "email_unverified") {
        setAccountState("email_unverified");
        setErr("Verify your email before signing in.");
      } else {
        setErr(describeAuthError(error, "Your sign-in details could not be verified. Check them and try again."));
      }
    } finally {
      setBusy(false);
    }
  };

  // Re-registering an unverified email sends a fresh code and returns the registration id needed to verify it.
  const resumeVerification = async () => {
    setErr(null);
    setBusy(true);
    try {
      const normalizedEmail = email.trim().toLowerCase();
      const result = await startRegistration({ email: normalizedEmail, password, acceptedTermsVersion: publicTermsVersion });
      await navigate({ to: "/auth/sign-up", search: { resume: result.registrationId, email: normalizedEmail } });
    } catch (error) {
      setErr(describeAuthError(error, "We couldn't send a new verification code. Please try again later."));
    } finally {
      setBusy(false);
    }
  };

  const continueWithProvider = async (provider: SocialProvider) => {
    setErr(null);
    setSocialBusy(provider);
    try {
      const u = await signInWithProvider(provider);
      await continueAfterAuth(u);
    } catch (error) {
      if (!isSocialAuthCancellation(error)) {
        const code = socialAuthErrorCode(error);
        setErr(
          code === "provider_not_ready"
            ? "This sign-in method is temporarily unavailable. Please try again later."
            : describeAuthError(error, "Your sign-in details could not be verified. Check them and try again."),
        );
      }
    } finally {
      setSocialBusy(null);
    }
  };

  return (
    <AuthShell
      title="Welcome back"
      subtitle="Sign in to your LiveUIN account. One login for Tenant and LocalPro."
      footer={
        <span className="text-slate-600">
          New to LiveUIN?{" "}
          <Link to="/auth/sign-up" className="font-semibold text-indigo-600">
            Create your LiveUIN account
          </Link>
        </span>
      }
    >
      <button
        type="button"
        onClick={() => void navigate({ to: "/welcome", replace: true })}
        className="mb-2 inline-flex items-center rounded-full px-1 py-2 text-sm font-semibold text-slate-600 transition hover:text-slate-900"
      >
        Back
      </button>
      <form noValidate onSubmit={submit} aria-busy={busy} className="min-w-0 max-w-full space-y-4">
        <Field label="Email">
          <input
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.sg"
              className="w-full min-w-0 h-12 rounded-2xl border border-slate-200 bg-white px-4 text-base text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/40 focus:border-indigo-400"
          />
        </Field>

        <Field
          label="Password"
          right={
            <Link to="/auth/forgot-password" className="text-xs text-indigo-600 font-semibold">
              Forgot?
            </Link>
          }
        >
          <div className="relative">
            <input
              type={show ? "text" : "password"}
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full min-w-0 h-12 rounded-2xl border border-slate-200 bg-white px-4 pr-11 text-base text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/40 focus:border-indigo-400"
            />
            <button
              type="button"
              onClick={() => setShow((s) => !s)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
              aria-label={show ? "Hide password" : "Show password"}
            >
              {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </Field>

        {pendingDeletion && accountState === null ? (
          <div role="status" className="rounded-2xl border border-amber-200 bg-amber-50 p-3 text-xs leading-5 text-amber-900">
            {pendingDeletionMessage(pendingDeletion.cancelUntil)}
            <Link
              to="/auth/cancel-deletion"
              className="mt-2 block rounded-full bg-slate-900 px-4 py-2.5 text-center text-sm font-semibold text-white"
            >
              Cancel deletion
            </Link>
          </div>
        ) : null}

        {accountState === "deletion_pending" ? (
          <div role="alert" className="rounded-2xl border border-amber-200 bg-amber-50 p-3 text-xs leading-5 text-amber-900">
            Your account is scheduled for deletion.
            <Link
              to="/auth/cancel-deletion"
              className="mt-2 block rounded-full bg-slate-900 px-4 py-2.5 text-center text-sm font-semibold text-white"
            >
              Cancel deletion
            </Link>
            <a href={buildSupportMailto("My LiveUIN account", "I can't sign in to my LiveUIN account.")} className="mt-2 block text-center font-semibold text-indigo-600">
              If you didn't ask for this, contact support
            </a>
          </div>
        ) : null}

        {err ? <AuthFeedback message={err} /> : null}

        {accountState === "email_unverified" ? (
          <button
            type="button"
            onClick={() => void resumeVerification()}
            disabled={busy}
            className="w-full rounded-2xl border border-indigo-200 bg-white py-3 text-sm font-semibold text-indigo-600 disabled:opacity-70"
          >
            Send a new verification code
          </button>
        ) : null}

        <button
          type="submit"
          disabled={busy || socialBusy !== null}
          className="w-full min-w-0 h-13 py-3.5 rounded-2xl bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-sora font-semibold text-base shadow-lg shadow-indigo-500/20 active:scale-[0.99] transition disabled:opacity-70 flex items-center justify-center gap-2"
        >
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
          {busy ? "Signing in…" : "Sign in"}
        </button>

        {isProviderVisible("apple") || isProviderVisible("google") ? (
          <div className="space-y-3 pt-2">
            <div className="flex items-center gap-3 text-xs font-semibold uppercase tracking-wide text-slate-400">
              <span className="h-px flex-1 bg-slate-200" />
              <span>Or continue with</span>
              <span className="h-px flex-1 bg-slate-200" />
            </div>
            {isProviderVisible("apple") ? (
              <button
                type="button"
                onClick={() => void continueWithProvider("apple")}
                disabled={busy || socialBusy !== null}
                className="flex h-12 w-full min-w-0 items-center justify-center rounded-2xl border border-slate-200 bg-slate-950 px-4 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:opacity-70"
              >
                {socialBusy === "apple" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Continue with Apple
              </button>
            ) : null}
            {isProviderVisible("google") ? (
              <button
                type="button"
                onClick={() => void continueWithProvider("google")}
                disabled={busy || socialBusy !== null}
                className="flex h-12 w-full min-w-0 items-center justify-center rounded-2xl border border-slate-200 bg-white px-4 text-sm font-semibold text-slate-900 transition hover:bg-slate-50 disabled:opacity-70"
              >
                {socialBusy === "google" ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Continue with Google
              </button>
            ) : null}
          </div>
        ) : null}

      </form>
    </AuthShell>
  );
}

function Field({ label, right, children }: { label: string; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <label className="block">
      <div className="mb-1.5 flex min-w-0 items-center justify-between gap-2">
        <span className="text-xs font-semibold text-slate-700 uppercase tracking-wide">{label}</span>
        {right ? <span className="shrink-0">{right}</span> : null}
      </div>
      {children}
    </label>
  );
}
