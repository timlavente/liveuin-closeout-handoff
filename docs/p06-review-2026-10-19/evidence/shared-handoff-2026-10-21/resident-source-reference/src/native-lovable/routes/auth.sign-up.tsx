import { createFileRoute, Link, useLocation, useNavigate } from "@/native-lovable/router";
import { useQuery } from "@tanstack/react-query";
import { useState, type FormEvent, type ReactNode } from "react";
import { AuthShell } from "@/components/liveuin/AuthShell";
import { CompleteProfileForm } from "@/native-lovable/components/CompleteProfileForm";
import { describeAuthError, publicTermsVersion, useAuth } from "@/lib/auth-context";
import { ResidentApiError } from "@/lib/residentNativeHttp";
import { PASSWORD_RULES_MESSAGE, passwordMeetsRules } from "@/lib/residentPasswordRules";
import { useLanguage } from "@/lib/language-context";
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

export const Route = createFileRoute("/auth/sign-up")({
  head: () => ({ meta: [{ title: "Create your LiveUIN account" }] }),
  component: SignUp,
});

type Step = "details" | "verify" | "profile";

function SignUp() {
  const {
    signInWithProvider,
    startRegistration,
    verifyRegistration,
    resendRegistration,
    getOnboardingStatus,
    completeProfile,
    completeTenantOnboarding,
  } = useAuth();
  const { language } = useLanguage();
  const { switchProfile } = useProfile();
  const navigate = useNavigate();
  // Arriving from sign-in after `email_unverified`: a fresh code was sent and sign-in handed over the registration id.
  const resumeParams = new URLSearchParams(useLocation().search);
  const requestedReturnTo = resumeParams.get("returnTo");
  const resumeRegistrationId = /^reg_[A-Za-z0-9]+$/.test(resumeParams.get("resume") || "") ? String(resumeParams.get("resume")) : "";
  const [step, setStep] = useState<Step>(resumeRegistrationId ? "verify" : "details");
  const [email, setEmail] = useState(resumeRegistrationId ? String(resumeParams.get("email") || "") : "");
  const [password, setPassword] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [registrationId, setRegistrationId] = useState(resumeRegistrationId);
  const [verificationExpiry, setVerificationExpiry] = useState(0);
  const [showPassword, setShowPassword] = useState(false);
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [socialBusy, setSocialBusy] = useState<SocialProvider | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [errCode, setErrCode] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
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

  const run = async (action: () => Promise<void>) => {
    setBusy(true);
    setErr(null);
    setErrCode("");
    setNotice(null);
    try {
      await action();
    } catch (cause) {
      const code = cause instanceof ResidentApiError ? cause.errorCode || "" : "";
      setErrCode(code);
      // The code cannot be used any more: go back and start again, which sends a fresh one.
      if (step === "verify" && ["verification_locked", "verification_expired", "registration_not_found"].includes(code)) {
        setStep("details");
        setVerificationCode("");
        setRegistrationId("");
      }
      setErr(describeAuthError(cause, "LiveUIN could not complete that request. Please try again later."));
    } finally {
      setBusy(false);
    }
  };

  const start = async (event: FormEvent) => {
    event.preventDefault();
    await run(async () => {
      if (!termsAccepted) {
        setErr("Accept the LiveUIN terms to continue.");
        return;
      }
      if (!passwordMeetsRules(password)) {
        setErr(PASSWORD_RULES_MESSAGE);
        return;
      }
      if (!publicTermsVersion) {
        setErr("Account creation is temporarily unavailable. Please try again later.");
        return;
      }
      const result = await startRegistration({
        email,
        password,
        acceptedTermsVersion: publicTermsVersion,
        locale: language.code,
      });
      setRegistrationId(result.registrationId);
      setVerificationExpiry(result.expiresAt);
      setStep("verify");
    });
  };

  const verify = async (event: FormEvent) => {
    event.preventDefault();
    await run(async () => {
      await verifyRegistration(registrationId, verificationCode, email);
      const status = await getOnboardingStatus();
      if (status.next_action === "tenant_home" || status.profile_state === "tenant_active") {
        await navigate({ to: "/tenant/home" });
        return;
      }
      setStep("profile");
    });
  };

  const resend = async () => {
    await run(async () => {
      await resendRegistration(registrationId, email);
      setNotice("A new verification code has been sent.");
    });
  };

  const finishProfile = async (displayName: string) => {
    await run(async () => {
      await completeProfile(displayName, language.code);
      await completeTenantOnboarding();
      await navigate({ to: "/tenant/home" });
    });
  };

  const continueAfterSocialAuth = async (user: Awaited<ReturnType<typeof signInWithProvider>>) => {
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

  const continueWithProvider = async (provider: SocialProvider) => {
    setErr(null);
    setSocialBusy(provider);
    try {
      const user = await signInWithProvider(provider);
      await continueAfterSocialAuth(user);
    } catch (error) {
      if (!isSocialAuthCancellation(error)) {
        const code = socialAuthErrorCode(error);
        setErr(
          code === "provider_not_ready"
            ? "This sign-in method is temporarily unavailable. Please try again later."
            : describeAuthError(error, "This sign-in method could not be completed. Please try again later."),
        );
      }
    } finally {
      setSocialBusy(null);
    }
  };

  const title =
    step === "details" ? "Create your LiveUIN account" : step === "verify" ? "Check your email" : "Complete your LiveUIN profile";
  const subtitle =
    step === "details"
      ? "One account for your home, your work, and every move in between."
      : step === "verify"
        ? `Enter the verification code sent to ${email}.`
        : "Add your name to continue with your LiveUIN account.";

  return (
    <AuthShell
      title={title}
      subtitle={subtitle}
      footer={
        <span className="text-slate-600">
          I already have an account?{" "}
          <Link to="/auth/sign-in" className="font-semibold text-indigo-600">
            Sign in
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
      {step === "details" ? (
        <form onSubmit={start} className="min-w-0 max-w-full space-y-4">
          <Field label="Email">
            <input
              type="email"
              autoComplete="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="you@example.sg"
              className="h-12 w-full min-w-0 rounded-2xl border border-slate-200 bg-white px-4 text-base text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/40"
            />
          </Field>

          <Field label="Password">
            <div className="relative min-w-0">
              <input
                type={showPassword ? "text" : "password"}
                autoComplete="new-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="12+ characters, a letter and a number"
                className="h-12 w-full min-w-0 rounded-2xl border border-slate-200 bg-white px-4 pr-11 text-base text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/40"
              />
              <button
                type="button"
                onClick={() => setShowPassword((value) => !value)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </Field>

          <label className="flex min-w-0 items-start gap-3 text-sm leading-5 text-slate-600">
            <input
              type="checkbox"
              checked={termsAccepted}
              onChange={(event) => setTermsAccepted(event.target.checked)}
              className="mt-1 h-4 w-4 shrink-0 accent-indigo-600"
            />
            <span>
              I agree to the LiveUIN{" "}
              <a href="https://liveuin.com/legal/terms" target="_blank" rel="noopener noreferrer" className="font-semibold text-indigo-600 underline">
                terms
              </a>{" "}
              and{" "}
              <a href="https://liveuin.com/legal/privacy" target="_blank" rel="noopener noreferrer" className="font-semibold text-indigo-600 underline">
                privacy policy
              </a>
              .
            </span>
          </label>

          <PrimaryButton busy={busy} disabled={busy || socialBusy !== null}>Create account</PrimaryButton>

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
      ) : null}

      {step === "verify" ? (
        <form onSubmit={verify} className="min-w-0 max-w-full space-y-4">
          <Field label="Verification code">
            <input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              value={verificationCode}
              onChange={(event) => setVerificationCode(event.target.value.replace(/\D/g, "").slice(0, 12))}
              placeholder="Enter your code"
              className="h-12 w-full min-w-0 rounded-2xl border border-slate-200 bg-white px-4 text-base tracking-[0.24em] text-slate-900 placeholder:tracking-normal placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/40"
            />
          </Field>
          <p className="text-sm leading-6 text-slate-500">
            The code expires soon. {verificationExpiry > 0 ? "Request a new code if it has expired." : "Request a new code if needed."}
          </p>
          {notice ? <p className="text-sm leading-5 text-emerald-700">{notice}</p> : null}
          <PrimaryButton busy={busy}>Verify email</PrimaryButton>
          <button type="button" onClick={resend} disabled={busy} className="w-full min-w-0 py-2 text-sm font-semibold text-indigo-600 disabled:opacity-60">
            Resend code
          </button>
        </form>
      ) : null}

      {step === "profile" ? (
        <CompleteProfileForm busy={busy} onComplete={finishProfile} />
      ) : null}

      {err ? <p className="mt-4 max-w-full break-words text-xs leading-5 text-red-600">{err}</p> : null}
      {errCode === "duplicate_email" || errCode === "verification_not_pending" ? (
        <Link to="/auth/sign-in" className="mt-3 block rounded-2xl border border-indigo-200 bg-white py-3 text-center text-sm font-semibold text-indigo-600">
          Sign in instead
        </Link>
      ) : null}
    </AuthShell>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block min-w-0">
      <span className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-slate-700">{label}</span>
      {children}
    </label>
  );
}

function PrimaryButton({ busy, disabled = busy, children }: { busy: boolean; disabled?: boolean; children: ReactNode }) {
  return (
    <button
      type="submit"
      disabled={disabled}
      className="flex h-13 w-full min-w-0 items-center justify-center gap-2 rounded-2xl bg-gradient-to-r from-indigo-600 to-purple-600 py-3.5 text-base font-semibold text-white shadow-lg shadow-indigo-500/20 transition active:scale-[0.99] disabled:opacity-70"
    >
      {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
      {children}
    </button>
  );
}
