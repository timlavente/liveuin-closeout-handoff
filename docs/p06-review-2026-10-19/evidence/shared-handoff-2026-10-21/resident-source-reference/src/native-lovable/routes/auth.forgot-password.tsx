import { createFileRoute, Link } from "@/native-lovable/router";
import { useState, type FormEvent } from "react";
import { AuthShell } from "@/components/liveuin/AuthShell";
import { AuthFeedback } from "@/components/liveuin/AuthFeedback";
import { CheckCircle2, Loader2, Mail } from "lucide-react";
import { describeAuthError, useAuth } from "@/lib/auth-context";
import { buildSupportMailto } from "@/lib/residentSupportContact";

export const Route = createFileRoute("/auth/forgot-password")({
  head: () => ({ meta: [{ title: "Reset your password — LiveUIN" }] }),
  component: ForgotPassword,
});

type Step = "email" | "code" | "password" | "done";

const inputClass =
  "mt-1.5 w-full h-12 rounded-2xl border border-slate-200 bg-white px-4 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/40 focus:border-indigo-400";
const submitClass =
  "w-full py-3.5 rounded-2xl bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-sora font-semibold text-base shadow-lg shadow-indigo-500/20 disabled:opacity-70 flex items-center justify-center gap-2";

/**
 * Password recovery through LiveUIN Core identity:
 * POST /api/core/identity/password-resets/request -> /{reset_id}/verify -> /complete.
 * If Core cannot start recovery (e.g. the route is not served yet), the screen says so and offers
 * a prefilled email to support instead of pretending a reset link was sent.
 */
function ForgotPassword() {
  const { requestPasswordReset, verifyPasswordReset, completePasswordReset } = useAuth();
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [resetId, setResetId] = useState("");
  const [resetToken, setResetToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (work: () => Promise<void>, fallback: string) => {
    if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    setBusy(true);
    setError(null);
    try {
      await work();
    } catch (cause) {
      setError(describeAuthError(cause, fallback));
    } finally {
      setBusy(false);
    }
  };

  const submitEmail = (e: FormEvent) => {
    e.preventDefault();
    if (!email.trim()) {
      setError("Enter the email on your LiveUIN account.");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      setError("Enter a valid email address.");
      return;
    }
    void run(async () => {
      const result = await requestPasswordReset(email);
      setResetId(result.resetId);
      setStep("code");
    }, "We couldn't start password recovery. Please try again later.");
  };

  const submitCode = (e: FormEvent) => {
    e.preventDefault();
    if (!code.trim()) {
      setError("Enter the recovery code from your email.");
      return;
    }
    void run(async () => {
      const result = await verifyPasswordReset(resetId, code);
      setResetToken(result.resetToken);
      setStep("password");
    }, "That recovery code is not valid. Check it and try again.");
  };

  const submitPassword = (e: FormEvent) => {
    e.preventDefault();
    if (!newPassword) {
      setError("Enter your new password.");
      return;
    }
    void run(async () => {
      await completePasswordReset(resetToken, newPassword);
      setStep("done");
    }, "We couldn't update your password. Please try again later.");
  };

  const supportHref = buildSupportMailto(
    "Help resetting my LiveUIN password",
    `I can't reset my LiveUIN password from the iPhone app.\n\nAccount email: ${email.trim() || "(the address I am sending from)"}`,
  );

  return (
    <AuthShell
      title="Reset your password"
      subtitle={
        step === "code"
          ? "Enter the recovery code from your email."
          : step === "password"
            ? "Choose a new password for your LiveUIN account."
            : "Enter the email on your LiveUIN account and we'll send a recovery code."
      }
      footer={
        <span className="text-slate-600">
          Remembered it?{" "}
          <Link to="/auth/sign-in" className="text-indigo-600 font-semibold">
            Back to sign in
          </Link>
        </span>
      }
    >
      {step === "done" ? (
        <div className="pt-4 text-center">
          <div className="mx-auto w-14 h-14 rounded-full bg-emerald-100 flex items-center justify-center mb-3">
            <CheckCircle2 className="w-7 h-7 text-emerald-600" />
          </div>
          <AuthFeedback tone="status" message="Password updated" />
          <p className="text-sm text-slate-500 mt-1.5 leading-relaxed">You can now sign in with your new password.</p>
          <Link to="/auth/sign-in" className="mt-4 inline-block font-semibold text-indigo-600">
            Go to sign in
          </Link>
        </div>
      ) : step === "password" ? (
        <form noValidate onSubmit={submitPassword} aria-busy={busy} className="space-y-4">
          <AuthFeedback tone="status" message="Code verified. Choose your new password." />
          <label className="block">
            <span className="text-xs font-semibold text-slate-700 uppercase tracking-wide">New password</span>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              autoComplete="new-password"
              className={inputClass}
            />
          </label>
          <button type="submit" disabled={busy} className={submitClass}>
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
            {busy ? "Saving password…" : "Save new password"}
          </button>
        </form>
      ) : step === "code" ? (
        <form noValidate onSubmit={submitCode} aria-busy={busy} className="space-y-4">
          <AuthFeedback tone="status" message="Recovery requested. If this email belongs to a LiveUIN account, check your inbox for a code." />
          <label className="block">
            <span className="text-xs font-semibold text-slate-700 uppercase tracking-wide">Recovery code</span>
            <input
              inputMode="numeric"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoComplete="one-time-code"
              className={inputClass}
            />
          </label>
          <button type="submit" disabled={busy} className={submitClass}>
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
            {busy ? "Verifying code…" : "Verify code"}
          </button>
        </form>
      ) : (
        <form noValidate onSubmit={submitEmail} aria-busy={busy} className="space-y-4">
          <label className="block">
            <span className="text-xs font-semibold text-slate-700 uppercase tracking-wide">Email</span>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              autoComplete="email"
              className={inputClass}
            />
          </label>
          <button type="submit" disabled={busy} className={submitClass}>
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
            {busy ? "Sending recovery code…" : "Send recovery code"}
          </button>
        </form>
      )}

      {error ? (
        <div className="mt-4 rounded-2xl bg-amber-50 p-3 text-xs leading-5 text-amber-900">
          <AuthFeedback message={error} />
          <p className="mt-1">If this keeps happening, contact support and we'll help you get back in.</p>
          <a href={supportHref} className="mt-2 inline-flex items-center gap-1.5 font-semibold text-indigo-700">
            <Mail className="h-3.5 w-3.5" /> Contact support
          </a>
        </div>
      ) : null}

      {step === "code" || step === "password" ? (
        <button
          type="button"
          disabled={busy}
          className="mt-4 w-full rounded-2xl border border-slate-200 px-4 py-3 text-sm font-semibold text-indigo-700 disabled:opacity-70"
          onClick={() => {
            setResetId("");
            setResetToken("");
            setCode("");
            setNewPassword("");
            setError(null);
            setStep("email");
          }}
        >
          Start a new recovery request
        </button>
      ) : null}
    </AuthShell>
  );
}
