import { createFileRoute, Link } from "@/native-lovable/router";
import { useState, type FormEvent } from "react";
import { CheckCircle2, Eye, EyeOff, Loader2 } from "lucide-react";
import { AuthShell } from "@/components/liveuin/AuthShell";
import { cancelAccountDeletion } from "@/lib/residentAccountDeletion";
import { pendingDeletionMessage, readPendingAccountDeletion } from "@/lib/residentPendingDeletion";

export const Route = createFileRoute("/auth/cancel-deletion")({
  head: () => ({ meta: [{ title: "Cancel account deletion — LiveUIN" }] }),
  component: CancelDeletion,
});

const inputClass =
  "w-full min-w-0 h-12 rounded-2xl border border-slate-200 bg-white px-4 text-base text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/40 focus:border-indigo-400";

/**
 * Cancels a pending account deletion with email + password and no session
 * (`POST /api/core/identity/account-deletion/cancel`). Sessions are revoked once a deletion is
 * confirmed, so this is the only way back in during the 14-day window.
 */
function CancelDeletion() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [pending] = useState(() => readPendingAccountDeletion());

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    if (!email.trim() || !password) {
      setError("Enter your email and password.");
      return;
    }
    setBusy(true);
    try {
      await cancelAccountDeletion({ email, password });
      setPassword("");
      setDone(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "We couldn't cancel the deletion right now. Please try again later.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell
      title="Cancel account deletion"
      subtitle="Enter your email and password to keep your LiveUIN account."
      footer={
        <span className="text-slate-600">
          <Link to="/auth/sign-in" className="font-semibold text-indigo-600">
            Back to sign in
          </Link>
        </span>
      }
    >
      {done ? (
        <div role="status" className="rounded-2xl border border-emerald-100 bg-emerald-50/70 p-4">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600" />
            <div>
              <p className="text-sm font-semibold text-slate-900">Deletion cancelled. Sign in to continue.</p>
              <Link
                to="/auth/sign-in"
                replace
                className="mt-3 block rounded-2xl bg-gradient-to-r from-indigo-600 to-purple-600 py-3 text-center text-sm font-semibold text-white"
              >
                Sign in
              </Link>
            </div>
          </div>
        </div>
      ) : (
        <form onSubmit={submit} className="min-w-0 max-w-full space-y-4">
          {pending ? <p className="text-xs leading-5 text-slate-600">{pendingDeletionMessage(pending.cancelUntil)}</p> : null}
          <label className="block">
            <span className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-slate-700">Email</span>
            <input
              type="email"
              autoComplete="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="you@example.sg"
              className={inputClass}
            />
          </label>
          <label className="block">
            <span className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-slate-700">Password</span>
            <div className="relative">
              <input
                type={show ? "text" : "password"}
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="••••••••"
                className={`${inputClass} pr-11`}
              />
              <button
                type="button"
                onClick={() => setShow((value) => !value)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
                aria-label={show ? "Hide password" : "Show password"}
              >
                {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </label>
          {error ? (
            <p role="alert" className="max-w-full break-words text-xs leading-5 text-red-600">
              {error}
            </p>
          ) : null}
          <button
            type="submit"
            disabled={busy}
            className="flex h-13 w-full min-w-0 items-center justify-center gap-2 rounded-2xl bg-gradient-to-r from-indigo-600 to-purple-600 py-3.5 text-base font-semibold text-white shadow-lg shadow-indigo-500/20 disabled:opacity-70"
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            Cancel deletion
          </button>
        </form>
      )}
    </AuthShell>
  );
}
