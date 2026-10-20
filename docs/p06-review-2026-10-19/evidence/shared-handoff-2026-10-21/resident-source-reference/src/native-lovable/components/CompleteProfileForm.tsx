import { useState, type FormEvent } from "react";
import { Loader2 } from "lucide-react";

export function CompleteProfileForm({
  busy,
  onComplete,
  submitLabel = "Continue to Tenant",
}: {
  busy: boolean;
  onComplete: (displayName: string) => Promise<void>;
  submitLabel?: string;
}) {
  const [displayName, setDisplayName] = useState("");

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    await onComplete(displayName);
  };

  return (
    <form onSubmit={submit} className="min-w-0 max-w-full space-y-4">
      <label className="block min-w-0">
        <span className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-slate-700">Display name</span>
        <input
          type="text"
          autoComplete="name"
          value={displayName}
          onChange={(event) => setDisplayName(event.target.value)}
          placeholder="Your name"
          className="h-12 w-full min-w-0 rounded-2xl border border-slate-200 bg-white px-4 text-base text-slate-900 placeholder:text-slate-400 focus:border-indigo-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/40"
        />
      </label>
      <p className="text-sm leading-6 text-slate-500">Add your name to continue with your LiveUIN account.</p>
      <button
        type="submit"
        disabled={busy}
        className="flex h-13 w-full min-w-0 items-center justify-center gap-2 rounded-2xl bg-gradient-to-r from-indigo-600 to-purple-600 py-3.5 text-base font-semibold text-white shadow-lg shadow-indigo-500/20 transition active:scale-[0.99] disabled:opacity-70"
      >
        {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
        {submitLabel}
      </button>
    </form>
  );
}
