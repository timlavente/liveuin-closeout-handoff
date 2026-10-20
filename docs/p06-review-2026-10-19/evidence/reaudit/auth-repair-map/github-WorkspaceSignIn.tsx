import { type FormEvent, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

type WorkspaceRole = "host" | "partner" | "connect";

type RoleConfig = {
  label: string;
  identityRole: string;
  purpose: "operator_portal" | "connect_admin";
  surface: string;
  workspaceLabel: string;
};

const ROLE_CONFIG: Record<WorkspaceRole, RoleConfig> = {
  host: {
    label: "Host",
    identityRole: "landlord",
    purpose: "operator_portal",
    surface: "host_workspace",
    workspaceLabel: "Host workspace",
  },
  partner: {
    label: "Partner",
    identityRole: "agent",
    purpose: "connect_admin",
    surface: "partner_workspace",
    workspaceLabel: "Partner workspace",
  },
  connect: {
    label: "Connect admin",
    identityRole: "connector_admin",
    purpose: "connect_admin",
    surface: "connect_workspace",
    workspaceLabel: "Connect workspace",
  },
};

const safeReturnTo = (value: string) => {
  if (!value || value.startsWith("//") || !value.startsWith("/")) return "/";
  return value;
};

export default function WorkspaceSignIn({ role }: { role: WorkspaceRole }) {
  const [searchParams] = useSearchParams();
  const config = ROLE_CONFIG[role];
  const returnTo = useMemo(
    () => safeReturnTo(searchParams.get("returnTo") || searchParams.get("return_to") || `/${role}`),
    [role, searchParams],
  );
  const [email, setEmail] = useState("");
  const [challengeId, setChallengeId] = useState("");
  const [code, setCode] = useState("");
  const [previewCode, setPreviewCode] = useState("");
  const [status, setStatus] = useState("Use the email connected to your approved LiveUIN workspace.");
  const [busy, setBusy] = useState(false);

  const requestCode = async () => {
    const normalizedEmail = email.trim().toLowerCase();
    if (!normalizedEmail || !normalizedEmail.includes("@")) throw new Error("Enter a valid workspace email.");
    const response = await fetch("/api/ops/auth/request_code", {
      method: "POST",
      credentials: "include",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({
        email: normalizedEmail,
        ...(role === "host" ? {} : { workspace_id: "laijuzhu", liveuin_role: config.identityRole }),
        purpose: config.purpose,
        surface: config.surface,
        return_to: returnTo,
      }),
    });
    const payload = (await response.json().catch(() => ({}))) as {
      ok?: boolean;
      detail?: string;
      challenge_id?: string;
      preview_code?: string;
    };
    if (!response.ok || payload.ok !== true || !payload.challenge_id) {
      throw new Error(payload.detail || `workspace_sign_in_unavailable_${response.status}`);
    }
    setChallengeId(payload.challenge_id);
    setPreviewCode(String(payload.preview_code || ""));
    setStatus(payload.preview_code ? "Preview code created. Verify it to continue." : "Code sent. Enter it to continue.");
  };

  const verifyCode = async () => {
    if (!challengeId.trim() || !code.trim()) throw new Error("Enter the verification code.");
    const response = await fetch("/api/ops/auth/verify-code", {
      method: "POST",
      credentials: "include",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({
        challenge_id: challengeId.trim(),
        verification_code: code.trim(),
        ...(role === "host" ? {} : { workspace_id: "laijuzhu" }),
        return_to: returnTo,
      }),
    });
    const payload = (await response.json().catch(() => ({}))) as { ok?: boolean; detail?: string };
    if (!response.ok || payload.ok !== true) throw new Error(payload.detail || `workspace_sign_in_failed_${response.status}`);
    setStatus("Signed session created. Opening your workspace…");
    window.setTimeout(() => window.location.assign(returnTo), 150);
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    try {
      if (!challengeId) await requestCode();
      else await verifyCode();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Workspace sign-in failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="min-h-screen bg-slate-950 px-6 py-10 text-slate-100">
      <section className="mx-auto flex min-h-[calc(100vh-5rem)] w-full max-w-2xl items-center justify-center">
        <form onSubmit={submit} className="w-full rounded-[32px] border border-white/10 bg-white p-8 text-slate-950 shadow-2xl sm:p-12">
          <p className="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">LiveUIN Identity</p>
          <h1 className="mt-4 text-3xl font-semibold tracking-tight">Sign in to your {config.label} workspace</h1>
          <p className="mt-3 text-sm leading-6 text-slate-600">We’ll confirm your access before opening this workspace.</p>
          <div className="mt-6 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
            <strong>{config.workspaceLabel}</strong><span className="mx-2 text-slate-400">·</span>Role: {config.label}
          </div>
          <label className="mt-8 block text-sm font-medium">Work email<input value={email} onChange={(event) => setEmail(event.target.value)} className="mt-2 h-11 w-full rounded-xl border border-slate-300 px-3 outline-none focus:border-blue-500" autoComplete="username" placeholder="name@company.com" disabled={Boolean(challengeId)} /></label>
          {challengeId ? <label className="mt-4 block text-sm font-medium">Verification code<input value={code} onChange={(event) => setCode(event.target.value)} className="mt-2 h-11 w-full rounded-xl border border-slate-300 px-3 outline-none focus:border-blue-500" inputMode="numeric" autoComplete="one-time-code" maxLength={6} /></label> : null}
          {previewCode ? <div className="mt-4 rounded-xl border border-cyan-200 bg-cyan-50 px-4 py-3 text-sm text-cyan-950"><p className="font-semibold">Preview-only verification code</p><p className="mt-1 font-mono text-2xl tracking-[0.3em]">{previewCode}</p></div> : null}
          <button type="submit" disabled={busy} className="mt-7 h-12 w-full rounded-xl bg-slate-950 px-4 text-sm font-semibold text-white disabled:cursor-wait disabled:opacity-60">{busy ? "Checking your access…" : challengeId ? "Verify and open workspace" : "Send verification code"}</button>
          <p role="status" className="mt-4 min-h-12 rounded-xl bg-slate-100 px-4 py-3 text-sm text-slate-700">{status}</p>
          <a className="mt-5 inline-flex text-sm font-medium text-slate-600 underline" href="/">Return to LiveUIN</a>
        </form>
      </section>
    </main>
  );
}
