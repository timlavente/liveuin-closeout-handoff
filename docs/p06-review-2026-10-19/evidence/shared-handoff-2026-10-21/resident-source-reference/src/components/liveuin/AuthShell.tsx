import type { ReactNode } from "react";
import { Languages, ChevronDown } from "lucide-react";
import { useLanguage, LANGUAGES, type Language } from "@/lib/language-context";
import { useState } from "react";
import liveuinWordmark from "@/assets/liveuin-wordmark-light.png";

export function AuthShell({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <div data-auth-shell className="min-h-[var(--liveuin-app-height,100dvh)] w-full max-w-full overflow-hidden bg-[#F8F7FF]">
      <div data-auth-layout data-native-scroll className="relative flex min-h-[var(--liveuin-app-height,100dvh)] w-full max-w-full flex-col overflow-x-hidden overflow-y-auto bg-[#F8F7FF]">
        {/* Navy top */}
        <div
          className="relative shrink-0 max-w-full overflow-hidden rounded-b-[36px] bg-[#0B1222] px-6 pb-10 text-white sm:px-7"
          style={{
            paddingTop: "max(4.75rem, calc(env(safe-area-inset-top, 0px) + 3rem))",
            paddingLeft: "max(1.5rem, env(safe-area-inset-left))",
            paddingRight: "max(1.5rem, env(safe-area-inset-right))",
          }}
        >
          <div className="mb-6 flex min-w-0 items-center justify-between gap-2">
            <div className="flex min-w-0 items-center gap-2">
              <img src={liveuinWordmark} alt="LiveUIN" className="h-8 w-auto" />
            </div>
            <OnboardingLanguageChip />
          </div>
          <h1 className="max-w-full break-words font-sora text-[1.75rem] font-semibold leading-tight sm:text-3xl">
            {title}
          </h1>
          {subtitle ? (
            <p className="mt-2 max-w-full break-words text-sm leading-relaxed text-white/70">{subtitle}</p>
          ) : null}
        </div>

        <div
          className="min-w-0 flex-[1_0_auto] px-6 pb-6 pt-6"
          style={{
            paddingLeft: "max(1.5rem, env(safe-area-inset-left))",
            paddingRight: "max(1.5rem, env(safe-area-inset-right))",
          }}
        >
          {children}
        </div>

        {footer ? (
          <div
            className="shrink-0 min-w-0 overflow-hidden border-t border-slate-200/60 bg-white/60 px-6 pb-6 pt-3 text-center text-sm backdrop-blur-sm"
            style={{
              paddingBottom: "max(1.5rem, env(safe-area-inset-bottom))",
              paddingLeft: "max(1.5rem, env(safe-area-inset-left))",
              paddingRight: "max(1.5rem, env(safe-area-inset-right))",
            }}
          >
            {footer}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function OnboardingLanguageChip() {
  const { language, setLanguage } = useLanguage();
  const [open, setOpen] = useState(false);
  const supported = LANGUAGES.filter((l) => l.supported);
  const pick = (l: Language) => {
    if (l.supported) setLanguage(l);
    setOpen(false);
  };
  return (
    <div className="relative min-w-0 shrink-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex max-w-[8.5rem] items-center gap-1.5 rounded-full border border-white/15 bg-white/10 px-2.5 py-1.5 transition-colors hover:bg-white/15 active:scale-95"
      >
        <Languages className="w-3.5 h-3.5 text-white/70" strokeWidth={2.5} />
        <span className="min-w-0 truncate text-[11px] font-semibold tracking-wide">{language.native}</span>
        <ChevronDown className="w-3 h-3 text-white/60" strokeWidth={2.5} />
      </button>
      {open ? (
        <>
          <button
            aria-label="Close"
            className="fixed inset-0 z-10"
            onClick={() => setOpen(false)}
          />
          <div className="absolute right-0 top-full mt-2 w-56 bg-white rounded-2xl border border-slate-200 shadow-xl z-20 p-1.5 max-h-72 overflow-y-auto">
            <p className="px-2 py-1.5 text-[10px] font-bold uppercase tracking-widest text-slate-400">Available now</p>
            {supported.map((l) => (
              <button
                key={l.code}
                onClick={() => pick(l)}
                className={`w-full text-left px-2.5 py-2 rounded-lg text-sm hover:bg-slate-50 ${
                  l.code === language.code ? "bg-indigo-50 text-indigo-700 font-semibold" : "text-slate-800"
                }`}
              >
                {l.native} <span className="text-[11px] text-slate-400">· {l.name}</span>
              </button>
            ))}
          </div>
        </>
      ) : null}
    </div>
  );
}
