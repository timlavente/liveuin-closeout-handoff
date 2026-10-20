import { useEffect, useRef } from "react";

/** Keep the server's answer visible after the keyboard closes. */
export function AuthFeedback({ message, tone = "error" }: { message: string; tone?: "error" | "status" }) {
  const ref = useRef<HTMLParagraphElement>(null);
  useEffect(() => {
    ref.current?.focus({ preventScroll: true });
    ref.current?.scrollIntoView?.({ block: "nearest" });
  }, [message]);

  return (
    <p
      ref={ref}
      tabIndex={-1}
      role={tone === "error" ? "alert" : "status"}
      className={`max-w-full rounded-2xl p-3 text-sm leading-5 break-words ${tone === "error" ? "bg-red-50 text-red-700" : "bg-indigo-50 text-indigo-900"}`}
    >
      {message}
    </p>
  );
}
