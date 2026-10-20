import { useEffect, useState, type ReactNode } from "react";
import { isNativeRuntimeShell } from "@/lib/runtimeHost";
import { waitForResidentNativeLaunchContext } from "@/lib/residentNativeLaunch";

export function ResidentNativeRouteGate({
  fallback,
  children,
}: {
  fallback: ReactNode;
  children: ReactNode;
}) {
  const [ready, setReady] = useState(() => !isNativeRuntimeShell());

  useEffect(() => {
    if (!isNativeRuntimeShell()) {
      setReady(true);
      return;
    }

    let cancelled = false;

    void waitForResidentNativeLaunchContext().then(() => {
      if (!cancelled) {
        setReady(true);
      }
    });

    return () => {
      cancelled = true;
    };
  }, []);

  if (!ready) {
    return <>{fallback}</>;
  }

  return <>{children}</>;
}
