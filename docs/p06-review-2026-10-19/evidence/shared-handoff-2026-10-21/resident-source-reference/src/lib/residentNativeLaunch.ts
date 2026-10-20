import { isNativeRuntimeShell } from "@/lib/runtimeHost";

let launchContextResolved = false;
let launchContextWaiters: Array<() => void> = [];

function flushLaunchContextWaiters() {
  if (!launchContextWaiters.length) return;
  const pending = launchContextWaiters;
  launchContextWaiters = [];
  for (const resolve of pending) {
    resolve();
  }
}

export function markResidentNativeLaunchContextReady() {
  launchContextResolved = true;
  flushLaunchContextWaiters();
}

export function resetResidentNativeLaunchContextForTests() {
  launchContextResolved = false;
  launchContextWaiters = [];
}

export async function waitForResidentNativeLaunchContext(timeoutMs = 1500) {
  if (launchContextResolved) return;
  if (!isNativeRuntimeShell()) {
    markResidentNativeLaunchContextReady();
    return;
  }

  await new Promise<void>((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      if (timer) window.clearTimeout(timer);
      resolve();
    };
    const timer =
      typeof window !== "undefined" && timeoutMs > 0
        ? window.setTimeout(() => {
            markResidentNativeLaunchContextReady();
          }, timeoutMs)
        : 0;

    launchContextWaiters.push(finish);
  });
}
