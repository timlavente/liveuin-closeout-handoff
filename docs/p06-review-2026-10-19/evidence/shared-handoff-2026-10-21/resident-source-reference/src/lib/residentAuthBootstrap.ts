import type { QueryClient } from "@tanstack/react-query";
import type { ResidentSessionBootstrap } from "@/lib/residentAppRuntime";

const profileLoadFailure = "Your sign-in was accepted, but LiveUIN could not load your profile. Please try again.";

/** Wait for the canonical profile before allowing password sign-in to navigate. */
export async function awaitResidentAuthBootstrap(queryClient: QueryClient): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: ["resident-session-bootstrap"] }, { throwOnError: true });
    const bootstrap = queryClient.getQueryData<ResidentSessionBootstrap>(["resident-session-bootstrap"]);
    if (
      !bootstrap ||
      bootstrap.sessionState !== "resolved" ||
      bootstrap.authRequired !== false ||
      bootstrap.previewMode !== false
    ) {
      throw new Error(profileLoadFailure);
    }
  };

  try {
    await Promise.race([
      refresh(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(profileLoadFailure)), 20_000);
      }),
    ]);
  } catch {
    throw new Error(profileLoadFailure);
  } finally {
    clearTimeout(timer);
  }
}
