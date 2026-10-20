import type { AuthUser } from "./auth-context";
import { resolveCanonicalAuthContinuation } from "./residentProfileAuthorization";

export type ResidentAuthenticatedContinuation = ReturnType<typeof resolveCanonicalAuthContinuation>;

export function resolveAuthenticatedContinuation(
  user: Pick<AuthUser, "roles" | "profileState" | "nextAction" | "status">,
): ResidentAuthenticatedContinuation {
  return resolveCanonicalAuthContinuation(user);
}
