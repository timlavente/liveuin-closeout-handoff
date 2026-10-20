const SESSION_HEADER_COOKIE_NAMES = [
  "LIVEUIN_WORKSPACE_ID",
  "LIVEUIN_ACTOR_ID",
  "LIVEUIN_ROLE",
  "LIVEUIN_SCOPES",
  "LIVEUIN_SESSION_ID",
  "LIVEUIN_SESSION_ISSUED_AT",
  "LIVEUIN_AUTH_METHOD",
  "LIVEUIN_SESSION_SIGNATURE",
] as const;

const SESSION_METADATA_COOKIE_NAMES = [
  "LIVEUIN_SESSION_EXPIRES_AT",
  "LIVEUIN_SESSION_CREDENTIAL_KIND",
] as const;

const SESSION_COOKIE_NAMES = [
  ...SESSION_HEADER_COOKIE_NAMES,
  ...SESSION_METADATA_COOKIE_NAMES,
] as const;

const SESSION_STORAGE_KEY = "liveuin.resident.signed-session.v1";
const RESIDENT_PROFILE_SELECTION_STORAGE_KEY = "liveuin.mobile.profile-selection.v1";

const COOKIE_TO_HEADER: Record<(typeof SESSION_HEADER_COOKIE_NAMES)[number], string> = {
  LIVEUIN_WORKSPACE_ID: "X-LiveUIN-Workspace-Id",
  LIVEUIN_ACTOR_ID: "X-LiveUIN-Actor-Id",
  LIVEUIN_ROLE: "X-LiveUIN-Role",
  LIVEUIN_SCOPES: "X-LiveUIN-Scopes",
  LIVEUIN_SESSION_ID: "X-LiveUIN-Session-Id",
  LIVEUIN_SESSION_ISSUED_AT: "X-LiveUIN-Session-Issued-At",
  LIVEUIN_AUTH_METHOD: "X-LiveUIN-Auth-Method",
  LIVEUIN_SESSION_SIGNATURE: "X-LiveUIN-Session-Signature",
};

export type ResidentSignedSession = {
  sessionId: string;
  sessionHeaders: Record<string, string>;
  expiresAt: number;
  credentialKind: string;
};

let activeResidentSignedSession: ResidentSignedSession | null = null;

function sessionExpired(expiresAt: number) {
  return Boolean(expiresAt && expiresAt <= Math.floor(Date.now() / 1000));
}

function applyCookie(name: string, value: string, expiresAt: number) {
  if (typeof document === "undefined") return;
  const maxAge = expiresAt ? Math.max(0, expiresAt - Math.floor(Date.now() / 1000)) : null;
  document.cookie = `${name}=${encodeURIComponent(value)}; path=/;${maxAge === null ? "" : ` max-age=${maxAge};`} samesite=lax`;
}

function clearCookie(name: string) {
  if (typeof document === "undefined") return;
  document.cookie = `${name}=; path=/; max-age=0; samesite=lax`;
}

function readCookie(name: string) {
  if (typeof document === "undefined") return "";
  const prefix = `${name}=`;
  const match = document.cookie
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(prefix));
  if (!match) return "";
  return decodeURIComponent(match.slice(prefix.length));
}

function writeSessionStorage(session: ResidentSignedSession | null) {
  if (typeof window === "undefined") return;
  try {
    if (!session) {
      window.localStorage.removeItem(SESSION_STORAGE_KEY);
      return;
    }
    window.localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
  } catch {
    // Native/web storage is only a client-side cache of the issued session.
  }
}

function readSessionStorage() {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<ResidentSignedSession> | null;
    if (!parsed || typeof parsed !== "object") return null;

    const sessionId = String(parsed.sessionId || "").trim();
    const expiresAt = Number(parsed.expiresAt || 0);
    const credentialKind = String(parsed.credentialKind || "liveuin_session").trim() || "liveuin_session";
    const sessionHeaders =
      parsed.sessionHeaders && typeof parsed.sessionHeaders === "object" && !Array.isArray(parsed.sessionHeaders)
        ? Object.fromEntries(
            Object.entries(parsed.sessionHeaders as Record<string, unknown>)
              .map(([key, value]) => [String(key), String(value ?? "")] as const)
              .filter((entry): entry is [string, string] => Boolean(entry[0] && entry[1])),
          )
        : {};

    if (!sessionId || !Object.keys(sessionHeaders).length) return null;

    return {
      sessionId,
      sessionHeaders: {
        ...sessionHeaders,
        "X-LiveUIN-Session-Id": sessionId,
      },
      expiresAt,
      credentialKind,
    } satisfies ResidentSignedSession;
  } catch {
    return null;
  }
}

function mirrorSessionIntoCookies(session: ResidentSignedSession) {
  applyCookie("LIVEUIN_SESSION_ID", session.sessionId, session.expiresAt);
  applyCookie("LIVEUIN_SESSION_EXPIRES_AT", String(session.expiresAt || ""), session.expiresAt);
  applyCookie("LIVEUIN_SESSION_CREDENTIAL_KIND", session.credentialKind, session.expiresAt);
  for (const [cookieName, headerName] of Object.entries(COOKIE_TO_HEADER)) {
    if (cookieName === "LIVEUIN_SESSION_ID") continue;
    const value = session.sessionHeaders[headerName];
    if (value) {
      applyCookie(cookieName, value, session.expiresAt);
    }
  }
}

function rehydrateResidentSignedSessionFromCookies() {
  const storageSession = readSessionStorage();
  if (storageSession) {
    if (sessionExpired(storageSession.expiresAt)) {
      clearResidentSignedSession();
      return null;
    }
    activeResidentSignedSession = storageSession;
    mirrorSessionIntoCookies(storageSession);
    return activeResidentSignedSession;
  }

  const sessionId = readCookie("LIVEUIN_SESSION_ID");
  if (!sessionId) return null;

  const sessionHeaders = Object.fromEntries(
    Object.entries(COOKIE_TO_HEADER)
      .map(([cookieName, headerName]) => [headerName, readCookie(cookieName)] as const)
      .filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
  const expiresAt = Number(readCookie("LIVEUIN_SESSION_EXPIRES_AT") || 0);
  const credentialKind = readCookie("LIVEUIN_SESSION_CREDENTIAL_KIND") || "liveuin_session";

  if (sessionExpired(expiresAt)) {
    clearResidentSignedSession();
    return null;
  }

  const normalizedHeaders = {
    ...sessionHeaders,
    "X-LiveUIN-Session-Id": sessionId,
  };

  activeResidentSignedSession = {
    sessionId,
    sessionHeaders: normalizedHeaders,
    expiresAt,
    credentialKind,
  };

  return activeResidentSignedSession;
}

export function clearResidentSignedSession() {
  activeResidentSignedSession = null;
  writeSessionStorage(null);
  for (const name of SESSION_COOKIE_NAMES) {
    clearCookie(name);
  }
}

export function clearResidentProfileSelection() {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(RESIDENT_PROFILE_SELECTION_STORAGE_KEY);
  } catch {
    // Profile selection is only a client-side hint.
  }
}

export function setResidentSignedSession(input: {
  sessionId: string;
  sessionHeaders: Record<string, string>;
  expiresAt?: number;
  credentialKind?: string;
}) {
  const sessionId = String(input.sessionId || "").trim();
  const sessionHeaders = Object.fromEntries(
    Object.entries(input.sessionHeaders || {}).filter((entry): entry is [string, string] => Boolean(entry[0] && entry[1])),
  );
  const expiresAt = Number(input.expiresAt || 0);
  const credentialKind = String(input.credentialKind || "liveuin_session").trim() || "liveuin_session";
  const normalizedHeaders = {
    ...sessionHeaders,
    "X-LiveUIN-Session-Id": sessionId,
  };

  if (!sessionId || !Object.keys(normalizedHeaders).length) {
    clearResidentSignedSession();
    return null;
  }

  activeResidentSignedSession = {
    sessionId,
    sessionHeaders: normalizedHeaders,
    expiresAt,
    credentialKind,
  };

  writeSessionStorage(activeResidentSignedSession);
  mirrorSessionIntoCookies(activeResidentSignedSession);

  return activeResidentSignedSession;
}

export function getResidentSignedSession() {
  if (!activeResidentSignedSession) {
    return rehydrateResidentSignedSessionFromCookies();
  }
  if (sessionExpired(activeResidentSignedSession.expiresAt)) {
    clearResidentSignedSession();
    return null;
  }
  return activeResidentSignedSession;
}

export function getResidentSignedSessionHeaders() {
  return getResidentSignedSession()?.sessionHeaders || {};
}
