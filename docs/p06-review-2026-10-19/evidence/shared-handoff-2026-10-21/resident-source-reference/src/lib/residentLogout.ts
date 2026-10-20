import {
  ResidentApiError,
  residentFetchJsonResponse,
  type JsonPayload,
} from "@/lib/residentNativeHttp";
import {
  clearResidentProfileSelection,
  clearResidentSignedSession,
  getResidentSignedSession,
} from "@/lib/residentSessionBridge";
import {
  beginResidentLogout,
  finishResidentLogout,
  isResidentLogoutTokenCurrent,
} from "@/lib/residentSessionLifecycle";

export const RESIDENT_LOGOUT_PATH = "/api/core/identity/logout";
export const RESIDENT_LOGOUT_SAFE_MESSAGE = "LiveUIN could not complete sign out securely. Please try again.";

export type ResidentLogoutResult = {
  ok: true;
  outcome: "server_acknowledged" | "already_signed_out";
  requestId?: string;
};

export class ResidentLogoutError extends Error {
  readonly requestId?: string;
  readonly status: number;
  readonly responseClass?: string;
  readonly errorCode?: string;

  constructor(input: { requestId?: string; status?: number; responseClass?: string; errorCode?: string }) {
    super(RESIDENT_LOGOUT_SAFE_MESSAGE);
    this.name = "ResidentLogoutError";
    this.requestId = input.requestId;
    this.status = Number(input.status || 0);
    this.responseClass = input.responseClass;
    this.errorCode = input.errorCode;
  }
}

function responseIsTerminalSuccess(response: {
  status: number;
  ok: boolean;
  contentType: string;
  responseClass: string;
  payload: JsonPayload;
}) {
  const contentType = response.contentType.toLowerCase();
  return (
    response.status === 200 &&
    response.ok &&
    response.responseClass === "json" &&
    (contentType.includes("application/json") || contentType.includes("+json")) &&
    response.payload.ok !== false &&
    String(response.payload.status || "") === "identity_session_logged_out"
  );
}

function logoutErrorFromResponse(response: {
  status: number;
  responseClass: string;
  requestId?: string;
  errorCode?: string;
}) {
  return new ResidentLogoutError({
    requestId: response.requestId,
    status: response.status,
    responseClass: response.responseClass,
    errorCode: response.errorCode,
  });
}

function logoutErrorFromUnknown(error: unknown) {
  if (error instanceof ResidentLogoutError) return error;
  if (error instanceof ResidentApiError) {
    return new ResidentLogoutError({
      requestId: error.requestId,
      status: error.status,
      responseClass: error.responseClass,
      errorCode: error.errorCode,
    });
  }
  return new ResidentLogoutError({});
}

let activeLogoutPromise: Promise<ResidentLogoutResult> | null = null;

async function performResidentLogout(token: number): Promise<ResidentLogoutResult> {
  const session = getResidentSignedSession();
  if (!session) {
    clearResidentSignedSession();
    clearResidentProfileSelection();
    return { ok: true, outcome: "already_signed_out" };
  }

  try {
    const response = await residentFetchJsonResponse<JsonPayload>(RESIDENT_LOGOUT_PATH, {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: {
        Accept: "application/json",
        ...session.sessionHeaders,
      },
    });

    if (!isResidentLogoutTokenCurrent(token)) {
      throw new ResidentLogoutError({ requestId: response.requestId, status: response.status });
    }

    if (!responseIsTerminalSuccess(response)) {
      throw logoutErrorFromResponse(response);
    }

    clearResidentSignedSession();
    clearResidentProfileSelection();
    return { ok: true, outcome: "server_acknowledged", requestId: response.requestId };
  } catch (error) {
    throw logoutErrorFromUnknown(error);
  }
}

export function logoutResidentSession() {
  if (activeLogoutPromise) return activeLogoutPromise;

  const token = beginResidentLogout();
  activeLogoutPromise = performResidentLogout(token).finally(() => {
    finishResidentLogout();
    activeLogoutPromise = null;
  });
  return activeLogoutPromise;
}

