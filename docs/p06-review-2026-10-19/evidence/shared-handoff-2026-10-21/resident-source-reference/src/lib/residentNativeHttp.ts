import { CapacitorHttp } from "@capacitor/core";

import { buildResidentApiUrl, isNativeRuntimeShell } from "@/lib/runtimeHost";
import { getResidentSignedSessionHeaders } from "@/lib/residentSessionBridge";

export type JsonPayload = {
  ok?: boolean;
  detail?: string;
  status_code?: number;
  request_id?: string;
  error?: { code?: string; message?: string; field?: string | null; next_action?: string };
  [key: string]: unknown;
};

export type ResidentResponseClass = "json" | "empty" | "html" | "non_json" | "malformed_json" | "network" | "timeout";

export type ResidentJsonResponse<T> = {
  payload: T & JsonPayload;
  url: string;
  method: string;
  transport: "browser_fetch" | "capacitor_http";
  status: number;
  ok: boolean;
  contentType: string;
  parse: "json" | "empty" | "non_json" | "malformed_json";
  responseClass: Exclude<ResidentResponseClass, "network" | "timeout">;
  requestId?: string;
  errorCode?: string;
};

export class ResidentApiError extends Error {
  readonly status: number;
  readonly responseClass: ResidentResponseClass;
  readonly requestId?: string;
  readonly errorCode?: string;

  constructor(message: string, responseClass: ResidentResponseClass, requestId?: string, cause?: unknown, status = 0, errorCode?: string) {
    super(message);
    if (cause !== undefined) this.cause = cause;
    this.name = "ResidentApiError";
    this.status = status;
    this.responseClass = responseClass;
    this.requestId = requestId;
    this.errorCode = errorCode;
  }
}

export type ResidentDiagnosticEvent = {
  phase: "request_start" | "response" | "error" | "mapped_error";
  diagnosticOnly?: boolean;
  operation?: string;
  route: string;
  url: string;
  method: string;
  webViewOrigin: string;
  transport: "browser_fetch" | "capacitor_http";
  startedAt: string;
  completedAt?: string;
  receivedResponse?: boolean;
  status?: number;
  statusText?: string;
  contentType?: string;
  responseClass?: ResidentResponseClass;
  parse?: ResidentJsonResponse<unknown>["parse"];
  requestId?: string;
  errorCode?: string;
  errorName?: string;
  errorMessage?: string;
  userMessage?: string;
};

function diagnosticsEnabled() {
  return String(import.meta.env.VITE_LIVEUIN_RESIDENT_DIAGNOSTICS || "").trim() === "1";
}

function diagnosticRoute() {
  return typeof window === "undefined" ? "unknown" : window.location.pathname;
}

function diagnosticOrigin() {
  return typeof window === "undefined" ? "unknown" : window.location.origin;
}

function redactDiagnosticText(value: unknown) {
  return String(value || "")
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[redacted-email]")
    .replace(/(password|token|secret|authorization|cookie|verification_code|reset_id|reset_token|code)=?[^\s,;]+/gi, "$1=[redacted]");
}

export function recordResidentDiagnostic(event: ResidentDiagnosticEvent) {
  if (!diagnosticsEnabled()) return;
  const safeEvent = {
    ...event,
    errorMessage: event.errorMessage ? redactDiagnosticText(event.errorMessage) : undefined,
    userMessage: event.userMessage ? redactDiagnosticText(event.userMessage) : undefined,
  };
  console.info("[LiveUIN resident diagnostic]", JSON.stringify(safeEvent));
}

function normalizeHeaders(headers?: HeadersInit) {
  if (!headers) return {} as Record<string, string>;
  if (headers instanceof Headers) return Object.fromEntries(headers.entries());
  if (Array.isArray(headers)) return Object.fromEntries(headers.map(([key, value]) => [String(key), String(value)]));
  return Object.fromEntries(Object.entries(headers).map(([key, value]) => [key, String(value)]));
}

function normalizeBody(body?: BodyInit | null) {
  if (!body) return undefined;
  if (typeof body === "string") {
    try {
      return JSON.parse(body) as unknown;
    } catch {
      return body;
    }
  }
  if (body instanceof URLSearchParams) return body.toString();
  return body as unknown;
}

function headerValue(headers: Record<string, string> | undefined, name: string) {
  const target = name.toLowerCase();
  return Object.entries(headers || {}).find(([key]) => key.toLowerCase() === target)?.[1] || "";
}

function isJsonContentType(contentType: string) {
  return contentType.toLowerCase().includes("application/json") || contentType.toLowerCase().includes("+json");
}

function parseResponseBody<T>(body: unknown, contentType: string) {
  if (body === null || body === undefined || body === "") return { payload: {} as T & JsonPayload, parse: "empty" as const, responseClass: "empty" as const };
  if (typeof body !== "string") return { payload: (body || {}) as T & JsonPayload, parse: "json" as const, responseClass: "json" as const };
  const trimmed = body.trim();
  if (!trimmed) return { payload: {} as T & JsonPayload, parse: "empty" as const, responseClass: "empty" as const };
  if (!isJsonContentType(contentType)) {
    return { payload: {} as T & JsonPayload, parse: "non_json" as const, responseClass: contentType.toLowerCase().includes("text/html") ? "html" as const : "non_json" as const };
  }
  try {
    return { payload: JSON.parse(trimmed) as T & JsonPayload, parse: "json" as const, responseClass: "json" as const };
  } catch {
    return { payload: {} as T & JsonPayload, parse: "malformed_json" as const, responseClass: "malformed_json" as const };
  }
}

function requestIdFrom(payload: JsonPayload, headers?: Record<string, string>) {
  return String(payload.request_id || headerValue(headers, "x-request-id") || headerValue(headers, "x-liveuin-request-id") || "").trim() || undefined;
}

function errorCodeFrom(payload: JsonPayload) {
  return String(payload.error?.code || payload.detail || "").trim() || undefined;
}

function shouldUseNativeHttp(url: string) {
  return typeof document !== "undefined" && document.documentElement.hasAttribute("data-liveuin-native-app-only") && isNativeRuntimeShell() && /^https?:\/\//.test(url);
}

function transportError(error: unknown) {
  const detail = error instanceof Error ? `${error.name} ${error.message}` : String(error || "");
  const timeout = /timeout|timed out|etimedout/i.test(detail);
  return new ResidentApiError(timeout ? "LiveUIN took too long to respond. Please try again." : "LiveUIN could not connect. Check your connection and try again.", timeout ? "timeout" : "network", undefined, error);
}

/**
 * Plain fetch for callers that need the raw Response (status, headers, json()).
 * In the native shell a relative "/api/..." path would otherwise be resolved against the
 * WebView's own capacitor:// origin and never reach LiveUIN (and app.liveuin.com does not
 * allow capacitor:// origins for CORS). Here the path is resolved to the resident API host
 * and sent through CapacitorHttp, then wrapped back into a standard Response.
 */
export async function residentFetchRaw(path: string, init?: RequestInit): Promise<Response> {
  const url = buildResidentApiUrl(path);
  if (!shouldUseNativeHttp(url)) return fetch(url, init);
  const method = String(init?.method || "GET").toUpperCase();
  const nativeResponse = await CapacitorHttp.request({
    url,
    method,
    headers: normalizeHeaders(init?.headers),
    data: normalizeBody(init?.body),
    readTimeout: 60000,
    connectTimeout: 60000,
    responseType: "text",
  });
  const status = Number(nativeResponse.status || 0);
  if (!Number.isFinite(status) || status < 200 || status > 599) throw new TypeError("LiveUIN could not connect.");
  const data = nativeResponse.data;
  const body = data === null || data === undefined ? "" : typeof data === "string" ? data : JSON.stringify(data);
  const nullBodyStatus = status === 204 || status === 205 || status === 304;
  return new Response(nullBodyStatus ? null : body, {
    status,
    headers: normalizeHeaders(nativeResponse.headers as HeadersInit | undefined),
  });
}

export async function residentFetchJsonResponse<T>(path: string, init?: RequestInit, options: { timeoutMs?: number } = {}): Promise<ResidentJsonResponse<T>> {
  // Identity forms need a bounded answer even if a native callback never settles.
  // Wrap only transport/parsing: a late response cannot install a session.
  if (options.timeoutMs) {
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (init?.signal?.aborted) abort();
    init?.signal?.addEventListener("abort", abort, { once: true });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        residentFetchJsonResponse<T>(path, { ...init, signal: controller.signal }),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            reject(transportError(new Error("request timeout")));
            controller.abort();
          }, options.timeoutMs);
        }),
      ]);
    } finally {
      clearTimeout(timer);
      init?.signal?.removeEventListener("abort", abort);
    }
  }
  const url = buildResidentApiUrl(path);
  const method = String(init?.method || "GET").toUpperCase();
  const transport = shouldUseNativeHttp(url) ? "capacitor_http" : "browser_fetch";
  const startedAt = new Date().toISOString();
  const headers = { ...getResidentSignedSessionHeaders(), ...normalizeHeaders(init?.headers) };
  recordResidentDiagnostic({ phase: "request_start", route: diagnosticRoute(), url, method, webViewOrigin: diagnosticOrigin(), transport, startedAt });
  try {
    if (transport === "capacitor_http") {
      const nativeResponse = await CapacitorHttp.request({ url, method, headers, data: normalizeBody(init?.body), readTimeout: 60000, connectTimeout: 60000, responseType: "json" });
      const nativeHeaders = normalizeHeaders(nativeResponse.headers as HeadersInit | undefined);
      const parsed = parseResponseBody<T>(nativeResponse.data, headerValue(nativeHeaders, "content-type"));
      const result = {
        payload: parsed.payload, url, method, transport, status: Number(nativeResponse.status || 0),
        ok: Number(nativeResponse.status || 0) >= 200 && Number(nativeResponse.status || 0) < 300,
        contentType: headerValue(nativeHeaders, "content-type"), parse: parsed.parse, responseClass: parsed.responseClass,
        requestId: requestIdFrom(parsed.payload, nativeHeaders), errorCode: errorCodeFrom(parsed.payload),
      } satisfies ResidentJsonResponse<T>;
      recordResidentDiagnostic({ phase: "response", route: diagnosticRoute(), url, method, webViewOrigin: diagnosticOrigin(), transport, startedAt, completedAt: new Date().toISOString(), receivedResponse: true, status: result.status, contentType: result.contentType, responseClass: result.responseClass, parse: result.parse, requestId: result.requestId, errorCode: result.errorCode });
      return result;
    }
    const response = await fetch(url, { ...init, headers });
    const contentType = response.headers?.get?.("content-type") || "";
    const body = typeof response.text === "function" ? await response.text() : await response.json();
    const parsed = parseResponseBody<T>(body, contentType);
    const responseHeaders = Object.fromEntries(response.headers?.entries?.() || []);
    const result = {
      payload: parsed.payload, url, method, transport, status: response.status, ok: response.ok, contentType,
      parse: parsed.parse, responseClass: parsed.responseClass,
      requestId: requestIdFrom(parsed.payload, responseHeaders), errorCode: errorCodeFrom(parsed.payload),
    } satisfies ResidentJsonResponse<T>;
    recordResidentDiagnostic({ phase: "response", route: diagnosticRoute(), url, method, webViewOrigin: diagnosticOrigin(), transport, startedAt, completedAt: new Date().toISOString(), receivedResponse: true, status: result.status, statusText: response.statusText, contentType, responseClass: result.responseClass, parse: result.parse, requestId: result.requestId, errorCode: result.errorCode });
    return result;
  } catch (error) {
    const mapped = transportError(error);
    recordResidentDiagnostic({ phase: "error", route: diagnosticRoute(), url, method, webViewOrigin: diagnosticOrigin(), transport, startedAt, completedAt: new Date().toISOString(), receivedResponse: false, responseClass: mapped.responseClass, errorName: error instanceof Error ? error.name : undefined, errorMessage: error instanceof Error ? error.message : String(error || "") });
    throw mapped;
  }
}

export async function residentUploadFileJsonResponse<T>(path: string, file: Blob, init: Omit<RequestInit, "body"> = {}) {
  const url = buildResidentApiUrl(path);
  const method = String(init.method || "POST").toUpperCase();
  const headers = { ...getResidentSignedSessionHeaders(), ...normalizeHeaders(init.headers) };
  try {
    if (shouldUseNativeHttp(url)) {
      const reader = new FileReader();
      const base64 = await new Promise<string>((resolve, reject) => {
        reader.onload = () => resolve(String(reader.result || "").split(",").pop() || "");
        reader.onerror = () => reject(reader.error || new Error("file_read_failed"));
        reader.readAsDataURL(file);
      });
      const nativeResponse = await CapacitorHttp.request({ url, method, headers, data: base64, dataType: "file", readTimeout: 60000, connectTimeout: 60000, responseType: "json" });
      const nativeHeaders = normalizeHeaders(nativeResponse.headers as HeadersInit | undefined);
      const parsed = parseResponseBody<T>(nativeResponse.data, headerValue(nativeHeaders, "content-type"));
      return { payload: parsed.payload, url, method, transport: "capacitor_http" as const, status: Number(nativeResponse.status || 0), ok: Number(nativeResponse.status || 0) >= 200 && Number(nativeResponse.status || 0) < 300, contentType: headerValue(nativeHeaders, "content-type"), parse: parsed.parse, responseClass: parsed.responseClass, requestId: requestIdFrom(parsed.payload, nativeHeaders), errorCode: errorCodeFrom(parsed.payload) } satisfies ResidentJsonResponse<T>;
    }
    const response = await fetch(url, { ...init, headers, body: file });
    const contentType = response.headers.get("content-type") || "";
    const parsed = parseResponseBody<T>(await response.text(), contentType);
    const responseHeaders = Object.fromEntries(response.headers.entries());
    return { payload: parsed.payload, url, method, transport: "browser_fetch" as const, status: response.status, ok: response.ok, contentType, parse: parsed.parse, responseClass: parsed.responseClass, requestId: requestIdFrom(parsed.payload, responseHeaders), errorCode: errorCodeFrom(parsed.payload) } satisfies ResidentJsonResponse<T>;
  } catch (error) {
    throw transportError(error);
  }
}
