import type { ApprovalIntent, ApprovalIntentLocator, CiphertextSnapshot, ParentTransport, PasskeyCredentialDto, PasskeyOptions, ViewState } from "./types";

export class RelayTransportError extends Error {
  constructor(readonly status: number) { super(`relay response ${status}`); }
}

/** Only relative paths are accepted: the PWA may talk to its same-origin BFF, never raw relay mailboxes. */
export function sameOriginPath(basePath: string, path: string): string {
  if (!basePath.startsWith("/") || basePath.startsWith("//") || basePath.includes("://") || !path.startsWith("/")) {
    throw new Error("same-origin BFF path required");
  }
  return `${basePath.replace(/\/+$/u, "")}${path}` || "/";
}

async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) throw new RelayTransportError(response.status);
  return response.json() as Promise<T>;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method: "POST", credentials: "include",
    headers: body === undefined ? undefined : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  return readJson<T>(response);
}

export class HttpParentTransport implements ParentTransport {
  private readonly base: string;
  constructor(basePath = "/") { this.base = basePath; }
  createRegistrationOptions(): Promise<PasskeyOptions> { return post(sameOriginPath(this.base, "/v1/auth/register/options")); }
  async completeRegistration(credential: PasskeyCredentialDto): Promise<void> { await post(sameOriginPath(this.base, "/v1/auth/register/complete"), credential); }
  createLoginOptions(): Promise<PasskeyOptions> { return post(sameOriginPath(this.base, "/v1/auth/login/options")); }
  async completeLogin(credential: PasskeyCredentialDto): Promise<void> { await post(sameOriginPath(this.base, "/v1/auth/login/complete"), credential); }
  async listSnapshots(): Promise<readonly CiphertextSnapshot[]> { return readJson(await fetch(sameOriginPath(this.base, "/v1/parent/inbox"), { credentials: "include" })); }
  /** This endpoint creates an untrusted locator only. Android rechecks the complete snapshot and choice. */
  createApprovalIntent(input: ApprovalIntent): Promise<ApprovalIntentLocator> { return post(sameOriginPath(this.base, "/v1/parent/approval-intents"), input); }
}

export function stateForRelayError(error: unknown): ViewState {
  if (error instanceof RelayTransportError && error.status === 410) return "expired";
  if (error instanceof RelayTransportError && error.status === 409) return "already-resolved";
  return navigator.onLine ? "error" : "offline";
}
