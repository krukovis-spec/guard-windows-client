import { decodeBase64Url } from "./base64url";
import type { ApprovalIntent, ApprovalIntentLocator, EncryptedRelayFrame, ParentTransport, PasskeyCredentialDto, PasskeyOptions, ViewState } from "./types";

const maximumInboxFrames = 20;
const maximumTotalInboxFrames = 128;
const maximumRelayFrameBytes = 64 * 1024;
const canonicalIdentifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/u;

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
    headers: {
      "x-guard-csrf": "1",
      ...(body === undefined ? {} : { "content-type": "application/json" })
    },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
  return readJson<T>(response);
}

function decodeInbox(value: unknown, after: number): readonly EncryptedRelayFrame[] {
  if (!Array.isArray(value) || value.length > maximumInboxFrames) {
    throw new Error("inbox must be a bounded array");
  }

  const frameIds = new Set<string>();
  let cursor = after;
  return value.map((entry, index) => {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new Error(`inbox[${index}] must be an object`);
    }
    const frame = entry as Record<string, unknown>;
    const keys = Object.keys(frame).sort();
    if (keys.length !== 4 || keys[0] !== "cursor" || keys[1] !== "frame" || keys[2] !== "frameId" || keys[3] !== "receivedAt") {
      throw new Error(`inbox[${index}] has unknown fields`);
    }
    if (!Number.isSafeInteger(frame.cursor) || Number(frame.cursor) <= cursor) {
      throw new Error(`inbox[${index}].cursor must advance`);
    }
    cursor = Number(frame.cursor);
    if (typeof frame.frameId !== "string" || !canonicalIdentifier.test(frame.frameId)) {
      throw new Error(`inbox[${index}].frameId must be canonical`);
    }
    if (frameIds.has(frame.frameId)) {
      throw new Error(`inbox[${index}].frameId must be unique`);
    }
    frameIds.add(frame.frameId);
    if (typeof frame.receivedAt !== "string") {
      throw new Error(`inbox[${index}].receivedAt must be canonical UTC`);
    }
    const received = new Date(frame.receivedAt);
    if (!Number.isFinite(received.valueOf()) || received.toISOString() !== frame.receivedAt) {
      throw new Error(`inbox[${index}].receivedAt must be canonical UTC`);
    }
    return {
      cursor,
      frameId: frame.frameId,
      encodedFrame: decodeBase64Url(
        frame.frame,
        `inbox[${index}].frame`,
        8,
        maximumRelayFrameBytes
      ),
      receivedAt: frame.receivedAt
    };
  });
}

export class HttpParentTransport implements ParentTransport {
  private readonly base: string;
  constructor(basePath = "/") { this.base = basePath; }
  createRegistrationOptions(): Promise<PasskeyOptions> { return post(sameOriginPath(this.base, "/v1/auth/register/options")); }
  async completeRegistration(credential: PasskeyCredentialDto): Promise<void> { await post(sameOriginPath(this.base, "/v1/auth/register/complete"), credential); }
  createLoginOptions(): Promise<PasskeyOptions> { return post(sameOriginPath(this.base, "/v1/auth/login/options")); }
  async completeLogin(credential: PasskeyCredentialDto): Promise<void> { await post(sameOriginPath(this.base, "/v1/auth/login/complete"), credential); }
  async listSnapshots(): Promise<readonly EncryptedRelayFrame[]> {
    const frames: EncryptedRelayFrame[] = [];
    const ids = new Set<string>();
    let after = 0;
    while (true) {
      const page = decodeInbox(await readJson<unknown>(
        await fetch(sameOriginPath(this.base, `/v1/parent/inbox?after=${after}&limit=${maximumInboxFrames}`), { credentials: "include" })
      ), after);
      if (frames.length + page.length > maximumTotalInboxFrames) throw new Error("inbox capacity exceeded");
      for (const frame of page) {
        if (ids.has(frame.frameId)) throw new Error("inbox frame id repeated across pages");
        ids.add(frame.frameId);
        frames.push(frame);
      }
      if (page.length < maximumInboxFrames) return frames;
      after = page[page.length - 1]!.cursor;
    }
  }
  /** This endpoint creates an untrusted locator only. Android rechecks the complete snapshot and choice. */
  createApprovalIntent(input: ApprovalIntent): Promise<ApprovalIntentLocator> { return post(sameOriginPath(this.base, "/v1/parent/approval-intents"), input); }
}

export function stateForRelayError(error: unknown): ViewState {
  if (error instanceof RelayTransportError && error.status === 410) return "expired";
  if (error instanceof RelayTransportError && error.status === 409) return "already-resolved";
  return navigator.onLine ? "error" : "offline";
}
