import { env, runInDurableObject, SELF } from "cloudflare:test";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { describe, expect, it } from "vitest";
import { BFF_AUTH_OBJECT_NAME } from "../src/bff";
import worker, { type Env } from "../src/index";

const rpId = "example.test";
const origin = "https://example.test";
const inviteSecret = "test-only-parent-invite-174c34797fbb42d9a3e57ce5a5bcf82e";
const bootstrapToken = "test-only-bootstrap-token-8f3f0d4dd15ebd16c4f5ac14a1c9e617";
const adminToken = "webauthn-admin-token-0000000000001";
const deviceToken = "webauthn-device-token-000000000001";
const mailboxId = "mailbox-webauthn-main";
const recipientKeyId = "recipient-parent-main";
const authOrigin = { origin };
const jsonOrigin = { origin, "content-type": "application/json" };
const request = (path: string, init: RequestInit = {}) => SELF.fetch(`${origin}${path}`, init);

interface RegistrationPublicKey {
  challenge: string;
  rp: { id: string };
  user: { id: string };
}

interface AuthenticationPublicKey {
  challenge: string;
  rpId: string;
}

interface AuthenticatorMaterial {
  readonly credentialId: Uint8Array;
  readonly credentialIdBase64Url: string;
  readonly privateKey: CryptoKey;
  readonly userHandle: string;
}

let registeredAuthenticator: AuthenticatorMaterial;
let authenticatedSessionCookie: string;

describe.sequential("parent WebAuthn BFF", () => {
  it("fails closed before touching Durable Objects when required WebAuthn secrets are absent", async () => {
    const response = await worker.fetch(
      new Request(`${origin}/v1/auth/login/options`, { method: "POST", headers: authOrigin }),
      { DEVICE_MAILBOX: env.DEVICE_MAILBOX } as Env,
    );
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({ error: "webauthn_bff_not_configured" });
  });

  it("registers a real passkey and exposes only session-backed parent BFF routes", async () => {
    const optionsResponse = await registrationOptions(mailboxId, recipientKeyId);
    expect(optionsResponse.status).toBe(200);
    const optionsBody = await optionsResponse.json() as { publicKey: RegistrationPublicKey };
    expect(Object.keys(optionsBody)).toEqual(["publicKey"]);
    expect(optionsBody.publicKey.rp.id).toBe(rpId);

    const ceremonyCookie = cookieFrom(optionsResponse, "__Host-guard_ceremony");
    const created = await registrationCredential(optionsBody.publicKey);
    registeredAuthenticator = created.material;
    const completion = await request("/v1/auth/register/complete", {
      method: "POST",
      headers: { ...jsonOrigin, cookie: ceremonyCookie },
      body: JSON.stringify(created.credential),
    });
    expect(completion.status).toBe(201);
    expect(await completion.json()).toEqual({ verified: true });
    const setCookie = completion.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("Secure");
    expect(setCookie).toContain("SameSite=Strict");
    const sessionCookie = cookieFrom(completion, "__Host-guard_session");

    let response = await request("/v1/parent/inbox", {
      headers: { ...authOrigin, cookie: sessionCookie },
    });
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual([]);
    response = await request("/v1/parent/inbox", {
      headers: { "sec-fetch-site": "same-origin", cookie: sessionCookie },
    });
    expect(response.status).toBe(200);
    response = await request("/v1/parent/inbox", {
      headers: { "sec-fetch-site": "cross-site", cookie: sessionCookie },
    });
    expect(response.status).toBe(403);

    response = await request("/v1/admin/bootstrap", {
      method: "POST",
      headers: { authorization: `Bearer ${bootstrapToken}`, "content-type": "application/json" },
      body: JSON.stringify({ mailboxId, accessToken: adminToken }),
    });
    expect(response.status).toBe(201);
    response = await request(`/v1/mailboxes/${mailboxId}/tokens`, {
      method: "POST",
      headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" },
      body: JSON.stringify({ accessToken: deviceToken, role: "device", expiresAt: Date.now() + 600_000 }),
    });
    expect(response.status).toBe(201);
    const createdAt = Date.now();
    const relayFrame = buildFrame(mailboxId, recipientKeyId, "frame-parent-snapshot-0001", createdAt);
    response = await request(`/v1/mailboxes/${mailboxId}/frames`, {
      method: "POST",
      headers: { authorization: `Bearer ${deviceToken}` },
      body: relayFrame,
    });
    expect(response.status).toBe(201);

    response = await request("/v1/parent/inbox", {
      headers: { ...authOrigin, cookie: sessionCookie },
    });
    expect(response.status).toBe(200);
    const snapshots = await response.json() as Array<Record<string, unknown>>;
    expect(snapshots).toEqual([{
      frameId: "frame-parent-snapshot-0001",
      frame: base64Url(relayFrame),
      receivedAt: new Date(createdAt).toISOString(),
    }]);
    expect(snapshots[0]!.frame).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(JSON.stringify(snapshots)).not.toContain("requestId");
    expect(decodeBase64Url(String(snapshots[0]!.frame))).toEqual(relayFrame);

    const mailboxStub = env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(mailboxId));
    await runInDurableObject(mailboxStub, (_instance, state) => {
      state.storage.sql.exec(
        "INSERT INTO frames(frame_id,recipient_key_id,kind,cursor,expires_at,bytes,size) VALUES(?,?,?,?,?,?,?)",
        "frame-corrupt-0001",
        recipientKeyId,
        1,
        2,
        Date.now() + 60_000,
        Uint8Array.of(1, 2, 3, 4, 5),
        5,
      );
    });
    response = await request("/v1/parent/inbox", {
      headers: { ...authOrigin, cookie: sessionCookie },
    });
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({ error: "mailbox_frame_corrupt" });
    await runInDurableObject(mailboxStub, (_instance, state) => {
      state.storage.sql.exec("DELETE FROM frames WHERE frame_id=?", "frame-corrupt-0001");
      const oversized = new Uint8Array(64 * 1024 + 1);
      state.storage.sql.exec(
        "INSERT INTO frames(frame_id,recipient_key_id,kind,cursor,expires_at,bytes,size) VALUES(?,?,?,?,?,?,?)",
        "frame-oversized-0001",
        recipientKeyId,
        1,
        2,
        Date.now() + 60_000,
        oversized,
        oversized.byteLength,
      );
    });
    response = await request("/v1/parent/inbox", {
      headers: { ...authOrigin, cookie: sessionCookie },
    });
    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({ error: "mailbox_frame_corrupt" });
    await runInDurableObject(mailboxStub, (_instance, state) => {
      state.storage.sql.exec("DELETE FROM frames WHERE frame_id=?", "frame-oversized-0001");
    });

    const intent = { requestId: "request-parent-0001", kind: "Deny" };
    response = await request("/v1/parent/approval-intents", {
      method: "POST",
      headers: { ...jsonOrigin, cookie: sessionCookie },
      body: JSON.stringify(intent),
    });
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({ error: "csrf_rejected" });

    response = await request("/v1/parent/approval-intents", {
      method: "POST",
      headers: { ...jsonOrigin, cookie: sessionCookie, "x-guard-csrf": "0" },
      body: JSON.stringify(intent),
    });
    expect(response.status).toBe(403);

    response = await request("/v1/parent/approval-intents", {
      method: "POST",
      headers: { ...jsonOrigin, cookie: sessionCookie, "x-guard-csrf": "1" },
      body: JSON.stringify(intent),
    });
    expect(response.status).toBe(201);
    const locator = await response.json() as Record<string, unknown>;
    expect(locator).toMatchObject({
      nonAuthoritative: true,
      confirmationRequiredOnAndroid: true,
    });
    expect(locator.locator).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(JSON.stringify(locator)).not.toContain("Deny");
    expect(JSON.stringify(locator)).not.toContain("Bearer");
  });

  it("rejects the wrong origin and the wrong high-entropy invite", async () => {
    let response = await request("/v1/auth/login/options", {
      method: "POST",
      headers: { origin: "https://evil.example" },
    });
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({ error: "origin_rejected" });

    response = await request("/v1/auth/register/options", {
      method: "POST",
      headers: jsonOrigin,
      body: JSON.stringify({
        mailboxId: "mailbox-wrong-invite",
        recipientKeyId: "recipient-wrong-invite",
        inviteSecret: "x".repeat(32),
      }),
    });
    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({ error: "registration_forbidden" });
  });

  it("binds the ceremony to RP ID and challenge, then burns failed attempts", async () => {
    let optionsResponse = await registrationOptions("mailbox-wrong-rp", "recipient-wrong-rp");
    let optionsBody = await optionsResponse.json() as { publicKey: RegistrationPublicKey };
    let ceremonyCookie = cookieFrom(optionsResponse, "__Host-guard_ceremony");
    let created = await registrationCredential(optionsBody.publicKey, { rpId: "wrong.example.test" });
    let response = await request("/v1/auth/register/complete", {
      method: "POST",
      headers: { ...jsonOrigin, cookie: ceremonyCookie },
      body: JSON.stringify(created.credential),
    });
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "webauthn_verification_failed" });

    created = await registrationCredential(optionsBody.publicKey);
    response = await request("/v1/auth/register/complete", {
      method: "POST",
      headers: { ...jsonOrigin, cookie: ceremonyCookie },
      body: JSON.stringify(created.credential),
    });
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toEqual({ error: "ceremony_not_pending" });

    optionsResponse = await registrationOptions("mailbox-wrong-challenge", "recipient-wrong-challenge");
    optionsBody = await optionsResponse.json() as { publicKey: RegistrationPublicKey };
    ceremonyCookie = cookieFrom(optionsResponse, "__Host-guard_ceremony");
    created = await registrationCredential(optionsBody.publicKey, { challenge: base64Url(randomBytes(32)) });
    response = await request("/v1/auth/register/complete", {
      method: "POST",
      headers: { ...jsonOrigin, cookie: ceremonyCookie },
      body: JSON.stringify(created.credential),
    });
    expect(response.status).toBe(400);

    created = await registrationCredential(optionsBody.publicKey);
    response = await request("/v1/auth/register/complete", {
      method: "POST",
      headers: { ...jsonOrigin, cookie: ceremonyCookie },
      body: JSON.stringify(created.credential),
    });
    expect(response.status).toBe(409);
  });

  it("authenticates a real assertion and rejects ceremony replay", async () => {
    const optionsResponse = await request("/v1/auth/login/options", {
      method: "POST",
      headers: authOrigin,
    });
    expect(optionsResponse.status).toBe(200);
    const optionsBody = await optionsResponse.json() as { publicKey: AuthenticationPublicKey };
    const ceremonyCookie = cookieFrom(optionsResponse, "__Host-guard_ceremony");
    const assertion = await authenticationCredential(optionsBody.publicKey, registeredAuthenticator, 1);
    const response = await request("/v1/auth/login/complete", {
      method: "POST",
      headers: { ...jsonOrigin, cookie: ceremonyCookie },
      body: JSON.stringify(assertion),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ verified: true });
    authenticatedSessionCookie = cookieFrom(response, "__Host-guard_session");

    const replay = await request("/v1/auth/login/complete", {
      method: "POST",
      headers: { ...jsonOrigin, cookie: ceremonyCookie },
      body: JSON.stringify(assertion),
    });
    expect(replay.status).toBe(409);
    await expect(replay.json()).resolves.toEqual({ error: "ceremony_not_pending" });
  });

  it("rejects expired challenges and expired sessions", async () => {
    const optionsResponse = await request("/v1/auth/login/options", {
      method: "POST",
      headers: authOrigin,
    });
    const optionsBody = await optionsResponse.json() as { publicKey: AuthenticationPublicKey };
    const ceremonyCookie = cookieFrom(optionsResponse, "__Host-guard_ceremony");
    const ceremonyId = signedCookieValue(ceremonyCookie);
    const authStub = env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(BFF_AUTH_OBJECT_NAME));
    await runInDurableObject(authStub, (_instance, state) => {
      state.storage.sql.exec("UPDATE webauthn_challenges SET expires_at=0 WHERE ceremony_id=?", ceremonyId);
    });

    const assertion = await authenticationCredential(optionsBody.publicKey, registeredAuthenticator, 2);
    let response = await request("/v1/auth/login/complete", {
      method: "POST",
      headers: { ...jsonOrigin, cookie: ceremonyCookie },
      body: JSON.stringify(assertion),
    });
    expect(response.status).toBe(410);
    await expect(response.json()).resolves.toEqual({ error: "ceremony_expired" });

    await runInDurableObject(authStub, (_instance, state) => {
      state.storage.sql.exec("UPDATE parent_sessions SET expires_at=0 WHERE mailbox_id=?", mailboxId);
    });
    response = await request("/v1/parent/inbox", {
      headers: { ...authOrigin, cookie: authenticatedSessionCookie },
    });
    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({ error: "authentication_required" });
  });
});

async function registrationOptions(mailbox: string, recipient: string): Promise<Response> {
  return request("/v1/auth/register/options", {
    method: "POST",
    headers: jsonOrigin,
    body: JSON.stringify({
      mailboxId: mailbox,
      recipientKeyId: recipient,
      inviteSecret,
      username: "parent",
      displayName: "Guard Parent",
    }),
  });
}

async function registrationCredential(
  options: RegistrationPublicKey,
  overrides: { rpId?: string; challenge?: string } = {},
): Promise<{
  credential: Record<string, unknown>;
  material: AuthenticatorMaterial;
}> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  const credentialId = randomBytes(32);
  const coseKey = isoCBOR.encode(new Map<number, number | Uint8Array>([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, publicKey.slice(1, 33)],
    [-3, publicKey.slice(33, 65)],
  ]));
  const rpHash = new Uint8Array(await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(overrides.rpId ?? options.rp.id),
  ));
  const authenticatorData = concatenate(
    rpHash,
    Uint8Array.of(0x45),
    uint32(0),
    new Uint8Array(16),
    uint16(credentialId.byteLength),
    credentialId,
    coseKey,
  );
  const attestationObject = isoCBOR.encode(new Map<string, string | Uint8Array | Map<never, never>>([
    ["fmt", "none"],
    ["attStmt", new Map()],
    ["authData", authenticatorData],
  ]));
  const clientDataJSON = new TextEncoder().encode(JSON.stringify({
    type: "webauthn.create",
    challenge: overrides.challenge ?? options.challenge,
    origin,
    crossOrigin: false,
  }));
  const credentialIdBase64Url = base64Url(credentialId);
  return {
    credential: {
      id: credentialIdBase64Url,
      rawId: credentialIdBase64Url,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: base64Url(clientDataJSON),
        attestationObject: base64Url(attestationObject),
        transports: ["internal"],
      },
    },
    material: {
      credentialId,
      credentialIdBase64Url,
      privateKey: keyPair.privateKey,
      userHandle: options.user.id,
    },
  };
}

async function authenticationCredential(
  options: AuthenticationPublicKey,
  authenticator: AuthenticatorMaterial,
  counter: number,
): Promise<Record<string, unknown>> {
  const rpHash = new Uint8Array(await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(options.rpId),
  ));
  const authenticatorData = concatenate(rpHash, Uint8Array.of(0x05), uint32(counter));
  const clientDataJSON = new TextEncoder().encode(JSON.stringify({
    type: "webauthn.get",
    challenge: options.challenge,
    origin,
    crossOrigin: false,
  }));
  const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON));
  const rawSignature = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    authenticator.privateKey,
    concatenate(authenticatorData, clientHash),
  ));
  return {
    id: authenticator.credentialIdBase64Url,
    rawId: authenticator.credentialIdBase64Url,
    type: "public-key",
    authenticatorAttachment: "platform",
    clientExtensionResults: {},
    response: {
      clientDataJSON: base64Url(clientDataJSON),
      authenticatorData: base64Url(authenticatorData),
      signature: base64Url(rawSignature.byteLength === 64 ? p1363ToDer(rawSignature) : rawSignature),
      userHandle: authenticator.userHandle,
    },
  };
}

function cookieFrom(response: Response, name: string): string {
  const combined = response.headers.get("set-cookie") ?? "";
  const match = new RegExp(`${name}=([^;,\\s]+)`).exec(combined);
  if (!match) throw new Error(`missing ${name} cookie`);
  return `${name}=${match[1]!}`;
}

function signedCookieValue(cookie: string): string {
  const match = /=v1\.([A-Za-z0-9_-]{43})\./.exec(cookie);
  if (!match) throw new Error("invalid signed cookie");
  return match[1]!;
}

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(decoded, character => character.charCodeAt(0));
}

function buildFrame(
  mailbox: string,
  recipient: string,
  frameId: string,
  createdAt: number,
): Uint8Array {
  return concatenate(
    new TextEncoder().encode("GRF1"),
    uint32(1),
    uint32(1),
    canonicalText(mailbox),
    canonicalText(recipient),
    canonicalText(frameId),
    uint64(1),
    uint64(0),
    uint64(createdAt),
    uint64(createdAt + 60_000),
    uint32(65),
    Uint8Array.from({ length: 65 }, (_value, index) => index + 1),
    uint32(16),
    Uint8Array.from({ length: 16 }, (_value, index) => 128 + index),
  );
}

function canonicalText(value: string): Uint8Array {
  const encoded = new TextEncoder().encode(value);
  return concatenate(uint32(encoded.byteLength), encoded);
}

function uint16(value: number): Uint8Array {
  return Uint8Array.of((value >>> 8) & 0xff, value & 0xff);
}

function uint64(value: number): Uint8Array {
  let remaining = BigInt(value);
  const result = new Uint8Array(8);
  for (let index = 7; index >= 0; index--) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result;
}

function uint32(value: number): Uint8Array {
  return Uint8Array.of((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function concatenate(...values: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((length, value) => length + value.byteLength, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.byteLength;
  }
  return result;
}

function p1363ToDer(signature: Uint8Array): Uint8Array {
  const r = derInteger(signature.slice(0, 32));
  const s = derInteger(signature.slice(32));
  return concatenate(Uint8Array.of(0x30, r.byteLength + s.byteLength), r, s);
}

function derInteger(value: Uint8Array): Uint8Array {
  let offset = 0;
  while (offset < value.byteLength - 1 && value[offset] === 0) offset++;
  const unsigned = value.slice(offset);
  const content = unsigned[0]! >= 0x80 ? concatenate(Uint8Array.of(0), unsigned) : unsigned;
  return concatenate(Uint8Array.of(0x02, content.byteLength), content);
}
