import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { MAX_FRAME_BYTES, parseRelayFrame } from "./frame";

export interface ParentBffEnv {
  DEVICE_MAILBOX: DurableObjectNamespace;
  RP_ID?: string;
  RP_ORIGIN?: string;
  SESSION_SECRET?: string;
  PARENT_INVITE_SECRET?: string;
}

export interface ParentBffContext {
  readonly state: DurableObjectState;
  readonly sql: SqlStorage;
  readonly env: ParentBffEnv;
}

export const BFF_AUTH_OBJECT_NAME = "guard:bff:auth:v1";

const jsonHeaders = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cross-origin-resource-policy": "same-origin",
};
const ceremonyCookieName = "__Host-guard_ceremony";
const sessionCookieName = "__Host-guard_session";
const internalHeaderName = "x-guard-bff-proof";
const maxJsonBytes = 64 * 1024;
const challengeLifetimeMs = 5 * 60 * 1000;
const sessionLifetimeMs = 8 * 60 * 60 * 1000;
const locatorLifetimeMs = 5 * 60 * 1000;
const maximumActiveChallenges = 64;
const maximumUsers = 32;
const maximumPasskeysPerUser = 8;
const maximumSessionsPerUser = 32;
const maximumLocatorsPerMailbox = 256;
const maximumPoll = 50;
const allowedTransports = new Set<AuthenticatorTransportFuture>([
  "ble",
  "cable",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb",
]);

interface ParentBffConfig {
  readonly rpId: string;
  readonly rpOrigin: string;
  readonly sessionSecret: string;
  readonly inviteSecret: string;
}

interface ChallengeRow extends Record<string, SqlStorageValue> {
  purpose: "register" | "login";
  user_id: ArrayBuffer | null;
  challenge: string;
  expires_at: number;
}

interface ParentUserRow extends Record<string, SqlStorageValue> {
  user_id: ArrayBuffer;
  mailbox_id: string;
  recipient_key_id: string;
  username: string;
  display_name: string;
}

interface PasskeyRow extends Record<string, SqlStorageValue> {
  credential_id: string;
  user_id: ArrayBuffer;
  public_key: ArrayBuffer;
  counter: number;
  transports: string;
}

interface SessionRow extends Record<string, SqlStorageValue> {
  user_id: ArrayBuffer;
  mailbox_id: string;
  recipient_key_id: string;
  expires_at: number;
}

interface NewSession {
  readonly token: string;
  readonly tokenHash: Uint8Array;
  readonly expiresAt: number;
}

interface RegistrationOptionsInput {
  mailboxId?: unknown;
  recipientKeyId?: unknown;
  inviteSecret?: unknown;
  username?: unknown;
  displayName?: unknown;
}

interface ApprovalIntentInput {
  requestId?: unknown;
  kind?: unknown;
  minutes?: unknown;
}

class ParentBffHttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
  }
}

export function isParentBffPath(pathname: string): boolean {
  return /^\/v1\/(?:auth\/(?:register|login)\/(?:options|complete)|parent\/(?:inbox|approval-intents))$/.test(pathname);
}

export async function forwardParentBff(request: Request, env: ParentBffEnv): Promise<Response> {
  try {
    const config = requireConfig(env);
    const headers = sanitizedHeaders(request.headers);
    headers.set(internalHeaderName, await internalProof(config, `auth:${BFF_AUTH_OBJECT_NAME}`));
    const body = request.method === "GET" || request.method === "HEAD"
      ? undefined
      : await request.arrayBuffer();
    const stub = env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(BFF_AUTH_OBJECT_NAME));
    return await stub.fetch(new Request(`https://auth.internal${new URL(request.url).pathname}${new URL(request.url).search}`, {
      method: request.method,
      headers,
      body,
    }));
  } catch (error) {
    return bffFailure(error);
  }
}

export async function handleParentBffRequest(context: ParentBffContext, request: Request): Promise<Response | null> {
  const pathname = new URL(request.url).pathname;
  const isAuthObjectRoute = isParentBffPath(pathname);
  const isMailboxInternalRoute = pathname === "/internal/bff/inbox" || pathname === "/internal/bff/approval-intents";
  if (!isAuthObjectRoute && !isMailboxInternalRoute) return null;

  try {
    const config = requireConfig(context.env);
    if (isAuthObjectRoute) {
      if (context.state.id.name !== BFF_AUTH_OBJECT_NAME) throw new ParentBffHttpError(404, "not_found");
      await requireInternalProof(request, config, `auth:${BFF_AUTH_OBJECT_NAME}`);
      return await handleAuthObjectRoute(context, request, config);
    }

    const mailboxId = context.state.id.name;
    if (!mailboxId || !validId(mailboxId)) throw new ParentBffHttpError(404, "not_found");
    await requireInternalProof(request, config, `mailbox:${mailboxId}`);
    return pathname === "/internal/bff/inbox"
      ? mailboxInbox(context, request)
      : await mailboxApprovalIntent(context, request);
  } catch (error) {
    return bffFailure(error);
  }
}

function requireConfig(env: ParentBffEnv): ParentBffConfig {
  const rpId = env.RP_ID;
  const rpOrigin = env.RP_ORIGIN;
  const sessionSecret = env.SESSION_SECRET;
  const inviteSecret = env.PARENT_INVITE_SECRET;
  if (
    typeof rpId !== "string"
    || !validRpId(rpId)
    || typeof rpOrigin !== "string"
    || typeof sessionSecret !== "string"
    || !validSecret(sessionSecret)
    || typeof inviteSecret !== "string"
    || !validSecret(inviteSecret)
  ) {
    throw new ParentBffHttpError(503, "webauthn_bff_not_configured");
  }

  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(rpOrigin);
  } catch {
    throw new ParentBffHttpError(503, "webauthn_bff_not_configured");
  }
  if (
    parsedOrigin.protocol !== "https:"
    || parsedOrigin.origin !== rpOrigin
    || parsedOrigin.pathname !== "/"
    || parsedOrigin.search
    || parsedOrigin.hash
    || (parsedOrigin.hostname !== rpId && !parsedOrigin.hostname.endsWith(`.${rpId}`))
  ) {
    throw new ParentBffHttpError(503, "webauthn_bff_not_configured");
  }
  return { rpId, rpOrigin, sessionSecret, inviteSecret };
}

async function handleAuthObjectRoute(
  context: ParentBffContext,
  request: Request,
  config: ParentBffConfig,
): Promise<Response> {
  const pathname = new URL(request.url).pathname;
  if (pathname === "/v1/parent/inbox") requireSameOriginRead(request, config);
  else requireOrigin(request, config);
  if (pathname === "/v1/auth/register/options") {
    requireMethod(request, "POST");
    return registrationOptions(context, request, config);
  }
  if (pathname === "/v1/auth/register/complete") {
    requireMethod(request, "POST");
    return registrationComplete(context, request, config);
  }
  if (pathname === "/v1/auth/login/options") {
    requireMethod(request, "POST");
    return loginOptions(context, request, config);
  }
  if (pathname === "/v1/auth/login/complete") {
    requireMethod(request, "POST");
    return loginComplete(context, request, config);
  }

  const session = await requireSession(context, request, config);
  if (pathname === "/v1/parent/inbox") {
    requireMethod(request, "GET");
    return forwardInbox(context, request, config, session);
  }
  requireMethod(request, "POST");
  requireCsrf(request);
  return forwardApprovalIntent(context, request, config, session);
}

async function registrationOptions(
  context: ParentBffContext,
  request: Request,
  config: ParentBffConfig,
): Promise<Response> {
  const input = await readJsonObject<RegistrationOptionsInput>(request);
  if (
    !validId(input.mailboxId)
    || !validId(input.recipientKeyId)
    || typeof input.inviteSecret !== "string"
    || !validSecret(input.inviteSecret)
  ) {
    throw new ParentBffHttpError(400, "invalid_registration_request");
  }
  if (!constantTimeEqual(await sha256(input.inviteSecret), await sha256(config.inviteSecret))) {
    throw new ParentBffHttpError(403, "registration_forbidden");
  }
  const username = input.username === undefined ? "parent" : input.username;
  const displayName = input.displayName === undefined ? "Guard Parent" : input.displayName;
  if (!validUsername(username) || !validDisplayName(displayName)) {
    throw new ParentBffHttpError(400, "invalid_registration_request");
  }

  cleanupExpiredChallenges(context.sql, null);
  let user = selectUser(context.sql, input.mailboxId, username);
  if (user && user.recipient_key_id !== input.recipientKeyId) {
    throw new ParentBffHttpError(409, "registration_binding_conflict");
  }
  if (!user) {
    const userCount = first(context.sql.exec<{ count: number }>("SELECT count(*) count FROM parent_users"))?.count ?? 0;
    if (userCount >= maximumUsers) throw new ParentBffHttpError(429, "parent_user_limit_reached");
    const userId = randomBytes(32);
    context.sql.exec(
      "INSERT INTO parent_users(user_id,mailbox_id,recipient_key_id,username,display_name,created_at) VALUES(?,?,?,?,?,?)",
      userId,
      input.mailboxId,
      input.recipientKeyId,
      username,
      displayName,
      Date.now(),
    );
    user = selectUser(context.sql, input.mailboxId, username);
    if (!user) throw new ParentBffHttpError(503, "webauthn_bff_unavailable");
  }

  const credentials = [...context.sql.exec<{ credential_id: string; transports: string }>(
    "SELECT credential_id,transports FROM parent_passkeys WHERE user_id=? ORDER BY created_at ASC",
    user.user_id,
  )];
  if (credentials.length >= maximumPasskeysPerUser) {
    throw new ParentBffHttpError(429, "passkey_limit_reached");
  }

  const ceremony = await createChallenge(context, "register", user.user_id);
  const options = await generateRegistrationOptions({
    rpName: "Guard Parent",
    rpID: config.rpId,
    userName: user.username,
    userDisplayName: user.display_name,
    userID: new Uint8Array(user.user_id),
    challenge: base64UrlToBytes(ceremony.challenge),
    timeout: challengeLifetimeMs,
    attestationType: "none",
    supportedAlgorithmIDs: [-7],
    excludeCredentials: credentials.map(item => ({
      id: item.credential_id,
      transports: parseTransports(item.transports),
    })),
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required",
    },
  });
  return jsonResponse({ publicKey: options }, 200, {
    "set-cookie": await signedCookie(ceremonyCookieName, "ceremony", ceremony.id, challengeLifetimeMs, config),
  });
}

async function registrationComplete(
  context: ParentBffContext,
  request: Request,
  config: ParentBffConfig,
): Promise<Response> {
  const credential = parseRegistrationCredential(await readJsonObject<unknown>(request));
  const challenge = await takeChallenge(context, request, "register", config);
  if (!challenge.user_id) throw new ParentBffHttpError(409, "ceremony_not_pending");
  const user = selectUserById(context.sql, challenge.user_id);
  if (!user) throw new ParentBffHttpError(409, "ceremony_not_pending");

  let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: challenge.challenge,
      expectedOrigin: config.rpOrigin,
      expectedRPID: config.rpId,
      expectedType: "webauthn.create",
      requireUserPresence: true,
      requireUserVerification: true,
      supportedAlgorithmIDs: [-7],
    });
  } catch {
    cleanupUnregisteredUser(context.sql, challenge.user_id);
    throw new ParentBffHttpError(400, "webauthn_verification_failed");
  }
  if (!verification.verified || !verification.registrationInfo.userVerified) {
    cleanupUnregisteredUser(context.sql, challenge.user_id);
    throw new ParentBffHttpError(400, "webauthn_verification_failed");
  }
  const registration = verification.registrationInfo;
  const existing = first(context.sql.exec("SELECT 1 FROM parent_passkeys WHERE credential_id=?", registration.credential.id));
  if (existing) {
    cleanupUnregisteredUser(context.sql, challenge.user_id);
    throw new ParentBffHttpError(409, "credential_already_registered");
  }
  const passkeyCount = first(context.sql.exec<{ count: number }>(
    "SELECT count(*) count FROM parent_passkeys WHERE user_id=?",
    user.user_id,
  ))?.count ?? 0;
  if (passkeyCount >= maximumPasskeysPerUser) throw new ParentBffHttpError(429, "passkey_limit_reached");

  const session = await newSession();
  await context.state.storage.transaction(async () => {
    context.sql.exec(
      "INSERT INTO parent_passkeys(credential_id,user_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)",
      registration.credential.id,
      user.user_id,
      registration.credential.publicKey,
      registration.credential.counter,
      JSON.stringify(normalizeTransports(credential.response.transports)),
      registration.credentialDeviceType,
      registration.credentialBackedUp ? 1 : 0,
      Date.now(),
    );
    storeSession(context.sql, user, session);
  });
  return authenticatedResponse(session, config, 201);
}

async function loginOptions(
  context: ParentBffContext,
  request: Request,
  config: ParentBffConfig,
): Promise<Response> {
  if ((await request.arrayBuffer()).byteLength !== 0) {
    throw new ParentBffHttpError(400, "invalid_login_request");
  }
  const ceremony = await createChallenge(context, "login", null);
  const options = await generateAuthenticationOptions({
    rpID: config.rpId,
    challenge: base64UrlToBytes(ceremony.challenge),
    timeout: challengeLifetimeMs,
    userVerification: "required",
  });
  return jsonResponse({ publicKey: options }, 200, {
    "set-cookie": await signedCookie(ceremonyCookieName, "ceremony", ceremony.id, challengeLifetimeMs, config),
  });
}

async function loginComplete(
  context: ParentBffContext,
  request: Request,
  config: ParentBffConfig,
): Promise<Response> {
  const credential = parseAuthenticationCredential(await readJsonObject<unknown>(request));
  const challenge = await takeChallenge(context, request, "login", config);
  const passkey = first(context.sql.exec<PasskeyRow>(
    "SELECT credential_id,user_id,public_key,counter,transports FROM parent_passkeys WHERE credential_id=?",
    credential.id,
  ));
  if (!passkey) throw new ParentBffHttpError(401, "authentication_failed");
  const user = selectUserById(context.sql, passkey.user_id);
  if (!user) throw new ParentBffHttpError(401, "authentication_failed");
  const userHandle = credential.response.userHandle;
  if (
    !userHandle
    || !constantTimeEqual(base64UrlToBytes(userHandle), new Uint8Array(user.user_id))
  ) {
    throw new ParentBffHttpError(401, "authentication_failed");
  }

  let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challenge.challenge,
      expectedOrigin: config.rpOrigin,
      expectedRPID: config.rpId,
      expectedType: "webauthn.get",
      requireUserVerification: true,
      credential: {
        id: passkey.credential_id,
        publicKey: new Uint8Array(passkey.public_key),
        counter: passkey.counter,
        transports: parseTransports(passkey.transports),
      },
    });
  } catch {
    throw new ParentBffHttpError(401, "authentication_failed");
  }
  if (!verification.verified || !verification.authenticationInfo.userVerified) {
    throw new ParentBffHttpError(401, "authentication_failed");
  }

  const session = await newSession();
  await context.state.storage.transaction(async () => {
    const current = first(context.sql.exec<{ counter: number }>(
      "SELECT counter FROM parent_passkeys WHERE credential_id=?",
      passkey.credential_id,
    ));
    if (!current || current.counter !== passkey.counter) {
      throw new ParentBffHttpError(409, "credential_counter_conflict");
    }
    context.sql.exec(
      "UPDATE parent_passkeys SET counter=?,device_type=?,backed_up=? WHERE credential_id=?",
      verification.authenticationInfo.newCounter,
      verification.authenticationInfo.credentialDeviceType,
      verification.authenticationInfo.credentialBackedUp ? 1 : 0,
      passkey.credential_id,
    );
    storeSession(context.sql, user, session);
  });
  return authenticatedResponse(session, config, 200);
}

async function requireSession(
  context: ParentBffContext,
  request: Request,
  config: ParentBffConfig,
): Promise<SessionRow> {
  const cookie = singleCookie(request.headers.get("cookie"), sessionCookieName);
  const parsed = cookie ? parseSignedValue(cookie) : null;
  if (!parsed || !await validSignedValue("session", parsed.value, parsed.mac, config)) {
    throw new ParentBffHttpError(401, "authentication_required");
  }
  const tokenHash = await sha256(parsed.value);
  const session = first(context.sql.exec<SessionRow>(
    "SELECT user_id,mailbox_id,recipient_key_id,expires_at FROM parent_sessions WHERE token_hash=? AND expires_at>?",
    tokenHash,
    Date.now(),
  ));
  if (!session || !validId(session.mailbox_id) || !validId(session.recipient_key_id)) {
    throw new ParentBffHttpError(401, "authentication_required");
  }
  return session;
}

function requireCsrf(request: Request): void {
  if (request.headers.get("x-guard-csrf") !== "1") throw new ParentBffHttpError(403, "csrf_rejected");
}

async function forwardInbox(
  context: ParentBffContext,
  request: Request,
  config: ParentBffConfig,
  session: SessionRow,
): Promise<Response> {
  const source = new URL(request.url);
  const after = parseNatural(source.searchParams.get("after") ?? "0");
  const limit = Math.min(parseNatural(source.searchParams.get("limit") ?? "20"), maximumPoll);
  if (after < 0 || limit < 1) throw new ParentBffHttpError(400, "invalid_poll");
  const target = new URL("https://mailbox.internal/internal/bff/inbox");
  target.searchParams.set("recipient", session.recipient_key_id);
  target.searchParams.set("after", String(after));
  target.searchParams.set("limit", String(limit));
  return forwardToMailbox(context, config, session.mailbox_id, target, "GET");
}

async function forwardApprovalIntent(
  context: ParentBffContext,
  request: Request,
  config: ParentBffConfig,
  session: SessionRow,
): Promise<Response> {
  const input = await readJsonObject<ApprovalIntentInput>(request);
  if (!validId(input.requestId) || !validApproval(input)) {
    throw new ParentBffHttpError(400, "invalid_approval_intent");
  }
  /*
   * The selected action is intentionally not forwarded or stored. The locator
   * only lets Android find the exact pending request; Android must show it again
   * and obtain a fresh biometric-confirmed decision.
   */
  return forwardToMailbox(
    context,
    config,
    session.mailbox_id,
    new URL("https://mailbox.internal/internal/bff/approval-intents"),
    "POST",
    JSON.stringify({ requestId: input.requestId }),
  );
}

async function forwardToMailbox(
  context: ParentBffContext,
  config: ParentBffConfig,
  mailboxId: string,
  url: URL,
  method: "GET" | "POST",
  body?: string,
): Promise<Response> {
  const headers = new Headers();
  headers.set(internalHeaderName, await internalProof(config, `mailbox:${mailboxId}`));
  if (body !== undefined) headers.set("content-type", "application/json");
  const stub = context.env.DEVICE_MAILBOX.get(context.env.DEVICE_MAILBOX.idFromName(mailboxId));
  return stub.fetch(new Request(url, { method, headers, body }));
}

function mailboxInbox(context: ParentBffContext, request: Request): Response {
  requireMethod(request, "GET");
  const url = new URL(request.url);
  const recipient = url.searchParams.get("recipient");
  const after = parseNatural(url.searchParams.get("after") ?? "0");
  const limit = Math.min(parseNatural(url.searchParams.get("limit") ?? "20"), maximumPoll);
  if (!validId(recipient) || after < 0 || limit < 1) {
    throw new ParentBffHttpError(400, "invalid_poll");
  }
  const rows = [...context.sql.exec<{ frame_id: string; bytes: ArrayBuffer; cursor: number; size: number }>(
    "SELECT frame_id,bytes,cursor,size FROM frames WHERE recipient_key_id=? AND kind=1 AND cursor>? AND expires_at>? ORDER BY cursor ASC LIMIT ?",
    recipient,
    after,
    Date.now(),
    limit,
  )];
  const snapshots = rows.map(row => {
    const bytes = new Uint8Array(row.bytes);
    if (bytes.byteLength !== row.size || bytes.byteLength > MAX_FRAME_BYTES) {
      throw new ParentBffHttpError(503, "mailbox_frame_corrupt");
    }
    let parsed;
    try {
      parsed = parseRelayFrame(bytes);
    } catch {
      throw new ParentBffHttpError(503, "mailbox_frame_corrupt");
    }
    const createdAt = Number(parsed.createdAt);
    if (
      parsed.frameId !== row.frame_id
      || parsed.recipientKeyId !== recipient
      || parsed.cursor !== BigInt(row.cursor)
      || parsed.mailboxId !== context.state.id.name
      || !Number.isSafeInteger(createdAt)
      || Number.isNaN(new Date(createdAt).valueOf())
    ) {
      throw new ParentBffHttpError(503, "mailbox_frame_corrupt");
    }
    return {
      frameId: parsed.frameId,
      frame: bytesToBase64Url(bytes),
      receivedAt: new Date(createdAt).toISOString(),
    };
  });
  return jsonResponse(snapshots);
}

async function mailboxApprovalIntent(context: ParentBffContext, request: Request): Promise<Response> {
  requireMethod(request, "POST");
  const input = await readJsonObject<{ requestId?: unknown }>(request);
  if (!validId(input.requestId)) throw new ParentBffHttpError(400, "invalid_approval_intent");
  const count = first(context.sql.exec<{ count: number }>(
    "SELECT count(*) count FROM parent_locators WHERE expires_at>?",
    Date.now(),
  ))?.count ?? 0;
  if (count >= maximumLocatorsPerMailbox) throw new ParentBffHttpError(429, "approval_locator_limit_reached");

  const locator = randomBase64Url(32);
  const locatorHash = await sha256(locator);
  const requestIdHash = await sha256(input.requestId);
  const expiresAt = Date.now() + locatorLifetimeMs;
  context.sql.exec(
    "INSERT INTO parent_locators(locator_hash,request_id_hash,expires_at,created_at) VALUES(?,?,?,?)",
    locatorHash,
    requestIdHash,
    expiresAt,
    Date.now(),
  );
  return jsonResponse({
    locator,
    expiresAt: new Date(expiresAt).toISOString(),
    nonAuthoritative: true,
    confirmationRequiredOnAndroid: true,
  }, 201);
}

async function createChallenge(
  context: ParentBffContext,
  purpose: "register" | "login",
  userId: ArrayBuffer | null,
): Promise<{ id: string; challenge: string }> {
  cleanupExpiredChallenges(context.sql, userId);
  const active = first(context.sql.exec<{ count: number }>(
    "SELECT count(*) count FROM webauthn_challenges WHERE expires_at>?",
    Date.now(),
  ))?.count ?? 0;
  if (active >= maximumActiveChallenges) throw new ParentBffHttpError(429, "ceremony_limit_reached");
  const id = randomBase64Url(32);
  const challenge = randomBase64Url(32);
  context.sql.exec(
    "INSERT INTO webauthn_challenges(ceremony_id,purpose,user_id,challenge,expires_at,created_at) VALUES(?,?,?,?,?,?)",
    id,
    purpose,
    userId,
    challenge,
    Date.now() + challengeLifetimeMs,
    Date.now(),
  );
  return { id, challenge };
}

async function takeChallenge(
  context: ParentBffContext,
  request: Request,
  expectedPurpose: "register" | "login",
  config: ParentBffConfig,
): Promise<ChallengeRow> {
  const cookie = singleCookie(request.headers.get("cookie"), ceremonyCookieName);
  const parsed = cookie ? parseSignedValue(cookie) : null;
  if (!parsed || !await validSignedValue("ceremony", parsed.value, parsed.mac, config)) {
    throw new ParentBffHttpError(409, "ceremony_not_pending");
  }
  return context.state.storage.transaction(async () => {
    const challenge = first(context.sql.exec<ChallengeRow>(
      "SELECT purpose,user_id,challenge,expires_at FROM webauthn_challenges WHERE ceremony_id=?",
      parsed.value,
    ));
    if (!challenge) throw new ParentBffHttpError(409, "ceremony_not_pending");
    context.sql.exec("DELETE FROM webauthn_challenges WHERE ceremony_id=?", parsed.value);
    if (challenge.expires_at <= Date.now()) {
      cleanupUnregisteredUser(context.sql, challenge.user_id);
      throw new ParentBffHttpError(410, "ceremony_expired");
    }
    if (challenge.purpose !== expectedPurpose) {
      cleanupUnregisteredUser(context.sql, challenge.user_id);
      throw new ParentBffHttpError(409, "ceremony_not_pending");
    }
    return challenge;
  });
}

function selectUser(sql: SqlStorage, mailboxId: string, username: string): ParentUserRow | undefined {
  return first(sql.exec<ParentUserRow>(
    "SELECT user_id,mailbox_id,recipient_key_id,username,display_name FROM parent_users WHERE mailbox_id=? AND username=?",
    mailboxId,
    username,
  ));
}

function selectUserById(sql: SqlStorage, userId: ArrayBuffer): ParentUserRow | undefined {
  return first(sql.exec<ParentUserRow>(
    "SELECT user_id,mailbox_id,recipient_key_id,username,display_name FROM parent_users WHERE user_id=?",
    userId,
  ));
}

function cleanupUnregisteredUser(sql: SqlStorage, userId: ArrayBuffer | null): void {
  if (!userId) return;
  const passkey = first(sql.exec("SELECT 1 FROM parent_passkeys WHERE user_id=? LIMIT 1", userId));
  const pending = first(sql.exec("SELECT 1 FROM webauthn_challenges WHERE user_id=? LIMIT 1", userId));
  if (!passkey && !pending) sql.exec("DELETE FROM parent_users WHERE user_id=?", userId);
}

function cleanupExpiredChallenges(sql: SqlStorage, protectedUserId: ArrayBuffer | null): void {
  const now = Date.now();
  const expiredUsers = [...sql.exec<{ user_id: ArrayBuffer }>(
    "SELECT user_id FROM webauthn_challenges WHERE expires_at<=? AND user_id IS NOT NULL",
    now,
  )];
  sql.exec("DELETE FROM webauthn_challenges WHERE expires_at<=?", now);
  for (const expired of expiredUsers) {
    if (
      !protectedUserId
      || !constantTimeEqual(new Uint8Array(expired.user_id), new Uint8Array(protectedUserId))
    ) {
      cleanupUnregisteredUser(sql, expired.user_id);
    }
  }
}

async function newSession(): Promise<NewSession> {
  const token = randomBase64Url(32);
  return {
    token,
    tokenHash: await sha256(token),
    expiresAt: Date.now() + sessionLifetimeMs,
  };
}

function storeSession(sql: SqlStorage, user: ParentUserRow, session: NewSession): void {
  const current = first(sql.exec<{ count: number }>(
    "SELECT count(*) count FROM parent_sessions WHERE user_id=? AND expires_at>?",
    user.user_id,
    Date.now(),
  ))?.count ?? 0;
  const remove = current - maximumSessionsPerUser + 1;
  if (remove > 0) {
    sql.exec(
      "DELETE FROM parent_sessions WHERE token_hash IN (SELECT token_hash FROM parent_sessions WHERE user_id=? ORDER BY created_at ASC LIMIT ?)",
      user.user_id,
      remove,
    );
  }
  sql.exec(
    "INSERT INTO parent_sessions(token_hash,user_id,mailbox_id,recipient_key_id,expires_at,created_at) VALUES(?,?,?,?,?,?)",
    session.tokenHash,
    user.user_id,
    user.mailbox_id,
    user.recipient_key_id,
    session.expiresAt,
    Date.now(),
  );
}

async function authenticatedResponse(
  session: NewSession,
  config: ParentBffConfig,
  status: number,
): Promise<Response> {
  const response = jsonResponse({ verified: true }, status);
  response.headers.append(
    "set-cookie",
    expireCookie(ceremonyCookieName),
  );
  response.headers.append(
    "set-cookie",
    await signedCookie(sessionCookieName, "session", session.token, sessionLifetimeMs, config),
  );
  return response;
}

function parseRegistrationCredential(value: unknown): RegistrationResponseJSON {
  if (!isRecord(value) || !baseCredentialShape(value)) {
    throw new ParentBffHttpError(400, "invalid_webauthn_response");
  }
  const response = value.response;
  if (
    !isRecord(response)
    || !validBase64Url(response.clientDataJSON, 1, 8192)
    || !validBase64Url(response.attestationObject, 1, 65536)
    || (response.transports !== undefined && !validTransports(response.transports))
  ) {
    throw new ParentBffHttpError(400, "invalid_webauthn_response");
  }
  return value as unknown as RegistrationResponseJSON;
}

function parseAuthenticationCredential(value: unknown): AuthenticationResponseJSON {
  if (!isRecord(value) || !baseCredentialShape(value)) {
    throw new ParentBffHttpError(400, "invalid_webauthn_response");
  }
  const response = value.response;
  if (
    !isRecord(response)
    || !validBase64Url(response.clientDataJSON, 1, 8192)
    || !validBase64Url(response.authenticatorData, 1, 4096)
    || !validBase64Url(response.signature, 1, 4096)
    || (response.userHandle !== undefined && response.userHandle !== null && !validBase64Url(response.userHandle, 1, 2048))
  ) {
    throw new ParentBffHttpError(400, "invalid_webauthn_response");
  }
  const normalized = structuredClone(value) as Record<string, unknown>;
  const normalizedResponse = normalized.response as Record<string, unknown>;
  if (normalizedResponse.userHandle === null) delete normalizedResponse.userHandle;
  return normalized as unknown as AuthenticationResponseJSON;
}

function baseCredentialShape(value: Record<string, unknown>): boolean {
  return (
    validBase64Url(value.id, 1, 2048)
    && value.rawId === value.id
    && value.type === "public-key"
    && isRecord(value.clientExtensionResults)
    && isRecord(value.response)
  );
}

async function readJsonObject<T>(request: Request): Promise<T> {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/.test(contentType)) {
    throw new ParentBffHttpError(415, "json_content_type_required");
  }
  const declared = request.headers.get("content-length");
  if (declared && (!/^[0-9]+$/.test(declared) || Number(declared) > maxJsonBytes)) {
    throw new ParentBffHttpError(413, "request_too_large");
  }
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength === 0 || bytes.byteLength > maxJsonBytes) {
    throw new ParentBffHttpError(bytes.byteLength === 0 ? 400 : 413, bytes.byteLength === 0 ? "invalid_json" : "request_too_large");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new ParentBffHttpError(400, "invalid_json");
  }
  if (!isRecord(parsed)) throw new ParentBffHttpError(400, "invalid_json");
  return parsed as T;
}

function requireOrigin(request: Request, config: ParentBffConfig): void {
  if (request.headers.get("origin") !== config.rpOrigin) {
    throw new ParentBffHttpError(403, "origin_rejected");
  }
}

function requireSameOriginRead(request: Request, config: ParentBffConfig): void {
  const origin = request.headers.get("origin");
  if (origin === config.rpOrigin) return;
  if (origin === null && request.headers.get("sec-fetch-site") === "same-origin") return;
  throw new ParentBffHttpError(403, "origin_rejected");
}

function requireMethod(request: Request, expected: "GET" | "POST"): void {
  if (request.method !== expected) throw new ParentBffHttpError(405, "method_not_allowed");
}

function validApproval(input: ApprovalIntentInput): boolean {
  if (!["AllowAlways", "AllowTemporary", "AllowDailyQuota", "Deny"].includes(String(input.kind))) return false;
  if (input.kind === "AllowTemporary") {
    return Number.isSafeInteger(input.minutes) && Number(input.minutes) >= 5 && Number(input.minutes) <= 240;
  }
  if (input.kind === "AllowDailyQuota") {
    return Number.isSafeInteger(input.minutes) && Number(input.minutes) >= 15 && Number(input.minutes) <= 480;
  }
  return input.minutes === undefined;
}

function validUsername(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$/.test(value);
}

function validDisplayName(value: unknown): value is string {
  return typeof value === "string"
    && value.trim() === value
    && value.length > 0
    && new TextEncoder().encode(value).byteLength <= 128;
}

function validId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value);
}

function validRpId(value: string): boolean {
  return value.length <= 253
    && value === value.toLowerCase()
    && /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(value);
}

function validSecret(value: string): boolean {
  return value.length >= 32 && value.length <= 512;
}

function validBase64Url(value: unknown, minimumBytes: number, maximumBytes: number): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  const approximateBytes = Math.floor(value.length * 3 / 4);
  return approximateBytes >= minimumBytes && approximateBytes <= maximumBytes;
}

function validTransports(value: unknown): value is AuthenticatorTransportFuture[] {
  return Array.isArray(value)
    && value.length <= allowedTransports.size
    && value.every(item => typeof item === "string" && allowedTransports.has(item as AuthenticatorTransportFuture));
}

function normalizeTransports(value: unknown): AuthenticatorTransportFuture[] {
  if (!validTransports(value)) return [];
  return [...new Set(value)];
}

function parseTransports(value: string): AuthenticatorTransportFuture[] {
  try {
    return normalizeTransports(JSON.parse(value));
  } catch {
    return [];
  }
}

function parseNatural(value: string): number {
  if (!/^[0-9]+$/.test(value)) return -1;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : -1;
}

function first<T extends Record<string, SqlStorageValue>>(cursor: SqlStorageCursor<T>): T | undefined {
  return [...cursor][0];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sanitizedHeaders(source: Headers): Headers {
  const result = new Headers(source);
  const names: string[] = [];
  result.forEach((_value, name) => names.push(name));
  for (const name of names) {
    if (name.toLowerCase().startsWith("x-guard-bff-")) result.delete(name);
  }
  result.delete("authorization");
  return result;
}

async function requireInternalProof(request: Request, config: ParentBffConfig, purpose: string): Promise<void> {
  const actual = request.headers.get(internalHeaderName);
  const expected = await internalProof(config, purpose);
  if (!actual || !constantTimeEqual(new TextEncoder().encode(actual), new TextEncoder().encode(expected))) {
    throw new ParentBffHttpError(404, "not_found");
  }
}

async function internalProof(config: ParentBffConfig, purpose: string): Promise<string> {
  return hmac(config.sessionSecret, `guard-parent-bff-internal-v1\n${purpose}`);
}

async function signedCookie(
  name: string,
  purpose: "ceremony" | "session",
  value: string,
  lifetimeMs: number,
  config: ParentBffConfig,
): Promise<string> {
  const mac = await hmac(config.sessionSecret, `guard-parent-bff-cookie-v1\n${purpose}\n${value}`);
  return `${name}=v1.${value}.${mac}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.floor(lifetimeMs / 1000)}`;
}

function expireCookie(name: string): string {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

function singleCookie(header: string | null, name: string): string | null {
  if (!header) return null;
  const values = header
    .split(";")
    .map(item => item.trim())
    .filter(item => item.startsWith(`${name}=`))
    .map(item => item.slice(name.length + 1));
  return values.length === 1 ? values[0]! : null;
}

function parseSignedValue(value: string): { value: string; mac: string } | null {
  const match = /^v1\.([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{43})$/.exec(value);
  return match ? { value: match[1]!, mac: match[2]! } : null;
}

async function validSignedValue(
  purpose: "ceremony" | "session",
  value: string,
  mac: string,
  config: ParentBffConfig,
): Promise<boolean> {
  const expected = await hmac(config.sessionSecret, `guard-parent-bff-cookie-v1\n${purpose}\n${value}`);
  return constantTimeEqual(new TextEncoder().encode(mac), new TextEncoder().encode(expected));
}

async function hmac(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value))));
}

async function sha256(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
}

function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

function randomBase64Url(length: number): string {
  return bytesToBase64Url(randomBytes(length));
}

function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const decoded = atob(padded);
  const result = new Uint8Array(decoded.length);
  for (let index = 0; index < decoded.length; index++) result[index] = decoded.charCodeAt(index);
  return result;
}

function bytesToBase64(bytes: Uint8Array): string {
  let value = "";
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let different = 0;
  for (let index = 0; index < a.length; index++) different |= a[index]! ^ b[index]!;
  return different === 0;
}

function jsonResponse(
  body: unknown,
  status = 200,
  additionalHeaders?: Record<string, string>,
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...jsonHeaders, ...additionalHeaders },
  });
}

function bffFailure(error: unknown): Response {
  if (error instanceof ParentBffHttpError) return jsonResponse({ error: error.code }, error.status);
  return jsonResponse({ error: "webauthn_bff_unavailable" }, 503);
}
