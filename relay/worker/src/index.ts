import { FrameError, isGuardIdentifier as validId, MAX_FRAME_BYTES, parseRelayFrame, type RelayFrame } from "./frame";
import { readBoundedBody, RequestBodyError } from "./bounded-body";
import { handleEnrollment, MAX_ENROLLMENT_BYTES, migrateEnrollment } from "./enrollment";
import {
  BFF_AUTH_OBJECT_NAME,
  forwardParentBff,
  forwardRegistrationTicket,
  handleParentBffRequest,
  isParentBffPath,
  type ParentBffEnv,
} from "./bff";

export interface Env extends ParentBffEnv { BOOTSTRAP_ADMIN_TOKEN?: string; }
type Role = "admin" | "device" | "approval" | "reader";
const roles: readonly Role[] = ["admin", "device", "approval", "reader"];
const maxPoll = 50;
const headers = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "cross-origin-resource-policy": "same-origin" };
const json = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), { status, headers });
const fail = (status: number, code: string): Response => json({ error: code }, status);
const tokenFrom = (request: Request): string | null => { const value = request.headers.get("authorization"); return value?.startsWith("Bearer ") && value.length > 7 ? value.slice(7) : null; };
// The global authentication DO shares this namespace, but must never be a public mailbox.
const validMailboxId = (value: unknown): value is string => validId(value) && value !== BFF_AUTH_OBJECT_NAME;
const mailboxPath = (pathname: string): string | null => {
  const id = /^\/v1\/mailboxes\/([^/]+)(?:\/|$)/u.exec(pathname)?.[1];
  return validMailboxId(id) ? id : null;
};

async function forward(env: Env, mailboxId: string, request: Request, token: string | null, bootstrap = false): Promise<Response> {
  const id = env.DEVICE_MAILBOX.idFromName(mailboxId);
  const copy = new Headers(request.headers); if (token) copy.set("x-guard-token", token); if (bootstrap) copy.set("x-guard-bootstrap", "1");
  copy.delete("content-length");
  const body = request.method === "GET" || request.method === "HEAD" ? undefined :
    await readBoundedBody(request, request.method === "POST" && /^\/v1\/mailboxes\/[^/]+\/enrollments\/[a-f0-9]{64}\/requests$/.test(new URL(request.url).pathname) ? MAX_ENROLLMENT_BYTES : MAX_FRAME_BYTES);
  return env.DEVICE_MAILBOX.get(id).fetch(new Request(`https://mailbox.internal${new URL(request.url).pathname}${new URL(request.url).search}`, { method: request.method, headers: copy, body }));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return fail(405, "method_not_allowed");
    if (url.pathname === "/v1/admin/bootstrap" && request.method === "POST") {
      const bootstrap = tokenFrom(request); if (!env.BOOTSTRAP_ADMIN_TOKEN || !bootstrap || !constantTimeEqual(await sha256(bootstrap), await sha256(env.BOOTSTRAP_ADMIN_TOKEN))) return fail(403, "bootstrap_forbidden");
      const body = await readJsonObject(request);
      if (!validMailboxId(body.mailboxId) || !validToken(body.accessToken)) return fail(400, "invalid_bootstrap");
      return await forward(env, body.mailboxId, new Request(request.url, { method: "POST", headers: request.headers, body: JSON.stringify(body) }), bootstrap, true);
    }
    if (isParentBffPath(url.pathname)) return forwardParentBff(request, env);
    const mailboxId = mailboxPath(url.pathname); if (!mailboxId) return fail(404, "not_found");
    const token = tokenFrom(request); if (!token || !validToken(token)) return fail(401, "authentication_required");
    return await forward(env, mailboxId, request, token);
    } catch (error) {
      if (error instanceof RelayHttpError || error instanceof RequestBodyError) return fail(error.status, error.code);
      return fail(503, "relay_unavailable");
    }
  }
} satisfies ExportedHandler<Env>;

function validToken(value: unknown): value is string { return typeof value === "string" && /^[!-~]{32,512}$/.test(value); }
async function sha256(value: string): Promise<Uint8Array> { return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))); }
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean { if (a.length !== b.length) return false; let result = 0; for (let i = 0; i < a.length; i++) result |= a[i]! ^ b[i]!; return result === 0; }

export class DeviceMailbox implements DurableObject {
  private readonly sql: SqlStorage;
  constructor(readonly state: DurableObjectState, readonly env: Env) { this.sql = state.storage.sql; state.blockConcurrencyWhile(async () => this.migrate()); }
  private migrate(): void {
    migrateEnrollment(this.sql);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS tokens(hash BLOB PRIMARY KEY, role TEXT NOT NULL, expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS frames(frame_id TEXT PRIMARY KEY, recipient_key_id TEXT NOT NULL, kind INTEGER NOT NULL, cursor INTEGER NOT NULL, expires_at INTEGER NOT NULL, bytes BLOB NOT NULL, size INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS frames_recipient_cursor ON frames(recipient_key_id,cursor);
      CREATE TABLE IF NOT EXISTS acknowledgements(recipient_key_id TEXT PRIMARY KEY, cursor INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS sequence_floors(authority_epoch INTEGER NOT NULL,key_id TEXT NOT NULL,floor INTEGER NOT NULL,PRIMARY KEY(authority_epoch,key_id));
      CREATE TABLE IF NOT EXISTS intents(authority_epoch INTEGER NOT NULL,key_id TEXT NOT NULL,sequence INTEGER NOT NULL,status TEXT NOT NULL,intent_id TEXT NOT NULL,expires_at INTEGER NOT NULL,PRIMARY KEY(authority_epoch,key_id));
      CREATE TABLE IF NOT EXISTS idempotency(token_hash BLOB NOT NULL,request_id TEXT NOT NULL,status INTEGER NOT NULL,response TEXT NOT NULL,expires_at INTEGER NOT NULL,PRIMARY KEY(token_hash,request_id));
      CREATE TABLE IF NOT EXISTS tombstones(frame_id TEXT PRIMARY KEY,expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS parent_users(user_id BLOB PRIMARY KEY,mailbox_id TEXT NOT NULL,recipient_key_id TEXT NOT NULL,username TEXT NOT NULL,display_name TEXT NOT NULL,created_at INTEGER NOT NULL,UNIQUE(mailbox_id,username));
      CREATE TABLE IF NOT EXISTS parent_passkeys(credential_id TEXT PRIMARY KEY,user_id BLOB NOT NULL,public_key BLOB NOT NULL,counter INTEGER NOT NULL,transports TEXT NOT NULL,device_type TEXT NOT NULL,backed_up INTEGER NOT NULL,created_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS parent_passkeys_user ON parent_passkeys(user_id);
      CREATE TABLE IF NOT EXISTS webauthn_challenges(ceremony_id TEXT PRIMARY KEY,purpose TEXT NOT NULL,user_id BLOB,challenge TEXT NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS webauthn_challenges_expiry ON webauthn_challenges(expires_at);
      CREATE TABLE IF NOT EXISTS parent_sessions(token_hash BLOB PRIMARY KEY,user_id BLOB NOT NULL,mailbox_id TEXT NOT NULL,recipient_key_id TEXT NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS parent_sessions_user_expiry ON parent_sessions(user_id,expires_at);
      CREATE TABLE IF NOT EXISTS parent_locators(locator_hash BLOB PRIMARY KEY,request_id_hash BLOB NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL);
      CREATE INDEX IF NOT EXISTS parent_locators_expiry ON parent_locators(expires_at);`);
    const addedColumns = {
      tokens: { recipient_key_id: "TEXT", publish_recipient_key_ids: "TEXT", approval_key_id: "TEXT", authority_epoch: "INTEGER", view_recipient_key_ids: "TEXT" },
      webauthn_challenges: { registration_ticket_hash: "BLOB" },
      parent_locators: { view_recipient_key_id: "TEXT" },
      tombstones: { recipient_key_id: "TEXT", cursor: "INTEGER", frame_hash: "BLOB" },
    };
    for (const [table, columns] of Object.entries(addedColumns)) {
      const existing = new Set([...this.sql.exec<{ name: string }>(`PRAGMA table_info(${table})`)].map(row => row.name));
      for (const [column, type] of Object.entries(columns))
        if (!existing.has(column)) this.sql.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
    }
    // Retain initial intents through their original expiry, including after token revocation.
    this.sql.exec("CREATE TABLE IF NOT EXISTS initial_device_tokens(hash BLOB PRIMARY KEY,recipient_key_id TEXT NOT NULL,expires_at INTEGER NOT NULL)");
    this.sql.exec(`CREATE TABLE IF NOT EXISTS parent_registration_tickets(ticket_hash BLOB PRIMARY KEY,mailbox_id TEXT NOT NULL,recipient_key_id TEXT NOT NULL,username TEXT NOT NULL,display_name TEXT NOT NULL,expires_at INTEGER NOT NULL,UNIQUE(mailbox_id,username));
      CREATE TABLE IF NOT EXISTS publication_cursors(recipient_key_id TEXT PRIMARY KEY,cursor INTEGER NOT NULL);
      INSERT INTO publication_cursors(recipient_key_id,cursor)
      SELECT recipient_key_id,max(cursor) FROM (SELECT recipient_key_id,cursor FROM frames UNION ALL SELECT recipient_key_id,cursor FROM acknowledgements) GROUP BY recipient_key_id
      ON CONFLICT(recipient_key_id) DO UPDATE SET cursor=max(cursor,excluded.cursor);`);
  }
  async fetch(request: Request): Promise<Response> {
    try { this.cleanup(); const path = new URL(request.url).pathname;
      const bffResponse = await handleParentBffRequest({ state: this.state, sql: this.sql, env: this.env }, request);
      if (bffResponse) return bffResponse;
      if (request.headers.get("x-guard-bootstrap") === "1" && path === "/v1/admin/bootstrap") return await this.bootstrap(request);
      const enrollmentResponse = await handleEnrollment(request, this.state, () => this.authenticate(request));
      if (enrollmentResponse) return enrollmentResponse;
      const auth = await this.authenticate(request); if (!auth) return fail(401, "authentication_required");
      this.requireCurrentAuth(auth);
      const prefix = `/v1/mailboxes/${this.state.id.name}`;
      if (path === `${prefix}/registration-tickets` && (request.method === "POST" || request.method === "DELETE")) {
        if (auth.role !== "admin") throw new RelayHttpError(403, "role_forbidden");
        return await forwardRegistrationTicket(request, this.env, this.state.id.name!);
      }
      if (path === `${prefix}/frames` && request.method === "POST") return await this.publish(request, auth);
      if (path === `${prefix}/poll` && request.method === "GET") return this.poll(request, auth);
      if (path === `${prefix}/ack` && request.method === "POST") return await this.ack(request, auth);
      if (path === `${prefix}/tokens` && request.method === "POST") return await this.provisionToken(request, auth);
      if (path === `${prefix}/tokens/initial` && request.method === "POST") return await this.provisionToken(request, auth, true);
      if (path === `${prefix}/tokens` && request.method === "DELETE") return await this.revokeToken(request, auth);
      if (path === `${prefix}/locators/redeem` && request.method === "POST") return await this.redeemLocator(request, auth);
      if (path === `${prefix}/intents/reserve` && request.method === "POST") return await this.intent(request, auth, "reserve");
      if (path === `${prefix}/intents/finalize` && request.method === "POST") return await this.intent(request, auth, "finalize");
      if (path === `${prefix}/intents/cancel` && request.method === "POST") return await this.intent(request, auth, "cancel");
      if (path === `${prefix}/intents` && request.method === "GET") return this.getIntent(request, auth);
      return fail(404, "not_found");
    } catch (error) { if (error instanceof RelayHttpError || error instanceof RequestBodyError) return fail(error.status, error.code); return fail(503, "relay_unavailable"); }
  }
  private cleanup(): void {
    const now = Date.now();
    this.sql.exec("DELETE FROM frames WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM tokens WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM initial_device_tokens WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM idempotency WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM tombstones WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM intents WHERE expires_at <= ? AND status != 'pending'", now);
    this.sql.exec("DELETE FROM parent_sessions WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM parent_locators WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM parent_registration_tickets WHERE expires_at <= ?", now);
  }
  private async bootstrap(request: Request): Promise<Response> { const body = await readJsonObject(request); if (!validToken(body.accessToken)) return fail(400, "invalid_bootstrap"); const hash = await sha256(body.accessToken); const exists = [...this.sql.exec("SELECT 1 FROM tokens LIMIT 1")].length > 0; if (exists) return fail(409, "already_bootstrapped"); this.sql.exec("INSERT INTO tokens(hash,role,expires_at) VALUES(?,?,?)", hash.buffer, "admin", Date.now() + 365 * 86400000); return json({ role: "admin" }, 201); }
  private async provisionToken(request: Request, auth: Auth, initialOnly = false): Promise<Response> {
    if (auth.role !== "admin") throw new RelayHttpError(403, "role_forbidden");
    const body = await readJsonObject(request);
    const scope = tokenScope(body.role, body);
    if (!validToken(body.accessToken) || !scope || typeof body.expiresAt !== "number" ||
      !Number.isSafeInteger(body.expiresAt) || body.expiresAt <= Date.now()) throw new RelayHttpError(400, "invalid_token_provisioning");
    if (initialOnly && (scope.role !== "device" || scope.publishRecipientKeyIds.length !== 0 ||
      Object.keys(body).length !== 5 || Object.keys(body).some(name =>
        !["accessToken", "role", "expiresAt", "recipientKeyId", "publishRecipientKeyIds"].includes(name))))
      throw new RelayHttpError(400, "invalid_initial_device_token");
    const expiresAt = body.expiresAt;
    const hash = await sha256(body.accessToken);
    return this.state.storage.transactionSync(() => {
      this.requireCurrentAuth(auth);
      if (expiresAt <= Date.now()) throw new RelayHttpError(400, "invalid_token_provisioning");
      if ([...this.sql.exec("SELECT 1 FROM enrollments WHERE token_hash=?", hash.buffer)].length)
        throw new RelayHttpError(409, "enrollment_token_conflict");
      const existing = [...this.sql.exec<{ expires_at: number }>("SELECT expires_at FROM tokens WHERE hash=?", hash.buffer)][0];
      if (initialOnly) {
        const initial = [...this.sql.exec<{ recipient_key_id: string; expires_at: number }>(
          "SELECT recipient_key_id,expires_at FROM initial_device_tokens WHERE hash=?", hash.buffer)][0];
        if (initial) {
          const current = this.findAuth(hash);
          if (initial.recipient_key_id !== scope.recipientKeyId || initial.expires_at !== expiresAt ||
            !existing || existing.expires_at !== expiresAt || !current || current.role !== "device" ||
            current.recipientKeyId !== scope.recipientKeyId || current.publishRecipientKeyIds.length !== 0 ||
            current.approvalKeyId !== null || current.authorityEpoch !== null || current.viewRecipientKeyIds.length !== 0)
            throw new RelayHttpError(409, "initial_device_token_conflict");
          return json({ role: "device", expiresAt }, 201); // Exact retry is read-only, never an upsert.
        }
        if (existing) throw new RelayHttpError(409, "initial_device_token_conflict");
        if ([...this.sql.exec<{ n: number }>("SELECT count(*) n FROM initial_device_tokens")][0]!.n >= 256)
          throw new RelayHttpError(429, "initial_device_token_limit_reached");
      }
      if (!existing && [...this.sql.exec<{ n: number }>("SELECT count(*) n FROM tokens")][0]!.n >= 256)
        throw new RelayHttpError(429, "token_limit_reached");
      if (initialOnly) this.sql.exec("INSERT INTO initial_device_tokens(hash,recipient_key_id,expires_at) VALUES(?,?,?)",
        hash.buffer, scope.recipientKeyId, expiresAt);
      this.sql.exec(`INSERT INTO tokens(hash,role,expires_at,recipient_key_id,publish_recipient_key_ids,approval_key_id,authority_epoch,view_recipient_key_ids)
        VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(hash) DO UPDATE SET role=excluded.role,expires_at=excluded.expires_at,
        recipient_key_id=excluded.recipient_key_id,publish_recipient_key_ids=excluded.publish_recipient_key_ids,
        approval_key_id=excluded.approval_key_id,authority_epoch=excluded.authority_epoch,view_recipient_key_ids=excluded.view_recipient_key_ids`,
        hash.buffer, scope.role, expiresAt, scope.recipientKeyId, JSON.stringify(scope.publishRecipientKeyIds),
        scope.approvalKeyId, scope.authorityEpoch, JSON.stringify(scope.viewRecipientKeyIds));
      return json({ role: scope.role, expiresAt }, 201);
    });
  }
  private async revokeToken(request: Request, auth: Auth): Promise<Response> { if (auth.role !== "admin") throw new RelayHttpError(403, "role_forbidden"); const b = await readJsonObject(request); if (!validToken(b.accessToken)) throw new RelayHttpError(400, "invalid_token_revocation"); const hash = await sha256(b.accessToken); this.requireCurrentAuth(auth); this.sql.exec("DELETE FROM tokens WHERE hash=?", hash.buffer); return new Response(null, { status: 204, headers }); }
  private async redeemLocator(request: Request, auth: Auth): Promise<Response> {
    if (auth.role !== "approval") throw new RelayHttpError(403, "role_forbidden");
    if (request.headers.get("content-type") !== "application/json") throw new RelayHttpError(415, "json_content_type_required");
    const bytes = await readBoundedBody(request, 512);
    let body: { locator?: unknown };
    try { body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as typeof body; }
    catch { throw new RelayHttpError(400, "invalid_json"); }
    if (!body || typeof body !== "object" || Array.isArray(body) || typeof body.locator !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(body.locator)) {
      throw new RelayHttpError(400, "invalid_locator");
    }
    const locatorHash = await sha256(body.locator);
    return this.state.storage.transaction(async () => {
      this.requireCurrentAuth(auth);
      const row = [...this.sql.exec<{ request_id_hash: ArrayBuffer; view_recipient_key_id: string | null }>(
        "SELECT request_id_hash,view_recipient_key_id FROM parent_locators WHERE locator_hash=? AND expires_at>?",
        locatorHash.buffer,
        Date.now(),
      )][0];
      if (!row || !row.view_recipient_key_id || !auth.viewRecipientKeyIds.includes(row.view_recipient_key_id) || new Uint8Array(row.request_id_hash).length !== 32) {
        throw new RelayHttpError(410, "approval_locator_expired");
      }
      this.sql.exec("DELETE FROM parent_locators WHERE locator_hash=?", locatorHash.buffer);
      const requestIdHash = Array.from(new Uint8Array(row.request_id_hash), byte => byte.toString(16).padStart(2, "0")).join("");
      return json({ requestIdSha256: requestIdHash, nonAuthoritative: true });
    });
  }
  private async authenticate(request: Request): Promise<Auth | null> {
    const token = request.headers.get("x-guard-token"); if (!token || !validToken(token)) return null;
    const hash = await sha256(token);
    return this.findAuth(hash);
  }
  private findAuth(hash: Uint8Array): Auth | null {
    const row = [...this.sql.exec<{ role: string; recipient_key_id: string | null; publish_recipient_key_ids: string | null;
      approval_key_id: string | null; authority_epoch: number | null; view_recipient_key_ids: string | null }>(
      "SELECT role,recipient_key_id,publish_recipient_key_ids,approval_key_id,authority_epoch,view_recipient_key_ids FROM tokens WHERE hash=? AND expires_at>?",
      hash.buffer, Date.now())][0];
    if (!row) return null;
    try {
      const scope = tokenScope(row.role, { recipientKeyId: row.recipient_key_id,
        publishRecipientKeyIds: JSON.parse(row.publish_recipient_key_ids ?? "null"), approvalKeyId: row.approval_key_id,
        authorityEpoch: row.authority_epoch, viewRecipientKeyIds: JSON.parse(row.view_recipient_key_ids ?? "null") });
      return scope ? { ...scope, tokenHash: hash } : null;
    } catch { return null; } // Legacy unscoped/corrupt non-admin credentials fail closed.
  }
  private requireCurrentAuth(auth: Auth): void {
    const current = this.findAuth(auth.tokenHash);
    if (!current) throw new RelayHttpError(401, "authentication_required");
    // Both objects are created solely by findAuth with deterministic field order; no request properties enter them.
    if (JSON.stringify(current) !== JSON.stringify(auth)) throw new RelayHttpError(403, "credential_scope_changed");
  }
  private async publish(request: Request, auth: Auth): Promise<Response> { const raw = await readBoundedBody(request, MAX_FRAME_BYTES); let frame: RelayFrame; try { frame = parseRelayFrame(raw); } catch (e) { throw new RelayHttpError(400, e instanceof FrameError ? "malformed_frame" : "invalid_frame"); }
    const mailbox = mailboxPath(new URL(request.url).pathname); if (frame.mailboxId !== mailbox) throw new RelayHttpError(400, "mailbox_mismatch");
    if ((auth.role !== "device" && auth.role !== "admin") && frame.kind !== 2) throw new RelayHttpError(403, "role_forbidden");
    if ((auth.role === "device") && frame.kind !== 1 && frame.kind !== 3) throw new RelayHttpError(403, "role_forbidden");
    if ((auth.role === "reader") || (auth.role === "approval" && frame.kind !== 2)) throw new RelayHttpError(403, "role_forbidden");
    if (auth.role !== "admin" && !auth.publishRecipientKeyIds.includes(frame.recipientKeyId)) throw new RelayHttpError(403, "recipient_forbidden");
    if (frame.cursor === 0n) throw new RelayHttpError(400, "invalid_cursor");
    const now = Date.now();
    if (frame.expiresAt <= BigInt(now)) throw new RelayHttpError(410, "frame_expired");
    if (frame.createdAt > BigInt(now + 5 * 60000)) throw new RelayHttpError(400, "frame_from_future");
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
    return this.state.storage.transactionSync(() => {
      this.requireCurrentAuth(auth);
      if (frame.expiresAt <= BigInt(Date.now())) throw new RelayHttpError(410, "frame_expired");
      const delivered = [...this.sql.exec<{ frame_hash: ArrayBuffer | null; recipient_key_id: string | null; cursor: number | null }>(
        "SELECT frame_hash,recipient_key_id,cursor FROM tombstones WHERE frame_id=?", frame.frameId)][0];
      if (delivered) {
        if (!delivered.frame_hash || delivered.recipient_key_id !== frame.recipientKeyId || delivered.cursor !== Number(frame.cursor) ||
          !sameBytes(new Uint8Array(delivered.frame_hash), hash)) throw new RelayHttpError(409, "frame_id_conflict");
        return json({ frameId: frame.frameId, duplicate: true });
      }
      const prior = [...this.sql.exec<{ bytes: ArrayBuffer }>("SELECT bytes FROM frames WHERE frame_id=?", frame.frameId)][0];
      if (prior && !sameBytes(new Uint8Array(prior.bytes), raw)) throw new RelayHttpError(409, "frame_id_conflict");
      if (!prior) {
        const count = [...this.sql.exec<{ n: number; bytes: number }>("SELECT count(*) n, coalesce(sum(size),0) bytes FROM frames")][0]!;
        if (count.n >= 1000 || count.bytes + raw.byteLength > 8 * 1024 * 1024 ||
          [...this.sql.exec<{ n: number }>("SELECT count(*) n FROM tombstones")][0]!.n >= 10000)
          throw new RelayHttpError(429, "mailbox_quota_exceeded");
        const floor = [...this.sql.exec<{ cursor: number }>("SELECT cursor FROM publication_cursors WHERE recipient_key_id=?", frame.recipientKeyId)][0]?.cursor;
        if (floor !== undefined && Number(frame.cursor) !== floor + 1) throw new RelayHttpError(409, "cursor_not_monotonic");
        if (floor === undefined && [...this.sql.exec<{ n: number }>("SELECT count(*) n FROM publication_cursors")][0]!.n >= 128)
          throw new RelayHttpError(429, "recipient_limit_reached");
        this.sql.exec("INSERT INTO frames(frame_id,recipient_key_id,kind,cursor,expires_at,bytes,size) VALUES(?,?,?,?,?,?,?)",
          frame.frameId, frame.recipientKeyId, frame.kind, Number(frame.cursor), Number(frame.expiresAt), raw, raw.byteLength);
        this.sql.exec("INSERT INTO publication_cursors(recipient_key_id,cursor) VALUES(?,?) ON CONFLICT(recipient_key_id) DO UPDATE SET cursor=excluded.cursor",
          frame.recipientKeyId, Number(frame.cursor));
      }
      this.sql.exec("INSERT INTO tombstones(frame_id,recipient_key_id,cursor,frame_hash,expires_at) VALUES(?,?,?,?,?)",
        frame.frameId, frame.recipientKeyId, Number(frame.cursor), hash, Number(frame.expiresAt));
      return json({ frameId: frame.frameId, duplicate: !!prior }, prior ? 200 : 201);
    });
  }
  private poll(request: Request, auth: Auth): Response { if (auth.role === "reader") throw new RelayHttpError(403, "role_forbidden"); const url = new URL(request.url); const recipient = url.searchParams.get("recipient"); const after = parseNatural(url.searchParams.get("after") ?? "0"); const limit = Math.min(parseNatural(url.searchParams.get("limit") ?? "20"), maxPoll); if (!validId(recipient) || after < 0 || limit < 1) throw new RelayHttpError(400, "invalid_poll"); requireRecipient(auth, recipient); const rows = [...this.sql.exec<{ bytes: ArrayBuffer; cursor: number }>("SELECT bytes,cursor FROM frames WHERE recipient_key_id=? AND cursor>? AND expires_at>? ORDER BY cursor ASC LIMIT ?", recipient, after, Date.now(), limit)]; return json({ frames: rows.map(x => bytesToBase64(new Uint8Array(x.bytes))), nextCursor: rows.length ? rows[rows.length - 1]!.cursor : after }); }
  private async ack(request: Request, auth: Auth): Promise<Response> {
    if (auth.role === "reader") throw new RelayHttpError(403, "role_forbidden");
    const b = await readJsonObject(request);
    this.requireCurrentAuth(auth);
    if (!validId(b.recipientKeyId) || typeof b.cursor !== "number" || !Number.isSafeInteger(b.cursor) || b.cursor < 0)
      throw new RelayHttpError(400, "invalid_ack");
    const recipient = b.recipientKeyId, cursor = b.cursor;
    requireRecipient(auth, recipient);
    const current = [...this.sql.exec<{ cursor: number }>("SELECT cursor FROM acknowledgements WHERE recipient_key_id=?", recipient)][0]?.cursor ?? 0;
    if (cursor < current) return json({ cursor: current, duplicate: true });
    const maximum = [...this.sql.exec<{ cursor: number }>("SELECT cursor FROM publication_cursors WHERE recipient_key_id=?", recipient)][0]?.cursor ?? current;
    if (cursor > maximum) throw new RelayHttpError(409, "ack_beyond_published");
    this.sql.exec("INSERT INTO acknowledgements(recipient_key_id,cursor) VALUES(?,?) ON CONFLICT(recipient_key_id) DO UPDATE SET cursor=excluded.cursor", recipient, cursor);
    this.sql.exec("DELETE FROM frames WHERE recipient_key_id=? AND cursor<=?", recipient, cursor);
    return json({ cursor, duplicate: cursor === current });
  }
  private async intent(request: Request, auth: Auth, operation: "reserve" | "finalize" | "cancel"): Promise<Response> { if (auth.role !== "approval" && auth.role !== "admin") throw new RelayHttpError(403, "role_forbidden"); const b = await readJsonObject(request) as unknown as IntentBody; if (!validId(b.keyId) || !Number.isSafeInteger(b.authorityEpoch) || b.authorityEpoch < 1 || !validId(b.intentId)) throw new RelayHttpError(400, "invalid_intent"); requireApprovalAuthority(auth, b.keyId, b.authorityEpoch); return this.state.storage.transaction(async () => { this.requireCurrentAuth(auth); const now = Date.now(); const existing = [...this.sql.exec<{ sequence: number; status: string; intent_id: string; expires_at: number }>("SELECT sequence,status,intent_id,expires_at FROM intents WHERE authority_epoch=? AND key_id=?", b.authorityEpoch, b.keyId)][0]; if (operation === "reserve") { if (existing && (existing.status === "pending" || existing.status === "receipt_observed") && existing.expires_at > now) { if (existing.intent_id === b.intentId) return json({ sequence: existing.sequence, status: existing.status, duplicate: true, nonAuthoritative: true }); throw new RelayHttpError(409, "signing_intent_pending"); }
      const floor = [...this.sql.exec<{ floor: number }>("SELECT floor FROM sequence_floors WHERE authority_epoch=? AND key_id=?", b.authorityEpoch, b.keyId)][0]?.floor ?? 0; const sequence = floor + 1; if (!Number.isSafeInteger(sequence)) throw new RelayHttpError(409, "sequence_exhausted"); this.sql.exec("INSERT INTO intents(authority_epoch,key_id,sequence,status,intent_id,expires_at) VALUES(?,?,?,?,?,?) ON CONFLICT(authority_epoch,key_id) DO UPDATE SET sequence=excluded.sequence,status=excluded.status,intent_id=excluded.intent_id,expires_at=excluded.expires_at", b.authorityEpoch,b.keyId,sequence,"pending",b.intentId,now+15*60000); return json({ sequence, status: "pending", duplicate: false, nonAuthoritative: true }, 201); }
    if (!existing || existing.intent_id !== b.intentId) throw new RelayHttpError(409, "unknown_signing_intent"); if (existing.status !== "pending" || existing.expires_at <= now) throw new RelayHttpError(409, "signing_intent_not_pending"); if (operation === "finalize") { if (!validId(b.receiptFrameId) || ![...this.sql.exec("SELECT 1 FROM frames WHERE frame_id=? AND kind=3 AND (? IS NULL OR recipient_key_id=?)", b.receiptFrameId, auth.role === "admin" ? null : auth.recipientKeyId, auth.role === "admin" ? null : auth.recipientKeyId)][0]) throw new RelayHttpError(409, "receipt_evidence_required"); this.sql.exec("INSERT INTO sequence_floors(authority_epoch,key_id,floor) VALUES(?,?,?) ON CONFLICT(authority_epoch,key_id) DO UPDATE SET floor=max(floor,excluded.floor)", b.authorityEpoch,b.keyId,existing.sequence); this.sql.exec("UPDATE intents SET status='receipt_observed' WHERE authority_epoch=? AND key_id=?", b.authorityEpoch,b.keyId); return json({ sequence: existing.sequence, status: "receipt_observed", nonAuthoritative: true }); }
    this.sql.exec("INSERT INTO sequence_floors(authority_epoch,key_id,floor) VALUES(?,?,?) ON CONFLICT(authority_epoch,key_id) DO UPDATE SET floor=max(floor,excluded.floor)", b.authorityEpoch,b.keyId,existing.sequence); this.sql.exec("UPDATE intents SET status='cancelled' WHERE authority_epoch=? AND key_id=?", b.authorityEpoch,b.keyId); return json({ sequence: existing.sequence, status: "cancelled", nonAuthoritative: true }); }); }
  private getIntent(request: Request, auth: Auth): Response { if (auth.role !== "approval" && auth.role !== "admin") throw new RelayHttpError(403, "role_forbidden"); const u = new URL(request.url); const epoch = parseNatural(u.searchParams.get("authorityEpoch") ?? "0"); const keyId = u.searchParams.get("keyId"); if (epoch < 1 || !validId(keyId)) throw new RelayHttpError(400, "invalid_intent"); requireApprovalAuthority(auth, keyId, epoch); const row = [...this.sql.exec<{ sequence: number; status: string; intent_id: string; expires_at: number }>("SELECT sequence,status,intent_id,expires_at FROM intents WHERE authority_epoch=? AND key_id=?", epoch,keyId)][0]; return row ? json({ sequence: row.sequence, status: row.status, intentId: row.intent_id, expiresAt: row.expires_at }) : json({ status: "none" }); }
}
interface TokenScope {
  role: Role;
  recipientKeyId: string | null;
  publishRecipientKeyIds: string[];
  approvalKeyId: string | null;
  authorityEpoch: number | null;
  viewRecipientKeyIds: string[];
}
type Auth = TokenScope & { tokenHash: Uint8Array };
interface IntentBody { authorityEpoch: number; keyId: string; intentId: string; receiptFrameId?: string; }
class RelayHttpError extends Error { constructor(readonly status: number, readonly code: string) { super(code); } }
function tokenScope(role: unknown, input: Record<string, unknown>): TokenScope | null {
  if (!roles.includes(role as Role)) return null;
  if (role === "admin") {
    if (input.recipientKeyId != null || input.approvalKeyId != null || input.authorityEpoch != null ||
      (input.publishRecipientKeyIds != null && (!validRecipients(input.publishRecipientKeyIds) || input.publishRecipientKeyIds.length !== 0)) ||
      (input.viewRecipientKeyIds != null && (!validRecipients(input.viewRecipientKeyIds) || input.viewRecipientKeyIds.length !== 0))) return null;
    return { role, recipientKeyId: null, publishRecipientKeyIds: [], approvalKeyId: null, authorityEpoch: null, viewRecipientKeyIds: [] };
  }
  if (!validId(input.recipientKeyId) || !validRecipients(input.publishRecipientKeyIds) ||
    (role === "reader" && input.publishRecipientKeyIds.length !== 0) ||
    (role === "approval" && input.publishRecipientKeyIds.length === 0)) return null;
  // An explicit empty device list bootstraps GREX before any phone key exists; it never authorizes GRF1 publication.
  if (role === "approval") {
    if (!validId(input.approvalKeyId) || typeof input.authorityEpoch !== "number" || !Number.isSafeInteger(input.authorityEpoch) ||
      input.authorityEpoch < 1 || !validRecipients(input.viewRecipientKeyIds) || input.viewRecipientKeyIds.length === 0) return null;
    return { role, recipientKeyId: input.recipientKeyId, publishRecipientKeyIds: input.publishRecipientKeyIds,
      approvalKeyId: input.approvalKeyId, authorityEpoch: input.authorityEpoch, viewRecipientKeyIds: input.viewRecipientKeyIds };
  }
  if (input.approvalKeyId != null || input.authorityEpoch != null || (input.viewRecipientKeyIds != null &&
    (!validRecipients(input.viewRecipientKeyIds) || input.viewRecipientKeyIds.length !== 0))) return null;
  return { role: role as Role, recipientKeyId: input.recipientKeyId, publishRecipientKeyIds: input.publishRecipientKeyIds,
    approvalKeyId: null, authorityEpoch: null, viewRecipientKeyIds: [] };
}
function validRecipients(value: unknown): value is string[] {
  return Array.isArray(value) && value.length <= 32 && value.every(validId) && new Set(value).size === value.length;
}
function requireRecipient(auth: Auth, recipientKeyId: string): void {
  if (auth.role !== "admin" && auth.recipientKeyId !== recipientKeyId) throw new RelayHttpError(403, "recipient_forbidden");
}
function requireApprovalAuthority(auth: Auth, keyId: string, epoch: number): void {
  if (auth.role !== "admin" && (auth.approvalKeyId !== keyId || auth.authorityEpoch !== epoch))
    throw new RelayHttpError(403, "authority_forbidden");
}
async function readJsonObject(request: Request): Promise<Record<string, unknown>> {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get("content-type") ?? ""))
    throw new RelayHttpError(415, "json_content_type_required");
  const bytes = await readBoundedBody(request, 16 * 1024);
  let body: unknown;
  try { body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw new RelayHttpError(400, "invalid_json"); }
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new RelayHttpError(400, "invalid_json");
  return body as Record<string, unknown>;
}
function parseNatural(value: string): number { const number = /^[0-9]+$/.test(value) ? Number(value) : -1; return Number.isSafeInteger(number) ? number : -1; }
function bytesToBase64(bytes: Uint8Array): string { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); }
function sameBytes(a: Uint8Array, b: Uint8Array): boolean { if (a.length !== b.length) return false; let different = 0; for (let i = 0; i < a.length; i++) different |= a[i]! ^ b[i]!; return different === 0; }
