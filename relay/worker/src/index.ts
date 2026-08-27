import { FrameError, MAX_FRAME_BYTES, parseRelayFrame, type RelayFrame } from "./frame";
import {
  forwardParentBff,
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
const validId = (value: string | null | undefined): value is string => !!value && /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value);
const mailboxPath = (pathname: string): string | null => { const m = /^\/v1\/mailboxes\/([A-Za-z0-9][A-Za-z0-9._-]{0,127})(?:\/|$)/.exec(pathname); return m?.[1] ?? null; };

async function forward(env: Env, mailboxId: string, request: Request, token: string | null, bootstrap = false): Promise<Response> {
  const id = env.DEVICE_MAILBOX.idFromName(mailboxId);
  const copy = new Headers(request.headers); if (token) copy.set("x-guard-token", token); if (bootstrap) copy.set("x-guard-bootstrap", "1");
  const body = request.method === "GET" || request.method === "HEAD" ? undefined : await request.arrayBuffer();
  return env.DEVICE_MAILBOX.get(id).fetch(new Request(`https://mailbox.internal${new URL(request.url).pathname}${new URL(request.url).search}`, { method: request.method, headers: copy, body }));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return fail(405, "method_not_allowed");
    if (url.pathname === "/v1/admin/bootstrap" && request.method === "POST") {
      const bootstrap = tokenFrom(request); if (!env.BOOTSTRAP_ADMIN_TOKEN || !bootstrap || !constantTimeEqual(await sha256(bootstrap), await sha256(env.BOOTSTRAP_ADMIN_TOKEN))) return fail(403, "bootstrap_forbidden");
      let body: { mailboxId?: string; accessToken?: string };
      try { body = await request.json() as typeof body; } catch { return fail(400, "invalid_json"); }
      if (!validId(body.mailboxId) || !validToken(body.accessToken)) return fail(400, "invalid_bootstrap");
      return forward(env, body.mailboxId, new Request(request.url, { method: "POST", headers: request.headers, body: JSON.stringify(body) }), bootstrap, true);
    }
    if (isParentBffPath(url.pathname)) return forwardParentBff(request, env);
    const mailboxId = mailboxPath(url.pathname); if (!mailboxId) return fail(404, "not_found");
    const token = tokenFrom(request); if (!token || !validToken(token)) return fail(401, "authentication_required");
    return forward(env, mailboxId, request, token);
  }
} satisfies ExportedHandler<Env>;

function validToken(value: string | undefined): value is string { return !!value && value.length >= 32 && value.length <= 512; }
async function sha256(value: string): Promise<Uint8Array> { return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))); }
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean { if (a.length !== b.length) return false; let result = 0; for (let i = 0; i < a.length; i++) result |= a[i]! ^ b[i]!; return result === 0; }

export class DeviceMailbox implements DurableObject {
  private readonly sql: SqlStorage;
  constructor(readonly state: DurableObjectState, readonly env: Env) { this.sql = state.storage.sql; state.blockConcurrencyWhile(async () => this.migrate()); }
  private migrate(): void {
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
  }
  async fetch(request: Request): Promise<Response> {
    try { this.cleanup(); const path = new URL(request.url).pathname;
      const bffResponse = await handleParentBffRequest({ state: this.state, sql: this.sql, env: this.env }, request);
      if (bffResponse) return bffResponse;
      if (request.headers.get("x-guard-bootstrap") === "1" && path === "/v1/admin/bootstrap") return await this.bootstrap(request);
      const auth = await this.authenticate(request); if (!auth) return fail(401, "authentication_required");
      if (path.endsWith("/frames") && request.method === "POST") return await this.publish(request, auth);
      if (path.endsWith("/poll") && request.method === "GET") return this.poll(request, auth);
      if (path.endsWith("/ack") && request.method === "POST") return await this.ack(request, auth);
      if (path.endsWith("/tokens") && request.method === "POST") return await this.provisionToken(request, auth);
      if (path.endsWith("/tokens") && request.method === "DELETE") return await this.revokeToken(request, auth);
      if (path.endsWith("/intents/reserve") && request.method === "POST") return await this.intent(request, auth, "reserve");
      if (path.endsWith("/intents/finalize") && request.method === "POST") return await this.intent(request, auth, "finalize");
      if (path.endsWith("/intents/cancel") && request.method === "POST") return await this.intent(request, auth, "cancel");
      if (path.endsWith("/intents") && request.method === "GET") return this.getIntent(request, auth);
      return fail(404, "not_found");
    } catch (error) { if (error instanceof RelayHttpError) return fail(error.status, error.code); return fail(503, "relay_unavailable"); }
  }
  private cleanup(): void {
    const now = Date.now();
    this.sql.exec("DELETE FROM frames WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM tokens WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM idempotency WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM tombstones WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM intents WHERE expires_at <= ? AND status != 'pending'", now);
    this.sql.exec("DELETE FROM parent_sessions WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM parent_locators WHERE expires_at <= ?", now);
  }
  private async bootstrap(request: Request): Promise<Response> { const body = await request.json() as { accessToken?: string }; if (!validToken(body.accessToken)) return fail(400, "invalid_bootstrap"); const exists = [...this.sql.exec("SELECT 1 FROM tokens LIMIT 1")].length > 0; if (exists) return fail(409, "already_bootstrapped"); const hash = await sha256(body.accessToken); this.sql.exec("INSERT INTO tokens(hash,role,expires_at) VALUES(?,?,?)", hash.buffer, "admin", Date.now() + 365 * 86400000); return json({ role: "admin" }, 201); }
  private async provisionToken(request: Request, auth: Auth): Promise<Response> { if (auth.role !== "admin") throw new RelayHttpError(403, "role_forbidden"); const b = await request.json() as { accessToken?: string; role?: Role; expiresAt?: number }; if (!validToken(b.accessToken) || !roles.includes(b.role as Role) || typeof b.expiresAt !== "number" || !Number.isSafeInteger(b.expiresAt) || b.expiresAt <= Date.now()) throw new RelayHttpError(400, "invalid_token_provisioning"); const hash = await sha256(b.accessToken); this.sql.exec("INSERT INTO tokens(hash,role,expires_at) VALUES(?,?,?) ON CONFLICT(hash) DO UPDATE SET role=excluded.role,expires_at=excluded.expires_at", hash.buffer, b.role!, b.expiresAt); return json({ role: b.role, expiresAt: b.expiresAt }, 201); }
  private async revokeToken(request: Request, auth: Auth): Promise<Response> { if (auth.role !== "admin") throw new RelayHttpError(403, "role_forbidden"); const b = await request.json() as { accessToken?: string }; if (!validToken(b.accessToken)) throw new RelayHttpError(400, "invalid_token_revocation"); const hash = await sha256(b.accessToken); this.sql.exec("DELETE FROM tokens WHERE hash=?", hash.buffer); return new Response(null, { status: 204, headers }); }
  private async authenticate(request: Request): Promise<Auth | null> { const token = request.headers.get("x-guard-token"); if (!token || !validToken(token)) return null; const hash = await sha256(token); const row = [...this.sql.exec<{ role: Role }>("SELECT role FROM tokens WHERE hash=? AND expires_at>?", hash.buffer, Date.now())][0]; return row && roles.includes(row.role) ? { hash, role: row.role } : null; }
  private async publish(request: Request, auth: Auth): Promise<Response> { const raw = new Uint8Array(await request.arrayBuffer()); if (raw.byteLength > MAX_FRAME_BYTES) throw new RelayHttpError(413, "frame_too_large"); let frame: RelayFrame; try { frame = parseRelayFrame(raw); } catch (e) { throw new RelayHttpError(400, e instanceof FrameError ? "malformed_frame" : "invalid_frame"); }
    const mailbox = mailboxPath(new URL(request.url).pathname); if (frame.mailboxId !== mailbox) throw new RelayHttpError(400, "mailbox_mismatch");
    if ((auth.role !== "device" && auth.role !== "admin") && frame.kind !== 2) throw new RelayHttpError(403, "role_forbidden");
    if ((auth.role === "device") && frame.kind !== 1 && frame.kind !== 3) throw new RelayHttpError(403, "role_forbidden");
    if ((auth.role === "reader") || (auth.role === "approval" && frame.kind !== 2)) throw new RelayHttpError(403, "role_forbidden");
    if (frame.expiresAt <= BigInt(Date.now())) throw new RelayHttpError(410, "frame_expired");
    const count = [...this.sql.exec<{ n: number; bytes: number }>("SELECT count(*) n, coalesce(sum(size),0) bytes FROM frames")][0]!; if (count.n >= 1000 || count.bytes + raw.byteLength > 8 * 1024 * 1024) throw new RelayHttpError(429, "mailbox_quota_exceeded");
    const prior = [...this.sql.exec<{ bytes: ArrayBuffer }>("SELECT bytes FROM frames WHERE frame_id=?", frame.frameId)][0]; if (prior) { if (!sameBytes(new Uint8Array(prior.bytes), raw)) throw new RelayHttpError(409, "frame_id_conflict"); return json({ frameId: frame.frameId, duplicate: true }, 200); }
    const latest = [...this.sql.exec<{ cursor: number }>("SELECT cursor FROM frames WHERE recipient_key_id=? ORDER BY cursor DESC LIMIT 1", frame.recipientKeyId)][0]?.cursor;
    const acknowledged = [...this.sql.exec<{ cursor: number }>("SELECT cursor FROM acknowledgements WHERE recipient_key_id=?", frame.recipientKeyId)][0]?.cursor;
    const floor = latest ?? acknowledged;
    if (floor !== undefined && Number(frame.cursor) !== floor + 1) throw new RelayHttpError(409, "cursor_not_monotonic");
    this.sql.exec("INSERT INTO frames(frame_id,recipient_key_id,kind,cursor,expires_at,bytes,size) VALUES(?,?,?,?,?,?,?)", frame.frameId, frame.recipientKeyId, frame.kind, Number(frame.cursor), Number(frame.expiresAt), raw, raw.byteLength);
    return json({ frameId: frame.frameId, duplicate: false }, 201);
  }
  private poll(request: Request, auth: Auth): Response { if (auth.role === "reader") throw new RelayHttpError(403, "role_forbidden"); const url = new URL(request.url); const recipient = url.searchParams.get("recipient"); const after = parseNatural(url.searchParams.get("after") ?? "0"); const limit = Math.min(parseNatural(url.searchParams.get("limit") ?? "20"), maxPoll); if (!validId(recipient) || limit < 1) throw new RelayHttpError(400, "invalid_poll"); const rows = [...this.sql.exec<{ bytes: ArrayBuffer; cursor: number }>("SELECT bytes,cursor FROM frames WHERE recipient_key_id=? AND cursor>? AND expires_at>? ORDER BY cursor ASC LIMIT ?", recipient, after, Date.now(), limit)]; return json({ frames: rows.map(x => bytesToBase64(new Uint8Array(x.bytes))), nextCursor: rows.length ? rows[rows.length - 1]!.cursor : after }); }
  private async ack(request: Request, auth: Auth): Promise<Response> { if (auth.role === "reader") throw new RelayHttpError(403, "role_forbidden"); const b = await request.json() as { recipientKeyId?: string; cursor?: number }; if (!validId(b.recipientKeyId) || typeof b.cursor !== "number" || !Number.isSafeInteger(b.cursor) || b.cursor < 0) throw new RelayHttpError(400, "invalid_ack"); const recipient = b.recipientKeyId; const cursor = b.cursor; const current = [...this.sql.exec<{ cursor: number }>("SELECT cursor FROM acknowledgements WHERE recipient_key_id=?", recipient)][0]?.cursor ?? 0; if (cursor < current) return json({ cursor: current, duplicate: true }); const maximum = [...this.sql.exec<{ cursor: number }>("SELECT max(cursor) cursor FROM frames WHERE recipient_key_id=?", recipient)][0]?.cursor ?? current; if (cursor > maximum) throw new RelayHttpError(409, "ack_beyond_published"); this.sql.exec("INSERT INTO acknowledgements(recipient_key_id,cursor) VALUES(?,?) ON CONFLICT(recipient_key_id) DO UPDATE SET cursor=excluded.cursor", recipient, cursor); this.sql.exec("DELETE FROM frames WHERE recipient_key_id=? AND cursor<=?", recipient, cursor); return json({ cursor, duplicate: cursor === current }); }
  private async intent(request: Request, auth: Auth, operation: "reserve" | "finalize" | "cancel"): Promise<Response> { if (auth.role !== "approval" && auth.role !== "admin") throw new RelayHttpError(403, "role_forbidden"); const b = await request.json() as IntentBody; if (!validId(b.keyId) || !Number.isSafeInteger(b.authorityEpoch) || b.authorityEpoch < 1 || !validId(b.intentId)) throw new RelayHttpError(400, "invalid_intent"); return this.state.storage.transaction(async () => { const now = Date.now(); const existing = [...this.sql.exec<{ sequence: number; status: string; intent_id: string; expires_at: number }>("SELECT sequence,status,intent_id,expires_at FROM intents WHERE authority_epoch=? AND key_id=?", b.authorityEpoch, b.keyId)][0]; if (operation === "reserve") { if (existing && (existing.status === "pending" || existing.status === "receipt_observed") && existing.expires_at > now) { if (existing.intent_id === b.intentId) return json({ sequence: existing.sequence, status: existing.status, duplicate: true, nonAuthoritative: true }); throw new RelayHttpError(409, "signing_intent_pending"); }
      const floor = [...this.sql.exec<{ floor: number }>("SELECT floor FROM sequence_floors WHERE authority_epoch=? AND key_id=?", b.authorityEpoch, b.keyId)][0]?.floor ?? 0; const sequence = floor + 1; this.sql.exec("INSERT INTO intents(authority_epoch,key_id,sequence,status,intent_id,expires_at) VALUES(?,?,?,?,?,?) ON CONFLICT(authority_epoch,key_id) DO UPDATE SET sequence=excluded.sequence,status=excluded.status,intent_id=excluded.intent_id,expires_at=excluded.expires_at", b.authorityEpoch,b.keyId,sequence,"pending",b.intentId,now+15*60000); return json({ sequence, status: "pending", duplicate: false, nonAuthoritative: true }, 201); }
    if (!existing || existing.intent_id !== b.intentId) throw new RelayHttpError(409, "unknown_signing_intent"); if (existing.status !== "pending" || existing.expires_at <= now) throw new RelayHttpError(409, "signing_intent_not_pending"); if (operation === "finalize") { if (!validId(b.receiptFrameId) || ![...this.sql.exec("SELECT 1 FROM frames WHERE frame_id=? AND kind=3", b.receiptFrameId)][0]) throw new RelayHttpError(409, "receipt_evidence_required"); this.sql.exec("INSERT INTO sequence_floors(authority_epoch,key_id,floor) VALUES(?,?,?) ON CONFLICT(authority_epoch,key_id) DO UPDATE SET floor=max(floor,excluded.floor)", b.authorityEpoch,b.keyId,existing.sequence); this.sql.exec("UPDATE intents SET status='receipt_observed' WHERE authority_epoch=? AND key_id=?", b.authorityEpoch,b.keyId); return json({ sequence: existing.sequence, status: "receipt_observed", nonAuthoritative: true }); }
    this.sql.exec("INSERT INTO sequence_floors(authority_epoch,key_id,floor) VALUES(?,?,?) ON CONFLICT(authority_epoch,key_id) DO UPDATE SET floor=max(floor,excluded.floor)", b.authorityEpoch,b.keyId,existing.sequence); this.sql.exec("UPDATE intents SET status='cancelled' WHERE authority_epoch=? AND key_id=?", b.authorityEpoch,b.keyId); return json({ sequence: existing.sequence, status: "cancelled", nonAuthoritative: true }); }); }
  private getIntent(request: Request, auth: Auth): Response { if (auth.role !== "approval" && auth.role !== "admin") throw new RelayHttpError(403, "role_forbidden"); const u = new URL(request.url); const epoch = parseNatural(u.searchParams.get("authorityEpoch") ?? "0"); const keyId = u.searchParams.get("keyId"); if (epoch < 1 || !validId(keyId)) throw new RelayHttpError(400, "invalid_intent"); const safeKeyId = keyId; const row = [...this.sql.exec<{ sequence: number; status: string; intent_id: string; expires_at: number }>("SELECT sequence,status,intent_id,expires_at FROM intents WHERE authority_epoch=? AND key_id=?", epoch,safeKeyId)][0]; return row ? json({ sequence: row.sequence, status: row.status, intentId: row.intent_id, expiresAt: row.expires_at }) : json({ status: "none" }); }
}
interface Auth { hash: Uint8Array; role: Role; }
interface IntentBody { authorityEpoch: number; keyId: string; intentId: string; receiptFrameId?: string; }
class RelayHttpError extends Error { constructor(readonly status: number, readonly code: string) { super(code); } }
function parseNatural(value: string): number { return /^[0-9]+$/.test(value) ? Number(value) : -1; }
function bytesToBase64(bytes: Uint8Array): string { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); }
function sameBytes(a: Uint8Array, b: Uint8Array): boolean { if (a.length !== b.length) return false; let different = 0; for (let i = 0; i < a.length; i++) different |= a[i]! ^ b[i]!; return different === 0; }
