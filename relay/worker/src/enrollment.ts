import { readBoundedBody, RequestBodyError } from "./bounded-body";

export const MAX_ENROLLMENT_BYTES = 70 * 1024;
const minute = 60000;
const headers = { "cache-control": "no-store", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "cross-origin-resource-policy": "same-origin" };
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { ...headers, "content-type": "application/json" } });
const binary = (value: ArrayBuffer | null) => new Response(value, { status: value ? 200 : 204, headers: { ...headers, "content-type": "application/octet-stream" } });
const reject = (status: number, code: string): never => { throw new RequestBodyError(status, code); };
const hex = (value: Uint8Array) => Array.from(value, byte => byte.toString(16).padStart(2, "0")).join("");
const digest = (value: Uint8Array<ArrayBuffer>) => crypto.subtle.digest("SHA-256", value);
const same = (a: ArrayBuffer, b: ArrayBuffer) => { const x = new Uint8Array(a), y = new Uint8Array(b); if (x.length !== y.length) return false; let changed = 0; for (let i = 0; i < x.length; i++) changed |= x[i]! ^ y[i]!; return changed === 0; };
type DeviceAuth = { role: string; recipientKeyId: string | null } | null;
type Session = { owner: string; token_hash: ArrayBuffer; submit_until: number; retain_until: number };
type Exchange = { request: ArrayBuffer; request_hash: ArrayBuffer; reply: ArrayBuffer | null; rejected: number; expires_at: number };

export function migrateEnrollment(sql: SqlStorage): void {
  sql.exec(`CREATE TABLE IF NOT EXISTS enrollments(offer TEXT PRIMARY KEY,owner TEXT NOT NULL,token_hash BLOB NOT NULL,submit_until INTEGER NOT NULL,retain_until INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS enrollment_exchanges(offer TEXT NOT NULL,nonce TEXT NOT NULL,request BLOB NOT NULL,request_hash BLOB NOT NULL,reply BLOB,rejected INTEGER NOT NULL DEFAULT 0,expires_at INTEGER NOT NULL,PRIMARY KEY(offer,nonce));`);
}

/** Only the public routing header is parsed. Cryptographic meaning remains at the phone/device. */
export function parseEnrollment(raw: Uint8Array): { kind: number; offer: string; nonce: string } {
  if (raw.length < 193 || raw.length > MAX_ENROLLMENT_BYTES) reject(400, "invalid_enrollment_frame");
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const kind = view.getUint32(8), size = view.getUint32(173);
  if (view.getUint32(0) !== 0x47524558 || view.getUint32(4) !== 1 || kind < 1 || kind > 4 || raw[108] !== 4 ||
    size !== raw.length - 177 || size < 16 || (kind === 2 && size !== 48) || (kind === 3 && size !== 16) || (kind === 4 && size > 237))
    reject(400, "invalid_enrollment_frame");
  return { kind, offer: hex(raw.subarray(12, 44)), nonce: hex(raw.subarray(76, 108)) };
}

/** This capability conveys queue access, never attestation, approval, ownership or local confirmation. */
export async function handleEnrollment(request: Request, state: DurableObjectState, authenticate: () => Promise<DeviceAuth>): Promise<Response | null> {
  const url = new URL(request.url), prefix = `/v1/mailboxes/${state.id.name}/enrollments/`;
  if (!url.pathname.startsWith(prefix)) return null;
  const route = /^([a-f0-9]{64})(?:\/(requests|replies)(?:\/([a-f0-9]{64}))?)?$/.exec(url.pathname.slice(prefix.length));
  if (!route || url.search) reject(404, "not_found");
  const [_, offer, resource, nonce] = route!;
  const sql = state.storage.sql;
  const now = Date.now();
  sql.exec("DELETE FROM enrollment_exchanges WHERE expires_at<=? OR offer IN (SELECT offer FROM enrollments WHERE retain_until<=?)", now, now);
  sql.exec("DELETE FROM enrollments WHERE retain_until<=?", now);
  const token = request.headers.get("x-guard-token");
  if (!token) reject(401, "authentication_required");
  const tokenHash = await digest(new TextEncoder().encode(token!));
  function requireDevice(owner: string): void {
    if (![...sql.exec("SELECT 1 FROM tokens WHERE hash=? AND role='device' AND recipient_key_id=? AND expires_at>?", tokenHash, owner, Date.now())].length)
      reject(403, "role_forbidden");
  }
  if (!resource && request.method === "POST") {
    if (request.headers.get("content-type") !== "application/json") reject(415, "json_content_type_required");
    const body = await readBoundedBody(request, 1024);
    let input: { phoneToken?: unknown; expiresAt?: unknown };
    try { input = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body)); }
    catch { return reject(400, "invalid_enrollment"); }
    if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).sort().join(",") !== "expiresAt,phoneToken" ||
      typeof input.phoneToken !== "string" || !/^[a-f0-9]{64}$/.test(input.phoneToken) ||
      typeof input.expiresAt !== "number" || !Number.isSafeInteger(input.expiresAt)) reject(400, "invalid_enrollment");
    const phoneHash = await digest(new TextEncoder().encode(input.phoneToken as string));
    const auth = await authenticate(); // Recheck after body/hash awaits, immediately before the synchronous transaction.
    if (auth?.role !== "device" || !auth.recipientKeyId) reject(403, "role_forbidden");
    return state.storage.transactionSync(() => {
      requireDevice(auth!.recipientKeyId!);
      const existing = [...sql.exec<Session>("SELECT * FROM enrollments WHERE offer=?", offer!)][0];
      if (existing) {
        if (existing.owner !== auth!.recipientKeyId) reject(403, "role_forbidden");
        if (!same(existing.token_hash, phoneHash) || existing.submit_until !== input.expiresAt)
          reject(409, "enrollment_conflict");
        return json({ duplicate: true, retainUntil: existing.retain_until }); // Never renew either deadline.
      }
      const created = Date.now();
      if ((input.expiresAt as number) <= created || (input.expiresAt as number) > created + 10 * minute) reject(400, "invalid_enrollment_expiry");
      if ([...sql.exec("SELECT 1 FROM tokens WHERE hash=?", phoneHash)].length) reject(409, "enrollment_token_conflict");
      if ([...sql.exec("SELECT 1 FROM enrollments WHERE token_hash=?", phoneHash)].length) reject(409, "enrollment_token_conflict");
      if ([...sql.exec<{ n: number }>("SELECT count(*) n FROM enrollments")][0]!.n >= 8) reject(429, "enrollment_limit");
      const retain = (input.expiresAt as number) + 24 * 60 * minute;
      sql.exec("INSERT INTO enrollments(offer,owner,token_hash,submit_until,retain_until) VALUES(?,?,?,?,?)", offer!, auth!.recipientKeyId!, phoneHash, input.expiresAt as number, retain);
      return json({ duplicate: false, retainUntil: retain }, 201);
    });
  }
  const session = [...sql.exec<Session>("SELECT * FROM enrollments WHERE offer=? AND retain_until>?", offer!, Date.now())][0];
  if (!session) reject(410, "enrollment_expired");
  const phone = same(session!.token_hash, tokenHash);
  const auth = phone ? null : await authenticate();
  const device = auth?.role === "device" && auth.recipientKeyId === session!.owner;
  if (!phone && !device) reject(403, "role_forbidden");
  // Recheck the exact capability and device token after body/digest awaits; revocation cannot race publication.
  function current(): void {
    if (device) requireDevice(session!.owner);
    const latest = [...sql.exec<Session>("SELECT * FROM enrollments WHERE offer=? AND retain_until>?", offer!, Date.now())][0];
    if (!latest || latest.owner !== session!.owner || latest.submit_until !== session!.submit_until ||
      !same(latest.token_hash, session!.token_hash)) reject(410, "enrollment_expired");
  }
  current();
  if (!resource && request.method === "DELETE") {
    if (!device) reject(403, "role_forbidden");
    return state.storage.transactionSync(() => {
      sql.exec("DELETE FROM enrollment_exchanges WHERE offer=?", offer!);
      sql.exec("DELETE FROM enrollments WHERE offer=?", offer!);
      return new Response(null, { status: 204, headers });
    }); // Transport revocation only, never owner/key deletion.
  }
  if (resource === "requests" && !nonce && request.method === "GET") {
    if (!device) reject(403, "role_forbidden");
    const row = [...sql.exec<{ request: ArrayBuffer }>("SELECT request FROM enrollment_exchanges WHERE offer=? AND reply IS NULL AND rejected=0 AND expires_at>? ORDER BY rowid LIMIT 1", offer!, Date.now())][0];
    return binary(row?.request ?? null);
  }
  if (resource === "replies" && nonce && request.method === "GET") {
    if (!phone) reject(403, "role_forbidden");
    const row = [...sql.exec<Exchange>("SELECT * FROM enrollment_exchanges WHERE offer=? AND nonce=? AND expires_at>?", offer!, nonce, Date.now())][0];
    if (!row) reject(410, "enrollment_exchange_expired");
    if (row!.rejected) reject(422, "enrollment_request_rejected");
    return binary(row!.reply);
  }
  if (resource === "requests" && nonce && request.method === "DELETE") {
    if (!device) reject(403, "role_forbidden");
    sql.exec("UPDATE enrollment_exchanges SET rejected=1 WHERE offer=? AND nonce=? AND reply IS NULL", offer!, nonce);
    return new Response(null, { status: 204, headers });
  }
  if ((resource === "requests" || resource === "replies") && !nonce && request.method === "POST") {
    if ((resource === "requests" && !phone) || (resource === "replies" && !device)) reject(403, "role_forbidden");
    if (request.headers.get("content-type") !== "application/octet-stream") reject(415, "binary_content_type_required");
    const raw = await readBoundedBody(request, resource === "requests" ? MAX_ENROLLMENT_BYTES : 414);
    const frame = parseEnrollment(raw);
    if (frame.offer !== offer || (resource === "requests" ? frame.kind === 4 : frame.kind !== 4)) reject(400, "enrollment_direction_or_binding");
    const hash = await digest(raw);
    return state.storage.transactionSync(() => {
      current();
      const at = Date.now();
      sql.exec("DELETE FROM enrollment_exchanges WHERE expires_at<=?", at);
      const row = [...sql.exec<Exchange>("SELECT * FROM enrollment_exchanges WHERE offer=? AND nonce=? AND expires_at>?", offer!, frame.nonce, at)][0];
      if (resource === "requests") {
        if (row) {
          if (hex(new Uint8Array(row.request_hash)) !== hex(new Uint8Array(hash))) reject(409, "enrollment_nonce_conflict");
          return json({ duplicate: true });
        }
        if (frame.kind !== 3 && at >= session!.submit_until) reject(410, "enrollment_submission_expired");
        const totals = [...sql.exec<{ n: number; size: number }>("SELECT count(*) n,coalesce(sum(length(request)),0) size FROM enrollment_exchanges")][0]!;
        if (totals.n >= 256 || totals.size + raw.length > 1024 * 1024 ||
          [...sql.exec<{ n: number }>("SELECT count(*) n FROM enrollment_exchanges WHERE offer=?", offer!)][0]!.n >= 32) reject(429, "enrollment_queue_full");
        sql.exec("INSERT INTO enrollment_exchanges(offer,nonce,request,request_hash,expires_at) VALUES(?,?,?,?,?)", offer!, frame.nonce, raw, hash, Math.min(at + 2 * minute, session!.retain_until));
        return json({ duplicate: false }, 201);
      }
      if (!row || row.rejected) reject(410, "enrollment_exchange_expired");
      if (hex(new Uint8Array(row!.request).subarray(12, 108)) !== hex(raw.subarray(12, 108))) reject(409, "enrollment_reply_binding");
      if (row!.reply) {
        if (hex(new Uint8Array(row!.reply)) !== hex(raw)) reject(409, "enrollment_reply_conflict");
        return json({ duplicate: true });
      }
      sql.exec("UPDATE enrollment_exchanges SET reply=? WHERE offer=? AND nonce=?", raw, offer!, frame.nonce);
      return json({ duplicate: false }, 201);
    });
  }
  return reject(404, "not_found");
}
