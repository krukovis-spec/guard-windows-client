import { env, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { DeviceMailbox } from "../src/index";
import { MAX_ENROLLMENT_BYTES, parseEnrollment } from "../src/enrollment";
import fixture from "../../../protocol/test-vectors/enrollment-exchange-v1.properties?raw";

// Shared PUBLIC TEST-ONLY crypto bytes. The mailbox must not decrypt or bless them.
const field = (name: string): Uint8Array<ArrayBuffer> => Uint8Array.from(fixture.split(/\r?\n/).find((line: string) => line.startsWith(name + "="))!.split("=")[1]!.match(/../g)!.map((x: string) => parseInt(x, 16)));
const query = field("kotlin.query"), reply = field("reply.confirmed");
const { offer, nonce } = parseEnrollment(query);
const admin = "a".repeat(64), device = "d".repeat(64), phone = "e".repeat(64), other = "o".repeat(64);
const recipient = "device-encryption-0001";
const bootstrap = "test-only-bootstrap-token-8f3f0d4dd15ebd16c4f5ac14a1c9e617";
const headers = (token: string, type = "application/json") => ({ authorization: `Bearer ${token}`, "content-type": type });
const call = (path: string, token: string, method = "GET", body?: unknown) => SELF.fetch(`https://example.test${path}`, {
  method, headers: headers(token, body instanceof Uint8Array ? "application/octet-stream" : "application/json"),
  body: body instanceof Uint8Array ? body : body === undefined ? undefined : JSON.stringify(body),
});
const base = (mailbox: string, hash = offer) => `/v1/mailboxes/${mailbox}/enrollments/${hash}`;
const stub = (mailbox: string) => env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(mailbox));
async function setup(mailbox: string, capability = phone): Promise<number> {
  expect((await call("/v1/admin/bootstrap", bootstrap, "POST", { mailboxId: mailbox, accessToken: admin })).status).toBe(201);
  for (const [token, key] of [[device, recipient], [other, "other-device-key-0001"]])
    expect((await call(`/v1/mailboxes/${mailbox}/tokens`, admin, "POST", { accessToken: token, role: "device", recipientKeyId: key,
      publishRecipientKeyIds: [], expiresAt: Date.now() + 3600000 })).status).toBe(201);
  const expiresAt = Date.now() + 300000;
  expect((await call(base(mailbox), device, "POST", { phoneToken: capability, expiresAt })).status).toBe(201);
  return expiresAt;
}
function frame(kind = 3, number = 0, size = kind === 2 ? 225 : kind === 4 ? 301 : 193): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(size); bytes.set(query.subarray(0, 177));
  const view = new DataView(bytes.buffer); view.setUint32(8, kind); view.setUint32(104, number); view.setUint32(173, size - 177);
  return bytes;
}

describe("scoped opaque enrollment exchange", () => {
  it("carries actual Kotlin/.NET bytes through HTTP and SQLite with restart/lost-response retries", async () => {
    const mailbox = "enrollment-happy-0001", path = base(mailbox);
    const expiresAt = await setup(mailbox);
    expect((await call(path, device, "POST", { phoneToken: phone, expiresAt })).status).toBe(200);
    expect((await call(path + "/requests", device)).status).toBe(204);
    expect((await call(path + "/requests", phone, "POST", query)).status).toBe(201);
    expect((await call(path + "/requests", phone, "POST", query)).status).toBe(200);
    expect((await call(path + "/replies/" + nonce, phone)).status).toBe(204);
    await runInDurableObject(stub(mailbox), (_instance, state) => {
      new DeviceMailbox(state, env); // Idempotent migration/reopen does not drop the queue.
      const row = [...state.storage.sql.exec<{ token_hash: ArrayBuffer }>("SELECT token_hash FROM enrollments")][0]!;
      expect(new Uint8Array(row.token_hash)).toHaveLength(32);
      expect(new TextDecoder().decode(row.token_hash)).not.toContain(phone);
      expect([...state.storage.sql.exec<{ n: number }>("SELECT count(*) n FROM tokens")][0]!.n).toBe(3); // No approval token created.
    });
    const received = await call(path + "/requests", device);
    expect(new Uint8Array(await received.arrayBuffer())).toEqual(query);
    expect((await call(path + "/replies", device, "POST", reply)).status).toBe(201);
    expect((await call(path + "/replies", device, "POST", reply)).status).toBe(200);
    expect((await call(path + "/requests", phone, "POST", query)).status).toBe(200);
    const response = await call(path + "/replies/" + nonce, phone);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(reply);
    expect((await call(path + "/requests", device)).status).toBe(204);
    const changed = query.slice(); changed[changed.length - 1] ^= 1;
    expect((await call(path + "/requests", phone, "POST", changed)).status).toBe(409);
    const changedReply = reply.slice(); changedReply[changedReply.length - 1] ^= 1;
    expect((await call(path + "/replies", device, "POST", changedReply)).status).toBe(409);
  });

  it("never widens a phone capability into device/admin/approval or another offer/mailbox", async () => {
    const mailbox = "enrollment-scope-0001", path = base(mailbox); const expiresAt = await setup(mailbox);
    const approval = "p".repeat(64), reader = "r".repeat(64);
    for (const [token, role] of [[approval, "approval"], [reader, "reader"]])
      expect((await call(`/v1/mailboxes/${mailbox}/tokens`, admin, "POST", { accessToken: token, role, recipientKeyId: "parent-recipient-0001",
        publishRecipientKeyIds: role === "approval" ? [recipient] : [], expiresAt: Date.now() + 60000,
        ...(role === "approval" ? { approvalKeyId: "parent-signing-key-001", authorityEpoch: 1, viewRecipientKeyIds: ["parent-view-key-0001"] } : {}) })).status).toBe(201);
    for (const token of [phone, admin, other, approval, reader, "x".repeat(64)]) {
      expect((await call(path + "/requests", token)).status).toBe(403);
      expect((await call(path + "/replies", token, "POST", reply)).status).toBe(403);
      expect((await call(path, token, "DELETE")).status).toBe(403);
      expect((await call(path, token, "POST", { phoneToken: phone, expiresAt })).status).toBe(403);
    }
    expect((await call(path + "/requests", device, "POST", query)).status).toBe(403);
    expect((await call(path + "/replies/" + nonce, device)).status).toBe(403);
    for (const suffix of ["tokens", "poll?recipient=" + recipient, "intents", "registration-tickets"])
      expect((await call(`/v1/mailboxes/${mailbox}/${suffix}`, phone)).status).toBe(401);
    expect((await call(`/v1/mailboxes/${mailbox}/tokens`, admin, "POST", { accessToken: phone, role: "admin", expiresAt })).status).toBe(409);
    expect((await call(base(mailbox, "f".repeat(64)) + "/requests", phone, "POST", query)).status).toBe(410);
    await setup("enrollment-scope-0002", "2".repeat(64));
    expect((await call(base("enrollment-scope-0002") + "/requests", phone, "POST", query)).status).toBe(403);
    expect((await call(base(mailbox, "f".repeat(64)), device, "POST", { phoneToken: phone, expiresAt })).status).toBe(409);
    expect((await call(base(mailbox, "f".repeat(64)), device, "POST", { phoneToken: device, expiresAt })).status).toBe(409);
    const response = await call(path, device, "POST", { phoneToken: "1".repeat(64), expiresAt });
    expect(response.status).toBe(409);
    expect((await call(path, device, "POST", { phoneToken: phone, expiresAt: expiresAt + 1 })).status).toBe(409);
    expect((await call(path + "/requests?anything=1", phone, "POST", query)).status).toBe(404);
  });

  it("allows only status queries after QR expiry and closes all access on retention expiry/revocation", async () => {
    const mailbox = "enrollment-expiry-001", path = base(mailbox); await setup(mailbox);
    await runInDurableObject(stub(mailbox), (_instance, state) => state.storage.sql.exec("UPDATE enrollments SET submit_until=?", Date.now() - 1));
    expect((await call(path + "/requests", phone, "POST", frame(1))).status).toBe(410);
    expect((await call(path + "/requests", phone, "POST", frame(2))).status).toBe(410);
    expect((await call(path + "/requests", phone, "POST", query)).status).toBe(201);
    expect((await call(path + "/replies", device, "POST", reply)).status).toBe(201);
    expect((await call(path + "/replies/" + nonce, phone)).status).toBe(200);
    await runInDurableObject(stub(mailbox), (_instance, state) => state.storage.sql.exec("UPDATE enrollment_exchanges SET expires_at=0"));
    expect((await call(path + "/replies/" + nonce, phone)).status).toBe(410);
    expect((await call(path + "/requests", phone, "POST", frame(3, 1))).status).toBe(201);
    expect((await call(path, device, "DELETE")).status).toBe(204);
    expect((await call(path + "/requests", phone, "POST", query)).status).toBe(410);
    await runInDurableObject(stub(mailbox), (_instance, state) => {
      expect([...state.storage.sql.exec("SELECT * FROM enrollment_exchanges")]).toHaveLength(0);
    });
    expect((await call(path, device, "POST", { phoneToken: phone, expiresAt: Date.now() + 60000 })).status).toBe(201);
    await runInDurableObject(stub(mailbox), (_instance, state) => state.storage.sql.exec("UPDATE enrollments SET retain_until=0"));
    expect((await call(path + "/requests", device)).status).toBe(410);
  });

  it("bounds framing and full chain without widening GRF1; binds replies and lets the device reject poison", async () => {
    const mailbox = "enrollment-bounds-001", path = base(mailbox); await setup(mailbox);
    const large = frame(1, 1, 66000);
    expect((await call(path + "/requests", phone, "POST", large)).status).toBe(201);
    expect((await call(`/v1/mailboxes/${mailbox}/frames`, device, "POST", large)).status).toBe(413);
    expect((await call(path + "/requests", phone, "POST", frame(1, 2, MAX_ENROLLMENT_BYTES + 1))).status).toBe(413);
    for (const raw of [query.slice(0, 192), new Uint8Array([...query, 0]), frame(0), frame(5), frame(2, 2, 226), frame(3, 2, 194), reply])
      expect((await call(path + "/requests", phone, "POST", raw)).status).toBe(400);
    const badVersion = query.slice(); badVersion[7] = 2;
    const badPoint = query.slice(); badPoint[108] = 3;
    const wrongOffer = query.slice(); wrongOffer[12] ^= 1;
    for (const raw of [badVersion, badPoint, wrongOffer]) expect((await call(path + "/requests", phone, "POST", raw)).status).toBe(400);
    const id = parseEnrollment(large).nonce;
    const response = frame(4, 1); response[44] ^= 1;
    expect((await call(path + "/replies", device, "POST", response)).status).toBe(409);
    expect((await call(path + "/replies", device, "POST", frame(4, 1, 415))).status).toBe(413);
    expect((await call(path + "/requests/" + id, device, "DELETE")).status).toBe(204);
    expect((await call(path + "/replies/" + id, phone)).status).toBe(422);
    expect((await call(path + "/requests", device)).status).toBe(204);
    expect((await call(path + "/replies", device, "POST", frame(4, 1))).status).toBe(410);
  });

  it("atomically handles duplicate/colliding nonces and keeps retries working at queue quota", async () => {
    const mailbox = "enrollment-quota-001", path = base(mailbox); await setup(mailbox);
    const both = await Promise.all([call(path + "/requests", phone, "POST", query), call(path + "/requests", phone, "POST", query)]);
    expect(both.map(r => r.status).sort()).toEqual([200, 201]);
    const a = frame(3, 100), b = a.slice(); b[b.length - 1] ^= 1;
    const conflict = await Promise.all([call(path + "/requests", phone, "POST", a), call(path + "/requests", phone, "POST", b)]);
    expect(conflict.map(r => r.status).sort()).toEqual([201, 409]);
    for (let i = 0; i < 30; i++) expect((await call(path + "/requests", phone, "POST", frame(3, i))).status).toBe(201);
    expect((await call(path + "/requests", phone, "POST", frame(3, 999))).status).toBe(429);
    expect((await call(path + "/requests", phone, "POST", query)).status).toBe(200);
    for (let i = 1; i < 8; i++) expect((await call(base(mailbox, i.toString(16).padStart(64, "0")), device, "POST", { phoneToken: i.toString(16).padStart(64, "0"), expiresAt: Date.now() + 60000 })).status).toBe(201);
    expect((await call(base(mailbox, "f".repeat(64)), device, "POST", { phoneToken: "f".repeat(64), expiresAt: Date.now() + 60000 })).status).toBe(429);
  });

  it("enforces actual byte quota and strict registration bounds", async () => {
    const mailbox = "enrollment-byte-0001", path = base(mailbox); await setup(mailbox);
    for (let i = 0; i < 14; i++) expect((await call(path + "/requests", phone, "POST", frame(1, i, MAX_ENROLLMENT_BYTES))).status).toBe(201);
    expect((await call(path + "/requests", phone, "POST", frame(1, 15, MAX_ENROLLMENT_BYTES))).status).toBe(429);
    expect((await call(path + "/requests", phone, "POST", frame(1, 0, MAX_ENROLLMENT_BYTES))).status).toBe(200);
    const next = base(mailbox, "f".repeat(64)), good = { phoneToken: "f".repeat(64), expiresAt: Date.now() + 60000 };
    for (const body of [null, [], {}, { ...good, extra: 1 }, { ...good, phoneToken: "F".repeat(64) },
      { ...good, expiresAt: 0 }, { ...good, expiresAt: Date.now() + 11 * 60000 }, { ...good, expiresAt: 1.1 },
      { ...good, expiresAt: Number.MAX_SAFE_INTEGER + 1 }])
      expect((await call(next, device, "POST", body)).status).toBe(400);
    const bom = await SELF.fetch(`https://example.test${next}`, { method: "POST", headers: headers(device), body: "\ufeff" + JSON.stringify(good) });
    expect(bom.status).toBe(400);
    expect((await call(next, device, "POST", { ...good, phoneToken: "f".repeat(1100) })).status).toBe(413);
    const raw = new Request(`https://example.test${path}/requests`, { method: "POST", headers: { ...headers(phone, "application/octet-stream"), "content-length": "1" }, body: frame(1, 16, MAX_ENROLLMENT_BYTES + 1) });
    expect((await SELF.fetch(raw)).status).toBe(413);
  });

  it("rechecks revoked device credentials after a slow body before writing a reply", async () => {
    const mailbox = "enrollment-revoke-01", path = base(mailbox); await setup(mailbox);
    expect((await call(path + "/requests", phone, "POST", query)).status).toBe(201);
    await runInDurableObject(stub(mailbox), async (instance, state) => {
      let started!: () => void; const reading = new Promise<void>(resolve => { started = resolve; });
      let controller!: ReadableStreamDefaultController<Uint8Array>;
      const stream = new ReadableStream<Uint8Array>({ start(value) { controller = value; }, pull() { started(); } }, { highWaterMark: 0 });
      const pending = instance.fetch(new Request(`https://mailbox.internal${path}/replies`, { method: "POST", headers: { "x-guard-token": device, "content-type": "application/octet-stream" }, body: stream }));
      await reading;
      state.storage.sql.exec("DELETE FROM tokens WHERE role='device'");
      controller.enqueue(reply); controller.close();
      expect((await pending).status).toBe(403);
      expect([...state.storage.sql.exec<{ reply: ArrayBuffer | null }>("SELECT reply FROM enrollment_exchanges")][0]!.reply).toBeNull();
    });
  });

  it("does not publish a slow request after capability revocation and handles expiry during read", async () => {
    const mailbox = "enrollment-slow-0001", path = base(mailbox); await setup(mailbox);
    await runInDurableObject(stub(mailbox), async (instance, state) => {
      for (const revoke of [false, true]) {
        let started!: () => void; const reading = new Promise<void>(resolve => { started = resolve; });
        let controller!: ReadableStreamDefaultController<Uint8Array>;
        const stream = new ReadableStream<Uint8Array>({ start(value) { controller = value; }, pull() { started(); } }, { highWaterMark: 0 });
        const pending = instance.fetch(new Request(`https://mailbox.internal${path}/requests`, { method: "POST", headers: { "x-guard-token": phone, "content-type": "application/octet-stream" }, body: stream }));
        await reading;
        if (revoke) state.storage.sql.exec("DELETE FROM enrollments");
        else state.storage.sql.exec("UPDATE enrollments SET submit_until=0");
        controller.enqueue(frame(1)); controller.close();
        expect((await pending).status).toBe(410);
        expect([...state.storage.sql.exec("SELECT * FROM enrollment_exchanges")]).toHaveLength(0);
      }
    });
  });
});
