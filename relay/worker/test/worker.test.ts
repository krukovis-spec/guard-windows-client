import { env, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { DeviceMailbox } from "../src/index";

const adminToken = "a".repeat(32);
const deviceToken = "d".repeat(32);
const approvalToken = "p".repeat(32);
const readerToken = "r".repeat(32);
const bootstrapToken = "test-only-bootstrap-token-8f3f0d4dd15ebd16c4f5ac14a1c9e617";
const request = (url: string, init: RequestInit = {}) => SELF.fetch(`https://example.test${url}`, init);
const mailbox = "mailbox-test-00001";
const deviceRecipient = "recipient-dev-0001";
const parentRecipient = "recipient-key-0001";
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });
const vectorHex = "475246310000000100000002000000126d61696c626f782d616c7068612d3030303100000012726563697069656e742d6b65792d30303031000000116672616d652d616c7068612d3030303031000000000000000b000000000000000a0000019f93ff31b80000019f93ff35a0000000410102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40410000002065666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384";
const vector = Uint8Array.from(vectorHex.match(/../g)!.map(x => Number.parseInt(x, 16)));
function writeU64(bytes: Uint8Array, offset: number, value: number): void { let x = BigInt(value); for (let i = 7; i >= 0; i--) { bytes[offset + i] = Number(x & 255n); x >>= 8n; } }
function frame(cursor: number, id: string, kind = 1, recipient = parentRecipient, mailboxId = mailbox): Uint8Array { const b = vector.slice(); b[11] = kind; const mailboxOffset = 16; b.set(new TextEncoder().encode(mailboxId), mailboxOffset); b.set(new TextEncoder().encode(recipient), 38); b.set(new TextEncoder().encode(id), 60); writeU64(b, 77, cursor); writeU64(b, 85, 0); writeU64(b, 93, Date.now()); writeU64(b, 101, Date.now() + 60000); return b; }

describe("mailbox authorization and signing intent", () => {
  it("fails closed when bootstrap secret is absent", async () => {
    const result = await request("/v1/admin/bootstrap", { method: "POST", headers: { authorization: `Bearer ${adminToken}`, "content-type": "application/json" }, body: JSON.stringify({ mailboxId: "mailbox-test-0001", accessToken: adminToken }) });
    expect(result.status).toBe(403);
  });
  it("rejects unauthenticated and role-bypass requests", async () => {
    const result = await request("/v1/mailboxes/mailbox-test-0001/frames", { method: "POST", body: new Uint8Array() });
    expect(result.status).toBe(401);
  });
  it("rejects WebAuthn options without the configured relying-party origin", async () => {
    const result = await request("/v1/auth/login/options", { method: "POST" });
    expect(result.status).toBe(403);
    await expect(result.json()).resolves.toEqual({ error: "origin_rejected" });
  });
  it("migrates old tables fail closed and preserves existing published cursor floors", async () => {
    const migrationMailbox = "mailbox-test-00002";
    const stub = env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(migrationMailbox));
    const oldFrame = frame(21, "frame-alpha-00021", 1, parentRecipient, migrationMailbox);
    await runInDurableObject(stub, async (_instance, state) => {
      // Only the disposable local test DO: recreate the previous schema.
      state.storage.sql.exec(`DROP TABLE tokens; DROP TABLE parent_locators; DROP TABLE tombstones; DROP TABLE publication_cursors;
        CREATE TABLE tokens(hash BLOB PRIMARY KEY,role TEXT NOT NULL,expires_at INTEGER NOT NULL);
        CREATE TABLE parent_locators(locator_hash BLOB PRIMARY KEY,request_id_hash BLOB NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL);
        CREATE TABLE tombstones(frame_id TEXT PRIMARY KEY,expires_at INTEGER NOT NULL);`);
      for (const [token, role] of [[adminToken, "admin"], [deviceToken, "device"]]) {
        const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
        state.storage.sql.exec("INSERT INTO tokens(hash,role,expires_at) VALUES(?,?,?)", hash, role, Date.now() + 60000);
      }
      state.storage.sql.exec("INSERT INTO frames(frame_id,recipient_key_id,kind,cursor,expires_at,bytes,size) VALUES(?,?,?,?,?,?,?)",
        "frame-alpha-00021", parentRecipient, 1, 21, Date.now() + 60000, oldFrame, oldFrame.byteLength);
      state.storage.sql.exec("INSERT INTO acknowledgements(recipient_key_id,cursor) VALUES(?,?)", parentRecipient, 20);
      new DeviceMailbox(state, env);
    });
    let response = await request(`/v1/mailboxes/${migrationMailbox}/poll?recipient=${parentRecipient}&after=20`, { headers: bearer(adminToken) });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ nextCursor: 21 });
    response = await request(`/v1/mailboxes/${migrationMailbox}/poll?recipient=${parentRecipient}&after=20`, { headers: bearer(deviceToken) });
    expect(response.status).toBe(401);
    await runInDurableObject(stub, (_instance, state) => {
      new DeviceMailbox(state, env); // Idempotent second migration.
      expect([...state.storage.sql.exec<{ cursor: number }>("SELECT cursor FROM publication_cursors WHERE recipient_key_id=?", parentRecipient)][0]?.cursor).toBe(21);
    });
  });
  it("enforces persisted cursors, role boundaries, idempotency, and burned sequence hints", async () => {
    let response = await request("/v1/admin/bootstrap", { method: "POST", headers: { ...bearer(bootstrapToken), "content-type": "application/json" }, body: JSON.stringify({ mailboxId: mailbox, accessToken: adminToken }) });
    expect(response.status).toBe(201);
    response = await request("/v1/admin/bootstrap", { method: "POST", headers: { ...bearer(bootstrapToken), "content-type": "application/json" }, body: JSON.stringify({ mailboxId: mailbox, accessToken: adminToken }) });
    expect(response.status).toBe(409);
    for (const [accessToken, role] of [[deviceToken, "device"], [approvalToken, "approval"], [readerToken, "reader"]] as const) {
      response = await request(`/v1/mailboxes/${mailbox}/tokens`, { method: "POST", headers: { ...bearer(adminToken), "content-type": "application/json" }, body: JSON.stringify({ accessToken, role, expiresAt: Date.now() + 600000,
        recipientKeyId: role === "device" ? deviceRecipient : parentRecipient,
        publishRecipientKeyIds: role === "device" ? [parentRecipient] : role === "approval" ? [deviceRecipient] : [],
        ...(role === "approval" ? { approvalKeyId: "parent-key-test-01", authorityEpoch: 1, viewRecipientKeyIds: [parentRecipient] } : {}) }) }); expect(response.status).toBe(201);
    }
    const ten = frame(10, "frame-alpha-00010");
    const future = frame(10, "frame-alpha-00010");
    writeU64(future, 93, Date.now() + 10 * 60000); writeU64(future, 101, Date.now() + 11 * 60000);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: future }); expect(response.status).toBe(400);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: ten }); expect(response.status).toBe(201);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: ten }); expect(response.status).toBe(200);
    const conflict = frame(10, "frame-alpha-00010"); conflict[conflict.length - 1] ^= 1;
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: conflict }); expect(response.status).toBe(409);
    response = await request(`/v1/mailboxes/${mailbox}/ack`, { method: "POST", headers: { ...bearer(deviceToken), "content-type": "application/json" }, body: JSON.stringify({ recipientKeyId: parentRecipient, cursor: 10 }) }); expect(response.status).toBe(403);
    response = await request(`/v1/mailboxes/${mailbox}/ack`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ recipientKeyId: parentRecipient, cursor: 10 }) }); expect(response.status).toBe(200);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: ten }); expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ frameId: "frame-alpha-00010", duplicate: true });
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: conflict }); expect(response.status).toBe(409);
    response = await request(`/v1/mailboxes/${mailbox}/ack`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ recipientKeyId: parentRecipient, cursor: 11 }) }); expect(response.status).toBe(409);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: frame(11, "frame-alpha-00011") }); expect(response.status).toBe(201);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: frame(10, "frame-alpha-00012") }); expect(response.status).toBe(409);
    response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=recipient-key-0001&after=10`, { headers: bearer(approvalToken) }); expect(response.status).toBe(200);
    response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=recipient-key-0001&after=10`, { headers: bearer(readerToken) }); expect(response.status).toBe(403);
    response = await request(`/v1/mailboxes/${mailbox}/intents/reserve`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ authorityEpoch: 1, keyId: "parent-key-test-01", intentId: "intent-alpha-0001" }) }); expect(await response.json()).toMatchObject({ sequence: 1 });
    response = await request(`/v1/mailboxes/${mailbox}/intents/cancel`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ authorityEpoch: 1, keyId: "parent-key-test-01", intentId: "intent-alpha-0001" }) }); expect(response.status).toBe(200);
    response = await request(`/v1/mailboxes/${mailbox}/intents/reserve`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ authorityEpoch: 1, keyId: "parent-key-test-01", intentId: "intent-alpha-0002" }) }); expect(await response.json()).toMatchObject({ sequence: 2 });

    for (const [token, recipient] of [[deviceToken, parentRecipient], [approvalToken, deviceRecipient]]) {
      response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=${recipient}&after=0`, { headers: bearer(token!) });
      expect(response.status).toBe(403);
      response = await request(`/v1/mailboxes/${mailbox}/ack`, { method: "POST", headers: { ...bearer(token!), "content-type": "application/json" }, body: JSON.stringify({ recipientKeyId: recipient, cursor: 1 }) });
      expect(response.status).toBe(403);
    }
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: frame(1, "frame-alpha-00013", 1, deviceRecipient) }); expect(response.status).toBe(403);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(approvalToken), body: frame(1, "frame-alpha-00013", 2) }); expect(response.status).toBe(403);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(approvalToken), body: frame(1, "frame-alpha-00013", 1, deviceRecipient) }); expect(response.status).toBe(403);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(approvalToken), body: frame(1, "frame-alpha-00013", 2, deviceRecipient) }); expect(response.status).toBe(201);
    response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=${deviceRecipient}&after=0`, { headers: bearer(deviceToken) });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ nextCursor: 1 });

    for (const operation of ["reserve", "finalize", "cancel"]) {
      for (const [keyId, authorityEpoch] of [["parent-key-other-1", 1], ["parent-key-test-01", 2]]) {
        response = await request(`/v1/mailboxes/${mailbox}/intents/${operation}`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ keyId, authorityEpoch, intentId: "intent-alpha-0002" }) });
        expect(response.status).toBe(403);
      }
    }
    response = await request(`/v1/mailboxes/${mailbox}/intents?authorityEpoch=1&keyId=parent-key-other-1`, { headers: bearer(approvalToken) }); expect(response.status).toBe(403);
    response = await request(`/v1/mailboxes/${mailbox}/other/frames`, { method: "POST", headers: bearer(deviceToken), body: ten }); expect(response.status).toBe(404);
    for (const after of ["-1", "9007199254740992", "1e3", "NaN"]) {
      response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=${parentRecipient}&after=${after}`, { headers: bearer(approvalToken) }); expect(response.status).toBe(400);
    }

    const ownIntent = { keyId: "parent-key-test-01", authorityEpoch: 1, intentId: "intent-alpha-0002" };
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(adminToken), body: frame(1, "frame-alpha-00014", 3, "recipient-key-0002") }); expect(response.status).toBe(201);
    response = await request(`/v1/mailboxes/${mailbox}/intents/finalize`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ ...ownIntent, receiptFrameId: "frame-alpha-00014" }) }); expect(response.status).toBe(409);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: frame(12, "frame-alpha-00015", 3) }); expect(response.status).toBe(201);
    response = await request(`/v1/mailboxes/${mailbox}/intents/finalize`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ ...ownIntent, receiptFrameId: "frame-alpha-00015" }) });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ sequence: 2, status: "receipt_observed", nonAuthoritative: true });

    const stub = env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(mailbox));
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec("UPDATE frames SET expires_at=0 WHERE recipient_key_id=?", parentRecipient);
      state.storage.sql.exec("UPDATE tombstones SET expires_at=0 WHERE recipient_key_id=?", parentRecipient);
    });
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: frame(12, "frame-alpha-00016") }); expect(response.status).toBe(409);
    response = await request(`/v1/mailboxes/${mailbox}/ack`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ recipientKeyId: parentRecipient, cursor: 12 }) }); expect(response.status).toBe(200);
    const next = frame(13, "frame-alpha-00017");
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: next }); expect(response.status).toBe(201);
    response = await request(`/v1/mailboxes/${mailbox}/ack`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ recipientKeyId: parentRecipient, cursor: 13 }) }); expect(response.status).toBe(200);
    await runInDurableObject(stub, (_instance, state) => {
      for (let index = 0; index < 1000; index++) state.storage.sql.exec(
        "INSERT INTO frames(frame_id,recipient_key_id,kind,cursor,expires_at,bytes,size) VALUES(?,?,?,?,?,?,?)",
        `quota-fixture-${index}`, "quota-fixture-recipient", 1, index, Date.now() + 60000, Uint8Array.of(0), 1);
    });
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: next }); expect(response.status).toBe(200);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: frame(14, "frame-alpha-00018") }); expect(response.status).toBe(429);

    const legacyToken = "l".repeat(32);
    await runInDurableObject(stub, async (_instance, state) => {
      const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(legacyToken));
      state.storage.sql.exec("INSERT INTO tokens(hash,role,expires_at) VALUES(?,?,?)", hash, "device", Date.now() + 60000);
    });
    response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=${deviceRecipient}&after=0`, { headers: bearer(legacyToken) }); expect(response.status).toBe(401);
    response = await request(`/v1/mailboxes/${mailbox}/tokens`, { method: "POST", headers: { ...bearer(adminToken), "content-type": "application/json" }, body: JSON.stringify({ accessToken: "x".repeat(32), role: "device", expiresAt: Date.now() + 60000 }) }); expect(response.status).toBe(400);
    response = await request(`/v1/mailboxes/${mailbox}/tokens`, { method: "DELETE", headers: { ...bearer(adminToken), "content-type": "application/json" }, body: JSON.stringify({ accessToken: approvalToken }) }); expect(response.status).toBe(204);
    response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=${parentRecipient}&after=0`, { headers: bearer(approvalToken) }); expect(response.status).toBe(401);
    await runInDurableObject(stub, (_instance, state) => { state.storage.sql.exec("UPDATE tokens SET expires_at=0 WHERE role='device'"); });
    response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=${deviceRecipient}&after=0`, { headers: bearer(deviceToken) }); expect(response.status).toBe(401);
  });
});
