import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const adminToken = "a".repeat(32);
const deviceToken = "d".repeat(32);
const approvalToken = "p".repeat(32);
const readerToken = "r".repeat(32);
const bootstrapToken = "test-only-bootstrap-token-8f3f0d4dd15ebd16c4f5ac14a1c9e617";
const request = (url: string, init: RequestInit = {}) => SELF.fetch(`https://example.test${url}`, init);
const mailbox = "mailbox-test-00001";
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });
const vectorHex = "475246310000000100000002000000126d61696c626f782d616c7068612d3030303100000012726563697069656e742d6b65792d30303031000000116672616d652d616c7068612d3030303031000000000000000b000000000000000a0000019f93ff31b80000019f93ff35a0000000410102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40410000002065666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384";
const vector = Uint8Array.from(vectorHex.match(/../g)!.map(x => Number.parseInt(x, 16)));
function writeU64(bytes: Uint8Array, offset: number, value: number): void { let x = BigInt(value); for (let i = 7; i >= 0; i--) { bytes[offset + i] = Number(x & 255n); x >>= 8n; } }
function frame(cursor: number, id: string, kind = 1): Uint8Array { const b = vector.slice(); b[11] = kind; const mailboxOffset = 16; b.set(new TextEncoder().encode(mailbox), mailboxOffset); b.set(new TextEncoder().encode(id), 60); writeU64(b, 77, cursor); writeU64(b, 85, 0); writeU64(b, 93, Date.now()); writeU64(b, 101, Date.now() + 60000); return b; }

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
  it("enforces persisted cursors, role boundaries, idempotency, and burned sequence hints", async () => {
    let response = await request("/v1/admin/bootstrap", { method: "POST", headers: { ...bearer(bootstrapToken), "content-type": "application/json" }, body: JSON.stringify({ mailboxId: mailbox, accessToken: adminToken }) });
    expect(response.status).toBe(201);
    response = await request("/v1/admin/bootstrap", { method: "POST", headers: { ...bearer(bootstrapToken), "content-type": "application/json" }, body: JSON.stringify({ mailboxId: mailbox, accessToken: adminToken }) });
    expect(response.status).toBe(409);
    for (const [accessToken, role] of [[deviceToken, "device"], [approvalToken, "approval"], [readerToken, "reader"]] as const) {
      response = await request(`/v1/mailboxes/${mailbox}/tokens`, { method: "POST", headers: { ...bearer(adminToken), "content-type": "application/json" }, body: JSON.stringify({ accessToken, role, expiresAt: Date.now() + 600000 }) }); expect(response.status).toBe(201);
    }
    const ten = frame(10, "frame-alpha-00010");
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: ten }); expect(response.status).toBe(201);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: ten }); expect(response.status).toBe(200);
    const conflict = frame(10, "frame-alpha-00010"); conflict[conflict.length - 1] ^= 1;
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: conflict }); expect(response.status).toBe(409);
    response = await request(`/v1/mailboxes/${mailbox}/ack`, { method: "POST", headers: { ...bearer(deviceToken), "content-type": "application/json" }, body: JSON.stringify({ recipientKeyId: "recipient-key-0001", cursor: 10 }) }); expect(response.status).toBe(200);
    response = await request(`/v1/mailboxes/${mailbox}/ack`, { method: "POST", headers: { ...bearer(deviceToken), "content-type": "application/json" }, body: JSON.stringify({ recipientKeyId: "recipient-key-0001", cursor: 11 }) }); expect(response.status).toBe(409);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: frame(11, "frame-alpha-00011") }); expect(response.status).toBe(201);
    response = await request(`/v1/mailboxes/${mailbox}/frames`, { method: "POST", headers: bearer(deviceToken), body: frame(10, "frame-alpha-00012") }); expect(response.status).toBe(409);
    response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=recipient-key-0001&after=10`, { headers: bearer(approvalToken) }); expect(response.status).toBe(200);
    response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=recipient-key-0001&after=10`, { headers: bearer(readerToken) }); expect(response.status).toBe(403);
    response = await request(`/v1/mailboxes/${mailbox}/intents/reserve`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ authorityEpoch: 1, keyId: "parent-key-test-01", intentId: "intent-alpha-0001" }) }); expect(await response.json()).toMatchObject({ sequence: 1 });
    response = await request(`/v1/mailboxes/${mailbox}/intents/cancel`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ authorityEpoch: 1, keyId: "parent-key-test-01", intentId: "intent-alpha-0001" }) }); expect(response.status).toBe(200);
    response = await request(`/v1/mailboxes/${mailbox}/intents/reserve`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ authorityEpoch: 1, keyId: "parent-key-test-01", intentId: "intent-alpha-0002" }) }); expect(await response.json()).toMatchObject({ sequence: 2 });
  });
});
