import { env, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { DeviceMailbox } from "../src/index";
import { BFF_AUTH_OBJECT_NAME } from "../src/bff";

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
function buildFrame(cursor: number, id: string, kind = 1, recipient = parentRecipient, mailboxId = mailbox): Uint8Array {
  const identifiers = [mailboxId, recipient, id].flatMap(value => {
    const bytes = new TextEncoder().encode(value);
    const field = new Uint8Array(4 + bytes.length);
    new DataView(field.buffer).setUint32(0, bytes.length);
    field.set(bytes, 4);
    return [...field];
  });
  const suffix = vector.slice(77);
  writeU64(suffix, 0, cursor); writeU64(suffix, 8, 0);
  writeU64(suffix, 16, Date.now()); writeU64(suffix, 24, Date.now() + 60000);
  const bytes = new Uint8Array([...vector.slice(0, 12), ...identifiers, ...suffix]);
  bytes[11] = kind;
  return bytes;
}

describe("mailbox authorization and signing intent", () => {
  it("retries initial device provisioning without changing later rights or resurrecting revocation", async () => {
    const mailbox = "mailbox-initial-retry-0001", prefix = `/v1/mailboxes/${mailbox}`;
    const call = (path: string, body: unknown, token = adminToken, method = "POST") => request(path, {
      method, headers: { ...bearer(token), "content-type": "application/json" }, body: JSON.stringify(body),
    });
    expect((await call("/v1/admin/bootstrap", { mailboxId: mailbox, accessToken: adminToken }, bootstrapToken)).status).toBe(201);
    const initial = { accessToken: deviceToken, role: "device", recipientKeyId: deviceRecipient,
      publishRecipientKeyIds: [], expiresAt: Date.now() + 600000 };
    const create = (body: unknown = initial, token = adminToken) => call(prefix + "/tokens/initial", body, token);
    const stub = env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(mailbox));
    expect((await create()).status).toBe(201); // Simulate lost reply: repeat the identical durable intent.
    await runInDurableObject(stub, (_instance, state) => { new DeviceMailbox(state, env); });
    expect(await (await create()).json()).toEqual({ role: "device", expiresAt: initial.expiresAt });
    expect((await create(initial, deviceToken)).status).toBe(403);
    expect((await call(prefix + "/tokens/initial", initial, adminToken, "DELETE")).status).toBe(404);
    for (const change of [{ role: "admin", recipientKeyId: undefined }, { role: "reader" },
      { publishRecipientKeyIds: [parentRecipient] }, { publishRecipientKeyIds: undefined },
      { accessToken: "short" }, { expiresAt: Date.now() - 1 }, { expiresAt: Number.MAX_SAFE_INTEGER + 1 }, { ignored: true }])
      expect((await create({ ...initial, ...change })).status).toBe(400);
    for (const change of [{ recipientKeyId: parentRecipient }, { expiresAt: initial.expiresAt + 1 }])
      expect((await create({ ...initial, ...change })).status).toBe(409);
    // Intentional later provisioning remains available, but a delayed INITIAL retry must not undo it.
    const later = { ...initial, publishRecipientKeyIds: [parentRecipient] };
    expect((await call(prefix + "/tokens", later)).status).toBe(201);
    expect((await create()).status).toBe(409);
    expect((await request(prefix + "/frames", { method: "POST", headers: bearer(deviceToken),
      body: buildFrame(1, "frame-initial-retry-001", 1, parentRecipient, mailbox) })).status).toBe(201);
    expect((await call(prefix + "/tokens", { accessToken: deviceToken }, adminToken, "DELETE")).status).toBe(204);
    await runInDurableObject(stub, (_instance, state) => { new DeviceMailbox(state, env); });
    expect((await create()).status).toBe(409);
    expect((await create({ ...initial, expiresAt: initial.expiresAt + 60000 })).status).toBe(409);
    expect((await request(prefix + `/poll?recipient=${deviceRecipient}`, { headers: bearer(deviceToken) })).status).toBe(401);
    // The initial route cannot adopt even an identical credential created by the ordinary admin route.
    const legacy = { ...initial, accessToken: "l".repeat(32) };
    expect((await call(prefix + "/tokens", legacy)).status).toBe(201);
    expect((await create(legacy)).status).toBe(409);
    await runInDurableObject(stub, (_instance, state) => {
      const rows = [...state.storage.sql.exec("SELECT recipient_key_id,expires_at FROM initial_device_tokens")];
      expect(rows).toEqual([{ recipient_key_id: deviceRecipient, expires_at: initial.expiresAt }]);
    });
  });

  it("serializes conflicting initial intents and commits their retry marker atomically", async () => {
    const mailbox = "mailbox-initial-atomic-0001", prefix = `/v1/mailboxes/${mailbox}`;
    const post = (path: string, body: unknown, token = adminToken) => request(path, {
      method: "POST", headers: { ...bearer(token), "content-type": "application/json" }, body: JSON.stringify(body),
    });
    expect((await post("/v1/admin/bootstrap", { mailboxId: mailbox, accessToken: adminToken }, bootstrapToken)).status).toBe(201);
    const initial = { accessToken: deviceToken, role: "device", recipientKeyId: deviceRecipient,
      publishRecipientKeyIds: [], expiresAt: Date.now() + 600000 };
    const stub = env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(mailbox));
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec("CREATE TRIGGER fail_initial BEFORE INSERT ON tokens BEGIN SELECT RAISE(ABORT,'test-only-fault'); END");
    });
    expect((await post(prefix + "/tokens/initial", initial)).status).toBe(503);
    await runInDurableObject(stub, (_instance, state) => {
      expect([...state.storage.sql.exec<{ n: number }>("SELECT count(*) n FROM initial_device_tokens")][0]!.n).toBe(0);
      expect([...state.storage.sql.exec<{ n: number }>("SELECT count(*) n FROM tokens")][0]!.n).toBe(1);
      state.storage.sql.exec("DROP TRIGGER fail_initial");
    });
    const competing = [initial, { ...initial, recipientKeyId: parentRecipient }];
    const results = await Promise.all(competing.map(body => post(prefix + "/tokens/initial", body)));
    expect(results.map(result => result.status).sort()).toEqual([201, 409]);
    const winner = competing[results.findIndex(result => result.status === 201)]!;
    expect((await post(prefix + "/tokens/initial", winner)).status).toBe(201);
    await runInDurableObject(stub, (_instance, state) => {
      expect([...state.storage.sql.exec("SELECT recipient_key_id,expires_at FROM initial_device_tokens")])
        .toEqual([{ recipient_key_id: winner.recipientKeyId, expires_at: initial.expiresAt }]);
    });
  });

  it("bounds initial retry history without evicting live revocation markers", async () => {
    const mailbox = "mailbox-initial-quota-0001", prefix = `/v1/mailboxes/${mailbox}`;
    const post = (path: string, body: unknown, token = adminToken) => request(path, {
      method: "POST", headers: { ...bearer(token), "content-type": "application/json" }, body: JSON.stringify(body),
    });
    expect((await post("/v1/admin/bootstrap", { mailboxId: mailbox, accessToken: adminToken }, bootstrapToken)).status).toBe(201);
    const initial = { accessToken: deviceToken, role: "device", recipientKeyId: deviceRecipient,
      publishRecipientKeyIds: [], expiresAt: Date.now() + 600000 };
    const create = (body: unknown = initial) => post(prefix + "/tokens/initial", body);
    expect((await create()).status).toBe(201);
    const stub = env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(mailbox));
    await runInDurableObject(stub, (_instance, state) => {
      for (let i = 0; i < 255; i++) {
        const hash = new Uint8Array(32); hash[0] = i;
        state.storage.sql.exec("INSERT INTO initial_device_tokens(hash,recipient_key_id,expires_at) VALUES(?,?,?)",
          hash.buffer, parentRecipient, initial.expiresAt);
      }
    });
    expect((await create()).status).toBe(201); // Read-only duplicates do not consume quota.
    const next = { ...initial, accessToken: "n".repeat(32) };
    expect((await create(next)).status).toBe(429);
    await runInDurableObject(stub, (_instance, state) => {
      expect([...state.storage.sql.exec<{ n: number }>("SELECT count(*) n FROM tokens")][0]!.n).toBe(2);
      expect([...state.storage.sql.exec<{ n: number }>("SELECT count(*) n FROM initial_device_tokens")][0]!.n).toBe(256);
      state.storage.sql.exec("UPDATE initial_device_tokens SET expires_at=0 WHERE recipient_key_id=?", parentRecipient);
    });
    expect((await create(next)).status).toBe(201); // Only expired markers are cleaned up.
    expect((await create({ ...initial, accessToken: "e".repeat(32), expiresAt: Date.now() - 1 })).status).toBe(400);
    await runInDurableObject(stub, (_instance, state) => {
      expect([...state.storage.sql.exec<{ n: number }>("SELECT count(*) n FROM initial_device_tokens")][0]!.n).toBe(2);
      for (let i = 0; i < 253; i++) {
        const hash = new Uint8Array(32); hash[0] = i;
        state.storage.sql.exec("INSERT INTO tokens(hash,role,expires_at) VALUES(?,'admin',?)", hash.buffer, initial.expiresAt);
      }
    });
    expect((await create({ ...initial, accessToken: "q".repeat(32) })).status).toBe(429);
    await runInDurableObject(stub, (_instance, state) => {
      expect([...state.storage.sql.exec<{ n: number }>("SELECT count(*) n FROM initial_device_tokens")][0]!.n).toBe(2);
    });
  });

  it("commits only one concurrent initial mailbox administrator", async () => {
    const mailbox = "mailbox-bootstrap-race-0001";
    const responses = await Promise.all([adminToken, "z".repeat(32)].map(accessToken => request("/v1/admin/bootstrap", {
      method: "POST", headers: { ...bearer(bootstrapToken), "content-type": "application/json" },
      body: JSON.stringify({ mailboxId: mailbox, accessToken }),
    })));
    expect(responses.map(response => response.status).sort()).toEqual([201, 409]);
    await runInDurableObject(env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(mailbox)), (_instance, state) => {
      expect([...state.storage.sql.exec<{ n: number }>("SELECT count(*) n FROM tokens WHERE role='admin'")][0]!.n).toBe(1);
    });
  });

  it("rejects stale scope, role or lifetime after reading a slow mutating request", async () => {
    const cases = [
      ["frames", "POST", deviceToken, "UPDATE tokens SET publish_recipient_key_ids='[]' WHERE role='device'", 403],
      ["frames", "POST", deviceToken, "UPDATE tokens SET expires_at=0 WHERE role='device'", 401],
      ["tokens", "POST", adminToken, "DELETE FROM tokens WHERE role='admin'", 401],
      ["tokens/initial", "POST", adminToken, "DELETE FROM tokens WHERE role='admin'", 401],
      ["tokens", "DELETE", adminToken, "DELETE FROM tokens WHERE role='admin'", 401],
      ["ack", "POST", deviceToken, "UPDATE tokens SET recipient_key_id='recipient-other-0001' WHERE role='device'", 403],
      ...["reserve", "finalize", "cancel"].map(operation => ["intents/" + operation, "POST", approvalToken,
        "UPDATE tokens SET authority_epoch=2 WHERE role='approval'", 403] as const),
      ["locators/redeem", "POST", approvalToken, "UPDATE tokens SET view_recipient_key_ids='[\"recipient-other-0001\"]' WHERE role='approval'", 403],
    ] as const;
    for (const [index, [route, method, token, mutation, status]] of cases.entries()) {
      const mailbox = `mailbox-slow-scope-${index}-0001`, prefix = `/v1/mailboxes/${mailbox}`;
      const post = (path: string, bearerToken: string, body: unknown) => request(path, {
        method: "POST", headers: { ...bearer(bearerToken), "content-type": "application/json" }, body: JSON.stringify(body),
      });
      expect((await post("/v1/admin/bootstrap", bootstrapToken, { mailboxId: mailbox, accessToken: adminToken })).status).toBe(201);
      for (const [accessToken, role] of [[deviceToken, "device"], [approvalToken, "approval"]] as const)
        expect((await post(prefix + "/tokens", adminToken, { accessToken, role, expiresAt: Date.now() + 600000,
          recipientKeyId: role === "device" ? deviceRecipient : parentRecipient,
          publishRecipientKeyIds: [role === "device" ? parentRecipient : deviceRecipient],
          ...(role === "approval" ? { approvalKeyId: "approval-signing-0001", authorityEpoch: 1, viewRecipientKeyIds: [parentRecipient] } : {}),
        })).status).toBe(201);
      const payload = route === "frames" ? buildFrame(1, "frame-slow-scope-001", 1, parentRecipient, mailbox) : new TextEncoder().encode(JSON.stringify(
        route === "tokens/initial" ? { accessToken: "x".repeat(32), role: "device", recipientKeyId: deviceRecipient,
          publishRecipientKeyIds: [], expiresAt: Date.now() + 600000 } : route === "tokens" ? (method === "DELETE" ? { accessToken: deviceToken } : {
          accessToken: "x".repeat(32), role: "reader", recipientKeyId: parentRecipient, publishRecipientKeyIds: [], expiresAt: Date.now() + 600000,
        }) : route === "ack" ? { recipientKeyId: deviceRecipient, cursor: 0 } : route === "locators/redeem" ? { locator: "A".repeat(43) } :
          { keyId: "approval-signing-0001", authorityEpoch: 1, intentId: "intent-slow-test-0001" }));
      await runInDurableObject(env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(mailbox)), async (instance, state) => {
        let started!: () => void;
        const reading = new Promise<void>(resolve => { started = resolve; });
        let controller!: ReadableStreamDefaultController<Uint8Array>;
        const stream = new ReadableStream<Uint8Array>({ start(value) { controller = value; }, pull() { started(); } }, { highWaterMark: 0 });
        const pending = instance.fetch(new Request(`https://mailbox.internal${prefix}/${route}`, {
          method, headers: { "x-guard-token": token, "content-type": route === "frames" ? "application/octet-stream" : "application/json" }, body: stream,
        }));
        await reading;
        state.storage.sql.exec(mutation);
        const capture = () => ["tokens", "initial_device_tokens", "frames", "acknowledgements", "intents", "sequence_floors", "parent_locators"]
          .map(table => [...state.storage.sql.exec(`SELECT * FROM ${table} ORDER BY rowid`)]);
        const before = capture();
        controller.enqueue(payload); controller.close();
        expect((await pending).status, route).toBe(status);
        expect(capture(), route + " mutated state after scope change").toEqual(before);
      });
    }
  });

  it("starts a device without invented phone recipients and grants only an explicit later scope", async () => {
    const mailbox = "mailbox-before-phone-0001", prefix = `/v1/mailboxes/${mailbox}`;
    const jsonCall = (path: string, token: string, body: unknown, method = "POST") => request(path, {
      method, headers: { ...bearer(token), "content-type": "application/json" }, body: JSON.stringify(body),
    });
    expect((await jsonCall("/v1/admin/bootstrap", bootstrapToken, { mailboxId: mailbox, accessToken: adminToken })).status).toBe(201);
    const scope = { accessToken: deviceToken, role: "device", recipientKeyId: deviceRecipient,
      publishRecipientKeyIds: [] as string[], expiresAt: Date.now() + 600000 };
    expect((await jsonCall(prefix + "/tokens", adminToken, scope)).status).toBe(201);
    const stub = env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(mailbox));
    await runInDurableObject(stub, (_instance, state) => { new DeviceMailbox(state, env); });
    const publish = (id: string, kind = 1, recipient = parentRecipient) => request(prefix + "/frames", {
      method: "POST", headers: bearer(deviceToken), body: buildFrame(1, id, kind, recipient, mailbox),
    });
    for (const kind of [1, 2, 3, 4])
      expect((await publish(`frame-unbound-${kind}-0001`, kind)).status).toBe(403);
    expect((await publish("frame-to-self-0001", 1, deviceRecipient)).status).toBe(403);
    expect((await request(prefix + `/poll?recipient=${deviceRecipient}&after=0`, { headers: bearer(deviceToken) })).status).toBe(200);
    expect((await request(prefix + `/poll?recipient=${parentRecipient}&after=0`, { headers: bearer(deviceToken) })).status).toBe(403);
    expect((await jsonCall(prefix + "/ack", deviceToken, { recipientKeyId: parentRecipient, cursor: 1 })).status).toBe(403);
    for (const body of [{ ...scope, publishRecipientKeyIds: [parentRecipient] }, { ...scope, role: "admin", recipientKeyId: undefined }])
      expect((await jsonCall(prefix + "/tokens", deviceToken, body)).status).toBe(403);
    expect((await jsonCall(prefix + "/tokens", deviceToken, { accessToken: adminToken }, "DELETE")).status).toBe(403);
    for (const route of ["registration-tickets", "intents/reserve", "locators/redeem"])
      expect((await jsonCall(prefix + "/" + route, deviceToken, {})).status).toBe(403);
    const approval = { ...scope, accessToken: approvalToken, role: "approval", approvalKeyId: "approval-signing-0001",
      authorityEpoch: 1, viewRecipientKeyIds: [parentRecipient] };
    for (const body of [approval, { ...scope, publishRecipientKeyIds: null },
      { ...scope, publishRecipientKeyIds: undefined }, { ...scope, recipientKeyId: undefined },
      { ...scope, publishRecipientKeyIds: ["*"] }, { ...scope, publishRecipientKeyIds: [parentRecipient, parentRecipient] }])
      expect((await jsonCall(prefix + "/tokens", adminToken, body)).status).toBe(400);
    // Invalid updates cannot broaden or invalidate the previously installed empty scope.
    expect((await publish("frame-still-unbound-01")).status).toBe(403);
    await runInDurableObject(stub, (_instance, state) => {
      expect([...state.storage.sql.exec<{ n: number }>("SELECT count(*) n FROM frames")][0]!.n).toBe(0);
    });
    expect((await jsonCall(prefix + "/tokens", adminToken, { ...scope, publishRecipientKeyIds: [parentRecipient] })).status).toBe(201);
    expect((await publish("frame-after-binding-01")).status).toBe(201);
    expect((await publish("frame-other-parent-01", 1, "recipient-other-0001")).status).toBe(403);
    // Withdrawing destinations leaves the same token usable for its own inbox/ceremony only.
    expect((await jsonCall(prefix + "/tokens", adminToken, scope)).status).toBe(201);
    expect((await publish("frame-after-withdraw-01")).status).toBe(403);
    expect((await jsonCall(prefix + "/tokens", adminToken, { accessToken: deviceToken }, "DELETE")).status).toBe(204);
    expect((await request(prefix + `/poll?recipient=${deviceRecipient}&after=0`, { headers: bearer(deviceToken) })).status).toBe(401);
  });

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
  it("rejects malformed mailbox IDs and keeps the global auth object private", async () => {
    for (const mailboxId of [BFF_AUTH_OBJECT_NAME, "a".repeat(15), "a".repeat(129), "mailbox-invalid-01\n",
      "mailbox-invalid-01/", "mailbox-invalid-01%", "mailbox-invalid-01é"]) {
      const response = await request("/v1/admin/bootstrap", { method: "POST", headers: { ...bearer(bootstrapToken), "content-type": "application/json" },
        body: JSON.stringify({ mailboxId, accessToken: adminToken }) });
      expect(response.status).toBe(400);
      expect((await request(`/v1/mailboxes/${encodeURIComponent(mailboxId)}/poll`, { headers: bearer(adminToken) })).status).toBe(404);
    }
    expect((await request(`/v1/mailboxes/${BFF_AUTH_OBJECT_NAME}/tokens`, { method: "POST", headers: bearer(adminToken) })).status).toBe(404);
    const stub = env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(BFF_AUTH_OBJECT_NAME));
    await runInDurableObject(stub, (_instance, state) => {
      expect([...state.storage.sql.exec<{ n: number }>("SELECT count(*) n FROM tokens")][0]!.n).toBe(0);
    });
  });
  it("migrates old tables fail closed and preserves existing published cursor floors", async () => {
    const migrationMailbox = "mailbox-test-00002";
    const stub = env.DEVICE_MAILBOX.get(env.DEVICE_MAILBOX.idFromName(migrationMailbox));
    const oldFrame = buildFrame(21, "frame-alpha-00021", 1, parentRecipient, migrationMailbox);
    await runInDurableObject(stub, async (_instance, state) => {
      // Only the disposable local test DO: recreate the previous schema.
      state.storage.sql.exec(`DROP TABLE tokens; DROP TABLE initial_device_tokens; DROP TABLE parent_locators; DROP TABLE tombstones; DROP TABLE publication_cursors;
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
  it.each([false, true])("enforces cursors, roles, idempotency, and signing intents (fingerprint IDs: %s)", async fingerprintIds => {
    const mailbox = fingerprintIds ? ":mailbox:native-001" : "mailbox-test-00001";
    const deviceRecipient = fingerprintIds ? "p256:" + "D".repeat(43) : "recipient-dev-0001";
    const parentRecipient = fingerprintIds ? "p256:" + "P".repeat(43) : "recipient-key-0001";
    const approvalKey = fingerprintIds ? "p256:" + "S".repeat(43) : "parent-key-test-01";
    const frame = (cursor: number, id: string, kind = 1, recipient = parentRecipient) =>
      buildFrame(cursor, id, kind, recipient, mailbox);
    let response = await request("/v1/admin/bootstrap", { method: "POST", headers: { ...bearer(bootstrapToken), "content-type": "application/json" }, body: JSON.stringify({ mailboxId: mailbox, accessToken: adminToken }) });
    expect(response.status).toBe(201);
    response = await request("/v1/admin/bootstrap", { method: "POST", headers: { ...bearer(bootstrapToken), "content-type": "application/json" }, body: JSON.stringify({ mailboxId: mailbox, accessToken: adminToken }) });
    expect(response.status).toBe(409);
    for (const [accessToken, role] of [[deviceToken, "device"], [approvalToken, "approval"], [readerToken, "reader"]] as const) {
      response = await request(`/v1/mailboxes/${mailbox}/tokens`, { method: "POST", headers: { ...bearer(adminToken), "content-type": "application/json" }, body: JSON.stringify({ accessToken, role, expiresAt: Date.now() + 600000,
        recipientKeyId: role === "device" ? deviceRecipient : parentRecipient,
        publishRecipientKeyIds: role === "device" ? [parentRecipient] : role === "approval" ? [deviceRecipient] : [],
        ...(role === "approval" ? { approvalKeyId: approvalKey, authorityEpoch: 1, viewRecipientKeyIds: [parentRecipient] } : {}) }) }); expect(response.status).toBe(201);
    }
    const ten = frame(10, "frame-alpha-00010");
    const future = frame(10, "frame-alpha-00010");
    const suffixOffset = future.length - (vector.length - 77);
    writeU64(future, suffixOffset + 16, Date.now() + 10 * 60000); writeU64(future, suffixOffset + 24, Date.now() + 11 * 60000);
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
    response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=${parentRecipient}&after=10`, { headers: bearer(approvalToken) }); expect(response.status).toBe(200);
    response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=${parentRecipient}&after=10`, { headers: bearer(readerToken) }); expect(response.status).toBe(403);
    response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=${parentRecipient.toUpperCase()}&after=0`, { headers: bearer(approvalToken) }); expect(response.status).toBe(403);
    response = await request(`/v1/mailboxes/${mailbox}/intents/reserve`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ authorityEpoch: 1, keyId: approvalKey, intentId: "intent-alpha-0001" }) }); expect(await response.json()).toMatchObject({ sequence: 1 });
    response = await request(`/v1/mailboxes/${mailbox}/intents/cancel`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ authorityEpoch: 1, keyId: approvalKey, intentId: "intent-alpha-0001" }) }); expect(response.status).toBe(200);
    response = await request(`/v1/mailboxes/${mailbox}/intents/reserve`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ authorityEpoch: 1, keyId: approvalKey, intentId: "intent-alpha-0002" }) }); expect(await response.json()).toMatchObject({ sequence: 2 });

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
      for (const [keyId, authorityEpoch] of [["parent-key-other-1", 1], [approvalKey, 2], [approvalKey.toUpperCase(), 1]]) {
        response = await request(`/v1/mailboxes/${mailbox}/intents/${operation}`, { method: "POST", headers: { ...bearer(approvalToken), "content-type": "application/json" }, body: JSON.stringify({ keyId, authorityEpoch, intentId: "intent-alpha-0002" }) });
        expect(response.status).toBe(403);
      }
    }
    response = await request(`/v1/mailboxes/${mailbox}/intents?authorityEpoch=1&keyId=parent-key-other-1`, { headers: bearer(approvalToken) }); expect(response.status).toBe(403);
    response = await request(`/v1/mailboxes/${mailbox}/other/frames`, { method: "POST", headers: bearer(deviceToken), body: ten }); expect(response.status).toBe(404);
    for (const after of ["-1", "9007199254740992", "1e3", "NaN"]) {
      response = await request(`/v1/mailboxes/${mailbox}/poll?recipient=${parentRecipient}&after=${after}`, { headers: bearer(approvalToken) }); expect(response.status).toBe(400);
    }

    const ownIntent = { keyId: approvalKey, authorityEpoch: 1, intentId: "intent-alpha-0002" };
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
