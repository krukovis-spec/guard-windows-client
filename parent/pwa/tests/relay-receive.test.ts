import { createCipheriv, createECDH, createHmac, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { createViewSnapshotVerifier, type ViewEnrollment } from "../src/relay-receive";
import type { EncryptedRelayFrame, SnapshotVerifier } from "../src/types";

// Public .NET/Kotlin interop test material, never a real enrollment or production key.
const fixture = Object.fromEntries(readFileSync(new URL("../../../protocol/test-vectors/relay-exchange-v1.properties", import.meta.url), "utf8")
  .split(/\r?\n/u).filter(line => line && !line.startsWith("#")).map(line => {
    const separator = line.indexOf("="); return [line.slice(0, separator), line.slice(separator + 1)];
  }));
const hex = (name: string) => Buffer.from(fixture[name]!, "hex");
const now = Number(fixture.now);
const publicPoint = hex("recipient.public");
const raw = hex("request.frame");
const plaintext = hex("request.plaintext");
const snapshot = plaintext.subarray(12, 12 + plaintext.readUInt32BE(8));
const u32 = (value: number) => { const b = Buffer.alloc(4); b.writeUInt32BE(value); return b; };
const i64 = (value: bigint) => { const b = Buffer.alloc(8); b.writeBigInt64BE(value); return b; };
const field = (value: Uint8Array) => Buffer.concat([u32(value.length), value]);
function frame(bytes: Uint8Array = raw): EncryptedRelayFrame {
  return { cursor: 1, frameId: "frame-alpha-000001", encodedFrame: Uint8Array.from(bytes).buffer,
    receivedAt: new Date(now - 60000).toISOString() };
}
async function key(extractable = false): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", {
    kty: "EC", crv: "P-256", x: publicPoint.subarray(1, 33).toString("base64url"),
    y: publicPoint.subarray(33).toString("base64url"), d: hex("recipient.private").toString("base64url"),
    ext: extractable, key_ops: ["deriveBits"]
  }, { name: "ECDH", namedCurve: "P-256" }, extractable, ["deriveBits"]);
}
let trust: ViewEnrollment;
let verifier: SnapshotVerifier;
beforeAll(async () => {
  trust = { mailboxId: "mailbox-alpha-0001", recipientKeyId: "recipient-key-0001", deviceId: "device-alpha-0001",
    deviceKeyId: "device-signing-0001", deviceEpoch: 2n, authorityEpoch: 4n, devicePublicKey: hex("device.public"),
    viewPublicKey: publicPoint, decryptionKey: await key(), deviceLabel: "Test PC", childLabel: "Test child" };
  verifier = await createViewSnapshotVerifier(trust, () => now);
});

describe("real .NET encrypted signed request", () => {
  it("validates every trusted identifier with the same canonical grammar as HTTP", async () => {
    for (const property of ["mailboxId", "recipientKeyId", "deviceId", "deviceKeyId"] as const) {
      for (const id of ["p256:" + "A".repeat(43), ":".repeat(16), ".".repeat(128)])
        await expect(createViewSnapshotVerifier({ ...trust, [property]: id })).resolves.toBeDefined();
      for (const id of ["a".repeat(15), "a".repeat(129), "frame-alpha-0001\n", "\ufeffframe-alpha-0001", "frame-alpha-0001/", "frame-alpha-0001é"])
        await expect(createViewSnapshotVerifier({ ...trust, [property]: id })).rejects.toThrow();
    }
  });

  it("decrypts and verifies the shared .NET/Kotlin fixture, not a server trust flag", async () => {
    expect(await verifier.decryptAndVerify(frame())).toEqual({ verified: true, snapshot: {
      requestId: "request-alpha-001", requestRevision: 3n, kind: "website", subject: "https://example.test/path",
      evidence: "host: example.test", childReason: "homework", childLabel: "Test child", deviceLabel: "Test PC",
      requestedAt: new Date(now - 60000).toISOString(), expiresAt: new Date(now + 7200000).toISOString(), status: "pending"
    } });
  });

  it.each([
    { mailboxId: "mailbox-other-0001" }, { recipientKeyId: "recipient-other-01" }, { deviceId: "device-other-0001" },
    { deviceKeyId: "device-signing-0002" }, { deviceEpoch: 3n }, { authorityEpoch: 5n },
    { devicePublicKey: publicPoint }, { viewPublicKey: hex("device.public") }
  ])("rejects a different trusted binding: %s", async (change) => {
    const other = await createViewSnapshotVerifier({ ...trust, ...change }, () => now);
    await expect(other.decryptAndVerify(frame())).rejects.toThrow();
  });

  it("rejects every one-byte mutation and every truncation of the wire fixture", async () => {
    for (let i = 0; i < raw.length; i++) {
      const changed = Buffer.from(raw); changed[i] = changed[i]! ^ 1;
      await expect(verifier.decryptAndVerify(frame(changed)), `mutation at ${i}`).rejects.toThrow();
      await expect(verifier.decryptAndVerify(frame(raw.subarray(0, i))), `truncation at ${i}`).rejects.toThrow();
    }
    await expect(verifier.decryptAndVerify(frame(Buffer.concat([raw, Buffer.of(0)])))).rejects.toThrow();
    await expect(verifier.decryptAndVerify(frame(new Uint8Array(65537)))).rejects.toThrow();
  });

  it.each([{ cursor: 2 }, { cursor: 1.5 }, { frameId: "frame-other-000001" }, { receivedAt: new Date(now).toISOString() }])(
    "rejects mismatched BFF metadata: %j", async change => {
      await expect(verifier.decryptAndVerify({ ...frame(), ...change })).rejects.toThrow();
    });

  it.each([now - 60001, now + 3600000, NaN, Infinity])("rejects invalid/out-of-window time %s", async time => {
    const clocked = await createViewSnapshotVerifier(trust, () => time);
    await expect(clocked.decryptAndVerify(frame())).rejects.toThrow();
  });

  it("checks expiry again after asynchronous verification", async () => {
    let calls = 0;
    const clocked = await createViewSnapshotVerifier(trust, () => calls++ ? now + 3600000 : now);
    await expect(clocked.decryptAndVerify(frame())).rejects.toThrow();
    expect(calls).toBe(2);
  });

  it("rejects extractable/signing keys and invalid P-256 points at enrollment", async () => {
    await expect(createViewSnapshotVerifier({ ...trust, decryptionKey: await key(true) })).rejects.toThrow();
    const signing = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    await expect(createViewSnapshotVerifier({ ...trust, decryptionKey: signing.privateKey })).rejects.toThrow();
    for (const name of ["devicePublicKey", "viewPublicKey"] as const) {
      await expect(createViewSnapshotVerifier({ ...trust, [name]: new Uint8Array(65).fill(4) })).rejects.toThrow();
    }
  });

  it("the view key cannot sign or be exported, and invalid trusted labels fail closed", async () => {
    await expect(crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, trust.decryptionKey, new Uint8Array(32))).rejects.toThrow();
    await expect(crypto.subtle.exportKey("jwk", trust.decryptionKey)).rejects.toThrow();
    for (const deviceLabel of ["", "bad\nlabel", "e\u0301", "\ud800", "a".repeat(129)]) {
      await expect(createViewSnapshotVerifier({ ...trust, deviceLabel })).rejects.toThrow();
    }
    await expect(createViewSnapshotVerifier({ ...trust, deviceLabel: "PC 🖥️" })).resolves.toBeDefined();
  });

  it("snapshots mutable enrollment buffers and frame bytes before awaits", async () => {
    const enrollment = { ...trust, devicePublicKey: Uint8Array.from(trust.devicePublicKey), viewPublicKey: Uint8Array.from(trust.viewPublicKey) };
    const pending = createViewSnapshotVerifier(enrollment, () => now);
    enrollment.devicePublicKey.fill(0); enrollment.viewPublicKey.fill(0); enrollment.deviceId = "device-other-0001";
    const isolated = await pending;
    const input = frame(); const result = isolated.decryptAndVerify(input);
    new Uint8Array(input.encodedFrame).fill(0);
    expect((await result).verified).toBe(true);
  });
});

// Node's independent OpenSSL-backed sender lets malformed, genuinely signed plaintext
// reach the parser. The production receiver/its HMAC implementation is never reused.
let offset = 12;
for (let i = 0; i < 3; i++) offset += 4 + raw.readUInt32BE(offset);
const aad = raw.subarray(0, offset + 32);
function seal(body: Uint8Array): EncryptedRelayFrame {
  const ephemeral = createECDH("prime256v1"); const enc = ephemeral.generateKeys();
  const hmac = (salt: Uint8Array, input: Uint8Array) => createHmac("sha256", salt).update(input).digest();
  const extract = (suite: Uint8Array, salt: Uint8Array, label: string, input: Uint8Array) =>
    hmac(salt, Buffer.concat([Buffer.from("HPKE-v1"), suite, Buffer.from(label), input]));
  const expand = (suite: Uint8Array, prk: Uint8Array, label: string, info: Uint8Array, size: number) =>
    hmac(prk, Buffer.concat([Buffer.of(0, size), Buffer.from("HPKE-v1"), suite, Buffer.from(label), info, Buffer.of(1)])).subarray(0, size);
  const kem = Buffer.from("4b454d0010", "hex"); const suite = Buffer.from("48504b45001000010002", "hex"); const empty = Buffer.alloc(0);
  const prk = extract(kem, empty, "eae_prk", ephemeral.computeSecret(publicPoint));
  const shared = expand(kem, prk, "shared_secret", Buffer.concat([enc, publicPoint]), 32);
  const context = Buffer.concat([Buffer.of(0), extract(suite, empty, "psk_id_hash", empty),
    extract(suite, empty, "info_hash", Buffer.concat([Buffer.from("guard-relay-request-hpke-v1"), aad]))]);
  const secret = extract(suite, shared, "secret", empty);
  const cipher = createCipheriv("aes-256-gcm", expand(suite, secret, "key", context, 32), expand(suite, secret, "base_nonce", context, 12));
  cipher.setAAD(aad);
  return frame(Buffer.concat([aad, field(enc), field(Buffer.concat([cipher.update(body), cipher.final(), cipher.getAuthTag()]))]));
}
const signer = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const signerJwk = signer.publicKey.export({ format: "jwk" });
const signerPoint = Buffer.concat([Buffer.of(4), Buffer.from(signerJwk.x!, "base64url"), Buffer.from(signerJwk.y!, "base64url")]);
function signed(body: Uint8Array): Buffer {
  const input = Buffer.concat([Buffer.from("GRDE"), u32(1), field(body), field(Buffer.from("device-signing-0001"))]);
  return Buffer.concat([input, field(sign("sha256", input, { key: signer.privateKey, dsaEncoding: "ieee-p1363" }))]);
}
// Locate fields of the existing canonical snapshot, without reproducing its serializer.
let p = 8;
const skipText = () => { const start = p; p += 4 + snapshot.readUInt32BE(p); return start; };
skipText(); p += 16; skipText(); skipText();
const revision = p; p += 8;
const kind = p; p += 4;
skipText(); const count = p; p += 4;
for (let i = 0; i < snapshot.readUInt32BE(count); i++) { skipText(); skipText(); }
const reason = skipText(); const created = p; const expires = p + 8;
const replace = (start: number, size: number, bytes: Uint8Array) => Buffer.concat([snapshot.subarray(0, start), bytes, snapshot.subarray(start + size)]);

describe("authenticated hostile plaintext", () => {
  it("rejects a re-encrypted request whose original device signature was changed", async () => {
    const changed = Buffer.from(plaintext); changed[changed.length - 1] = changed[changed.length - 1]! ^ 1;
    await expect(verifier.decryptAndVerify(seal(changed))).rejects.toThrow();
    await expect(verifier.decryptAndVerify(seal(Buffer.concat([plaintext, Buffer.of(0)])))).rejects.toThrow();
  });

  it("keeps valid int64 request revisions exact beyond JavaScript number precision", async () => {
    const receiving = await createViewSnapshotVerifier({ ...trust, devicePublicKey: signerPoint }, () => now);
    const large = 9007199254740993n;
    const result = await receiving.decryptAndVerify(seal(signed(replace(revision, 8, i64(large)))));
    expect(result.snapshot?.requestRevision).toBe(large);
  });

  it.each([
    ["unknown version", replace(4, 4, u32(2))], ["zero revision", replace(revision, 8, i64(0n))],
    ["negative revision", replace(revision, 8, i64(-1n))], ["unknown kind", replace(kind, 4, u32(3))],
    ["excess evidence", replace(count, 4, u32(9))],
    ["control character", replace(reason, 4 + snapshot.readUInt32BE(reason), field(Buffer.from("bad\nreason")))],
    ["non-NFC text", replace(reason, 4 + snapshot.readUInt32BE(reason), field(Buffer.from("e\u0301")))],
    ["invalid UTF8", replace(reason, 4 + snapshot.readUInt32BE(reason), field(Buffer.of(0xc0, 0x80)))],
    ["oversized reason", replace(reason, 4 + snapshot.readUInt32BE(reason), field(Buffer.alloc(281, 65)))],
    ["future creation", replace(created, 8, i64(BigInt(now + 1)))], ["expired", replace(expires, 8, i64(BigInt(now)))],
    ["excess lifetime", replace(expires, 8, i64(BigInt(now + 7 * 86400000)))],
    ["out-of-range date", replace(expires, 8, i64(253402300800000n))],
    ["negative policy revision", replace(snapshot.length - 8, 8, i64(-1n))],
    ["truncated payload", snapshot.subarray(0, snapshot.length - 1)], ["trailing byte", Buffer.concat([snapshot, Buffer.of(0)])]
  ])("rejects signed %s", async (_name, body) => {
    const receiving = await createViewSnapshotVerifier({ ...trust, devicePublicKey: signerPoint }, () => now);
    await expect(receiving.decryptAndVerify(seal(signed(body as Buffer)))).rejects.toThrow();
  });
});
