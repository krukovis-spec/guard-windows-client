import type { EncryptedRelayFrame, SnapshotVerifier } from "./types";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const maximumFrame = 64 * 1024;
const maximumLifetime = 7 * 86400000;
export const isGuardIdentifier = (value: unknown): value is string => typeof value === "string" &&
  value.length >= 16 && value.length <= 128 && !/[^A-Za-z0-9._:-]/u.test(value);
const kemSuite = Uint8Array.of(0x4b, 0x45, 0x4d, 0, 0x10);
const suite = Uint8Array.of(0x48, 0x50, 0x4b, 0x45, 0, 0x10, 0, 1, 0, 2);
const hpkeVersion = encoder.encode("HPKE-v1");

/** Supplied by trusted view enrollment, never by a relay response or a registration ticket. */
export interface ViewEnrollment {
  readonly mailboxId: string;
  readonly recipientKeyId: string;
  readonly deviceId: string;
  readonly deviceKeyId: string;
  readonly deviceEpoch: bigint;
  readonly authorityEpoch: bigint;
  readonly devicePublicKey: Uint8Array;
  readonly viewPublicKey: Uint8Array;
  /** Non-extractable ECDH key with deriveBits only; never an approval/signing key. */
  readonly decryptionKey: CryptoKey;
  readonly deviceLabel: string;
  readonly childLabel: string;
}

/** GRF1/GRDE/GRRQ receive only; same fixed RFC 9180 suite and bytes as .NET/Kotlin. */
export async function createViewSnapshotVerifier(enrollment: ViewEnrollment, now = Date.now): Promise<SnapshotVerifier> {
  const trust = { ...enrollment, devicePublicKey: enrollment.devicePublicKey.slice(), viewPublicKey: enrollment.viewPublicKey.slice() };
  for (const id of [trust.mailboxId, trust.recipientKeyId, trust.deviceId, trust.deviceKeyId]) requireValid(isGuardIdentifier(id));
  for (const epoch of [trust.deviceEpoch, trust.authorityEpoch]) requireValid(typeof epoch === "bigint" && epoch > 0n && epoch <= 0x7fffffffffffffffn);
  for (const label of [trust.deviceLabel, trust.childLabel]) validText(label, 128, false);
  const key = trust.decryptionKey;
  requireValid(key.type === "private" && !key.extractable && key.algorithm.name === "ECDH"
    && (key.algorithm as EcKeyAlgorithm).namedCurve === "P-256" && key.usages.length === 1 && key.usages[0] === "deriveBits");
  await importPoint(trust.viewPublicKey, "ECDH");
  const verificationKey = await importPoint(trust.devicePublicKey, "ECDSA");
  return {
    async decryptAndVerify(input: EncryptedRelayFrame) {
      // Copy before awaiting: neither transport nor a caller may change authenticated bytes mid-flight.
      requireValid(input.encodedFrame.byteLength <= maximumFrame);
      const raw = new Uint8Array(input.encodedFrame.slice(0));
      const r = new Reader(raw, "GRF1");
      requireValid(r.u32() === 1); // Request only; receipt/approval use distinct domains.
      requireValid(r.id() === trust.mailboxId && r.id() === trust.recipientKeyId);
      requireValid(r.id() === input.frameId);
      const cursor = r.nonnegative(); const ack = r.nonnegative();
      requireValid(cursor > 0n && cursor <= BigInt(Number.MAX_SAFE_INTEGER) && ack <= cursor
        && Number.isSafeInteger(input.cursor) && cursor === BigInt(input.cursor));
      const created = r.time(); const expires = r.time();
      requireLifetime(created, expires); requireCurrent(now(), created, expires);
      requireValid(input.receivedAt === new Date(created).toISOString());
      const aad = raw.slice(0, r.position);
      const enc = r.bytes(65, 65); const ciphertext = r.bytes(16, 60 * 1024); r.done();
      const plaintext = await openHpke(trust, enc, ciphertext, aad);
      try {
        const signed = new Reader(plaintext, "GRDE");
        const snapshot = signed.bytes(1, maximumFrame);
        requireValid(signed.id() === trust.deviceKeyId);
        const signatureInput = plaintext.slice(0, signed.position);
        const signature = signed.bytes(64, 64); signed.done();
        // WebCrypto hashes the original signed bytes once; .NET signs that SHA-256 digest.
        requireValid(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, verificationKey, signature, signatureInput));
        const request = new Reader(snapshot, "GRRQ");
        requireValid(request.id() === trust.deviceId && request.positive() === trust.deviceEpoch && request.positive() === trust.authorityEpoch);
        request.id(); // Device event id is signed, not a browser routing hint.
        const requestId = request.id(); const requestRevision = request.positive();
        const kind = request.u32(); requireValid(kind === 1 || kind === 2);
        const subject = request.text(2048, false);
        const count = request.u32(); requireValid(count <= 8);
        const evidence: string[] = [];
        for (let i = 0; i < count; i++) evidence.push(`${request.text(48, false)}: ${request.text(512, true)}`);
        const childReason = request.text(280, true);
        const requested = request.time(); const pendingExpires = request.time();
        requireLifetime(requested, pendingExpires);
        request.take(32); request.nonnegative(); request.done(); // challenge and policy revision
        const completedAt = now();
        requireCurrent(completedAt, created, expires);
        requireCurrent(completedAt, requested, pendingExpires);
        return { verified: true, snapshot: {
          requestId, requestRevision, childLabel: trust.childLabel, deviceLabel: trust.deviceLabel,
          kind: kind === 1 ? "website" : "application", subject, evidence: evidence.join("\n"), childReason,
          requestedAt: new Date(requested).toISOString(), expiresAt: new Date(pendingExpires).toISOString(), status: "pending"
        } };
      } finally { plaintext.fill(0); }
    }
  };
}

class Reader {
  position = 0;
  constructor(private readonly raw: Uint8Array<ArrayBuffer>, magic: string) {
    requireValid(raw.length <= maximumFrame && decoder.decode(this.take(4)) === magic && this.u32() === 1);
  }
  take(length: number): Uint8Array<ArrayBuffer> {
    requireValid(Number.isSafeInteger(length) && length >= 0 && length <= this.raw.length - this.position);
    const bytes = this.raw.slice(this.position, this.position + length); this.position += length; return bytes;
  }
  u32(): number { return new DataView(this.take(4).buffer).getUint32(0); }
  nonnegative(): bigint { const value = new DataView(this.take(8).buffer).getBigInt64(0); requireValid(value >= 0n); return value; }
  positive(): bigint { const value = this.nonnegative(); requireValid(value > 0n); return value; }
  time(): number { const value = this.nonnegative(); requireValid(value <= 253402300799999n); return Number(value); }
  bytes(min: number, max: number): Uint8Array<ArrayBuffer> { const n = this.u32(); requireValid(n >= min && n <= max); return this.take(n); }
  text(max: number, empty: boolean): string {
    const value = decoder.decode(this.bytes(empty ? 0 : 1, max)); validText(value, max, empty); return value;
  }
  id(): string { const value = this.text(128, false); requireValid(isGuardIdentifier(value)); return value; }
  done(): void { requireValid(this.position === this.raw.length); }
}

function validText(value: string, max: number, empty: boolean): void {
  requireValid(typeof value === "string" && (empty || value.length > 0) && value.normalize("NFC") === value
    && !/[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(value) && encoder.encode(value).length <= max);
}
function requireLifetime(start: number, end: number): void { requireValid(end > start && end - start <= maximumLifetime); }
function requireCurrent(now: number, start: number, end: number): void { requireValid(Number.isSafeInteger(now) && now >= start && now < end); }
function requireValid(valid: boolean): asserts valid { if (!valid) throw new Error("request verification failed"); }
function join(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const output = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0; for (const part of parts) { output.set(part, offset); offset += part.length; } return output;
}
async function importPoint(point: Uint8Array<ArrayBuffer>, name: "ECDH" | "ECDSA"): Promise<CryptoKey> {
  requireValid(point.length === 65 && point[0] === 4);
  // The native P-256 import validates coordinates/on-curve membership.
  return crypto.subtle.importKey("raw", point, { name, namedCurve: "P-256" }, false, name === "ECDSA" ? ["verify"] : []);
}

async function openHpke(trust: ViewEnrollment, enc: Uint8Array<ArrayBuffer>, ciphertext: Uint8Array<ArrayBuffer>, aad: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const ephemeral = await importPoint(enc, "ECDH");
  const temporary: Uint8Array[] = [];
  const keep = (bytes: Uint8Array<ArrayBuffer>) => { temporary.push(bytes); return bytes; };
  try {
    const dh = keep(new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: ephemeral }, trust.decryptionKey, 256)));
    const prk = keep(await extract(kemSuite, new Uint8Array(), "eae_prk", dh));
    const shared = keep(await expand(kemSuite, prk, "shared_secret", join(enc, trust.viewPublicKey), 32));
    const psk = await extract(suite, new Uint8Array(), "psk_id_hash", new Uint8Array());
    const info = await extract(suite, new Uint8Array(), "info_hash", join(encoder.encode("guard-relay-request-hpke-v1"), aad));
    const context = join(Uint8Array.of(0), psk, info);
    const secret = keep(await extract(suite, shared, "secret", new Uint8Array()));
    const keyBytes = keep(await expand(suite, secret, "key", context, 32));
    const nonce = keep(await expand(suite, secret, "base_nonce", context, 12));
    const aes = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, aes, ciphertext));
  } finally { for (const bytes of temporary) bytes.fill(0); }
}
async function hmac(keyBytes: Uint8Array<ArrayBuffer>, message: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey("raw", keyBytes.length ? keyBytes : new Uint8Array(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  // HMAC is only HPKE's KDF; this module has no ECDSA signing operation/key.
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
}
async function extract(suiteId: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer>, label: string, input: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const material = join(hpkeVersion, suiteId, encoder.encode(label), input);
  try { return await hmac(salt, material); } finally { material.fill(0); }
}
async function expand(suiteId: Uint8Array<ArrayBuffer>, prk: Uint8Array<ArrayBuffer>, label: string, info: Uint8Array<ArrayBuffer>, length: number): Promise<Uint8Array<ArrayBuffer>> {
  // This fixed suite only needs 12 or 32 bytes: one RFC 5869 expansion block.
  requireValid(length === 12 || length === 32);
  const block = await hmac(prk, join(Uint8Array.of(0, length), hpkeVersion, suiteId, encoder.encode(label), info, Uint8Array.of(1)));
  try { return block.slice(0, length); } finally { block.fill(0); }
}
