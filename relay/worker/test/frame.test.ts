import { describe, expect, it } from "vitest";
import { FrameError, parseRelayFrame } from "../src/frame";

const hex = "475246310000000100000002000000126d61696c626f782d616c7068612d3030303100000012726563697069656e742d6b65792d30303031000000116672616d652d616c7068612d3030303031000000000000000b000000000000000a0000019f93ff31b80000019f93ff35a0000000410102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40410000002065666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384";
const fixture = Uint8Array.from(hex.match(/../g)!.map(x => Number.parseInt(x, 16)));

function withIdentifiers(id: string): Uint8Array {
  const text = new TextEncoder().encode(id);
  const field = new Uint8Array(4 + text.length);
  new DataView(field.buffer).setUint32(0, text.length);
  field.set(text, 4);
  return new Uint8Array([...fixture.slice(0, 12), ...field, ...field, ...field, ...fixture.slice(77)]);
}

describe("RelayFrame v1 parser", () => {
  it("accepts the cross-language golden vector", () => {
    const frame = parseRelayFrame(fixture);
    expect(frame).toMatchObject({ kind: 2, mailboxId: "mailbox-alpha-0001", recipientKeyId: "recipient-key-0001", frameId: "frame-alpha-00001", cursor: 11n, ackCursor: 10n });
  });
  it.each(["p256:" + "Ab_-".repeat(10) + "abc", ":".repeat(16), ".".repeat(128), "_frame:alpha-0001"])("preserves canonical identifier %s", id => {
    expect(parseRelayFrame(withIdentifiers(id))).toMatchObject({ mailboxId: id, recipientKeyId: id, frameId: id });
  });
  it.each(["a".repeat(15), "a".repeat(129), "frame-alpha-0001\n", "frame-alpha-0001\r", "frame-alpha-0001\0",
    "frame-alpha-0001/", "frame-alpha-0001%", "frame-alpha-0001?", "frame-alpha-0001#", "frame-alpha-0001&", "frame-alpha-0001é",
    "\ufeffframe-alpha-0001"])("rejects noncanonical identifier %j", id => {
    expect(() => parseRelayFrame(withIdentifiers(id))).toThrow(FrameError);
  });
  it.each([fixture.slice(0, -1), new Uint8Array([...fixture, 0]), Uint8Array.from([...fixture.slice(0, 4), 0, 0, 0, 2, ...fixture.slice(8)])])("rejects truncation, trailing bytes, and version drift", value => expect(() => parseRelayFrame(value)).toThrow(FrameError));
  it("rejects malformed ciphertext and bad expiry", () => {
    const ciphertextLengthOffset = fixture.length - 36;
    const tiny = fixture.slice(); tiny[ciphertextLengthOffset + 3] = 15;
    expect(() => parseRelayFrame(tiny)).toThrow(FrameError);
    const expired = fixture.slice();
    for (let i = 0; i < 8; i++) expired[101 + i] = fixture[93 + i]!;
    expect(() => parseRelayFrame(expired)).toThrow(FrameError);
  });
  it("rejects cursors that cannot round-trip through SQLite/JSON numbers", () => {
    const overflow = fixture.slice();
    new DataView(overflow.buffer).setBigInt64(77, BigInt(Number.MAX_SAFE_INTEGER) + 1n);
    expect(() => parseRelayFrame(overflow)).toThrow(FrameError);
    new DataView(overflow.buffer).setBigInt64(77, BigInt(Number.MAX_SAFE_INTEGER));
    expect(parseRelayFrame(overflow).cursor).toBe(BigInt(Number.MAX_SAFE_INTEGER));
  });
});
