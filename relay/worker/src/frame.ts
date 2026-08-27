export const MAX_FRAME_BYTES = 64 * 1024;
export const MAX_CIPHERTEXT_BYTES = 60 * 1024;
const decoder = new TextDecoder("utf-8", { fatal: true });

export type RelayKind = 1 | 2 | 3 | 4;
export interface RelayFrame {
  readonly kind: RelayKind;
  readonly mailboxId: string;
  readonly recipientKeyId: string;
  readonly frameId: string;
  readonly cursor: bigint;
  readonly ackCursor: bigint;
  readonly createdAt: bigint;
  readonly expiresAt: bigint;
}

export class FrameError extends Error {}

class Reader {
  private offset = 0;
  readonly bytes: Uint8Array;
  constructor(input: Uint8Array) { this.bytes = input; }
  private need(length: number): void {
    if (length < 0 || this.offset > this.bytes.length - length) throw new FrameError("truncated relay frame");
  }
  bytesOf(length: number): Uint8Array { this.need(length); const result = this.bytes.slice(this.offset, this.offset + length); this.offset += length; return result; }
  u32(): number { const b = this.bytesOf(4); return ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0; }
  i64(): bigint { const b = this.bytesOf(8); let value = 0n; for (const byte of b) value = (value << 8n) | BigInt(byte); return (value & (1n << 63n)) === 0n ? value : value - (1n << 64n); }
  text(max: number): string { const length = this.u32(); if (length === 0 || length > max) throw new FrameError("invalid text length"); let value: string; try { value = decoder.decode(this.bytesOf(length)); } catch { throw new FrameError("invalid utf-8"); } if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)) throw new FrameError("invalid canonical identifier"); return value; }
  remaining(): number { return this.bytes.length - this.offset; }
}

export function parseRelayFrame(input: ArrayBuffer | Uint8Array): RelayFrame {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (bytes.length < 4 + 4 || bytes.length > MAX_FRAME_BYTES) throw new FrameError("invalid frame size");
  const r = new Reader(bytes);
  if (new TextDecoder().decode(r.bytesOf(4)) !== "GRF1") throw new FrameError("unexpected magic");
  if (r.u32() !== 1) throw new FrameError("unsupported version");
  const kind = r.u32(); if (kind < 1 || kind > 4) throw new FrameError("unknown frame kind");
  const mailboxId = r.text(128); const recipientKeyId = r.text(128); const frameId = r.text(128);
  const cursor = r.i64(); const ackCursor = r.i64();
  if (cursor < 0n || ackCursor < 0n || ackCursor > cursor) throw new FrameError("invalid cursors");
  const createdAt = r.i64(); const expiresAt = r.i64();
  if (expiresAt <= createdAt || expiresAt - createdAt > 7n * 24n * 60n * 60n * 1000n) throw new FrameError("invalid lifetime");
  if (r.u32() !== 65) throw new FrameError("invalid HPKE encapsulated key length");
  r.bytesOf(65);
  const ciphertextLength = r.u32();
  if (ciphertextLength < 16 || ciphertextLength > MAX_CIPHERTEXT_BYTES) throw new FrameError("invalid ciphertext length");
  r.bytesOf(ciphertextLength);
  if (r.remaining() !== 0) throw new FrameError("trailing bytes forbidden");
  return { kind: kind as RelayKind, mailboxId, recipientKeyId, frameId, cursor, ackCursor, createdAt, expiresAt };
}
