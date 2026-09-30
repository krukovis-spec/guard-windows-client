import { describe, expect, it, vi } from "vitest";
import { readBoundedBody } from "../src/bounded-body";

describe("bounded HTTP body", () => {
  it("bounds actual streamed bytes, cancels overflow and rejects a forged declared length", async () => {
    const request = (body: ReadableStream<Uint8Array>, declared?: string) => new Request("https://example.test/", {
      method: "POST", body, headers: declared === undefined ? {} : { "content-length": declared },
    });
    let canceled = false;
    const overflow = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(Uint8Array.of(1, 2)); controller.enqueue(Uint8Array.of(3, 4)); },
      cancel() { canceled = true; },
    });
    await expect(readBoundedBody(request(overflow, "1"), 3)).rejects.toMatchObject({ status: 413 });
    expect(canceled).toBe(true);
    const valid = new ReadableStream<Uint8Array>({ start(controller) {
      controller.enqueue(Uint8Array.of(1, 2)); controller.enqueue(Uint8Array.of(3)); controller.close();
    } });
    await expect(readBoundedBody(request(valid), 3)).resolves.toEqual(Uint8Array.of(1, 2, 3));
    let headerRejectedBodyCanceled = false;
    await expect(readBoundedBody(request(new ReadableStream({ cancel() { headerRejectedBodyCanceled = true; } }), "9007199254740992"), 3)).rejects.toMatchObject({ status: 413 });
    expect(headerRejectedBodyCanceled).toBe(true);
  });
  it("cancels a body that never finishes within the fixed deadline", async () => {
    vi.useFakeTimers();
    try {
      let canceled = false;
      const stream = new ReadableStream<Uint8Array>({ cancel() { canceled = true; } });
      const pending = readBoundedBody(new Request("https://example.test/", { method: "POST", body: stream }), 16);
      const rejected = expect(pending).rejects.toMatchObject({ status: 408, code: "request_timeout" });
      await vi.advanceTimersByTimeAsync(20000);
      await rejected;
      expect(canceled).toBe(true);
    } finally { vi.useRealTimers(); }
  });
});
