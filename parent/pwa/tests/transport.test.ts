import { afterEach, describe, expect, it, vi } from "vitest";
import { encodeBase64Url } from "../src/base64url";
import { HttpParentTransport, sameOriginPath } from "../src/transport";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("same-origin parent transport", () => {
  it("adds the non-simple CSRF header to passkey POST requests", async () => {
    const fetchMock = vi.fn<
      (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
    >(async () => new Response(
        JSON.stringify({ publicKey: {} }),
        { status: 200, headers: { "content-type": "application/json" } }
      ));
    vi.stubGlobal("fetch", fetchMock);

    await new HttpParentTransport().createLoginOptions();

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/v1/auth/login/options");
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      method: "POST",
      credentials: "include",
      headers: { "x-guard-csrf": "1" }
    });
  });

  it("rejects absolute and protocol-relative BFF paths", () => {
    expect(() => sameOriginPath("https://relay.example", "/v1")).toThrow();
    expect(() => sameOriginPath("//relay.example", "/v1")).toThrow();
  });

  it("decodes bounded full GRF1 bytes without exposing an inner request id", async () => {
    const encodedFrame = new Uint8Array([0x47, 0x52, 0x46, 0x31, 0, 0, 0, 1]);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify([{
      frameId: "frame-alpha-00001",
      frame: encodeBase64Url(encodedFrame.buffer),
      receivedAt: "2026-07-24T20:00:00.000Z"
    }]), { status: 200, headers: { "content-type": "application/json" } })));

    const inbox = await new HttpParentTransport().listSnapshots();

    expect(inbox).toHaveLength(1);
    const first = inbox[0];
    if (!first) throw new Error("missing decoded frame");
    expect(first.frameId).toBe("frame-alpha-00001");
    expect(Array.from(new Uint8Array(first.encodedFrame))).toEqual(Array.from(encodedFrame));
  });

  it("rejects leaked inner fields, duplicate ids, and oversized frames", async () => {
    const valid = {
      frameId: "frame-alpha-00001",
      frame: encodeBase64Url(new Uint8Array(8).buffer),
      receivedAt: "2026-07-24T20:00:00.000Z"
    };
    const responses = [
      [{ ...valid, requestId: "request-alpha-001" }],
      [valid, valid],
      [{ ...valid, frame: encodeBase64Url(new Uint8Array(64 * 1024 + 1).buffer) }]
    ];

    for (const body of responses) {
      vi.stubGlobal("fetch", vi.fn(async () => new Response(
        JSON.stringify(body),
        { status: 200, headers: { "content-type": "application/json" } }
      )));
      await expect(new HttpParentTransport().listSnapshots()).rejects.toThrow();
    }
  });
});
