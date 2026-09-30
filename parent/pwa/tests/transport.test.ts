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

  it("sends only the scoped registration ticket in the POST body, never a global invite", async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ publicKey: {} }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const transport = new HttpParentTransport();
    await expect(transport.createRegistrationOptions("")).rejects.toThrow("registration ticket required");
    expect(fetchMock).not.toHaveBeenCalled();
    const registrationTicket = "t".repeat(43);
    await transport.createRegistrationOptions(registrationTicket);
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith("/v1/auth/register/options", {
      method: "POST", credentials: "include",
      headers: { "x-guard-csrf": "1", "content-type": "application/json" },
      body: JSON.stringify({ registrationTicket })
    });
  });

  it("decodes bounded full GRF1 bytes without exposing an inner request id", async () => {
    const encodedFrame = new Uint8Array([0x47, 0x52, 0x46, 0x31, 0, 0, 0, 1]);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify([{
      cursor: 1,
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

  it("pages beyond the BFF's default twenty frames but rejects overfilled pages", async () => {
    const frame = encodeBase64Url(new Uint8Array(8).buffer);
    const makePage = (count: number, start = 0) => Array.from({ length: count }, (_, index) => ({
      cursor: start + index + 1,
      frameId: `frame-parent-${String(start + index).padStart(5, "0")}`,
      frame,
      receivedAt: "2026-07-24T20:00:00.000Z"
    }));
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const after = Number(new URL(String(input), "https://example.test").searchParams.get("after"));
      return new Response(JSON.stringify(after === 0 ? makePage(20) : makePage(2, 20)), { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    await expect(new HttpParentTransport().listSnapshots()).resolves.toHaveLength(22);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(makePage(21)), { status: 200 })));
    await expect(new HttpParentTransport().listSnapshots()).rejects.toThrow();
  });

  it("preserves canonical IDs and rejects normalization and delimiter lookalikes", async () => {
    const validIds = ["p256:" + "Ab_-".repeat(10) + "abc", ":".repeat(16), ".".repeat(128), "_frame:alpha-0001"];
    const invalidIds = ["a".repeat(15), "a".repeat(129), "frame-alpha-0001\n", "frame-alpha-0001\0", "\ufeffframe-alpha-0001",
      "frame-alpha-0001/", "frame-alpha-0001%", "frame-alpha-0001?", "frame-alpha-0001#", "frame-alpha-0001&", "frame-alpha-0001é"];
    for (const frameId of [...validIds, ...invalidIds]) {
      vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify([{
        cursor: 1, frameId, frame: encodeBase64Url(new Uint8Array(8).buffer), receivedAt: "2026-07-24T20:00:00.000Z"
      }]), { status: 200 })));
      const result = new HttpParentTransport().listSnapshots();
      if (validIds.includes(frameId)) await expect(result).resolves.toMatchObject([{ frameId }]);
      else await expect(result).rejects.toThrow("frameId must be canonical");
    }
  });

  it("rejects leaked inner fields, duplicate ids, and oversized frames", async () => {
    const valid = {
      cursor: 1,
      frameId: "frame-alpha-00001",
      frame: encodeBase64Url(new Uint8Array(8).buffer),
      receivedAt: "2026-07-24T20:00:00.000Z"
    };
    const responses = [
      [{ ...valid, requestId: "request-alpha-001" }],
      [valid, valid],
      [{ ...valid, cursor: 0 }],
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
