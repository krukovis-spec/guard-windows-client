import { afterEach, describe, expect, it, vi } from "vitest";
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
});
