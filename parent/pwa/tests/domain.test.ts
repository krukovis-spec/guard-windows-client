import { describe, expect, it } from "vitest";
import { requestApprovalLocator } from "../src/approval-intent";
import { androidIntentLink, boundedMinutes, makeIntent } from "../src/domain";
import { copyFor } from "../src/i18n";
import { verifiedSnapshots } from "../src/security";
import { RelayTransportError, sameOriginPath, stateForRelayError } from "../src/transport";
import { passkeyDto } from "../src/passkey";

describe("approval intent boundary", () => {
  it("bounds temporary and quota durations before an intent can be created", () => {
    expect(boundedMinutes("AllowTemporary", -3)).toBe(5);
    expect(boundedMinutes("AllowTemporary", 999)).toBe(240);
    expect(boundedMinutes("AllowDailyQuota", 1)).toBe(15);
    expect(boundedMinutes("AllowDailyQuota", 999)).toBe(480);
    expect(makeIntent("r1", "Deny", 1)).toEqual({ requestId: "r1", kind: "Deny", minutes: undefined });
  });

  it("creates only a locator deep link, never an approval", () => {
    expect(androidIntentLink("opaque:only-a-locator")).toBe("guard-parent://approval-intent/opaque%3Aonly-a-locator");
  });

  it("a permissive choice can only create an intent locator", async () => {
    const calls: string[] = [];
    const locator = await requestApprovalLocator({
      createApprovalIntent: async () => { calls.push("intent"); return { locator: "opaque", expiresAt: "2026-01-01T00:00:00Z" }; }
    } as never, "r1", "AllowAlways", 30);
    expect(calls).toEqual(["intent"]);
    expect(locator.locator).toBe("opaque");
  });
});

describe("display trust boundary", () => {
  it("does not render an unverified relay snapshot", async () => {
    const result = await verifiedSnapshots([{
      frameId: "frame-untrusted-001",
      encodedFrame: new ArrayBuffer(8),
      receivedAt: "2026-01-01T00:00:00.000Z"
    }], {
      decryptAndVerify: async () => ({ verified: false, snapshot: { requestId: "untrusted" } as never })
    });
    expect(result).toEqual([]);
  });
});

describe("localization", () => {
  it("has explicit Russian and English outage copy", () => {
    expect(copyFor("ru").outage).toContain("по умолчанию запрещены");
    expect(copyFor("en").outage).toContain("default to deny");
  });
});

describe("relay states", () => {
  it("keeps expired and resolved requests distinct from generic errors", () => {
    expect(stateForRelayError(new RelayTransportError(410))).toBe("expired");
    expect(stateForRelayError(new RelayTransportError(409))).toBe("already-resolved");
  });

  it("uses only a configurable same-origin BFF path", () => {
    expect(sameOriginPath("/guard", "/v1/parent/inbox")).toBe("/guard/v1/parent/inbox");
    expect(() => sameOriginPath("https://relay.example", "/v1/parent/inbox")).toThrow("same-origin");
  });
});

describe("passkey transport", () => {
  it("serializes assertion binary values explicitly as base64url DTO", () => {
    const dto = passkeyDto({
      id: "credential-id", rawId: Uint8Array.from([255, 0]).buffer, type: "public-key",
      response: { clientDataJSON: Uint8Array.from([1]).buffer, authenticatorData: Uint8Array.from([2]).buffer, signature: Uint8Array.from([3]).buffer, userHandle: null },
      getClientExtensionResults: () => ({})
    } as unknown as PublicKeyCredential);
    expect(dto).toMatchObject({ id: "credential-id", rawId: "_wA", response: { clientDataJSON: "AQ", authenticatorData: "Ag", signature: "Aw", userHandle: null } });
  });
});
