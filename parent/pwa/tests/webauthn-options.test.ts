import { describe, expect, it } from "vitest";
import { decodeAuthenticationOptions, decodeRegistrationOptions } from "../src/passkey";

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

const challenge = base64Url(Uint8Array.from({ length: 32 }, (_, index) => index));

describe("WebAuthn JSON option decoding", () => {
  it("decodes registration challenge, user id, and excluded credential ids", () => {
    const decoded = decodeRegistrationOptions({
      publicKey: {
        challenge,
        rp: { id: "parent.example", name: "Guard Parent" },
        user: { id: "AQID", name: "ivan", displayName: "Иван" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: [{ type: "public-key", id: "_wA", transports: ["internal"] }]
      }
    });

    expect(Array.from(new Uint8Array(decoded.challenge as ArrayBuffer))).toEqual(Array.from({ length: 32 }, (_, index) => index));
    expect(Array.from(new Uint8Array(decoded.user.id as ArrayBuffer))).toEqual([1, 2, 3]);
    expect(Array.from(new Uint8Array(decoded.excludeCredentials?.[0]?.id as ArrayBuffer))).toEqual([255, 0]);
  });

  it("decodes authentication challenge and allowed credential ids", () => {
    const decoded = decodeAuthenticationOptions({
      publicKey: {
        challenge,
        rpId: "parent.example",
        userVerification: "required",
        allowCredentials: [{ type: "public-key", id: "BAUG" }]
      }
    });

    expect(Array.from(new Uint8Array(decoded.challenge as ArrayBuffer))).toHaveLength(32);
    expect(Array.from(new Uint8Array(decoded.allowCredentials?.[0]?.id as ArrayBuffer))).toEqual([4, 5, 6]);
    expect(decoded.userVerification).toBe("required");
  });

  it.each([
    ["padding", `${challenge}=`],
    ["non-url alphabet", `${challenge.slice(0, -1)}+`],
    ["impossible length", "A"],
    ["non-canonical trailing bits", "_x"]
  ])("rejects malformed %s base64url", (_name, malformed) => {
    expect(() => decodeAuthenticationOptions({ publicKey: { challenge: malformed } })).toThrow(/base64url|decoded size/u);
  });

  it("rejects malformed user and credential ids instead of passing strings to the browser", () => {
    expect(() => decodeRegistrationOptions({
      publicKey: {
        challenge,
        rp: { name: "Guard Parent" },
        user: { id: "AQ==", name: "ivan", displayName: "Ivan" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      }
    })).toThrow(/base64url/u);
    expect(() => decodeAuthenticationOptions({
      publicKey: {
        challenge,
        allowCredentials: [{ type: "public-key", id: "**invalid**" }]
      }
    })).toThrow(/base64url/u);
  });

  it("rejects oversized binary fields and credential lists before browser use", () => {
    const oversizedChallenge = base64Url(new Uint8Array(513));
    const oversizedUserId = base64Url(new Uint8Array(65));
    const oversizedCredentialId = base64Url(new Uint8Array(1025));
    expect(() => decodeAuthenticationOptions({ publicKey: { challenge: oversizedChallenge } })).toThrow(/bounded|size/u);
    expect(() => decodeRegistrationOptions({
      publicKey: {
        challenge,
        rp: { name: "Guard Parent" },
        user: { id: oversizedUserId, name: "ivan", displayName: "Ivan" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }]
      }
    })).toThrow(/bounded|size/u);
    expect(() => decodeAuthenticationOptions({
      publicKey: {
        challenge,
        allowCredentials: [{ type: "public-key", id: oversizedCredentialId }]
      }
    })).toThrow(/bounded|size/u);
    expect(() => decodeAuthenticationOptions({
      publicKey: {
        challenge,
        allowCredentials: Array.from({ length: 129 }, () => ({ type: "public-key", id: "AQ" }))
      }
    })).toThrow(/bounded/u);
  });
});
