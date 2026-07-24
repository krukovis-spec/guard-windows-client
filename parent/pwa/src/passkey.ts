import type { PasskeyCredentialDto } from "./types";

const maximumChallengeBytes = 512;
const maximumUserIdBytes = 64;
const maximumCredentialIdBytes = 1024;
const maximumCredentials = 128;
const acceptedTransports = new Set(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"]);

function base64Url(value: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function nonEmptyString(value: unknown, path: string, maximumLength: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximumLength) {
    throw new Error(`${path} must be a bounded non-empty string`);
  }
  return value;
}

/**
 * Decode canonical, unpadded base64url without allocating from an attacker-controlled
 * string before its encoded and decoded sizes have been checked.
 */
function base64UrlBuffer(value: unknown, path: string, minimumBytes: number, maximumBytes: number): ArrayBuffer {
  const encoded = nonEmptyString(value, path, Math.ceil(maximumBytes * 4 / 3) + 2);
  if (!/^[A-Za-z0-9_-]+$/u.test(encoded) || encoded.length % 4 === 1) {
    throw new Error(`${path} must be canonical unpadded base64url`);
  }

  let binary: string;
  try {
    binary = atob(encoded.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(encoded.length / 4) * 4, "="));
  } catch {
    throw new Error(`${path} must be canonical unpadded base64url`);
  }

  if (binary.length < minimumBytes || binary.length > maximumBytes) {
    throw new Error(`${path} has an invalid decoded size`);
  }

  const decoded = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) decoded[index] = binary.charCodeAt(index);
  if (base64Url(decoded.buffer) !== encoded) {
    throw new Error(`${path} must be canonical unpadded base64url`);
  }
  return decoded.buffer;
}

function optionalString(value: unknown, path: string, maximumLength: number): string | undefined {
  return value === undefined ? undefined : nonEmptyString(value, path, maximumLength);
}

function credentialDescriptors(value: unknown, path: string): PublicKeyCredentialDescriptor[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > maximumCredentials) {
    throw new Error(`${path} must be a bounded array`);
  }

  return value.map((entry, index) => {
    const descriptor = record(entry, `${path}[${index}]`);
    if (descriptor.type !== "public-key") throw new Error(`${path}[${index}].type must be public-key`);
    const transports = descriptor.transports;
    if (transports !== undefined && (!Array.isArray(transports) || transports.length > 8
      || transports.some((transport) => typeof transport !== "string" || !acceptedTransports.has(transport)))) {
      throw new Error(`${path}[${index}].transports contains an unsupported value`);
    }
    return {
      id: base64UrlBuffer(descriptor.id, `${path}[${index}].id`, 1, maximumCredentialIdBytes),
      type: "public-key",
      ...(transports === undefined ? {} : { transports: transports as AuthenticatorTransport[] })
    };
  });
}

function publicKeyOptions(value: unknown): Record<string, unknown> {
  return record(record(value, "options").publicKey, "options.publicKey");
}

/** Convert the JSON registration options returned by SimpleWebAuthn/BFF to browser options. */
export function decodeRegistrationOptions(value: unknown): PublicKeyCredentialCreationOptions {
  const publicKey = publicKeyOptions(value);
  const relyingParty = record(publicKey.rp, "options.publicKey.rp");
  const user = record(publicKey.user, "options.publicKey.user");
  const parameters = publicKey.pubKeyCredParams;
  if (!Array.isArray(parameters) || parameters.length === 0 || parameters.length > 64) {
    throw new Error("options.publicKey.pubKeyCredParams must be a bounded non-empty array");
  }
  for (const [index, entry] of parameters.entries()) {
    const parameter = record(entry, `options.publicKey.pubKeyCredParams[${index}]`);
    if (parameter.type !== "public-key" || !Number.isSafeInteger(parameter.alg)) {
      throw new Error(`options.publicKey.pubKeyCredParams[${index}] is invalid`);
    }
  }

  const decoded: PublicKeyCredentialCreationOptions = {
    ...(publicKey as unknown as PublicKeyCredentialCreationOptions),
    challenge: base64UrlBuffer(publicKey.challenge, "options.publicKey.challenge", 16, maximumChallengeBytes),
    rp: {
      ...(relyingParty as unknown as PublicKeyCredentialRpEntity),
      name: nonEmptyString(relyingParty.name, "options.publicKey.rp.name", 256),
      id: optionalString(relyingParty.id, "options.publicKey.rp.id", 253)
    },
    user: {
      ...(user as unknown as PublicKeyCredentialUserEntity),
      id: base64UrlBuffer(user.id, "options.publicKey.user.id", 1, maximumUserIdBytes),
      name: nonEmptyString(user.name, "options.publicKey.user.name", 256),
      displayName: nonEmptyString(user.displayName, "options.publicKey.user.displayName", 256)
    },
    pubKeyCredParams: parameters as PublicKeyCredentialParameters[],
    excludeCredentials: credentialDescriptors(publicKey.excludeCredentials, "options.publicKey.excludeCredentials")
  };
  return decoded;
}

/** Convert the JSON authentication options returned by SimpleWebAuthn/BFF to browser options. */
export function decodeAuthenticationOptions(value: unknown): PublicKeyCredentialRequestOptions {
  const publicKey = publicKeyOptions(value);
  return {
    ...(publicKey as unknown as PublicKeyCredentialRequestOptions),
    challenge: base64UrlBuffer(publicKey.challenge, "options.publicKey.challenge", 16, maximumChallengeBytes),
    rpId: optionalString(publicKey.rpId, "options.publicKey.rpId", 253),
    allowCredentials: credentialDescriptors(publicKey.allowCredentials, "options.publicKey.allowCredentials")
  };
}

/** Convert WebAuthn binary fields explicitly; JSON.stringify(PublicKeyCredential) is unsafe. */
export function passkeyDto(credential: PublicKeyCredential): PasskeyCredentialDto {
  const response = credential.response;
  const extensions = credential.getClientExtensionResults();
  const common = {
    id: credential.id,
    rawId: base64Url(credential.rawId),
    type: "public-key" as const,
    clientExtensionResults: extensions
  };
  if ("attestationObject" in response) {
    const attestation = response as AuthenticatorAttestationResponse;
    return { ...common, response: { clientDataJSON: base64Url(attestation.clientDataJSON), attestationObject: base64Url(attestation.attestationObject) } };
  }
  if ("authenticatorData" in response && "signature" in response) {
    const assertion = response as AuthenticatorAssertionResponse;
    return {
      ...common,
      response: {
        clientDataJSON: base64Url(assertion.clientDataJSON),
        authenticatorData: base64Url(assertion.authenticatorData),
        signature: base64Url(assertion.signature),
        userHandle: assertion.userHandle ? base64Url(assertion.userHandle) : null
      }
    };
  }
  throw new Error("unsupported passkey response");
}
