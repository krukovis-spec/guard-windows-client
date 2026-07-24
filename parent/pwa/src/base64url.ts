export function encodeBase64Url(value: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(value)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

/**
 * Decode canonical, unpadded base64url after bounding both the encoded and
 * decoded sizes. Re-encoding rejects alternate representations.
 */
export function decodeBase64Url(
  value: unknown,
  path: string,
  minimumBytes: number,
  maximumBytes: number
): ArrayBuffer {
  if (!Number.isSafeInteger(minimumBytes) || !Number.isSafeInteger(maximumBytes)
    || minimumBytes < 0 || maximumBytes < minimumBytes) {
    throw new Error("invalid base64url bounds");
  }

  const maximumCharacters = Math.ceil(maximumBytes * 4 / 3);
  if (typeof value !== "string" || value.length === 0
    || !/^[A-Za-z0-9_-]+$/u.test(value) || value.length % 4 === 1) {
    throw new Error(`${path} must be canonical unpadded base64url`);
  }
  if (value.length > maximumCharacters) {
    throw new Error(`${path} has an invalid decoded size`);
  }

  let binary: string;
  try {
    binary = atob(value.replaceAll("-", "+").replaceAll("_", "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "="));
  } catch {
    throw new Error(`${path} must be canonical unpadded base64url`);
  }

  if (binary.length < minimumBytes || binary.length > maximumBytes) {
    throw new Error(`${path} has an invalid decoded size`);
  }

  const decoded = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    decoded[index] = binary.charCodeAt(index);
  }
  if (encodeBase64Url(decoded.buffer) !== value) {
    throw new Error(`${path} must be canonical unpadded base64url`);
  }
  return decoded.buffer;
}
