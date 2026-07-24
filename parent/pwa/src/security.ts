import type { EncryptedRelayFrame, RequestSnapshot, SnapshotVerifier } from "./types";

export async function verifiedSnapshots(
  encrypted: readonly EncryptedRelayFrame[],
  verifier: SnapshotVerifier
): Promise<readonly RequestSnapshot[]> {
  const results = await Promise.all(encrypted.map((snapshot) => verifier.decryptAndVerify(snapshot)));
  return results.flatMap((result) => result.verified && result.snapshot ? [result.snapshot] : []);
}
