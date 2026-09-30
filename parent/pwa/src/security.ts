import type { EncryptedRelayFrame, RequestSnapshot, SnapshotVerifier } from "./types";

export async function verifiedSnapshots(
  encrypted: readonly EncryptedRelayFrame[],
  verifier: SnapshotVerifier
): Promise<readonly RequestSnapshot[]> {
  if (encrypted.length > 128) throw new Error("request batch too large");
  const results = await Promise.all(encrypted.map((snapshot) => verifier.decryptAndVerify(snapshot)));
  return results.map((result) => {
    if (!result.verified || !result.snapshot) throw new Error("request verification failed");
    return result.snapshot;
  });
}
