# Guard Relay v1

The relay is an untrusted HTTPS poll/store-forward mailbox. It cannot decide policy, decrypt inner content, mint approvals, or advance a parent sequence. Per parent key, endpoints use stop-and-wait: no sequence `n + 1` before a signed terminal receipt for `n`.

All messages use strict UTF-8, big-endian integers, version 1, bounded lengths, and reject unknown enums, trailing bytes, malformed lengths, invalid timestamps and oversized data. `RequestSnapshot` (`GRRQ`) is immutable and device-signed before encryption: device ID/epoch, authority epoch, device event ID, request/revision, Website/Application target and canonical target identity, bounded display evidence/reason, created/pending-expiry timestamps, 32-byte challenge and policy revision.

`SignedApprovalEnvelope` (`GRAP`) binds authority epoch, parent key/sequence, command/nonce/times, device ID/epoch, request/revision, snapshot SHA-256, exact 32-byte challenge, target kind/identity and policy revision. The only decisions are `AllowAlways`, `AllowTemporary`, `AllowDailyQuota`, and `Deny`; temporary/daily duration is 1..1440 minutes and other decisions use zero. Every P-256 P1363 signature is encoded as a length-prefixed `bytes` field whose declared length must equal 64.

`CommandReceipt` records device and authority epochs, parent key/sequence, request/revision, terminal status (`Applied`, `AlreadyResolved`, `Rejected`, `Expired`, `AcceptedPendingReconciliation`), committed policy revision and reconciliation result/detail. `DeviceSignedCommandReceiptEnvelope` (`GRDC`) signs it with a 64-byte P-256 P1363 device signature.

Outer `RelayFrame` (`GRF1`) contains only opaque mailbox ID, recipient key ID, random frame ID, kind, created/expiry, cursor/ack, HPKE encapsulated key and ciphertext; it never reveals a device ID. `EncodeRelayFrameAssociatedData` is exactly the visible metadata and is HPKE AAD. Inner sender signature precedes encryption. Use RFC 9180 HPKE Base mode `DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM`; encryption and signing keys are separate. This module intentionally implements canonical encoding/hashes, not cryptographic primitives.

Golden deterministic fixtures are in `protocol/test-vectors/relay-v1.json` and `.hex`; no real credentials are present.

## Wire order

| Magic | Signature/AAD input (after `int32 version`) |
|---|---|
| `GRRQ` | deviceId:text, deviceEpoch:i64, authorityEpoch:i64, deviceEventId:text, requestId:text, requestRevision:i64, targetKind:i32, targetIdentity:text, evidence[count:i32,name:text,value:text], reason:text, created:i64, pendingExpiry:i64, challenge:32 bytes, policyRevision:i64 |
| `GRDE` | requestSnapshot:bytes, deviceKeyId:text; append signature:bytes with an explicit length prefix that must equal 64 |
| `GRAP` | authorityEpoch:i64, keyId:text, sequence:i64, commandId:text, nonce:text, issued:i64, expiry:i64, deviceId:text, deviceEpoch:i64, requestId:text, requestRevision:i64, snapshotHash:32 bytes, challenge:32 bytes, targetKind:i32, targetIdentity:text, policyRevision:i64, decision:i32, minutes:i32; append signature:bytes with an explicit length prefix that must equal 64 |
| `GRRC` | deviceId:text, deviceEpoch:i64, authorityEpoch:i64, keyId:text, sequence:i64, commandId:text, requestId:text, requestRevision:i64, status:i32, processed:i64, approvalHash:32 bytes, committedPolicyRevision:i64, reconciliation:i32, detailCode:text |
| `GRDC` | commandReceipt:bytes, deviceKeyId:text; append signature:bytes with an explicit length prefix that must equal 64 |
| `GRF1` | **AAD:** kind:i32, mailboxId:text, recipientKeyId:text, frameId:text, cursor:i64, ack:i64, created:i64, expiry:i64; then enc:bytes with an explicit length prefix that must equal 65, ciphertext:bytes with an explicit length prefix (minimum 16-byte GCM tag) |

All `text` values are length-prefixed strict UTF-8, Unicode NFC and contain no control characters. `detailCode` and all IDs are canonical Guard tokens. `SigningIntent = 4` is a reserved opaque relay frame kind for future separately signed/encrypted intent delivery; FCM/deep links are locator-only and never carry a plaintext decision.

## Native enrollment transcript (QR v2)

This is a checked transcript/candidate-verification component, **not yet a connected enrollment endpoint**. The old Android `GREN`/QR v1 parser is removed. Reuse the binary rules above, with new magic and binary version 1:

| Magic | Exact field order after version |
|---|---|
| `GREO` | relayEndpoint:text(256), enrollmentId:id, deviceId:id, deviceLabel:text(96), deviceEpoch:positive i64, authorityEpoch:positive i64, mailboxId:id, deviceSigningKeyId:id, signingPublicSec1:65 fixed bytes, deviceEncryptionKeyId:id, encryptionPublicSec1:65 fixed bytes, created:i64, expiry:i64, independentChallenge:32 fixed bytes |
| `GREC` | offerHash:32 fixed bytes, approvalKeyId:id, approvalSpki:91 fixed bytes, parentEncryptionKeyId:id, parentEncryptionPublicSec1:65 fixed bytes |

The offer is at most 1536 bytes, the claim at most 460. Times are nonnegative Unix milliseconds, `created < expiry <= created + 10 minutes`. Native scan and Windows verification reject `now < created` and `now >= expiry`. Relay is an exactly pinned canonical lowercase HTTPS DNS endpoint, no credentials/port/query/fragment/encoded or dot-segment path; each optional path segment contains only lowercase ASCII letters, digits, `_` or `-`. No endpoint normalization or relay-provided trust is allowed. Codecs check key encodings; native curve import and attestation, not successful parsing, establish usable keys. Candidate verification requires four distinct public keys and IDs; approval ID must equal the existing `ParentTrustAnchor` fingerprint (`p256:` + unpadded base64url SHA256 of canonical SPKI).

QR text is exactly `guard-enroll://v2?offer=<base64url GREO>&secret=<base64url 32-byte random setup secret>`, unpadded canonical base64url, at most 2200 characters. Render/scan only in native setup, never navigate, log or send the QR to relay/PWA. The public challenge is independently random, NOT the secret or its SHA256; both obvious reuse errors are rejected. Android owns a private copied secret buffer and clears it on close; the scanner/UI must also discard the original QR string. No secret appears in `GREO` or `GREC`.

`offerHash = SHA256(GREO)` is the Android key-attestation challenge, known before key generation. `claimHash = SHA256(GREC)` binds that offer and both parent keys; sign it with the attested approval key after fresh strong biometrics (ECDSA P-256/SHA256, 64-byte P1363). QR possession uses the existing SYSTEM-held `SHA256(setup secret)` as the **secret authentication key**, not a public verifier: `HMAC-SHA256(key, ASCII("guard-enrollment-possession-v1") || claimHash)`, full 32-byte output. Never publish/store this key outside the protected setup state. Use platform [HMAC](https://www.rfc-editor.org/rfc/rfc2104.html); [Android attestation](https://developer.android.com/privacy-and-security/security-key-attestation) is checked separately off-phone, with trusted roots/status. `VerifyEnrollmentCandidate` computes these digests itself against the locally trusted offer and checks MAC, key roles/points, signature and chain.

**A valid candidate does not authorize a commit.** Someone with a live photographed QR and another valid phone can produce one. The remaining coordinator/UI must pin a candidate digest, require the originating elevated setup session to confirm the same full claim as shown on the intended phone, and CAS-consume the still-current unexpired challenge. No first-reply-wins binding, silent pending replacement, truncated-code shortcut without a reviewed commitment protocol, or fallback to the old shape-only `CompleteAsync`. Persist the full offer and pending candidate; preserve existing ownership on restart/error. Bounded encrypted transport/chain envelope, phone encryption-key confirmation, local confirmation/CAS, real scanner/biometric/Google-chain evidence and PWA view bootstrap remain integration gates. PWA keys are not approved by merely adding them to a relay message.

Checks: the existing .NET relay-crypto harness and Android `EnrollmentTest` pin common offer/claim/MAC digests, reject every truncation and bind every accepted mutated byte. Android writes only PUBLIC TEST material to its ignored build directory. After Android JVM tests, run `dotnet run --project tests/Guard.Windows.RelayCrypto.Tests -c Release --no-launch-profile -- --verify-android-enrollment parent/android/app/build/test-interop/android-enrollment.txt` to verify exact bytes/QR/MAC and the real JCA signature independently in .NET. Synthetic attested-candidate checks live in the existing Windows crypto harness; neither check is physical biometric evidence.
