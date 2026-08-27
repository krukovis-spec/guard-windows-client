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
