# Guard Relay Worker

This is an untrusted, HTTP-poll-only mailbox. It stores exact opaque `GRF1` bytes and never decrypts inner requests, approvals, receipts, target names, reasons, device identifiers, or access tokens.

`POST /v1/admin/bootstrap` is one-time and fails closed unless the deployment supplies `BOOTSTRAP_ADMIN_TOKEN` as a Worker secret. It creates the first admin token from the request without echoing it. Admins then use `/v1/mailboxes/{mailboxId}/tokens` (`POST` provision, `DELETE` revoke); only SHA-256 token hashes and expiry/role are stored.

Mailbox routes are `/frames`, `/poll?recipient=&after=&limit=`, `/ack`, `/intents/reserve`, `/intents/finalize`, `/intents/cancel`, and `/intents?authorityEpoch=&keyId=`. Approval roles can poll the recipient-specific inbox; reader tokens cannot poll or publish. Frame cursors are sender-bound AAD and must be monotonically consecutive per recipient. An acknowledgement must be sent only after the recipient's durable local commit; it retires frames no newer than that committed cursor.

Signing-intent state is an availability hint only, never authority. A finalize call requires an existing opaque receipt frame, remains `receipt_observed`, and never advances the sequence floor. Android/PWA must independently decrypt and verify the device-signed terminal receipt before issuing sequence N+1. If no verified receipt arrives, signing remains blocked until explicit expiry/cancellation policy on the client.

## Parent WebAuthn BFF

The parent BFF uses exact-pinned `@simplewebauthn/server` `13.3.1`. It fails closed with `503 webauthn_bff_not_configured` unless all four deployment values are present and valid:

- `RP_ID`: WebAuthn relying-party DNS name, with no scheme.
- `RP_ORIGIN`: one exact HTTPS origin whose host is the RP ID or its subdomain.
- `SESSION_SECRET`: independently generated high-entropy secret (minimum 32 characters).
- `PARENT_INVITE_SECRET`: independently generated high-entropy registration/bootstrap secret (minimum 32 characters).

`SESSION_SECRET`, `PARENT_INVITE_SECRET`, and `BOOTSTRAP_ADMIN_TOKEN` are deployment secrets; they must not be placed in `wrangler.jsonc`, Git, browser storage, URLs, or logs. The invite is accepted only over the exact configured origin. Rotate it after the intended bootstrap ceremonies.

Registration options are requested with:

```json
{
  "mailboxId": "canonical-mailbox-id",
  "recipientKeyId": "canonical-parent-recipient-key-id",
  "inviteSecret": "<deployment bootstrap secret>",
  "username": "parent",
  "displayName": "Guard Parent"
}
```

Both registration and login options return `{ "publicKey": ... }`. Registration requires a platform resident credential, ES256, and user verification. Login uses a discoverable credential and also requires user verification. Challenges are single-use and consumed before verification, so a failed or replayed response cannot retry the same ceremony.

Passkey public keys, counters, challenge records, and session hashes are kept in the SQLite Durable Object with bounded counts and TTLs. The browser receives only `HttpOnly; Secure; SameSite=Strict; Path=/` cookies, never a mailbox bearer token. All WebAuthn POSTs require the exact configured `Origin`. `POST /v1/parent/approval-intents` additionally requires the exact `x-guard-csrf: 1` header. `GET /v1/parent/inbox` accepts the exact origin or a browser-provided `Sec-Fetch-Site: same-origin`; no permissive CORS headers are emitted.

`GET /v1/parent/inbox` returns a bounded JSON array of:

```json
{
  "frameId": "outer-canonical-frame-id",
  "frame": "<full canonical GRF1 bytes as unpadded base64url>",
  "receivedAt": "2026-07-24T00:00:00.000Z"
}
```

The full frame is required for HPKE encapsulated-key and AAD verification. Inner request IDs, plaintext targets, decisions, relay tokens, and numeric byte arrays are never returned. A malformed, oversized, or storage-inconsistent frame fails the whole response closed instead of returning a partial inbox.

`POST /v1/parent/approval-intents` validates the UI choice but deliberately stores neither that choice nor its duration. It creates only a short-lived, non-authoritative locator bound to the hash of the pending request identifier. Android must fetch and verify the exact request, show it again, obtain a fresh biometric-confirmed decision, sign it locally, and observe a device-signed receipt. The BFF never signs, reserves a signing sequence, publishes an approval frame, or finalizes a decision for Android.

`NoopWakeAdapter` is the default. A future FCM adapter may carry only `{ mailboxId, collapseToken }`; wake payloads must never include names, domains, reasons, actions, or credentials.
