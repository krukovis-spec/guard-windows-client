# Guard Relay Worker

This is an untrusted, HTTP-poll-only mailbox. It stores exact opaque `GRF1` bytes and never decrypts inner requests, approvals, receipts, target names, reasons, device identifiers, or access tokens.

`POST /v1/admin/bootstrap` is one-time and fails closed unless the deployment supplies `BOOTSTRAP_ADMIN_TOKEN` as a Worker secret. It creates the first admin token from the request without echoing it. Admins then use `/v1/mailboxes/{mailboxId}/tokens` (`POST` provision, `DELETE` revoke); only SHA-256 token hashes, expiry, role and bounded recipient scopes are stored. Admin tokens are infrastructure credentials, never application credentials.

Non-admin credentials require `recipientKeyId` (their own inbox/ack target) and `publishRecipientKeyIds` (an explicit unique list, maximum 32, of allowed destinations). A device may publish only Request/Receipt; an approval client may publish only Approval; a reader may publish nothing and cannot use the raw poll/ack APIs. An approval credential additionally pins `approvalKeyId`, positive JS-safe `authorityEpoch`, and nonempty `viewRecipientKeyIds` for its trusted PWA-to-native locator links. These are separate view/decryption/signing identities; the browser cannot choose or broaden the links. Provisioning must come from trusted enrollment, not a user-supplied QR/server hint alone.

Example approval provisioning body (fictional IDs; credential value is never echoed):

```json
{
  "accessToken": "<independently generated application credential>",
  "role": "approval",
  "expiresAt": 1791000000000,
  "recipientKeyId": "native-decryption-key-01",
  "publishRecipientKeyIds": ["device-decryption-key-01"],
  "approvalKeyId": "native-biometric-key-01",
  "authorityEpoch": 1,
  "viewRecipientKeyIds": ["browser-view-key-0001"]
}
```

Migration is additive/idempotent. Existing admin access remains available for reprovisioning, but unscoped/corrupt legacy non-admin tokens fail closed (401); old unbound locators expire rather than acquire default permissions. Trusted enrollment/recovery must reissue these credentials with exact scopes and coordinate the device's own epochs/cursors. Migration cannot reconstruct already-deleted historical publications from the old implementation.

Mailbox routes are exact `/v1/mailboxes/{mailboxId}/frames`, `/poll?recipient=&after=&limit=`, `/ack`, `/intents/reserve`, `/intents/finalize`, `/intents/cancel`, and `/intents?authorityEpoch=&keyId=` paths; nested aliases are rejected. Non-admins may poll/ack only their own pinned recipient. Frame cursors are sender-bound AAD, positive JS-safe integers and monotonically consecutive per recipient; the persisted publication floor survives frame expiry/deletion. An acknowledgement must be sent only after the recipient's durable local commit; it retires frames no newer than that committed cursor. An exact retry is accepted even after receiver ack and even at queue quota, using a hash-only publication tombstone retained until frame expiry. Different bytes with the same frame ID conflict.

Actual streaming bodies have a 20-second deadline and bounded buffers, including outer forwarding and WebAuthn ingress; a Content-Length alone is not trusted. Frame/body limit is 64 KiB, control JSON 16 KiB, locator body 512 bytes. Bounds per mailbox: 1000 pending frames / 8 MiB, 10000 unexpired publication tombstones, 128 publication recipients and 256 active tokens. Frames more than five minutes in the server's future are rejected to keep history TTL bounded; the relay's clock still grants no local authority.

The device's .NET outbox keeps its local queue sequence separate from each recipient's GRF1 cursor. A request can atomically enqueue independently encrypted phone/view copies; recipient heads survive publication acknowledgement and local queue deletion. HTTPS validates the exact recipient/cursor metadata against durable GRF1 bytes before sending. Relay-state schema 2 persists those heads canonically. Only untouched schema-1 enrollment can be read automatically; old delivery history fails closed without rewriting/deleting files or guessing lost heads. Explicit history migration/re-enrollment remains a lifecycle gate. This is locally tested source, not production startup wiring or real multi-parent exchange; independent Android publishers still need coordinated wire-cursor allocation for their shared device inbox.

Signing-intent state is an availability hint only, never authority. Approval operations are scoped to the pinned signing key and epoch. A finalize call requires an existing opaque receipt for the client's pinned inbox and remains `receipt_observed`; it can advance only the untrusted server hint floor, not the computer/phone replay floor. The relay cannot verify the encrypted receipt's command or terminal outcome. Android must independently decrypt and verify the exact device-signed terminal receipt before issuing sequence N+1. If no verified receipt arrives, signing remains blocked until explicit expiry/cancellation policy on the client.

## Parent WebAuthn BFF

The parent BFF uses exact-pinned `@simplewebauthn/server` `13.3.3`. It fails closed with `503 webauthn_bff_not_configured` unless these deployment values are present and valid:

- `RP_ID`: WebAuthn relying-party DNS name, with no scheme.
- `RP_ORIGIN`: one exact HTTPS origin whose host is the RP ID or its subdomain.
- `SESSION_SECRET`: independently generated high-entropy secret (minimum 32 characters).

`SESSION_SECRET` and `BOOTSTRAP_ADMIN_TOKEN` are deployment secrets; they must not be placed in `wrangler.jsonc`, Git, browser storage, URLs, or logs. The old global `PARENT_INVITE_SECRET` contract is removed: it is neither required nor accepted by registration. Existing passkeys/sessions are retained; pending legacy registration challenges without a ticket binding fail closed.

After trusted enrollment, the off-device provisioning operator uses its **mailbox admin** credential to `POST /v1/mailboxes/{mailboxId}/registration-tickets` with:

```json
{
  "recipientKeyId": "canonical-parent-recipient-key-id",
  "username": "parent",
  "displayName": "Guard Parent"
}
```

The mailbox comes from the authenticated route, not browser input. Response: `{ "registrationTicket": "<256-bit random base64url value>", "expiresAt": "<UTC>" }`. Only its SHA-256 hash and exact mailbox/view-recipient/username/display-name binding are stored. Maximum 64 outstanding tickets; one per mailbox/username, reissuing replaces the unused ticket. `DELETE` on the same admin route with `{ "registrationTicket": "..." }` revokes an unused ticket in that mailbox. Device/approval/reader credentials and browser sessions cannot issue tickets.

The browser sends only `{ "registrationTicket": "..." }` to `POST /v1/auth/register/options` at the exact configured origin. Unknown fields/global invite/binding overrides are rejected. Redemption, user binding and ceremony creation commit in one SQLite transaction; concurrent redemption has one winner. The ticket and ceremony share the original five-minute deadline, checked again before storing the passkey. Missing/expired/revoked/replayed tickets return 410; a different existing recipient binding returns 409. A lost response, cancellation or failed ceremony requires a newly issued ticket. The PWA keeps the pasted ticket only in the current form/request, clears the field on submission, and does not put it in a URL or persistent browser storage.

This ticket authorizes one **view passkey registration**, not device ownership, decryption-key trust or Android approval capability. A consumed ticket cannot be revoked through the unused-ticket endpoint; full view-device/passkey/session revocation remains an enrollment/lifecycle gate. Trusted enrollment/attestation, provisioning UI, PWA snapshot verifier and real-phone integration are still not wired; the PWA remains disabled without its verifier. Do not distribute admin credentials to the child PC or browser to work around those missing integrations.

Both registration and login options return `{ "publicKey": ... }`. Registration requires a platform resident credential, ES256, and user verification. Login uses a discoverable credential and also requires user verification. Challenges are single-use and consumed before verification, so a failed or replayed response cannot retry the same ceremony.

Passkey public keys, counters, challenge records, and session hashes are kept in the SQLite Durable Object with bounded counts and TTLs. The browser receives only `HttpOnly; Secure; SameSite=Strict; Path=/` cookies, never a mailbox bearer token. All WebAuthn POSTs require the exact configured `Origin`. `POST /v1/parent/approval-intents` additionally requires the exact `x-guard-csrf: 1` header. `GET /v1/parent/inbox` accepts the exact origin or a browser-provided `Sec-Fetch-Site: same-origin`; no permissive CORS headers are emitted.

`GET /v1/parent/inbox` returns a bounded JSON array of:

```json
{
  "cursor": 1,
  "frameId": "outer-canonical-frame-id",
  "frame": "<full canonical GRF1 bytes as unpadded base64url>",
  "receivedAt": "2026-07-24T00:00:00.000Z"
}
```

The full frame is required for HPKE encapsulated-key and AAD verification. Inner request IDs, plaintext targets, decisions, relay tokens, and numeric byte arrays are never returned. A malformed, oversized, or storage-inconsistent frame fails the whole response closed instead of returning a partial inbox.
The cursor is the authenticated outer frame cursor. The parent client pages with `after` and verifies strict forward progress; it does not use this untrusted server hint as an approval replay floor.

`POST /v1/parent/approval-intents` validates the UI choice but deliberately stores neither that choice nor its duration. It creates only a short-lived, non-authoritative locator bound to the hash of the pending request identifier. Android must fetch and verify the exact request, show it again, obtain a fresh biometric-confirmed decision, sign it locally, and observe a device-signed receipt. The BFF never signs, reserves a signing sequence, publishes an approval frame, or finalizes a decision for Android.

An enrolled Android client redeems the locator once with its recipient/key/epoch-scoped `approval` bearer token: `POST /v1/mailboxes/{mailboxId}/locators/redeem`, JSON `{ "locator": "..." }`. A locator also pins its originating PWA view recipient, derived from the server session, not browser input; only an approval credential with the enrolled view link may redeem it. The response contains only `{ "requestIdSha256": "64 lowercase hex characters", "nonAuthoritative": true }`. Android must find the matching identifier among independently decrypted, device-signed pending snapshots from its enrolled mailbox. Wrong role is 403; wrong view link, expired, missing or replayed locator is 410 and a wrong-link attempt does not consume the locator. The locator is not an approval credential and cannot authorize an action by itself. Native redemption and snapshot matching are not yet wired into the Android UI.

`NoopWakeAdapter` is the default. A future FCM adapter may carry only `{ mailboxId, collapseToken }`; wake payloads must never include names, domains, reasons, actions, or credentials.
