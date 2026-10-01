# Guard Relay Worker

This is an untrusted, HTTP-poll-only mailbox. It stores exact opaque `GRF1` bytes and never decrypts inner requests, approvals, receipts, target names, reasons, device identifiers, or access tokens.

## Deployment status — 2026-10-01

The code at `477f18f` is active at `https://guard-relay.voicepaste.workers.dev`, Cloudflare version `1ecc4c0c-0866-44d5-b9ea-c9673ee70341` (100% deployment `69590ea4-a942-4447-b995-1c7be575301a`). This includes durable one-time mailbox bootstrap, scoped credentials, initial issuance, GREX and registration-ticket routes. It is **not provisioned for clients**: bootstrap/session secrets, RP settings and PWA assets remain absent; real device/phone exchange has not run.

Before upload: 59 tests, typecheck and dry-run bundle PASS; production dependency audit was clean earlier the same day and dependencies have not changed. Deploy used the existing DPAPI-backed Guard-only token with `wrangler deploy --keep-vars --strict`; no token scope, namespace, secret, route or VoicePaste changes. Wrangler uploaded successfully but exited 1 on the account-wide `/workers/subdomain` read. A separate process verified the exact new active version/message and unchanged `DEVICE_MAILBOX` namespace. Do not broaden permissions or blindly redeploy because of this post-upload error.

Nine external HTTPS checks: root 404, OPTIONS 405, missing/invalid mailbox credential 401, initial issuance without credential 401, bootstrap without secret (including spoofed internal headers) 403, unconfigured BFF 503; all `no-store`, no permissive CORS. Invalid-credential requests reached the existing synthetic `guard-deploy-smoke-20261001` DO and fresh `guard-bootstrap-smoke-20261001`, exercising migration/initialization without credentials or messages. This does not test existing family-data migration or an authenticated exchange. The immediately previous version `55fd57ef-52b6-4669-8a47-6987ff289641` predates the durable bootstrap guard and is not an automatic rollback target.

Reconnection uses the existing service-connection registry (Cloudflare — Guard): Bitwarden master, CurrentUser DPAPI operational copy outside Git, token only in the child process environment; never pass it in CLI arguments. The older September 26 version `537c1852-f838-47d7-9575-7ab17257c0f5` is also for incident comparison, **not an automatic rollback target**: it predates scope/enrollment fixes. Cloudflare version rollback does not undo Durable Object data/schema; inspect compatibility and security before rollback ([official limitations](https://developers.cloudflare.com/workers/versions-and-deployments/rollbacks/)). Next: trusted operator bootstrap/release pins and an authenticated synthetic exchange, then physical phone/VM acceptance.

## Mailbox authorization

`POST /v1/admin/bootstrap` fails closed unless the deployment supplies `BOOTSTRAP_ADMIN_TOKEN` as a Worker secret. Its exact JSON has only `mailboxId` and `accessToken`; no query parameters. First issuance stores an immutable hash-only singleton marker and admin token atomically and returns `201 {role: "admin", expiresAt}` (one year from initial issuance), never the token. A byte-equivalent credential retry confirms the original expiry only while that exact admin token remains valid and unchanged. A changed, expired or revoked token returns 409; bootstrap never recreates it or extends its lifetime. The marker is permanent (one row/mailbox), not removed by token cleanup/revocation. Legacy mailboxes, including empty ones, are sealed without adopting an unknown prior credential; migration does not remove their existing access. Retrying against older code may fail closed; no unsafe upsert fallback.

The off-PC operator [utility](../../tools/Guard.Provisioning/README.md) persists the initial intent using CurrentUser DPAPI and a separate purpose before HTTP. Master admin credential must already be in the password manager; the global bootstrap credential is input-only. After confirmed initial provisioning, disable the global bootstrap secret through the operator's Cloudflare access. Admins then use `/v1/mailboxes/{mailboxId}/tokens` (`POST` provision, `DELETE` revoke); only SHA-256 token hashes, expiry, role and bounded recipient scopes are stored. Admin tokens are infrastructure credentials, never application credentials.

Non-admin credentials require `recipientKeyId` (their own inbox/ack target) and `publishRecipientKeyIds` (an explicit unique list, maximum 32, of allowed destinations). A new device starts with `publishRecipientKeyIds: []`: its own inbox and GREX ceremony work before the phone key exists, but **no GRF1 publication is allowed**, including to itself. Missing/null scope is still invalid, never a wildcard. After trusted local confirmation, the off-PC operator may explicitly activate the exact confirmed native recipients as below; merely receiving a claim or reply never changes these scopes. Later explicit admin re-scoping remains available; setting the publication list back to `[]` withdraws publication without granting another destination.

Initial device provisioning must use **`POST /v1/mailboxes/{mailboxId}/tokens/initial`**, authenticated with the off-PC mailbox admin credential. Its body has exactly five fields: `accessToken`, `role: "device"`, `expiresAt` (future Unix milliseconds), `recipientKeyId` (the independently verified device decryption key), and `publishRecipientKeyIds: []`. It returns `201 { role: "device", expiresAt }`, never the credential. Persist the exact intent securely on the operator computer **before** sending; after an ambiguous network result retry the same credential/recipient/expiry, not a freshly generated token.

This route creates an initial credential and a hash-only retry marker atomically. An identical retry is read-only and succeeds only while the current credential still has the exact initial role, recipient, scope and expiry. A changed intent, subsequent re-scoping, revocation or pre-existing credential from the ordinary provisioning route returns `409 initial_device_token_conflict`; it never resets later rights or resurrects a revoked credential. Markers survive token deletion and process restart until the original expiry. Each mailbox allows at most 256 live markers, including revoked ones; quota returns 429 instead of evicting them. Expired markers are removed, but the original now-expired request is still rejected. Reusing a credential with a deliberately new future expiry is a new admin operation, not recovery of the old intent; operators must generate a new credential for a new installation.

The ordinary `/tokens` POST remains an intentional admin upsert for later scope changes. **Never fall back to it** when `/tokens/initial` returns an error or an older deployment returns 404: it can overwrite later rights. Neither endpoint proves device ownership or attestation. Trusted descriptor acquisition, secure operator persistence, encrypted device-only handoff, installer integration and the release deployment remain integration gates; this server API alone is not a working installation tool.

### Initial native activation — local code only, not deployed

`POST /v1/mailboxes/{mailboxId}/tokens/activate-native` is mailbox-admin-only. Its exact seven fields are `deviceAccessToken`, `deviceRecipientKeyId`, `approvalAccessToken`, `approvalRecipientKeyId`, `approvalKeyId`, `authorityEpoch: 1`, and `expiresAt` (the **unchanged** initial device expiry). The three key IDs must be distinct; the approval credential must be independently generated and new, not an existing admin/device/reader/GREX capability or retained initial/activation credential. The operator must first verify the committed enrollment against independently trusted device keys and durably save its exact activation intent outside Git. A claim/QR/relay success is not such evidence. This API does not receive, verify, or replace the ownership transcript.

In one SQLite transaction it changes the still-exact initial device publication scope to the native decryption key, issues the approval credential with its own inbox, device-only publication and pinned signing key/epoch, and saves a hash-only activation marker. Both credentials retain the original expiry. It returns only `201 {role: "approval", expiresAt}`. An exact retry is read-only, independent of JSON property order, and works only while both credentials retain every original activated scope and expiry. Changed intent, re-scoping, expiry or revocation conflicts; no resurrection, renewed lifetime or fallback to `/tokens`. Conflicting activation has one winner. A partial database failure rolls back both rights and marker. The marker survives token deletion/reopen through expiry and is bounded by the 256 initial-device intents; activation also respects the 256 active-token limit.

This first step grants **no PWA/view/locator links**: the approval credential has explicit `viewRecipientKeyIds: []`, so every locator redemption refuses without consuming it. Browser view enrollment and explicit later operator re-scoping remain separate. Missing/null/invalid view lists still refuse. Do not fill in a fictional browser recipient to bootstrap native transport.

Local evidence: 63 Worker tests, typecheck and dry-run bundle PASS (2026-10-01), including real SQL rollback faults, lost-response/reopen retry with write-aborting triggers, role/destination/epoch/locator refusal, revocation/scope/expiry, preflight collisions, quota and admin revocation/expiry while reading a request. **No production activation, authenticated phone exchange or client integration is claimed.** Trusted confirmed-transcript export/operator verification, protected phone handoff and runtime clients are the next gates; do not roll out this route as a finished enrollment workflow.

Local Windows/operator code now supplies signed GNA1 export and `verify-native` against the original independently pinned device job (see [protocol](../../protocol/guard-relay-v1.md)). It does not yet call this endpoint or provision the phone; real installed-service trust and device acceptance remain unverified.

A scoped device may publish only Request/Receipt; an approval client requires nonempty publication destinations and may publish only Approval; a reader requires an empty list, may publish nothing and cannot use the raw poll/ack APIs. An approval credential additionally pins `approvalKeyId`, positive JS-safe `authorityEpoch`, and explicit bounded `viewRecipientKeyIds` for its trusted PWA-to-native locator links (empty means no links). These are separate view/decryption/signing identities; the browser cannot choose or broaden the links. Provisioning must come from trusted enrollment, not a user-supplied QR/server hint alone. The trusted off-PC provisioning/installer UI is still an integration gate; these server capabilities are not that UI or proof of device ownership.

Mailbox-local mutation handlers recheck the token's current validity and exact scope synchronously after body/crypto awaits, immediately before publication: frames, token provision/revoke, acknowledgements, signing intents and locator redemption. A revoked/expired token or changed role/recipient/epoch/view/publication scope rejects the in-flight operation without its state changes. Already committed messages are not retroactively withdrawn. Concurrent initial admin bootstrap requests cannot both succeed; the empty-mailbox check and insert have no intervening await. This does not claim distributed atomic revocation of already forwarded BFF requests or a replacement for local cryptographic authority.

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

## Native enrollment transport

The existing mailbox also carries bounded opaque GREX exchanges, separate from GRF1. These routes are deployed and locally tested, **but no live client is provisioned and real enrollment remains unverified**. The QR never carries a mailbox admin credential. A trusted, already provisioned `device` credential opens a transport session at `POST /v1/mailboxes/{mailboxId}/enrollments/{offerHashHex}` with exact JSON `{ "phoneToken": "<64 lowercase hex characters>", "expiresAt": <offer expiry Unix milliseconds> }`. The expiry must be within ten minutes. Owner is the credential's pinned device recipient; admins/other recipients cannot act as that device through these routes. Exact re-provisioning is idempotent and never extends the deadline or replaces the capability.

Both clients derive the 32-byte phone capability as `HMAC-SHA256(SHA256(QR secret), ASCII("guard-enrollment-relay-capability-v1") || fullOfferHash)`, serialized lowercase hex. It is domain-separated from the claim possession MAC and never reveals that MAC key. Only SHA-256 of the textual bearer token is retained in SQLite. Capabilities cannot be reused for another retained offer in that mailbox or ordinary token provisioning. The phone uses it only as an Authorization Bearer on that exact pinned HTTPS endpoint, never in URLs/logs/browser storage. Android now retains it without the QR secret in its no-backup enrollment record with exact request bytes and verified results. Both client HTTP adapters are locally tested; real release pins, trusted device provisioning, completed startup/UI and authenticated live exchange remain open.

Suffixes below use the same offer-scoped base path. No query parameters or path aliases are accepted; binary POSTs require `application/octet-stream`.

| Route | Credential | Meaning |
| --- | --- | --- |
| `POST /requests` | Phone capability | Enqueue exact GREX claim/proof/query; 201 new, 200 byte-identical retry, 409 nonce collision. |
| `GET /requests` | Owning device | One oldest unreplied request as exact binary bytes, or 204. Read does not consume. |
| `POST /replies` | Owning device | Store exact GREX reply matching full offer/claim/nonce header of an existing request. |
| `GET /replies/{nonceHex}` | Phone capability | Exact reply, 204 waiting, 410 missing/expired, 422 device rejected. |
| `DELETE /requests/{nonceHex}` | Owning device | Mark an invalid request rejected so it cannot jam the queue. Does not replace an existing reply. |
| `DELETE` base path | Owning device | Revoke this transport session and its queue, **not** ownership/keys on either endpoint. |

New claim/proof submissions stop at offer expiry; query-only reconciliation lasts another 24 hours. Each exchange lasts at most two minutes, while signed replies have their independent one-minute client-verified validity. After a lost/stale reply the client creates a fresh nonce/query; after retention expiry it requires explicit recovery/reconciliation, never silent key deletion or re-enrollment. HTTP statuses, retention deadlines and rejection hints are untrusted availability information, not proof of ownership or revocation. Cryptographic verification/local confirmation remains mandatory.

Bounds: 70 KiB requests, 414-byte replies, 1024-byte provisioning JSON; eight retained offers/mailbox, 32 exchanges/offer, 256 exchanges/1 MiB request bytes/mailbox. Expired rows are purged on enrollment requests; exact retries do not use additional quota. There is no new Durable Object namespace, service or dependency. Publication/replies use synchronous SQLite transactions with fresh capability/device-token checks after body/crypto awaits ([Cloudflare storage semantics](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)). Bodies retain the shared streaming size/deadline enforcement. Ordinary GRF1 limits and roles are unchanged.

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
