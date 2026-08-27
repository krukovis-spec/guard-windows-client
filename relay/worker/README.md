# Guard Relay Worker

This is an untrusted, HTTP-poll-only mailbox. It stores exact opaque `GRF1` bytes and never decrypts inner requests, approvals, receipts, target names, reasons, device identifiers, or access tokens.

`POST /v1/admin/bootstrap` is one-time and fails closed unless the deployment supplies `BOOTSTRAP_ADMIN_TOKEN` as a Worker secret. It creates the first admin token from the request without echoing it. Admins then use `/v1/mailboxes/{mailboxId}/tokens` (`POST` provision, `DELETE` revoke); only SHA-256 token hashes and expiry/role are stored.

Mailbox routes are `/frames`, `/poll?recipient=&after=&limit=`, `/ack`, `/intents/reserve`, `/intents/finalize`, `/intents/cancel`, and `/intents?authorityEpoch=&keyId=`. Approval roles can poll the recipient-specific inbox; reader tokens cannot poll or publish. Frame cursors are sender-bound AAD and must be monotonically consecutive per recipient. An acknowledgement must be sent only after the recipient's durable local commit; it retires frames no newer than that committed cursor.

Signing-intent state is an availability hint only, never authority. A finalize call requires an existing opaque receipt frame, remains `receipt_observed`, and never advances the sequence floor. Android/PWA must independently decrypt and verify the device-signed terminal receipt before issuing sequence N+1. If no verified receipt arrives, signing remains blocked until explicit expiry/cancellation policy on the client.

PWA boundary: canonical `/v1/auth/{register,login}/{options,complete}` and `/v1/parent/{inbox,approval-intents}` currently return `503 webauthn_bff_not_configured` fail-closed. They are intentionally not pseudo-implemented: a production BFF needs a separately provisioned relying-party ID/origin, verified `@simplewebauthn/server` Workers compatibility, a session-key secret, invite/bootstrap ceremony, and persistent credential/counter store. Until those are verified, no browser session or relay bearer token is issued. The browser must never receive a mailbox bearer token.

`NoopWakeAdapter` is the default. A future FCM adapter may carry only `{ mailboxId, collapseToken }`; wake payloads must never include names, domains, reasons, actions, or credentials.
