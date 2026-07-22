# Decisions

## 2026-07-22 - Guard v2 uses request-first default-deny and passkey parent approval

- Decision: everything unknown is blocked; the child requests an app or site; the parent decides `always`, `temporary`, `daily quota`, or `deny` in a Russian-default PWA. Every permissive decision uses a passkey with fresh fingerprint/Face ID. Parent PIN, TOTP, SMS and email codes are not used, including as the normal recovery route.
- Why: this matches Ivan's real family workflow and prevents the observed reset-code bypass from an unlocked phone or notification preview.
- Alternatives: parent-maintained blocklists; LAN-only cabinet and password/PIN; TOTP backup; a native mobile app first. Blocklists invert the desired workflow, LAN/PIN and TOTP can be observed or transferred, and native-first delays validation on both mobile platforms unless PWA cannot enforce biometric-only approval.
- Risk: PWA push delivery is not the source of truth, so the request inbox and device queue must remain reliable; total loss of all passkeys still needs an approved recovery ceremony. If the child knows the phone unlock PIN and the platform lets a passkey fall back to it, PWA approval may be insufficient; this is a real-device security gate and may force a native parent app or hardware FIDO2 key.
- Check: canonical scenarios, threat model, stages and open questions are in `docs/guard-v2-development-plan.md`.

## 2026-07-22 - Guard v2 replaces global unlock and UI-Automation website blocking

- Decision: use a 15/30/60-minute passkey-gated maintenance mode with automatic relock. For sites, support managed browsers only, block all other browsers as apps, enforce a localhost domain proxy without TLS decryption, and use a managed extension for the child request page.
- Why: a forgotten global unlock defeats the product, while the current address-bar reader reacts after navigation and can be bypassed. The proxy can deny the HTTPS destination before content loads; the extension supplies understandable UX.
- Alternatives: keep process-closing UI Automation; HTTPS MITM; DNS-only filtering. UI Automation is late and fragile, MITM creates a high-risk root certificate/privacy boundary, and DNS alone is bypassable and cannot model modern browser traffic reliably.
- Risk: QUIC, DoH, VPN, proxy, Tor, OAuth redirects and multi-domain services require explicit browser policies, WFP constraints, service bundles and VM tests.
- Check: enforcement and attack-matrix requirements are in `docs/guard-v2-development-plan.md`.

## 2026-06-14 - Emergency PIN cannot be recovered through email-visible server codes

- Decision: reject server-driven `pinCode` updates completely and disable the legacy `guard.alexweb.app` remote path by default; emergency PIN is changed only from the LAN parent cabinet after parent password step-up, and `123456` stays a temporary fallback only.
- Why: Ivan observed a real bypass where a child triggered a reset email/code and read it from the parent phone lock-screen notification shade.
- Alternatives: keep accepting remote `pinCode` for the legacy cloud flow; require a second code; hide only phone notifications. Accepting remote PIN keeps the bypass; extra codes still risk notification leakage; phone settings are necessary but not enough.
- Risk: legacy `guard.alexweb.app` account reset and remote sync no longer update this fork automatically unless future code explicitly opts in.
- Check: `Guard.Tests` covers remote PIN rejection, default PIN rejection, local remote-skip, and legacy remote-skip; Release build passes.

## 2026-06-08 - Strict default-deny without breaking Windows shell

- Decision: make Ivan's local pairing default to parent-approval mode: AppControl `Enforce` for normal apps and web default-deny through hidden domain rules, while preserving Windows/Guard stability rules in AppLocker.
- Why: Ivan wants "everything blocked until parent approves"; AppLocker is the right layer for app launches, and hidden site rules let approved `DomainAccessGrants` re-open only the requested site.
- Alternatives: remove all Windows AppLocker default rules; use only manual block lists; build a browser extension/proxy. Removing all Windows rules risks breaking logon/shell; block lists do not satisfy default-deny; extension/proxy is stronger for websites but a larger next phase.
- Risk: Windows built-in shell essentials remain allowed; browser URL detection is best-effort through UI Automation. Real enforcement still needs VM/child-account validation.
- Check: Release build passes; `Guard.Tests` covers website default deny, AppLocker policy script broad `Program Files` removal, request approvals, and expiry behavior.

## 2026-06-06 - Parent-friendly pairing MVP

- Decision: use a local-first hybrid direction. Child PC should show a short expiring code (`ABCD-EFGH` style); parent enters it in a protected cabinet and then manages restrictions remotely.
- Why: Ivan can store strong parent passwords in Bitwarden, but typing strong credentials on the child PC is inconvenient and error-prone.
- Alternatives: keep `guard.alexweb.app` flow; build full cloud server first; build local-only mode. Full cloud is the final direction, but local-first gives a safer testable base.
- Risk: local pairing is now wired to the LAN cabinet, but it is still home-network only and not an internet/cloud account.
- Check: pairing model, parent commands, password hashing, and local-mode remote-skip are covered by `Guard.Tests`.

## 2026-06-06 - LAN cabinet before cloud backend

- Decision: make the first runnable MVP a LAN parent cabinet served by the child Guard client on port `8765`.
- Why: it lets Ivan install and test the full parent flow without building a separate internet backend first.
- Alternatives: build cloud server first; keep child-PC-only admin panel. Cloud is the correct long-term direction, but slower; child-PC-only admin misses Ivan's core usability requirement.
- Risk: LAN MVP uses HTTP, not HTTPS, and may require Windows Firewall private-network permission. It is for home-network testing, not internet exposure.
- Check: cabinet logic is integrated through `ParentCommandApplier`; password hashing is covered by `Guard.Tests`.

## 2026-06-06 - AppLocker for application control

- Decision: use Windows AppLocker as the enforcement layer for "allowed apps only" instead of trying to kill arbitrary unauthorized processes in a custom loop.
- Why: blocking downloaded browsers/installers must happen before launch; AppLocker is built for allow/deny execution policy, while Guard should handle parent UX, temporary grants, warnings, and expiry.
- Alternatives: custom process killer; WDAC. Process killing is easier to bypass and noisy; WDAC is stronger but too risky/complex for the first home MVP.
- Risk: AppLocker policy is a live Windows policy. First test should be `Audit`, child account non-admin, then `Enforce` only after allowed app paths are entered.
- Check: App control commands, temporary warning/expiry, and generated allow-path selection are covered by `Guard.Tests`.
