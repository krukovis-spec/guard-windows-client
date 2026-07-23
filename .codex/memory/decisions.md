# Decisions

## 2026-07-23 - Guard v2 Stage 2 uses a fail-closed LocalSystem boundary

- Decision: pin official `.NET SDK 10.0.302`; use official `Microsoft.Extensions.Hosting.WindowsServices` `10.0.10`; start production only through SCM as `LocalSystem`; allow initial authoritative-state creation only with one exact CLI bootstrap flag after that boundary; never reset existing/corrupt artifacts.
- Decision: `%ProgramData%\Guard\v2` is SYSTEM-only, DPAPI-protected and atomically replaced under a single writer lease with CAS and a protected hash-chained version journal. Admin/child/proxy use separate first-instance local-only pipes whose role comes from the verified token/SID/integrity, never the payload.
- Decision: a fresh installation binds one validated standard-child SID only during an active elevated admin setup challenge; binding is immutable, and the exact-SID child endpoint appears after service restart. No public ParentRelay pipe is exposed; relay work will use a future internal outbound path.
- Why: these constraints prevent child-side ownership claim, same-user secret access, second-writer races, role spoofing and silent recovery-by-reset.
- Risk: code-only tests do not prove Windows tamper resistance. Real SCM/ACL/DPAPI/named-pipe/account/crash behavior remains a disposable-VM gate; joint offline rollback of both state and journal needs a future TPM or remote witness.
- Check: implementation `078ffa1`; Release build; 159/159 safe checks; clean NuGet audit and secret/diff checks; two independent final reviews accepted the exact staged tree with no P0/P1/P2. No service or system action was run.

## 2026-07-23 - Guard v2 uses a side-by-side authoritative service architecture

- Decision: build Guard v2 beside quarantined legacy code. `Guard.Service` will be the only authoritative writer; child/admin/proxy use separate restricted IPC; setup atomically consumes a one-time challenge and binds parent public-key material; signed decisions are exact-request-bound and committed before reconciliation.
- Why: promoting the interactive tray, CurrentUser storage or LAN cabinet would preserve the same child-visible and same-user trust failures that P0 contained.
- Alternatives: convert `guard.exe` into a service; reuse legacy DPAPI state and pairing IDs; use one role-bearing pipe. These make untrusted payload identity or child-readable legacy state part of the security boundary.
- Risk: this decision began as a cross-platform foundation. Stage 2 now supplies ECDSA, ProgramData ACL/encryption and named-pipe token/DACL adapters in code; AppLocker/proxy adapters and Windows VM attack tests remain required.
- Check: checkpoint `6bfcb15e50f05b9110e6c0227c927be683a5f293`; implementation `de4db2d`; evidence `784ccd0`; Release build, 84/84 safe checks, clean NuGet/staged-secret scans and independent review with no remaining P0/P1/P2.

## 2026-07-22 - P0 quarantines legacy control and requires confirmed cleanup

- Decision: until passkey provisioning and the `LocalSystem` boundary exist, hard-disable the LAN cabinet, child pairing/email, Assign API, legacy remote sync and telemetry for every persisted state. Local disable/uninstall accepts only an existing custom PIN other than `123456`; Inno removes binaries only after Cleaner confirms every cleanup stage and returns exit 0.
- Why: preserving any first-caller or legacy recovery route keeps the ownership takeover open, while swallowed cleanup errors can delete recovery binaries after a partial uninstall.
- Alternatives: keep legacy routes for previously assigned devices; retain `123456` for migration; accept best-effort cleanup. All three preserve a known bypass or false-success path, so P0 intentionally breaks those legacy flows.
- Risk: new pairing and old remote administration are unavailable; blank/default-PIN installations need a future parent-admin migration ceremony; system cleanup is not transactional and still needs disposable-VM lifecycle testing.
- Check: remote checkpoint `381afa54a067665b2977389d582ec3166bc8a4ef`; application commit `3e7e384d26864a5976da85652f160e0dd7da67ab`; Release build, 45/45 safe checks, Inno syntax/package compile, NuGet audit, diff check, masked secret scan and independent security review accepted without remaining P0/P1.

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

- Decision: reject server-driven `pinCode` updates completely. Guard v2 P0 later strengthened this decision: the entire legacy remote/LAN ownership path is hard-disabled and `123456` is never an authorization fallback.
- Why: Ivan observed a real bypass where a child triggered a reset email/code and read it from the parent phone lock-screen notification shade.
- Alternatives: keep accepting remote `pinCode` for the legacy cloud flow; require a second code; hide only phone notifications. Accepting remote PIN keeps the bypass; extra codes still risk notification leakage; phone settings are necessary but not enough.
- Risk: legacy `guard.alexweb.app` account reset and remote sync no longer update this fork; future code must not reopen them through a persisted opt-in.
- Check: `Guard.Tests` covers remote PIN rejection, missing/default PIN fail-closed, telemetry quarantine and hard-disabled legacy remote use; Release build passes.

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
