# Decisions

## 2026-07-24 - Stage 6 starts Android-first on zero-cost pilot infrastructure

- Decision: the first native parent approval client is Android/Kotlin on Ivan's real fingerprint device and permits signatures only through Android Keystore `AUTH_BIOMETRIC_STRONG`. The shared cabinet remains a PWA; iPhone waits for Mac/Xcode and a real device.
- Decision: development and the closed family pilot use a separate Guard Cloudflare Workers Free deployment with SQLite Durable Objects/D1 on `workers.dev` and no-cost FCM push. VoicePaste database/namespaces are never reused, and Guard gets a separate least-privilege token. REG.RU is optional static/download hosting only, not relay, authoritative state or key storage.
- Decision: Ivan authorized a disposable Hyper-V Windows 11 Pro VM for live Guard/SCM/AppLocker/WFP/browser/installer/Cleaner/tamper tests. The host PC remains prohibited; a test CA trusted only in the VM may validate signing mechanics until public release signing is purchased.
- Why: the available Android device closes the biometric gate now, existing free quotas are ample for one family, and VM isolation allows real Windows evidence without risking Ivan's workstation.
- Alternatives: wait for both mobile platforms; run a long-lived relay on REG.RU shared hosting; test on the host; buy production signing/hosting immediately. These delay validation, weaken operational isolation or spend before the product passes its gates.
- Risk: free quotas have no promised public SLA and must fail closed. Hyper-V still needs an elevated feature/host check; public domain, iPhone build route, trusted Windows signing and store accounts remain release decisions.
- Check: REG.RU/ISPmanager SFTP and existing Cloudflare connection are documented in the local service registry; current official Cloudflare Free/D1/Durable Objects and FCM limits support the closed-pilot design.

## 2026-07-24 - Recovery uses a Guard key, not the Bitwarden master password

- Decision: generate a Guard Recovery Kit with at least 256 bits of randomness. Store its master copy as a protected Bitwarden entry and a second sealed paper copy outside the parent phone and child PC; never send the Bitwarden master password to Guard or derive Guard authority from a human-chosen password.
- Decision: using the kit requires physical access and a separate elevated local recovery ceremony with delay, revocation of all previous parent approval keys and notification of any still-registered parent device.
- Why: Bitwarden is suitable protected storage, but reusing its master password would couple two security boundaries and create a memorable transferable Guard secret.
- Alternatives: email/SMS/TOTP reset, a remembered Guard password/PIN, Bitwarden-only copy, or paid FIDO2 as a current requirement. The first two reproduce known bypasses, the third creates a single loss point, and paid hardware can remain an optional later layer.
- Risk: compromise of both Bitwarden and the local parent-admin credential remains outside the promised threat boundary. Recovery implementation and destructive-key-rotation behavior still need protocol tests and VM evidence.
- Check: Ivan confirmed Bitwarden availability; the canonical plan now specifies the separate recovery kit and offline backup.

## 2026-07-24 - Stage 5 web authority is signed, exact and recoverable

- Decision: authorize only canonical DNS hosts with exact/subtree scope from a signed `guard.web-bundle.v2`. Its signed identity includes catalog, sequence, bundle version, issue/expiry, minimum Guard version, signing-key id and digest; durable catalog/per-bundle floors reject rollback and same-version digest substitution.
- Decision: enable network enforcement only with exact low-privilege proxy identity, loopback exclusivity, WFP closure and effective Edge/Chrome managed-policy evidence. Extension UX is a separate exact child-session/browser-digest dependency; future, stale or mismatched evidence blocks website requests without weakening independent enforcement.
- Decision: accepted website decisions atomically commit desired policy plus a bounded reconcile intent. Accepted, rejected, rate-limited and dependency-failed request outcomes all create stable durable idempotent audit intents.
- Why: child input, ambiguous HTTP framing, browser proxy overrides, stale extensions, bundle replay, process cancellation and sink/audit outages must not widen access or silently lose a revoke/security event.
- Alternatives: trust the requested host, DNS-only blocking, HTTPS interception, broad browser proxy state, in-memory retry/audit. These either expand child authority, create bypasses/privacy risk or lose crash recovery, so they are rejected.
- Risk: real proxy/DNS, registry/effective-policy, extension, WFP, catalog/PSL, store/scheduler/audit and service adapters are still absent. Exact browser/network/crash behavior remains a disposable Windows 11 Pro VM gate.
- Check: implementation `b685072`; warning-free Release build; 321/321 safe checks including 85/85 Stage 5; clean NuGet audit; review loop fixed twelve findings; focused and independent final reviews found no remaining P0/P1/P2 in code-only scope.

## 2026-07-24 - Windows anti-removal and mobile child control are separate boundaries

- Decision: resisting stop, tamper and uninstall by the standard child is a mandatory Windows release gate. Authorized update/uninstall requires the parent ceremony and signed release path; absolute protection is not promised if the child has administrator/recovery credentials or physical offline access.
- Decision: the first Windows release uses Android/iPhone only for the parent's PWA and compact biometric-only approval signer. A Guard agent for the child's Android/iPhone is a separate future product.
- Why: Windows self-protection depends on SCM/DACL/signed installer/Secure Boot/BitLocker evidence, while mobile child control requires different OS facilities such as MDM/VPN/device policy and should not delay the Windows boundary.
- Risk: Windows anti-removal is not proven until the full stop/delete/Safe Mode/offline/update/uninstall attack matrix passes in a disposable VM. Parent mobile platform order and shared runtime remain open.
- Check: canonical scope and release gates are recorded in `docs/guard-v2-development-plan.md`; no live Windows or mobile-system action was run.

## 2026-07-24 - Stage 4 grants and reconciliation stay exact and recoverable

- Decision: unpackaged binaries can execute only through exact SHA-256 grants and packaged apps through exact PFN grants. Publisher/product/secure-root identity is service-attested provenance used to classify update candidates, never a broad executable allow.
- Decision: a valid desired revision is committed before rule-catalog verification. Before every sink apply, the coordinator persists `min(now + 1 minute, natural deadline)`; failure or cancellation keeps that marker, and the natural deadline or clear replaces it only after successful apply.
- Why: AppLocker cannot safely express the required publisher/product AND secure-root conjunction, and a transient catalog/scheduler/sink failure must never discard a revoke or strand an old allow without bounded retry.
- Alternatives: broad publisher/path rules; trust child-supplied path/publisher/PFN; verify catalog before commit; clear expiry before sink apply. These widen authority or lose recovery invariants, so they are rejected.
- Risk: production implementations of store/scheduler/catalog/AppLocker sink and updater carry-forward are still absent. Exact Windows semantics, atomic replacement, crash recovery and the arbitrary-launch matrix remain disposable-VM gates.
- Check: implementation `35c79ca`; Release build; 236/236 safe checks; clean NuGet audit; code-review-loop fixed three P1 and finished clean on pass 1; independent final review found no remaining P0/P1/P2 in the code-only scope.

## 2026-07-24 - PWA cabinet uses a native biometric-only approval key

- Decision: retain one PWA for requests, status and non-permissive management, but require a compact native Android/iPhone approval module to sign `Allow`, disable, maintenance and recovery commands. Its Secure Enclave/Android Keystore key requires fresh strong biometry for every operation and excludes device PIN/passcode fallback.
- Why: official Apple and Android passkeys may use the device passcode, PIN, pattern or password when biometrics are unavailable. That does not protect a family scenario where the child may know the phone unlock code.
- Alternatives: PWA-only passkey; two complete native cabinets; hardware FIDO2 only. PWA-only fails the biometric-only boundary, full duplicate apps add unnecessary scope, and FIDO2 remains a fallback rather than the default daily UX.
- Risk: the parent platform order and shared UI runtime remain open. Real-device tests must prove key invalidation after biometric changes and refusal when only device credentials are available. A child Android/iOS control agent remains outside the first Windows release.
- Check: canonical details and official platform references are recorded in `docs/guard-v2-development-plan.md`.

## 2026-07-23 - Readiness is observational and full service proof is indivisible

- Decision: `GetReadiness` is admin-only and observational. It returns eight fixed bounded facts and stable finding codes; any `Unknown`, `Error` or `Unsatisfied` fact blocks `CanEnableProtection`. A future enable command must collect fresh facts again immediately before commit/apply.
- Decision: service readiness requires both runtime health and one complete observed installation contract: exact LocalSystem own-process/noninteractive service, automatic start, service SID, recovery actions, no standard-user stop/change/delete rights, exact binary, protected non-reparse install root and disabled legacy authority. Partial SCM observations never count as ready.
- Why: a green check based only on a running process or stale setup snapshot would turn missing security evidence into authority and create a TOCTOU bypass.
- Alternatives: treat unavailable checks as warnings; accept a running LocalSystem service as sufficient; reuse legacy account/AppLocker state. Each alternative can certify protection that is absent or child-modifiable, so production currently reports BitLocker, browser coverage and the full service boundary as `Unknown`.
- Risk: actual Windows edition, Secure Boot, account membership, SCM/DACL/recovery/service-SID and tamper behavior still require a disposable Windows 11 Pro VM. The checked-in SCM adapter is query-only and is not wired as complete service proof.
- Check: implementation `15b8b60`; Release build; 192/192 safe checks; clean NuGet audit; code-review-loop clean on pass 1 and independent review with no P0/P1/P2. No live Windows action was run.

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

## 2026-07-22 - Guard v2 uses request-first default-deny and parent approval (updated 2026-07-24)

- Decision: everything unknown is blocked; the child requests an app or site; the parent decides `always`, `temporary`, `daily quota`, or `deny` in a Russian-default PWA. Passkeys provide account entry, while every permissive or dangerous command uses the native biometric-only approval key defined by the 2026-07-24 decision. Parent PIN, TOTP, SMS and email codes are not used, including as the normal recovery route.
- Why: this matches Ivan's real family workflow and prevents the observed reset-code bypass from an unlocked phone or notification preview.
- Alternatives: parent-maintained blocklists; LAN-only cabinet and password/PIN; TOTP backup; duplicate full native cabinets. Blocklists invert the workflow, LAN/PIN and TOTP can be observed or transferred, and full duplicate apps add scope when only approval signing must be native.
- Risk: PWA push delivery is not the source of truth, so the request inbox and device queue must remain reliable; total loss of all approval keys/passkeys still needs an approved recovery ceremony.
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
