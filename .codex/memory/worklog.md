# Worklog

## 2026-09-30 — clean evaluation Windows and VM checkpoint restore

- Clean-installed Windows 11 Enterprise Evaluation from the Microsoft-hosted ISO onto the sole 80 GiB `GuardV2-Lab-20260930` virtual disk, replacing the failed offline BCD attempt. Local `GuardLabAdmin` reached the desktop; no real account credentials were recorded in project files. ISO filename says 26H2, but its `setup.exe` and the guest watermark show build 26100; exact release identity remains unverified.
- Verified exact VM/disk/ISO, Generation 2, Secure Boot, vTPM and ProductionOnly mode; created `clean-windows-20260930`, restored it after a graceful guest shutdown, restarted the VM and observed the `GuardLabAdmin` login. The first snapshot command failed before creating anything because `Get-VMTPM` is not a cmdlet; corrected to `Get-VMSecurity` and verified the snapshot and restore succeeded.
- No Guard, installer, Cleaner, AppLocker, WFP, firewall, hosts, registry, accounts or other protection was run on the host. M0 still lacks guest recovery-media/test accounts and Windows 11 Pro acceptance; M1 VM enforcement and phone biometrics remain NOT RUN. No code change or rebuild in this increment.

## 2026-09-30 — isolated VM boot diagnosis and safe detach

- Ivan approved the VM-only elevated diagnostics. `bcdboot` returned exit 183 / `c0000035` on the guest EFI partition. Retrying with `/c`, then after a verified backup renaming the guest BCD and trying `/c /offline`, returned the same collision. `bcdedit /store` confirmed the newly written BCD is invalid. The original BCD is preserved at `D:\GuardV2Lab\guest-bcd-original.bak` and on the guest EFI partition as `BCD.pre-repair`; the VM is disposable and has no user data.
- The exact powered-off `GuardV2-Lab-20260930` VHDX was detached after reverse path/disk checks. Temporary host letters S:/W: disappeared. The VM is **Off** and its evaluation ISO remains attached to its virtual DVD. No host reboot, Guard, installer or policy execution occurred.
- Elevated VMConnect still does not accept Computer Use input. The VM window is visible, but Ivan must click `Пуск`, then click the black VM screen and press Space at `Press any key to boot from CD or DVD` to enter Windows Setup. Clean guest install, snapshot/recovery and M1 remain NOT RUN.

## 2026-09-30 — Windows image applied to isolated VM; boot check blocked

- Ivan approved restarting **only** `GuardV2-Lab-20260930` with Hyper-V. Computer Use showed the ISO's "press any key" prompt but could not send input to elevated VMConnect. No host reboot occurred.
- Mounted the official evaluation ISO read-only on the host. Its single WIM index is `Windows 11 Enterprise Evaluation`. Before any partition write, verified the exact powered-off VM/VHDX path, the reverse `Get-VHD -DiskNumber` mapping, `File Backed Virtual` bus, empty RAW partition table and 80 GiB size. Only that virtual disk (disk 3 at the time) received GPT/EFI/MSR/NTFS partitions and the Windows image. No physical disk was partitioned.
- Guest Windows files and an EFI BCD file exist. The initial `bcdboot` returned exit code 1, so guest boot was **not verified**. The first follow-up UAC was canceled; diagnostics resumed after Ivan confirmed he did not intend to cancel it. The later entry above records the final detached state. No Guard, installer or policy was run on host or guest.
- Rechecked Release solution build, 29 v2 harnesses and legacy P0 checks, PWA 27/27 + build, Worker 15/15 + typecheck, and Android offline unit-test/APK tasks: all passed. Android Gradle tasks were up to date rather than rerun from scratch. No real phone test or production deployment occurred.

## 2026-09-30 — M0 disposable VM prepared, OS installation pending

- Ivan explicitly approved renewed UAC for the lab. Elevated inventory found zero pre-existing VMs and the built-in Default Switch. Created only `GuardV2-Lab-20260930`, Generation 2, 4 vCPU, 8 GiB startup, dynamic 80 GiB VHDX, Secure Boot on, vTPM on, ProductionOnly checkpoints. VM files moved to `C:\Users\kruko\AppData\Local\GuardV2Lab\VM` because D: free space unexpectedly dropped to ~29 GiB from unrelated activity; VHDX was verified dynamic and only 4 MiB. No unrelated D: data was deleted.
- Downloaded the 90-day Windows 11 Enterprise Evaluation 26H2 ISO from a Microsoft `go.microsoft.com` redirect to the Microsoft CDN into `D:\GuardV2Lab`; size 8,225,329,152 bytes, SHA-256 `BC3F24086EBADC94489066B5AD78089E2CF5C3491E90E790BB81A2B199C10E38`. The published Microsoft hash PDF currently says 25H2, so this is **not** a match against a version-correct official hash; the digest matches an independent catalog only. ISO attached to the dedicated VM. This is preliminary feasibility, not Windows 11 Pro acceptance.
- VM started. Non-elevated VMConnect received access denied; elevated VMConnect showed Hyper-V UEFI boot summary because the DVD keypress window was missed. Awaiting Ivan's action-time confirmation to restart guest and begin Windows installation via VMConnect. No Guard or Windows policy was applied to host or guest yet. No snapshot/recovery test yet.

## 2026-09-29 — M0 execution start

- User explicitly started full development. Planned baseline `a46b73d628ecb5128f1069578f1e184483d6b0bf` pushed as `codex/checkpoint-20260929-2325-guard-integrated`; implementation branch `codex/guard-v2-integrated`. Existing dirty files were the five known planning documents only, committed before checkpoint. No application code changed before checkpoint push.
- Release solution build PASS; 29 explicitly allowlisted v2 console harnesses and legacy P0 checks PASS through `scripts/run-safe-tests.ps1 -SkipBuild`. PWA 27/27 + build, Worker 15/15 + typecheck, Android 18/18 JVM + debug APK PASS. No live Guard/installer/system policy ran on the host.
- Elevated read-only `Get-VM` returned zero guests. Hyper-V service is running; the next read-only UAC for switch inventory was canceled by the user. Do not repeat it silently. Official 90-day Windows 11 Enterprise Eval ISO download was paused at 1.72/7.66 GiB in `D:\GuardV2Lab`; Windows 11 Pro remains final target. Phone not connected (`adb devices` empty), so physical biometric evidence is NOT RUN.
- Official Microsoft guidance confirms standalone local admin can fully control AppLocker; signed App Control with Secure Boot can resist policy tampering but does not document TTL for a previously signed supplemental allow after service loss. M1 cannot be marked PASS from source reading or unit tests.
- Worker now has approval-role-only, one-time locator redemption that returns only a SHA-256 request-id digest. Device token cannot redeem; replay is 410. Worker tests/typecheck PASS. No production deployment performed yet.
- BFF now includes verified frame cursor; PWA pages up to 128 encrypted frames instead of failing on the server's default 20, and direct Android opening no longer depends on clipboard permissions. Android minSdk=31 because its hardware ECDH API starts there. All corresponding safe checks passed and commits were pushed; trusted enrollment, actual UI verifier and native transport remain absent.

## 2026-09-29 — completion plan, implementation not started

- Reconciled the canonical plan with `a53cdad`: M0–M9 deliverables, existing-vs-missing integration map, T01–T20 tests, E01–E10 real acceptance scenarios, VM/phone boundaries and release gates. Updated current handoff and superseded conflicting old passkey/publisher/domain-scope text.
- Verified official Microsoft RSA/PKCS#7 signed-policy requirements and Android ECDH API 31 requirement. M1 must prove dynamic grants/revoke and admin tamper before claiming the strict product; no new key/signing service architecture was silently selected.
- Planning only: no application edits, builds, system tests, deployment or production credentials changed. Memory: PROJECT_ONLY. Resume implementation only after Ivan's next start command; no separate parallel plan created.
## 2026-09-29 — PWA → Android request link

- Fixed the PWA approval locator link to use the scheme, host and query accepted by the existing Android intent filter/parser; invalid locators now fail before navigation. PWA 26/26 tests and production build passed; Android unit-test task and debug APK build passed with the existing GuardDev JDK 17.
- This only delivers a locator to the Android shell. It does not redeem/decrypt the request, request a fingerprint, sign a decision, or grant Windows access. Hyper-V read-only inventory remains unconfirmed; no VM or Guard/system protection was started.

## 2026-09-29 — Guard token master copy

- Ivan confirmed the `Cloudflare — Guard relay deployment` secure note with a masked `API` field was saved in Bitwarden. The note itself was not read back; local DPAPI copy still decrypts. Clipboard had changed after the screenshot and no Guard token remained there.

## 2026-09-26 — Guard Cloudflare token and fail-closed relay publication

- Created no-expiry `Guard relay deployment` account token scoped only to `guard-relay` Individual Workers Editor. Verified from fresh process: token and Guard HTTP 200, VoicePaste HTTP 403. Stored a separate CurrentUser DPAPI operational copy with user-only ACL outside Git; cleared clipboard. Bitwarden master copy is pending Ivan's manual save.
- Relay 15/15 tests, typecheck and production audit passed. Wrangler uploaded and activated `guard-relay` with SQLite Durable Object, then exited 1 because the token cannot read account-wide Workers subdomain settings. External endpoint proves live fail-closed code: 404 root, 401 unauthenticated mailbox, 403 unconfigured bootstrap, 503 unconfigured parent BFF. No broad permission added; no Guard system action on host. Full product remains incomplete.

## 2026-09-25 — Guard Cloudflare access bootstrap, token pending

- Confirmed VoicePaste's separate User API Token → process-only `CLOUDFLARE_API_TOKEN` → CurrentUser DPAPI pattern. The in-app browser could not complete Wrangler's localhost OAuth callback; repeated two-minute sessions expired.
- Created `guard-relay` as a separate Worker in account `7135a2335784ee593d8942ef1d79525f`; replaced the public Hello World template with a fail-closed HTTP 404 stub and verified it from a new request. No production relay code or Guard installation was run.
- Prepared but did not issue the account-owned `Guard relay deployment` token: `Specified Workers: guard-relay`, `Individual Workers Editor`. Ivan authorized creation without expiration on 2026-09-25; the existing 90-day draft must be edited before issuance. Cloudflare browser control timed out, so no token was created or saved. VoicePaste's token and Worker remain untouched.

## 2026-09-24 — verified completion increment, overall product still incomplete

- Code commits on `codex/guard-completion`: `3d2c936` Android, `8d1c94f` account-readiness, `f9da083` dependency patches; docs/memory follow separately. Pre-edit GitHub checkpoint verified at `bd8e7a8ed024c23b1402eeebeec71532bbda0e30`.
- Fixed Android compilation, real .NET/Kotlin signed encrypted request/receipt interop, exact-receipt acceptance and atomic one-process approval outbox; hardened expiry/device-key binding/DER and non-destructive enrollment.
- Tightened existing Windows readiness against Internet-linked and extra enabled administrators. Ivan approved the daily-standard/local-recovery-admin model; full containment after gaining admin rights remains a signed-policy/VM gate.
- Verified Release build, 29 v2 harnesses, 45 legacy checks, Android 18 tests + APK, PWA 26 tests/build, relay 15 tests/typecheck. PWA and relay production audits clean; Cloudflare dev tools retain five high findings. No live Guard, account changes or enforcement.
- External prerequisites verified missing: Hyper-V access denied to this process, Cloudflare CLI unauthenticated. No deployment/VM/phone acceptance, no claim of a finished application. Memory: PROJECT_ONLY; canonical status in `docs/guard-v2-development-plan.md`.

## 2026-07-24 - Guard v2 Stage 5 default-deny web foundation

- Committed `b685072` (`feat(v2): add default-deny web foundation`) on `codex/guard-v2-implementation`.
- Added strict canonical DNS host/PSL exact/subtree decisions; signed `guard.web-bundle.v2` envelopes with catalog/per-bundle rollback floors; a header-only HTTP/CONNECT parser; exact Edge/Chrome managed-policy plans; and fail-closed proxy/WFP/browser/extension readiness.
- Kept authoritative network enforcement independent from extension UX. Future, stale or wrong-session extension evidence blocks child requests, while exact low-privilege proxy SID, loopback exclusivity, WFP closure and effective browser policy remain mandatory for enforcement.
- Website request payloads stay opaque. Service-owned observations bind host/PSL/bundle identity; desired state and bounded reconciliation intent commit atomically; every request outcome has a durable idempotent audit intent.
- Verification: warning-free Release solution build; 321/321 safe checks, including 85/85 Stage 5; clean NuGet vulnerability audit and staged secret/diff checks. The review loop fixed twelve findings and finished clean; focused protocol/state reviews and the independent final security review found no remaining P0/P1/P2 in the code-only scope.
- No Guard, service executable, installer, Cleaner, helper, browser policy, AppLocker, WFP, firewall, hosts, registry, scheduled-task, account or other live system action was run. User-owned `Output`, `.gstack`, review files and Yandex.Disk conflict copies remain unstaged.
- Remaining gate: production proxy/DNS/browser/extension/WFP/catalog/store/scheduler/audit/service adapters plus disposable Windows 11 Pro crash/recovery and browser/network bypass matrix.
- Product boundary confirmed: anti-stop/tamper/uninstall is mandatory for the Windows release and remains a VM/release gate; the first mobile deliverable is parent PWA plus compact native Android/iPhone approval signing, not a child-phone Guard agent.

## 2026-07-24 - Guard v2 Stage 4 default-deny application foundation

- Committed and pushed `35c79ca` (`feat(v2): add default-deny application foundation`) on `codex/guard-v2-implementation`.
- Added mutually exclusive signed-provenance, exact SHA-256 and exact PFN identities; only SHA/PFN can become executable grants. Added exact Main/Updater/Helper bundles, service-attested inventories, maintenance delta candidates and default-deny EXE/MSI/Script/Appx/DLL plans.
- Added a strict child application-request payload containing only an opaque observation id and bounded reason. Service-side observation resolution supplies the exact executable identity and authenticated device/child SID; atomic deduplication and audit fail closed.
- Desired state now commits before catalog lookup. Expiry/quota deadlines are durable, and every apply retains a bounded pre-apply recovery marker until the sink and final schedule succeed. This closes revoke loss during catalog, scheduler, sink and post-commit cancellation failures.
- Verification: warning-free Release solution build; 236/236 safe checks, including 44/44 Stage 4 and 13/13 reconciliation checks; clean NuGet vulnerability audit and staged secret/diff checks. Independent final review found no remaining P0/P1/P2 in the code-only scope.
- Code review loop: 1/1 broad pass, clean on pass 1 after three P1 fixes; score 6.0 to 9.3. Report: `.codex/review-loop-stage4/.codex/review-loop/runs/20260724-013347/report.md` (review artifact intentionally unstaged).
- Updated the canonical plan: the PWA remains the shared parent cabinet, but permissive/dangerous commands use a small native Android/iPhone approval module with a biometric-only hardware-backed signing key because ordinary mobile passkeys allow phone PIN/passcode fallback. A child mobile agent remains outside the first Windows release.
- No Guard, service executable, installer, Cleaner, helper, AppLocker, firewall, hosts, registry, scheduled-task, account or other live system action was run. User-owned `Output`, `.gstack`, review files and Yandex.Disk conflict copies remain unstaged.
- Remaining gate: production policy store/scheduler, signed immutable catalog, Authenticode/PFN extraction, AppLocker sink, service/child wiring, updater carry-forward and Windows 11 Pro VM attack/recovery matrix.

## 2026-07-23 - Guard v2 Stage 3 fail-closed Windows readiness

- Committed `15b8b60` (`feat(v2): add fail-closed Windows readiness`) on `codex/guard-v2-implementation`.
- Added admin-only observational `GetReadiness`; strict bounded wire facts/findings; Windows 11 Pro-only and Secure Boot read probes; bound-child revalidation; bounded separate-local-admin inventory with indirect membership facts; ProgramData ACL recheck; query-only SCM facts; and a pure complete service installation/self-protection contract.
- Production remains fail closed: BitLocker, managed browsers and full service installation proof are `Unknown`; partial SCM health cannot mark the service boundary ready or set `CanEnableProtection=true`.
- Verification: Release solution build; 192/192 safe checks; clean NuGet vulnerability audit, staged diff and high-confidence secret scan. Independent security/correctness review found no P0/P1/P2.
- Code review loop: 1/1 broad pass, clean on pass 1 after three P3 hardening fixes; score 8.8 to 9.4. Report: `.codex/review-loop-stage3/.codex/review-loop/runs/20260723-stage3-readiness/report.md` (review artifact intentionally unstaged).
- No Guard, service executable, installer, Cleaner, helper, AppLocker, firewall, hosts, registry, scheduled-task or account-changing action was run. User-owned `Output`, `.gstack`, review files and Yandex.Disk conflict copies remain unstaged.
- Remaining gate is disposable Windows 11 Pro VM evidence for the native probes, full SCM/install-root/DACL/recovery/service-SID contract, stop/delete/Safe Mode and account-escalation matrix.

## 2026-07-23 - Guard v2 Stage 2 secure service boundary

- Ivan explicitly approved installing the official .NET 10 SDK and Microsoft Windows-service package. Installed SDK `10.0.302`, pinned it in `global.json`, and locked `Microsoft.Extensions.Hosting.WindowsServices` to `10.0.10`.
- Committed `078ffa1` (`feat(v2): add secure Windows service boundary`) on `codex/guard-v2-implementation`.
- Added the SCM/`LocalSystem` service gate; explicit no-reset bootstrap; SYSTEM-only ProgramData layout; LocalSystem DPAPI; encrypted/versioned atomic state with writer lease, CAS and protected hash-chained journal; strict ECDSA P-256; exact-role named pipes with local-only first-instance DACL/token/SID/integrity validation; and active-admin-challenge binding of one validated standard-child SID.
- Fresh setup no longer needs a pre-injected parent key. Child binding is immutable, and the exact-SID child endpoint becomes available after service restart. No public ParentRelay pipe exists.
- Verification: Release solution build; 159/159 safe tests; NuGet vulnerable-package audit clean; exact staged allowlist, diff and high-confidence secret checks clean. Two independent final security/correctness reviews found no P0/P1/P2.
- Code review loop: one clean final pass after 13 fixes; score improved from 5.5 to 9.2. Report: `.codex/review-loop-stage2/.codex/review-loop/runs/20260723-153239/report.md` (review artifact intentionally unstaged).
- No Guard, service executable, installer, Cleaner, helper, AppLocker, firewall, hosts, registry, scheduled-task or account action was run. User-owned `Output`, `.gstack`, review artifacts and Yandex.Disk conflict copies remain unstaged.
- Remaining evidence gate is disposable Windows 11 Pro VM testing. Stronger protection against joint offline rollback of both state and journal requires a future TPM or remote witness.

## 2026-07-23 - Guard v2 full-plan execution checkpoint

- Ivan explicitly authorized continued execution of the approved Guard v2 plan beyond P0.
- Safe remote checkpoint created before new application-code changes: `codex/checkpoint-20260723-0041-guard-v2-implementation` at `6bfcb15e50f05b9110e6c0227c927be683a5f293`.
- Working branch: `codex/guard-v2-implementation`, created from the same commit.
- Check: committed HEAD high-confidence secret scan passed; GitHub identity and push permission were verified. The direct Happ/TUN route timed out once, then the existing process-local Xray proxy completed API and push checks without changing Windows proxy settings.
- Excluded unchanged: user-owned generated `Output`, `.gstack`, Yandex.Disk conflict copies and `.codex/review-loop` artifacts. No Guard executable or Windows enforcement action was run.
- Committed and pushed `de4db2d` (`feat(v2): add secure protocol and domain foundation`) on `codex/guard-v2-implementation`.
- Added isolated Guard v2 contracts/domain/protocol/application layers and four safe harnesses. Setup now binds validated parent public-key material in the same CAS transaction that consumes the one-time challenge; signed parent decisions are canonical, typed and exact-request-bound; reducer, replay, readiness, identity, IPC timeout/quota and maintenance boundaries fail closed.
- Verification: Release solution build; 84/84 safe tests; NuGet vulnerable-package scan clean; staged high-confidence secret scan clean; independent final review found no remaining P0/P1/P2.
- No live Guard, installer, Cleaner, helper, AppLocker, firewall, hosts, registry, scheduled task, service or account action was run. Existing user artifacts remain unstaged.
- The next service increment required explicit permission to install official .NET 10 SDK and the Microsoft Windows-service package. Ivan later approved it; the resolved work is recorded in the Stage 2 entry above. The target was never downgraded to .NET 8.

## 2026-07-22 - Guard v2 Foundation checkpoint

- Done: verified the existing dirty MVP baseline, created writable fork `krukovis-spec/guard-windows-client`, and pushed checkpoint branch `codex/checkpoint-20260722-1920-guard-v2-foundation` at `381afa54a067665b2977389d582ec3166bc8a4ef` before any Guard v2 application-code change.
- Working branch: `codex/guard-v2-foundation`, created from the same checkpoint commit.
- Check: masked secret scan found no high-confidence secret patterns; Release build passed with the existing nullable warning; `Guard.Tests` passed 35/35; staged `git diff --check` passed; remote SHA and push permission were verified.
- Excluded safely: modified generated `Output/Guard-Setup-v1.0.0.exe`, `.gstack`, and Yandex.Disk conflict copies `*копия с компьютера LG*`. These local user files were not deleted or reverted.
- Network: GitHub API POST timeouts were initially isolated to the Happ TUN route; the existing scoped Xray proxy `http://127.0.0.1:10808` completed fork creation and push verification without enabling a global Windows proxy. A later direct recheck passed authenticated GETs and three consecutive side-effect-free POST probes without the proxy, with push permission still true.
- Safety: no Guard, installer, cleaner, helper, AppLocker, firewall, hosts, registry, scheduled-task, or account-changing action was run.
- P0 implementation: hard-disabled legacy LAN cabinet, child pairing/email, Assign API, remote updater and telemetry; removed default PIN fallback and unauthenticated diagnostic/reset/cleanup routes; changed installer/Cleaner to one exact authorized cleanup mode without `uninstall.ok`; added safe diagnostic summary and structured fail-fast cleanup results.
- Implementation commit: `3e7e384d26864a5976da85652f160e0dd7da67ab` (`security: contain legacy Guard control paths`), created from an exact 18-file allowlist. User-owned `Output`, `.gstack`, conflict copies and `.codex/review-loop` stayed unstaged.
- Final verification: Release solution build passed; expanded safe harness passed 45/45 checks, including fake cleanup failures, exit-code contract and scheduled-task query classification. Inno 6.7.3 compiled the post-confirmation uninstall hook into an excluded review-only directory; the installer was not run and `Output` was untouched. NuGet audit, diff check, masked secret scan and UTF-8/mojibake check passed. Independent review accepted the code/security delta with no remaining P0/P1.

## 2026-06-14 - PIN recovery bypass hardening

- Done: closed the old-server PIN-reset bypass Ivan described: `DeviceUpdater` now ignores remote `pinCode`, emergency PIN changes remain parent-cabinet-only with step-up parent password, `123456` cannot be saved as a permanent custom PIN, legacy remote server mode is disabled by default, and the tray no longer offers `Привязать через сервер`.
- Files: `Guard.Core/GuardState.cs`, `guard/DeviceUpdater.cs`, `Guard.Core/ParentCommand.cs`, `guard/Program.cs`, `Guard.Tests/Program.cs`, `docs/parent-mvp-checklist.md`.
- Check: `dotnet run --project Guard.Tests\Guard.Tests.csproj` passes 35/35; `dotnet msbuild guard.sln /restore /p:Configuration=Release /p:Platform="Any CPU"` passes with one existing nullable warning in `ParentAdminServer.cs`; `git diff --check` passes except LF/CRLF warnings on existing files.
- Safety: no live Guard/helper/cleaner/installer/AppLocker/hosts/firewall/registry/scheduled-task action was run.

## 2026-06-08 - Russian/English interface

- Done: added `GuardState.UiLanguage` defaulting to Russian, `set-language` parent command, a signed-in parent-cabinet language switch, and Russian/English copy for parent dashboard, child tray request flows, ask-parent prompts, tasks, PIN dialog, pairing/server-assign forms, and diagnostic-window buttons.
- Files: `Guard.Core/UiLanguage.cs`, `Guard.Core/GuardState.cs`, `Guard.Core/ParentCommand.cs`, `Guard.Core/PinForm.cs`, `guard/ParentAdminServer.cs`, `guard/Program.cs`, `guard/AssignForm.cs`, `guard/DiagnosticWindow.cs`, `Guard.Tests/Program.cs`, `.codex/memory/*`.
- Check: final `git diff --check` passes; Release build passes after fixing the `GuardState.UiLanguage` name-shadowing compile error; `Guard.Tests\bin\Release\net48\Guard.Tests.exe` passes 32/32; Inno Setup rebuilt `Output\Guard-Setup-v1.0.0.exe` to 2732742 bytes at 2026-06-08 21:10.
- Safety: installer was compiled only; no Guard app/helper/cleaner/installer/AppLocker/hosts/firewall/registry/scheduled-task action was run in Codex.

## 2026-06-08 - Strict default-deny approval mode

- Done: closed the gap in Ivan's desired flow: new LAN pairing arms AppControl `Enforce`, AppLocker blocked launches ask the child to request access, web default-deny creates hidden blocked-domain rules for unknown browser domains, prompts the child, closes the browser, and lets the parent approve 15/60 minutes, always, or deny.
- Files: `Guard.Core/WebAccessPolicy.cs`, `Guard.Core/DomainAccess.cs`, `Guard.Core/AccessRequest.cs`, `Guard.Core/ApplicationControl.cs`, `Guard.Core/GuardState.cs`, `guard/Program.cs`, `guard/ActivityMonitor.cs`, `guard/ParentAdminServer.cs`, `Guard.Tests/Program.cs`, `docs/parent-mvp-checklist.md`.
- Check: `git diff --check` passes except existing LF/CRLF warnings; `dotnet msbuild guard.sln /restore /p:Configuration=Release /p:Platform="Any CPU"` passes; `Guard.Tests\bin\Release\net48\Guard.Tests.exe` passes 31/31; Inno Setup rebuilt `Output\Guard-Setup-v1.0.0.exe`.
- Safety: no live Guard/helper/cleaner/installer/AppLocker/hosts/firewall/registry/scheduled-task action was run in Codex.
- Memory: `Directory.Build.props` now excludes Yandex.Disk `*копия с компьютера LG*` files from SDK-style compilation after MSBuild found duplicate type definitions; `GuardInstaller.iss` excludes the same copy files from installer bin wildcards.

## 2026-06-06

- Done: unlocked baseline build with project-local .NET Framework 4.8 reference assemblies, added `Guard.Tests`, safe command runner abstraction, pairing code model, parent command contract, and child-side pairing code form.
- Files: `Directory.Build.props`, `Guard.Core/*`, `Guard.Tests/*`, `guard/PairingForm.cs`, `guard/Program.cs`, `guard.sln`.
- Check: `dotnet msbuild guard.sln /p:Configuration=Release /p:Platform="Any CPU"` passes; `Guard.Tests\bin\Release\net48\Guard.Tests.exe` passes 9 checks.
- Safety: did not run `guard.exe`, `Guard.Cleaner.exe`, `StartHelperG.exe`, installer, or live hosts/firewall/registry/scheduled-task commands.

## 2026-06-06 - LAN parent cabinet MVP

- Done: added `ParentAdminServer` LAN cabinet with pairing-code setup, parent password auth, domain block/unblock, sync toggle, emergency PIN update, and installer build.
- Files: `guard/ParentAdminServer.cs`, `Guard.Core/ParentAdminAuth.cs`, `Guard.Core/GuardState.cs`, `Guard.Tests/Program.cs`, `docs/parent-mvp-checklist.md`.
- Check: sequential `dotnet msbuild guard.sln /p:Configuration=Release /p:Platform="Any CPU"` passes; `Guard.Tests\bin\Release\net48\Guard.Tests.exe` passes 10 checks; Inno Setup built `Output\Guard-Setup-v1.0.0.exe`.
- Safety: installer was compiled only, not executed; no live Guard/cleaner/helper/system actions were run in Codex.

## 2026-06-06 - Local mode remote-skip hardening

- Done: added `GuardState.LocalParentMode`, set it during LAN parent setup, and made local mode skip old remote update/info-log calls to `guard.alexweb.app`.
- Files: `Guard.Core/GuardState.cs`, `guard/ParentAdminServer.cs`, `guard/DeviceUpdater.cs`, `guard/Program.cs`, `Guard.Tests/Program.cs`.
- Check: one preliminary build/test passed; then 5 sequential cycles of Release build plus `Guard.Tests` passed 11/11 checks; Inno Setup rebuilt `Output\Guard-Setup-v1.0.0.exe`.
- Safety: did not run Guard app, helper, cleaner, installer, or live hosts/firewall/registry/scheduled-task actions.

## 2026-06-06 - Application control MVP

- Done: added AppLocker-backed application control model, parent cabinet controls for `Off` / `Audit` / `Enforce`, permanent app allowances, temporary app grants, warning-before-expiry, and stop-on-expiry runtime checks.
- Files: `Guard.Core/ApplicationControl.cs`, `Guard.Core/GuardState.cs`, `Guard.Core/ParentCommand.cs`, `guard/ParentAdminServer.cs`, `guard/Program.cs`, `Guard.Tests/Program.cs`, `docs/parent-mvp-checklist.md`.
- Check: one build/test passed, then 5 sequential Release build plus `Guard.Tests` cycles passed 14/14 checks; Inno Setup rebuilt `Output\Guard-Setup-v1.0.0.exe`.
- Safety: AppLocker policy was not applied in Codex; no Guard app/helper/cleaner/installer or live system policy action was run.

## 2026-06-07 - Countdown and Task Manager hardening

- Done: final app-grant warnings now fire at each minute mark `5/4/3/2/1`; Task Manager has AppControl state, deny-rule generation, runtime stop, and parent-cabinet temporary allowance/block-now controls.
- Files: `Guard.Core/ApplicationControl.cs`, `Guard.Core/ParentCommand.cs`, `guard/ParentAdminServer.cs`, `guard/Program.cs`, `Guard.Tests/Program.cs`, `docs/parent-mvp-checklist.md`.
- Check: 5 sequential Release build plus `Guard.Tests` cycles passed 16/16 checks; Inno Setup rebuilt `Output\Guard-Setup-v1.0.0.exe`.
- Safety: no live Guard/helper/cleaner/installer/AppLocker/system-policy action was run.

## 2026-06-07 - Review-loop hardening before live use

- Done: fixed AppControl bypasses via Windows management tools (`taskkill`, `cmd`, PowerShell, script hosts, registry/service/task tools), made Task Manager/system-tool status null-safe, made runtime handle null/single-use process lists, and added `PolicySchemaVersion` so old active AppLocker policies reapply after upgrade.
- Files: `Guard.Core/ApplicationControl.cs`, `guard/ParentAdminServer.cs`, `Guard.Tests/Program.cs`, `docs/parent-mvp-checklist.md`, `Output/Guard-Setup-v1.0.0.exe`.
- Check: Release build passes; `Guard.Tests\bin\Release\net48\Guard.Tests.exe` passes 19/19; `git diff --check` passes except existing LF/CRLF warnings; Inno Setup rebuilt installer to 2687354 bytes at 2026-06-07 00:50.
- Safety: installer was compiled only; no Guard app/helper/cleaner/installer or live AppLocker/hosts/firewall/registry/scheduled-task action was run.

## 2026-06-07 - Parent requests, activity, limits, tasks

- Done: added application access request inbox, AppLocker event parser/reader, child tray request action, parent approve/deny controls, activity accounting, app categories, daily/session limits, daily tasks with bonus minutes, child tray task completion, and safe account-hardening command guard.
- Files: `Guard.Core/AccessRequest.cs`, `Guard.Core/AppLockerBlockedEvent.cs`, `Guard.Core/ActivityAccounting.cs`, `Guard.Core/DailyTasks.cs`, `Guard.Core/AccountHardening.cs`, `guard/AppLockerEventReader.cs`, `guard/ActivityMonitor.cs`, `guard/ParentAdminServer.cs`, `guard/Program.cs`, `Guard.Tests/Program.cs`, `docs/*`.
- Check: Release build passes; `Guard.Tests\bin\Release\net48\Guard.Tests.exe` passes 25/25; `git diff --check` passes except existing LF/CRLF warnings; Inno Setup rebuilt installer to 2707290 bytes at 2026-06-07 03:27.
- Safety: no live Guard/helper/cleaner/installer/AppLocker/EventLog/account/hosts/firewall/registry/scheduled-task action was run in Codex.
- Remaining: true cloud cabinet is still not implemented.

## 2026-06-07 - Website requests and guarded Windows account UI

- Done: added child tray `Request Site Access`, website `AccessRequest` approvals for 15/60 minutes or always, active site grants with `Revoke`, expiry-driven domain rule rebuild, and parent-cabinet `Windows account` guard for selecting/demoting the child user only when a separate admin exists.
- Files: `Guard.Core/DomainAccess.cs`, `Guard.Core/AccessRequest.cs`, `Guard.Core/ParentCommand.cs`, `Guard.Core/AccountHardening.cs`, `Guard.Core/GuardState.cs`, `guard/ParentAdminServer.cs`, `guard/Program.cs`, `Guard.Tests/Program.cs`, `docs/*`.
- Check: Release build passes; `Guard.Tests\bin\Release\net48\Guard.Tests.exe` passes 26/26; `git diff --check` passes except existing LF/CRLF warnings; UTF-8 mojibake check passes; Inno Setup rebuilt installer to 2712139 bytes at 2026-06-07 04:50.
- Safety: no live Guard/helper/cleaner/installer/AppLocker/EventLog/account/hosts/firewall/registry/scheduled-task action was run in Codex.
- Remaining: true cloud cabinet over the internet is still not implemented; current parent cabinet is LAN-only.

## 2026-06-07 - Site activity and site limits

- Done: added site activity target `site:domain`, site category rules, parent cabinet category forms for allowed sites and site usage, browser-domain capture through Windows UI Automation, and domain grant filtering when site/category limits are reached.
- Files: `Guard.Core/ActivityAccounting.cs`, `Guard.Core/DomainAccess.cs`, `Guard.Core/ParentCommand.cs`, `guard/ActivityMonitor.cs`, `guard/ParentAdminServer.cs`, `guard/Program.cs`, `guard/guard.csproj`, `Guard.Tests/Program.cs`, `docs/*`.
- Check: Release build passes; `Guard.Tests\bin\Release\net48\Guard.Tests.exe` passes 27/27; `git diff --check` passes except existing LF/CRLF warnings; UTF-8 mojibake check passes; Inno Setup rebuilt installer to 2714724 bytes at 2026-06-07 05:14.
- Safety: no live Guard/helper/cleaner/installer/AppLocker/account/hosts/firewall/registry/scheduled-task action was run in Codex.
- Limitation: browser-domain activity is best-effort via UI Automation; if the browser does not expose the URL, Guard counts the browser app instead of the specific site.

## 2026-06-07 - Parent maintenance mode

- Done: added parent-cabinet `Maintenance mode` for temporarily unlocking all protections, preserving previous blocking/AppControl/Task Manager state, extending active maintenance, repairing accidental protection changes while active, restoring automatically on timer expiry, and auto-refreshing the signed-in dashboard every 15 seconds when the parent is not typing.
- Files: `Guard.Core/MaintenanceMode.cs`, `Guard.Core/GuardState.cs`, `Guard.Core/ParentCommand.cs`, `guard/ParentAdminServer.cs`, `guard/Program.cs`, `Guard.Tests/Program.cs`, `docs/parent-mvp-checklist.md`, `.codex/memory/features.md`.
- Check: Release build passes; `Guard.Tests\bin\Release\net48\Guard.Tests.exe` passes 28/28; `git diff --check` passes except existing LF/CRLF warnings; Inno Setup rebuilt installer to 2716658 bytes at 2026-06-07 12:40.
- Safety: no live Guard/helper/cleaner/installer/AppLocker/account/hosts/firewall/registry/scheduled-task action was run in Codex.

## 2026-06-07 - Parent cabinet step-up auth

- Done: added 5-minute parent-cabinet sessions and step-up parent-password confirmation for actions that can weaken protection, including maintenance mode, sync-off, app-control changes, approvals, app grants, Task Manager access, limits/tasks/categories, PIN and Windows account actions.
- Files: `Guard.Core/ParentAdminSecurity.cs`, `guard/ParentAdminServer.cs`, `Guard.Tests/Program.cs`, `docs/parent-mvp-checklist.md`, `.codex/memory/features.md`, `.codex/memory/project.md`.
- Check: Release build passes; `Guard.Tests\bin\Release\net48\Guard.Tests.exe` passes 29/29; Inno Setup rebuilt installer to 2717786 bytes at 2026-06-07 13:29.
- Safety: no live Guard/helper/cleaner/installer/AppLocker/account/hosts/firewall/registry/scheduled-task action was run in Codex.
