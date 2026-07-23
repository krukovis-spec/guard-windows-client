# Worklog

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
