# Worklog

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
