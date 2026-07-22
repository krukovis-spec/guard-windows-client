# Project Capsule

## Purpose

- `guard-windows-client` is an open-source Windows parental-control/filtering client under `.NET Framework 4.8`.
- Original upstream code contains sync/assign/log routes for `https://guard.alexweb.app`, but Guard v2 P0 hard-disables the complete legacy control plane and telemetry regardless of persisted state. Remote `pinCode` updates are ignored and legacy Assign/pairing UI is excluded from the active build.
- Guard v2 is now a defined parent-first product: app/site default-deny, child requests, remote parent decisions, an outbound cloud relay and a passkey-protected PWA. The canonical living specification is `docs/guard-v2-development-plan.md`.

## How To Work

- Root: `C:\Yandex.Disk\Projects\guard-windows-client`.
- Start every future session with `AGENTS.md`, then this capsule.
- During design discussion, update `docs/guard-v2-development-plan.md` in the same turn. Silence after a recommendation means acceptance; later Ivan corrections replace the old decision. Do not change application code until Ivan explicitly starts implementation.
- Do not run the app, installer, cleaner, helper or admin-affecting code without Ivan's explicit approval.
- Prefer first verifying build/toolchain, then adding tests around pure logic before touching system enforcement.

## Architecture

- `guard/` - main WinForms/tray client, API sync, forms, rule application.
- `Guard.Core/` - shared state, DPAPI storage, cleanup helpers, scheduled task helper, models.
- `Guard.Cleaner/` - uninstall/PIN cleanup helper.
- `GuardStartHelper/` - startup/watchdog helper.
- `GuardInstaller.iss` - Inno Setup installer.

## Current State

- Cloned from `https://github.com/ganjie/guard-windows-client.git`.
- Moved to `C:\Yandex.Disk\Projects\guard-windows-client` on 2026-06-06.
- Git state at bootstrap: `main...origin/main`, clean.
- Tooling observed on 2026-06-06: `dotnet.exe` exists (`.NET SDK 8.0.421`); legacy Framework MSBuild exists (`4.8.9221.0`); Visual Studio 2022 Build Tools MSBuild not found in standard paths.
- Baseline build on 2026-06-06 was fixed without installing Visual Studio Build Tools by adding `Directory.Build.props` with `Microsoft.NETFramework.ReferenceAssemblies.net48` and `GenerateResourceMSBuildArchitecture/Runtime = Current...`. Current gate: `dotnet msbuild guard.sln /p:Configuration=Release /p:Platform="Any CPU"` passes cleanly. No Guard app/cleaner/helper exe was launched.
- Inno Setup is available at `C:\Users\kruko\AppData\Local\Programs\Inno Setup 6\ISCC.exe`.
- `Guard.Tests` is a no-framework console harness for safe pure-logic checks. Current P0 gate is 45/45 checks via `Guard.Tests\bin\Release\net48\Guard.Tests.exe`.
- `Directory.Build.props` also excludes Yandex.Disk conflict-copy files matching `**/*копия с компьютера LG*.*`; otherwise SDK-style `.csproj` auto-includes duplicate `.cs` files and the build fails with repeated type definitions.
- System process calls now route through `ISystemCommandRunner` / `SystemCommandRunnerProvider`, so tests can fake `cmd`, `netsh`, and `schtasks` without touching Windows.
- The LAN pairing/PIN flow below is historical MVP state, not the Guard v2 security boundary. The 2026-07-22 plan replaces it with a short-lived parent-scanned setup QR, passkeys, no email recovery, a `LocalSystem` service and restricted child UI.
- The old LAN parent cabinet remains only as quarantined migration code. `MainForm` never starts it, `ParentAdminServer.Start()` always fails closed under P0 policy, `/setup` returns 403, and child-visible pairing/Assign/email surfaces are not compiled into the active client.
- `DeviceUpdater` and `SendInfoLogAsync` check the same hard-false legacy policy before any network payload. Persisted `AllowLegacyRemoteServer=true`, `Assigned=true`, or a legacy `DeviceId` cannot reopen sync or telemetry.
- Application control MVP is implemented: new LAN pairing sets AppLocker `Enforce` mode by default, parent cabinet can still set `Off` / `Audit` / `Enforce`, add permanent `.exe` allowances, grant temporary `.exe` access, show countdown warnings for each final minute `5/4/3/2/1`, and stop expired running apps. Task Manager plus core management tools (`taskkill`, `cmd`, PowerShell, script hosts, registry/service/task tools) are blocked by default in AppControl mode and can be temporarily allowed only from the parent cabinet. Policy generation uses `ApplicationControlPolicyManager` through `SystemCommandRunnerProvider`; Codex only built/tested it and did not apply live AppLocker policy.
- Strict parent-approval mode exists for apps and sites. AppLocker blocked-launch events in `Enforce` ask the child whether to request access; parent approves for 15/60 minutes, always, or denies. Web default-deny is enabled by default: unknown browser domains become hidden `default-deny-site:*` block rules, the child sees an ask-parent prompt, and active `DomainAccessGrants` suppress those blocks only while time/category limits allow.
- Activity/limit/task MVP exists: Guard records foreground app usage without typed-key content, ignores idle intervals, tries to record active browser domain through Windows UI Automation, lets parent categorize apps/sites, set daily/session category limits, define daily tasks, and grant bonus minutes from self-report or verified app-time tasks. If browser URL is unavailable, time falls back to the browser app entry.
- Account hardening is wired to the parent cabinet with an explicit child Windows user selector. It reads the local built-in Administrators group name via SID, verifies a separate admin exists, then can demote the selected child user through `ISystemCommandRunner`; Codex tested fake commands only and did not change live accounts.
- Parent maintenance mode is implemented: the parent cabinet can temporarily unlock all protections for 1-480 minutes, preserving prior site blocking, AppControl mode, and Task Manager/system-tool state; timer expiry or `End maintenance now` restores the prior state and marks rules/policy for reapply.
- Parent cabinet sessions expire after 5 minutes, and sensitive actions require step-up parent password confirmation. Browser auto-refresh does not replace Bitwarden/Windows locking; Ivan should still set Bitwarden vault timeout and use Windows lock on the parent PC.
- P0 local privileged actions accept only an already stored matching custom six-digit PIN. Missing/blank state and the known value `123456` always fail closed for disable and uninstall; no default secret is substituted. Email/SMS/TOTP and legacy payloads cannot establish or recover ownership.
- Cleaner accepts only the exact `/authorize-and-clean` mode from Inno, has no reusable `uninstall.ok`, and reports success only after every cleanup stage is confirmed. Inno invokes it at post-confirmation `usUninstall`; structured failures map to exit code 2 and `Abort` binary removal. Scheduled-task cleanup treats only explicit file/task-not-found results as confirmed absence; ambiguous nonzero errors fail closed.
- Main parent/child UI is bilingual Russian/English. `GuardState.UiLanguage` defaults to Russian; the signed-in parent cabinet has a `Language` switch (`set-language`) that does not require step-up auth or reapply protection. Parent cabinet, tray child requests/tasks, pairing/server-assign forms, PIN form, and diagnostic-window buttons use the selected language; technical logs remain mostly English.
- AppControl policy has `PolicySchemaVersion`; active old schemas reapply automatically so newly added deny-rules are not skipped after an upgrade.
- Installer builds successfully with Inno Setup to `Output\Guard-Setup-v1.0.0.exe`. Latest build after RU/EN UI: 2026-06-08 21:10, size 2732742 bytes, compiled successfully with `GuardInstaller.iss`; the installer was built but not run in Codex. `GuardInstaller.iss` excludes `*копия с компьютера LG*` from bin wildcards so conflict copies do not ship.

## Risks

- The 2026-07-22 P0 source changes close the child-visible first-pairing takeover, known/missing PIN bypasses, legacy telemetry and unsafe Cleaner routes. Do not deploy to the child PC yet: installer/Cleaner and enforcement lifecycle still require disposable Windows VM validation.
- The current admin tray process, HKCU autostart and interactive scheduled-task watchdog do not form a reliable boundary for a separate standard child account. The recommended architecture is a `LocalSystem` Windows service that owns policy/state plus a separate child-session UI over restricted IPC.
- Current web default-deny is best-effort UI Automation after navigation, not browser-independent enforcement. The AppLocker policy also keeps broad Windows allow rules while blocking only a partial list of documented bypass hosts.
- The installer and all executable components were `NotSigned` on 2026-07-22; there is no CI workflow or Windows VM security test matrix. Release build and all 45 safe checks pass, but this is not evidence that enforcement is tamper-resistant.
- Live execution can modify `hosts`, firewall, scheduled tasks, registry autostart and DPAPI state backups.
- App control live execution can modify local Windows AppLocker policy and start Application Identity service. New pairing now arms `Enforce`, so the first real run should be on a VM/test child account or with Ivan explicitly ready to use parent `Maintenance mode`. Child Windows account should be non-admin. When maintenance access is temporarily allowed, Task Manager and the related system tools are allowed together for that window.
- Site default-deny is best-effort at browser level: it depends on browser UI Automation exposing the address bar, then closes the browser process after prompting. It does not read keystrokes or browser history.
- Hardcoded external service URLs still exist in quarantined legacy code, but P0 policy blocks them before network use and Assign UI is excluded from compilation. Do not weaken this to a persisted opt-in or restore server-driven PIN/email recovery.
- Diagnostics now expose only aggregate status/counts. Never add logs with PIN, assign code, device id or raw private server data.

## Recommended Next

- Guard v2 Foundation/P0 containment is the active first increment on `codex/guard-v2-foundation`; its remote baseline is `codex/checkpoint-20260722-1920-guard-v2-foundation` at `381afa54a067665b2977389d582ec3166bc8a4ef`, and the reviewed application commit is `3e7e384d26864a5976da85652f160e0dd7da67ab`.
- Current product path remains: temporary passkey-gated maintenance, signed app identities, managed supported browsers, localhost domain proxy without HTTPS interception, parent PWA and four decisions (`always`, `temporary`, `daily quota`, `deny`).
- Next only after Ivan's instruction: establish the `LocalSystem` service boundary and secure Windows account baseline. Do not start that increment implicitly.
- Do not install or live-test the current build on the child PC. After the P0 changes, validate only in disposable Windows 11 Pro VMs before any real-device pilot.
- Reuse the tested request/grant/limit/task engines, but replace the privileged tray/watchdog boundary, child-known pairing/PIN recovery, UI-Automation web enforcement and one-page LAN cabinet.
- The current cabinet is LAN-only and must not be exposed to the internet. Guard v2 requires a new outbound TLS device channel, encrypted relay payloads where practical, and a passkey-protected parent PWA.
