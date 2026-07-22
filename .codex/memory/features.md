# Features

## Russian/English UI

- User value: Ivan can use the app in Russian by default while keeping English available if needed.
- Where: `Guard.Core/UiLanguage.cs`, `Guard.Core/GuardState.cs`, `Guard.Core/ParentCommand.cs`, `guard/ParentAdminServer.cs`, `guard/Program.cs`, `guard/AssignForm.cs`, `guard/DiagnosticWindow.cs`, `Guard.Core/PinForm.cs`.
- Status: built and packaged; safe tests cover language normalization, parent command switching, and no step-up auth for `set-language`.
- Demo line: open the signed-in parent cabinet, use `Язык / Language`, switch `Русский` or `English`; child tray requests, ask-parent prompts, tasks, PIN, pairing, and main cabinet copy follow the saved language.

## Strict Default-Deny Approval Mode

- User value: the child cannot just open a random app/site; Guard blocks by default, offers an ask-parent flow, and the parent decides 15 minutes, 60 minutes, always, or deny.
- Where: `Guard.Core/WebAccessPolicy.cs`, `Guard.Core/ApplicationControl.cs`, `Guard.Core/AccessRequest.cs`, `guard/Program.cs`, `guard/ParentAdminServer.cs`.
- Status: built and safe-tested; real AppLocker/browser enforcement still needs a VM or Ivan-approved child-account test because Codex did not apply live Windows policy.
- Demo line: child launches an unapproved `.exe` or opens an unknown site in a supported browser; Guard shows an ask-parent prompt; the request appears in the LAN parent cabinet.

## LAN Parent Cabinet MVP

- User value: parent installs Guard on the child PC, reads a short pairing code, then manages basic blocking from a browser on the parent PC in the same home network.
- Where: `guard/PairingForm.cs`, `guard/ParentAdminServer.cs`, `Guard.Core/ParentCommand.cs`, `Guard.Core/ParentAdminAuth.cs`.
- Status: built and packaged; not live-tested in Codex because installer/app/system actions require Ivan's explicit confirmation.
- Demo line: open the LAN URL shown in the pairing window, enter the pairing code, set a strong parent password, then add/remove blocked domains or pause/enable blocking.

## Application Control MVP

- User value: parent can prevent the child from bypassing site blocks by downloading another browser or installer, and can give a game/app temporary access with a save-warning before time expires.
- Where: `Guard.Core/ApplicationControl.cs`, `guard/ParentAdminServer.cs`, `guard/Program.cs`.
- Status: built and packaged; verified by safe tests only. Real AppLocker enforcement still needs a live Windows test with Ivan's explicit approval.
- Demo line: add allowed `.exe` paths in `Audit`, switch to `Enforce`, then use `Allow temporarily` for a game/installer; final warnings tick `5/4/3/2/1`, and Task Manager plus core system tools can be allowed temporarily only from the parent cabinet.

## Requests, Activity, Limits, Tasks

- User value: child can request an app or site without knowing the parent password; parent sees the request, approves temporarily/always or denies, then sees real app/site activity and can trade tasks for bonus time.
- Where: `Guard.Core/AccessRequest.cs`, `Guard.Core/DomainAccess.cs`, `Guard.Core/ActivityAccounting.cs`, `Guard.Core/DailyTasks.cs`, `guard/ParentAdminServer.cs`, `guard/Program.cs`.
- Status: built and packaged; safe tests cover app/site request flow, AppLocker event parsing, idle-aware app activity, browser-domain site activity, daily/session limits, task rewards, and guarded admin demotion. Real AppLocker/account/system enforcement still needs Ivan-approved live test.
- Demo line: child tray `Request App Access` or `Request Site Access` creates a pending request; parent cabinet approves `15 min` / `60 min` / `Always`; `Allowed sites`, `Today activity`, `Time limits`, and `Daily tasks` manage usage and rewards.

## Windows Account Hardening

- User value: parent can stop the main bypass, the child staying a Windows admin, without guessing command-line steps.
- Where: `Guard.Core/AccountHardening.cs`, `Guard.Core/ParentCommand.cs`, `guard/ParentAdminServer.cs`.
- Status: parent cabinet has a guarded account block; demotion is offered only when a separate admin exists. Tested with fake command runner only.
- Demo line: set `Child Windows user` in the cabinet, confirm Guard sees another admin, then convert the child account to standard user.

## Maintenance Mode

- User value: parent can temporarily unlock the child PC for setup/updates without deleting Guard rules, then restore protection automatically.
- Where: `Guard.Core/MaintenanceMode.cs`, `Guard.Core/ParentCommand.cs`, `Guard.Core/ParentAdminSecurity.cs`, `guard/ParentAdminServer.cs`, `guard/Program.cs`.
- Status: built and packaged; safe tests cover start, extension, accidental protection changes during maintenance, timer expiry, and restore.
- Demo line: keep the signed-in parent cabinet open; it auto-refreshes when the parent is not typing, so requests appear quickly. Use `Maintenance mode` -> `Unlock all temporarily`, do setup on the child PC, then press `End maintenance now` or wait for the timer.

## Parent Cabinet Step-Up Auth

- User value: if the parent leaves the parent PC unlocked, the child still cannot use the open cabinet to weaken protection without the parent password.
- Where: `Guard.Core/ParentAdminSecurity.cs`, `guard/ParentAdminServer.cs`.
- Status: built; safe tests cover 5-minute session expiry and sensitive-action classification.
- Demo line: click a dangerous action such as `Unlock all temporarily` or `Approve always`; Guard shows a separate parent-password confirmation before applying it.
