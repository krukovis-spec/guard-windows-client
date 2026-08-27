# Guard Personal MVP Implementation Plan

## Target User Flow

- Child PC: install Guard, open the first-run window, see a short pairing code.
- Parent PC: open the parent cabinet, enter the pairing code, set a strong cabinet password, then manage restrictions from the parent PC.
- After pairing: the child PC should not require routine password entry. Local PIN remains only as an emergency fallback for uninstall/disable flows.
- Parent cabinet access must be protected by a strong password. Ivan stores passwords in Bitwarden, so password complexity is acceptable on the parent side.

## Product Direction

- Recommended MVP: local-first hybrid.
- First phase: make the command/rules model independent from `guard.alexweb.app`, so local admin, LAN admin, and future cloud server can all feed the same client logic.
- Final direction: parent cabinet with secure auth, device pairing, remote policy updates, and client polling.

## Step 1 - Build And Test Foundation

Goal:
- Make the project buildable and testable without launching Guard or touching Windows system settings.

Actions:
- Install or reference `.NET Framework 4.8` targeting/reference assemblies only after Ivan approves.
- Restore NuGet packages.
- Add a small test/harness project for pure logic if the existing toolchain allows it.

Gate:
- `dotnet msbuild guard.sln /restore /p:Configuration=Release /p:Platform="Any CPU"` passes, or the remaining error is documented with exact cause.
- No app exe, installer, cleaner, StartHelperG, hosts, firewall, registry, or scheduled task action is run.

## Step 2 - Safe System Boundary

Goal:
- Prevent accidental live writes while changing product logic.

Actions:
- Introduce interfaces/adapters around hosts, firewall, scheduled tasks, registry startup, DNS flush, and network reset.
- Keep the current real implementation, but add a fake/dry-run implementation for tests.

Gate:
- Pure tests/harness can exercise policy application decisions without admin rights.
- System command strings are validated before they can reach `netsh`, `schtasks`, `cmd`, or file paths.
- No new logs include PIN, pairing code, device id, or raw server payloads.

## Step 3 - Pairing Model

Goal:
- Replace the current parent-on-child-password flow with one-time child-code pairing.

Actions:
- Add a pairing model: pairing code, device display name, device id, pairing status, paired-at timestamp.
- Child PC first-run screen shows a short code and clear status: waiting, paired, expired, failed.
- Parent cabinet uses the code to claim the device.

Gate:
- Pairing code validation is covered by tests.
- Pairing code is short enough to type, expires, and is never logged raw.
- Child-side UI does not ask for the parent cabinet password.

## Step 4 - Parent Cabinet Contract

Goal:
- Define the parent-side commands before building UI around them.

Actions:
- Create a single policy/command schema for:
  - block custom site/domain;
  - block preset/category;
  - schedule;
  - temporary allow/block;
  - sync on/off;
  - emergency PIN update.
- Make both future server sync and local/LAN admin use this schema.

Gate:
- Existing `InstructionsModel`, `RuleParser`, and `SchedulerEngine` can consume the schema or have an adapter with tests.
- No hardcoded `guard.alexweb.app` remains in core policy logic.

## Step 5 - Local Parent Admin MVP

Goal:
- Give Ivan useful control from the parent PC before a full cloud service exists.

Actions:
- Build a minimal parent cabinet/admin surface with strong password auth.
- Allow entering a pairing code and managing one child device.
- Start with simple rules: add blocked domain, remove blocked domain, toggle sync.

Gate:
- Parent-side actions change only the policy store/mock server in tests.
- Child client can fetch/apply the changed policy through the same contract.

## Step 6 - Remote Server Option

Goal:
- Add internet-based remote management after local flow is proven.

Actions:
- Implement or select a small backend for auth, device pairing, policy storage, and client polling.
- Support Google/Yandex auth if practical; password-only is acceptable for first private MVP if protected and stored in Bitwarden.

Gate:
- Parent auth is separated from child pairing.
- Child polling uses HTTPS and does not expose admin password.
- Loss of internet leaves the last known policy active.

## Stop Conditions

- Stop before installing Visual Studio Build Tools, .NET Developer Pack, NuGet packages, or other system dependencies unless Ivan approves.
- Stop before running any generated exe, installer, cleaner, StartHelperG, or action that can touch hosts/firewall/registry/scheduled tasks.
- Stop if a gate fails twice with the same root cause; document the blocker and next safest option.
