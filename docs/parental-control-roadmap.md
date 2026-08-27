# Guard parental-control roadmap

> Исторический roadmap текущего MVP. Канонический план Guard v2 находится в
> [`guard-v2-development-plan.md`](guard-v2-development-plan.md). Новые продуктовые,
> UX- и архитектурные решения добавляются только туда.

## Goal

Make Guard usable for Ivan as a parent-first Windows parental-control app:
the child asks for access, the parent approves remotely, Guard tracks real
activity and applies limits without requiring the parent to use the child PC.

## Safety Rule

- Do not silently demote every administrator account.
- Setup may convert the child account to standard user only after Guard verifies
  that a separate parent/admin account remains available.
- Codex must not run live installer, Guard app, AppLocker, hosts, firewall,
  registry, scheduled-task or account-management actions without Ivan approval.

## Steps And Gates

Status on 2026-06-07: steps 1-7 are implemented and covered by safe tests.
The remaining product step is the internet/cloud cabinet; the current cabinet is
LAN-only.

1. Access request inbox for applications.
   - Result: a blocked or requested `.exe` creates a pending request; parent can
     deny, allow for 15/60 minutes, or allow always.
   - Gate: pure logic tests pass; parent cabinet renders the request; approval
     updates AppControl allowlist.

2. Request capture.
   - Result: AppLocker blocked-launch events and child-side manual request form
     both create the same request object.
   - Gate: event parser tests pass; no live EventLog/AppLocker read in Codex.

3. Activity accounting.
   - Result: Guard records active foreground app, title, category and input
     activity without recording typed text. For known browsers it also tries to
     record the active domain through Windows UI Automation.
   - Gate: tests prove idle time is not counted as active use and site activity
     is normalized as `site:domain`.

4. Categories and limits.
   - Result: applications/sites can be grouped as study, video, game,
     useful-training, communication or system; limits apply per category.
   - Gate: time-budget tests cover daily limit, session limit, app limits and
     site limits.

5. Site/domain requests and timed grants.
   - Result: child can request a blocked domain; parent can approve temporarily
     or always; temporary grants expire and domain rules are rebuilt.
   - Gate: domain validation, request approval, grant filtering and expiry
     tests pass.

6. Tasks and rewards.
   - Result: parent defines daily tasks; verified app activity or child
     self-report can grant extra time within parent-set caps.
   - Gate: reward cannot exceed daily cap; verified tasks require real active
     app/input time.

7. Child account hardening.
   - Result: parent cabinet lets Ivan choose the child Windows user, shows
     administrator status, and offers guarded conversion to standard user only
     when a separate parent admin account exists.
   - Gate: local admin query and demotion command are tested through
     `ISystemCommandRunner`; no live account changes in Codex.

8. Release gate.
   - Result: Release build, `Guard.Tests`, `git diff --check`, docs and
     installer build pass.
   - Gate: installer is compiled only; live test requires Ivan approval.
