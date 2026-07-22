using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using Guard;

namespace Guard.Tests
{
    internal static class Program
    {
        private static int _failures;

        private static int Main()
        {
            Run("validates PINs", TestPins);
            Run("enforces emergency PIN policy", TestEmergencyPinPolicy);
            Run("validates domains", TestDomains);
            Run("validates IP addresses", TestIps);
            Run("parses instruction JSON", TestInstructionsParser);
            Run("converts preset-backed custom URL rules", TestRuleParser);
            Run("routes system commands through injectable runner", TestSystemCommandRunner);
            Run("removes only matching firewall rules through command runner", TestFirewallRuleCleanupUsesRunner);
            Run("creates short expiring pairing codes", TestPairingCodes);
            Run("applies parent commands to Guard state", TestParentCommands);
            Run("applies UI language command", TestUiLanguageCommand);
            Run("hashes and verifies parent admin passwords", TestParentAdminAuth);
            Run("expires parent admin sessions and marks sensitive actions", TestParentAdminSecurity);
            Run("ignores remote PIN updates", TestRemotePinUpdatesDoNotChangeLocalPin);
            Run("keeps local parent mode offline", TestLocalParentModeSkipsRemoteUpdater);
            Run("keeps legacy remote server disabled by default", TestLegacyRemoteServerDisabledByDefault);
            Run("applies application control commands", TestApplicationControlCommands);
            Run("handles application access requests", TestApplicationAccessRequests);
            Run("handles website access requests and grants", TestWebsiteAccessRequests);
            Run("enforces website default deny requests", TestWebsiteDefaultDenyRequests);
            Run("parses AppLocker blocked app events", TestAppLockerBlockedEventParser);
            Run("records active app usage without counting idle time", TestActivityAccounting);
            Run("records site activity and applies site limits", TestSiteActivityAndLimits);
            Run("enforces time limits in app allowlist decisions", TestTimeLimits);
            Run("handles daily tasks and reward minutes", TestDailyTasksAndRewards);
            Run("guards child administrator demotion", TestAccountHardening);
            Run("warns and expires temporary applications", TestApplicationControlRuntime);
            Run("builds application control policy paths", TestApplicationControlPolicyPaths);
            Run("builds default-deny AppLocker policy script", TestApplicationControlPolicyScript);
            Run("detects stale application control policy schema", TestApplicationControlPolicyApplyNeed);
            Run("counts down all final warning minutes", TestApplicationControlCountdownWarnings);
            Run("handles maintenance mode pause and restore", TestMaintenanceMode);
            Run("controls Task Manager access from parent commands", TestTaskManagerAccessCommands);
            Run("handles application control runtime edge cases", TestApplicationControlRuntimeEdgeCases);
            Run("describes Task Manager status safely", TestTaskManagerStatusDescription);

            if (_failures == 0)
            {
                Console.WriteLine("All Guard.Tests checks passed.");
                return 0;
            }

            Console.WriteLine($"{_failures} Guard.Tests check(s) failed.");
            return 1;
        }

        private static void Run(string name, Action test)
        {
            try
            {
                test();
                Console.WriteLine($"PASS {name}");
            }
            catch (Exception ex)
            {
                _failures++;
                Console.WriteLine($"FAIL {name}: {ex.Message}");
            }
        }

        private static void TestPins()
        {
            Assert(InputSanitizer.IsValidPin("123456"), "six digits should be valid");
            Assert(!InputSanitizer.IsValidPin("12345"), "short PIN should be invalid");
            Assert(!InputSanitizer.IsValidPin("abcdef"), "letters should be invalid");
            Assert(!InputSanitizer.IsValidPin(null), "null PIN should be invalid");
        }

        private static void TestEmergencyPinPolicy()
        {
            Assert(EmergencyPinPolicy.GetEffectivePin("") == EmergencyPinPolicy.TemporaryDefaultPin, "empty stored PIN should use temporary default");
            Assert(EmergencyPinPolicy.GetEffectivePin(null) == EmergencyPinPolicy.TemporaryDefaultPin, "null stored PIN should use temporary default");
            Assert(EmergencyPinPolicy.GetEffectivePin("654321") == "654321", "custom stored PIN should be effective");
            Assert(EmergencyPinPolicy.IsTemporaryDefault(""), "empty PIN should be reported as temporary default");
            Assert(EmergencyPinPolicy.IsTemporaryDefault("123456"), "default PIN should be reported as temporary default");
            Assert(!EmergencyPinPolicy.IsTemporaryDefault("654321"), "custom PIN should not be reported as temporary default");
            Assert(!EmergencyPinPolicy.IsAllowedCustomPin("123456"), "temporary default should not be allowed as custom PIN");
            Assert(EmergencyPinPolicy.IsAllowedCustomPin("654321"), "non-default six digit PIN should be allowed");
        }

        private static void TestDomains()
        {
            Assert(InputSanitizer.IsValidDomainName("youtube.com"), "basic domain should be valid");
            Assert(InputSanitizer.IsValidDomainName("sub.example-site.org"), "subdomain with hyphen should be valid");
            Assert(!InputSanitizer.IsValidDomainName("bad.com & del"), "shell metacharacters should be invalid");
            Assert(!InputSanitizer.IsValidDomainName(new string('a', 256)), "overlong domain should be invalid");
        }

        private static void TestIps()
        {
            Assert(InputSanitizer.IsValidIpAddress("192.168.1.1"), "IPv4 should be valid");
            Assert(InputSanitizer.IsValidIpAddress("192.168.0.0/24"), "IPv4 CIDR should be valid");
            Assert(!InputSanitizer.IsValidIpAddress("192.168.0.0/99"), "invalid CIDR should be rejected");
            Assert(!InputSanitizer.IsValidIpAddress("not-an-ip"), "plain text should be rejected");
        }

        private static void TestInstructionsParser()
        {
            const string json = "{\"restrictedCategoryIds\":\"1.2\",\"rules\":[{\"id\":\"r1\",\"type\":\"custom_url\",\"value\":\"youtube.com\",\"schedule\":\"1\"}],\"presets\":[],\"restrictedCategories\":[]}";
            var parsed = InstructionsParser.Parse(json);
            Assert(parsed != null, "valid instructions should parse");
            Assert(parsed!.Rules.Count == 1, "one rule should parse");
            Assert(InstructionsParser.Parse("{not json") == null, "invalid JSON should return null");
        }

        private static void TestRuleParser()
        {
            var state = new GuardState
            {
                Presets = new List<Preset>
                {
                    new Preset
                    {
                        Url = "youtube.com",
                        Domains = "youtube.com|googlevideo.com",
                        Ips = "203.0.113.10"
                    }
                }
            };

            var rule = new InstructionRule
            {
                Id = "rule-1",
                Type = "custom_url",
                Value = "youtube.com",
                Schedule = "1"
            };

            var parsed = RuleParser.ConvertRuleToParsedRule(rule, state);
            Assert(parsed.RuleId == "rule-1", "rule ID should be preserved");
            Assert(parsed.Urls.Contains("youtube.com"), "original URL should be included");
            Assert(parsed.Urls.Contains("googlevideo.com"), "preset domains should be expanded");
            Assert(parsed.Ips.Contains("203.0.113.10"), "preset IPs should be expanded");
        }

        private static void TestSystemCommandRunner()
        {
            var runner = new RecordingCommandRunner();
            SystemCommandRunnerProvider.Current = runner;
            try
            {
                SystemCleaner.RunCmd("ipconfig /flushdns");
            }
            finally
            {
                SystemCommandRunnerProvider.Reset();
            }

            Assert(runner.Commands.Count == 1, "one command should be routed");
            Assert(runner.Commands[0].FileName == "cmd.exe", "RunCmd should use cmd.exe");
            Assert(runner.Commands[0].Arguments == "/c ipconfig /flushdns", "RunCmd should pass command through /c");
        }

        private static void TestFirewallRuleCleanupUsesRunner()
        {
            var runner = new RecordingCommandRunner
            {
                Output =
                    "Rule Name: GuardBlock-Cat\r\n" +
                    "Rule Name: OtherRule\r\n" +
                    "Rule Name: GuardBlock-Rules-Child\r\n"
            };
            SystemCommandRunnerProvider.Current = runner;
            try
            {
                SystemCleaner.RemoveFirewallRulesAsync(log: null, tag: "GuardBlock-Rules").GetAwaiter().GetResult();
            }
            finally
            {
                SystemCommandRunnerProvider.Reset();
            }

            Assert(runner.Commands.Count == 2, "show and delete commands should be routed");
            Assert(runner.Commands[0].FileName == "netsh", "first command should query netsh rules");
            Assert(runner.Commands[1].FileName == "cmd.exe", "delete command should go through RunCmd");
            Assert(runner.Commands[1].Arguments.Contains("GuardBlock-Rules-Child"), "matching rule should be deleted");
            Assert(!runner.Commands[1].Arguments.Contains("OtherRule"), "unmatched rule should not be deleted");
        }

        private static void TestPairingCodes()
        {
            var now = new DateTime(2026, 6, 6, 10, 0, 0, DateTimeKind.Utc);
            var pairing = PairingCodeService.StartPairing("Child laptop", now);

            Assert(pairing.Status == PairingStatus.WaitingForParent, "new pairing should wait for parent");
            Assert(pairing.GeneratedAtUtc == now, "generated timestamp should be stored");
            Assert(pairing.ExpiresAtUtc == now.Add(PairingCodeService.DefaultLifetime), "default expiration should be stored");
            Assert(PairingCodeService.IsValidCode(pairing.Code), "generated code should be valid");
            Assert(pairing.Code.Length == 9 && pairing.Code[4] == '-', "code should be formatted as ABCD-EFGH");
            Assert(PairingCodeService.NormalizeCode(" abcd-efgh ") == "ABCDEFGH", "normalization should ignore spaces and hyphen");
            Assert(PairingCodeService.FormatCode("ABCDEFGH") == "ABCD-EFGH", "formatting should add separator");
            Assert(PairingCodeService.IsExpired(pairing, now.AddMinutes(16)), "pairing should expire after default lifetime");
            Assert(!PairingCodeService.IsValidCode("O0I1-!!!!"), "confusing or invalid characters should be rejected");
        }

        private static void TestParentCommands()
        {
            var state = new GuardState { SyncStatus = false, PinCode = "123456" };

            var addResult = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.AddBlockedDomain,
                Value = " YouTube.com "
            });
            Assert(addResult.Changed, "adding a valid domain should change state");
            Assert(state.Rules.Count == 1, "domain command should add one rule");
            Assert(state.Rules[0].Id == ParentCommandApplier.BuildDomainRuleId("youtube.com"), "rule ID should be stable");
            Assert(state.Rules[0].Value == "youtube.com", "domain should be normalized");
            Assert(state.UpdateInfo.Rules, "rule update flag should be set");
            Assert(!state.UpdateInfo.UpdateApplied, "update should be marked unapplied");

            var duplicateResult = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.AddBlockedDomain,
                Value = "youtube.com"
            });
            Assert(!duplicateResult.Changed, "adding the same domain twice should be idempotent");
            Assert(state.Rules.Count == 1, "duplicate domain should not create another rule");

            var invalidResult = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.AddBlockedDomain,
                Value = "youtube.com & del"
            });
            Assert(!invalidResult.Changed, "invalid domain should not change state");
            Assert(!string.IsNullOrEmpty(invalidResult.Error), "invalid domain should report an error");

            var syncResult = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetSyncStatus,
                BoolValue = true
            });
            Assert(syncResult.Changed, "sync command should change state");
            Assert(state.SyncStatus, "sync should be enabled");
            Assert(state.UpdateInfo.SyncStatUpdate, "sync update flag should be set");

            var pinResult = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetEmergencyPin,
                Value = "654321"
            });
            Assert(pinResult.Changed, "PIN command should change state");
            Assert(state.PinCode == "654321", "PIN should be updated");

            var defaultPinResult = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetEmergencyPin,
                Value = EmergencyPinPolicy.TemporaryDefaultPin
            });
            Assert(!defaultPinResult.Changed, "default PIN should not be accepted as custom PIN");
            Assert(!string.IsNullOrEmpty(defaultPinResult.Error), "default PIN rejection should explain the error");
            Assert(state.PinCode == "654321", "rejected default PIN should not overwrite the custom PIN");

            var removeResult = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.RemoveBlockedDomain,
                Value = "youtube.com"
            });
            Assert(removeResult.Changed, "remove command should change state");
            Assert(state.Rules.Count == 0, "domain rule should be removed");
        }

        private static void TestUiLanguageCommand()
        {
            var state = new GuardState();
            Assert(state.UiLanguage == UiLanguage.Russian, "new state should default to Russian UI");

            var english = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetUiLanguage,
                Value = "en"
            });
            Assert(english.Changed, "language command should change state");
            Assert(state.UiLanguage == UiLanguage.English, "English language should be stored");

            var duplicate = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetUiLanguage,
                Value = "en"
            });
            Assert(!duplicate.Changed, "setting the same language should be idempotent");

            var fallback = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetUiLanguage,
                Value = "de"
            });
            Assert(fallback.Changed, "unknown languages should normalize to Russian");
            Assert(state.UiLanguage == UiLanguage.Russian, "unknown language should fall back to Russian");
        }

        private static void TestParentAdminAuth()
        {
            var state = new GuardState();
            Assert(!ParentAdminAuth.IsConfigured(state), "new state should not have parent auth configured");
            Assert(!ParentAdminAuth.SetPassword(state, "short"), "short password should be rejected");

            Assert(ParentAdminAuth.SetPassword(state, "correct horse battery staple"), "strong password should be accepted");
            Assert(ParentAdminAuth.IsConfigured(state), "state should be configured after password setup");
            Assert(!string.IsNullOrWhiteSpace(state.ParentAdminPasswordHash), "password hash should be stored");
            Assert(!string.IsNullOrWhiteSpace(state.ParentAdminPasswordSalt), "password salt should be stored");
            Assert(!state.ParentAdminPasswordHash.Contains("correct"), "raw password should not be stored");
            Assert(ParentAdminAuth.VerifyPassword(state, "correct horse battery staple"), "correct password should verify");
            Assert(!ParentAdminAuth.VerifyPassword(state, "wrong horse battery staple"), "wrong password should fail");
        }

        private static void TestParentAdminSecurity()
        {
            var now = new DateTime(2026, 6, 7, 9, 0, 0, DateTimeKind.Utc);
            var store = new ParentAdminSessionStore();
            store.Add("token-1", now);

            Assert(store.IsValid("token-1", now.AddMinutes(4).AddSeconds(59)), "session should be valid before timeout");
            Assert(!store.IsValid("token-1", now.AddMinutes(5)), "session should expire at timeout");
            Assert(!store.IsValid("token-1", now.AddMinutes(6)), "expired session should stay removed");

            store.Add("token-2", now);
            store.Renew("token-2", now.AddMinutes(4));
            Assert(store.IsValid("token-2", now.AddMinutes(8).AddSeconds(59)), "renewed session should stay valid");
            Assert(!store.IsValid("token-2", now.AddMinutes(9)), "renewed session should expire after the renewed timeout");

            Assert(ParentAdminSecurityPolicy.RequiresParentPassword("start-maintenance"), "maintenance should require parent password");
            Assert(ParentAdminSecurityPolicy.RequiresParentPassword("approve-request-always"), "permanent approvals should require parent password");
            Assert(ParentAdminSecurityPolicy.RequiresParentPassword("app-control-off"), "turning app control off should require parent password");
            Assert(ParentAdminSecurityPolicy.RequiresParentPassword("sync-off"), "pausing blocking should require parent password");
            Assert(ParentAdminSecurityPolicy.RequiresParentPassword("set-daily-screen-limit"), "changing time limits should require parent password");
            Assert(!ParentAdminSecurityPolicy.RequiresParentPassword("set-language"), "language change should not require step-up auth");
            Assert(!ParentAdminSecurityPolicy.RequiresParentPassword("deny-request"), "denying a request should not need step-up auth");
            Assert(!ParentAdminSecurityPolicy.RequiresParentPassword("end-maintenance"), "ending maintenance should stay quick");
        }

        private static void TestLocalParentModeSkipsRemoteUpdater()
        {
            var state = new GuardState
            {
                Assigned = true,
                LocalParentMode = true,
                AssignCode = "LOCALTEST"
            };
            var logs = new List<string>();

            DeviceUpdater.SendDeviceUpdateAsync(state, logs.Add).GetAwaiter().GetResult();

            Assert(logs.Exists(log => log.Contains("remote update skipped")), "local mode should skip remote updater");
        }

        private static void TestRemotePinUpdatesDoNotChangeLocalPin()
        {
            var state = new GuardState { PinCode = "654321" };
            var logs = new List<string>();

            var changed = DeviceUpdater.ApplyRemotePinCodeIfAllowed(state, "111222", logs.Add);

            Assert(!changed, "remote PIN updates should be rejected");
            Assert(state.PinCode == "654321", "remote PIN should not overwrite the local PIN");
            Assert(logs.Exists(log => log.Contains("Ignored remote PIN update")), "remote PIN rejection should be logged");
        }

        private static void TestLegacyRemoteServerDisabledByDefault()
        {
            var state = new GuardState
            {
                Assigned = true,
                AssignCode = "LEGACYTEST"
            };
            var logs = new List<string>();

            DeviceUpdater.SendDeviceUpdateAsync(state, logs.Add).GetAwaiter().GetResult();

            Assert(!state.AllowLegacyRemoteServer, "legacy remote server should be disabled by default");
            Assert(logs.Exists(log => log.Contains("Legacy remote server mode is disabled")), "legacy remote updater should be skipped");
        }

        private static void TestApplicationControlCommands()
        {
            var state = new GuardState();

            var mode = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetApplicationControlMode,
                Value = "audit"
            });
            Assert(mode.Changed, "mode should change");
            Assert(state.AppControl.Mode == ApplicationControlMode.AuditOnly, "audit mode should be stored");
            Assert(state.AppControl.PolicyUpdatePending, "policy update should be marked pending");

            var add = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.AddAllowedApplication,
                Value = @"C:\Games\Minecraft\Minecraft.exe",
                DisplayName = "Minecraft"
            });
            Assert(add.Changed, "allowed app should be added");
            Assert(state.AppControl.AllowedApplications.Count == 1, "one app should be stored");
            Assert(state.AppControl.AllowedApplications[0].DisplayName == "Minecraft", "display name should be stored");

            var grant = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.GrantTemporaryApplication,
                Value = @"C:\Games\Roblox\Roblox.exe",
                DisplayName = "Roblox",
                IntValue = 60
            });
            Assert(grant.Changed, "temporary grant should be added");
            Assert(state.AppControl.AllowedApplications.Count == 2, "temporary app should be stored");
            Assert(state.AppControl.AllowedApplications[1].AllowedUntilUtc.HasValue, "temporary grant should have expiration");

            var invalid = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.AddAllowedApplication,
                Value = "minecraft.bat",
                DisplayName = "Bad"
            });
            Assert(!invalid.Changed, "invalid path should not change state");
            Assert(!string.IsNullOrEmpty(invalid.Error), "invalid path should report error");

            var remove = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.RemoveAllowedApplication,
                Value = @"C:\Games\Minecraft\Minecraft.exe"
            });
            Assert(remove.Changed, "allowed app should be removed");
            Assert(state.AppControl.AllowedApplications.Count == 1, "one app should remain");
        }

        private static void TestApplicationAccessRequests()
        {
            var now = new DateTime(2026, 6, 7, 9, 0, 0, DateTimeKind.Utc);
            var state = new GuardState();
            var request = AccessRequestApplier.RequestApplication(
                state,
                @"C:\Downloads\DroneSim.exe",
                "Drone Simulator",
                "applocker",
                "Kirill",
                now);

            Assert(request.Changed, "new app request should change state");
            Assert(state.AccessRequests.Count == 1, "one access request should be stored");
            Assert(state.AccessRequests[0].Status == AccessRequestStatus.Pending, "new request should be pending");
            Assert(state.AccessRequests[0].AttemptCount == 1, "first request should have one attempt");

            var duplicate = AccessRequestApplier.RequestApplication(
                state,
                @"C:\Downloads\DroneSim.exe",
                "Drone Simulator",
                "applocker",
                "Kirill",
                now.AddMinutes(1));
            Assert(duplicate.Changed, "repeat request should update state");
            Assert(state.AccessRequests.Count == 1, "repeat request should not create duplicates");
            Assert(state.AccessRequests[0].AttemptCount == 2, "repeat request should increase attempt count");

            var requestId = state.AccessRequests[0].Id;
            var approveTemporary = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.ApproveAccessRequest,
                Value = requestId,
                IntValue = 15
            });
            Assert(approveTemporary.Changed, "temporary approval should change state");
            Assert(state.AccessRequests[0].Status == AccessRequestStatus.Approved, "request should be approved");
            Assert(state.AccessRequests[0].DecisionMinutes == 15, "temporary approval should store minutes");
            Assert(state.AppControl.AllowedApplications.Count == 1, "temporary approval should add allowed app");
            Assert(state.AppControl.AllowedApplications[0].AllowedUntilUtc.HasValue, "temporary approval should expire");
            Assert(state.AppControl.PolicyUpdatePending, "temporary approval should require policy update");

            var reRequest = AccessRequestApplier.RequestApplication(
                state,
                @"C:\Downloads\DroneSim.exe",
                "Drone Simulator",
                "applocker",
                "Kirill",
                now.AddMinutes(2));
            Assert(reRequest.Changed, "request after decision should reopen");
            Assert(state.AccessRequests[0].Status == AccessRequestStatus.Pending, "repeated decided request should become pending again");

            var deny = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.DenyAccessRequest,
                Value = requestId
            });
            Assert(deny.Changed, "denying request should change state");
            Assert(AccessRequestApplier.GetPendingRequests(state).Count == 0, "denied request should leave pending inbox");

            AccessRequestApplier.RequestApplication(
                state,
                @"C:\Program Files\Contour Talk\ContourTalk.exe",
                "Kontur Talk",
                "manual",
                "Kirill",
                now.AddMinutes(3));
            var secondRequestId = AccessRequestApplier.GetPendingRequests(state)[0].Id;
            var approveAlways = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.ApproveAccessRequest,
                Value = secondRequestId
            });
            Assert(approveAlways.Changed, "permanent approval should change state");
            Assert(state.AppControl.AllowedApplications.Exists(app => app.FilePath.EndsWith("ContourTalk.exe") && !app.AllowedUntilUtc.HasValue), "permanent approval should add non-expiring app");
        }

        private static void TestWebsiteAccessRequests()
        {
            var now = new DateTime(2026, 6, 7, 9, 0, 0, DateTimeKind.Utc);
            var state = new GuardState();

            var request = AccessRequestApplier.RequestWebsite(
                state,
                "https://www.vk.com/video?q=kids",
                "child-manual",
                "Kirill",
                now);
            Assert(request.Changed, "new website request should change state");
            Assert(state.AccessRequests.Count == 1, "one website request should be stored");
            Assert(state.AccessRequests[0].Type == AccessRequestType.Website, "request type should be website");
            Assert(state.AccessRequests[0].Target == "vk.com", "website request should normalize a pasted URL");

            var duplicate = AccessRequestApplier.RequestWebsite(
                state,
                "m.vk.com",
                "child-manual",
                "Kirill",
                now.AddMinutes(1));
            Assert(duplicate.Changed, "repeat website request should update state");
            Assert(state.AccessRequests.Count == 1, "repeat website request should not create duplicates");
            Assert(state.AccessRequests[0].AttemptCount == 2, "repeat website request should increase attempts");

            var invalid = AccessRequestApplier.RequestWebsite(
                state,
                "127.0.0.1",
                "child-manual",
                "Kirill",
                now);
            Assert(!invalid.Changed, "IP address should not be accepted as website access request");
            Assert(!string.IsNullOrWhiteSpace(invalid.Error), "invalid website request should return error");

            var requestId = AccessRequestApplier.GetPendingRequests(state)[0].Id;
            var approve = AccessRequestApplier.ApproveRequest(state, requestId, 15, now);
            Assert(approve.Changed, "website approval should change state");
            Assert(state.AccessRequests[0].Status == AccessRequestStatus.Approved, "website request should be approved");
            Assert(state.DomainAccessGrants.Count == 1, "website approval should store a grant");
            Assert(state.DomainAccessGrants[0].Domain == "vk.com", "grant domain should be normalized");
            Assert(state.DomainAccessGrants[0].AllowedUntilUtc == now.AddMinutes(15), "temporary grant should have expiration");
            Assert(state.UpdateInfo.Rules && state.UpdateInfo.Cats && !state.UpdateInfo.UpdateApplied, "website approval should require domain reapply");

            var filtered = DomainAccessGrantApplier.FilterBlockedDomains(
                new[] { "vk.com", "www.vk.com", "youtube.com" },
                state,
                now.AddMinutes(5));
            Assert(!filtered.Contains("vk.com"), "active grant should suppress exact blocked domain");
            Assert(!filtered.Contains("www.vk.com"), "active grant should suppress subdomain block");
            Assert(filtered.Contains("youtube.com"), "unrelated domains should remain blocked");

            var expiredSweep = DomainAccessGrantApplier.RemoveExpiredTemporaryGrants(state, now.AddMinutes(16));
            Assert(expiredSweep.Changed, "expired website grant should be removed");
            Assert(state.DomainAccessGrants.Count == 0, "expired grant should not remain active");

            AccessRequestApplier.RequestWebsite(state, "youtube.com", "manual", "Kirill", now.AddMinutes(17));
            var alwaysId = AccessRequestApplier.GetPendingRequests(state)[0].Id;
            var always = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.ApproveAccessRequest,
                Value = alwaysId
            });
            Assert(always.Changed, "permanent website approval should change state");
            Assert(state.DomainAccessGrants.Count == 1, "permanent grant should be stored");
            Assert(state.DomainAccessGrants[0].IsPermanent, "permanent grant should be marked permanent");
            Assert(!state.DomainAccessGrants[0].AllowedUntilUtc.HasValue, "permanent grant should not expire");

            var remove = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.RemoveWebsiteGrant,
                Value = "youtube.com"
            });
            Assert(remove.Changed, "parent should be able to revoke a website grant");
            Assert(state.DomainAccessGrants.Count == 0, "revoked website grant should be removed");
        }

        private static void TestWebsiteDefaultDenyRequests()
        {
            var now = new DateTime(2026, 6, 8, 9, 0, 0, DateTimeKind.Utc);
            var state = new GuardState
            {
                SyncStatus = true
            };

            Assert(WebsiteAccessPolicy.IsDefaultDenyActive(state, now), "web default deny should be enabled by default when blocking is active");
            Assert(WebsiteAccessPolicy.ShouldBlockWebsite(state, "youtube.com", now), "unknown site should be blocked by default");

            var markBlocked = WebsiteAccessPolicy.EnsureDefaultDeniedDomainRule(state, "https://www.youtube.com/watch?v=1");
            Assert(markBlocked.Changed, "default-deny site should create a hidden block rule");
            Assert(state.Rules.Exists(rule => rule.Id == WebsiteAccessPolicy.BuildDefaultDenyRuleId("youtube.com")), "hidden default-deny rule should be stored");
            Assert(state.UpdateInfo.Rules && !state.UpdateInfo.UpdateApplied, "hidden block rule should require rules reapply");

            var request = AccessRequestApplier.RequestWebsite(state, "youtube.com", "browser", "Kirill", now);
            Assert(request.Changed, "default-denied site request should be stored");
            Assert(state.AccessRequests.Count == 1, "one site request should be pending");
            Assert(state.Rules.Count(rule => rule.Id == WebsiteAccessPolicy.BuildDefaultDenyRuleId("youtube.com")) == 1, "repeated request should not duplicate hidden block rule");

            var approve = AccessRequestApplier.ApproveRequest(state, state.AccessRequests[0].Id, 60, now);
            Assert(approve.Changed, "parent approval should change state");
            Assert(WebsiteAccessPolicy.IsWebsiteAllowed(state, "www.youtube.com", now.AddMinutes(10)), "approved site should be allowed");
            Assert(!WebsiteAccessPolicy.ShouldBlockWebsite(state, "youtube.com", now.AddMinutes(10)), "approved site should no longer be blocked");

            var blocked = DomainAccessGrantApplier.FilterBlockedDomains(new[] { "youtube.com", "vk.com" }, state, now.AddMinutes(10));
            Assert(!blocked.Contains("youtube.com"), "approved default-deny domain should be suppressed from block rules");
            Assert(blocked.Contains("vk.com"), "unapproved domain should remain blocked");
        }

        private static void TestAppLockerBlockedEventParser()
        {
            Assert(AppLockerBlockedEventParser.IsRequestWorthyEventId(8003), "audit event should be request-worthy");
            Assert(AppLockerBlockedEventParser.IsRequestWorthyEventId(8004), "deny event should be request-worthy");
            Assert(!AppLockerBlockedEventParser.IsRequestWorthyEventId(8002), "allow event should not create request");

            var propertyResult = AppLockerBlockedEventParser.TryExtractExecutablePath(
                new[] { "not a path", @"C:\Downloads\PortableBrowser.exe" },
                "",
                out var propertyPath);
            Assert(propertyResult, "parser should extract path from event properties");
            Assert(propertyPath == @"C:\Downloads\PortableBrowser.exe", "property path should be preserved");

            var descriptionResult = AppLockerBlockedEventParser.TryExtractExecutablePath(
                Array.Empty<string>(),
                "AppLocker prevented C:\\Games\\Drone Sim\\DroneSim.exe from running.",
                out var descriptionPath);
            Assert(descriptionResult, "parser should extract path from event description");
            Assert(descriptionPath == @"C:\Games\Drone Sim\DroneSim.exe", "description path should be preserved");
        }

        private static void TestActivityAccounting()
        {
            var state = new GuardState();
            var categorize = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetApplicationCategory,
                Value = @"C:\Program Files\Contour Talk\ContourTalk.exe",
                DisplayName = "Kontur Talk",
                ActivityCategory = ActivityCategory.Study,
                BoolValue = true
            });
            Assert(categorize.Changed, "category command should change state");

            var start = new DateTime(2026, 6, 7, 10, 0, 0, DateTimeKind.Utc);
            ActivityAccountingEngine.RecordSnapshot(state, new ActivitySnapshot
            {
                TimestampUtc = start,
                ForegroundFilePath = @"C:\Program Files\Contour Talk\ContourTalk.exe",
                ForegroundTitle = "Lesson",
                DisplayName = "Kontur Talk",
                IdleSeconds = 0
            });
            ActivityAccountingEngine.RecordSnapshot(state, new ActivitySnapshot
            {
                TimestampUtc = start.AddSeconds(30),
                ForegroundFilePath = @"C:\Program Files\Contour Talk\ContourTalk.exe",
                ForegroundTitle = "Lesson",
                DisplayName = "Kontur Talk",
                IdleSeconds = 0
            });
            ActivityAccountingEngine.RecordSnapshot(state, new ActivitySnapshot
            {
                TimestampUtc = start.AddSeconds(60),
                ForegroundFilePath = @"C:\Program Files\Contour Talk\ContourTalk.exe",
                ForegroundTitle = "Lesson",
                DisplayName = "Kontur Talk",
                IdleSeconds = 120
            });
            ActivityAccountingEngine.RecordSnapshot(state, new ActivitySnapshot
            {
                TimestampUtc = start.AddSeconds(90),
                ForegroundFilePath = @"C:\Program Files\Contour Talk\ContourTalk.exe",
                ForegroundTitle = "Lesson",
                DisplayName = "Kontur Talk",
                IdleSeconds = 0
            });

            var usage = ActivityAccountingEngine.GetTodayUsage(state, start);
            Assert(usage.Count == 1, "one app usage entry should be stored");
            Assert(usage[0].ActiveSeconds == 60, "idle interval should not be counted");
            Assert(usage[0].Category == ActivityCategory.Study, "usage should keep configured category");
            Assert(!usage[0].DisplayName.Contains("Lesson"), "window title should not replace app display name");
        }

        private static void TestSiteActivityAndLimits()
        {
            var now = new DateTime(2026, 6, 7, 10, 0, 0, DateTimeKind.Utc);
            var state = new GuardState();
            var categorize = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetSiteCategory,
                Value = "https://www.vk.com/video",
                DisplayName = "VK Video",
                ActivityCategory = ActivityCategory.Video,
                BoolValue = true
            });
            Assert(categorize.Changed, "site category command should change state");
            Assert(state.ActivitySettings.SiteRules.Count == 1, "site rule should be stored");
            Assert(state.ActivitySettings.SiteRules[0].Domain == "vk.com", "site rule should normalize pasted URL");

            ActivityAccountingEngine.RecordSnapshot(state, new ActivitySnapshot
            {
                TimestampUtc = now,
                ForegroundFilePath = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                ForegroundDomain = "www.vk.com",
                DisplayName = "Chrome",
                IdleSeconds = 0
            });
            ActivityAccountingEngine.RecordSnapshot(state, new ActivitySnapshot
            {
                TimestampUtc = now.AddSeconds(60),
                ForegroundFilePath = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                ForegroundDomain = "m.vk.com",
                DisplayName = "Chrome",
                IdleSeconds = 0
            });

            var usage = ActivityAccountingEngine.GetTodayUsage(state, now);
            Assert(usage.Count == 1, "site usage should be stored as one normalized domain entry");
            Assert(usage[0].FilePath == ActivityAccountingEngine.BuildSiteActivityKey("vk.com"), "site usage key should be stable");
            Assert(usage[0].DisplayName == "VK Video", "site usage should use configured display name");
            Assert(usage[0].Category == ActivityCategory.Video, "site usage should keep configured category");
            Assert(usage[0].ActiveSeconds == 60, "site active time should be counted");

            ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetCategoryTimeLimit,
                ActivityCategory = ActivityCategory.Video,
                IntValue = 1
            });
            DomainAccessGrantApplier.GrantWebsite(state, "vk.com", "VK Video", minutes: null, sourceRequestId: "", utcNow: now);

            Assert(!TimeLimitEngine.IsWebsiteAllowedByTimeLimits(state, "vk.com", now.AddSeconds(60)), "site should be disallowed after category limit");
            var filtered = DomainAccessGrantApplier.FilterBlockedDomains(new[] { "vk.com", "youtube.com" }, state, now.AddSeconds(60));
            Assert(filtered.Contains("vk.com"), "over-limit grant should no longer suppress blocked domain");
            Assert(filtered.Contains("youtube.com"), "unrelated blocked domain should remain");

            var sessionState = new GuardState();
            ParentCommandApplier.Apply(sessionState, new ParentCommand
            {
                Type = ParentCommandType.SetSiteCategory,
                Value = "drone-sim.example.com",
                DisplayName = "Drone site",
                ActivityCategory = ActivityCategory.UsefulTraining,
                BoolValue = true
            });
            ParentCommandApplier.Apply(sessionState, new ParentCommand
            {
                Type = ParentCommandType.SetCategoryTimeLimit,
                ActivityCategory = ActivityCategory.UsefulTraining,
                IntValue = 0,
                Schedule = "1"
            });
            ActivityAccountingEngine.RecordSnapshot(sessionState, new ActivitySnapshot
            {
                TimestampUtc = now,
                ForegroundFilePath = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                ForegroundDomain = "drone-sim.example.com",
                DisplayName = "Chrome",
                IdleSeconds = 0
            });
            ActivityAccountingEngine.RecordSnapshot(sessionState, new ActivitySnapshot
            {
                TimestampUtc = now.AddSeconds(60),
                ForegroundFilePath = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                ForegroundDomain = "drone-sim.example.com",
                DisplayName = "Chrome",
                IdleSeconds = 0
            });
            Assert(!TimeLimitEngine.IsWebsiteAllowedByTimeLimits(sessionState, "drone-sim.example.com", now.AddSeconds(60)), "site should be disallowed after session limit");
        }

        private static void TestTimeLimits()
        {
            var now = new DateTime(2026, 6, 7, 10, 0, 0, DateTimeKind.Utc);
            var state = new GuardState();
            ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.AddAllowedApplication,
                Value = @"C:\Video\VkVideo.exe",
                DisplayName = "VK Video"
            });
            ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetApplicationCategory,
                Value = @"C:\Video\VkVideo.exe",
                DisplayName = "VK Video",
                ActivityCategory = ActivityCategory.Video,
                BoolValue = true
            });
            var limit = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetCategoryTimeLimit,
                ActivityCategory = ActivityCategory.Video,
                IntValue = 1
            });
            Assert(limit.Changed, "category limit should change state");

            state.ActivityUsage.Add(new ActivityUsageEntry
            {
                Date = "2026-06-07",
                FilePath = @"C:\Video\VkVideo.exe",
                DisplayName = "VK Video",
                Category = ActivityCategory.Video,
                CountsAsScreenTime = true,
                ActiveSeconds = 60,
                LastSeenUtc = now
            });

            Assert(!TimeLimitEngine.IsApplicationAllowedByTimeLimits(state, @"C:\Video\VkVideo.exe", now), "app should be disallowed after category limit");
            var allowedPaths = ApplicationControlPolicyManager.BuildAllowedPaths(state, @"C:\Program Files\Guard\guard.exe", now);
            Assert(!ContainsPath(allowedPaths, @"C:\Video\VkVideo.exe"), "over-limit app should be excluded from allowlist");

            var sessionState = new GuardState();
            ParentCommandApplier.Apply(sessionState, new ParentCommand
            {
                Type = ParentCommandType.SetApplicationCategory,
                Value = @"C:\Games\DroneSim.exe",
                DisplayName = "Drone Sim",
                ActivityCategory = ActivityCategory.UsefulTraining,
                BoolValue = true
            });
            ParentCommandApplier.Apply(sessionState, new ParentCommand
            {
                Type = ParentCommandType.SetCategoryTimeLimit,
                ActivityCategory = ActivityCategory.UsefulTraining,
                IntValue = 0,
                Schedule = "1"
            });

            ActivityAccountingEngine.RecordSnapshot(sessionState, new ActivitySnapshot
            {
                TimestampUtc = now,
                ForegroundFilePath = @"C:\Games\DroneSim.exe",
                DisplayName = "Drone Sim",
                IdleSeconds = 0
            });
            ActivityAccountingEngine.RecordSnapshot(sessionState, new ActivitySnapshot
            {
                TimestampUtc = now.AddSeconds(60),
                ForegroundFilePath = @"C:\Games\DroneSim.exe",
                DisplayName = "Drone Sim",
                IdleSeconds = 0
            });
            Assert(!TimeLimitEngine.IsApplicationAllowedByTimeLimits(sessionState, @"C:\Games\DroneSim.exe", now.AddSeconds(60)), "app should be disallowed after session limit");
        }

        private static void TestDailyTasksAndRewards()
        {
            var now = new DateTime(2026, 6, 7, 10, 0, 0, DateTimeKind.Utc);
            var state = new GuardState();
            ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetApplicationCategory,
                Value = @"C:\Games\Game.exe",
                DisplayName = "Game",
                ActivityCategory = ActivityCategory.Game,
                BoolValue = true
            });
            ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.SetCategoryTimeLimit,
                ActivityCategory = ActivityCategory.Game,
                IntValue = 60
            });
            state.ActivityUsage.Add(new ActivityUsageEntry
            {
                Date = "2026-06-07",
                FilePath = @"C:\Games\Game.exe",
                DisplayName = "Game",
                Category = ActivityCategory.Game,
                CountsAsScreenTime = true,
                ActiveSeconds = 60 * 60,
                LastSeenUtc = now
            });
            Assert(!TimeLimitEngine.IsApplicationAllowedByTimeLimits(state, @"C:\Games\Game.exe", now), "game should be blocked at base limit");

            var addTask = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.AddDailyTask,
                DisplayName = "10 squats",
                DailyTaskType = DailyTaskType.SelfReport,
                Schedule = "15",
                RewardCategory = ActivityCategory.Game
            });
            Assert(addTask.Changed, "self-report task should be added");
            var complete = DailyTaskEngine.CompleteTask(state, state.DailyTasks[0].Id, "child", now);
            Assert(complete.Changed, "self-report task should complete");
            Assert(TimeLimitEngine.IsApplicationAllowedByTimeLimits(state, @"C:\Games\Game.exe", now), "reward should extend game limit");

            var duplicate = DailyTaskEngine.CompleteTask(state, state.DailyTasks[0].Id, "child", now);
            Assert(!string.IsNullOrEmpty(duplicate.Error), "same task should not complete twice in one day");

            var verifiedState = new GuardState();
            var addVerified = ParentCommandApplier.Apply(verifiedState, new ParentCommand
            {
                Type = ParentCommandType.AddDailyTask,
                DisplayName = "Drone simulator",
                DailyTaskType = DailyTaskType.VerifiedApplicationTime,
                Value = @"C:\Games\DroneSim.exe",
                ActivityCategory = ActivityCategory.UsefulTraining,
                IntValue = 15,
                Schedule = "10",
                RewardCategory = ActivityCategory.Game
            });
            Assert(addVerified.Changed, "verified task should be added");
            var tooEarly = ParentCommandApplier.Apply(verifiedState, new ParentCommand
            {
                Type = ParentCommandType.CompleteDailyTask,
                Value = verifiedState.DailyTasks[0].Id,
                DisplayName = "child"
            });
            Assert(!string.IsNullOrEmpty(tooEarly.Error), "verified task should require active app time");
            verifiedState.ActivityUsage.Add(new ActivityUsageEntry
            {
                Date = "2026-06-07",
                FilePath = @"C:\Games\DroneSim.exe",
                DisplayName = "Drone simulator",
                Category = ActivityCategory.UsefulTraining,
                CountsAsScreenTime = true,
                ActiveSeconds = 15 * 60,
                LastSeenUtc = now
            });
            var verifiedComplete = DailyTaskEngine.CompleteTask(verifiedState, verifiedState.DailyTasks[0].Id, "child", now);
            Assert(verifiedComplete.Changed, "verified task should complete after enough active time");
            Assert(verifiedState.BonusTimeGrants.Count == 1, "verified task should grant bonus time");
        }

        private static void TestAccountHardening()
        {
            var safeStatus = AccountHardeningEngine.BuildStatus(
                "Kirill",
                childIsAdministrator: true,
                administratorUsers: new[] { "Kirill", "ParentAdmin" });
            Assert(safeStatus.CanDemoteChild, "child can be demoted only with a separate admin");

            var runner = new RecordingCommandRunner();
            SystemCommandRunnerProvider.Current = runner;
            try
            {
                var demote = AccountHardeningEngine.DemoteChildFromAdministrators(safeStatus);
                Assert(demote.Changed, "safe demotion should run command");
            }
            finally
            {
                SystemCommandRunnerProvider.Reset();
            }

            Assert(runner.Commands.Count == 1, "one demotion command should be routed");
            Assert(runner.Commands[0].FileName == "net.exe", "demotion should use net.exe");
            Assert(runner.Commands[0].Arguments.Contains("\"Kirill\" /delete"), "demotion should remove child from Administrators");

            var unsafeStatus = AccountHardeningEngine.BuildStatus(
                "Kirill",
                childIsAdministrator: true,
                administratorUsers: new[] { "Kirill" });
            Assert(!unsafeStatus.CanDemoteChild, "child should not be demoted without separate admin");
            var unsafeDemote = AccountHardeningEngine.DemoteChildFromAdministrators(unsafeStatus);
            Assert(!string.IsNullOrEmpty(unsafeDemote.Error), "unsafe demotion should return an error");

            var parsed = AccountHardeningEngine.ParseLocalGroupUsers(
                "Alias name Administrators\r\n" +
                "-------------------------------------------------------------------------------\r\n" +
                "Kirill\r\n" +
                "ParentAdmin\r\n" +
                "The command completed successfully.\r\n");
            Assert(parsed.Count == 2 && parsed[0] == "Kirill" && parsed[1] == "ParentAdmin", "localgroup users should parse");

            var statusRunner = new RecordingCommandRunner
            {
                Output =
                    "Alias name Administrators\r\n" +
                    "-------------------------------------------------------------------------------\r\n" +
                    @"PC\Kirill" + "\r\n" +
                    @"PC\ParentAdmin" + "\r\n" +
                    "The command completed successfully.\r\n"
            };
            SystemCommandRunnerProvider.Current = statusRunner;
            try
            {
                var localStatus = AccountHardeningEngine.BuildLocalStatus("Kirill");
                Assert(localStatus.CanDemoteChild, "local status should match child by leaf account name");
                Assert(localStatus.AdministratorUsers.Count == 2, "local status should include parsed admin users");
            }
            finally
            {
                SystemCommandRunnerProvider.Reset();
            }

            var onlyChildRunner = new RecordingCommandRunner
            {
                Output =
                    "Alias name Administrators\r\n" +
                    "-------------------------------------------------------------------------------\r\n" +
                    @"PC\Kirill" + "\r\n" +
                    "The command completed successfully.\r\n"
            };
            SystemCommandRunnerProvider.Current = onlyChildRunner;
            try
            {
                var localUnsafeStatus = AccountHardeningEngine.BuildLocalStatus("Kirill");
                Assert(!localUnsafeStatus.CanDemoteChild, "leaf-name match should not count child as separate admin");
            }
            finally
            {
                SystemCommandRunnerProvider.Reset();
            }

            var commandState = new GuardState();
            var setUser = ParentCommandApplier.Apply(commandState, new ParentCommand
            {
                Type = ParentCommandType.SetChildWindowsUser,
                Value = "Kirill"
            });
            Assert(setUser.Changed && commandState.ChildWindowsUserName == "Kirill", "parent command should store selected child Windows user");

            var commandRunner = new RecordingCommandRunner
            {
                Output =
                    "Alias name Administrators\r\n" +
                    "-------------------------------------------------------------------------------\r\n" +
                    "Kirill\r\n" +
                    "ParentAdmin\r\n" +
                    "The command completed successfully.\r\n"
            };
            SystemCommandRunnerProvider.Current = commandRunner;
            try
            {
                var demoteCommand = ParentCommandApplier.Apply(commandState, new ParentCommand
                {
                    Type = ParentCommandType.DemoteChildWindowsUser
                });
                Assert(demoteCommand.Changed, "parent demotion command should run when status is safe");
            }
            finally
            {
                SystemCommandRunnerProvider.Reset();
            }

            Assert(commandRunner.Commands.Count == 2, "demotion command should query admins and then demote");
            Assert(commandRunner.Commands[0].CaptureOutput, "admin query should capture output");
            Assert(commandRunner.Commands[1].Arguments.Contains("\"Kirill\" /delete"), "parent demotion should target selected child user");
        }

        private static void TestApplicationControlRuntime()
        {
            var now = new DateTime(2026, 6, 6, 12, 0, 0, DateTimeKind.Utc);
            var app = new AllowedApplication
            {
                Id = "app:test",
                DisplayName = "Minecraft",
                FilePath = @"C:\Games\Minecraft\Minecraft.exe",
                AllowedUntilUtc = now.AddMinutes(4),
                IsTemporary = true
            };
            var settings = new ApplicationControlSettings
            {
                Mode = ApplicationControlMode.Enforced,
                WarningMinutes = 5,
                AllowedApplications = new List<AllowedApplication> { app }
            };
            var running = new[]
            {
                new RunningApplication { ProcessId = 123, FilePath = @"C:\Games\Minecraft\Minecraft.exe" }
            };

            var warning = ApplicationControlRuntime.Evaluate(settings, running, now);
            Assert(warning.WarningApplications.Count == 1, "running app should warn before expiration");
            Assert(warning.WarningApplications[0].MinutesLeft == 4, "warning should include minutes left");
            Assert(app.LastWarningUtc == now, "warning timestamp should be stored");
            Assert(app.WarningMinuteMarksShown.Contains(4), "warning minute mark should be stored");
            Assert(!settings.PolicyUpdatePending, "warning should not require AppLocker update");

            var expired = ApplicationControlRuntime.Evaluate(settings, running, now.AddMinutes(5));
            Assert(expired.ExpiredRunningApplications.Count == 1, "expired running app should be returned for stop");
            Assert(settings.PolicyUpdatePending, "expiration should require AppLocker update");
            Assert(app.ExpirationApplied, "expiration should be marked applied");
        }

        private static void TestApplicationControlPolicyPaths()
        {
            var now = new DateTime(2026, 6, 6, 12, 0, 0, DateTimeKind.Utc);
            var state = new GuardState();
            state.AppControl.AllowedApplications.Add(new AllowedApplication
            {
                Id = "app:active",
                DisplayName = "Active Game",
                FilePath = @"C:\Games\Active\Active.exe"
            });
            state.AppControl.AllowedApplications.Add(new AllowedApplication
            {
                Id = "app:expired",
                DisplayName = "Expired Game",
                FilePath = @"C:\Games\Expired\Expired.exe",
                AllowedUntilUtc = now.AddMinutes(-1)
            });

            var paths = ApplicationControlPolicyManager.BuildAllowedPaths(state, @"C:\Program Files\Guard\guard.exe", now);
            Assert(paths.Contains(@"C:\Program Files\Guard\guard.exe"), "Guard app should be included");
            Assert(paths.Contains(@"C:\Program Files\Guard\StartHelperG.exe"), "helper should be included");
            Assert(paths.Contains(@"C:\Program Files\Guard\Guard.Cleaner.exe"), "cleaner should be included");
            Assert(paths.Contains(@"C:\Games\Active\Active.exe"), "active app should be included");
            Assert(!paths.Contains(@"C:\Games\Expired\Expired.exe"), "expired app should be excluded");

            var blockedTools = ApplicationControlPolicyManager.BuildBlockedManagementToolPaths();
            var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            Assert(ContainsPath(blockedTools, Path.Combine(windowsDirectory, @"System32\Taskmgr.exe")), "Task Manager deny path should be generated");
            Assert(ContainsPath(blockedTools, Path.Combine(windowsDirectory, @"System32\taskkill.exe")), "taskkill deny path should be generated");
            Assert(ContainsPath(blockedTools, Path.Combine(windowsDirectory, @"System32\cmd.exe")), "cmd deny path should be generated");
            Assert(ContainsPath(blockedTools, Path.Combine(windowsDirectory, @"System32\WindowsPowerShell\v1.0\powershell.exe")), "PowerShell deny path should be generated");
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (!string.IsNullOrWhiteSpace(programFiles))
            {
                Assert(ContainsPath(blockedTools, Path.Combine(programFiles, @"PowerShell\7\pwsh.exe")), "PowerShell 7 deny path should be generated");
            }
        }

        private static void TestApplicationControlPolicyScript()
        {
            var script = ApplicationControlPolicyManager.BuildPolicyScriptForDiagnostics();
            Assert(ApplicationControlPolicyManager.CurrentPolicySchemaVersion >= 3, "default-deny policy change should bump schema version");
            Assert(script.Contains("Remove-BroadProgramFilesAllows"), "policy script should remove broad Program Files allow rules");
            Assert(script.Contains("New-AppLockerPolicy -AllowWindows"), "policy script should still keep Windows default rules for OS stability");
            Assert(script.Contains("Guard: allow Guard application directory"), "policy script should allow Guard itself");
            Assert(script.Contains("Guard: deny management tool"), "policy script should deny management tools");
        }

        private static void TestApplicationControlPolicyApplyNeed()
        {
            var off = new ApplicationControlSettings
            {
                Mode = ApplicationControlMode.Off,
                PolicyUpdatePending = false,
                PolicySchemaVersion = 0
            };
            Assert(!ApplicationControlPolicyManager.NeedsApply(off), "off mode without pending changes should not apply policy");

            var stale = new ApplicationControlSettings
            {
                Mode = ApplicationControlMode.Enforced,
                PolicyUpdatePending = false,
                PolicySchemaVersion = 0
            };
            Assert(ApplicationControlPolicyManager.NeedsApply(stale), "old enforced policy schema should be reapplied");

            var current = new ApplicationControlSettings
            {
                Mode = ApplicationControlMode.Enforced,
                PolicyUpdatePending = false,
                PolicySchemaVersion = ApplicationControlPolicyManager.CurrentPolicySchemaVersion
            };
            Assert(!ApplicationControlPolicyManager.NeedsApply(current), "current enforced policy schema should not reapply every tick");

            var pendingOff = new ApplicationControlSettings
            {
                Mode = ApplicationControlMode.Off,
                PolicyUpdatePending = true,
                PolicySchemaVersion = ApplicationControlPolicyManager.CurrentPolicySchemaVersion
            };
            Assert(ApplicationControlPolicyManager.NeedsApply(pendingOff), "pending off mode should still clear policy");
        }

        private static void TestApplicationControlCountdownWarnings()
        {
            var now = new DateTime(2026, 6, 6, 12, 0, 0, DateTimeKind.Utc);
            var app = new AllowedApplication
            {
                Id = "app:countdown",
                DisplayName = "Game",
                FilePath = @"C:\Games\Game.exe",
                AllowedUntilUtc = now.AddMinutes(5),
                IsTemporary = true
            };
            var settings = new ApplicationControlSettings
            {
                Mode = ApplicationControlMode.Enforced,
                WarningMinutes = 5,
                AllowedApplications = new List<AllowedApplication> { app }
            };
            var running = new[]
            {
                new RunningApplication { ProcessId = 123, FilePath = @"C:\Games\Game.exe" }
            };

            var five = ApplicationControlRuntime.Evaluate(settings, running, now);
            var duplicateFive = ApplicationControlRuntime.Evaluate(settings, running, now.AddSeconds(20));
            var four = ApplicationControlRuntime.Evaluate(settings, running, now.AddMinutes(1).AddSeconds(1));
            var three = ApplicationControlRuntime.Evaluate(settings, running, now.AddMinutes(2).AddSeconds(1));
            var two = ApplicationControlRuntime.Evaluate(settings, running, now.AddMinutes(3).AddSeconds(1));
            var one = ApplicationControlRuntime.Evaluate(settings, running, now.AddMinutes(4).AddSeconds(1));

            Assert(five.WarningApplications.Count == 1 && five.WarningApplications[0].MinutesLeft == 5, "5 minute warning should fire");
            Assert(duplicateFive.WarningApplications.Count == 0, "same minute warning should not duplicate");
            Assert(four.WarningApplications.Count == 1 && four.WarningApplications[0].MinutesLeft == 4, "4 minute warning should fire");
            Assert(three.WarningApplications.Count == 1 && three.WarningApplications[0].MinutesLeft == 3, "3 minute warning should fire");
            Assert(two.WarningApplications.Count == 1 && two.WarningApplications[0].MinutesLeft == 2, "2 minute warning should fire");
            Assert(one.WarningApplications.Count == 1 && one.WarningApplications[0].MinutesLeft == 1, "1 minute warning should fire");
        }

        private static void TestTaskManagerAccessCommands()
        {
            var now = new DateTime(2026, 6, 6, 12, 0, 0, DateTimeKind.Utc);
            var state = new GuardState();
            state.AppControl.Mode = ApplicationControlMode.Enforced;
            Assert(ApplicationControlApplier.IsTaskManagerBlocked(state.AppControl, now), "Task Manager should be blocked by default");

            var allow = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.GrantTaskManagerAccess,
                IntValue = 10
            });
            Assert(allow.Changed, "Task Manager temporary access should change state");
            Assert(state.AppControl.TaskManagerAllowedUntilUtc.HasValue, "Task Manager allowance should have expiration");
            Assert(!ApplicationControlApplier.IsTaskManagerBlocked(state.AppControl, DateTime.UtcNow), "Task Manager should be temporarily allowed");

            var running = new[]
            {
                new RunningApplication { ProcessId = 321, FilePath = @"C:\Windows\System32\Taskmgr.exe" }
            };
            var allowedTick = ApplicationControlRuntime.Evaluate(state.AppControl, running, DateTime.UtcNow);
            Assert(allowedTick.BlockedManagementTools.Count == 0, "allowed Task Manager should not be stopped");

            var block = ParentCommandApplier.Apply(state, new ParentCommand
            {
                Type = ParentCommandType.BlockTaskManagerNow
            });
            Assert(block.Changed, "Task Manager block now should change state");
            Assert(ApplicationControlApplier.IsTaskManagerBlocked(state.AppControl, DateTime.UtcNow), "Task Manager should be blocked again");

            var blockedTick = ApplicationControlRuntime.Evaluate(state.AppControl, running, DateTime.UtcNow);
            Assert(blockedTick.BlockedManagementTools.Count == 1, "blocked Task Manager should be returned for stop");
        }

        private static void TestMaintenanceMode()
        {
            var now = new DateTime(2026, 6, 6, 12, 0, 0, DateTimeKind.Utc);
            var state = new GuardState
            {
                SyncStatus = true
            };
            state.UpdateInfo.UpdateApplied = true;
            state.AppControl.Mode = ApplicationControlMode.Enforced;
            state.AppControl.BlockTaskManager = true;

            var invalid = MaintenanceModeApplier.Start(state, 0, now);
            Assert(!invalid.Changed && !string.IsNullOrEmpty(invalid.Error), "invalid maintenance duration should be rejected");
            Assert(!state.MaintenanceMode.IsActive, "invalid maintenance duration should not activate maintenance");

            var start = MaintenanceModeApplier.Start(state, 30, now);
            Assert(start.Changed, "maintenance start should change state");
            Assert(state.MaintenanceMode.IsActive, "maintenance should be active");
            Assert(state.MaintenanceMode.PreviousSyncStatus, "previous blocking state should be saved");
            Assert(state.MaintenanceMode.PreviousAppControlMode == ApplicationControlMode.Enforced, "previous app mode should be saved");
            Assert(!state.SyncStatus, "blocking should be paused in maintenance mode");
            Assert(state.AppControl.Mode == ApplicationControlMode.Off, "application control should be off in maintenance mode");
            Assert(!state.AppControl.BlockTaskManager, "Task Manager should be allowed in maintenance mode");
            Assert(state.AppControl.TaskManagerAllowedUntilUtc == now.AddMinutes(30), "Task Manager allowance should match maintenance timer");
            Assert(state.AppControl.PolicyUpdatePending, "maintenance start should require policy apply");
            Assert(!state.UpdateInfo.UpdateApplied, "blocking update should be marked unapplied");

            var extend = MaintenanceModeApplier.Start(state, 60, now.AddMinutes(5));
            Assert(extend.Changed, "active maintenance can be extended");
            Assert(state.MaintenanceMode.PreviousAppControlMode == ApplicationControlMode.Enforced, "extension should keep original app mode");
            Assert(state.MaintenanceMode.UntilUtc == now.AddMinutes(65), "extension should update expiration");

            state.SyncStatus = true;
            state.AppControl.Mode = ApplicationControlMode.AuditOnly;
            state.AppControl.BlockTaskManager = true;
            var refresh = MaintenanceModeApplier.RefreshActiveState(state, now.AddMinutes(10));
            Assert(refresh.Changed, "maintenance refresh should repair accidental protection changes");
            Assert(!state.SyncStatus, "maintenance refresh should pause blocking again");
            Assert(state.AppControl.Mode == ApplicationControlMode.Off, "maintenance refresh should turn app control off again");
            Assert(!state.AppControl.BlockTaskManager, "maintenance refresh should allow Task Manager again");
            Assert(state.MaintenanceMode.PreviousAppControlMode == ApplicationControlMode.Enforced, "refresh should not overwrite original app mode");

            var early = MaintenanceModeApplier.ExpireIfNeeded(state, now.AddMinutes(20));
            Assert(!early.Changed, "maintenance should not expire too early");

            var expired = MaintenanceModeApplier.ExpireIfNeeded(state, now.AddMinutes(66));
            Assert(expired.Changed, "maintenance should expire after the timer");
            Assert(!state.MaintenanceMode.IsActive, "maintenance should be inactive after expiration");
            Assert(state.SyncStatus, "blocking should be restored after maintenance");
            Assert(state.AppControl.Mode == ApplicationControlMode.Enforced, "application control mode should be restored after maintenance");
            Assert(state.AppControl.BlockTaskManager, "Task Manager block setting should be restored after maintenance");
            Assert(!state.AppControl.TaskManagerAllowedUntilUtc.HasValue, "Task Manager temporary allowance should be restored after maintenance");
            Assert(state.UpdateInfo.SyncStatUpdate && state.UpdateInfo.Rules && state.UpdateInfo.Cats, "restoring maintenance should mark protection for reapply");
        }

        private static void TestApplicationControlRuntimeEdgeCases()
        {
            var now = new DateTime(2026, 6, 6, 12, 0, 0, DateTimeKind.Utc);
            var settings = new ApplicationControlSettings
            {
                Mode = ApplicationControlMode.Enforced,
                WarningMinutes = 5,
                AllowedApplications = new List<AllowedApplication>
                {
                    new AllowedApplication
                    {
                        Id = "app:single-use",
                        DisplayName = "Game",
                        FilePath = @"C:\Games\Game.exe",
                        AllowedUntilUtc = now.AddMinutes(5),
                        IsTemporary = true
                    }
                }
            };
            var running = new SingleUseEnumerable<RunningApplication>(new[]
            {
                new RunningApplication { ProcessId = 111, FilePath = @"C:\Games\Game.exe" },
                new RunningApplication { ProcessId = 222, FilePath = @"C:\Windows\System32\Taskmgr.exe" },
                new RunningApplication { ProcessId = 333, FilePath = @"C:\Windows\System32\taskkill.exe" },
                new RunningApplication { ProcessId = 444, FilePath = @"C:\Windows\System32\cmd.exe" },
                new RunningApplication { ProcessId = 555, FilePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" }
            });

            var result = ApplicationControlRuntime.Evaluate(settings, running, now);
            Assert(result.WarningApplications.Count == 1, "single-use process list should still warn for the game");
            Assert(result.BlockedManagementTools.Count == 4, "single-use process list should still block management tools");
            Assert(ApplicationControlApplier.IsBlockedManagementToolFileName("taskkill.exe"), "taskkill should be treated as a blocked management tool");
            Assert(ApplicationControlApplier.IsBlockedManagementToolFileName("powershell.exe"), "PowerShell should be treated as a blocked management tool");
            Assert(ApplicationControlApplier.IsBlockedManagementToolFileName("pwsh.exe"), "PowerShell 7 should be treated as a blocked management tool");

            var nullRunning = ApplicationControlRuntime.Evaluate(settings, null!, now.AddMinutes(1));
            Assert(nullRunning.WarningApplications.Count == 0, "null process list should not warn");
            Assert(nullRunning.BlockedManagementTools.Count == 0, "null process list should not block tools");
        }

        private static void TestTaskManagerStatusDescription()
        {
            var now = new DateTime(2026, 6, 6, 12, 0, 0, DateTimeKind.Utc);
            var blocked = new ApplicationControlSettings { BlockTaskManager = true };
            Assert(
                ApplicationControlApplier.DescribeTaskManagerStatus(blocked, now).Contains("заблокированы"),
                "blocked Task Manager should be described safely");

            var temporarilyAllowed = new ApplicationControlSettings
            {
                BlockTaskManager = true,
                TaskManagerAllowedUntilUtc = now.AddMinutes(10)
            };
            Assert(
                ApplicationControlApplier.DescribeTaskManagerStatus(temporarilyAllowed, now).Contains("разрешены до"),
                "temporary Task Manager access should include an expiration");

            var allowedWithoutExpiration = new ApplicationControlSettings
            {
                BlockTaskManager = false,
                TaskManagerAllowedUntilUtc = null
            };
            Assert(
                ApplicationControlApplier.DescribeTaskManagerStatus(allowedWithoutExpiration, now).Contains("разрешены"),
                "allowed Task Manager without expiration should not throw");
        }

        private static void Assert(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private static bool ContainsPath(IReadOnlyList<string> paths, string expectedPath)
        {
            foreach (var path in paths)
            {
                if (string.Equals(path, expectedPath, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private sealed class RecordingCommandRunner : ISystemCommandRunner
        {
            public readonly List<(string FileName, string Arguments, bool CaptureOutput)> Commands = new List<(string, string, bool)>();
            public string Output { get; set; } = "";

            public SystemCommandResult Run(string fileName, string arguments, bool captureOutput = false)
            {
                Commands.Add((fileName, arguments, captureOutput));
                return new SystemCommandResult
                {
                    Started = true,
                    ExitCode = 0,
                    Output = Output,
                    Error = ""
                };
            }
        }

        private sealed class SingleUseEnumerable<T> : IEnumerable<T>
        {
            private readonly IEnumerable<T> _items;
            private bool _used;

            public SingleUseEnumerable(IEnumerable<T> items)
            {
                _items = items;
            }

            public IEnumerator<T> GetEnumerator()
            {
                if (_used)
                {
                    throw new InvalidOperationException("Enumerable was enumerated twice.");
                }

                _used = true;
                return _items.GetEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return GetEnumerator();
            }
        }
    }
}
