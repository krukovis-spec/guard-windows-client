using System;
using System.IO;
using System.Security.Principal;
using System.Text.Json;
using Guard.Contracts;
using Guard.Windows.Ipc;

namespace Guard.Windows.Ipc.Tests;

// Explicit opt-in only, invoked by the UUID-pinned disposable-VM script. No service/policy writes.
internal static class InstalledServiceChecks
{
    internal static int Run(string[] args)
    {
        var phase = "guest-boundary";
        object? observations = null;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (args.Length is not (2 or 3 or 4) || args[0] != "--installed-service-lab" ||
                Environment.MachineName != "DESKTOP-8C2FU3H" || identity.IsSystem ||
                !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new InvalidOperationException("Disposable guest administrator required.");
            var expectedOrigin = args.Length >= 3 ? args[2] : "https://guard-lab.invalid";
            if (expectedOrigin is not ("https://guard-lab.invalid" or "https://guard-relay.voicepaste.workers.dev"))
                throw new ArgumentException("Unknown lab deployment.");
            if (args[1] == "reject-bootstrap")
            {
                if (args.Length == 4) throw new ArgumentException("Unexpected export argument.");
                phase = "reject-bootstrap-query";
                try { GuardSetupQueryClient.QueryAsync(GuardVerb.GetStatus, default).GetAwaiter().GetResult(); }
                catch (UnauthorizedAccessException)
                { Console.WriteLine("{\"status\":\"PASS\",\"bootstrapEndpoint\":\"REJECTED\"}"); return 0; }
                throw new InvalidOperationException("Bootstrap endpoint was accepted.");
            }
            if (args[1] != "inspect") throw new ArgumentException("Unknown lab mode.");
            phase = "inspect-query";
            var inspection = SetupInspection.ReadAsync(default).GetAwaiter().GetResult();
            phase = "descriptor-query";
            var descriptor = SetupInspection.ReadDescriptorAsync(default).GetAwaiter().GetResult();
            phase = "inspect-validation";
            observations = new { inspection.CanExport, inspection.Status.StateVersion, inspection.Readiness.CanEnableProtection,
                serviceBoundary = inspection.Readiness.ServiceBoundary.ToString(), programDataAcl = inspection.Readiness.ProgramDataAcl.ToString(),
                expectedLabOrigin = descriptor.RelayOrigin == expectedOrigin };
            if (!inspection.CanExport || inspection.Status.StateVersion != 0 || inspection.Readiness.CanEnableProtection ||
                inspection.Readiness.ServiceBoundary != GuardReadinessFactState.Satisfied ||
                inspection.Readiness.ProgramDataAcl != GuardReadinessFactState.Satisfied ||
                descriptor.RelayOrigin != expectedOrigin)
                throw new InvalidOperationException("Unexpected fresh lab state or trust profile.");
            if (args.Length == 4)
            {
                phase = "descriptor-export";
                // Only the exact UUID-pinned runner package may receive this public export.
                var directory = Path.GetDirectoryName(Environment.ProcessPath!)!;
                var package = Directory.GetParent(directory)!.FullName;
                if (!System.Text.RegularExpressions.Regex.IsMatch(package,
                        @"^C:\\GuardLab\\ServiceSmoke-[a-f0-9]{32}$") ||
                    args[3] != Path.Combine(package, "device.json"))
                    throw new ArgumentException("Unexpected lab export path.");
                descriptor.SaveNew(args[3]);
            }
            Console.WriteLine(JsonSerializer.Serialize(new { status = "PASS", authenticatedSystemService = true,
                stateVersion = inspection.Status.StateVersion, ownerBound = inspection.Status.IsProvisioned,
                readiness = inspection.Readiness.CanEnableProtection, serviceConfiguration = "OBSERVED", programDataAcl = "SYSTEM_ONLY",
                descriptorSha256 = descriptor.Sha256, protectionAccepted = false }));
            return 0;
        }
        catch (Exception error)
        {
            // Never print state, key material, paths or arbitrary exception messages.
            Console.WriteLine(JsonSerializer.Serialize(new { status = "FAIL", phase, observations,
                errorType = error.GetType().Name, errorCode = error.HResult,
                member = error.TargetSite?.DeclaringType?.FullName + "." + error.TargetSite?.Name }));
            return 1;
        }
    }
}
