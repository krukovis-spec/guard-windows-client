using System;
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
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (args.Length != 2 || args[0] != "--installed-service-lab" ||
                Environment.MachineName != "DESKTOP-8C2FU3H" || identity.IsSystem ||
                !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new InvalidOperationException("Disposable guest administrator required.");
            if (args[1] == "reject-bootstrap")
            {
                try { GuardSetupQueryClient.QueryAsync(GuardVerb.GetStatus, default).GetAwaiter().GetResult(); }
                catch (UnauthorizedAccessException)
                { Console.WriteLine("{\"status\":\"PASS\",\"bootstrapEndpoint\":\"REJECTED\"}"); return 0; }
                throw new InvalidOperationException("Bootstrap endpoint was accepted.");
            }
            if (args[1] != "inspect") throw new ArgumentException("Unknown lab mode.");
            var inspection = SetupInspection.ReadAsync(default).GetAwaiter().GetResult();
            var descriptor = SetupInspection.ReadDescriptorAsync(default).GetAwaiter().GetResult();
            if (!inspection.CanExport || inspection.Status.StateVersion != 0 || inspection.Readiness.CanEnableProtection ||
                inspection.Readiness.ProgramDataAcl != GuardReadinessFactState.Satisfied ||
                descriptor.RelayOrigin != "https://guard-lab.invalid")
                throw new InvalidOperationException("Unexpected fresh lab state or trust profile.");
            Console.WriteLine(JsonSerializer.Serialize(new { status = "PASS", authenticatedSystemService = true,
                stateVersion = inspection.Status.StateVersion, ownerBound = inspection.Status.IsProvisioned,
                readiness = inspection.Readiness.CanEnableProtection, programDataAcl = "SYSTEM_ONLY",
                descriptorSha256 = descriptor.Sha256, protectionAccepted = false }));
            return 0;
        }
        catch (Exception error)
        {
            // Never print state, key material, paths or arbitrary exception messages.
            Console.WriteLine(JsonSerializer.Serialize(new { status = "FAIL", errorType = error.GetType().Name, errorCode = error.HResult }));
            return 1;
        }
    }
}
