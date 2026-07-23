using System;
using System.Security;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;

namespace Guard.Service
{
    internal static class Program
    {
        private const int InvalidExecutionBoundaryExitCode = 5;
        private const int FatalStartupExitCode = 6;

        private static async Task<int> Main(string[] args)
        {
            if (!OperatingSystem.IsWindows() || !WindowsServiceHelpers.IsWindowsService())
            {
                return InvalidExecutionBoundaryExitCode;
            }

            try
            {
                using (var host = GuardServiceHost.Build(args))
                {
                    var exitStatus = host.Services.GetRequiredService<ServiceExitStatus>();
                    await host.RunAsync().ConfigureAwait(false);
                    return exitStatus.ExitCode;
                }
            }
            catch (SecurityException)
            {
                return InvalidExecutionBoundaryExitCode;
            }
            catch (Exception)
            {
                return FatalStartupExitCode;
            }
        }
    }
}
