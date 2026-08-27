using System;
using System.Diagnostics;

namespace Guard
{
    public sealed class SystemCommandResult
    {
        public bool Started { get; set; }
        public int ExitCode { get; set; }
        public string Output { get; set; } = "";
        public string Error { get; set; } = "";
    }

    public interface ISystemCommandRunner
    {
        SystemCommandResult Run(string fileName, string arguments, bool captureOutput = false);
    }

    public sealed class ProcessSystemCommandRunner : ISystemCommandRunner
    {
        public SystemCommandResult Run(string fileName, string arguments, bool captureOutput = false)
        {
            var psi = new ProcessStartInfo(fileName, arguments)
            {
                WindowStyle = ProcessWindowStyle.Hidden,
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = captureOutput,
                RedirectStandardError = captureOutput
            };

            using (var process = Process.Start(psi))
            {
                if (process == null)
                {
                    return new SystemCommandResult { Started = false };
                }

                string output = captureOutput ? process.StandardOutput.ReadToEnd() : "";
                string error = captureOutput ? process.StandardError.ReadToEnd() : "";
                process.WaitForExit();

                return new SystemCommandResult
                {
                    Started = true,
                    ExitCode = process.ExitCode,
                    Output = output,
                    Error = error
                };
            }
        }
    }

    public static class SystemCommandRunnerProvider
    {
        public static ISystemCommandRunner Current { get; set; } = new ProcessSystemCommandRunner();

        public static void Reset()
        {
            Current = new ProcessSystemCommandRunner();
        }
    }
}
