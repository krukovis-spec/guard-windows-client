using System;
using System.IO;

namespace Guard.Windows.Services;

public static class GuardServiceIdentity
{
    public const string ServiceName = "Guard";

    public static string ExpectedBinaryPath
    {
        get
        {
            var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (string.IsNullOrWhiteSpace(programFiles))
                throw new InvalidOperationException("The protected Program Files root is unavailable.");
            return Path.Combine(programFiles, "Guard", "Guard.Service.exe");
        }
    }
}
