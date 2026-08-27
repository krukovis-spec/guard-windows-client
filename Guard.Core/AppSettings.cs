using System;
using System.IO;

namespace Guard
{
    public static class AppSettings
    {
        // This is the single, shared path for our disable flag file.
        public static string DisableFlagPath => Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "session.lock");
    }
}