using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Threading;

internal static class Marker
{
#if VARIANT_TWO
    private const string Variant = "v2";
#else
    private const string Variant = "v1";
#endif

    private static bool TryGetHoldSeconds(string[] args, out int seconds)
    {
        seconds = 0;
        return args.Length == 0 ||
            (args.Length == 2 && args[0] == "--hold-seconds" &&
             int.TryParse(args[1], NumberStyles.None, CultureInfo.InvariantCulture, out seconds) &&
             seconds >= 0 && seconds <= 600);
    }

    private static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--self-test")
        {
            int seconds;
            if (!TryGetHoldSeconds(new string[0], out seconds) || seconds != 0 ||
                !TryGetHoldSeconds(new[] { "--hold-seconds", "600" }, out seconds) || seconds != 600 ||
                TryGetHoldSeconds(new[] { "--hold-seconds", "601" }, out seconds) ||
                TryGetHoldSeconds(new[] { "--hold-seconds", "-1" }, out seconds) ||
                TryGetHoldSeconds(new[] { "--hold-seconds", "x" }, out seconds) ||
                TryGetHoldSeconds(new[] { "unexpected" }, out seconds)) return 1;
            Console.WriteLine("MARKER_SELF_TEST_PASS " + Variant);
            return 0;
        }

        int holdSeconds;
        if (!TryGetHoldSeconds(args, out holdSeconds)) return 2;
        string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "GuardLabMarker");
        Directory.CreateDirectory(root);
        string entry = string.Format(CultureInfo.InvariantCulture, "{0:o} {1} pid={2}{3}", DateTime.UtcNow, Variant, Process.GetCurrentProcess().Id, Environment.NewLine);
        File.AppendAllText(Path.Combine(root, "starts.log"), entry);
        Console.WriteLine("MARKER_STARTED " + Variant);
        Thread.Sleep(holdSeconds * 1000);
        Console.WriteLine("MARKER_FINISHED " + Variant);
        return 0;
    }
}
