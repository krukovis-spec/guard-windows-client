using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Automation;

namespace Guard
{
    internal static class ActivityMonitor
    {
        public static ActivitySnapshot Capture(DateTime utcNow)
        {
            var snapshot = new ActivitySnapshot
            {
                TimestampUtc = utcNow,
                IdleSeconds = GetIdleSeconds()
            };

            try
            {
                var hwnd = GetForegroundWindow();
                if (hwnd == IntPtr.Zero)
                {
                    return snapshot;
                }

                snapshot.ForegroundTitle = GetWindowTitle(hwnd);
                GetWindowThreadProcessId(hwnd, out var processId);
                if (processId == 0)
                {
                    return snapshot;
                }

                snapshot.ForegroundProcessId = (int)processId;
                using (var process = Process.GetProcessById((int)processId))
                {
                    snapshot.DisplayName = process.ProcessName;
                    var processName = process.ProcessName ?? "";
                    try
                    {
                        snapshot.ForegroundFilePath = process.MainModule?.FileName ?? "";
                    }
                    catch
                    {
                        snapshot.ForegroundFilePath = "";
                    }

                    snapshot.ForegroundDomain = TryReadBrowserDomain(hwnd, processName);
                }
            }
            catch
            {
            }

            return snapshot;
        }

        private static string TryReadBrowserDomain(IntPtr hwnd, string processName)
        {
            if (!IsBrowserProcess(processName))
            {
                return "";
            }

            try
            {
                var root = AutomationElement.FromHandle(hwnd);
                if (root == null)
                {
                    return "";
                }

                var edits = root.FindAll(
                    TreeScope.Descendants,
                    new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Edit));
                foreach (AutomationElement edit in edits)
                {
                    if (!edit.TryGetCurrentPattern(ValuePattern.Pattern, out var pattern))
                    {
                        continue;
                    }

                    var value = ((ValuePattern)pattern).Current.Value;
                    var domain = TryExtractDomain(value);
                    if (!string.IsNullOrWhiteSpace(domain))
                    {
                        return domain;
                    }
                }
            }
            catch
            {
            }

            return "";
        }

        private static bool IsBrowserProcess(string processName)
        {
            var name = (processName ?? "").Trim().ToLowerInvariant();
            return name == "chrome" ||
                name == "msedge" ||
                name == "firefox" ||
                name == "browser" ||
                name == "brave" ||
                name == "brave-browser" ||
                name == "opera" ||
                name == "vivaldi" ||
                name.Contains("yandex");
        }

        private static string TryExtractDomain(string value)
        {
            var text = (value ?? "").Trim();
            if (text.Length == 0 || text.Contains(" "))
            {
                return "";
            }

            if (!text.Contains("://") && text.Contains("."))
            {
                text = "https://" + text;
            }

            var domain = DomainAccessGrantApplier.NormalizeDomainInput(text);
            return DomainAccessGrantApplier.IsValidWebsiteDomain(domain) ? domain : "";
        }

        private static int GetIdleSeconds()
        {
            var info = new LastInputInfo
            {
                cbSize = (uint)Marshal.SizeOf(typeof(LastInputInfo))
            };

            if (!GetLastInputInfo(ref info))
            {
                return 0;
            }

            var idleMilliseconds = Environment.TickCount - unchecked((int)info.dwTime);
            if (idleMilliseconds < 0)
            {
                return 0;
            }

            return idleMilliseconds / 1000;
        }

        private static string GetWindowTitle(IntPtr hwnd)
        {
            var length = GetWindowTextLength(hwnd);
            if (length <= 0)
            {
                return "";
            }

            var builder = new StringBuilder(length + 1);
            GetWindowText(hwnd, builder, builder.Capacity);
            return builder.ToString();
        }

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowTextLength(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool GetLastInputInfo(ref LastInputInfo info);

        [StructLayout(LayoutKind.Sequential)]
        private struct LastInputInfo
        {
            public uint cbSize;
            public uint dwTime;
        }
    }
}
