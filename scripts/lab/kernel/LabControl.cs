using System;
using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

// Lab-only one-shot trigger. No timer, service, process termination or policy effect in user mode.
internal static class LabControl
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(SafeFileHandle file, uint code, IntPtr input, uint inputSize,
        IntPtr output, uint outputSize, out uint returned, IntPtr overlapped);

    private static int Main(string[] args)
    {
        if (args.Length != 1 || args[0] != "--arm-lab-once") return 2;
        // Refuse host execution even if somebody copied/loaded a driver with the same device name.
        using (var search = new ManagementObjectSearcher("SELECT UUID FROM Win32_ComputerSystemProduct"))
        using (var rows = search.Get())
        {
            bool pinned = false;
            foreach (ManagementObject row in rows)
                using (row) pinned = string.Equals((string)row["UUID"], "236ea6ef-9cc6-4295-9934-6f7497f9d262", StringComparison.OrdinalIgnoreCase);
            if (!pinned) { Console.WriteLine("LAB_VM_REQUIRED"); return 3; }
        }
        using (var file = CreateFile(@"\\.\GuardKernelLab", 0xc0000000, 0, IntPtr.Zero, 3, 0, IntPtr.Zero))
        {
            if (file.IsInvalid) { Console.WriteLine("OPEN_WIN32=" + Marshal.GetLastWin32Error()); return 4; }
            uint returned;
            if (!DeviceIoControl(file, 0x8337e000, IntPtr.Zero, 0, IntPtr.Zero, 0, out returned, IntPtr.Zero))
            { Console.WriteLine("ARM_WIN32=" + Marshal.GetLastWin32Error()); return 5; }
            Console.WriteLine("LAB_ARMED_20_SECONDS");
            return 0;
        }
    }
}
