using System;
using System.Runtime.InteropServices;

namespace NSFShield
{
    static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetDefaultDllDirectories(uint directoryFlags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool SetDllDirectory(string path);

        /// <summary>
        /// Restricts the DLL search order: the current directory and PATH folders are not searched, only the app folder
        /// (admin-protected in the installed version) and System32. Called on the first line of Main.
        /// </summary>
        public static void HardenDllSearch()
        {
            const uint LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x200, LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800;
            try { if (SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)) return; } catch { }
            try { SetDllDirectory(""); } catch { }   // older systems: at least remove the current directory
        }

        [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache")]
        static extern bool DnsFlushResolverCacheNative();

        public static bool FlushDns()
        {
            try { return DnsFlushResolverCacheNative(); } catch { return false; }
        }

        [DllImport("user32.dll")] public static extern bool ReleaseCapture();
        [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
        [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
        [DllImport("user32.dll")] public static extern bool DestroyIcon(IntPtr hIcon);

        [DllImport("dwmapi.dll")]
        static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        public static void RoundCorners(IntPtr hwnd)
        {
            try { int v = 2; DwmSetWindowAttribute(hwnd, 33, ref v, 4); } catch { }
        }

        /// <summary>Makes the title bar dark/light (Windows 10 1809+).</summary>
        public static void DarkTitle(IntPtr hwnd, bool dark)
        {
            try
            {
                int v = dark ? 1 : 0;
                if (DwmSetWindowAttribute(hwnd, 20, ref v, 4) != 0) DwmSetWindowAttribute(hwnd, 19, ref v, 4);
            }
            catch { }
        }

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        static extern int SetWindowTheme(IntPtr hwnd, string app, string idList);

        /// <summary>Makes scroll bars and standard controls follow the dark theme.</summary>
        public static void ThemeWindow(IntPtr hwnd, string name)
        {
            try { SetWindowTheme(hwnd, name, null); } catch { }
        }

        const int WM_SETREDRAW = 0x000B;
        [DllImport("user32.dll")] static extern bool RedrawWindow(IntPtr hWnd, IntPtr rect, IntPtr rgn, uint flags);

        /// <summary>Stops (false) or resumes (true) painting of a window and its children, for flicker-free rebuilds.</summary>
        public static void SetRedraw(IntPtr hwnd, bool on)
        {
            SendMessage(hwnd, WM_SETREDRAW, (IntPtr)(on ? 1 : 0), IntPtr.Zero);
            // RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN | RDW_UPDATENOW
            if (on) RedrawWindow(hwnd, IntPtr.Zero, IntPtr.Zero, 0x0001 | 0x0004 | 0x0400 | 0x0080 | 0x0100);
        }

        public static void DragWindow(IntPtr hwnd)
        {
            ReleaseCapture();
            SendMessage(hwnd, 0xA1, (IntPtr)2, IntPtr.Zero);
        }

        // ---- Job object: if the app exits/crashes, goodbyedpi.exe exits too ----
        [StructLayout(LayoutKind.Sequential)]
        struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IO_COUNTERS
        {
            public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
            public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr CreateJobObject(IntPtr attrs, string name);

        [DllImport("kernel32.dll")]
        static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        static IntPtr _job;

        public static void AttachToKillJob(IntPtr processHandle)
        {
            try
            {
                if (_job == IntPtr.Zero)
                {
                    _job = CreateJobObject(IntPtr.Zero, null);
                    var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                    info.BasicLimitInformation.LimitFlags = 0x2000; // KILL_ON_JOB_CLOSE
                    SetInformationJobObject(_job, 9, ref info, (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
                }
                // KILL_ON_JOB_CLOSE: even if the app crashes or is killed, GoodbyeDPI exits with it and the filter does not stay attached
                if (_job == IntPtr.Zero || !AssignProcessToJobObject(_job, processHandle))
                    App.Log("GoodbyeDPI could not be attached to the app (Win32 error " + Marshal.GetLastWin32Error() + "); it may stay open if the app crashes.", LogLevel.Warn);
            }
            catch (Exception ign) { App.Log("GoodbyeDPI could not be attached to the app (it may stay open if the app crashes): " + ign.Message, LogLevel.Warn); }
        }
    }
}
