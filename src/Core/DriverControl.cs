using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using Microsoft.Win32;

namespace NSFShield
{
    /// <summary>
    /// The WinDivert kernel driver. GoodbyeDPI (WinDivert 2.2.0, bin\x86_64) and Zapret (WinDivert 2.2.2, bin\zapret) each
    /// ship their own signed driver; both register the same "WinDivert" service, so whichever was loaded first is used by the
    /// other. When the engine changes – or before an upgrade replaces the files – the driver loaded from this folder is
    /// stopped ("sc stop" only, never deleted; WinDivert marks itself for deletion, so the entry disappears once stopped),
    /// and the next engine loads its own driver. A driver still used by another WinDivert program is left alone.
    /// </summary>
    public static class DriverControl
    {
        /// <summary>Service names of the WinDivert driver (2.x, and 1.4 of older GoodbyeDPI builds).</summary>
        public static readonly string[] DriverServices = { "WinDivert", "WinDivert1.4", "WinDivert14" };

        /// <summary>
        /// The file of a driver service's ImagePath (\??\C:\..., \SystemRoot\..., system32\drivers\...) as a full local path; null if
        /// it is empty, not local or not valid.
        /// </summary>
        public static string DriverFile(string imagePath)
        {
            if (string.IsNullOrWhiteSpace(imagePath)) return null;
            string s = imagePath.Trim().Trim('"');
            try
            {
                if (s.StartsWith(@"\??\")) s = s.Substring(4);
                else if (s.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase)) s = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), s.Substring(12));
                else if (!Path.IsPathRooted(s)) s = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), s);
                if (s.StartsWith(@"\\") || s.StartsWith("UNC\\", StringComparison.OrdinalIgnoreCase) || s.Length < 3 || s[1] != ':') return null;
                return Path.GetFullPath(s);
            }
            catch (Exception) { return null; }
        }

        /// <summary>
        /// True if the driver of this ImagePath was loaded from the given folder (only then it locks a file of ours). Both paths
        /// are compared in their long form (an 8.3 short name in the ImagePath still matches).
        /// </summary>
        public static bool DriverInFolder(string imagePath, string dir)
        {
            string file = DriverFile(imagePath);
            if (file == null || string.IsNullOrEmpty(dir)) return false;
            return PathSafety.Inside(file, dir);
        }

        /// <summary>
        /// The strict form for deleting a driver entry (uninstall): the driver file exists and its physical final path is
        /// inside the physical final path of the folder. Unreadable or elsewhere: false (the entry is kept).
        /// </summary>
        public static bool DriverInFolderVerified(string imagePath, string dir)
        {
            if (!DriverInFolder(imagePath, dir)) return false;
            string file = PathSafety.FinalPath(DriverFile(imagePath)), root = PathSafety.FinalPath(dir);
            return file != null && root != null && file.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
        }

        public static string ImagePath(string service)
        {
            using (var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + service))
                return key?.GetValue("ImagePath", null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        }

        /// <summary>The file of the WinDivert driver that is loaded now (null if none is running).</summary>
        public static string LoadedFile()
        {
            foreach (var name in DriverServices)
            {
                try
                {
                    using (var sc = new ServiceController(name))
                        if (sc.Status != ServiceControllerStatus.Stopped) return DriverFile(ImagePath(name));
                }
                catch (InvalidOperationException) { }
                catch (Exception ign) { App.Ignored("Driver state could not be read", ign); }
            }
            return null;
        }

        /// <summary>Is a WinDivert engine (goodbyedpi / winws) still running (one of another program, ours were closed before)?</summary>
        public static bool DriverUserRunning()
        {
            foreach (var n in Engines.DriverProcessNames)
            {
                var ps = Process.GetProcessesByName(n);
                bool any = ps.Length > 0;
                foreach (var p in ps) p.Dispose();
                if (any) return true;
            }
            return false;
        }

        /// <summary>
        /// Unloads (stops) a WinDivert driver loaded from <paramref name="dir"/> and waits until it has stopped – except the
        /// driver file <paramref name="keep"/> (the one the next engine uses itself). The driver entry is never deleted here.
        /// </summary>
        public static void Release(string dir, StringBuilder log, string keep = null)
        {
            foreach (var name in DriverServices)
            {
                try
                {
                    string image = ImagePath(name);
                    if (!DriverInFolder(image, dir)) continue;
                    if (keep != null && string.Equals(DriverFile(image), Path.GetFullPath(keep), StringComparison.OrdinalIgnoreCase)) continue;
                    using (var sc = new ServiceController(name))
                    {
                        var st = sc.Status;
                        if (st == ServiceControllerStatus.Stopped) continue;
                        if (DriverUserRunning()) { log.AppendLine("Driver " + name + " kept loaded: another WinDivert program (GoodbyeDPI/winws) is running."); continue; }
                        if (st != ServiceControllerStatus.StopPending) sc.Stop();
                        log.AppendLine(WaitStopped(sc) ? "Driver " + name + " unloaded (" + Path.GetFileName(Path.GetDirectoryName(DriverFile(image) ?? "")) + ")." : "Driver " + name + " did not unload within 10 s.");
                    }
                }
                catch (InvalidOperationException) { /* no such driver, or it was removed while stopping */ }
                catch (Exception ex) { log.AppendLine("Driver " + name + " could not be unloaded: " + ex.Message); }
            }
        }

        /// <summary>Polls for at most 10 s; a driver marked for deletion disappears when it stops, which also counts as stopped.</summary>
        public static bool WaitStopped(ServiceController sc)
        {
            var until = DateTime.UtcNow.AddSeconds(10);
            while (true)
            {
                try
                {
                    sc.Refresh();
                    if (sc.Status == ServiceControllerStatus.Stopped) return true;
                }
                catch (InvalidOperationException) { return true; }
                if (DateTime.UtcNow > until) return false;
                System.Threading.Thread.Sleep(250);
            }
        }
    }
}
