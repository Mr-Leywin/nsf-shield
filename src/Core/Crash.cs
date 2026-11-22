using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace NSFShield
{
    /// <summary>
    /// Unexpected shutdown marker. data\running.marker is written when the app starts and deleted on a clean exit.
    /// If the file is still there at the next start, the previous run crashed, was killed or the power went out:
    /// the user gets a "Last shutdown was unexpected" notice (NSF-106) and access to the log.
    /// When our own tools (update, setup, uninstall) close the app they delete the marker, so no false warning appears.
    /// </summary>
    public static class CrashMarker
    {
        const string MarkerName = "running.marker", CrashName = "last-crash.txt";

        static string Marker(string dataDir) => Path.Combine(dataDir, MarkerName);
        public static string CrashFile => Path.Combine(App.DataDir, CrashName);

        /// <summary>Short description if the previous run ended unexpectedly (otherwise null).</summary>
        public static string PreviousUnexpected { get; private set; }

        public static void Begin()
        {
            if (App.Preview) return;
            PreviousUnexpected = null;
            try
            {
                string m = Marker(App.DataDir);
                if (File.Exists(m))
                {
                    string info = File.ReadAllText(m, Encoding.UTF8).Trim();
                    string crash = null;
                    if (File.Exists(CrashFile) && File.GetLastWriteTimeUtc(CrashFile) >= File.GetLastWriteTimeUtc(m))
                        crash = FirstLine(File.ReadAllText(CrashFile, Encoding.UTF8));
                    PreviousUnexpected = (info.Length > 0 ? info : Loc.T("crash.previousRun")) + (crash != null ? " " + Loc.T("crash.lastError") + " " + crash : "");
                    App.Log("[NSF-106] Last shutdown was unexpected (" + PreviousUnexpected + ").", LogLevel.Warn);
                }
                Directory.CreateDirectory(App.DataDir);
                File.WriteAllText(m, "version " + App.Version + ", started " + DateTime.Now.ToString("yyyy-MM-dd HH:mm") +
                                     ", process " + Process.GetCurrentProcess().Id, Encoding.UTF8);
            }
            catch (Exception ex) { App.Ignored("Running marker could not be written", ex); }
        }

        /// <summary>Clean exit: deletes the marker.</summary>
        public static void End()
        {
            if (App.Preview) return;
            Clear(App.DataDir);
        }

        /// <summary>Deletes the marker in another folder (e.g. the installation being updated); called by tools that close the app on purpose.</summary>
        public static void Clear(string dataDir)
        {
            try { string m = Marker(dataDir); if (File.Exists(m)) File.Delete(m); }
            catch (Exception ex) { App.Ignored("Running marker could not be deleted", ex); }
        }

        /// <summary>Writes the details of an unhandled exception to data\last-crash.txt.</summary>
        public static void Record(Exception ex, bool fatal)
        {
            if (App.Preview || ex == null) return;
            try
            {
                // the same privacy mask as the log: the stack trace and messages may contain the user's folder
                File.WriteAllText(CrashFile, Privacy.MaskUser((fatal ? "Fatal error (app closed): " : "Unexpected error: ") + ex.GetType().Name + ": " + ex.Message +
                                             Environment.NewLine + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " · version " + App.Version +
                                             Environment.NewLine + Environment.NewLine + ex), Encoding.UTF8);
            }
            catch { /* nothing can be done if it cannot be written while crashing */ }
        }

        static string FirstLine(string s)
        {
            string l = (s ?? "").Split('\n')[0].Trim();
            return l.Length > 160 ? l.Substring(0, 160) + "…" : l;
        }
    }
}
