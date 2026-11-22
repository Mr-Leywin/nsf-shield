using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Windows.Forms;

namespace NSFShield
{
    public enum LogLevel { Debug, Info, Success, Warn, Error, Output }

    public class LogEntry
    {
        public DateTime Time;
        public LogLevel Level;
        public string Text;
    }

    /// <summary>Application-wide shared state.</summary>
    public static class App
    {
        public const string Name = "NSF Shield";
        /// <summary>The product title with its author (About page, README): never translated.</summary>
        public const string Title = Name + " — by Nightshift";
        /// <summary>Publisher (exe and installer version info, About page). The GitHub user name is separate (RepoUrl).</summary>
        public const string Publisher = "Nightshift (Osman Barış MEDİNE)";
        /// <summary>Copyright line of the MIT licence (same as LICENSE).</summary>
        public const string Copyright = "Copyright (c) 2026 " + Publisher;
        public const string RepoUrl = "https://github.com/Mr-Leywin/nsf-shield";
        /// <summary>Microsoft page for reporting a false positive (wrong virus warning).</summary>
        public const string WdsiUrl = "https://www.microsoft.com/en-us/wdsi/filesubmission";
        public static readonly string Version = Assembly.GetExecutingAssembly().GetName().Version.ToString(3);

        public static string BaseDir = AppDomain.CurrentDomain.BaseDirectory;
        public static string DataDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "data");
        public static string LogFile => Path.Combine(DataDir, "app.log");

        public static AppSettings Settings;
        public static Engine Engine;
        public static readonly ProblemCenter Problems = new ProblemCenter();
        public static bool Preview;
        public static SynchronizationContext UI;

        public static readonly List<LogEntry> LogBuffer = new List<LogEntry>();
        static readonly object LogLock = new object();

        public static event Action<LogEntry> LogAdded;
        /// <summary>Raised when the engine state, settings or test results change.</summary>
        public static event Action StatusChanged;

        public static List<HostResult> LastTest;
        public static DateTime? LastTestTime;
        /// <summary>System DNS check of the last test: null unknown, true correct, false fake/blocked.</summary>
        public static bool? LastDnsOk;

        /// <summary>Is the app running from inside a zip or from the Temp folder?</summary>
        public static bool RunningFromTemp
        {
            get
            {
                try
                {
                    const char S = '\\';
                    string b = Path.GetFullPath(BaseDir).TrimEnd(S) + S;
                    string t = Path.GetFullPath(Path.GetTempPath()).TrimEnd(S) + S;
                    return b.StartsWith(t, StringComparison.OrdinalIgnoreCase) ||
                           b.IndexOf(S + "Temp" + S, StringComparison.OrdinalIgnoreCase) >= 0 ||
                           b.IndexOf(".zip" + S, StringComparison.OrdinalIgnoreCase) >= 0;
                }
                catch { return false; }
            }
        }

        /// <summary>The data folder of an app folder (settings, profiles, lists, logs; never part of the package).</summary>
        public const string DataDirName = "data";

        public static void Init()
        {
            try { Directory.CreateDirectory(DataDir); } catch (Exception ign) { App.Ignored("Data folder could not be created", ign); }
            try
            {
                var fi = new FileInfo(LogFile);
                if (fi.Exists && fi.Length > 2 * 1024 * 1024)
                {
                    string old = LogFile + ".old";
                    if (File.Exists(old)) File.Delete(old);
                    File.Move(LogFile, old);
                }
            }
            catch (Exception ign) { App.Ignored("Log file could not be rotated", ign); }
            Settings = SettingsStore.Load();
            Loc.Init(Settings.Language);
            History.Load();
            Engine = new Engine();
        }

        public static bool IsAdmin()
        {
            try
            {
                using (var id = WindowsIdentity.GetCurrent())
                    return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        public static void Log(string text, LogLevel level = LogLevel.Info)
        {
            // the user's folder never goes into the log as it is (a portable copy may live on the desktop)
            var e = new LogEntry { Time = DateTime.Now, Level = level, Text = Privacy.MaskUser(text) };
            lock (LogLock)
            {
                LogBuffer.Add(e);
                if (LogBuffer.Count > 4000) LogBuffer.RemoveRange(0, 1000);
                if (!Preview)
                {
                    try
                    {
                        File.AppendAllText(LogFile,
                            e.Time.ToString("yyyy-MM-dd HH:mm:ss") + " [" + level + "] " + e.Text + Environment.NewLine);
                    }
                    catch { }
                }
            }
            Post(() => LogAdded?.Invoke(e));
        }

        public static LogEntry[] LogSnapshot() { lock (LogLock) return LogBuffer.ToArray(); }
        public static void ClearLog() { lock (LogLock) LogBuffer.Clear(); }

        /// <summary>
        /// Writes errors that do not stop the flow but must not vanish silently to the log at Debug level
        /// (instead of empty catch blocks). Visible in the Advanced UI log and in the support package.
        /// </summary>
        public static void Ignored(string where, Exception ex)
        {
            try { Log(where + ": " + (ex == null ? "?" : ex.GetType().Name + " – " + ex.Message), LogLevel.Debug); } catch { }
        }

        public static void Post(Action a)
        {
            var ui = UI;
            if (ui == null) { try { a(); } catch (Exception ign) { App.Ignored("Background operation", ign); } return; }
            ui.Post(_ => { try { a(); } catch (Exception ex) { Ignored("UI operation", ex); } }, null);
        }

        public static void RaiseStatus() => Post(() => StatusChanged?.Invoke());

        public static IEnumerable<Profile> AllProfiles => Profiles.BuiltIns.Concat(Settings.CustomProfiles);

        public static Profile SelectedProfile =>
            AllProfiles.FirstOrDefault(p => p.Id == Settings.SelectedProfileId) ?? Profiles.BuiltIns[0];

        public static Profile FindProfile(string id) => AllProfiles.FirstOrDefault(p => p.Id == id);

        public static void Save() => SettingsStore.Save(Settings);

        /// <summary>Saves and tells whether it worked (for steps that must not go on without the saved state).</summary>
        public static bool TrySave() => SettingsStore.Save(Settings);

        public static void Notify(string title, string text, ToolTipIcon icon = ToolTipIcon.Info)
        {
            Post(() => MainForm.Instance?.ShowBalloon(title, text, icon));
        }
    }
}
