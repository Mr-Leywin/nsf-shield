using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace NSFShield
{
    /// <summary>One Windows proxy value of the signed-in user: exists or not, its type (DWORD or text) and its data.</summary>
    public struct ProxyValue
    {
        public bool Exists;
        public bool Dword;
        public string Data;

        public static ProxyValue Absent => new ProxyValue { Exists = false, Data = "" };
        public static ProxyValue Number(int v) => new ProxyValue { Exists = true, Dword = true, Data = v.ToString(System.Globalization.CultureInfo.InvariantCulture) };
        public static ProxyValue Text(string v) => new ProxyValue { Exists = true, Dword = false, Data = v ?? "" };

        public bool SameAs(ProxyValue o) =>
            Exists == o.Exists && (!Exists || (Dword == o.Dword && string.Equals(Data ?? "", o.Data ?? "", StringComparison.Ordinal)));

        public override string ToString() => !Exists ? "(absent)" : (Dword ? "dword:" : "text:") + Data;
    }

    /// <summary>
    /// The recovery record of a Windows proxy change by NSF Shield: who changed it, the four values before the change (Backup)
    /// and the four values NSF Shield wrote (Written), each with its existence. It is one registry text value (written in one
    /// step, flushed and read back) with a SHA-256 check, so a record torn by a power loss is never used.
    /// </summary>
    public sealed class ProxyRecord
    {
        public const int Version = 1;
        public string Owner = "";
        /// <summary>True: restore at the next sign-in if the app is not running (the ByeDPI bridge does not outlive the app).</summary>
        public bool AtSignIn;
        public ProxyValue[] Backup = new ProxyValue[4], Written = new ProxyValue[4];

        static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s ?? ""));
        static string Un64(string s) => Encoding.UTF8.GetString(Convert.FromBase64String(s));
        static string Val(ProxyValue v) => (v.Exists ? (v.Dword ? "d" : "s") : "-") + ":" + B64(v.Exists ? v.Data : "");

        static ProxyValue ParseVal(string t)
        {
            int i = t.IndexOf(':');
            if (i != 1) throw new FormatException("value");
            char k = t[0];
            string data = Un64(t.Substring(2));
            if (k == '-') return ProxyValue.Absent;
            if (k == 'd') { if (!int.TryParse(data, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out int n)) throw new FormatException("dword"); return ProxyValue.Number(n); }
            if (k == 's') return ProxyValue.Text(data);
            throw new FormatException("kind");
        }

        static string Hash(string body)
        {
            using (var h = SHA256.Create()) return BitConverter.ToString(h.ComputeHash(Encoding.UTF8.GetBytes(body))).Replace("-", "").ToLowerInvariant();
        }

        public string Serialize()
        {
            var parts = new List<string> { "NSFR" + Version, B64(Owner), AtSignIn ? "1" : "0" };
            parts.AddRange(Backup.Select(Val));
            parts.AddRange(Written.Select(Val));
            string body = string.Join("|", parts);
            return body + "|" + Hash(body);
        }

        /// <summary>The record, or null for anything that is not a complete record of this version (torn, edited, unknown).</summary>
        public static ProxyRecord Parse(string text)
        {
            try
            {
                if (string.IsNullOrEmpty(text) || text.Length > 1 << 20) return null;
                int cut = text.LastIndexOf('|');
                if (cut < 0) return null;
                string body = text.Substring(0, cut);
                if (!string.Equals(text.Substring(cut + 1), Hash(body), StringComparison.Ordinal)) return null;
                var p = body.Split('|');
                if (p.Length != 11 || p[0] != "NSFR" + Version || (p[2] != "0" && p[2] != "1")) return null;
                var r = new ProxyRecord { Owner = Un64(p[1]), AtSignIn = p[2] == "1" };
                for (int i = 0; i < 4; i++) { r.Backup[i] = ParseVal(p[3 + i]); r.Written[i] = ParseVal(p[7 + i]); }
                return r;
            }
            catch (FormatException) { return null; }
        }
    }

    /// <summary>
    /// The one restore and preparation logic of the Windows proxy, shared by NSF Shield and its sign-in recovery helper
    /// (NSFShieldProxyRecovery.exe, asInvoker, no other dependency). Ownership is decided per value: a value that still equals
    /// what NSF Shield wrote is NSF Shield's and goes back to the backup; a value that already equals the backup is done (an
    /// interrupted restore of NSF Shield itself is never taken for a user change); any other value is the user's and is kept.
    /// When the user set another proxy server, the whole proxy setting is the user's: nothing is written back.
    /// </summary>
    public static class ProxyRecovery
    {
        public static readonly string[] Names = { "ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL" };
        public const int Enable = 0, Server = 1, Override = 2, Pac = 3;
        public const string InetKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        public const string RecordKey = @"Software\NSFShield";
        public const string RecordValue = "ProxyRecovery";
        public const string RunOnceKey = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
        public const string RunOnceName = "NSFShieldProxyRecovery";
        public const string HelperFile = "NSFShieldProxyRecovery.exe";
        public const string LockName = @"Local\NSFShield_ProxyRecovery";

        // ------------------------------------------------------------ registry access (the self-test replaces every one)

        /// <summary>Reads one Internet Settings value (null: it cannot be read; then nothing is changed).</summary>
        public static Func<string, ProxyValue?> ReadValue = name =>
        {
            using (var k = Registry.CurrentUser.OpenSubKey(InetKey))
            {
                if (k == null) return ProxyValue.Absent;
                object v = k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                if (v == null) return ProxyValue.Absent;
                var kind = k.GetValueKind(name);
                if (kind == RegistryValueKind.DWord) return ProxyValue.Number((int)v);
                if (kind == RegistryValueKind.String) return ProxyValue.Text((string)v);
                return null;   // another type (binary, expandable, multi-string) is not restored exactly: unsupported
            }
        };
        public static Action<string, ProxyValue> WriteValue = (name, v) =>
        {
            if (!v.Exists) { using (var k = Registry.CurrentUser.OpenSubKey(InetKey, true)) k?.DeleteValue(name, false); return; }
            using (var k = Registry.CurrentUser.CreateSubKey(InetKey))
            {
                if (v.Dword) k.SetValue(name, int.Parse(v.Data, System.Globalization.CultureInfo.InvariantCulture), RegistryValueKind.DWord);
                else k.SetValue(name, v.Data ?? "", RegistryValueKind.String);
            }
        };
        /// <summary>Reads, writes (null: deletes) and flushes a text value of HKCU: the record and the sign-in entry.</summary>
        public static Func<string, string, string> ReadText = (key, name) =>
        {
            using (var k = Registry.CurrentUser.OpenSubKey(key)) return k?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
        };
        public static Action<string, string, string> WriteText = (key, name, value) =>
        {
            if (value == null) { using (var k = Registry.CurrentUser.OpenSubKey(key, true)) k?.DeleteValue(name, false); }
            else using (var k = Registry.CurrentUser.CreateSubKey(key)) k.SetValue(name, value, RegistryValueKind.String);
            using (var k = Registry.CurrentUser.OpenSubKey(key, true)) if (k != null) RegFlushKey(k.Handle.DangerousGetHandle());
        };
        /// <summary>Tells running programs that the proxy changed (the self-test replaces it).</summary>
        public static Action Announce = () =>
        {
            InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);   // INTERNET_OPTION_SETTINGS_CHANGED
            InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);   // INTERNET_OPTION_REFRESH
        };

        [DllImport("advapi32.dll")] static extern int RegFlushKey(IntPtr hKey);
        [DllImport("wininet.dll", SetLastError = true)] static extern bool InternetSetOption(IntPtr h, int option, IntPtr buffer, int len);

        // ------------------------------------------------------------ record

        public static ProxyRecord Read() => ProxyRecord.Parse(ReadText(RecordKey, RecordValue));

        /// <summary>The raw record text exists (also a torn one).</summary>
        public static bool RecordPresent => ReadText(RecordKey, RecordValue) != null;

        /// <summary>The four live values (null when one of them cannot be read or has an unsupported type).</summary>
        public static ProxyValue[] Live()
        {
            var a = new ProxyValue[4];
            for (int i = 0; i < 4; i++)
            {
                var v = ReadValue(Names[i]);
                if (v == null) return null;
                a[i] = v.Value;
            }
            return a;
        }

        /// <summary>The values NSF Shield writes for a proxy address (the automatic configuration script is turned off).</summary>
        public static ProxyValue[] For(string server, string bypass) =>
            new[] { ProxyValue.Number(1), ProxyValue.Text(server), ProxyValue.Text(bypass), ProxyValue.Absent };

        /// <summary>Do the enable flag and the server still equal what NSF Shield wrote (the proxy itself is still NSF Shield's)?</summary>
        public static bool ProxyStillOurs(ProxyRecord r, ProxyValue[] live) =>
            r != null && live != null && live[Enable].SameAs(r.Written[Enable]) && live[Server].SameAs(r.Written[Server]);

        /// <summary>The sign-in entry for the helper (a quoted full path and one fixed argument).</summary>
        public static string HelperCommand(string helperPath) => "\"" + helperPath + "\" --restore";

        /// <summary>
        /// Prepares a change: the record (and, for a sign-in restore, the sign-in entry) is written, flushed and read back. An
        /// existing record of the same owner keeps its backup (the values from before NSF Shield). False: nothing is prepared and
        /// the caller must not change the live setting.
        /// </summary>
        public static bool Arm(ProxyRecord r, string helperCommand, out string error)
        {
            error = null;
            using (var l = Lock())
            {
                try
                {
                    var old = Read();
                    if (old != null && old.Owner != r.Owner) { error = "another-owner"; return false; }
                    if (old == null && RecordPresent) { error = "damaged-record"; return false; }
                    if (old != null) r.Backup = old.Backup;
                    if (r.Backup.Length != 4 || r.Written.Length != 4) { error = "values"; return false; }
                    string text = r.Serialize();
                    WriteText(RecordKey, RecordValue, text);
                    if (ReadText(RecordKey, RecordValue) != text) { Drop(); error = "record-not-verified"; return false; }
                    if (r.AtSignIn)
                    {
                        if (string.IsNullOrEmpty(helperCommand)) { Drop(); error = "no-helper"; return false; }
                        WriteText(RunOnceKey, RunOnceName, helperCommand);
                        if (ReadText(RunOnceKey, RunOnceName) != helperCommand) { Drop(); error = "sign-in-entry-not-verified"; return false; }
                    }
                    return true;
                }
                catch (Exception ex)
                {
                    try { Drop(); } catch { }
                    error = ex.GetType().Name + ": " + ex.Message;
                    return false;
                }
            }
        }

        /// <summary>Removes the record and the sign-in entry. Never touches the proxy values.</summary>
        public static void Drop()
        {
            WriteText(RecordKey, RecordValue, null);
            WriteText(RunOnceKey, RunOnceName, null);
        }

        /// <summary>Writes the values (each write is tried; the first failure is returned, the record stays for a retry).</summary>
        public static bool WriteLive(ProxyValue[] values, out string error)
        {
            error = null;
            for (int i = 0; i < 4; i++)
            {
                try { WriteValue(Names[i], values[i]); }
                catch (Exception ex) { error = Names[i] + ": " + ex.Message; return false; }
            }
            return true;
        }

        public enum Outcome { Restored, UserKept, Failed }

        public sealed class Result
        {
            public Outcome Outcome;
            /// <summary>Values written back, values of the user kept, the first failure.</summary>
            public List<string> RestoredNames = new List<string>(), KeptNames = new List<string>();
            public string Error;
            public override string ToString() =>
                Outcome + (RestoredNames.Count > 0 ? " restored: " + string.Join(",", RestoredNames) : "") +
                (KeptNames.Count > 0 ? " kept (user): " + string.Join(",", KeptNames) : "") + (Error != null ? " error: " + Error : "");
        }

        /// <summary>
        /// Restores the values that are still NSF Shield's and keeps the user's, then reads them back. Restored / UserKept: the
        /// record and the sign-in entries are removed. Failed (unreadable values, a failed write, a value not read back): the
        /// record stays for the next attempt.
        /// </summary>
        public static Result Restore(ProxyRecord r)
        {
            var res = new Result();
            using (var l = Lock())
            {
                try
                {
                    var live = Live();
                    if (live == null) { res.Outcome = Outcome.Failed; res.Error = "unreadable"; return res; }
                    bool serverUser = !live[Server].SameAs(r.Written[Server]) && !live[Server].SameAs(r.Backup[Server]);
                    var planned = new List<int>();
                    for (int i = 0; i < 4; i++)
                    {
                        if (live[i].SameAs(r.Backup[i])) continue;
                        if (live[i].SameAs(r.Written[i]) && !serverUser) planned.Add(i);
                        else res.KeptNames.Add(Names[i]);
                    }
                    foreach (int i in planned)
                    {
                        try { WriteValue(Names[i], r.Backup[i]); }
                        catch (Exception ex) { if (res.Error == null) res.Error = Names[i] + ": " + ex.Message; }
                    }
                    if (planned.Count > 0) { try { Announce(); } catch { } }
                    var after = Live();
                    foreach (int i in planned)
                    {
                        if (after != null && after[i].SameAs(r.Backup[i])) res.RestoredNames.Add(Names[i]);
                        else if (res.Error == null) res.Error = Names[i] + ": not read back";
                    }
                    if (res.Error != null || after == null) { res.Outcome = Outcome.Failed; if (res.Error == null) res.Error = "unreadable after the restore"; return res; }
                    Drop();
                    res.Outcome = res.KeptNames.Count > 0 ? Outcome.UserKept : Outcome.Restored;
                    return res;
                }
                catch (Exception ex)
                {
                    res.Outcome = Outcome.Failed;
                    res.Error = ex.GetType().Name + ": " + ex.Message;
                    return res;
                }
            }
        }

        /// <summary>One restore or preparation at a time (NSF Shield, its guard process and the sign-in helper).</summary>
        public static IDisposable Lock() => new Gate();

        sealed class Gate : IDisposable
        {
            readonly Mutex m;
            readonly bool held;
            public Gate()
            {
                try
                {
                    m = new Mutex(false, LockName);
                    try { held = m.WaitOne(15000); } catch (AbandonedMutexException) { held = true; }
                }
                catch (Exception) { m = null; }
            }
            public void Dispose()
            {
                try { if (held) m.ReleaseMutex(); } catch { }
                m?.Dispose();
            }
        }

        /// <summary>
        /// The sign-in restore of the helper (NSFShieldProxyRecovery.exe --restore): nothing without a complete record; a saved
        /// proxy of the user (no sign-in restore) stays; while NSF Shield runs nothing changes and only the sign-in entry is
        /// renewed; otherwise the per-value restore – on a failure the record stays and the entry is renewed for the next
        /// sign-in. Returns the exit code (0 done or nothing to do, 1 failed) and a note with value names only.
        /// </summary>
        public static (int Code, string Note) SignInRestore(string helperPath, Func<bool> appRunning)
        {
            var rec = Read();
            if (rec == null) return (0, RecordPresent ? "damaged record: nothing changed" : "nothing to restore");
            if (!rec.AtSignIn) return (0, "the proxy is a saved proxy of the user: nothing changed");
            if (appRunning())
            {
                WriteText(RunOnceKey, RunOnceName, HelperCommand(helperPath));
                return (0, "NSF Shield is running: nothing changed");
            }
            var res = Restore(rec);
            if (res.Outcome == Outcome.Failed)
            {
                WriteText(RunOnceKey, RunOnceName, HelperCommand(helperPath));
                return (1, "failed, kept for the next sign-in: " + res.Error);
            }
            return (0, res.ToString());
        }

        /// <summary>Is a NSF Shield window running in this session (its single-instance lock exists)?</summary>
        public static bool AppRunning()
        {
            try
            {
                if (Mutex.TryOpenExisting(@"Local\NSFShield_SingleInstance", out var m)) { m.Dispose(); return true; }
                return false;
            }
            catch (UnauthorizedAccessException) { return true; }   // it exists (created by the elevated app)
            catch (Exception) { return false; }
        }
    }
}
