using System;
using System.Diagnostics;
using System.Globalization;

namespace NSFShield.Recovery
{
    /// <summary>
    /// NSFShieldProxyRecovery.exe --restore: started once by Windows at the next sign-in (HKCU RunOnce) when NSF Shield's ByeDPI
    /// engine had pointed the Windows proxy at its local bridge and the app could not undo it (power loss, crash before the
    /// guard). It runs as the signed-in user (asInvoker, no window, no network, no script host) and only applies the same
    /// per-value rules as the app (src\Core\ProxyRecovery.cs): values NSF Shield wrote go back, values the user changed stay.
    /// While NSF Shield runs it changes nothing and only renews its sign-in entry (the app restores the proxy itself).
    /// Exit codes: 0 done or nothing to do, 1 the restore failed (the record and a new sign-in entry stay), 2 usage.
    /// </summary>
    static class Program
    {
        const string LastValue = "ProxyRecoveryLast";

        static int Main(string[] args)
        {
            if (args.Length != 1 || args[0] != "--restore") return 2;
            try
            {
                // the same decision and restore code as the app (src\Core\ProxyRecovery.cs, tested by its self-test): a record
                // that is not complete never leads to a change on a guess; while NSF Shield runs, nothing changes
                string self = Process.GetCurrentProcess().MainModule.FileName;
                var (code, note) = ProxyRecovery.SignInRestore(self, ProxyRecovery.AppRunning);
                Note(note);
                return code;
            }
            catch (Exception ex)
            {
                try { Note("failed: " + ex.GetType().Name); } catch { }
                return 1;
            }
        }

        /// <summary>The last result for NSF Shield's log (value names only, never an address).</summary>
        static void Note(string text) =>
            ProxyRecovery.WriteText(ProxyRecovery.RecordKey, LastValue, DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture) + " " + text);
    }
}
