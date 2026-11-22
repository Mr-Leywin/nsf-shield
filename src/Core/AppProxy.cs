using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace NSFShield
{
    public enum AppProxyMode { Chromium, Discord, Firefox, Env }

    /// <summary>A rule that makes only a specific program use a proxy.</summary>
    public class ProxyApp
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Name { get; set; } = "";
        public string ExePath { get; set; } = "";
        public string ExtraArgs { get; set; } = "";
        public string ProxyId { get; set; } = "";
        public AppProxyMode Mode { get; set; } = AppProxyMode.Env;
        /// <summary>A separate profile for browsers (so a proxied window can open while the browser is already open).</summary>
        public bool SeparateProfile { get; set; } = true;
        /// <summary>Close the open copies of the program before opening it (for single-instance programs).</summary>
        public bool CloseRunning { get; set; } = true;

        public string ModeLabel
        {
            get
            {
                switch (Mode)
                {
                    case AppProxyMode.Discord: return "Discord (--proxy-server)";
                    case AppProxyMode.Chromium: return "Chromium/Electron (--proxy-server)";
                    case AppProxyMode.Firefox: return Loc.T("appProxy.mode.firefox");
                    default: return Loc.T("appProxy.mode.env");
                }
            }
        }
    }

    /// <summary>Starting the selected program with a proxy: command line, profile or environment variables depending on the type.</summary>
    public static class AppProxy
    {
        static string Local => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        static string Roaming => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        static string PF => Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        static string PF86 => Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);

        /// <summary>Separate proxy profiles of the programs (in a place the user can write to).</summary>
        public static string ProfileRoot
        {
            get
            {
                return Path.Combine(Local, "NSF Shield", "profiles");
            }
        }

        /// <summary>Possible installation places of known programs.</summary>
        public static List<(string Name, string Path)> Installed()
        {
            var c = new List<(string, string)>
            {
                ("Discord", Path.Combine(Local, "Discord", "Update.exe")),
                ("Discord PTB", Path.Combine(Local, "DiscordPTB", "Update.exe")),
                ("Google Chrome", Path.Combine(PF, @"Google\Chrome\Application\chrome.exe")),
                ("Google Chrome", Path.Combine(PF86, @"Google\Chrome\Application\chrome.exe")),
                ("Google Chrome", Path.Combine(Local, @"Google\Chrome\Application\chrome.exe")),
                ("Microsoft Edge", Path.Combine(PF86, @"Microsoft\Edge\Application\msedge.exe")),
                ("Microsoft Edge", Path.Combine(PF, @"Microsoft\Edge\Application\msedge.exe")),
                ("Brave", Path.Combine(PF, @"BraveSoftware\Brave-Browser\Application\brave.exe")),
                ("Brave", Path.Combine(Local, @"BraveSoftware\Brave-Browser\Application\brave.exe")),
                ("Opera", Path.Combine(Local, @"Programs\Opera\opera.exe")),
                ("Opera GX", Path.Combine(Local, @"Programs\Opera GX\opera.exe")),
                ("Vivaldi", Path.Combine(Local, @"Vivaldi\Application\vivaldi.exe")),
                ("Yandex Browser", Path.Combine(Local, @"Yandex\YandexBrowser\Application\browser.exe")),
                ("Mozilla Firefox", Path.Combine(PF, @"Mozilla Firefox\firefox.exe")),
                ("Mozilla Firefox", Path.Combine(PF86, @"Mozilla Firefox\firefox.exe")),
                ("Spotify", Path.Combine(Roaming, @"Spotify\Spotify.exe")),
                ("Slack", Path.Combine(Local, @"slack\slack.exe")),
                ("Visual Studio Code", Path.Combine(Local, @"Programs\Microsoft VS Code\Code.exe")),
            };
            return c.Where(x => File.Exists(x.Item2)).GroupBy(x => x.Item1).Select(g => g.First()).ToList();
        }

        /// <summary>Guesses how the program will receive the proxy.</summary>
        public static AppProxyMode Detect(string exe)
        {
            string name = Path.GetFileName(exe ?? "").ToLowerInvariant();
            string dir = Path.GetDirectoryName(exe ?? "") ?? "";
            if (name == "update.exe" && dir.IndexOf("discord", StringComparison.OrdinalIgnoreCase) >= 0) return AppProxyMode.Discord;
            if (name.StartsWith("discord")) return AppProxyMode.Discord;
            if (name == "firefox.exe" || name == "librewolf.exe" || name == "waterfox.exe") return AppProxyMode.Firefox;
            string[] chromium = { "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe", "browser.exe", "spotify.exe", "slack.exe", "code.exe", "chromium.exe" };
            if (chromium.Contains(name)) return AppProxyMode.Chromium;
            // Electron/Chromium based programs carry these files next to them
            try
            {
                if (File.Exists(Path.Combine(dir, "resources.pak")) || File.Exists(Path.Combine(dir, "chrome_100_percent.pak")) ||
                    File.Exists(Path.Combine(dir, "v8_context_snapshot.bin")) || File.Exists(Path.Combine(dir, "icudtl.dat")))
                    return AppProxyMode.Chromium;
                // installations with version folders (e.g. Opera, Edge: Application\<version>\resources.pak)
                if (Directory.Exists(dir) && Directory.GetDirectories(dir).Any(d => File.Exists(Path.Combine(d, "resources.pak"))))
                    return AppProxyMode.Chromium;
            }
            catch (Exception ign) { App.Ignored("Program type could not be detected", ign); }
            return AppProxyMode.Env;
        }

        static bool IsBrowser(ProxyApp a)
        {
            string n = Path.GetFileName(a.ExePath).ToLowerInvariant();
            return a.Mode == AppProxyMode.Firefox || new[] { "chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe", "browser.exe", "chromium.exe" }.Contains(n);
        }

        /// <summary>Does this rule need the local bridge? (a proxy with a password, or a method that does not support SOCKS5 directly)</summary>
        public static bool NeedsBridge(ProxyApp a, ProxyEntry p) =>
            p.HasAuth || (a.Mode == AppProxyMode.Env && p.Kind == ProxyKind.Socks5);

        /// <summary>Proxy address given to the program.</summary>
        public static string ProxyUrl(ProxyApp a, ProxyEntry p) => NeedsBridge(a, p) ? ProxyBridge.LocalUrl(p) : p.Scheme + "://" + p.Address;

        static string ProfileDir(ProxyApp a) => Path.Combine(ProfileRoot, Scripts.Slug(a.Name.Length > 0 ? a.Name : Path.GetFileNameWithoutExtension(a.ExePath)) + "-" + a.Id.Substring(0, 6));

        /// <summary>Start plan: target file, parameters, working folder, window state.</summary>
        public static (string Target, string Args, string WorkDir, int WindowStyle) Plan(ProxyApp a, ProxyEntry p)
        {
            string url = ProxyUrl(a, p);
            string extra = string.IsNullOrWhiteSpace(a.ExtraArgs) ? "" : " " + a.ExtraArgs.Trim();
            string exe = a.ExePath;
            if (CmdLine.HasControlChars(extra) || CmdLine.HasControlChars(exe) || CmdLine.HasControlChars(url))
                throw new ArgumentException(Loc.T("appProxy.invalidChars"));
            string wd = Path.GetDirectoryName(exe);
            switch (a.Mode)
            {
                case AppProxyMode.Discord:
                    {
                        string upd = exe;
                        string flavor = "Discord";
                        if (!Path.GetFileName(exe).Equals("Update.exe", StringComparison.OrdinalIgnoreCase))
                        {
                            // ...\Discord\app-1.0.x\Discord.exe → ...\Discord\Update.exe
                            flavor = Path.GetFileNameWithoutExtension(exe);
                            var root = Directory.GetParent(wd)?.FullName ?? wd;
                            upd = Path.Combine(root, "Update.exe");
                            wd = root;
                        }
                        else
                        {
                            string folder = Path.GetFileName(wd);
                            flavor = folder.Equals("DiscordPTB", StringComparison.OrdinalIgnoreCase) ? "DiscordPTB"
                                   : folder.Equals("DiscordCanary", StringComparison.OrdinalIgnoreCase) ? "DiscordCanary" : "Discord";
                        }
                        return (upd, "--processStart " + flavor + ".exe --process-start-args \"--proxy-server=" + url + extra.Replace("\"", "") + "\"", wd, 1);
                    }
                case AppProxyMode.Chromium:
                    {
                        string args = "--proxy-server=\"" + url + "\"";
                        if (a.SeparateProfile && IsBrowser(a)) args += " --user-data-dir=\"" + ProfileDir(a) + "\" --no-first-run";
                        return (exe, args + extra, wd, 1);
                    }
                case AppProxyMode.Firefox:
                    {
                        string dir = ProfileDir(a);
                        WriteFirefoxPrefs(dir, a, p);
                        return (exe, "-no-remote -profile \"" + dir + "\"" + extra, wd, 1);
                    }
                default:
                    {
                        // start with environment variables (cmd opens minimized and closes right away).
                        // every value that goes on the cmd command line is checked: quoted ones (path, address) cannot contain quote/percent/exclamation,
                        // unquoted extra parameters cannot contain & | < > ^ % !; otherwise a command could be injected.
                        if (!CmdLine.QuotedSafe(exe)) throw new ArgumentException(Loc.T("appProxy.badExePath"));
                        if (!CmdLine.QuotedSafe(url)) throw new ArgumentException(Loc.T("appProxy.badProxyUrl"));
                        if (!CmdLine.BareSafe(extra)) throw new ArgumentException(Loc.T("appProxy.badExtraArgs"));
                        string cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
                        var sb = new StringBuilder("/c ");
                        foreach (var v in new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy" })
                            sb.Append("set \"" + v + "=" + url + "\" && ");
                        sb.Append("set \"NO_PROXY=localhost,127.0.0.1\" && start \"\" \"" + exe + "\"" + extra);
                        return (cmd, sb.ToString(), wd, 7);
                    }
            }
        }

        static void WriteFirefoxPrefs(string dir, ProxyApp a, ProxyEntry p)
        {
            Directory.CreateDirectory(dir);
            bool bridge = NeedsBridge(a, p);
            string host = bridge ? "127.0.0.1" : p.Host;
            int port = bridge ? p.LocalPort : p.Port;
            bool socks = !bridge && p.Kind == ProxyKind.Socks5;
            var sb = new StringBuilder();
            sb.AppendLine("// written by NSF Shield – this profile only works with the proxy");
            sb.AppendLine("user_pref(\"network.proxy.type\", 1);");
            if (socks)
            {
                sb.AppendLine("user_pref(\"network.proxy.socks\", \"" + host + "\");");
                sb.AppendLine("user_pref(\"network.proxy.socks_port\", " + port + ");");
                sb.AppendLine("user_pref(\"network.proxy.socks_version\", 5);");
                sb.AppendLine("user_pref(\"network.proxy.socks_remote_dns\", true);");
                sb.AppendLine("user_pref(\"network.proxy.http\", \"\");");
                sb.AppendLine("user_pref(\"network.proxy.share_proxy_settings\", false);");
            }
            else
            {
                sb.AppendLine("user_pref(\"network.proxy.http\", \"" + host + "\");");
                sb.AppendLine("user_pref(\"network.proxy.http_port\", " + port + ");");
                sb.AppendLine("user_pref(\"network.proxy.ssl\", \"" + host + "\");");
                sb.AppendLine("user_pref(\"network.proxy.ssl_port\", " + port + ");");
                sb.AppendLine("user_pref(\"network.proxy.share_proxy_settings\", true);");
                sb.AppendLine("user_pref(\"network.proxy.socks\", \"\");");
            }
            sb.AppendLine("user_pref(\"network.proxy.no_proxies_on\", \"localhost, 127.0.0.1\");");
            sb.AppendLine("user_pref(\"network.trr.mode\", 0);");
            sb.AppendLine("user_pref(\"browser.shell.checkDefaultBrowser\", false);");
            sb.AppendLine("user_pref(\"browser.aboutwelcome.enabled\", false);");
            File.WriteAllText(Path.Combine(dir, "user.js"), sb.ToString(), new UTF8Encoding(false));
        }

        /// <summary>Creates a .lnk shortcut for the rule.</summary>
        public static string CreateShortcut(ProxyApp a, ProxyEntry p, string path)
        {
            var (target, args, wd, style) = Plan(a, p);
            if (!File.Exists(target)) throw new FileNotFoundException(Loc.T("appProxy.notFound") + " " + target);
            var t = Type.GetTypeFromProgID("WScript.Shell");
            object sh = Activator.CreateInstance(t);
            try
            {
                object lnk = t.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, sh, new object[] { path });
                var lt = lnk.GetType();
                void Set(string prop, object v) => lt.InvokeMember(prop, BindingFlags.SetProperty, null, lnk, new[] { v });
                Set("TargetPath", target);
                Set("Arguments", args);
                Set("WorkingDirectory", wd ?? "");
                Set("WindowStyle", style);
                Set("IconLocation", a.Mode == AppProxyMode.Discord ? target + ",0" : a.ExePath + ",0");
                Set("Description", a.Name + " – " + p.KindLabel + " proxy " + p.Address + " (NSF Shield)");
                lt.InvokeMember("Save", BindingFlags.InvokeMethod, null, lnk, null);
                Marshal.FinalReleaseComObject(lnk);
            }
            finally { Marshal.FinalReleaseComObject(sh); }
            return path;
        }

        /// <summary>
        /// Is a running process (by its full image path) a copy of the rule's program? The exact exe path for every mode; for
        /// Discord started through Update.exe, the Discord exe inside that installation's own "app-x.y.z" folder.
        /// </summary>
        internal static bool IsCopyOf(ProxyApp a, string runningPath)
        {
            if (string.IsNullOrEmpty(runningPath) || string.IsNullOrEmpty(a?.ExePath)) return false;
            if (PathSafety.Same(runningPath, a.ExePath)) return true;
            if (a.Mode != AppProxyMode.Discord || !Path.GetFileName(a.ExePath).Equals("Update.exe", StringComparison.OrdinalIgnoreCase)) return false;
            string root = Path.GetDirectoryName(Path.GetFullPath(a.ExePath));
            string flavor = Path.GetFileName(root);
            string dir = Path.GetDirectoryName(Path.GetFullPath(runningPath));
            return string.Equals(Path.GetFileName(runningPath), flavor + ".exe", StringComparison.OrdinalIgnoreCase) &&
                   Path.GetFileName(dir).StartsWith("app-", StringComparison.OrdinalIgnoreCase) && PathSafety.Same(Path.GetDirectoryName(dir), root);
        }

        /// <summary>The running copies of the rule's program, told apart by their full path; a process whose path cannot be read is kept.</summary>
        static List<ProcEntry> RunningOf(ProxyApp a)
        {
            string name = a.Mode == AppProxyMode.Discord
                ? (Path.GetFileName(a.ExePath).Equals("Update.exe", StringComparison.OrdinalIgnoreCase) ? Path.GetFileName(Path.GetDirectoryName(a.ExePath)) : Path.GetFileNameWithoutExtension(a.ExePath))
                : Path.GetFileNameWithoutExtension(a.ExePath);
            return ProcReader.ByNames(new[] { name }).Where(pe => IsCopyOf(a, pe.Path)).ToList();
        }

        /// <summary>Starts the program with the proxy, with normal user rights.</summary>
        public static bool Launch(ProxyApp a, ProxyEntry p, out string message)
        {
            try
            {
                if (!File.Exists(a.ExePath)) { message = Loc.T("appProxy.notFound") + " " + a.ExePath; return false; }
                if (NeedsBridge(a, p) && !ProxyBridge.Ensure(p, out var err)) { message = err; return false; }
                bool browserProfile = a.SeparateProfile && IsBrowser(a);
                if (a.CloseRunning && !browserProfile && a.Mode != AppProxyMode.Firefox)
                {
                    // only copies of exactly this program (full path); a program with the same name elsewhere is never closed
                    var procs = RunningOf(a);
                    foreach (var pe in procs)
                        try { ProcReader.TerminateIf(pe.Pid, path => IsCopyOf(a, path), out _); }
                        catch (Exception ign) { App.Ignored("Program could not be closed", ign); }
                    if (procs.Count > 0) Thread.Sleep(1200);
                }
                string lnk = Path.Combine(Path.GetTempPath(), "NSFShield-" + Scripts.Slug(a.Name) + "-proxy.lnk");
                CreateShortcut(a, p, lnk);
                bool ok = Sys.OpenAsUser(lnk);
                message = ok ? Loc.T(NeedsBridge(a, p) ? "appProxy.openingBridge" : "appProxy.opening", a.Name, p.KindLabel, p.Address)
                             : Loc.T("appProxy.startFailed", a.Name);
                App.Log(message, ok ? LogLevel.Success : LogLevel.Warn);
                return ok;
            }
            catch (Exception ex)
            {
                message = Loc.T("appProxy.openFailed", a.Name) + " " + ex.Message;
                App.Log(message, LogLevel.Warn);
                return false;
            }
        }
    }
}
