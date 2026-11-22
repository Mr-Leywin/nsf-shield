using System;
using System.Drawing;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static NSFShield.Theme;

namespace NSFShield
{
    /// <summary>"Switch to the installed version": download and verify Setup.exe, install, carry the settings over, reopen.</summary>
    sealed class SwitchDialog : Form
    {
        readonly string localPath, localSha;
        readonly Label status;
        readonly ProgressLine bar;
        readonly FlatBtn bGo, bClose;
        CancellationTokenSource cts;
        bool busy, installing;

        /// <param name="localPath">Test hook: a local setup package with its SHA-256 instead of the GitHub release.</param>
        public static void Run(IWin32Window owner, string localPath = null, string localSha = null)
        {
            using (var d = new SwitchDialog(localPath, localSha)) d.ShowDialog(owner);
        }

        SwitchDialog(string localPath, string localSha)
        {
            this.localPath = localPath;
            this.localSha = localSha;
            Text = Loc.T("switch.title") + " – " + App.Name;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = MinimizeBox = false;
            ShowInTaskbar = false;
            AutoScaleMode = AutoScaleMode.None;
            BackColor = Bg;
            Font = Body;
            ClientSize = new Size(D(600), D(384));
            UIx.FitDialog(this);
            Icon = IconArt.AppIcon(32);

            Controls.Add(UIx.L(Loc.T("switch.title"), H2, Theme.Text, 24, 16, 550, 30));
            Controls.Add(UIx.L(Loc.T("switch.subtitle"), Small, Muted, 25, 48, 550, 36));
            var card = new Card { Bounds = R(24, 90, 552, 168) };
            Controls.Add(card);
            var steps = card.Add(new ReportBox { Bounds = R(16, 12, 520, 146) });
            steps.BackColor = Theme.Card;
            steps.Out(Loc.T("switch.stepsTitle"), Muted, Theme.Caption);
            for (int i = 1; i <= 4; i++) steps.Out(i + ".  " + Loc.T("switch.step" + i), Theme.Text, Small);
            steps.Blank();
            steps.Out(Loc.T(localPath != null ? "switch.sourceLocal" : "switch.sourceGithub", localPath ?? ""), Muted, Small);
            steps.SelectionStart = 0;

            status = UIx.L(Loc.T("switch.ready"), Small, Muted, 24, 266, 552, 50);
            Controls.Add(status);
            bar = new ProgressLine { Bounds = R(24, 318, 552, 6), BackColor = Bg, Visible = false };
            Controls.Add(bar);
            bGo = new FlatBtn { Text = Loc.T("switch.go"), Glyph = GShield, Kind = FlatBtn.Kinds.Primary, Bounds = R(24, 332, 250, 40) };
            bClose = new FlatBtn { Text = Loc.T("common.cancel"), Kind = FlatBtn.Kinds.Secondary, Bounds = R(456, 332, 120, 40) };
            Controls.AddRange(new Control[] { bGo, bClose });
            ActiveControl = bGo;
            bGo.Click += async (s, e) => await DoSwitch();
            bClose.Click += (s, e) => Close();
        }

#if PREVIEW
        /// <summary>Screenshots: the switch window, or the window shown in the installed copy after the switch.</summary>
        internal static Form DebugCreate(bool done) => done ? (Form)new DoneDialog() : new SwitchDialog(null, null);
#endif

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            Native.DarkTitle(Handle, IsDark);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // the download can be cancelled; once the setup package runs, the window waits for it
            if (busy) { if (!installing) cts?.Cancel(); e.Cancel = true; return; }
            base.OnFormClosing(e);
        }

        void Say(string text, Color color)
        {
            status.Text = text;
            status.ForeColor = color;
        }

        async Task DoSwitch()
        {
            if (App.Preview) { Say(Loc.T("switch.previewOnly"), AmberText); return; }
            busy = true;
            bGo.Enabled = false;
            bar.Visible = true;
            cts = new CancellationTokenSource();
            try
            {
                Updater.Prepared prep;
#if PREVIEW
                // the local setup package hook exists in the test build only (never in NSFShield.exe)
                if (localPath != null)
                {
                    Say(Loc.T("switch.verifyingLocal"), Muted);
                    prep = await Task.Run(() => InstallerSwitch.PrepareLocal(localPath, localSha));
                }
                else
#endif
                {
                    Say(Loc.T("switch.checking"), Muted);
                    string err = "";
                    var info = await Task.Run(() => Updater.Check(out err));
                    if (info == null) throw new InvalidOperationException(err);
                    if (!InstallerSwitch.Usable(info, out err)) throw new InvalidOperationException(err);
                    Action<long, long> progress = (got, total) =>
                    {
                        try
                        {
                            BeginInvoke(new Action(() =>
                            {
                                if (IsDisposed) return;
                                bar.Value = total > 0 ? got / (float)total : 0;
                                Say(Loc.T("updateDialog.downloadingKb", got / 1024, total / 1024), Muted);
                            }));
                        }
                        catch (Exception ex) { App.Ignored("Progress could not be shown", ex); }
                    };
                    prep = await Task.Run(() => InstallerSwitch.Download(info, progress, cts.Token));
                }

                installing = true;
                bClose.Enabled = false;
                bar.Value = 1;
                Say(Loc.T("switch.installing"), Muted);
                int rc = await Task.Run(() => InstallerSwitch.RunSetup(prep, CancellationToken.None));
                if (rc != 0) throw new InvalidOperationException(Loc.T("switch.setupFailed", rc));

                Say(Loc.T("switch.transferring"), Muted);
                string dir = await Task.Run(() => InstallerSwitch.InstalledDir(out _));
                if (dir == null)
                {
                    InstallerSwitch.InstalledDir(out string why);
                    throw new InvalidOperationException(why);
                }
                await Task.Run(() => InstallerSwitch.Transfer(App.Settings, dir, App.DataDir));
                History.Add(new HistoryEntry { Time = DateTime.Now, Kind = "update", Profile = App.Version, Ok = 1, Total = 1, Running = App.Engine.IsActive, Note = "portable → " + dir });

                Say(Loc.T("switch.opening"), GreenText);
                await Task.Delay(500);
                InstallerSwitch.StartInstalled(dir);
                busy = false;
                App.Log("Switched to the installed version: " + dir + ". This portable copy closes; its folder can be deleted.", LogLevel.Success);
                MainForm.Instance.ExitApp(false);
            }
            catch (OperationCanceledException)
            {
                Say(Loc.T("updateDialog.cancelled"), Muted);
                Reset();
            }
            catch (Exception ex)
            {
                App.Log("Switch to the installed version failed: " + ex.Message, LogLevel.Error);
                Say(Loc.T("switch.failed", ex.Message), RedText);
                Reset();
            }
        }

        void Reset()
        {
            busy = installing = false;
            if (IsDisposed) return;
            bGo.Enabled = bClose.Enabled = true;
            bClose.Text = Loc.T("common.close");
            bar.Visible = false;
        }

        // ================================================================ in the installed copy, after the switch

        /// <summary>First start after the switch: offers the background service and start with Windows.</summary>
        public static void ShowDone(IWin32Window owner)
        {
            using (var d = new DoneDialog()) d.ShowDialog(owner);
        }

        sealed class DoneDialog : Form
        {
            readonly CheckX cStart, cService;
            readonly Label status;
            readonly FlatBtn bOn, bLater;

            public DoneDialog()
            {
                Text = App.Name;
                FormBorderStyle = FormBorderStyle.FixedDialog;
                StartPosition = FormStartPosition.CenterParent;
                MaximizeBox = MinimizeBox = false;
                ShowInTaskbar = false;
                AutoScaleMode = AutoScaleMode.None;
                BackColor = Bg;
                Font = Body;
                ClientSize = new Size(D(560), D(330));
                UIx.FitDialog(this);
                Icon = IconArt.AppIcon(32);

                Controls.Add(UIx.L(Loc.T("switch.doneTitle"), H2, Theme.Text, 24, 16, 510, 30));
                Controls.Add(UIx.L(Loc.T("switch.doneText"), Small, Muted, 25, 50, 510, 58));
                var card = new Card { Bounds = R(24, 116, 512, 120) };
                Controls.Add(card);
                cStart = card.Add(new CheckX { Text = Loc.T("settingsPage.startWin"), Bounds = R(18, 16, 470, 26), Checked = true });
                card.Add(UIx.L(Loc.T("switch.startInfo"), Small, Muted, 46, 42, 450, 20));
                cService = card.Add(new CheckX { Text = Loc.T("settingsPage.service"), Bounds = R(18, 68, 470, 26) });
                card.Add(UIx.L(Loc.T("switch.serviceInfo"), Small, Muted, 46, 94, 450, 20));
                status = UIx.L("", Small, Muted, 24, 242, 512, 30);
                Controls.Add(status);
                bOn = new FlatBtn { Text = Loc.T("switch.turnOn"), Glyph = GCheck, Kind = FlatBtn.Kinds.Primary, Bounds = R(24, 276, 200, 40) };
                bLater = new FlatBtn { Text = Loc.T("updateDialog.later"), Kind = FlatBtn.Kinds.Secondary, Bounds = R(416, 276, 120, 40) };
                Controls.AddRange(new Control[] { bOn, bLater });
                bOn.Click += async (s, e) => await TurnOn();
                bLater.Click += (s, e) => Close();
            }

            protected override void OnHandleCreated(EventArgs e)
            {
                base.OnHandleCreated(e);
                Native.DarkTitle(Handle, IsDark);
            }

            async Task TurnOn()
            {
                bOn.Enabled = bLater.Enabled = false;
                status.ForeColor = Muted;
                status.Text = Loc.T("switch.turningOn");
                var problems = new System.Collections.Generic.List<string>();
                if (cStart.Checked && !App.Settings.StartWithWindows)
                {
                    string err = null;
                    if (await Task.Run(() => Startup.Enable(out err))) App.Settings.StartWithWindows = true;
                    else { App.Problems.Report("NSF-703", err); problems.Add(Loc.T("settingsPage.taskFailed") + " " + err); }
                }
                if (cService.Checked && !App.Settings.ServiceMode)
                {
                    App.Settings.ServiceMode = true;
                    App.Save();
                    await Actions.StartAsync();
                    if (App.Engine.State != EngineState.Running)
                    {
                        App.Settings.ServiceMode = false;
                        await Task.Run(() => App.Engine.UninstallService());
                        problems.Add(Loc.T("settingsPage.serviceFailed") + " " + App.Engine.LastErrorCode);
                        await Actions.StartAsync();
                    }
                }
                App.Save();
                App.RaiseStatus();
                if (IsDisposed) return;
                if (problems.Count == 0) { Close(); return; }
                status.ForeColor = AmberText;
                status.Text = string.Join(" ", problems);
                bLater.Enabled = true;
                bLater.Text = Loc.T("common.close");
            }
        }
    }
}
