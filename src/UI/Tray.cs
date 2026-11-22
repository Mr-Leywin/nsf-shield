using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NSFShield
{
    /// <summary>What the tray icon shows.</summary>
    enum TrayStatus { Off, Busy, Active, Warning, Error }

    static class TrayLook
    {
        /// <summary>
        /// Green = protection active, gray = off, amber = starting/stopping, orange = active with a warning (e.g. a driver
        /// or connection problem was detected), red = error.
        /// </summary>
        public static TrayStatus From(EngineState s, IEnumerable<Severity> problems)
        {
            switch (s)
            {
                case EngineState.Error: return TrayStatus.Error;
                case EngineState.Starting:
                case EngineState.Stopping: return TrayStatus.Busy;
                case EngineState.Running:
                    return problems.Any(p => p == Severity.Warning || p == Severity.Error) ? TrayStatus.Warning : TrayStatus.Active;
                default: return TrayStatus.Off;
            }
        }

        public static TrayStatus Current() =>
            From(App.Engine.State, App.Problems.Snapshot().Where(p => p.Info != null).Select(p => p.Info.Severity));

        public static Icon MakeIcon(TrayStatus t, int size)
        {
            Color top, bottom;
            IconArt.Glyph glyph;
            switch (t)
            {
                case TrayStatus.Active: (top, bottom, glyph) = IconArt.StateLook(EngineState.Running); break;
                case TrayStatus.Busy: (top, bottom, glyph) = IconArt.StateLook(EngineState.Starting); break;
                case TrayStatus.Error: (top, bottom, glyph) = IconArt.StateLook(EngineState.Error); break;
                case TrayStatus.Warning: top = Color.FromArgb(253, 160, 72); bottom = Color.FromArgb(194, 65, 12); glyph = IconArt.Glyph.Exclaim; break;
                default: (top, bottom, glyph) = IconArt.StateLook(EngineState.Stopped); break;
            }
            using (var bmp = IconArt.ShieldBitmap(size, top, bottom, glyph)) return IconArt.MakeIcon(bmp);
        }
    }

    /// <summary>One entry of a quick-switch submenu in the tray.</summary>
    sealed class TrayChoice
    {
        public string Id, Label, Group, Tip = "";
        public bool Checked, Enabled = true;
    }

    /// <summary>A quick-switch submenu of the tray menu (engine, profiles of that engine).</summary>
    interface ITrayChoices
    {
        /// <summary>Locale key of the submenu title.</summary>
        string TitleKey { get; }
        IEnumerable<TrayChoice> Items();
        Task SelectAsync(string id);
    }

    /// <summary>Quick engine switch: GoodbyeDPI, Zapret (winws), ByeDPI (ciadpi); the active one is checked.</summary>
    sealed class EngineTrayChoices : ITrayChoices
    {
        public string TitleKey => "tray.engine";

        public IEnumerable<TrayChoice> Items()
        {
            bool busy = Actions.Scanning || App.Engine.State == EngineState.Starting || App.Engine.State == EngineState.Stopping;
            var cur = App.Engine.Current.Kind;
            return Engines.All.Select(e => new TrayChoice
            {
                Id = e.Kind.ToString(), Label = e.DisplayName, Group = "engines", Tip = Loc.T("engines." + e.Id + ".tip"),
                Checked = e.Kind == cur, Enabled = !busy && e.Available(out _),
            });
        }

        public async Task SelectAsync(string id)
        {
            if (Enum.TryParse(id, out EngineKind k)) await Actions.SelectEngineAsync(k);
        }
    }

    /// <summary>
    /// The recommended profiles of the active engine, and the selected / running specialized or custom profile once (the same
    /// rule as the home page and the profiles page: <see cref="ProfileCatalog.Visible"/>, in its compact form).
    /// </summary>
    sealed class ProfileTrayChoices : ITrayChoices
    {
        public string TitleKey => "tray.method";

        public IEnumerable<TrayChoice> Items()
        {
            bool busy = Actions.Scanning || App.Engine.State == EngineState.Starting || App.Engine.State == EngineState.Stopping;
            var running = App.Engine.IsActive ? App.Engine.ActiveProfile?.Id : null;
            return ProfileCatalog.Visible(App.AllProfiles, UiLevel.Standard, false, App.Engine.Current.Kind, App.Settings.SelectedProfileId, running)
                .Select(p => new TrayChoice
                {
                    Id = p.Id, Label = p.Name, Group = p.Tier.ToString(), Tip = p.Description,
                    Checked = p.Id == App.Settings.SelectedProfileId, Enabled = !busy,
                });
        }

        public async Task SelectAsync(string id)
        {
            var p = App.AllProfiles.FirstOrDefault(x => x.Id == id);
            if (p != null) await Actions.SelectProfileAsync(p);
        }
    }

    static class TrayMenus
    {
        /// <summary>The quick-switch submenus, in menu order.</summary>
        public static readonly List<ITrayChoices> Choices = new List<ITrayChoices> { new EngineTrayChoices(), new ProfileTrayChoices() };

        /// <summary>Fills a submenu from its choices (separators between groups, the active entry checked).</summary>
        public static void Fill(ToolStripMenuItem menu, ITrayChoices source, ToolStripRenderer renderer)
        {
            menu.DropDownItems.Clear();
            string lastGroup = null;
            foreach (var c in source.Items())
            {
                if (lastGroup != null && c.Group != lastGroup) menu.DropDownItems.Add(new ToolStripSeparator());
                lastGroup = c.Group;
                string id = c.Id;
                var it = new ToolStripMenuItem(c.Label) { Checked = c.Checked, Enabled = c.Enabled, ToolTipText = c.Tip };
                it.Click += async (s, e) => await source.SelectAsync(id);
                menu.DropDownItems.Add(it);
            }
            if (menu.DropDown is ToolStripDropDownMenu dd) { dd.Renderer = renderer; dd.ShowItemToolTips = true; }
        }
    }
}
