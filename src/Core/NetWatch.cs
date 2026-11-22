using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;

namespace NSFShield
{
    /// <summary>Encrypted DNS of the Windows DNS server in use: the saved backups of NSF Shield are not proof of it.</summary>
    public enum DohState { Unknown, Unsupported, Configured, NotConfigured }

    /// <summary>A read-only picture of the network: the adapter of the internet route and the Windows DNS choice on it.</summary>
    public sealed class NetState
    {
        public bool Online;
        /// <summary>The adapter that carries the internet route (null: none, or several and the route could not be read).</summary>
        public string AdapterId, AdapterName, AdapterType;
        public bool AdapterIsVpn;
        /// <summary>True when the adapter was picked by the routing table (not by list order).</summary>
        public bool RouteKnown;
        /// <summary>Adapters that could carry the route.</summary>
        public int Candidates;
        /// <summary>"auto", a provider id, "custom", "mixed" (several adapters, different settings) or null (unknown).</summary>
        public string DnsChoice;
        public DohState Doh;
        /// <summary>Equal keys are the same state (a repeated event for the same state is not shown again).</summary>
        public string Key => string.Join("|", Online, AdapterId ?? "-", DnsChoice ?? "-", Doh, RouteKnown, Candidates);
    }

    /// <summary>Reads <see cref="NetState"/> (live: adapters, route table, the adapter's DNS registry values, 'netsh dns show encryption').</summary>
    public static class NetStateReader
    {
        static readonly Dictionary<string, (DohState State, DateTime At)> dohCache = new Dictionary<string, (DohState, DateTime)>();

        public static NetState Read(bool fresh)
        {
            var all = NetTest.Adapters();
            var targets = all.Where(a => a.Gateways.Count > 0 || a.V4.Count > 0).ToList();
            int? best = Routes.BestInterfaceIndex();
            return Pick(targets, best, a => SystemDns.CurrentChoiceId(a), id => DohFor(id, fresh));
        }

        /// <summary>
        /// The decision (also used by the self-test): the routing table picks the adapter; with one candidate that one is used;
        /// with several and no route, no adapter is claimed and the DNS choice is "mixed" unless they all agree.
        /// </summary>
        public static NetState Pick(List<AdapterInfo> targets, int? bestIndex, Func<AdapterInfo, string> choiceOf, Func<string, DohState> dohOf)
        {
            var s = new NetState { Online = targets.Any(a => a.Gateways.Count > 0), Candidates = targets.Count };
            var routed = bestIndex.HasValue ? targets.FirstOrDefault(a => a.IfIndex == bestIndex.Value) : null;
            AdapterInfo use = routed ?? (targets.Count == 1 ? targets[0] : null);
            if (use != null)
            {
                s.AdapterId = use.Id; s.AdapterName = use.Name; s.AdapterType = use.Type; s.AdapterIsVpn = use.IsVpn;
                s.RouteKnown = routed != null;
                s.DnsChoice = choiceOf(use);
            }
            else if (targets.Count == 0) s.DnsChoice = "auto";
            else
            {
                var ids = targets.Select(choiceOf).Distinct().ToList();
                s.DnsChoice = ids.Count == 1 ? ids[0] : "mixed";
            }
            s.Doh = SystemDns.DohSupported ? dohOf(s.DnsChoice) : DohState.Unsupported;
            return s;
        }

        /// <summary>Is encrypted DNS registered for the provider's first server? (cached for 5 minutes; read again after a network change)</summary>
        static DohState DohFor(string choiceId, bool fresh)
        {
            var c = SystemDns.Choices.FirstOrDefault(x => x.Id == choiceId && !x.IsAuto);
            if (c == null || string.IsNullOrEmpty(c.V4a)) return DohState.Unknown;
            lock (dohCache)
                if (!fresh && dohCache.TryGetValue(c.V4a, out var hit) && (DateTime.Now - hit.At).TotalMinutes < 5) return hit.State;
            DohState st;
            try
            {
                var e = SystemDns.ReadEncryption(c.V4a);
                st = e == null ? DohState.Unknown : e.Exists && e.Template.Length > 0 && e.AutoUpgrade == true ? DohState.Configured : DohState.NotConfigured;
            }
            catch (Exception ign) { App.Ignored("Encrypted DNS state could not be read", ign); st = DohState.Unknown; }
            lock (dohCache) dohCache[c.V4a] = (st, DateTime.Now);
            return st;
        }
    }

    /// <summary>A restartable quiet-period timer (WinForms timer in the app, a manual clock in the self-test).</summary>
    public interface IDebounce : IDisposable
    {
        void Restart();
        void Stop();
        event Action Elapsed;
    }

    /// <summary>
    /// What happens after a network event: events are joined until 2.5 s have passed since the last one; then the state is read
    /// in the background and only the newest read reaches the UI (an older read that returns late is dropped). During a scan or
    /// its restore one refresh is kept and done once when the scan gate is free. The first picture is taken silently, the same
    /// state is never reported twice. Nothing here flushes DNS, tests the internet, restarts an engine, scans or writes DNS/proxy.
    /// </summary>
    public sealed class NetChangeFlow : IDisposable
    {
        public const int QuietMs = 2500;
        readonly IDebounce debounce;
        readonly Func<NetState> read;
        readonly Action<Action> post;
        readonly Func<bool> busy;
        readonly Action<NetState, NetState> changed;
        readonly Func<Func<NetState>, Task<NetState>> run;
        long gen;
        NetState last;
        bool pending, disposed, primed;

        public int Reads, Applied, Notified, Dropped, Deferred;
        public NetState Last => last;
        public bool Pending => pending;

        /// <param name="post">Runs an action on the UI thread (must do nothing after the window is gone).</param>
        /// <param name="changed">(old, new) on the UI thread, never for the first picture or an unchanged state.</param>
        public NetChangeFlow(IDebounce debounce, Func<NetState> read, Action<Action> post, Func<bool> busy, Action<NetState, NetState> changed,
                             Func<Func<NetState>, Task<NetState>> run = null)
        {
            this.debounce = debounce;
            this.read = read;
            this.post = post;
            this.busy = busy;
            this.changed = changed;
            this.run = run ?? (f => Task.Run(f));
            debounce.Elapsed += OnQuiet;
        }

        /// <summary>The first, silent picture (at start).</summary>
        public void Prime() { if (!disposed) StartRead(); }

        /// <summary>A network event (UI thread): the quiet period starts again.</summary>
        public void Signal()
        {
            if (disposed) return;
            debounce.Restart();
        }

        void OnQuiet()
        {
            debounce.Stop();
            if (disposed) return;
            if (busy()) { pending = true; Deferred++; return; }
            StartRead();
        }

        void StartRead()
        {
            long g = Interlocked.Increment(ref gen);
            Reads++;
            Task<NetState> t;
            try { t = run(read); } catch (Exception ign) { App.Ignored("Network state could not be read", ign); return; }
            t.ContinueWith(x =>
            {
                if (x.IsFaulted || x.IsCanceled || disposed) { var _ = x.Exception; return; }
                post(() => Apply(g, x.Result));
            }, TaskContinuationOptions.ExecuteSynchronously);
        }

        void Apply(long g, NetState s)
        {
            if (disposed || s == null) return;
            if (g != Interlocked.Read(ref gen)) { Dropped++; return; }
            if (busy()) { pending = true; Deferred++; return; }
            var old = last;
            last = s;
            Applied++;
            SystemDns.Publish(s);
            if (!primed) { primed = true; return; }
            if (old != null && old.Key == s.Key) return;
            Notified++;
            changed?.Invoke(old, s);
        }

        /// <summary>The scan gate is free again: a refresh kept during the scan is done once (on the UI thread).</summary>
        public void OnScanReleased() => post(() =>
        {
            if (disposed || !pending) return;
            pending = false;
            StartRead();
        });

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            debounce.Elapsed -= OnQuiet;
            debounce.Stop();
        }
    }

    /// <summary>Subscribing to the two static network events (replaced by a recorder in PREVIEW: no real events there).</summary>
    public interface INetEvents
    {
        void Subscribe(NetworkAddressChangedEventHandler address, NetworkAvailabilityChangedEventHandler availability);
        void Unsubscribe(NetworkAddressChangedEventHandler address, NetworkAvailabilityChangedEventHandler availability);
    }

    public sealed class SystemNetEvents : INetEvents
    {
        public void Subscribe(NetworkAddressChangedEventHandler a, NetworkAvailabilityChangedEventHandler b)
        {
            NetworkChange.NetworkAddressChanged += a;
            NetworkChange.NetworkAvailabilityChanged += b;
        }
        public void Unsubscribe(NetworkAddressChangedEventHandler a, NetworkAvailabilityChangedEventHandler b)
        {
            NetworkChange.NetworkAddressChanged -= a;
            NetworkChange.NetworkAvailabilityChanged -= b;
        }
    }

    /// <summary>Counts subscriptions (PREVIEW and the self-test: the window must subscribe once and unsubscribe on close).</summary>
    public sealed class RecordingNetEvents : INetEvents
    {
        public int Active, Subscribes, Unsubscribes;
        public NetworkAddressChangedEventHandler Address;
        public NetworkAvailabilityChangedEventHandler Availability;
        public void Subscribe(NetworkAddressChangedEventHandler a, NetworkAvailabilityChangedEventHandler b) { Subscribes++; Active++; Address += a; Availability += b; }
        public void Unsubscribe(NetworkAddressChangedEventHandler a, NetworkAvailabilityChangedEventHandler b) { Unsubscribes++; Active--; Address -= a; Availability -= b; }
        public void RaiseAddress() => Address?.Invoke(null, EventArgs.Empty);
    }

    /// <summary>
    /// The one network watcher of the main window: both static events feed the same <see cref="NetChangeFlow"/>; subscribed once
    /// in the constructor (a rebuild for the language, theme or UI level does not subscribe again), it keeps working while the
    /// window is hidden in the tray and is undone on the real close.
    /// </summary>
    public sealed class NetWatchHost : IDisposable
    {
        readonly INetEvents events;
        readonly Action<Action> uiPost;
        readonly NetworkAddressChangedEventHandler onAddress;
        readonly NetworkAvailabilityChangedEventHandler onAvailability;
        readonly Action onReleased;
        bool disposed;
        public readonly NetChangeFlow Flow;

        public NetWatchHost(INetEvents events, IDebounce debounce, Func<NetState> read, Action<Action> uiPost, Func<bool> busy,
                            Action<NetState, NetState> changed, Func<Func<NetState>, Task<NetState>> run = null)
        {
            this.events = events;
            this.uiPost = uiPost;
            Flow = new NetChangeFlow(debounce, read, a => { if (!disposed) uiPost(a); }, busy, changed, run);
            onAddress = (s, e) => Event();
            onAvailability = (s, e) => Event();
            onReleased = () => { if (!disposed) Flow.OnScanReleased(); };
            events.Subscribe(onAddress, onAvailability);
            ScanGate.Released += onReleased;
        }

        void Event()
        {
            if (disposed) return;
            try { uiPost(() => { if (!disposed) Flow.Signal(); }); } catch (Exception ign) { App.Ignored("Network event", ign); }
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            try { events.Unsubscribe(onAddress, onAvailability); } catch (Exception ign) { App.Ignored("Network events", ign); }
            ScanGate.Released -= onReleased;
            Flow.Dispose();
        }
    }

    /// <summary>The quiet-period timer of the main window (a WinForms timer: it ticks on the UI thread).</summary>
    public sealed class FormsDebounce : IDebounce
    {
        readonly System.Windows.Forms.Timer timer;
        public event Action Elapsed;
        public FormsDebounce(System.Windows.Forms.Timer timer) { this.timer = timer; timer.Tick += (s, e) => Elapsed?.Invoke(); }
        public void Restart() { timer.Stop(); timer.Start(); }
        public void Stop() => timer.Stop();
        public void Dispose() => timer.Stop();
    }
}
