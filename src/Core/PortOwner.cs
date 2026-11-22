using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

namespace NSFShield
{
    /// <summary>
    /// Which process listens on a TCP port (GetExtendedTcpTable, IPv4 and IPv6). "The port was free and then a connection
    /// worked" does not prove that our process listens there; only the owning PID of the listening socket does.
    /// </summary>
    public static class PortOwner
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool sort, int af, int tableClass, uint reserved);

        const int AF_INET = 2, AF_INET6 = 23, TCP_TABLE_OWNER_PID_LISTENER = 3;

        public sealed class Listener
        {
            public IPAddress Address;
            public int Port, Pid;
            public override string ToString() => (Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "[" + Address + "]" : Address.ToString()) + ":" + Port + " (PID " + Pid + ")";
        }

        /// <summary>Every listening socket on the port (all addresses, both IP versions).</summary>
        public static List<Listener> Listeners(int port)
        {
            var list = new List<Listener>();
            foreach (int af in new[] { AF_INET, AF_INET6 })
            {
                int size = 0;
                GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, TCP_TABLE_OWNER_PID_LISTENER, 0);
                if (size <= 0) continue;
                for (int attempt = 0; attempt < 3; attempt++)
                {
                    size += 4096;
                    IntPtr buf = Marshal.AllocHGlobal(size);
                    try
                    {
                        uint rc = GetExtendedTcpTable(buf, ref size, false, af, TCP_TABLE_OWNER_PID_LISTENER, 0);
                        if (rc == 122) continue;   // ERROR_INSUFFICIENT_BUFFER: the table grew, try again
                        if (rc != 0) break;
                        int n = Marshal.ReadInt32(buf);
                        int rowSize = af == AF_INET ? 24 : 56;
                        for (int i = 0; i < n; i++)
                        {
                            IntPtr row = buf + 4 + i * rowSize;
                            IPAddress addr;
                            int rawPort, pid;
                            if (af == AF_INET)
                            {
                                addr = new IPAddress(BitConverter.GetBytes(Marshal.ReadInt32(row, 4)));
                                rawPort = Marshal.ReadInt32(row, 8);
                                pid = Marshal.ReadInt32(row, 20);
                            }
                            else
                            {
                                var a = new byte[16];
                                Marshal.Copy(row, a, 0, 16);
                                addr = new IPAddress(a, (uint)Marshal.ReadInt32(row, 16));
                                rawPort = Marshal.ReadInt32(row, 20);
                                pid = Marshal.ReadInt32(row, 52);
                            }
                            int p = ((rawPort & 0xFF) << 8) | ((rawPort >> 8) & 0xFF);
                            if (p == port) list.Add(new Listener { Address = addr, Port = p, Pid = pid });
                        }
                        break;
                    }
                    finally { Marshal.FreeHGlobal(buf); }
                }
            }
            return list;
        }

        /// <summary>
        /// True if something listens on the port, every listener belongs to <paramref name="pid"/> and is bound to a loopback
        /// address. Otherwise <paramref name="detail"/> names what listens there.
        /// </summary>
        public static bool OwnedBy(int port, int pid, out string detail) => Check(Listeners(port), pid, out detail);

        /// <summary>The rule of <see cref="OwnedBy"/> on a given listener list (testable without sockets).</summary>
        public static bool Check(List<Listener> ls, int pid, out string detail)
        {
            detail = ls.Count == 0 ? "nothing listens" : string.Join(", ", ls);
            return ls.Count > 0 && ls.All(l => l.Pid == pid && IPAddress.IsLoopback(l.Address));
        }

        /// <summary>Is no process listening on the port at all (any address, both IP versions)?</summary>
        public static bool Unused(int port) => Listeners(port).Count == 0 && ByeDpiNet.PortFree(port);

        /// <summary>Waits until the started process itself listens on the port (it must stay alive); no connection is made.</summary>
        public static bool WaitOwned(int port, Process p, int timeoutMs, CancellationToken ct, out string detail)
        {
            detail = "";
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                ct.ThrowIfCancellationRequested();
                try { if (p.HasExited) { detail = "exited"; return false; } } catch { detail = "exited"; return false; }
                var ls = Listeners(port);
                if (ls.Any(l => l.Pid == p.Id)) return Check(ls, p.Id, out detail);
                if (ls.Count > 0) detail = string.Join(", ", ls);
                Thread.Sleep(100);
            }
            if (detail.Length == 0) detail = "nothing listens";
            return false;
        }

        /// <summary>
        /// A free loopback port for a scan trial in [from, to], never one of <paramref name="avoid"/> (the ports of a running
        /// ByeDPI and its bridge). 0 if none is free.
        /// </summary>
        public static int PickTrialPort(IEnumerable<int> avoid, int from = 18990, int to = 19089)
        {
            var skip = new HashSet<int>(avoid ?? Enumerable.Empty<int>());
            for (int port = from; port <= to; port++)
                if (!skip.Contains(port) && Unused(port)) return port;
            return 0;
        }
    }
}
