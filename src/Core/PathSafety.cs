using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace NSFShield
{
    /// <summary>
    /// File system checks before a privileged operation: redirecting reparse points (junctions, symbolic links, mount points)
    /// in a path, its parents or a tree, the physical final path of an existing file or folder (GetFinalPathNameByHandleW),
    /// the long form of a path (8.3 short names expanded) and the hard link count of an open file. Read-only: nothing is
    /// created or changed. Reparse points that do not redirect a name (OneDrive placeholders, app execution aliases) are
    /// not treated as redirections; a path whose state cannot be read counts as unsafe.
    /// </summary>
    public static class PathSafety
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sec, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetFinalPathNameByHandleW(SafeFileHandle h, StringBuilder buf, uint len, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint GetLongPathNameW(string shortPath, StringBuilder buf, uint len);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle h, out ByHandleInfo info);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandleEx(SafeFileHandle h, int infoClass, out AttributeTagInfo info, uint size);

        [StructLayout(LayoutKind.Sequential)]
        struct ByHandleInfo
        {
            public uint Attributes, CreatedLow, CreatedHigh, AccessedLow, AccessedHigh, WrittenLow, WrittenHigh;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct AttributeTagInfo { public uint Attributes, ReparseTag; }

        const uint FileReadAttributes = 0x80, ShareAll = 0x7, OpenExisting = 3;
        const uint BackupSemantics = 0x02000000, OpenReparsePoint = 0x00200000;
        const uint AttrReparse = 0x400;
        const int FileAttributeTagInfoClass = 9;

        /// <summary>
        /// A full local path in its long form (no 8.3 short names). For a path that does not exist (yet), its longest existing
        /// parent is expanded and the rest is kept as written; the input unchanged if it cannot be expanded at all.
        /// </summary>
        public static string LongPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            string full;
            try { full = Path.GetFullPath(path); } catch { return path; }
            string done = ExpandExisting(full);
            if (done != null) return done;
            try
            {
                string parent = Path.GetDirectoryName(full.TrimEnd('\\'));
                if (string.IsNullOrEmpty(parent) || parent.Length >= full.TrimEnd('\\').Length) return full;
                return Path.Combine(LongPath(parent), Path.GetFileName(full.TrimEnd('\\')));
            }
            catch { return full; }
        }

        static string ExpandExisting(string full)
        {
            try
            {
                var sb = new StringBuilder(1024);
                uint n = GetLongPathNameW(full, sb, (uint)sb.Capacity);
                if (n > sb.Capacity) { sb = new StringBuilder((int)n + 1); n = GetLongPathNameW(full, sb, (uint)sb.Capacity); }
                return n > 0 && n < sb.Capacity ? sb.ToString(0, (int)n) : null;
            }
            catch { return null; }
        }

        /// <summary>Do two paths name the same location (full, long form, case-insensitive, without a trailing backslash)?</summary>
        public static bool Same(string a, string b)
        {
            if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return false;
            return string.Equals(LongPath(a).TrimEnd('\\'), LongPath(b).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Is <paramref name="path"/> inside <paramref name="dir"/> (both compared in their long form)?</summary>
        public static bool Inside(string path, string dir)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(dir)) return false;
            string root = LongPath(dir).TrimEnd('\\') + "\\";
            return LongPath(path).StartsWith(root, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>The physical path Windows resolves an existing file or folder to (null if it cannot be opened).</summary>
        public static string FinalPath(string path)
        {
            try
            {
                using (var h = CreateFileW(Path.GetFullPath(path), FileReadAttributes, ShareAll, IntPtr.Zero, OpenExisting, BackupSemantics, IntPtr.Zero))
                {
                    if (h.IsInvalid) return null;
                    var sb = new StringBuilder(1024);
                    uint n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
                    if (n > sb.Capacity) { sb = new StringBuilder((int)n + 1); n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0); }
                    if (n == 0 || n >= sb.Capacity) return null;
                    string s = sb.ToString(0, (int)n);
                    if (s.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return @"\\" + s.Substring(8);
                    if (s.StartsWith(@"\\?\")) return s.Substring(4);
                    return s;
                }
            }
            catch { return null; }
        }

        /// <summary>Does the existing path resolve to itself (no junction, symbolic link, mount point or SUBST drive on the way)?</summary>
        public static bool ResolvesToItself(string path)
        {
            string fin = FinalPath(path);
            return fin != null && Same(fin, path);
        }

        public enum Kind { None, Redirect, Unreadable }

        /// <summary>
        /// Reparse state of one existing file or folder (the link itself is opened, not its target). Redirect: a name
        /// surrogate (junction, symbolic link, mount point). A path that does not exist is None; a path that cannot be read
        /// (access denied, an invalid name, any other error) is Unreadable – never taken for "not there".
        /// </summary>
        public static Kind Reparse(string path)
        {
            FileAttributes a;
            try
            {
                string p = path != null && path.Length == 2 && path[1] == ':' ? path + "\\" : path;   // "C:" is the drive's current folder
                a = File.GetAttributes(p);
            }
            catch (FileNotFoundException) { return Kind.None; }
            catch (DirectoryNotFoundException) { return Kind.None; }
            catch { return Kind.Unreadable; }
            if ((a & FileAttributes.ReparsePoint) == 0) return Kind.None;
            try
            {
                using (var h = CreateFileW(Path.GetFullPath(path), FileReadAttributes, ShareAll, IntPtr.Zero, OpenExisting, BackupSemantics | OpenReparsePoint, IntPtr.Zero))
                {
                    if (h.IsInvalid) return Kind.Unreadable;
                    if (!GetFileInformationByHandleEx(h, FileAttributeTagInfoClass, out var info, (uint)Marshal.SizeOf(typeof(AttributeTagInfo)))) return Kind.Unreadable;
                    if ((info.Attributes & AttrReparse) == 0) return Kind.None;
                    return IsNameSurrogate(info.ReparseTag) ? Kind.Redirect : Kind.None;
                }
            }
            catch { return Kind.Unreadable; }
        }

        /// <summary>A reparse tag that redirects a name (bit 29: junction 0xA0000003, symbolic link 0xA000000C, …).</summary>
        public static bool IsNameSurrogate(uint tag) => (tag & 0x20000000) != 0;

        /// <summary>The first unsafe entry of the path or one of its parents (null: none). Missing parts are skipped.</summary>
        public static string UnsafeInChain(string path)
        {
            string p;
            try { p = Path.GetFullPath(path).TrimEnd('\\'); } catch { return path ?? "?"; }
            for (var d = p; !string.IsNullOrEmpty(d); d = Parent(d))
                if (Reparse(d) != Kind.None) return d;
            return null;
        }

        static string Parent(string p)
        {
            try { return Path.GetDirectoryName(p); } catch { return null; }
        }

        /// <summary>The first unsafe entry inside a folder tree (the folder itself included; links are never followed); null: none.</summary>
        public static string UnsafeInTree(string dir, int maxEntries = 20000)
        {
            if (Reparse(dir) != Kind.None) return dir;
            if (!Directory.Exists(dir)) return null;
            var stack = new Stack<string>();
            stack.Push(dir);
            int seen = 0;
            while (stack.Count > 0)
            {
                string d = stack.Pop();
                string[] files, dirs;
                try { files = Directory.GetFiles(d); dirs = Directory.GetDirectories(d); }
                catch { return d; }
                foreach (var f in files)
                {
                    if (++seen > maxEntries) return d;
                    if (Reparse(f) != Kind.None) return f;
                }
                foreach (var s in dirs)
                {
                    if (++seen > maxEntries) return d;
                    if (Reparse(s) != Kind.None) return s;
                    stack.Push(s);
                }
            }
            return null;
        }

        /// <summary>Number of hard links of an open file (1 for a normal file); 0 if it cannot be read.</summary>
        public static int LinkCount(FileStream fs)
        {
            try { return GetFileInformationByHandle(fs.SafeFileHandle, out var i) ? (int)i.Links : 0; }
            catch { return 0; }
        }

        /// <summary>The physical path of an open file (null if it cannot be read).</summary>
        public static string FinalPathOf(FileStream fs)
        {
            try
            {
                var sb = new StringBuilder(1024);
                uint n = GetFinalPathNameByHandleW(fs.SafeFileHandle, sb, (uint)sb.Capacity, 0);
                if (n == 0 || n >= sb.Capacity) return null;
                string s = sb.ToString(0, (int)n);
                if (s.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return @"\\" + s.Substring(8);
                return s.StartsWith(@"\\?\") ? s.Substring(4) : s;
            }
            catch { return null; }
        }
    }
}
