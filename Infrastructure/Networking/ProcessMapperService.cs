using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace Infrastructure.Networking;

public sealed class ProcessMapperService : IDisposable
{
    private readonly object _lock = new();

        // Cache for PID -> process name to avoid frequent Process.GetProcessById calls
        private readonly System.Collections.Concurrent.ConcurrentDictionary<int, (string Name, DateTime Expires)> _nameCache = new();
        private readonly TimeSpan _nameCacheTtl = TimeSpan.FromSeconds(5);

    private Dictionary<TcpKey, int> _tcpMap = new();
    private Dictionary<UdpKey, int> _udpMap = new();

    private readonly System.Timers.Timer _timer;

    public ProcessMapperService(int refreshMs = 1000)
    {
        _timer = new System.Timers.Timer(refreshMs);
        _timer.Elapsed += (_, __) => RefreshSafe();
        _timer.AutoReset = true;
        _timer.Start();

        RefreshSafe();
    }

    public void Dispose()
    {
        _timer.Stop();
        _timer.Dispose();
    }

    public bool TryResolveTcp(IPAddress src, int srcPort, IPAddress dst, int dstPort, out int pid)
    {
        // TCP таблиця зберігає локальний+віддалений.
        // Для пакета локальна сторона може бути src або dst — тому шукаємо обидва варіанти.
        var k1 = new TcpKey(src, srcPort, dst, dstPort);
        var k2 = new TcpKey(dst, dstPort, src, srcPort);

        lock (_lock)
        {
            if (_tcpMap.TryGetValue(k1, out pid)) return true;
            if (_tcpMap.TryGetValue(k2, out pid)) return true;
        }

        pid = -1;
        return false;
    }

    public bool TryResolveUdp(IPAddress localIp, int localPort, out int pid)
    {
        var k = new UdpKey(localIp, localPort);

        lock (_lock)
        {
            if (_udpMap.TryGetValue(k, out pid)) return true;
        }

        pid = -1;
        return false;
    }

    public static string TryGetProcessName(int pid)
    {
        if (pid <= 0) return "";

        try
        {
            return Process.GetProcessById(pid).ProcessName;
        }
        catch
        {
            return "";
        }
    }

    // Cached variant to reduce expensive system calls
    public string GetProcessNameCached(int pid)
    {
        if (pid <= 0) return "";

        var now = DateTime.UtcNow;
        if (_nameCache.TryGetValue(pid, out var entry) && entry.Expires > now)
        {
            return entry.Name;
        }

        var name = TryGetProcessName(pid);
        _nameCache[pid] = (name, now.Add(_nameCacheTtl));
        return name;
    }

    private void RefreshSafe()
    {
        try
        {
            Refresh();
        }
        catch
        {
            // не валимо UI
        }
    }

    private void Refresh()
    {
        var tcp = ReadTcpTableAll();
        var udp = ReadUdpTableAll();

        lock (_lock)
        {
            _tcpMap = tcp;
            _udpMap = udp;
        }
    }

    // ---------------- TCP ----------------

    private static Dictionary<TcpKey, int> ReadTcpTableAll()
    {
        var map = new Dictionary<TcpKey, int>();

        // IPv4
        FillTcpV4(map);
        // IPv6
        FillTcpV6(map);

        return map;
    }

    private static void FillTcpV4(Dictionary<TcpKey, int> map)
    {
        int buffSize = 0;
        uint ret = GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
        if (ret != ERROR_INSUFFICIENT_BUFFER && buffSize <= 0) return;

        IntPtr buff = Marshal.AllocHGlobal(buffSize);
        try
        {
            ret = GetExtendedTcpTable(buff, ref buffSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(buff);
            IntPtr rowPtr = IntPtr.Add(buff, 4);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                var local = new IPAddress(row.localAddr);
                var remote = new IPAddress(row.remoteAddr);
                int lport = ntohs((ushort)row.localPort);
                int rport = ntohs((ushort)row.remotePort);

                var key = new TcpKey(local, lport, remote, rport);
                map[key] = (int)row.owningPid;

                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buff);
        }
    }

    private static void FillTcpV6(Dictionary<TcpKey, int> map)
    {
        int buffSize = 0;
        uint ret = GetExtendedTcpTable(IntPtr.Zero, ref buffSize, true, AF_INET6, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
        if (ret != ERROR_INSUFFICIENT_BUFFER && buffSize <= 0) return;

        IntPtr buff = Marshal.AllocHGlobal(buffSize);
        try
        {
            ret = GetExtendedTcpTable(buff, ref buffSize, true, AF_INET6, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(buff);
            IntPtr rowPtr = IntPtr.Add(buff, 4);
            int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);

                var local = new IPAddress(row.localAddr, row.localScopeId);
                var remote = new IPAddress(row.remoteAddr, row.remoteScopeId);

                int lport = ntohs((ushort)row.localPort);
                int rport = ntohs((ushort)row.remotePort);

                var key = new TcpKey(local, lport, remote, rport);
                map[key] = (int)row.owningPid;

                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buff);
        }
    }

    // ---------------- UDP ----------------

    private static Dictionary<UdpKey, int> ReadUdpTableAll()
    {
        var map = new Dictionary<UdpKey, int>();

        FillUdpV4(map);
        FillUdpV6(map);

        return map;
    }

    private static void FillUdpV4(Dictionary<UdpKey, int> map)
    {
        int buffSize = 0;
        uint ret = GetExtendedUdpTable(IntPtr.Zero, ref buffSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
        if (ret != ERROR_INSUFFICIENT_BUFFER && buffSize <= 0) return;

        IntPtr buff = Marshal.AllocHGlobal(buffSize);
        try
        {
            ret = GetExtendedUdpTable(buff, ref buffSize, true, AF_INET, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(buff);
            IntPtr rowPtr = IntPtr.Add(buff, 4);
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);

                var local = new IPAddress(row.localAddr);
                int lport = ntohs((ushort)row.localPort);

                var key = new UdpKey(local, lport);
                map[key] = (int)row.owningPid;

                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buff);
        }
    }

    private static void FillUdpV6(Dictionary<UdpKey, int> map)
    {
        int buffSize = 0;
        uint ret = GetExtendedUdpTable(IntPtr.Zero, ref buffSize, true, AF_INET6, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
        if (ret != ERROR_INSUFFICIENT_BUFFER && buffSize <= 0) return;

        IntPtr buff = Marshal.AllocHGlobal(buffSize);
        try
        {
            ret = GetExtendedUdpTable(buff, ref buffSize, true, AF_INET6, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(buff);
            IntPtr rowPtr = IntPtr.Add(buff, 4);
            int rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr);

                var local = new IPAddress(row.localAddr, row.localScopeId);
                int lport = ntohs((ushort)row.localPort);

                var key = new UdpKey(local, lport);
                map[key] = (int)row.owningPid;

                rowPtr = IntPtr.Add(rowPtr, rowSize);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buff);
        }
    }

    // ---------------- Keys ----------------

    private readonly record struct TcpKey(IPAddress LocalIp, int LocalPort, IPAddress RemoteIp, int RemotePort);
    private readonly record struct UdpKey(IPAddress LocalIp, int LocalPort);

    // ---------------- P/Invoke ----------------

    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    private enum TCP_TABLE_CLASS
    {
        TCP_TABLE_OWNER_PID_ALL = 5,
    }

    private enum UDP_TABLE_CLASS
    {
        UDP_TABLE_OWNER_PID = 1,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public uint localPort;
        public uint remoteAddr;
        public uint remotePort;
        public uint owningPid;
    }

    // NOTE: порти в цих структурах теж в network-order, але в uint
    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;

        public uint localScopeId;
        public uint localPort;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;

        public uint remoteScopeId;
        public uint remotePort;

        public uint state;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public uint localPort;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;

        public uint localScopeId;
        public uint localPort;
        public uint owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        TCP_TABLE_CLASS tblClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int dwOutBufLen,
        bool sort,
        int ipVersion,
        UDP_TABLE_CLASS tblClass,
        uint reserved);

    private static int ntohs(ushort net) => (net >> 8) | ((net & 0xFF) << 8);
}