using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace Infrastructure.Networking;

public sealed class ProcessMapperService : IDisposable
{
    // Cache for PID -> process name to avoid frequent Process.GetProcessById calls
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, (string Name, DateTime Expires)> _nameCache = new();
    private readonly TimeSpan _nameCacheTtl = TimeSpan.FromSeconds(5);

    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, (ProcessDetails Details, DateTime Expires)> _detailsCache = new();
    private readonly TimeSpan _detailsCacheTtl = TimeSpan.FromSeconds(30);

    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, (ProcessLivenessInfo Info, DateTime Expires)> _livenessCache = new();
    private readonly TimeSpan _livenessCacheTtl = TimeSpan.FromSeconds(2);

    // These dictionaries are treated as immutable snapshots:
    // Refresh() builds new instances and atomically swaps the references.
    // Readers access the current snapshot lock-free via Volatile.Read.
    private Dictionary<TcpKey, int> _tcpMap = new();
    private Dictionary<UdpKey, int> _udpMap = new();

    private readonly System.Timers.Timer _timer;
    private long _lastUdpMissRefreshTick = Environment.TickCount64 - 1000;
    private int _refreshInProgress;
    private const int UdpMissRefreshCooldownMs = 250;

    public bool IsRunning => _timer.Enabled;

    public ProcessMapperService(int refreshMs = 3000)
    {
        _timer = new System.Timers.Timer(refreshMs);
        _timer.Elapsed += (_, __) => RefreshSafe();
        _timer.AutoReset = true;

        // Do not start polling until capture starts; reading TCP/UDP tables is expensive.
    }

    public void Start()
    {
        if (_timer.Enabled)
            return;

        RefreshSafe();
        _timer.Start();
    }

    public void Stop()
    {
        if (!_timer.Enabled)
            return;

        _timer.Stop();
    }

    public void SetRefreshInterval(int refreshMs)
    {
        if (refreshMs < 250)
            refreshMs = 250;

        _timer.Interval = refreshMs;
    }

    public void Dispose()
    {
        Stop();
        _timer.Dispose();
    }

    public bool TryResolveTcp(IPAddress src, int srcPort, IPAddress dst, int dstPort, out int pid)
    {
        // TCP таблиця зберігає локальний+віддалений.
        // Для пакета локальна сторона може бути src або dst — тому шукаємо обидва варіанти.
        var k1 = new TcpKey(src, srcPort, dst, dstPort);
        var k2 = new TcpKey(dst, dstPort, src, srcPort);

        var map = Volatile.Read(ref _tcpMap);
        if (map.TryGetValue(k1, out pid)) return true;
        if (map.TryGetValue(k2, out pid)) return true;

        pid = -1;
        return false;
    }

    public bool TryResolveUdp(IPAddress localIp, int localPort, out int pid)
    {
        var map = Volatile.Read(ref _udpMap);
        if (TryResolveUdpFromMap(map, localIp, localPort, out pid))
            return true;

        RefreshUdpSnapshotOnMiss();
        map = Volatile.Read(ref _udpMap);
        if (TryResolveUdpFromMap(map, localIp, localPort, out pid))
            return true;

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

    public readonly record struct ProcessDetails(
        int Pid,
        string Name,
        string ExePath,
        int ParentPid,
        string Publisher,
        bool IsSigned,
        string SignerSubject);

    public readonly record struct ProcessLivenessInfo(bool IsAlive, string ExePath);

    public ProcessLivenessInfo GetProcessLivenessCached(int pid)
    {
        if (pid <= 0)
            return default;

        var now = DateTime.UtcNow;
        if (_livenessCache.TryGetValue(pid, out var entry) && entry.Expires > now)
            return entry.Info;

        var info = BuildProcessLivenessInfo(pid);
        _livenessCache[pid] = (info, now.Add(_livenessCacheTtl));
        return info;
    }

    private static ProcessLivenessInfo BuildProcessLivenessInfo(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            if (proc.HasExited)
                return new ProcessLivenessInfo(IsAlive: false, ExePath: "");

            string exePath = "";
            try
            {
                exePath = proc.MainModule?.FileName ?? "";
            }
            catch
            {
                // ignore
            }

            return new ProcessLivenessInfo(IsAlive: true, ExePath: exePath);
        }
        catch
        {
            return new ProcessLivenessInfo(IsAlive: false, ExePath: "");
        }
    }

    public ProcessDetails GetProcessDetailsCached(int pid)
    {
        if (pid <= 0)
            return default;

        var now = DateTime.UtcNow;
        if (_detailsCache.TryGetValue(pid, out var entry) && entry.Expires > now)
            return entry.Details;

        var details = BuildProcessDetails(pid);
        _detailsCache[pid] = (details, now.Add(_detailsCacheTtl));
        return details;
    }

    private ProcessDetails BuildProcessDetails(int pid)
    {
        string name = "";
        string exePath = "";
        int parentPid = 0;
        string publisher = "";
        bool isSigned = false;
        string signerSubject = "";

        try
        {
            using var proc = Process.GetProcessById(pid);
            name = proc.ProcessName ?? "";

            try
            {
                exePath = proc.MainModule?.FileName ?? "";
            }
            catch
            {
                // access denied / 32-64 bit mismatch etc.
            }

            try
            {
                if (TryGetParentPid(proc.Handle, out var pp))
                    parentPid = pp;
            }
            catch
            {
                // ignore
            }
        }
        catch
        {
            // ignore
        }

        if (!string.IsNullOrWhiteSpace(exePath) && File.Exists(exePath))
        {
            try
            {
                var fvi = FileVersionInfo.GetVersionInfo(exePath);
                publisher = fvi.CompanyName ?? "";
            }
            catch
            {
                // ignore
            }

            try
            {
                using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(exePath));
                isSigned = true;
                signerSubject = cert.Subject ?? "";

                var simpleName = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
                if (!string.IsNullOrWhiteSpace(simpleName))
                    publisher = simpleName;
            }
            catch
            {
                // not signed or cannot read cert
            }
        }

        if (string.IsNullOrWhiteSpace(name))
            name = GetProcessNameCached(pid);

        return new ProcessDetails(
            Pid: pid,
            Name: name,
            ExePath: exePath,
            ParentPid: parentPid,
            Publisher: publisher,
            IsSigned: isSigned,
            SignerSubject: signerSubject);
    }

    private void RefreshSafe()
    {
        if (Interlocked.Exchange(ref _refreshInProgress, 1) != 0)
            return;

        try
        {
            Refresh();
        }
        catch
        {
            // не валимо UI
        }
        finally
        {
            Volatile.Write(ref _refreshInProgress, 0);
        }
    }

    private void Refresh()
    {
        var tcp = ReadTcpTableAll();
        var udp = ReadUdpTableAll();

        // Atomic snapshot swap.
        Volatile.Write(ref _tcpMap, tcp);
        Volatile.Write(ref _udpMap, udp);
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

    private static bool TryResolveUdpFromMap(Dictionary<UdpKey, int> map, IPAddress localIp, int localPort, out int pid)
    {
        if (map.TryGetValue(new UdpKey(localIp, localPort), out pid))
            return true;

        // UDP sockets may be bound to wildcard addresses (0.0.0.0 / ::),
        // which is common for QUIC clients and servers on Windows.
        if (localIp.AddressFamily == AddressFamily.InterNetwork &&
            map.TryGetValue(new UdpKey(IPAddress.Any, localPort), out pid))
        {
            return true;
        }

        if (localIp.AddressFamily == AddressFamily.InterNetworkV6 &&
            map.TryGetValue(new UdpKey(IPAddress.IPv6Any, localPort), out pid))
        {
            return true;
        }

        pid = -1;
        return false;
    }

    private void RefreshUdpSnapshotOnMiss()
    {
        if (!IsRunning)
            return;

        long now = Environment.TickCount64;
        long last = Interlocked.Read(ref _lastUdpMissRefreshTick);
        if (now - last < UdpMissRefreshCooldownMs)
            return;

        if (Interlocked.CompareExchange(ref _lastUdpMissRefreshTick, now, last) != last)
            return;

        RefreshSafe();
    }

    // ---------------- Keys ----------------

    private readonly record struct TcpKey(IPAddress LocalIp, int LocalPort, IPAddress RemoteIp, int RemotePort);
    private readonly record struct UdpKey(IPAddress LocalIp, int LocalPort);

    // ---------------- Process parent PID ----------------

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation,
        int processInformationLength,
        out int returnLength);

    private static bool TryGetParentPid(IntPtr processHandle, out int parentPid)
    {
        parentPid = 0;
        try
        {
            PROCESS_BASIC_INFORMATION pbi = default;
            int ret = NtQueryInformationProcess(processHandle, processInformationClass: 0, ref pbi, Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
            if (ret != 0)
                return false;

            parentPid = pbi.InheritedFromUniqueProcessId.ToInt32();
            return parentPid > 0;
        }
        catch
        {
            return false;
        }
    }

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
