// Відповідає за збір локальних IP адрес з мережевих інтерфейсів Windows.
using Application.Abstractions;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Infrastructure.Networking;

public sealed class LocalAddressService : ILocalAddressService
{
    public IReadOnlyCollection<string> GetLocalIpStrings()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Loopback is important (Npcap Loopback Adapter, localhost traffic)
        set.Add(IPAddress.Loopback.ToString());
        set.Add(IPAddress.IPv6Loopback.ToString());

        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            // Відповідає за відбір активних фізичних/безпровідних інтерфейсів
            if (ni.OperationalStatus != OperationalStatus.Up)
                continue;

            // if (ni.NetworkInterfaceType != NetworkInterfaceType.Wireless80211) continue;

            var props = ni.GetIPProperties();
            foreach (var ua in props.UnicastAddresses)
            {
                var ip = ua.Address;
                if (ip is null) continue;

                // Відповідає за пропуск "порожніх" / небажаних адрес:
                if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
                    continue;

                var ipStr = ip.ToString();
                set.Add(ipStr);

                if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    int pct = ipStr.IndexOf('%');
                    if (pct > 0)
                        set.Add(ipStr[..pct]);
                }
            }
        }

        return set.ToList();
    }
}
