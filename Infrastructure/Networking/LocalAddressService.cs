// Відповідає за збір локальних IP адрес з мережевих інтерфейсів Windows.
using Application.Abstractions;
using System.Net;
using System.Net.NetworkInformation;

namespace Infrastructure.Networking;

public sealed class LocalAddressService : ILocalAddressService
{
    public IReadOnlyCollection<string> GetLocalIpStrings()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            // Відповідає за відбір активних фізичних/безпровідних інтерфейсів
            if (ni.OperationalStatus != OperationalStatus.Up)
                continue;

            // (Опційно) Якщо хочеш тільки Wi-Fi:
            // if (ni.NetworkInterfaceType != NetworkInterfaceType.Wireless80211) continue;

            var props = ni.GetIPProperties();
            foreach (var ua in props.UnicastAddresses)
            {
                var ip = ua.Address;
                if (ip is null) continue;

                // Відповідає за пропуск loopback
                if (IPAddress.IsLoopback(ip)) continue;

                // Відповідає за пропуск "порожніх" / небажаних адрес:
                // 0.0.0.0 не буде тут, але залишимо безпечно
                if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any))
                    continue;

                set.Add(ip.ToString());
            }
        }

        return set.ToList();
    }
}
