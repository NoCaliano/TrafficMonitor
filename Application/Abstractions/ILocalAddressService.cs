using System;
using System.Collections.Generic;
using System.Text;

// Відповідає за отримання локальних IP адрес ПК (для визначення Direction).
namespace Application.Abstractions;

public interface ILocalAddressService
{
    IReadOnlyCollection<string> GetLocalIpStrings();
}
