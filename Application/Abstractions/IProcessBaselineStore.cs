using Domain.Models;
using System.Collections.Generic;

namespace Application.Abstractions;

public interface IProcessBaselineStore
{
    IReadOnlyList<ProcessBehaviorBaseline> Load();
    void Save(IReadOnlyList<ProcessBehaviorBaseline> baselines);
}
