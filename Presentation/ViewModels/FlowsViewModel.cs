using Domain.Models;
using Presentation.Services;
using Presentation.Helpers;
using System.Collections.ObjectModel;
using System.Linq;
using System;
using System.Windows.Input;

namespace Presentation.ViewModels;

public sealed class FlowsViewModel : ViewModelBase
{
    private readonly IFlowFilterService _flowFilterService;
    private readonly Func<bool> _uiFilterNonEmpty;
    private readonly Action _onFilterChanged;

    public ObservableCollection<FlowInfo> Flows { get; } = new();

    public FlowsViewModel(IFlowFilterService flowFilterService, Func<bool> uiFilterNonEmpty, Action onFilterChanged)
    {
        _flowFilterService = flowFilterService;
        _uiFilterNonEmpty = uiFilterNonEmpty;
        _onFilterChanged = onFilterChanged;

        FollowFlowCommand = new RelayCommand(_ => ApplySelectedFlow(false), _ => SelectedFlow is not null);
        FollowFlowBothDirectionsCommand = new RelayCommand(_ => ApplySelectedFlow(true), _ => SelectedFlow is not null);
        ClearFlowFilterCommand = new RelayCommand(_ => ClearFilter(), _ => _flowFilterService.IsActive || _uiFilterNonEmpty());
    }

    private FlowInfo? _selectedFlow;
    public FlowInfo? SelectedFlow
    {
        get => _selectedFlow;
        set
        {
            if (!Set(ref _selectedFlow, value)) return;
            RaiseCanExecuteChangedForFlowCommands();
        }
    }

    public ICommand FollowFlowCommand { get; }
    public ICommand FollowFlowBothDirectionsCommand { get; }
    public ICommand ClearFlowFilterCommand { get; }

    private void ApplySelectedFlow(bool includeReverse)
    {
        if (SelectedFlow is null) return;

        _flowFilterService.ApplyFilter(SelectedFlow.Key, includeReverse);
        _onFilterChanged?.Invoke();
        RaiseCanExecuteChangedForFlowCommands();
    }

    private void ClearFilter()
    {
        _flowFilterService.Clear();
        _onFilterChanged?.Invoke();
        RaiseCanExecuteChangedForFlowCommands();
    }

    public void RaiseCanExecuteChangedForFlowCommands()
    {
        (FollowFlowCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (FollowFlowBothDirectionsCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ClearFlowFilterCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    public void UpdateFlows(IReadOnlyList<FlowInfo> snapshot)
    {
        var byKey = snapshot.ToDictionary(f => f.Key);

        foreach (var existing in Flows.ToList())
        {
            if (byKey.TryGetValue(existing.Key, out var fresh))
            {
                // totals
                existing.Packets = fresh.Packets;
                existing.Bytes = fresh.Bytes;
                existing.FirstSeen = fresh.FirstSeen;
                existing.LastSeen = fresh.LastSeen;

                // direction / local-remote
                existing.Direction = fresh.Direction;
                existing.LocalIp = fresh.LocalIp;
                existing.LocalPort = fresh.LocalPort;
                existing.RemoteIp = fresh.RemoteIp;
                existing.RemotePort = fresh.RemotePort;

                // bi-directional
                existing.PacketsAToB = fresh.PacketsAToB;
                existing.BytesAToB = fresh.BytesAToB;
                existing.PacketsBToA = fresh.PacketsBToA;
                existing.BytesBToA = fresh.BytesBToA;

                // local sent/recv
                existing.SentPackets = fresh.SentPackets;
                existing.SentBytes = fresh.SentBytes;
                existing.RecvPackets = fresh.RecvPackets;
                existing.RecvBytes = fresh.RecvBytes;

                byKey.Remove(existing.Key);
            }
            else
            {
                Flows.Remove(existing);
            }
        }

        foreach (var f in byKey.Values)
            Flows.Add(f);
    }
}
