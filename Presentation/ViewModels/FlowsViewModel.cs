using Domain.Models;
using Presentation.Services;
using Presentation.Helpers;
using System.Linq;
using System;
using System.Windows.Input;

namespace Presentation.ViewModels;

public sealed class FlowsViewModel : ViewModelBase
{
    private readonly IFlowFilterService _flowFilterService;
    private readonly Func<bool> _uiFilterNonEmpty;
    private readonly Action _onFilterChanged;

    public BulkObservableCollection<FlowInfo> Flows { get; } = new();

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
        // Updating many items individually causes a large amount of CollectionChanged work in WPF.
        // Replace the whole list with a single Reset notification.
        FlowKey? selectedKey = SelectedFlow?.Key;

        Flows.ReplaceAll(snapshot);

        // Re-apply selection (SelectedItem compares by reference; after reset WPF may clear it).
        if (selectedKey is not null)
            SelectedFlow = Flows.FirstOrDefault(f => f.Key.Equals(selectedKey.Value));
    }
}
