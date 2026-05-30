using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Linq;

namespace Presentation.Helpers;

public sealed class BulkObservableCollection<T> : ObservableCollection<T>
{
    public void AddRange(IEnumerable<T> items, bool useReset = false)
    {
        ArgumentNullException.ThrowIfNull(items);

        CheckReentrancy();

        var list = items as IList<T> ?? items.ToList();
        if (list.Count == 0)
            return;

        int startIndex = Items.Count;
        for (int i = 0; i < list.Count; i++)
            Items.Add(list[i]);

        RaiseCountAndIndexerChanged();

        if (useReset)
        {
            RaiseReset();
            return;
        }

        // WPF does not support range Add/Remove notifications.
        // Using Reset is very expensive because it forces the view to re-evaluate the entire collection.
        // Instead, raise per-item Add notifications (still much cheaper than full Refresh on big lists).
        using (BlockReentrancy())
        {
            for (int i = 0; i < list.Count; i++)
                OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Add, list[i], startIndex + i));
        }
    }

    public void AppendWindowed(IEnumerable<T> items, int maxCount, int resetThreshold = 256)
    {
        ArgumentNullException.ThrowIfNull(items);

        if (maxCount < 0)
            throw new ArgumentOutOfRangeException(nameof(maxCount));

        var list = items as IList<T> ?? items.ToList();
        if (list.Count == 0)
            return;

        if (maxCount == 0)
        {
            ReplaceAll(Array.Empty<T>());
            return;
        }

        if (list.Count >= maxCount)
        {
            ReplaceAll(list.Skip(list.Count - maxCount));
            return;
        }

        int projectedCount = Items.Count + list.Count;
        if (projectedCount > maxCount)
        {
            int keepExisting = maxCount - list.Count;
            var snapshot = new List<T>(maxCount);

            for (int i = Items.Count - keepExisting; i < Items.Count; i++)
                snapshot.Add(Items[i]);

            for (int i = 0; i < list.Count; i++)
                snapshot.Add(list[i]);

            ReplaceAll(snapshot);
            return;
        }

        AddRange(list, useReset: list.Count >= resetThreshold);
    }

    public void ReplaceAll(IEnumerable<T> items)
    {
        ArgumentNullException.ThrowIfNull(items);

        CheckReentrancy();

        Items.Clear();
        foreach (var item in items)
            Items.Add(item);

        RaiseCountAndIndexerChanged();
        RaiseReset();
    }

    private void RaiseCountAndIndexerChanged()
    {
        OnPropertyChanged(new System.ComponentModel.PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new System.ComponentModel.PropertyChangedEventArgs("Item[]"));
    }

    private void RaiseReset()
    {
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }
}
