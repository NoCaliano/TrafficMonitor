using Presentation.ViewModels;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Presentation.Views
{
    /// <summary>
    /// Логика взаимодействия для PacketsView.xaml
    /// </summary>
    public partial class PacketsView : UserControl
    {
        private bool _autoScrollPending;
        private bool _stickToBottom = true;
        private ScrollViewer? _packetsScrollViewer;
        private bool _scrollToEndInProgress;
        private MainViewModel? _vm;

        public PacketsView()
        {
            InitializeComponent();

            Loaded += PacketsView_Loaded;
            Unloaded += PacketsView_Unloaded;

            // attach to DataContextChanged to wire up PropertyChanged on VM
            this.DataContextChanged += PacketsView_DataContextChanged;

            // if DataContext already set at construction time
            if (this.DataContext is System.ComponentModel.INotifyPropertyChanged initial)
                initial.PropertyChanged += Vm_PropertyChanged;

            if (this.DataContext is MainViewModel vm)
                AttachVm(vm);
        }

        private void PacketsView_Loaded(object sender, RoutedEventArgs e)
        {
            EnsureScrollViewerHooked();
        }

        private void PacketsView_Unloaded(object sender, RoutedEventArgs e)
        {
            if (_packetsScrollViewer is not null)
                _packetsScrollViewer.ScrollChanged -= PacketsScrollViewer_ScrollChanged;
            _packetsScrollViewer = null;
        }

        // Wire up/unwire VM.PropertyChanged when DataContext changes
        private void PacketsView_DataContextChanged(object? sender, DependencyPropertyChangedEventArgs e)
        {
            if (e.OldValue is System.ComponentModel.INotifyPropertyChanged oldVm)
                oldVm.PropertyChanged -= Vm_PropertyChanged;

            if (e.OldValue is MainViewModel oldMainVm)
                DetachVm(oldMainVm);

            if (e.NewValue is System.ComponentModel.INotifyPropertyChanged newVm)
                newVm.PropertyChanged += Vm_PropertyChanged;

            if (e.NewValue is MainViewModel newMainVm)
                AttachVm(newMainVm);
        }

        private void AttachVm(MainViewModel vm)
        {
            _vm = vm;
            vm.Packets.CollectionChanged += Packets_CollectionChanged;

            // if the view is already loaded, hook scroll viewer now
            EnsureScrollViewerHooked();
        }

        private void DetachVm(MainViewModel vm)
        {
            if (_vm == vm)
                _vm = null;

            vm.Packets.CollectionChanged -= Packets_CollectionChanged;
        }

        private void Packets_CollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            // When packets are being appended in batches, ObservableCollection will raise many
            // change events; throttle to a single ScrollIntoView per UI loop.
            if (e.Action is not NotifyCollectionChangedAction.Add
                and not NotifyCollectionChangedAction.Reset)
            {
                return;
            }

            RequestAutoScrollToLatest();
        }

        private void EnsureScrollViewerHooked()
        {
            if (!IsLoaded)
                return;

            var dg = this.FindName("PacketsDataGrid") as DataGrid;
            if (dg is null)
                return;

            var sv = FindDescendant<ScrollViewer>(dg);
            if (sv is null || ReferenceEquals(_packetsScrollViewer, sv))
                return;

            if (_packetsScrollViewer is not null)
                _packetsScrollViewer.ScrollChanged -= PacketsScrollViewer_ScrollChanged;

            _packetsScrollViewer = sv;
            _packetsScrollViewer.ScrollChanged += PacketsScrollViewer_ScrollChanged;

            // initialize stick state
            _stickToBottom = IsAtBottom();
        }

        private void PacketsScrollViewer_ScrollChanged(object sender, ScrollChangedEventArgs e)
        {
            if (_scrollToEndInProgress)
                return;

            // If the content size changed (items appended/removed) and we're sticking to bottom,
            // keep following the end.
            if (e.ExtentHeightChange != 0)
            {
                if (_stickToBottom)
                    RequestAutoScrollToLatest();

                return;
            }

            // User-initiated scroll: update stick state.
            _stickToBottom = IsAtBottom();
        }

        private bool IsAtBottom()
        {
            if (_packetsScrollViewer is null)
                return true;

            const double tolerance = 1.0;
            return (_packetsScrollViewer.ScrollableHeight - _packetsScrollViewer.VerticalOffset) <= tolerance;
        }

        private void RequestAutoScrollToLatest()
        {
            if (_autoScrollPending)
                return;

            // Stick-to-bottom mode: only auto-scroll if the user is already at the bottom.
            if (!_stickToBottom)
                return;

            _autoScrollPending = true;

            Dispatcher.BeginInvoke(new Action(() =>
            {
                try
                {
                    EnsureScrollViewerHooked();

                    var dg = this.FindName("PacketsDataGrid") as DataGrid;
                    if (dg is null || dg.Items.Count == 0)
                        return;

                    // Scroll to the last visible item in the grid (respects current filters).
                    var lastItem = dg.Items[dg.Items.Count - 1];

                    _scrollToEndInProgress = true;
                    dg.ScrollIntoView(lastItem);
                    _packetsScrollViewer?.ScrollToEnd();
                    _scrollToEndInProgress = false;
                }
                finally
                {
                    _autoScrollPending = false;
                }
            }), System.Windows.Threading.DispatcherPriority.Background);
        }

        private static T? FindDescendant<T>(DependencyObject root) where T : DependencyObject
        {
            int count = VisualTreeHelper.GetChildrenCount(root);
            for (int i = 0; i < count; i++)
            {
                var child = VisualTreeHelper.GetChild(root, i);
                if (child is T match)
                    return match;

                var nested = FindDescendant<T>(child);
                if (nested is not null)
                    return nested;
            }

            return null;
        }

        private void Vm_PropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(Presentation.ViewModels.MainViewModel.SelectedPacket))
            {
                var vm = DataContext as Presentation.ViewModels.MainViewModel;
                if (vm?.SelectedPacket != null)
                {
                // Scroll selected into view on UI thread, using FindName to get the DataGrid
                var dg = this.FindName("PacketsDataGrid") as DataGrid;
                dg?.ScrollIntoView(vm.SelectedPacket);
                }
            }
        }

        private void ProtocolTreeItem_MouseEnter(object sender, MouseEventArgs e)
        {
            if (DataContext is not MainViewModel vm)
                return;

            // DataContext may be ProtocolNode; TreeViewItems are generated by WPF and
            // sender can be a TreeViewItem whose DataContext is a ProtocolNode.
            if (sender is not TreeViewItem uiItem)
                return;

            // support both Tag and DataContext.Tag (for our ProtocolNode) to get the range
            object? tag = uiItem.Tag ?? (uiItem.DataContext as Presentation.Helpers.ProtocolNode)?.Tag;
            if (tag is ValueTuple<int, int> range)
                vm.SelectedRange = range;
            else
                vm.SelectedRange = null;
        }

        private void ProtocolTreeItem_Selected(object sender, RoutedEventArgs e)
        {
            // щоб при кліку теж гарантовано підсвічувало
            ProtocolTreeItem_MouseEnter(sender, null!);
        }

        private void ProtocolTree_PreviewMouseMove(object sender, MouseEventArgs e)
        {
            if (DataContext is not MainViewModel vm)
                return;

            if (sender is not TreeView tree) return;

            Point pt = e.GetPosition(tree);
            HitTestResult hit = VisualTreeHelper.HitTest(tree, pt);
            if (hit == null)
            {
                vm.SelectedRange = null;
                return;
            }

            DependencyObject current = hit.VisualHit;
            while (current != null && current is not TreeViewItem)
            {
                current = VisualTreeHelper.GetParent(current);
            }

            if (current is TreeViewItem tvi)
            {
                object? tag = tvi.Tag ?? (tvi.DataContext as Presentation.Helpers.ProtocolNode)?.Tag;
                if (tag is ValueTuple<int, int> range)
                    vm.SelectedRange = range;
                else
                    vm.SelectedRange = null;
            }
            else
            {
                vm.SelectedRange = null;
            }
        }

        private void ProtocolTree_MouseLeave(object sender, MouseEventArgs e)
        {
            if (DataContext is not MainViewModel vm) return;
            vm.SelectedRange = null;
        }
    }
}
