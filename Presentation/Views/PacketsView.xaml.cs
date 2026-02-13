using Presentation.ViewModels;
using System;
using System.Collections.Generic;
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
        public PacketsView()
        {
            InitializeComponent();
        }

        private void ProtocolTreeItem_MouseEnter(object sender, MouseEventArgs e)
        {
            if (DataContext is not MainViewModel vm)
                return;

            if (sender is not TreeViewItem uiItem)
                return;

            object? tag = uiItem.Tag ?? (uiItem.DataContext as TreeViewItem)?.Tag;
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
                object? tag = tvi.Tag ?? (tvi.DataContext as TreeViewItem)?.Tag;
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
