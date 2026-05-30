using Presentation.ViewModels;
using System.Windows.Controls;
using System.Windows.Input;

namespace Presentation.Views;

public partial class ProcessPacketsView : UserControl
{
    public ProcessPacketsView()
    {
        InitializeComponent();
    }

    private void OnPreviewMouseUp(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton != MouseButton.XButton1)
            return;

        if (ProcessPacketsLayout.DataContext is not ProcessPacketsViewModel viewModel || !viewModel.IsProcessDetailsOpen)
            return;

        if (!viewModel.BackToProcessGridCommand.CanExecute(null))
            return;

        viewModel.BackToProcessGridCommand.Execute(null);
        e.Handled = true;
    }
}
