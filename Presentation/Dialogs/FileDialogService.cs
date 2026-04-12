using Microsoft.Win32;
using Presentation.Abstractions;
using System.Windows;

namespace Presentation.Dialogs;

public sealed class FileDialogService : IFileDialogService
{
    public string? ShowOpenPcapDialog(Window? owner)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Open capture",
            Filter = "pcap (*.pcap)|*.pcap|All files (*.*)|*.*",
            DefaultExt = ".pcap",
            Multiselect = false
        };

        return dlg.ShowDialog(owner) == true ? dlg.FileName : null;
    }

    public string? ShowSavePcapDialog(Window? owner, string suggestedFileName)
    {
        var dlg = new SaveFileDialog
        {
            Title = "Save capture",
            Filter = "pcap (*.pcap)|*.pcap|All files (*.*)|*.*",
            DefaultExt = ".pcap",
            AddExtension = true,
            FileName = suggestedFileName
        };

        return dlg.ShowDialog(owner) == true ? dlg.FileName : null;
    }
}
