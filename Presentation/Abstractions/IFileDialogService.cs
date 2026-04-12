using System.Windows;

namespace Presentation.Abstractions;

public interface IFileDialogService
{
    string? ShowOpenPcapDialog(Window? owner);
    string? ShowSavePcapDialog(Window? owner, string suggestedFileName);
}
