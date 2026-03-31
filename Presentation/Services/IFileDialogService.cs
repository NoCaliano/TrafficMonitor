using System.Windows;

namespace Presentation.Services;

public interface IFileDialogService
{
    string? ShowOpenPcapDialog(Window? owner);
    string? ShowSavePcapDialog(Window? owner, string suggestedFileName);
}
