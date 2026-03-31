using System.Windows;

namespace Presentation.Services;

public interface IUserPromptService
{
    MessageBoxResult Show(string messageBoxText, string caption, MessageBoxButton button, MessageBoxImage icon);
}
