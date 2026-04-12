using System.Windows;

namespace Presentation.Abstractions;

public interface IUserPromptService
{
    MessageBoxResult Show(string messageBoxText, string caption, MessageBoxButton button, MessageBoxImage icon);
}
