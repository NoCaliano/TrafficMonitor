using System.Windows;

namespace Presentation.Services;

public sealed class UserPromptService : IUserPromptService
{
    public MessageBoxResult Show(string messageBoxText, string caption, MessageBoxButton button, MessageBoxImage icon)
        => MessageBox.Show(messageBoxText, caption, button, icon);
}
