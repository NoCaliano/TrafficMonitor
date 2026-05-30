// Відповідає за ICommand для асинхронних операцій, щоб не блокувати UI.
using System.Windows.Input;

namespace Presentation.ViewModels;

public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<CancellationToken, Task> _execute;
    private readonly Func<bool>? _canExecute;
    private CancellationTokenSource? _cts;
    private bool _isExecuting;

    public event EventHandler? CanExecuteChanged;

    public AsyncRelayCommand(Func<CancellationToken, Task> execute, Func<bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => !_isExecuting && (_canExecute?.Invoke() ?? true);

    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter))
            return;

        _isExecuting = true;
        RaiseCanExecuteChanged();

        _cts = new CancellationTokenSource();

        try { await _execute(_cts.Token); }
        finally
        {
            _cts.Dispose();
            _cts = null;
            _isExecuting = false;
            RaiseCanExecuteChanged();
        }
    }

    public void Cancel() => _cts?.Cancel();

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}
