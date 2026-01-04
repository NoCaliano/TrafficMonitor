// Відповідає за ICommand для асинхронних операцій, щоб не блокувати UI.
using System.Windows.Input;

namespace Presentation.ViewModels;

public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<CancellationToken, Task> _execute;
    private CancellationTokenSource? _cts;
    private bool _isExecuting;

    public event EventHandler? CanExecuteChanged;

    public AsyncRelayCommand(Func<CancellationToken, Task> execute) => _execute = execute;

    public bool CanExecute(object? parameter) => !_isExecuting;

    public async void Execute(object? parameter)
    {
        if (_isExecuting) return;

        _isExecuting = true;
        CanExecuteChanged?.Invoke(this, EventArgs.Empty);

        _cts = new CancellationTokenSource();

        try { await _execute(_cts.Token); }
        finally
        {
            _cts.Dispose();
            _cts = null;
            _isExecuting = false;
            CanExecuteChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public void Cancel() => _cts?.Cancel();
}
