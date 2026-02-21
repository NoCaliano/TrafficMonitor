using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Media;

namespace Presentation.Models;

public sealed class ProcessStatRow : INotifyPropertyChanged
{
    private const int MaxSamples = 30;

    public int Pid { get; }
    public string ProcessName { get; }
    private long _packetCount;
    public long PacketCount { get => _packetCount; set { if (_packetCount != value) { _packetCount = value; OnPropertyChanged(); } } }

    private long _totalBytes;
    public long TotalBytes { get => _totalBytes; set { if (_totalBytes != value) { _totalBytes = value; OnPropertyChanged(); OnPropertyChanged(nameof(TrafficMb)); } } }

    // rolling samples of packets per update interval
    private readonly Queue<int> _samples = new();
    public IReadOnlyList<int> Samples => _samples.ToArray();

    public Geometry? SparklineGeometry { get => _sparklineGeometry; private set { _sparklineGeometry = value; OnPropertyChanged(); } }
    private Geometry? _sparklineGeometry;

    public double TrafficMb => TotalBytes / 1024.0 / 1024.0;

    public string DisplayName => Pid > 0 ? $"{ProcessName} (PID: {Pid})" : ProcessName;

    public ProcessStatRow(int pid, string name, long count, long totalBytes)
    {
        Pid = pid;
        ProcessName = name;
        _packetCount = count;
        _totalBytes = totalBytes;
    }

    public void AddSample(int value)
    {
        if (_samples.Count >= MaxSamples)
            _samples.Dequeue();
        _samples.Enqueue(value);
        RebuildGeometry();
    }

    private void RebuildGeometry()
    {
        if (_samples.Count == 0)
        {
            SparklineGeometry = null;
            return;
        }

        double width = 180; // fits column
        double height = 24;
        var pts = _samples.ToArray();
        int n = pts.Length;
        int max = pts.Max();
        if (max == 0) max = 1;

        var geom = new StreamGeometry();
        using (var ctx = geom.Open())
        {
            for (int i = 0; i < n; i++)
            {
                double x = (i * width) / (MaxSamples - 1);
                double y = height - ((double)pts[i] / max) * height;
                if (i == 0)
                    ctx.BeginFigure(new Point(x, y), false, false);
                else
                    ctx.LineTo(new Point(x, y), true, false);
            }
        }
        geom.Freeze();
        SparklineGeometry = geom;
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
