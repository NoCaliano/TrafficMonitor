using Presentation.Abstractions;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;

namespace Presentation.Formatting;

internal sealed class HexDumpService : IHexDumpService
{
    public string BuildHexDump(byte[] data, int bytesPerLine)
    {
        if (data.Length == 0) return "";

        var sb = new System.Text.StringBuilder(data.Length * 4);

        for (int i = 0; i < data.Length; i += bytesPerLine)
        {
            sb.Append(i.ToString("X4"));
            sb.Append(": ");

            int lineEnd = Math.Min(i + bytesPerLine, data.Length);
            for (int j = i; j < lineEnd; j++)
            {
                sb.Append(data[j].ToString("X2"));
                sb.Append(' ');
            }

            for (int j = lineEnd; j < i + bytesPerLine; j++)
                sb.Append("   ");

            sb.Append(" |");

            for (int j = i; j < lineEnd; j++)
            {
                byte b = data[j];
                sb.Append(b >= 32 && b <= 126 ? (char)b : '.');
            }

            sb.AppendLine("|");
        }

        return sb.ToString();
    }

    public FlowDocument BuildHexDocument(byte[] data, int bytesPerLine, (int start, int length)? sel)
    {
        int selStart = sel?.start ?? -1;
        int selEnd = sel is null ? -1 : sel.Value.start + Math.Max(0, sel.Value.length); // exclusive

        bool InSel(int idx) => sel is not null && idx >= selStart && idx < selEnd;

        var doc = new FlowDocument
        {
            PagePadding = new Thickness(0)
        };

        var p = new Paragraph
        {
            Margin = new Thickness(0),
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12
        };

        for (int i = 0; i < data.Length; i += bytesPerLine)
        {
            // offset
            p.Inlines.Add(new Run(i.ToString("X4") + ": ") { Foreground = Brushes.Gray });

            int lineEnd = Math.Min(i + bytesPerLine, data.Length);

            // HEX part
            for (int j = i; j < i + bytesPerLine; j++)
            {
                if (j < lineEnd)
                {
                    var run = new Run(data[j].ToString("X2") + " ");
                    if (InSel(j)) run.Background = Brushes.Yellow;
                    p.Inlines.Add(run);
                }
                else
                {
                    p.Inlines.Add(new Run("   "));
                }
            }

            p.Inlines.Add(new Run(" |") { Foreground = Brushes.Gray });

            // ASCII part
            for (int j = i; j < lineEnd; j++)
            {
                byte b = data[j];
                char c = (b >= 32 && b <= 126) ? (char)b : '.';

                var run = new Run(c.ToString());
                if (InSel(j)) run.Background = Brushes.Yellow;
                p.Inlines.Add(run);
            }

            p.Inlines.Add(new Run("|") { Foreground = Brushes.Gray });
            p.Inlines.Add(new LineBreak());
        }

        doc.Blocks.Add(p);
        return doc;
    }

    public FlowDocument BuildHexDocumentHighlighted(byte[] data, int bytesPerLine, (int start, int length)? sel)
    {
        // Keep older "Khaki" highlight color for selection in Rebuild
        int highlightStart = -1;
        int highlightEnd = -1;
        if (sel is { } r)
        {
            highlightStart = Math.Max(0, r.start);
            highlightEnd = Math.Min(data.Length, r.start + Math.Max(0, r.length)); // exclusive
            if (highlightStart >= highlightEnd)
            {
                highlightStart = highlightEnd = -1; // nothing
            }
        }

        Brush hlBg = Brushes.Khaki;

        var doc = new FlowDocument
        {
            PageWidth = 2000,
            LineHeight = 1,
        };

        for (int i = 0; i < data.Length; i += bytesPerLine)
        {
            int lineEnd = Math.Min(i + bytesPerLine, data.Length);

            var p = new Paragraph
            {
                Margin = new Thickness(0),
            };

            // Offset
            p.Inlines.Add(new Run(i.ToString("X4") + ": "));

            // HEX bytes
            for (int j = i; j < i + bytesPerLine; j++)
            {
                if (j < lineEnd)
                {
                    bool isHl = highlightStart >= 0 && j >= highlightStart && j < highlightEnd;

                    var run = new Run(data[j].ToString("X2") + " ");
                    if (isHl) run.Background = hlBg;
                    p.Inlines.Add(run);
                }
                else
                {
                    p.Inlines.Add(new Run("   "));
                }
            }

            // Separator
            p.Inlines.Add(new Run(" |"));

            // ASCII
            for (int j = i; j < lineEnd; j++)
            {
                bool isHl = highlightStart >= 0 && j >= highlightStart && j < highlightEnd;

                char c = data[j] >= 32 && data[j] <= 126 ? (char)data[j] : '.';
                var run = new Run(c.ToString());
                if (isHl) run.Background = hlBg;
                p.Inlines.Add(run);
            }

            // Close
            p.Inlines.Add(new Run("|"));

            doc.Blocks.Add(p);
        }

        return doc;
    }
}
