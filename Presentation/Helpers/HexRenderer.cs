// Відповідає за рендер hex-дампу у FlowDocument з підсвіткою діапазону байтів.
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;

namespace Presentation.Helpers;

public static class HexRenderer
{
    public static FlowDocument Render(byte[] bytes, (int start, int length)? highlight)
    {
        var doc = new FlowDocument
        {
            PagePadding = new Thickness(0)
        };

        if (bytes == null || bytes.Length == 0)
            return doc;

        int bytesPerLine = 16;
        int start = highlight?.start ?? -1;
        int end = highlight.HasValue ? highlight.Value.start + highlight.Value.length : -1;

        var para = new Paragraph { Margin = new Thickness(0) };

        for (int i = 0; i < bytes.Length; i += bytesPerLine)
        {
            // offset
            para.Inlines.Add(new Run(i.ToString("X8") + "  "));

            int lineLen = Math.Min(bytesPerLine, bytes.Length - i);

            // hex bytes
            for (int j = 0; j < bytesPerLine; j++)
            {
                if (j < lineLen)
                {
                    int idx = i + j;
                    var run = new Run(bytes[idx].ToString("X2") + " ");

                    if (highlight.HasValue && idx >= start && idx < end)
                        run.Background = Brushes.LightGoldenrodYellow;

                    para.Inlines.Add(run);
                }
                else
                {
                    para.Inlines.Add(new Run("   "));
                }

                if (j == 7) para.Inlines.Add(new Run(" "));
            }

            para.Inlines.Add(new Run(" |"));

            // ascii
            for (int j = 0; j < lineLen; j++)
            {
                int idx = i + j;
                byte b = bytes[idx];
                char c = (b >= 32 && b <= 126) ? (char)b : '.';

                var run = new Run(c.ToString());
                if (highlight.HasValue && idx >= start && idx < end)
                    run.Background = Brushes.LightGoldenrodYellow;

                para.Inlines.Add(run);
            }

            para.Inlines.Add(new Run("|"));
            para.Inlines.Add(new LineBreak());
        }

        doc.Blocks.Add(para);
        return doc;
    }
}
