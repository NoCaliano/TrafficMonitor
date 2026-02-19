using System.Windows.Documents;

namespace Presentation.Services;

public interface IHexDumpService
{
    string BuildHexDump(byte[] data, int bytesPerLine);
    FlowDocument BuildHexDocument(byte[] data, int bytesPerLine, (int start, int length)? sel);
    FlowDocument BuildHexDocumentHighlighted(byte[] data, int bytesPerLine, (int start, int length)? sel);
}
