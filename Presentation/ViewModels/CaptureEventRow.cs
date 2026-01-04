// Відповідає за рядок у таблиці: час + довжина + коротка примітка (поки без парсингу протоколів).
namespace Presentation.ViewModels;

public sealed class CaptureEventRow
{
    public string Time { get; set; } = "";
    public int Length { get; set; }
    public string Note { get; set; } = "";
}
