using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;

namespace Presentation.Helpers;

public static class RichTextBoxAssist
{
    public static readonly DependencyProperty BindableDocumentProperty =
        DependencyProperty.RegisterAttached(
            "BindableDocument",
            typeof(FlowDocument),
            typeof(RichTextBoxAssist),
            new FrameworkPropertyMetadata(null, OnBindableDocumentChanged));

    public static void SetBindableDocument(DependencyObject element, FlowDocument? value)
        => element.SetValue(BindableDocumentProperty, value);

    public static FlowDocument? GetBindableDocument(DependencyObject element)
        => (FlowDocument?)element.GetValue(BindableDocumentProperty);

    private static void OnBindableDocumentChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not RichTextBox rtb)
            return;

        rtb.Document = (FlowDocument?)e.NewValue ?? new FlowDocument();
    }
}