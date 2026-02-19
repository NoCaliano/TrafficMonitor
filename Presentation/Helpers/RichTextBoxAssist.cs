using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Markup;
using System.Xml;

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
        if (d is not RichTextBox rtb) return;

        var newDoc = e.NewValue as FlowDocument;
        if (newDoc == null)
        {
            rtb.Document = new FlowDocument();
            return;
        }

        // If document already belongs to another RichTextBox, clone it.
        if (newDoc.Parent is RichTextBox existing && !ReferenceEquals(existing, rtb))
        {
            rtb.Document = CloneFlowDocument(newDoc) ?? new FlowDocument();
            return;
        }

        try
        {
            rtb.Document = newDoc;
        }
        catch (ArgumentException) // handle the actual exception thrown by WPF
        {
            rtb.Document = CloneFlowDocument(newDoc) ?? new FlowDocument();
        }
    }

    private static FlowDocument? CloneFlowDocument(FlowDocument source)
    {
        if (source == null)
            return null;

        // Deep-clone via XAML serialization (preserves content & formatting).
        var xaml = XamlWriter.Save(source);
        using var stringReader = new StringReader(xaml);
        using var xmlReader = XmlReader.Create(stringReader);
        return (FlowDocument)XamlReader.Load(xmlReader);
    }
}