/////////////////////////////////////////////////////////////////////////////
// Name:        richtextctrl.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_richtextctrl wxRichTextCtrl Overview

@li @ref overview_richtextctrl_classes
@li @ref overview_richtextctrl_intro
@li @ref overview_richtextctrl_example
@li @ref overview_richtextctrl_starting
@li @ref overview_richtextctrl_styles
@li @ref overview_richtextctrl_dialogs
@li @ref overview_richtextctrl_impl
@li @ref overview_richtextctrl_roadmap


<hr>


@section overview_richtextctrl_classes Related Classes

<b>Major classes:</b>
wxRichTextCtrl, wxRichTextBuffer, wxRichTextEvent

<b>Helper classes:</b>
wxTextAttr, wxRichTextRange

<b>File handler classes:</b>
wxRichTextFileHandler, wxRichTextHTMLHandler, wxRichTextXMLHandler

<b>Style classes:</b>
wxRichTextCharacterStyleDefinition, wxRichTextParagraphStyleDefinition,
wxRichTextListStyleDefinition, wxRichTextStyleSheet

<b>Additional controls:</b>
wxRichTextStyleComboCtrl, wxRichTextStyleListBox, wxRichTextStyleListCtrl

<b>Printing classes:</b>
wxRichTextPrinting, wxRichTextPrintout, wxRichTextHeaderFooterData

<b>Dialog classes:</b>
wxRichTextStyleOrganiserDialog, wxRichTextFormattingDialog,
wxSymbolPickerDialog


@section overview_richtextctrl_intro Introduction

wxRichTextCtrl provides a generic implementation of a rich text editor that can
handle different character styles, paragraph formatting, and images. It's aimed
at editing 'natural' language text - if you need an editor that supports code
editing, wxStyledTextCtrl is a better choice.

Despite its name, it cannot currently read or write RTF (rich text format)
files. Instead, it uses its own XML format, and can also read and write plain
text. In future we expect to provide RTF file capabilities. Custom file formats
can be supported by creating additional file handlers and registering them with
the control.

wxRichTextCtrl is largely compatible with the wxTextCtrl API, but extends it
where necessary. The control can be used where the native rich text
capabilities of wxTextCtrl are not adequate (this is particularly true on
Windows) and where more direct access to the content representation is
required. It is difficult and inefficient to read the style information in a
wxTextCtrl, whereas this information is readily available in wxRichTextCtrl.
Since it's written in pure wxWidgets, any customizations you make to
wxRichTextCtrl will be reflected on all platforms.

wxRichTextCtrl supports basic printing via the easy-to-use wxRichTextPrinting
class. Creating applications with simple word processing features is simplified
with the inclusion of wxRichTextFormattingDialog, a tabbed dialog allowing
interactive tailoring of paragraph and character styling. Also provided is the
multi-purpose dialog wxRichTextStyleOrganiserDialog that can be used for
managing style definitions, browsing styles and applying them, or selecting
list styles with a renumber option.

There are a few disadvantages to using wxRichTextCtrl. It is not native, so
does not behave exactly as a native wxTextCtrl, although common editing
conventions are followed. Users may miss the built-in spelling correction on
Mac OS X, or any special character input that may be provided by the native
control. It would also be a poor choice if intended users rely on screen
readers that would be not work well with non-native text input implementation.
You might mitigate this by providing the choice between wxTextCtrl and
wxRichTextCtrl, with fewer features in the former case.

A good way to understand wxRichTextCtrl's capabilities is to compile and run
the sample, @c samples/richtext, and browse the code.


@section overview_richtextctrl_example Code Example

The following code is an example taken from the sample, and adds text and
styles to a rich text control programmatically.

@code
wxRichTextCtrl* richTextCtrl = new wxRichTextCtrl(
    splitter, wxID_ANY, wxEmptyString, wxDefaultPosition,
    wxSize(200, 200), wxVSCROLL | wxHSCROLL | wxBORDER_NONE | wxWANTS_CHARS);

wxFont textFont = wxFont(12, wxROMAN, wxNORMAL, wxNORMAL);
wxFont boldFont = wxFont(12, wxROMAN, wxNORMAL, wxBOLD);
wxFont italicFont = wxFont(12, wxROMAN, wxITALIC, wxNORMAL);

wxFont font(12, wxROMAN, wxNORMAL, wxNORMAL);

m_richTextCtrl->SetFont(font);

wxRichTextCtrl& r = richTextCtrl;

r.BeginSuppressUndo();

r.BeginParagraphSpacing(0, 20);

r.BeginAlignment(wxTEXT_ALIGNMENT_CENTRE);
r.BeginBold();

r.BeginFontSize(14);
r.WriteText(wxT("Welcome to wxRichTextCtrl, a wxWidgets control for editing and presenting styled text and images"));
r.EndFontSize();
r.Newline();

r.BeginItalic();
r.WriteText(wxT("by Julian Smart"));
r.EndItalic();

r.EndBold();

r.Newline();
r.WriteImage(wxBitmap(zebra_xpm));

r.EndAlignment();

r.Newline();
r.Newline();

r.WriteText(wxT("What can you do with this thing? "));
r.WriteImage(wxBitmap(smiley_xpm));
r.WriteText(wxT(" Well, you can change text "));

r.BeginTextColour(wxColour(255, 0, 0));
r.WriteText(wxT("colour, like this red bit."));
r.EndTextColour();

r.BeginTextColour(wxColour(0, 0, 255));
r.WriteText(wxT(" And this blue bit."));
r.EndTextColour();

r.WriteText(wxT(" Naturally you can make things "));
r.BeginBold();
r.WriteText(wxT("bold "));
r.EndBold();
r.BeginItalic();
r.WriteText(wxT("or italic "));
r.EndItalic();
r.BeginUnderline();
r.WriteText(wxT("or underlined."));
r.EndUnderline();

r.BeginFontSize(14);
r.WriteText(wxT(" Different font sizes on the same line is allowed, too."));
r.EndFontSize();

r.WriteText(wxT(" Next we'll show an indented paragraph."));

r.BeginLeftIndent(60);
r.Newline();

r.WriteText(wxT("Indented paragraph."));
r.EndLeftIndent();

r.Newline();

r.WriteText(wxT("Next, we'll show a first-line indent, achieved using BeginLeftIndent(100, -40)."));

r.BeginLeftIndent(100, -40);
r.Newline();

r.WriteText(wxT("It was in January, the most down-trodden month of an Edinburgh winter."));
r.EndLeftIndent();

r.Newline();

r.WriteText(wxT("Numbered bullets are possible, again using subindents:"));

r.BeginNumberedBullet(1, 100, 60);
r.Newline();

r.WriteText(wxT("This is my first item. Note that wxRichTextCtrl doesn't automatically do numbering, but this will be added later."));
r.EndNumberedBullet();

r.BeginNumberedBullet(2, 100, 60);
r.Newline();

r.WriteText(wxT("This is my second item."));
r.EndNumberedBullet();

r.Newline();

r.WriteText(wxT("The following paragraph is right-indented:"));

r.BeginRightIndent(200);
r.Newline();

r.WriteText(wxT("It was in January, the most down-trodden month of an Edinburgh winter. An attractive woman came into the cafe, which is nothing remarkable."));
r.EndRightIndent();

r.Newline();

wxArrayInt tabs;
tabs.Add(400);
tabs.Add(600);
tabs.Add(800);
tabs.Add(1000);
wxTextAttr attr;
attr.SetFlags(wxTEXT_ATTR_TABS);
attr.SetTabs(tabs);
r.SetDefaultStyle(attr);

r.WriteText(wxT("This line contains tabs:\tFirst tab\tSecond tab\tThird tab"));

r.Newline();
r.WriteText(wxT("Other notable features of wxRichTextCtrl include:"));

r.BeginSymbolBullet(wxT('*'), 100, 60);
r.Newline();
r.WriteText(wxT("Compatibility with wxTextCtrl API"));
r.EndSymbolBullet();

r.WriteText(wxT("Note: this sample content was generated programmatically from within the MyFrame constructor in the demo. The images were loaded from inline XPMs. Enjoy wxRichTextCtrl!"));

r.EndSuppressUndo();
@endcode


@section overview_richtextctrl_starting Starting to Use wxRichTextCtrl

You need to include @c @<wx/richtext/richtextctrl.h@> in your source, and link
with the appropriate wxWidgets library with @c richtext suffix. Put the rich
text library first in your link line to avoid unresolved symbols.

Then you can create a wxRichTextCtrl, with the wxWANT_CHARS style if you want
tabs to be processed by the control rather than being used for navigation
between controls.


@section overview_richtextctrl_styles Text Styles

Styling attributes are represented by wxTextAttr.

When setting a style, the flags of the attribute object determine which
attributes are applied. When querying a style, the passed flags are ignored
except (optionally) to determine whether attributes should be retrieved from
character content or from the paragraph object.

wxRichTextCtrl takes a layered approach to styles, so that different parts of
the content may be responsible for contributing different attributes to the
final style you see on the screen.

There are four main notions of style within a control:

@li <b>Basic style</b>: The fundamental style of a control, onto which any
    other styles are layered. It provides default attributes, and changing the
    basic style may immediately change the look of the content depending on
    what other styles the content uses. Calling wxRichTextCtrl::SetFont changes
    the font for the basic style. The basic style is set with
    wxRichTextCtrl::SetBasicStyle.
@li <b>Paragraph style</b>: Each paragraph has attributes that are set
    independently from other paragraphs and independently from the content
    within the paragraph. Normally, these attributes are paragraph-related,
    such as alignment and indentation, but it is possible to set character
    attributes too. The paragraph style can be set independently of its content
    by passing wxRICHTEXT_SETSTYLE_PARAGRAPHS_ONLY to
    wxRichTextCtrl::SetStyleEx.
@li <b>Character style</b>: Characters within each paragraph can have
    attributes. A single character, or a run of characters, can have a
    particular set of attributes. The character style can be with
    wxRichTextCtrl::SetStyle or wxRichTextCtrl::SetStyleEx.
@li <b>Default style</b>: This is the 'current' style that determines the style
    of content that is subsequently typed, pasted or programmatically inserted.
    The default style is set with wxRichTextCtrl::SetDefaultStyle.

What you see on the screen is the dynamically @e combined style, found by
merging the first three of the above style types (the fourth is only a guide
for future content insertion and therefore does not affect the currently
displayed content).

To make all this more concrete, here are examples of where you might set these
different styles:

@li You might set the <em>basic style</em> to have a Times Roman font in 12
    point, left-aligned, with two millimetres of spacing after each paragraph.
@li You might set the <em>paragraph style</em> (for one particular paragraph)
    to be centred.
@li You might set the <em>character style</em> of one particular word to bold.
@li You might set the <em>default style</em> to be underlined, for subsequent
    inserted text.

Naturally you can do any of these things either using your own UI, or
programmatically.

The basic wxTextCtrl doesn't make the same distinctions as wxRichTextCtrl
regarding attribute storage. So we need finer control when setting and
retrieving attributes. wxRichTextCtrl::SetStyleEx takes a @e flags parameter:

@li wxRICHTEXT_SETSTYLE_OPTIMIZE specifies that the style should be changed
    only if the combined attributes are different from the attributes for the
    current object. This is important when applying styling that has been
    edited by the user, because he has just edited the @e combined (visible)
    style, and wxRichTextCtrl wants to leave unchanged attributes associated
    with their original objects instead of applying them to both paragraph and
    content objects.
@li wxRICHTEXT_SETSTYLE_PARAGRAPHS_ONLY specifies that only paragraph objects
    within the given range should take on the attributes.
@li wxRICHTEXT_SETSTYLE_CHARACTERS_ONLY specifies that only content objects
    (text or images) within the given range should take on the attributes.
@li wxRICHTEXT_SETSTYLE_WITH_UNDO specifies that the operation should be
    undoable.

It's great to be able to change arbitrary attributes in a wxRichTextCtrl, but
it can be unwieldy for the user or programmer to set attributes separately.
Word processors have collections of styles that you can tailor or use as-is,
and this means that you can set a heading with one click instead of marking
text in bold, specifying a large font size, and applying a certain paragraph
spacing and alignment for every such heading. Similarly, wxWidgets provides a
class called wxRichTextStyleSheet which manages style definitions
(wxRichTextParagraphStyleDefinition, wxRichTextListStyleDefinition and
wxRichTextCharacterStyleDefinition). Once you have added definitions to a style
sheet and associated it with a wxRichTextCtrl, you can apply a named definition
to a range of text. The classes wxRichTextStyleComboCtrl and
wxRichTextStyleListBox can be used to present the user with a list of styles in
a sheet, and apply them to the selected text.

You can reapply a style sheet to the contents of the control, by calling
wxRichTextCtrl::ApplyStyleSheet. This is useful if the style definitions have
changed, and you want the content to reflect this. It relies on the fact that
when you apply a named style, the style definition name is recorded in the
content. So ApplyStyleSheet works by finding the paragraph attributes with
style names and re-applying the definition's attributes to the paragraph.
Currently, this works with paragraph and list style definitions only.


@section overview_richtextctrl_dialogs Included Dialogs

wxRichTextCtrl comes with standard dialogs to make it easier to implement text
editing functionality.

wxRichTextFormattingDialog can be used for character or paragraph formatting,
or a combination of both. It's a wxPropertySheetDialog with the following
available tabs: Font, Indents @& Spacing, Tabs, Bullets, Style, and List Style.
You can select which pages will be shown by supplying flags to the dialog
constructor. In a character formatting dialog, typically only the Font page
will be shown. In a paragraph formatting dialog, you'll show the Indents @&
Spacing, Tabs and Bullets pages. The Style tab is useful when editing a style
definition.

You can customize this dialog by providing your own
wxRichTextFormattingDialogFactory object, which tells the formatting dialog how
many pages are supported, what their identifiers are, and how to creates the
pages.

wxRichTextStyleOrganiserDialog is a multi-purpose dialog that can be used for
managing style definitions, browsing styles and applying them, or selecting
list styles with a renumber option. See the sample for usage - it is used for
the "Manage Styles" and "Bullets and Numbering" menu commands.

wxSymbolPickerDialog lets the user insert a symbol from a specified font. It
has no wxRichTextCtrl dependencies besides being included in the rich text
library.


@section overview_richtextctrl_impl How wxRichTextCtrl is Implemented

Data representation is handled by wxRichTextBuffer, and a wxRichTextCtrl always
has one such buffer.

The content is represented by a hierarchy of objects, all derived from
wxRichTextObject. An object might be an image, a fragment of text, a paragraph,
or a whole buffer. Objects store a wxTextAttr containing style information; a
paragraph object can contain both paragraph and character information, but
content objects such as text can only store character information. The final
style displayed in the control or in a printout is a combination of base style,
paragraph style and content (character) style.

The top of the hierarchy is the buffer, a kind of wxRichTextParagraphLayoutBox,
containing further wxRichTextParagraph objects, each of which can include text,
images and potentially other types of object.

Each object maintains a range (start and end position) measured from the start
of the main parent object.

When Layout is called on an object, it is given a size which the object must
limit itself to, or one or more flexible directions (vertical or horizontal).
So, for example, a centred paragraph is given the page width to play with
(minus any margins), but can extend indefinitely in the vertical direction.
The implementation of Layout caches the calculated size and position.

When the buffer is modified, a range is invalidated (marked as requiring
layout), so that only the minimum amount of layout is performed.

A paragraph of pure text with the same style contains just one further object,
a wxRichTextPlainText object. When styling is applied to part of this object,
the object is decomposed into separate objects, one object for each different
character style. So each object within a paragraph always has just one
wxTextAttr object to denote its character style. Of course, this can lead to
fragmentation after a lot of edit operations, potentially leading to several
objects with the same style where just one would do. So a Defragment function
is called when updating the control's display, to ensure that the minimum
number of objects is used.


@section overview_richtextctrl_roadmap Development Roadmap

@subsection overview_richtextctrl_roadmap_bugs Bugs

This is an incomplete list of bugs.

@li Moving the caret up at the beginning of a line sometimes incorrectly
    positions the caret.
@li As the selection is expanded, the text jumps slightly due to kerning
    differences between drawing a single text string versus drawing several
    fragments separately. This could be improved by using
    wxDC::GetPartialTextExtents to calculate exactly where the separate
    fragments should be drawn. Note that this problem also applies to
    separation of text fragments due to difference in their attributes.

@subsection overview_richtextctrl_roadmap_features Features

This is a list of some of the features that have yet to be implemented. Help
with them will be appreciated.

@li RTF input and output
@li Conversion from HTML
@li Open Office input and output
@li Floating images, with content wrapping around them
@li A ruler control
@li Standard editing toolbars
@li Tables
@li Bitmap bullets
@li Borders
@li Text frames
@li Justified text, in print/preview at least

There are also things that could be done to take advantage of the underlying
text capabilities of the platform; higher-level text formatting APIs are
available on some platforms, such as Mac OS X, and some of translation from
high level to low level wxDC API is unnecessary. However this would require
additions to the wxWidgets API.

*/

