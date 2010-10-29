/////////////////////////////////////////////////////////////////////////////
// Name:        roughguide.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_roughguide A Quick Guide to Writing Applications

To set a wxWidgets application going, you will need to derive a wxApp class and
override wxApp::OnInit.

An application must have a top-level wxFrame or wxDialog window. Each frame may
contain one or more instances of classes such as wxPanel, wxSplitterWindow or
other windows and controls.

A frame can have a wxMenuBar, a wxToolBar, a wxStatusBar, and a wxIcon for when
the frame is iconized.

A wxPanel is used to place controls (classes derived from wxControl) which are
used for user interaction. Examples of controls are wxButton, wxCheckBox,
wxChoice, wxListBox, wxRadioBox, and wxSlider.

Instances of wxDialog can also be used for controls and they have the advantage
of not requiring a separate frame.

Instead of creating a dialog box and populating it with items, it is possible
to choose one of the convenient common dialog classes, such as wxMessageDialog
and wxFileDialog.

You never draw directly onto a window - you use a <em>device context</em> (DC).
wxDC is the base for wxClientDC, wxPaintDC, wxMemoryDC, wxPostScriptDC,
wxMemoryDC, wxMetafileDC and wxPrinterDC. If your drawing functions have wxDC
as a parameter, you can pass any of these DCs to the function, and thus use the
same code to draw to several different devices. You can draw using the member
functions of wxDC, such as wxDC::DrawLine and wxDC::DrawText. Control colour on
a window (wxColour) with brushes (wxBrush) and pens (wxPen).

To intercept events, you add a DECLARE_EVENT_TABLE macro to the window class
declaration, and put a BEGIN_EVENT_TABLE ... END_EVENT_TABLE block in the
implementation file. Between these macros, you add event macros which map the
event (such as a mouse click) to a member function. These might override
predefined event handlers such as for wxKeyEvent and wxMouseEvent.

Most modern applications will have an on-line, hypertext help system; for this,
you need wxHelp and the wxHelpController class to control wxHelp.

GUI applications aren't all graphical wizardry. List and hash table needs are
catered for by wxList and wxHashMap. You will undoubtedly need some
platform-independent @ref group_funcmacro_file, and you may find it handy to
maintain and search a list of paths using wxPathList. There's many
@ref group_funcmacro_misc of operating system methods and other functions.

@see

@li @ref group_class

*/

