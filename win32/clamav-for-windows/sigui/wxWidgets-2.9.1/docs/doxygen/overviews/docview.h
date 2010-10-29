/////////////////////////////////////////////////////////////////////////////
// Name:        docview.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_docview Document/View Framework

Classes: wxDocument, wxView, wxDocTemplate, wxDocManager, wxDocParentFrame,
        wxDocChildFrame, wxDocMDIParentFrame, wxDocMDIChildFrame,
        wxCommand, wxCommandProcessor

The document/view framework is found in most application frameworks, because it
can dramatically simplify the code required to build many kinds of application.

The idea is that you can model your application primarily in terms of @e documents to store data
and provide interface-independent operations upon it, and @e views to visualise and manipulate
the data. Documents know how to do input and output given stream objects, and views are responsible
for taking input from physical windows and performing the manipulation on the document data.

If a document's data changes, all views should be updated to reflect the change.
The framework can provide many user-interface elements based on this model.

Once you have defined your own classes and the relationships between them, the framework
takes care of popping up file selectors, opening and closing files, asking the user to save
modifications, routing menu commands to appropriate (possibly default) code, even
some default print/preview functionality and support for command undo/redo.

The framework is highly modular, allowing overriding and replacement of functionality
and objects to achieve more than the default behaviour.

These are the overall steps involved in creating an application based on the
document/view framework:

@li Define your own document and view classes, overriding a minimal set of
    member functions e.g. for input/output, drawing and initialization.
@li Define any subwindows (such as a scrolled window) that are needed for the view(s).
    You may need to route some events to views or documents, for example OnPaint needs
    to be routed to wxView::OnDraw.
@li Decide what style of interface you will use: Microsoft's MDI (multiple
    document child frames surrounded by an overall frame), SDI (a separate, unconstrained frame
    for each document), or single-window (one document open at a time, as in Windows Write).
@li Use the appropriate wxDocParentFrame and wxDocChildFrame classes. Construct an instance
    of wxDocParentFrame in your wxApp::OnInit, and a wxDocChildFrame (if not single-window) when
    you initialize a view. Create menus using standard menu ids (such as wxID_OPEN, wxID_PRINT).
@li Construct a single wxDocManager instance at the beginning of your wxApp::OnInit, and then
    as many wxDocTemplate instances as necessary to define relationships between documents and
    views. For a simple application, there will be just one wxDocTemplate.

If you wish to implement Undo/Redo, you need to derive your own class(es) from wxCommand
and use wxCommandProcessor::Submit instead of directly executing code. The framework will
take care of calling Undo and Do functions as appropriate, so long as the wxID_UNDO and
wxID_REDO menu items are defined in the view menu.

Here are a few examples of the tailoring you can do to go beyond the default framework
behaviour:

@li Override wxDocument::OnCreateCommandProcessor to define a different Do/Undo strategy,
    or a command history editor.
@li Override wxView::OnCreatePrintout to create an instance of a derived wxPrintout
    class, to provide multi-page document facilities.
@li Override wxDocManager::SelectDocumentPath to provide a different file selector.
@li Limit the maximum number of open documents and the maximum number of undo commands.

Note that to activate framework functionality, you need to use some or all of
the wxWidgets @ref overview_docview_predefid in your menus.

@beginWxPerlOnly
The document/view framework is available in wxPerl. To use it,
you will need the following statements in your application code:

@code
use Wx::DocView;
use Wx ':docview';   # import constants (optional)
@endcode
@endWxPerlOnly

@li @ref overview_docview_wxdoc
@li @ref overview_docview_wxview
@li @ref overview_docview_wxdoctemplate
@li @ref overview_docview_wxdocmanager
@li @ref overview_docview_wxcommand
@li @ref overview_docview_wxcommandproc
@li @ref overview_docview_filehistory
@li @ref overview_docview_predefid


<hr>


@section overview_docview_wxdoc wxDocument overview

Class: wxDocument

The wxDocument class can be used to model an application's file-based
data. It is part of the document/view framework supported by wxWidgets,
and cooperates with the wxView, wxDocTemplate and wxDocManager classes.
Using this framework can save a lot of routine user-interface programming,
since a range of menu commands -- such as open, save, save as -- are supported
automatically.

The programmer just needs to define a minimal set of classes and member functions
for the framework to call when necessary. Data, and the means to view and edit
the data, are explicitly separated out in this model, and the concept of multiple
@e views onto the same data is supported.

Note that the document/view model will suit many but not all styles of application.
For example, it would be overkill for a simple file conversion utility, where there
may be no call for @e views on @e documents or the ability to open, edit and save
files. But probably the majority of applications are document-based.

See the example application in @c samples/docview.
To use the abstract wxDocument class, you need to derive a new class and override
at least the member functions SaveObject and LoadObject. SaveObject and
LoadObject will be called by the framework when the document needs to be saved
or loaded.

Use the macros DECLARE_DYNAMIC_CLASS and IMPLEMENT_DYNAMIC_CLASS in order
to allow the framework to create document objects on demand. When you create
a wxDocTemplate object on application initialization, you
should pass CLASSINFO(YourDocumentClass) to the wxDocTemplate constructor
so that it knows how to create an instance of this class.

If you do not wish to use the wxWidgets method of creating document
objects dynamically, you must override wxDocTemplate::CreateDocument
to return an instance of the appropriate class.



@section overview_docview_wxview wxView overview

Class: wxView

The wxView class can be used to model the viewing and editing component of
an application's file-based data. It is part of the document/view framework
supported by wxWidgets, and cooperates with the wxDocument, wxDocTemplate
and wxDocManager classes.

See the example application in @c samples/docview.

To use the abstract wxView class, you need to derive a new class and override
at least the member functions OnCreate, OnDraw, OnUpdate and OnClose. You will probably
want to respond to menu commands from the frame containing the view.

Use the macros DECLARE_DYNAMIC_CLASS and IMPLEMENT_DYNAMIC_CLASS in order
to allow the framework to create view objects on demand. When you create
a wxDocTemplate object on application initialization, you
should pass CLASSINFO(YourViewClass) to the wxDocTemplate constructor
so that it knows how to create an instance of this class.

If you do not wish to use the wxWidgets method of creating view
objects dynamically, you must override wxDocTemplate::CreateView
to return an instance of the appropriate class.



@section overview_docview_wxdoctemplate wxDocTemplate overview

Class: wxDocTemplate

The wxDocTemplate class is used to model the relationship between a
document class and a view class. The application creates a document
template object for each document/view pair. The list of document
templates managed by the wxDocManager instance is used to create
documents and views. Each document template knows what file filters
and default extension are appropriate for a document/view combination,
and how to create a document or view.

For example, you might write a small doodling application that can load
and save lists of line segments. If you had two views of the data -- graphical,
and a list of the segments -- then you would create one document class DoodleDocument,
and two view classes (DoodleGraphicView and DoodleListView). You would also
need two document templates, one for the graphical view and another for the
list view. You would pass the same document class and default file extension to both
document templates, but each would be passed a different view class. When
the user clicks on the Open menu item, the file selector is displayed
with a list of possible file filters -- one for each wxDocTemplate. Selecting
the filter selects the wxDocTemplate, and when a file is selected, that template
will be used for creating a document and view.

For the case where an application has one document type and one view type,
a single document template is constructed, and dialogs will be appropriately
simplified.

wxDocTemplate is part of the document/view framework supported by wxWidgets,
and cooperates with the wxView, wxDocument and wxDocManager classes.

See the example application in @c samples/docview.

To use the wxDocTemplate class, you do not need to derive a new class.
Just pass relevant information to the constructor including CLASSINFO(YourDocumentClass)
and CLASSINFO(YourViewClass) to allow dynamic instance creation.

If you do not wish to use the wxWidgets method of creating document
objects dynamically, you must override wxDocTemplate::CreateDocument
and wxDocTemplate::CreateView to return instances of the appropriate class.

@note The document template has nothing to do with the C++ template construct.



@section overview_docview_wxdocmanager wxDocManager overview

Class: wxDocManager

The wxDocManager class is part of the document/view framework supported by wxWidgets,
and cooperates with the wxView, wxDocument and wxDocTemplate classes.

A wxDocManager instance coordinates documents, views and document templates.
It keeps a list of document and template instances, and much functionality is routed
through this object, such as providing selection and file dialogs.
The application can use this class 'as is' or derive a class and override some members
to extend or change the functionality.

Create an instance of this class near the beginning of your application initialization,
before any documents, views or templates are manipulated.

There may be multiple wxDocManager instances in an application.
See the example application in @c samples/docview.



@section overview_docview_wxcommand wxCommand overview

Classes: wxCommand, wxCommandProcessor

wxCommand is a base class for modelling an application command,
which is an action usually performed by selecting a menu item, pressing
a toolbar button or any other means provided by the application to
change the data or view.

Instead of the application functionality being scattered around
switch statements and functions in a way that may be hard to
read and maintain, the functionality for a command is explicitly represented
as an object which can be manipulated by a framework or application.

When a user interface event occurs, the application @e submits a command
to a wxCommandProcessor object to execute and store.

The wxWidgets document/view framework handles Undo and Redo by use of
wxCommand and wxCommandProcessor objects. You might find further uses
for wxCommand, such as implementing a macro facility that stores, loads
and replays commands.

An application can derive a new class for every command, or, more likely, use
one class parameterized with an integer or string command identifier.



@section overview_docview_wxcommandproc wxCommandProcessor overview

Classes: wxCommandProcessor, wxCommand

wxCommandProcessor is a class that maintains a history of wxCommand
instances, with undo/redo functionality built-in. Derive a new class from this
if you want different behaviour.



@section overview_docview_filehistory wxFileHistory overview

Classes: wxFileHistory, wxDocManager

wxFileHistory encapsulates functionality to record the last few files visited, and
to allow the user to quickly load these files using the list appended to the File menu.
Although wxFileHistory is used by wxDocManager, it can be used independently. You may wish
to derive from it to allow different behaviour, such as popping up a scrolling
list of files.

By calling wxFileHistory::UseMenu() you can associate a file menu with the file history.
The menu will then be used for appending filenames that are added to the history.

Please notice that currently if the history already contained filenames when UseMenu()
is called (e.g. when initializing a second MDI child frame), the menu is not automatically
initialized with the existing filenames in the history and so you need to call
wxFileHistory::AddFilesToMenu() after UseMenu() explicitly in order to initialize the menu with
the existing list of MRU files (otherwise an assertion failure is raised in debug builds).

The filenames are appended using menu identifiers in the range @c wxID_FILE1 to @c wxID_FILE9.

In order to respond to a file load command from one of these identifiers,
you need to handle them using an event handler, for example:

@code
BEGIN_EVENT_TABLE(wxDocParentFrame, wxFrame)
    EVT_MENU(wxID_EXIT, wxDocParentFrame::OnExit)
    EVT_MENU_RANGE(wxID_FILE1, wxID_FILE9, wxDocParentFrame::OnMRUFile)
END_EVENT_TABLE()

void wxDocParentFrame::OnExit(wxCommandEvent& WXUNUSED(event))
{
    Close();
}

void wxDocParentFrame::OnMRUFile(wxCommandEvent& event)
{
    wxString f(m_docManager->GetHistoryFile(event.GetId() - wxID_FILE1));
    if (!f.empty())
        (void)m_docManager-CreateDocument(f, wxDOC_SILENT);
}
@endcode



@section overview_docview_predefid wxWidgets predefined command identifiers

To allow communication between the application's menus and the
document/view framework, several command identifiers are predefined for you
to use in menus.

@verbatim
wxID_OPEN (5000)
wxID_CLOSE (5001)
wxID_NEW (5002)
wxID_SAVE (5003)
wxID_SAVEAS (5004)
wxID_REVERT (5005)
wxID_EXIT (5006)
wxID_UNDO (5007)
wxID_REDO (5008)
wxID_HELP (5009)
wxID_PRINT (5010)
wxID_PRINT_SETUP (5011)
wxID_PREVIEW (5012)
@endverbatim

*/

