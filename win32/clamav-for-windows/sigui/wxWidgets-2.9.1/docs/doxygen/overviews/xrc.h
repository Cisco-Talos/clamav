/////////////////////////////////////////////////////////////////////////////
// Name:        xrc.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_xrc XML Based Resource System (XRC)

Classes: wxXmlResource, wxXmlResourceHandler

The XML-based resource system, known as XRC, allows user interface elements
such as dialogs, menu bars and toolbars, to be stored in text files and loaded
into the application at run-time. XRC files can also be compiled into binary
XRS files or C++ code (the former makes it possible to store all resources in a
single file and the latter is useful when you want to embed the resources into
the executable).

There are several advantages to using XRC resources:

@li Recompiling and linking an application is not necessary if the resources
    change.
@li If you use a dialog designer that generates C++ code, it can be hard to
    reintegrate this into existing C++ code. Separation of resources and code
    is a more elegant solution.
@li You can choose between different alternative resource files at run time, if
    necessary.
@li The XRC format uses sizers for flexibility, allowing dialogs to be
    resizable and highly portable.
@li The XRC format is a wxWidgets standard, and can be generated or
    postprocessed by any program that understands it. As it is basedon the XML
    standard, existing XML editors can be used for simple editing purposes.

XRC was written by Vaclav Slavik.

@li @ref overview_xrc_concepts
@li @ref overview_xrc_binaryresourcefiles
@li @ref overview_xrc_embeddedresource
@li @ref overview_xrc_cppsample
@li @ref overview_xrc_sample
@li @ref overview_xrc_cppheader
@li @ref overview_xrc_newresourcehandlers

See also the separate @ref overview_xrcformat page for details about the XRC file format.

<hr>


@section overview_xrc_concepts XRC Concepts

These are the typical steps for using XRC files in your application.

@li Include the appropriate headers: normally "wx/xrc/xmlres.h" will suffice.
@li If you are going to use XRS files (see
    @ref overview_xrc_binaryresourcefiles), install wxFileSystem archive
    handler first with wxFileSystem::AddHandler(new wxArchiveFSHandler);
@li Call wxXmlResource::Get()->InitAllHandlers() from your wxApp::OnInit
    function, and then call wxXmlResource::Get()->Load("myfile.xrc") to load
    the resource file.
@li To create a dialog from a resource, create it using the default
    constructor, and then load it. For example:
    wxXmlResource::Get()->LoadDialog(dlg, this, "dlg1");
@li Set up event tables as usual but use the XRCID(str) macro to translate from
    XRC string names to a suitable integer identifier, for example
    <tt>EVT_MENU(XRCID("quit"), MyFrame::OnQuit)</tt>.

To create an XRC file, you can use one of the following methods.

@li Create the file by hand.
@li Use wxDesigner <http://www.roebling.de/>, a commercial dialog designer/RAD
    tool.
@li Use DialogBlocks <http://www.anthemion.co.uk/dialogblocks/>, a commercial
    dialog editor.
@li Use XRCed <http://xrced.sf.net/>, a wxPython-based dialog editor that you
    can find in the wxPython/tools subdirectory of the wxWidgets SVN archive.
@li Use wxGlade <http://wxglade.sf.net/>, a GUI designer written in wxPython.
    At the moment it can generate Python, C++ and XRC.

A complete list of third-party tools that write to XRC can be found at
<http://www.wxwidgets.org/wiki/index.php/Tools>.

It is highly recommended that you use a resource editing tool, since it's
fiddly writing XRC files by hand.

You can use wxXmlResource::Load in a number of ways. You can pass an XRC file
(XML-based text resource file) or a zip-compressed file (see
@ref overview_xrc_binaryresourcefiles), with extension ZIP or XRS, containing
other XRC.

You can also use embedded C++ resources (see
@ref overview_xrc_embeddedresource).


@section overview_xrc_binaryresourcefiles Using Binary Resource Files

To compile binary resource files, use the command-line @c wxrc utility. It
takes one or more file parameters (the input XRC files) and the following
switches and options:

@li -h (--help): Show a help message.
@li -v (--verbose): Show verbose logging information.
@li -c (--cpp-code): Write C++ source rather than a XRS file.
@li -e (--extra-cpp-code): If used together with -c, generates C++ header file
    containing class definitions for the windows defined by the XRC file (see
    special subsection).
@li -u (--uncompressed): Do not compress XML files (C++ only).
@li -g (--gettext): Output underscore-wrapped strings that poEdit or gettext
    can scan. Outputs to stdout, or a file if -o is used.
@li -n (--function) @<name@>: Specify C++ function name (use with -c).
@li -o (--output) @<filename@>: Specify the output file, such as resource.xrs
    or resource.cpp.
@li -l (--list-of-handlers) @<filename@>: Output a list of necessary handlers
    to this file.

For example:

@code
$ wxrc resource.xrc
$ wxrc resource.xrc -o resource.xrs
$ wxrc resource.xrc -v -c -o resource.cpp
@endcode

@note XRS file is essentially a renamed ZIP archive which means that you can
manipulate it with standard ZIP tools. Note that if you are using XRS files,
you have to initialize the wxFileSystem archive handler first! It is a simple
thing to do:

@code
#include <wx/filesys.h>
#include <wx/fs_arc.h>
...
wxFileSystem::AddHandler(new wxArchiveFSHandler);
@endcode


@section overview_xrc_embeddedresource Using Embedded Resources

It is sometimes useful to embed resources in the executable itself instead of
loading an external file (e.g. when your app is small and consists only of one
exe file). XRC provides means to convert resources into regular C++ file that
can be compiled and included in the executable.

Use the @c -c switch to @c wxrc utility to produce C++ file with embedded
resources. This file will contain a function called @c InitXmlResource (unless
you override this with a command line switch). Use it to load the resource:

@code
extern void InitXmlResource(); // defined in generated file
...
wxXmlResource::Get()->InitAllHandlers();
InitXmlResource();
...
@endcode


@section overview_xrc_cppsample XRC C++ Sample

This is the C++ source file (xrcdemo.cpp) for the XRC sample.

@code
#include "wx/wx.h"
#include "wx/image.h"
#include "wx/xrc/xmlres.h"

// the application icon
#if defined(__WXGTK__) || defined(__WXMOTIF__) || defined(__WXMAC__)
    #include "rc/appicon.xpm"
#endif

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------

// Define a new application type, each program should derive a class from wxApp
class MyApp : public wxApp
{
public:
    // override base class virtuals
    // ----------------------------

    // this one is called on application startup and is a good place for the
    // app initialization (doing it here and not in the ctor allows to have an
    // error return: if OnInit() returns false, the application terminates)
    virtual bool OnInit();
};

// Define a new frame type: this is going to be our main frame
class MyFrame : public wxFrame
{
public:
    // ctor(s)
    MyFrame(const wxString& title, const wxPoint& pos, const wxSize& size);

    // event handlers (these functions should _not_ be virtual)
    void OnQuit(wxCommandEvent& event);
    void OnAbout(wxCommandEvent& event);
    void OnDlg1(wxCommandEvent& event);
    void OnDlg2(wxCommandEvent& event);

private:
    // any class wishing to process wxWidgets events must use this macro
    DECLARE_EVENT_TABLE()
};

// ----------------------------------------------------------------------------
// event tables and other macros for wxWidgets
// ----------------------------------------------------------------------------

BEGIN_EVENT_TABLE(MyFrame, wxFrame)
    EVT_MENU(XRCID("menu_quit"),  MyFrame::OnQuit)
    EVT_MENU(XRCID("menu_about"), MyFrame::OnAbout)
    EVT_MENU(XRCID("menu_dlg1"), MyFrame::OnDlg1)
    EVT_MENU(XRCID("menu_dlg2"), MyFrame::OnDlg2)
END_EVENT_TABLE()

IMPLEMENT_APP(MyApp)

// ----------------------------------------------------------------------------
// the application class
// ----------------------------------------------------------------------------

// 'Main program' equivalent: the program execution "starts" here
bool MyApp::OnInit()
{
    wxImage::AddHandler(new wxGIFHandler);
    wxXmlResource::Get()->InitAllHandlers();
    wxXmlResource::Get()->Load("rc/resource.xrc");

    MyFrame *frame = new MyFrame("XML resources demo",
                                 wxPoint(50, 50), wxSize(450, 340));
    frame->Show(true);
    return true;
}

// ----------------------------------------------------------------------------
// main frame
// ----------------------------------------------------------------------------

// frame constructor
MyFrame::MyFrame(const wxString& title, const wxPoint& pos, const wxSize& size)
: wxFrame((wxFrame *)NULL, -1, title, pos, size)
{
    SetIcon(wxICON(appicon));

    SetMenuBar(wxXmlResource::Get()->LoadMenuBar("mainmenu"));
    SetToolBar(wxXmlResource::Get()->LoadToolBar(this, "toolbar"));
}

// event handlers
void MyFrame::OnQuit(wxCommandEvent& WXUNUSED(event))
{
    // true is to force the frame to close
    Close(true);
}

void MyFrame::OnAbout(wxCommandEvent& WXUNUSED(event))
{
    wxString msg;
    msg.Printf( wxT("This is the about dialog of XML resources demo.\n")
                wxT("Welcome to %s"), wxVERSION_STRING);

    wxMessageBox(msg, "About XML resources demo",
                 wxOK | wxICON_INFORMATION, this);
}

void MyFrame::OnDlg1(wxCommandEvent& WXUNUSED(event))
{
    wxDialog dlg;
    wxXmlResource::Get()->LoadDialog(&dlg, this, "dlg1");
    dlg.ShowModal();
}

void MyFrame::OnDlg2(wxCommandEvent& WXUNUSED(event))
{
    wxDialog dlg;
    wxXmlResource::Get()->LoadDialog(&dlg, this, "dlg2");
    dlg.ShowModal();
}
@endcode


@section overview_xrc_sample XRC Resource File Sample

This is the XML file (resource.xrc) for the XRC sample.

@code
<?xml version="1.0"?>
<resource version="2.3.0.1">
  <object class="wxMenuBar" name="mainmenu">
    <style>wxMB_DOCKABLE</style>
    <object class="wxMenu" name="menu_file">
      <label>_File</label>
      <style>wxMENU_TEAROFF</style>
      <object class="wxMenuItem" name="menu_about">
        <label>_About...</label>
        <bitmap>filesave.gif</bitmap>
      </object>
      <object class="separator"/>
      <object class="wxMenuItem" name="menu_dlg1">
        <label>Dialog 1</label>
      </object>
      <object class="wxMenuItem" name="menu_dlg2">
        <label>Dialog 2</label>
      </object>
      <object class="separator"/>
      <object class="wxMenuItem" name="menu_quit">
        <label>E_xit\tAlt-X</label>
      </object>
    </object>
  </object>
  <object class="wxToolBar" name="toolbar">
    <style>wxTB_FLAT|wxTB_DOCKABLE</style>
    <margins>2,2</margins>
    <object class="tool" name="menu_open">
      <bitmap>fileopen.gif</bitmap>
      <tooltip>Open catalog</tooltip>
    </object>
    <object class="tool" name="menu_save">
      <bitmap>filesave.gif</bitmap>
      <tooltip>Save catalog</tooltip>
    </object>
    <object class="tool" name="menu_update">
      <bitmap>update.gif</bitmap>
      <tooltip>Update catalog - synchronize it with sources</tooltip>
    </object>
    <separator/>
    <object class="tool" name="menu_quotes">
      <bitmap>quotes.gif</bitmap>
      <toggle>1</toggle>
      <tooltip>Display quotes around the string?</tooltip>
    </object>
    <object class="separator"/>
    <object class="tool" name="menu_fuzzy">
      <bitmap>fuzzy.gif</bitmap>
      <tooltip>Toggled if selected string is fuzzy translation</tooltip>
      <toggle>1</toggle>
    </object>
  </object>
  <object class="wxDialog" name="dlg1">
    <object class="wxBoxSizer">
      <object class="sizeritem">
        <object class="wxBitmapButton">
          <bitmap>fuzzy.gif</bitmap>
          <focus>fileopen.gif</focus>
        </object>
      </object>
      <object class="sizeritem">
        <object class="wxPanel">
          <object class="wxStaticText">
            <label>fdgdfgdfgdfg</label>
          </object>
          <style>wxBORDER\_SUNKEN</style>
        </object>
        <flag>wxALIGN_CENTER</flag>
      </object>
      <object class="sizeritem">
        <object class="wxButton">
          <label>Buttonek</label>
        </object>
        <border>10d</border>
        <flag>wxALL</flag>
      </object>
      <object class="sizeritem">
        <object class="wxHtmlWindow">
          <htmlcode><h1>Hi,</h1>man</htmlcode>
          <size>100,45d</size>
        </object>
      </object>
      <object class="sizeritem">
        <object class="wxNotebook">
          <object class="notebookpage">
            <object class="wxPanel">
              <object class="wxBoxSizer">
                <object class="sizeritem">
                  <object class="wxHtmlWindow">
                    <htmlcode>Hello, we are inside a <u>NOTEBOOK</u>...</htmlcode>
                    <size>50,50d</size>
                  </object>
                  <option>1</option>
                </object>
              </object>
            </object>
            <label>Page</label>
            <image>0</image>
          </object>
          <object class="notebookpage">
            <object class="wxPanel">
              <object class="wxBoxSizer">
                <object class="sizeritem">
                  <object class="wxHtmlWindow">
                    <htmlcode>Hello, we are inside a <u>NOTEBOOK</u>...</htmlcode>
                    <size>50,50d</size>
                  </object>
                </object>
              </object>
            </object>
            <label>Page 2</label>
            <image>1</image>
          </object>
          <usenotebooksizer>1</usenotebooksizer>
        <imagelist>
            <size>16,16</size>
            <bitmap stock_id="wxART_QUESTION"/>
            <bitmap stock_id="wxART_WARNING"/>
        </imagelist>
        </object>
        <flag>wxEXPAND</flag>
      </object>
      <orient>wxVERTICAL</orient>
    </object>
  </object>
  <object class="wxDialog" name="dlg2">
    <object class="wxBoxSizer">
      <orient>wxVERTICAL</orient>
      <object class="sizeritem" name="dfgdfg">
        <object class="wxTextCtrl">
          <size>200,200d</size>
          <style>wxTE_MULTILINE|wxBORDER_SUNKEN</style>
          <value>Hello, this is an ordinary multiline\n         textctrl....</value>
        </object>
        <option>1</option>
        <flag>wxEXPAND|wxALL</flag>
        <border>10</border>
      </object>
      <object class="sizeritem">
        <object class="wxBoxSizer">
          <object class="sizeritem">
            <object class="wxButton" name="wxID_OK">
              <label>Ok</label>
              <default>1</default>
            </object>
          </object>
          <object class="sizeritem">
            <object class="wxButton" name="wxID_CANCEL">
              <label>Cancel</label>
            </object>
            <border>10</border>
            <flag>wxLEFT</flag>
          </object>
        </object>
        <flag>wxLEFT|wxRIGHT|wxBOTTOM|wxALIGN_RIGHT</flag>
        <border>10</border>
      </object>
    </object>
    <title>Second testing dialog</title>
  </object>
</resource>
@endcode


@section overview_xrc_cppheader C++ header file generation

Using the @c -e switch together with @c -c, a C++ header file is written
containing class definitions for the GUI windows defined in the XRC file. This
code generation can make it easier to use XRC and automate program development.
The classes can be used as basis for development, freeing the programmer from
dealing with most of the XRC specifics (e.g. @c XRCCTRL).

For each top level window defined in the XRC file a C++ class definition is
generated, containing as class members the named widgets of the window. A
default constructor for each class is also generated. Inside the constructor
all XRC loading is done and all class members representing widgets are
initialized.

A simple example will help understand how the scheme works. Suppose you have a
XRC file defining a top level window @c TestWnd_Base, which subclasses wxFrame
(any other class like @c wxDialog will do also), and has subwidgets wxTextCtrl A
and wxButton B.

The XRC file and corresponding class definition in the header file will be
something like:

@code
<?xml version="1.0"?>
<resource version="2.3.0.1">
    <object class="wxFrame" name="TestWnd_Base">
        <size>-1,-1</size>
        <title>Test</title>
        <object class="wxBoxSizer">
            <orient>wxHORIZONTAL</orient>
            <object class="sizeritem">
                <object class="wxTextCtrl" name="A">
                    <label>Test label</label>
                </object>
            </object>
            <object class="sizeritem">
                <object class="wxButton" name="B">
                    <label>Test button</label>
                </object>
            </object>
        </object>
    </object>
</resource>


class TestWnd_Base : public wxFrame
{
protected:
    wxTextCtrl* A;
    wxButton* B;

private:
    void InitWidgetsFromXRC()
    {
        wxXmlResource::Get()->LoadObject(this, NULL, "TestWnd", "wxFrame");
        A = XRCCTRL(*this, "A", wxTextCtrl);
        B = XRCCTRL(*this, "B", wxButton);
    }
public:
    TestWnd::TestWnd()
    {
        InitWidgetsFromXRC();
    }
};
@endcode

The generated window class can be used as basis for the full window class. The
class members which represent widgets may be accessed by name instead of using
@c XRCCTRL every time you wish to reference them (note that they are
@c protected class members), though you must still use @c XRCID to refer to
widget IDs in the event table.

Example:

@code
#include "resource.h"

class TestWnd : public TestWnd_Base
{
public:
    TestWnd()
    {
        // A, B already initialised at this point
        A->SetValue("Updated in TestWnd::TestWnd");
        B->SetValue("Nice :)");
    }
    void OnBPressed(wxEvent& event)
    {
        Close();
    }
    DECLARE_EVENT_TABLE();
};

BEGIN_EVENT_TABLE(TestWnd,TestWnd_Base)
    EVT_BUTTON(XRCID("B"), TestWnd::OnBPressed)
END_EVENT_TABLE()
@endcode

It is also possible to access the wxSizerItem of a sizer that is part of a
resource. This can be done using @c XRCSIZERITEM as shown.

The resource file can have something like this for a sizer item.

@code
<object class="spacer" name="area">
  <size>400, 300</size>
</object>
@endcode

The code can then access the sizer item by using @c XRCSIZERITEM and @c XRCID
together.

@code
wxSizerItem* item = XRCSIZERITEM(*this, "area");
@endcode


@section overview_xrc_newresourcehandlers Adding New Resource Handlers

Adding a new resource handler is pretty easy.

Typically, to add an handler for the @c MyControl class, you'll want to create
the @c xh_mycontrol.h and @c xh_mycontrol.cpp files.

The header needs to contains the @c MyControlXmlHandler class definition:

@code
class MyControlXmlHandler : public wxXmlResourceHandler
{
public:
    // Constructor.
    MyControlXmlHandler();

    // Creates the control and returns a pointer to it.
    virtual wxObject *DoCreateResource();

    // Returns true if we know how to create a control for the given node.
    virtual bool CanHandle(wxXmlNode *node);

    // Register with wxWidgets' dynamic class subsystem.
    DECLARE_DYNAMIC_CLASS(MyControlXmlHandler)
};
@endcode

The implementation of your custom XML handler will typically look as:

@code
// Register with wxWidgets' dynamic class subsystem.
IMPLEMENT_DYNAMIC_CLASS(MyControlXmlHandler, wxXmlResourceHandler)

MyControlXmlHandler::MyControlXmlHandler()
{
    // this call adds support for all wxWindows class styles
    // (e.g. wxBORDER_SIMPLE, wxBORDER_SUNKEN, wxWS_EX_* etc etc)
    AddWindowStyles();

    // if MyControl class supports e.g. MYCONTROL_DEFAULT_STYLE
    // you should use:
    //     XRC_ADD_STYLE(MYCONTROL_DEFAULT_STYLE);
}

wxObject *MyControlXmlHandler::DoCreateResource()
{
    // the following macro will init a pointer named "control"
    // with a new instance of the MyControl class, but will NOT
    // Create() it!
    XRC_MAKE_INSTANCE(control, MyControl)

    // this is the point where you'll typically need to do the most
    // important changes: here the control is created and initialized.
    // You'll want to use the wxXmlResourceHandler's getters to
    // do most of your work.
    // If e.g. the MyControl::Create function looks like:
    //
    // bool MyControl::Create(wxWindow *parent, int id,
    //                        const wxBitmap &first, const wxPoint &posFirst,
    //                        const wxBitmap &second, const wxPoint &posSecond,
    //                        const wxString &theTitle, const wxFont &titleFont,
    //                        const wxPoint &pos, const wxSize &size,
    //                        long style = MYCONTROL_DEFAULT_STYLE,
    //                        const wxString &name = wxT("MyControl"));
    //
    // Then the XRC for your component should look like:
    //
    //    <object class="MyControl" name="some_name">
    //      <first-bitmap>first.xpm</first-bitmap>
    //      <second-bitmap>text.xpm</second-bitmap>
    //      <first-pos>3,3</first-pos>
    //      <second-pos>4,4</second-pos>
    //      <the-title>a title</the-title>
    //      <title-font>
    //        <!-- Standard XRC tags for a font: <size>, <style>, <weight>, etc -->
    //      </title-font>
    //      <!-- XRC also accepts other usual tags for wxWindow-derived classes:
    //           like e.g. <name>, <style>, <size>, <position>, etc -->
    //    </object>
    //
    // And the code to read your custom tags from the XRC file is just:
    control->Create(m_parentAsWindow, GetID(),
                    GetBitmap(wxT("first-bitmap")),
                    GetPosition(wxT("first-pos")),
                    GetBitmap(wxT("second-bitmap")),
                    GetPosition(wxT("second-pos")),
                    GetText(wxT("the-title")),
                    GetFont(wxT("title-font")),
                    GetPosition(), GetSize(), GetStyle(), GetName());

    SetupWindow(control);

    return control;
}

bool MyControlXmlHandler::CanHandle(wxXmlNode *node)
{
    // this function tells XRC system that this handler can parse
    // the <object class="MyControl"> tags
    return IsOfClass(node, wxT("MyControl"));
}
@endcode

You may want to check the wxXmlResourceHandler documentation to see how many
built-in getters it contains. It's very easy to retrieve also complex
structures out of XRC files using them.

*/

