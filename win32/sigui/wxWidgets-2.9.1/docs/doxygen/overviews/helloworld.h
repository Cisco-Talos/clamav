/////////////////////////////////////////////////////////////////////////////
// Name:        helloworld.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_helloworld Hello World Example

Many people have requested a mini-sample to be published here
so that some quick judgment concerning syntax
and basic principles can be made, so here we go.

First, you have to include wxWidgets' header files, of course. This can
be done on a file by file basis (such as <tt>@#include "wx/window.h"</tt>)
or using one global include (<tt>@#include "wx/wx.h"</tt>). This is
also useful on platforms which support precompiled headers such
as all major compilers on the Windows platform and GCC on Unix platforms.

@code
//
// file name: hworld.cpp
//
//   purpose: wxWidgets "Hello world"
//

// For compilers that support precompilation, includes "wx/wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/wx.h"
#endif
@endcode

Practically every app should define a new class derived from wxApp.
By overriding wxApp's OnInit() the program can be initialized,
e.g. by creating a new main window.

@code
class MyApp: public wxApp
{
    virtual bool OnInit();
};
@endcode

The main window is created by deriving a class from wxFrame and
giving it a menu and a status bar in its constructor. Also, any class
that wishes to respond to any "event" (such as mouse clicks or
messages from the menu or a button) must declare an event table
using the macro below.

Finally, the way to react to such events must be done in "handlers".
In our sample, we react to two menu items, one for "Quit" and one for
displaying an "About" window. These handlers should not be virtual.

@code
class MyFrame: public wxFrame
{
public:
    MyFrame(const wxString& title, const wxPoint& pos, const wxSize& size);

    void OnQuit(wxCommandEvent& event);
    void OnAbout(wxCommandEvent& event);

private:
    DECLARE_EVENT_TABLE()
};
@endcode

In order to be able to react to a menu command, it must be given a unique
identifier such as a const or an enum.

@code
enum
{
    ID_Quit = 1,
    ID_About,
};
@endcode

We then proceed to actually implement an event table in which the events
are routed to their respective handler functions in the class MyFrame.

There are predefined macros for routing all common events, ranging from
the selection of a list box entry to a resize event when a user resizes
a window on the screen. If -1 is given as the ID, the given handler will be
invoked for any event of the specified type, so that you could add just
one entry in the event table for all menu commands or all button commands etc.

The origin of the event can still be distinguished in the event handler as
the (only) parameter in an event handler is a reference to a wxEvent object,
which holds various information about the event (such as the ID of and a
pointer to the class, which emitted the event).

@code
BEGIN_EVENT_TABLE(MyFrame, wxFrame)
    EVT_MENU(ID_Quit,  MyFrame::OnQuit)
    EVT_MENU(ID_About, MyFrame::OnAbout)
END_EVENT_TABLE()
@endcode

As in all programs there must be a "main" function. Under wxWidgets main is implemented
using this macro, which creates an application instance and starts the program.

@code
IMPLEMENT_APP(MyApp)
@endcode

As mentioned above, wxApp::OnInit() is called upon startup and should be
used to initialize the program, maybe showing a "splash screen" and creating
the main window (or several). The frame should get a title bar text ("Hello World")
and a position and start-up size. One frame can also be declared to be the
top window. Returning @true indicates a successful initialization.

@code
bool MyApp::OnInit()
{
    MyFrame *frame = new MyFrame( "Hello World", wxPoint(50,50), wxSize(450,340) );
    frame->Show( true );
    SetTopWindow( frame );
    return true;
}
@endcode

In the constructor of the main window (or later on) we create a menu with two menu
items as well as a status bar to be shown at the bottom of the main window. Both have
to be "announced" to the frame with respective calls.

@code
MyFrame::MyFrame(const wxString& title, const wxPoint& pos, const wxSize& size)
        : wxFrame((wxFrame *)NULL, -1, title, pos, size)
{
    wxMenu *menuFile = new wxMenu;

    menuFile->Append( ID_About, "" );
    menuFile->AppendSeparator();
    menuFile->Append( ID_Quit, "E" );

    wxMenuBar *menuBar = new wxMenuBar;
    menuBar->Append( menuFile, "" );

    SetMenuBar( menuBar );

    CreateStatusBar();
    SetStatusText( "Welcome to wxWidgets!" );
}
@endcode

Here are the actual event handlers. MyFrame::OnQuit() closes the main window
by calling Close(). The parameter @true indicates that other windows have no veto
power such as after asking "Do you really want to close?". If there is no other
main window left, the application will quit.

@code
void MyFrame::OnQuit(wxCommandEvent& WXUNUSED(event))
{
    Close( true );
}
@endcode

MyFrame::OnAbout() will display a small window with some text in it. In this
case a typical "About" window with information about the program.

@code
void MyFrame::OnAbout(wxCommandEvent& WXUNUSED(event))
{
    wxMessageBox( "This is a wxWidgets' Hello world sample",
                "About Hello World", wxOK | wxICON_INFORMATION );
}
@endcode

*/

