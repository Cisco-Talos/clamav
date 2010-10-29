/////////////////////////////////////////////////////////////////////////////
// Name:        client.cpp
// Purpose:     Remote help sample client
// Author:      Julian Smart
// Modified by: Eric Dowty
// Created:     25/01/99
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#define USE_REMOTE 1

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/wx.h"
#endif

#include <math.h>

#include "wx/process.h"
#include "wx/helpbase.h"
#include "wx/html/helpfrm.h"
#include "wx/html/helpctrl.h"
#include "wx/config.h"

// Settings common to both executables: determines whether
// we're using TCP/IP or real DDE.

//#include "ddesetup.h"
//#define wxUSE_DDE_FOR_IPC 0
#include <wx/ipc.h>

#if defined(__WXGTK__) || defined(__WXMOTIF__)
#include "mondrian.xpm"
#endif

#include "remhelp.h"
#include "client.h"

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

IMPLEMENT_APP(MyApp)

BEGIN_EVENT_TABLE(MyFrame, wxFrame)
EVT_MENU(CLIENT_QUIT, MyFrame::OnExit)
EVT_MENU(CLIENT_HELPMAIN, MyFrame::OnHelp_Main)
EVT_MENU(CLIENT_HELPBOOK1, MyFrame::OnHelp_Book1)
EVT_MENU(CLIENT_HELPBOOK2, MyFrame::OnHelp_Book2)

EVT_MENU(CLIENT_HELPINDEX, MyFrame::OnHelp_Index)
EVT_MENU(CLIENT_HELPCONTENTS, MyFrame::OnHelp_Contents)
EVT_MENU(CLIENT_HELPSEARCH, MyFrame::OnHelp_Search)
EVT_MENU(CLIENT_HELPTITLE, MyFrame::OnHelp_Title)
EVT_MENU(CLIENT_HELPADDBOOK, MyFrame::OnHelp_Addbook)
EVT_MENU(CLIENT_HELPTEMPDIR, MyFrame::OnHelp_Tempdir)
EVT_MENU(CLIENT_HELPQUIT, MyFrame::OnHelp_Quitserver)

EVT_MENU(DIALOG_MODAL, MyFrame::ModalDlg)
EVT_BUTTON(BUTTON_MODAL, MyFrame::ModalDlg)
END_EVENT_TABLE()

// ----------------------------------------------------------------------------
// globals
// ----------------------------------------------------------------------------

wxListBox *the_list = NULL;

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// MyApp
// ----------------------------------------------------------------------------

// The `main program' equivalent, creating the windows and returning the
// main frame
bool MyApp::OnInit()
{
    wxString a_appname, a_service, a_windowname, a_book;

    m_help = NULL;

    // for MSW (DDE classes), a_service is 'service name', apparently an arbitrary string
    // for Unix, should be a valid file name (for a nonexistent file)
    // for nonMSW, nonUnix, must be port number, for example "4242" (TCP/IP based classes)
    // should be unique to the client app
    a_service = "/tmp/wxWidgets-helpconnection";
    //a_service = "4242";
    a_windowname = "HTML Help Test: %s";

#if defined(__WXMSW__)
    a_appname = "helpview.exe";
#else
    a_appname = "./helpview";
#endif

    //a_book = "helpfiles/testing.hhp";
    a_book = "test.zip";

    wxConfig *conf = (wxConfig*) wxConfig::Get();

#if defined(USE_REMOTE)
    m_help = new wxRemoteHtmlHelpController();
    m_help->SetServer( a_appname );
    m_help->SetService( a_service );
#else
    m_help = new wxHtmlHelpController();
#endif

    //this is a dummy for wxRemoteHtmlHelpController
    m_help->UseConfig(conf);

    m_help->AddBook( a_book );
    m_help->SetTitleFormat( a_windowname );

    // Create the main frame window
    MyFrame* frame = new MyFrame(NULL, "Help Client");
    frame->Show(true);

    return true;
}

int MyApp::OnExit()
{
    delete m_help;
    delete wxConfig::Set(NULL);
    return 0;
}

// Define my frame constructor
MyFrame::MyFrame(wxFrame *frame, const wxString& title)
: wxFrame(frame, wxID_ANY, title, wxDefaultPosition, wxSize( 200, 100 ) )
{
    m_panel = NULL;

    // Give it an icon
    SetIcon(wxICON(mondrian));

    // Make a menubar
    wxMenu *file_menu = new wxMenu;

    file_menu->Append(CLIENT_HELPMAIN, "Help - Main");
    file_menu->Append(CLIENT_HELPBOOK1, "Help - Book1");
    file_menu->Append(CLIENT_HELPBOOK2, "Help - Book2");

    file_menu->Append(CLIENT_HELPINDEX, "Help - DisplayIndex");
    file_menu->Append(CLIENT_HELPCONTENTS, "Help - DisplayContents");
    file_menu->Append(CLIENT_HELPSEARCH, "Help - KeywordSearch");
    file_menu->Append(CLIENT_HELPTITLE, "Help - SetTitleFormat");
    file_menu->Append(CLIENT_HELPADDBOOK, "Help - AddBook");
    file_menu->Append(CLIENT_HELPTEMPDIR, "Help - SetTempDir");
    file_menu->Append(CLIENT_HELPQUIT, "Help - Kill Server");

    file_menu->Append(DIALOG_MODAL, "Modal dialog");
    file_menu->Append(CLIENT_QUIT, "Quit");

    wxMenuBar *menu_bar = new wxMenuBar;

    menu_bar->Append(file_menu, "File");

    // Associate the menu bar with the frame
    SetMenuBar(menu_bar);

    // Make a panel
    m_panel = new wxPanel(this );

    m_modalbutton = new wxButton( this, BUTTON_MODAL, "Modal Dialog",
    wxPoint(10,10), wxDefaultSize );
}

void MyFrame::OnHelp_Book1(wxCommandEvent& event)
{
    wxGetApp().m_help->Display( "book1.htm" );
}

void MyFrame::OnHelp_Book2(wxCommandEvent& event)
{
    wxGetApp().m_help->Display( "book2.htm" );
}

void MyFrame::OnHelp_Main(wxCommandEvent& event)
{
    wxGetApp().m_help->Display( "main.htm" );
}

void MyFrame::OnHelp_Index(wxCommandEvent& event)
{
    wxGetApp().m_help->DisplayIndex( );
}
void MyFrame::OnHelp_Contents(wxCommandEvent& event)
{
    wxGetApp().m_help->DisplayContents( );
}

void MyFrame::OnHelp_Search(wxCommandEvent& event)
{
    wxGetApp().m_help->KeywordSearch( "enjoy" );
}
void MyFrame::OnHelp_Title(wxCommandEvent& event)
{
    wxGetApp().m_help->SetTitleFormat( "Another_Title: %s" );
}
void MyFrame::OnHelp_Addbook(wxCommandEvent& event)
{
    wxGetApp().m_help->AddBook("helpfiles/another.hhp" );
}
void MyFrame::OnHelp_Tempdir(wxCommandEvent& event)
{
    wxGetApp().m_help->SetTempDir( "tempdir" );
}

void MyFrame::OnHelp_Quitserver(wxCommandEvent& event)
{
    // if (!wxGetApp().m_help->m_connection->Poke( wxT("--YouAreDead"), wxT("") ) )
    // wxLogError(wxT("wxRemoteHtmlHelpController - YouAreDead Failed"));

    wxGetApp().m_help->Quit();
}

void MyFrame::OnExit(wxCommandEvent& event)
{
    Close();
}

void MyFrame::ModalDlg(wxCommandEvent& WXUNUSED(event))
{
    MyModalDialog dlg(this);
    dlg.ShowModal();
}

BEGIN_EVENT_TABLE(MyModalDialog, wxDialog)
EVT_BUTTON(wxID_ANY, MyModalDialog::OnButton)
END_EVENT_TABLE()

// ----------------------------------------------------------------------------
// MyModalDialog
// ----------------------------------------------------------------------------

MyModalDialog::MyModalDialog(wxWindow *parent)
: wxDialog(parent, wxID_ANY, wxString("Modal dialog"))
{
    wxBoxSizer *sizerTop = new wxBoxSizer(wxHORIZONTAL);

    m_main = new wxButton(this, wxID_ANY, "Main");
    m_book1 = new wxButton(this, wxID_ANY, "Book1");
    m_book2 = new wxButton(this, wxID_ANY, "Book2");
    sizerTop->Add(m_main, 0, wxALIGN_CENTER | wxALL, 5);
    sizerTop->Add(m_book1, 0, wxALIGN_CENTER | wxALL, 5);
    sizerTop->Add(m_book2, 0, wxALIGN_CENTER | wxALL, 5);

    SetSizer(sizerTop);

    sizerTop->SetSizeHints(this);
    sizerTop->Fit(this);

    m_main->SetFocus();
    m_main->SetDefault();
}

void MyModalDialog::OnButton(wxCommandEvent& event)
{
    if ( event.GetEventObject() == m_main )
    {
        wxGetApp().m_help->Display( "main.htm" );
    }
    else if ( event.GetEventObject() == m_book1 )
    {
        wxGetApp().m_help->Display( "book1.htm" );
    }
    else if ( event.GetEventObject() == m_book2 )
    {
        wxGetApp().m_help->Display( "book2.htm" );
    }
    else
    {
        event.Skip();
    }
}

