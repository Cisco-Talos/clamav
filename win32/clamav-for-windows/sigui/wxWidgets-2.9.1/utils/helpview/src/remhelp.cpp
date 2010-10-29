/////////////////////////////////////////////////////////////////////////////
// Name:        remhelp.cpp
// Purpose:     Remote help controller class
// Author:      Eric Dowty
// Modified by:
// Created:     2002-11-18
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

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
#include "wx/confbase.h"

// Settings common to both executables: determines whether
// we're using TCP/IP or real DDE.

//#include "ddesetup.h"
//#define wxUSE_DDE_FOR_IPC 0

#if defined(__WXGTK__) || defined(__WXMOTIF__)
#include "mondrian.xpm"
#endif

#include "remhelp.h"
#include "client.h"

#if !defined(USE_REMOTE)
#include <wx/html/helpctrl.h>
#endif

//////////////////
//////////////////
// helper classes

rhhcClient::rhhcClient( bool *isconn_a )
{
    isconn_2 = isconn_a;
}

wxConnectionBase *rhhcClient::OnMakeConnection()
{
    return new rhhcConnection( isconn_2 );
}

rhhcConnection::rhhcConnection( bool *isconn_a )
: wxConnection()
{
    isconn_3 = isconn_a;
    *isconn_3 = true;
}

rhhcConnection::~rhhcConnection()
{
    *isconn_3 = false;
}

bool rhhcConnection::OnAdvise(const wxString& topic, const wxString& item, char *data, int size, wxIPCFormat format)
{
    return true;
}

bool rhhcConnection::OnDisconnect()
{
    *isconn_3 = false;

    return wxConnection::OnDisconnect();
}

//////////////////////////////////////////
/////////////////////////////////////////

// wxRemoteHtmlHelpController class

IMPLEMENT_CLASS(wxRemoteHtmlHelpController, wxHelpControllerBase)

wxRemoteHtmlHelpController::wxRemoteHtmlHelpController(int style )
{
    m_style = style;
    m_connection = NULL;
    m_client  = NULL;
    m_pid = 0;
    isconn_1 = false;
    m_process = NULL;

    // defaults
    //
    // server app is assumed to be local
    //
    // for MSW (DDE classes), a_service is 'service name', apparently an arbitrary string
    // for Unix, should be a valid file name (for a nonexistent file)
    // for nonMSW, nonUnix, must be port number, for example "4242" (TCP/IP based classes)
    // should be unique to the client app

    wxString thename = wxGetApp().GetAppName();
#if defined(__WXMSW__)
    m_appname = wxT("helpview.exe");
    m_service = thename + wxString(wxT("_helpservice"));
#elif defined(__UNIX__)
    m_appname = wxT("./helpview");
    m_service = wxT("/tmp/") + thename + wxString(wxT("_helpservice"));
#else
    m_appname = wxT("./helpview");
    m_service = wxT("4242");
#endif

    m_book = thename + wxT(".hhp");  // or .htb or .zip
    m_windowname = thename + wxT(" Help: %s");
    //underscores for spaces
    m_windowname.Replace( wxT(" "), wxT("_") );
}

void wxRemoteHtmlHelpController::SetService(wxString& a_service)
{
    m_service = a_service;
}
void wxRemoteHtmlHelpController::SetServer(wxString& a_appname)
{
    m_appname = a_appname;
}

void wxRemoteHtmlHelpController::OnQuit()
{
    //kill the Server here?
    //this function is not called ?
}

wxRemoteHtmlHelpController::~wxRemoteHtmlHelpController()
{
    if ( isconn_1 )
    {
        // if (!m_connection->Poke( wxT("--YouAreDead"), wxT("") ) )
        // wxLogError(wxT("wxRemoteHtmlHelpController - YouAreDead Failed"));

        // Kill the server.  This could be an option.
        Quit();

        m_connection->Disconnect();
        delete m_connection;

        delete m_process;
        m_process = NULL;
    }
    if( m_client )
        delete m_client; //should be automatic?

}

bool wxRemoteHtmlHelpController::DoConnection()
{
    wxString cmd, blank;
    int nsleep;

    blank = wxT("  ");

    // ignored under DDE, host name in TCP/IP based classes
    wxString hostName = wxT("localhost");

    // Create a new client
    if( !m_client ) m_client = new rhhcClient(&isconn_1);

    nsleep = 0;

    // suppress the log messages from MakeConnection()
    {
        wxLogNull nolog;

        //first try to connect assuming server is running
        if( !isconn_1 )
            m_connection = (rhhcConnection *)m_client->MakeConnection(hostName, m_service, wxT("HELP") );

        //if not, start server
        if( !isconn_1 ) {

            wxString stylestr;
            stylestr.Printf( wxT("--Style%d"), m_style );

            cmd = m_appname + blank + m_service + blank + m_windowname + blank + m_book + blank + stylestr;

            m_process = new wxProcess(NULL);
            m_pid = wxExecute( cmd, false, m_process );
            // leaks - wxExecute itself (if not deleted) and in wxExecute at
            // wxExecuteData *data = new wxExecuteData;
            if( m_pid <= 0 ) {
                wxLogError( wxT("wxRemoteHtmlHelpController - Failed to start Help server") );
                return false;
            }
        }

        while ( !isconn_1 )
        {
            //try every second for a while, then leave it to user
            wxSleep(1);
            if( nsleep > 4 ) {
                if ( wxMessageBox( wxT("Failed to make connection to Help server.\nRetry?") ,
                                   wxT("wxRemoteHtmlHelpController Error"),
                                   wxICON_ERROR | wxYES_NO | wxCANCEL ) != wxYES )
                {
                    // no server
                    return false;
                }
            }
            nsleep++;

            m_connection = (rhhcConnection *)m_client->MakeConnection(hostName, m_service, wxT("HELP") );
        }
    }

    if (!m_connection->StartAdvise(wxT("Item"))) {
        wxLogError(wxT("wxRemoteHtmlHelpController - StartAdvise failed") );
        return false;
    }

    return true;
}

bool wxRemoteHtmlHelpController::LoadFile(const wxString& WXUNUSED(file))
{
    return true;
}
bool wxRemoteHtmlHelpController::DisplaySection(int sectionNo)
{
    Display(sectionNo);
    return true;
}
bool wxRemoteHtmlHelpController::DisplayBlock(long blockNo)
{
    return DisplaySection((int)blockNo);
}

bool wxRemoteHtmlHelpController::Quit()
{
    //this code from exec sample - branches left in for testing
    // sig = 3, 6, 9 or 12 all kill server with no apparent problem
    // but give error message on MSW - timout?
    int sig = 15;   //3 = quit; 6 = abort; 9 = kill;  15 = terminate

/*
                    switch ( sig )
                    {
                    default:
                    wxFAIL_MSG( wxT("unexpected return value") );
                    // fall through

                      case -1:
                      // cancelled
                      return false;

                        case wxSIGNONE:
                        case wxSIGHUP:
                        case wxSIGINT:
                        case wxSIGQUIT:
                        case wxSIGILL:
                        case wxSIGTRAP:
                        case wxSIGABRT:
                        case wxSIGEMT:
                        case wxSIGFPE:
                        case wxSIGKILL:
                        case wxSIGBUS:
                        case wxSIGSEGV:
                        case wxSIGSYS:
                        case wxSIGPIPE:
                        case wxSIGALRM:
                        case wxSIGTERM:
                        break;
                        }
*/

    if ( sig == 0 )
    {
        if ( wxProcess::Exists(m_pid) )
        {
            wxLogStatus(wxT("Process %ld is running."), m_pid);
        }
        else
        {
            wxLogStatus(wxT("No process with pid = %ld."), m_pid);
        }
    }
    else // not SIGNONE
    {
        wxKillError rc = wxProcess::Kill(m_pid, (wxSignal)sig);
        if ( rc == wxKILL_OK )
        {
            wxLogStatus(wxT("Process %ld killed with signal %d."), m_pid, sig);
        }
        else
        {
            static const wxChar *errorText[] =
            {
                wxT(""), // no error
                    wxT("signal not supported"),
                    wxT("permission denied"),
                    wxT("no such process"),
                    wxT("unspecified error"),
            };

            // sig = 3, 6, 9 or 12 all kill server with no apparent problem
            // but give error message on MSW - timout?
            //
            //wxLogError(wxT("Failed to kill process %ld with signal %d: %s"),
            //            m_pid, sig, errorText[rc]);
        }
    }


    return true;
}

void wxRemoteHtmlHelpController::Display(const wxString& helpfile)
{
    if( !isconn_1 ) {
        if( !DoConnection() ) return;
    }

    if (!m_connection->Execute( helpfile, -1 ) )
        wxLogError(wxT("wxRemoteHtmlHelpController - Display Failed"));

}

void wxRemoteHtmlHelpController::Display(const int id)
{
    if( !isconn_1 ) {
        if( !DoConnection() ) return;
    }

    wxString intstring;
    intstring.Printf( "--intstring%d", id );

    if (!m_connection->Execute( intstring, -1 ) )
        wxLogError(wxT("wxRemoteHtmlHelpController - Display Failed"));

}

bool wxRemoteHtmlHelpController::AddBook(const wxString& book, bool show_wait_msg)
{
    //ignore show_wait_msg - there shouldn't be a delay in this step
    //show_wait_msg = true could be transmitted with ++AddBook
    m_book = book;

    if( isconn_1 ) {
        if (!m_connection->Poke( wxT("--AddBook"), (char*)book.c_str() ) )
        {
            wxLogError(wxT("wxRemoteHtmlHelpController - AddBook Failed"));
        }
        return false;
    }

    return true;
}

bool wxRemoteHtmlHelpController::DisplayContents()
{
    if( isconn_1 ) {
        if (!m_connection->Poke( wxT("--DisplayContents"), wxT("") ) ) {
            wxLogError(wxT("wxRemoteHtmlHelpController - DisplayContents Failed"));
            return false;
        }
    }
    return true;
}
void wxRemoteHtmlHelpController::DisplayIndex()
{
    if( isconn_1 ) {
        if (!m_connection->Poke( wxT("--DisplayIndex"), wxT("") ) )
        {
            wxLogError(wxT("wxRemoteHtmlHelpController - DisplayIndex Failed"));
        }
    }
}
bool wxRemoteHtmlHelpController::KeywordSearch(const wxString& keyword)
{
    if( isconn_1 ) {
        if (!m_connection->Poke( wxT("--KeywordSearch"), (char*)keyword.c_str() ) ) {
            wxLogError(wxT("wxRemoteHtmlHelpController - KeywordSearch Failed"));
            return false;
        }
    }
    return true;
}

void wxRemoteHtmlHelpController::SetTitleFormat(const wxString& format)
{
    m_windowname = format;
    m_windowname.Replace( wxT(" "), wxT("_") );

    if( isconn_1 ) {
        if (!m_connection->Poke( wxT("--SetTitleFormat"), (char*)format.c_str() ) )
        {
            wxLogError(wxT("wxRemoteHtmlHelpController - SetTitleFormat Failed"));
        }
    }
}

void wxRemoteHtmlHelpController::SetTempDir(const wxString& path)
{
    if( isconn_1 ) {
        if (!m_connection->Poke( wxT("--SetTempDir"), (char*)path.c_str() ) )
        {
            wxLogError(wxT("wxRemoteHtmlHelpController - SetTempDir Failed"));
        }
    }
}

