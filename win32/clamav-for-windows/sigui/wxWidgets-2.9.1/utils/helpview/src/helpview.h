/////////////////////////////////////////////////////////////////////////////
// Name:        helpview.h
// Purpose:     HelpView application class
// Author:      Vaclav Slavik, Julian Smart
// Modified by:
// Created:     2002-07-09
// RCS-ID:      $Id$
// Copyright:   (c) 2002 Vaclav Slavik, Julian Smart and others
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_HELPVIEW_H_
#define _WX_HELPVIEW_H_

#define hvVERSION 1.04

#if wxUSE_IPC
#include <wx/ipc.h>
class hvServer;
#endif

/*!
 * The helpview application class.
 */

class hvApp : public wxApp
{
public:
    hvApp();

    /// Initialise the application.
    virtual bool OnInit();

    /// Clean up the application's data.
    virtual int OnExit();

#ifdef __WXMAC__
    /// Respond to Apple Event for opening a document
    virtual void MacOpenFile(const wxString& filename);
#endif

    /// Prompt the user for a book to open
    bool OpenBook(wxHtmlHelpController* controller);

    /// Returns the help controller.
    wxHtmlHelpController* GetHelpController() { return m_helpController; }

#if wxUSE_IPC
    /// Returns the list of connections.
    wxList& GetConnections() { return m_connections; }
#endif

private:
    wxHtmlHelpController*   m_helpController;

#if wxUSE_IPC
    wxList                  m_connections;
    hvServer*               m_server;
#endif

};

#if wxUSE_IPC
class hvConnection : public wxConnection
{
public:
    hvConnection();
    virtual ~hvConnection();

    bool OnExec(const wxString& topic, const wxString& data);
    bool OnPoke(const wxString& topic, const wxString& item,
                const void *data, size_t size, wxIPCFormat format);

private:
};

class hvServer: public wxServer
{
public:
    wxConnectionBase *OnAcceptConnection(const wxString& topic);
};


#endif

#endif
  // _WX_HELPVIEW_H_

