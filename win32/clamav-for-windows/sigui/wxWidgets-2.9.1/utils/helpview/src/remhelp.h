/////////////////////////////////////////////////////////////////////////////
// Name:        remhelp.h
// Purpose:     Remote help controller class
// Author:      Eric Dowty
// Modified by:
// Created:     2002-11-18
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_REMHELP_H_
#define _WX_REMHELP_H_

#include <wx/helpbase.h>
#include <wx/ipc.h>
#include <wx/html/helpctrl.h>

class WXDLLIMPEXP_FWD_BASE wxConfigBase;

class rhhcConnection : public wxConnection
{
public:
    rhhcConnection(bool *isconn_a);
    virtual ~rhhcConnection();

    bool OnAdvise(const wxString& topic, const wxString& item, char *data, int size, wxIPCFormat format);
    bool OnDisconnect();
    bool *isconn_3;

};

class rhhcClient: public wxClient
{
public:
    rhhcClient(bool *isconn_a);
        //~rhhcClient( );
    wxConnectionBase *OnMakeConnection();
    bool *isconn_2;
};

class wxRemoteHtmlHelpController : public wxHelpControllerBase
{
    DECLARE_CLASS(wxRemoteHtmlHelpController)
public:
    wxRemoteHtmlHelpController(int style = wxHF_DEFAULT_STYLE);
    virtual ~wxRemoteHtmlHelpController();
    void OnQuit(void);

    void SetService(wxString& a_service);
    void SetServer(wxString& a_appname); //could be wxHelpController::SetViewer

    //standard wxHtmlHelpController functions
    bool AddBook(const wxString& book, bool show_wait_msg = false);
    void Display(const wxString& x);
    void Display(const int id);
    bool DisplayContents();
    void DisplayIndex();
    bool KeywordSearch(const wxString& keyword);
    void SetTempDir(const wxString& path);
    void SetTitleFormat(const wxString& format);

    //dummies - config is in server
    void UseConfig(wxConfigBase* config, const wxString& rootpath = wxEmptyString) {};
    void ReadCustomization(wxConfigBase* cfg, wxString path = wxEmptyString) {};
    void WriteCustomization(wxConfigBase* cfg, wxString path = wxEmptyString) {};

    //virtuals from wxHelpControllerBase - not in wxHtmlHelpController
    //won't compile without these
    bool LoadFile(const class wxString &); //dummy
    bool DisplaySection(int);
    bool DisplayBlock(long);
    bool Quit(void);

private:
    void OnExit(wxCommandEvent& event);
    bool DoConnection();

    rhhcConnection *m_connection;
    rhhcClient *m_client;
    wxProcess *m_process;

    int m_pid;
    int m_style;
    wxString m_appname;
    wxString m_service;
    wxString m_windowname;
    wxString m_book;
    bool isconn_1;
};

#endif
    // _WX_REMHELP_H_
