/////////////////////////////////////////////////////////////////////////////
// Name:        client.h
// Purpose:     Remote help sample client
// Author:      Julian Smart
// Modified by: Eric Dowty
// Created:     2002-11-18
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// Define a new application
class MyApp: public wxApp
{
public:
    virtual bool OnInit();
    virtual int OnExit();

#if defined(USE_REMOTE)
    wxRemoteHtmlHelpController *m_help;
#else
    wxHtmlHelpController *m_help;
#endif
};

DECLARE_APP(MyApp)

// Define a new frame
class MyFrame: public wxFrame
{
public:
    MyFrame(wxFrame *frame, const wxString& title);

private:
    void OnExit(wxCommandEvent& event);
    void OnHelp_Main(wxCommandEvent& event);
    void OnHelp_Book1(wxCommandEvent& event);
    void OnHelp_Book2(wxCommandEvent& event);
    void OnHelp_Index(wxCommandEvent& event);
    void OnHelp_Contents(wxCommandEvent& event);
    void OnHelp_Search(wxCommandEvent& event);
    void OnHelp_Title(wxCommandEvent& event);
    void OnHelp_Addbook(wxCommandEvent& event);
    void OnHelp_Tempdir(wxCommandEvent& event);
    void OnHelp_Quitserver(wxCommandEvent& event);

    void ModalDlg(wxCommandEvent& event);

    wxPanel *m_panel;
    wxButton *m_modalbutton;

    DECLARE_EVENT_TABLE()
};

class MyModalDialog : public wxDialog
{
public:
    MyModalDialog(wxWindow *parent);

private:
    void OnButton(wxCommandEvent& event);

    wxButton *m_main;
    wxButton *m_book1;
    wxButton *m_book2;

    DECLARE_EVENT_TABLE()
};


#define CLIENT_QUIT     wxID_EXIT
#define CLIENT_EXECUTE  2
#define CLIENT_REQUEST  3
#define CLIENT_POKE     4
#define CLIENT_HELPMAIN     5
#define CLIENT_HELPBOOK1     6
#define CLIENT_HELPBOOK2     7
#define DIALOG_MODAL     8
#define BUTTON_MODAL     9
#define CLIENT_HELPINDEX 10
#define CLIENT_HELPCONTENTS 11
#define CLIENT_HELPSEARCH 12
#define CLIENT_HELPTITLE 13
#define CLIENT_HELPADDBOOK 14
#define CLIENT_HELPTEMPDIR 15
#define CLIENT_HELPQUIT 16
