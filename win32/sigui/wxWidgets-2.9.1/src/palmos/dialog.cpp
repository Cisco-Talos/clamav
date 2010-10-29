/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/dialog.cpp
// Purpose:     wxDialog class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/12/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/dialog.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/frame.h"
    #include "wx/app.h"
    #include "wx/settings.h"
    #include "wx/intl.h"
    #include "wx/log.h"
#endif

#include "wx/evtloop.h"
#include "wx/scopedptr.h"

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxDialogStyle )

wxBEGIN_FLAGS( wxDialogStyle )
    // new style border flags, we put them first to
    // use them for streaming out
    wxFLAGS_MEMBER(wxBORDER_SIMPLE)
    wxFLAGS_MEMBER(wxBORDER_SUNKEN)
    wxFLAGS_MEMBER(wxBORDER_DOUBLE)
    wxFLAGS_MEMBER(wxBORDER_RAISED)
    wxFLAGS_MEMBER(wxBORDER_STATIC)
    wxFLAGS_MEMBER(wxBORDER_NONE)

    // old style border flags
    wxFLAGS_MEMBER(wxSIMPLE_BORDER)
    wxFLAGS_MEMBER(wxSUNKEN_BORDER)
    wxFLAGS_MEMBER(wxDOUBLE_BORDER)
    wxFLAGS_MEMBER(wxRAISED_BORDER)
    wxFLAGS_MEMBER(wxSTATIC_BORDER)
    wxFLAGS_MEMBER(wxNO_BORDER)

    // standard window styles
    wxFLAGS_MEMBER(wxTAB_TRAVERSAL)
    wxFLAGS_MEMBER(wxCLIP_CHILDREN)

    // dialog styles
    wxFLAGS_MEMBER(wxWS_EX_VALIDATE_RECURSIVELY)
    wxFLAGS_MEMBER(wxSTAY_ON_TOP)
    wxFLAGS_MEMBER(wxCAPTION)
#if WXWIN_COMPATIBILITY_2_6
    wxFLAGS_MEMBER(wxTHICK_FRAME)
#endif // WXWIN_COMPATIBILITY_2_6
    wxFLAGS_MEMBER(wxSYSTEM_MENU)
    wxFLAGS_MEMBER(wxRESIZE_BORDER)
#if WXWIN_COMPATIBILITY_2_6
    wxFLAGS_MEMBER(wxRESIZE_BOX)
#endif // WXWIN_COMPATIBILITY_2_6
    wxFLAGS_MEMBER(wxCLOSE_BOX)
    wxFLAGS_MEMBER(wxMAXIMIZE_BOX)
    wxFLAGS_MEMBER(wxMINIMIZE_BOX)
wxEND_FLAGS( wxDialogStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxDialog, wxTopLevelWindow,"wx/dialog.h")

wxBEGIN_PROPERTIES_TABLE(wxDialog)
    wxPROPERTY( Title, wxString, SetTitle, GetTitle, wxString() , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY_FLAGS( WindowStyle , wxDialogStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxDialog)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_6( wxDialog , wxWindow* , Parent , wxWindowID , Id , wxString , Title , wxPoint , Position , wxSize , Size , long , WindowStyle)

#else
IMPLEMENT_DYNAMIC_CLASS(wxDialog, wxTopLevelWindow)
#endif

// ----------------------------------------------------------------------------
// wxDialogModalData
// ----------------------------------------------------------------------------

// this is simply a container for any data we need to implement modality which
// allows us to avoid changing wxDialog each time the implementation changes
class wxDialogModalData
{
public:
    wxDialogModalData(wxDialog *dialog) : m_evtLoop(dialog) { }

    void RunLoop()
    {
        m_evtLoop.Run();
    }

    void ExitLoop()
    {
        m_evtLoop.Exit();
    }

private:
    wxModalEventLoop m_evtLoop;
};

wxDEFINE_TIED_SCOPED_PTR_TYPE(wxDialogModalData);

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxDialog construction
// ----------------------------------------------------------------------------

void wxDialog::Init()
{
}

bool wxDialog::Create(wxWindow *parent,
                      wxWindowID id,
                      const wxString& title,
                      const wxPoint& pos,
                      const wxSize& size,
                      long style,
                      const wxString& name)
{
    if ( !wxTopLevelWindow::Create(parent, id, title, pos, size, style, name) )
        return false;
    return true;
}

wxDialog::~wxDialog()
{
    Show (false);
}

// ----------------------------------------------------------------------------
// showing the dialogs
// ----------------------------------------------------------------------------

bool wxDialog::Show(bool show)
{
    if (show && CanDoLayoutAdaptation())
        DoLayoutAdaptation();

    return wxTopLevelWindowPalm::Show (show);
}

void wxDialog::Raise()
{
}

// show dialog modally
int wxDialog::ShowModal()
{
    Show (true);

    if (errNone == FrmDoDialog ((FormType *)wxTopLevelWindow::GetForm())) {
        return 0;
    }
    return -1;
}

void wxDialog::EndModal(int retCode)
{
}

