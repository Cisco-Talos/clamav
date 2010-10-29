/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/fdrepdlg.cpp
// Purpose:     wxFindReplaceDialog class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10.13.04
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

#if wxUSE_FINDREPLDLG

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/log.h"
#endif

#include "wx/palmos/private.h"

#include "wx/fdrepdlg.h"

// ----------------------------------------------------------------------------
// functions prototypes
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxFindReplaceDialog, wxDialog)

// ----------------------------------------------------------------------------
// wxFindReplaceDialogImpl: the internals of wxFindReplaceDialog
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxFindReplaceDialogImpl
{
public:
    wxFindReplaceDialogImpl(wxFindReplaceDialog *dialog, int flagsWX);
    ~wxFindReplaceDialogImpl();

    void InitFindWhat(const wxString& str);
    void InitReplaceWith(const wxString& str);

    void SubclassDialog(HWND hwnd);

    static UINT GetFindDialogMessage() { return ms_msgFindDialog; }

    // only for passing to ::FindText or ::ReplaceText
    FINDREPLACE *GetPtrFindReplace() { return &m_findReplace; }

    // set/query the "closed by user" flag
    void SetClosedByUser() { m_wasClosedByUser = TRUE; }
    bool WasClosedByUser() const { return m_wasClosedByUser; }

private:
    void InitString(const wxString& str, LPTSTR *ppStr, WORD *pLen);

    // the owner of the dialog
    HWND m_hwndOwner;

    // the previous window proc of our owner
    WNDPROC m_oldParentWndProc;

    // the find replace data used by the dialog
    FINDREPLACE m_findReplace;

    // TRUE if the user closed us, FALSE otherwise
    bool m_wasClosedByUser;

    // registered Message for Dialog
    static UINT ms_msgFindDialog;

    wxDECLARE_NO_COPY_CLASS(wxFindReplaceDialogImpl);
};

UINT wxFindReplaceDialogImpl::ms_msgFindDialog = 0;

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxFindReplaceDialogImpl
// ----------------------------------------------------------------------------

wxFindReplaceDialogImpl::wxFindReplaceDialogImpl(wxFindReplaceDialog *dialog,
                                                 int flagsWX)
{
}

void wxFindReplaceDialogImpl::InitString(const wxString& str,
                                         LPTSTR *ppStr, WORD *pLen)
{
}

void wxFindReplaceDialogImpl::InitFindWhat(const wxString& str)
{
}

void wxFindReplaceDialogImpl::InitReplaceWith(const wxString& str)
{
}

void wxFindReplaceDialogImpl::SubclassDialog(HWND hwnd)
{
}

wxFindReplaceDialogImpl::~wxFindReplaceDialogImpl()
{
}

// ============================================================================
// wxFindReplaceDialog implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxFindReplaceDialog ctors/dtor
// ----------------------------------------------------------------------------

void wxFindReplaceDialog::Init()
{
}

wxFindReplaceDialog::wxFindReplaceDialog(wxWindow *parent,
                                         wxFindReplaceData *data,
                                         const wxString &title,
                                         int flags)
                   : wxFindReplaceDialogBase(parent, data, title, flags)
{
}

wxFindReplaceDialog::~wxFindReplaceDialog()
{
}

bool wxFindReplaceDialog::Create(wxWindow *parent,
                                 wxFindReplaceData *data,
                                 const wxString &title,
                                 int flags)
{
    return false;
}

// ----------------------------------------------------------------------------
// wxFindReplaceData show/hide
// ----------------------------------------------------------------------------

bool wxFindReplaceDialog::Show(bool show)
{
    return false;
}

// ----------------------------------------------------------------------------
// wxFindReplaceDialog title handling
// ----------------------------------------------------------------------------

void wxFindReplaceDialog::SetTitle( const wxString& title)
{
}

wxString wxFindReplaceDialog::GetTitle() const
{
    return wxString;
}

// ----------------------------------------------------------------------------
// wxFindReplaceDialog position/size
// ----------------------------------------------------------------------------

void wxFindReplaceDialog::DoSetSize(int WXUNUSED(x), int WXUNUSED(y),
                                    int WXUNUSED(width), int WXUNUSED(height),
                                    int WXUNUSED(sizeFlags))
{
    // ignore - we can't change the size of this standard dialog
    return;
}

// NB: of course, both of these functions are completely bogus, but it's better
//     than nothing
void wxFindReplaceDialog::DoGetSize(int *width, int *height) const
{
}

void wxFindReplaceDialog::DoGetClientSize(int *width, int *height) const
{
}

#endif // wxUSE_FINDREPLDLG

