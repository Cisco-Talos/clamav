/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/printdlg.cpp
// Purpose:     wxPrintDialog, wxPageSetupDialog
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ===========================================================================
// declarations
// ===========================================================================

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

// Don't use the Windows print dialog if we're in wxUniv mode and using
// the PostScript architecture
#if wxUSE_PRINTING_ARCHITECTURE && (!defined(__WXUNIVERSAL__) || !wxUSE_POSTSCRIPT_ARCHITECTURE_IN_MSW)

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/dcprint.h"
#endif

#include "wx/printdlg.h"

#include "wx/palmos/private.h"

// ---------------------------------------------------------------------------
// wxWin macros
// ---------------------------------------------------------------------------

    IMPLEMENT_DYNAMIC_CLASS(wxPrintDialog, wxDialog)
    IMPLEMENT_CLASS(wxPageSetupDialog, wxDialog)

// ===========================================================================
// implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// wxPrintDialog
// ---------------------------------------------------------------------------

wxPrintDialog::wxPrintDialog()
{
}

wxPrintDialog::wxPrintDialog(wxWindow *p, wxPrintDialogData* data)
{
}

wxPrintDialog::wxPrintDialog(wxWindow *p, wxPrintData* data)
{
}

bool wxPrintDialog::Create(wxWindow *p, wxPrintDialogData* data)
{
    return false;
}

wxPrintDialog::~wxPrintDialog()
{
}

int wxPrintDialog::ShowModal()
{
    return wxID_CANCEL;
}

wxDC *wxPrintDialog::GetPrintDC()
{
    return NULL;
}

// ---------------------------------------------------------------------------
// wxPageSetupDialog
// ---------------------------------------------------------------------------

wxPageSetupDialog::wxPageSetupDialog()
{
}

wxPageSetupDialog::wxPageSetupDialog(wxWindow *p, wxPageSetupData *data)
{
}

bool wxPageSetupDialog::Create(wxWindow *p, wxPageSetupData *data)
{
    return false;
}

wxPageSetupDialog::~wxPageSetupDialog()
{
}

int wxPageSetupDialog::ShowModal()
{
    return wxID_CANCEL;
}

#endif
    // wxUSE_PRINTING_ARCHITECTURE
