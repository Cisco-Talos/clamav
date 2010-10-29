/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/printpalm.cpp
// Purpose:     wxPalmPrinter framework
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

// Don't use the Windows printer if we're in wxUniv mode and using
// the PostScript architecture
#if wxUSE_PRINTING_ARCHITECTURE && (!defined(__WXUNIVERSAL__) || !wxUSE_POSTSCRIPT_ARCHITECTURE_IN_MSW)

#ifndef WX_PRECOMP
    #include "wx/window.h"
    #include "wx/palmos/private.h"
    #include "wx/utils.h"
    #include "wx/dc.h"
    #include "wx/app.h"
    #include "wx/msgdlg.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/dcprint.h"
#endif

#include "wx/palmos/printpalm.h"
#include "wx/printdlg.h"
#include "wx/palmos/private.h"

// ---------------------------------------------------------------------------
// private functions
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// wxWin macros
// ---------------------------------------------------------------------------

    IMPLEMENT_DYNAMIC_CLASS(wxPalmPrinter, wxPrinterBase)
    IMPLEMENT_CLASS(wxPalmPrintPreview, wxPrintPreviewBase)

// ===========================================================================
// implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// Printer
// ---------------------------------------------------------------------------

wxPalmPrinter::wxPalmPrinter(wxPrintDialogData *data)
                : wxPrinterBase(data)
{
}

wxPalmPrinter::~wxPalmPrinter()
{
}

bool wxPalmPrinter::Print(wxWindow *parent, wxPrintout *printout, bool prompt)
{
    return false;
}

wxDC* wxPalmPrinter::PrintDialog(wxWindow *parent)
{
    wxDC* dc = NULL;

    return dc;
}

bool wxPalmPrinter::Setup(wxWindow *parent)
{
    return false;
}

/*
* Print preview
*/

wxPalmPrintPreview::wxPalmPrintPreview(wxPrintout *printout,
                                             wxPrintout *printoutForPrinting,
                                             wxPrintDialogData *data)
                     : wxPrintPreviewBase(printout, printoutForPrinting, data)
{
}

wxPalmPrintPreview::wxPalmPrintPreview(wxPrintout *printout,
                                             wxPrintout *printoutForPrinting,
                                             wxPrintData *data)
                     : wxPrintPreviewBase(printout, printoutForPrinting, data)
{
}

wxPalmPrintPreview::~wxPalmPrintPreview()
{
}

bool wxPalmPrintPreview::Print(bool interactive)
{
    return false;
}

void wxPalmPrintPreview::DetermineScaling()
{
    // TODO
}

#endif
    // wxUSE_PRINTING_ARCHITECTURE
