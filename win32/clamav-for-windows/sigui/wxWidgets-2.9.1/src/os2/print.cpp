/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/print.cpp
// Purpose:     Print framework
// Author:      David Webster
// Modified by:
// Created:     10/14/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_PRINTING_ARCHITECTURE

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/list.h"
    #include "wx/utils.h"
    #include "wx/app.h"
#endif

#include "wx/os2/printos2.h"
#include "wx/generic/prntdlgg.h"

IMPLEMENT_DYNAMIC_CLASS(wxOS2Printer, wxPrinterBase)
IMPLEMENT_CLASS(wxOS2PrintPreview, wxPrintPreviewBase)

/*
 * Printer
 */

wxOS2Printer::wxOS2Printer(wxPrintDialogData *data):
  wxPrinterBase(data)
{
}

wxOS2Printer::~wxOS2Printer()
{
}

bool wxOS2Printer::Print(wxWindow *WXUNUSED(parent),
                         wxPrintout *WXUNUSED(printout),
                         bool WXUNUSED(prompt))
{
    // TODO. See wxPostScriptPrinter::Print for hints.
    return false;
}

wxDC* wxOS2Printer::PrintDialog(wxWindow *WXUNUSED(parent))
{
// TODO:
/*
    wxPrintDialog dialog(parent, & m_printData);
    return (dialog.GetPrintDC());
*/
    return NULL;
}

bool wxOS2Printer::Setup(wxWindow *WXUNUSED(parent))
{
// TODO:
/*
    wxPrintDialog dialog(parent, & m_printData);
    return (dialog.ShowModal() == wxID_OK);
*/
    return false;
}

/*
 * Print preview
 */

wxOS2PrintPreview::wxOS2PrintPreview(wxPrintout *printout, wxPrintout *printoutForPrinting, wxPrintDialogData *data):
  wxPrintPreviewBase(printout, printoutForPrinting, data)
{
    DetermineScaling();
}

wxOS2PrintPreview::wxOS2PrintPreview(wxPrintout *printout, wxPrintout *printoutForPrinting, wxPrintData *data):
  wxPrintPreviewBase(printout, printoutForPrinting, data)
{
    DetermineScaling();
}

wxOS2PrintPreview::~wxOS2PrintPreview()
{
}

bool wxOS2PrintPreview::Print(bool WXUNUSED(interactive))
{
    if (!m_printPrintout)
        return false;
//    wxOS2Printer printer(&m_printData);
//    return printer.Print(m_previewFrame, m_printPrintout, interactive);
    return false;
}

void wxOS2PrintPreview::DetermineScaling()
{
    // TODO
}

#endif  //wxUSE_PRINTING_ARCHITECTURE
