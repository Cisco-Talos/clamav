/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/printpalm.h
// Purpose:     wxPalmPrinter, wxPalmPrintPreview classes
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_PRINTPALM_H_
#define _WX_PRINTPALM_H_

#include "wx/prntbase.h"

// ---------------------------------------------------------------------------
// Represents the printer: manages printing a wxPrintout object
// ---------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxPalmPrinter : public wxPrinterBase
{
    DECLARE_DYNAMIC_CLASS(wxPalmPrinter)

public:
    wxPalmPrinter(wxPrintDialogData *data = NULL);
    virtual ~wxPalmPrinter();

    virtual bool Print(wxWindow *parent,
                       wxPrintout *printout,
                       bool prompt = TRUE);
    virtual wxDC* PrintDialog(wxWindow *parent);
    virtual bool Setup(wxWindow *parent);

private:
    WXFARPROC     m_lpAbortProc;

    wxDECLARE_NO_COPY_CLASS(wxPalmPrinter);
};

// ---------------------------------------------------------------------------
// wxPrintPreview: programmer creates an object of this class to preview a
// wxPrintout.
// ---------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxPalmPrintPreview : public wxPrintPreviewBase
{
public:
    wxPalmPrintPreview(wxPrintout *printout,
                          wxPrintout *printoutForPrinting = NULL,
                          wxPrintDialogData *data = NULL);
    wxPalmPrintPreview(wxPrintout *printout,
                          wxPrintout *printoutForPrinting,
                          wxPrintData *data);
    virtual ~wxPalmPrintPreview();

    virtual bool Print(bool interactive);
    virtual void DetermineScaling();

private:
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxPalmPrintPreview)
};

#endif
// _WX_PRINTPALM_H_
