/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/dcprint.h
// Purpose:     wxPrinterDC class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_DCPRINT_H_
#define _WX_DCPRINT_H_

#if wxUSE_PRINTING_ARCHITECTURE

#include "wx/dc.h"
#include "wx/cmndata.h"

class WXDLLIMPEXP_CORE wxPrinterDC : public wxDC
{
public:
    // Create a printer DC (obsolete function: use wxPrintData version now)
    wxPrinterDC(const wxString& driver, const wxString& device, const wxString& output, bool interactive = TRUE, wxPrintOrientation orientation = wxPORTRAIT);

    // Create from print data
    wxPrinterDC(const wxPrintData& data);

    wxPrinterDC(WXHDC theDC);

    // override some base class virtuals
    virtual bool StartDoc(const wxString& message);
    virtual void EndDoc();
    virtual void StartPage();
    virtual void EndPage();

    wxRect GetPaperRect() const;

protected:
    virtual void DoDrawBitmap(const wxBitmap &bmp, wxCoord x, wxCoord y,
                              bool useMask = FALSE);
    virtual bool DoBlit(wxCoord xdest, wxCoord ydest,
                        wxCoord width, wxCoord height,
                        wxDC *source, wxCoord xsrc, wxCoord ysrc,
                        wxRasterOperationMode rop = wxCOPY, bool useMask = FALSE,
                        wxCoord xsrcMask = -1, wxCoord ysrcMask = -1);

    // init the dc
    void Init();

    wxPrintData m_printData;

private:
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxPrinterDC)
};

// Gets an HDC for the default printer configuration
// WXHDC WXDLLIMPEXP_CORE wxGetPrinterDC(int orientation);

// Gets an HDC for the specified printer configuration
WXHDC WXDLLIMPEXP_CORE wxGetPrinterDC(const wxPrintData& data);

#endif // wxUSE_PRINTING_ARCHITECTURE

#endif
    // _WX_DCPRINT_H_

