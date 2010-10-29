/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/dcprint.cpp
// Purpose:     wxPrinterDC class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
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

#if wxUSE_PRINTING_ARCHITECTURE

#include "wx/dcprint.h"

#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/log.h"
    #include "wx/window.h"
    #include "wx/dcmemory.h"
    #include "wx/math.h"
#endif

#include "wx/palmos/private.h"

#if wxUSE_WXDIB
#include "wx/palmos/dib.h"
#endif


// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

IMPLEMENT_CLASS(wxPrinterDC, wxDC)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxPrinterDC construction
// ----------------------------------------------------------------------------

// This form is deprecated
wxPrinterDC::wxPrinterDC(const wxString& driver_name,
                         const wxString& device_name,
                         const wxString& file,
                         bool interactive,
                         wxPrintOrientation orientation)
{
}

wxPrinterDC::wxPrinterDC(const wxPrintData& printData)
{
}


wxPrinterDC::wxPrinterDC(WXHDC dc)
{
}

void wxPrinterDC::Init()
{
}

// ----------------------------------------------------------------------------
// wxPrinterDC {Start/End}{Page/Doc} methods
// ----------------------------------------------------------------------------

bool wxPrinterDC::StartDoc(const wxString& message)
{
    return false;
}

void wxPrinterDC::EndDoc()
{
}

void wxPrinterDC::StartPage()
{
}

void wxPrinterDC::EndPage()
{
}

wxRect wxPrinterDC::GetPaperRect() const
{
    // Use page rect if we can't get paper rect.
    wxCoord w, h;
    GetSize(&w, &h);
    return wxRect(0, 0, w, h);
}

// Returns default device and port names
static bool wxGetDefaultDeviceName(wxString& deviceName, wxString& portName)
{
    return false;
}

// Gets an HDC for the specified printer configuration
WXHDC WXDLLEXPORT wxGetPrinterDC(const wxPrintData& printDataConst)
{
    return (WXHDC) 0;
}

// ----------------------------------------------------------------------------
// wxPrinterDC bit blitting/bitmap drawing
// ----------------------------------------------------------------------------

// helper of DoDrawBitmap() and DoBlit()
static
bool DrawBitmapUsingStretchDIBits(HDC hdc,
                                  const wxBitmap& bmp,
                                  wxCoord x, wxCoord y)
{
    return false;
}

void wxPrinterDC::DoDrawBitmap(const wxBitmap& bmp,
                               wxCoord x, wxCoord y,
                               bool useMask)
{
}

bool wxPrinterDC::DoBlit(wxCoord xdest, wxCoord ydest,
                         wxCoord width, wxCoord height,
                         wxDC *source,
                         wxCoord WXUNUSED(xsrc), wxCoord WXUNUSED(ysrc),
                         wxRasterOperationMode WXUNUSED(rop), bool useMask,
                         wxCoord WXUNUSED(xsrcMask), wxCoord WXUNUSED(ysrcMask))
{
    return false;
}

#endif
    // wxUSE_PRINTING_ARCHITECTURE
