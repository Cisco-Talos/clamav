/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/dcprint.cpp
// Purpose:     wxPrinterDC class
// Author:      David Webster
// Modified by:
// Created:     10/14/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_PRINTING_ARCHITECTURE

#include "wx/dcprint.h"
#include "wx/os2/dcprint.h"

#define INCL_DEV
#define INCL_GPI
#define INCL_PM
#include<os2.h>

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/math.h"
    #include "wx/string.h"
    #include "wx/log.h"
    #include "wx/window.h"
#endif

#include "wx/os2/private.h"

IMPLEMENT_ABSTRACT_CLASS(wxPrinterDCImpl, wxPMDCImpl)

wxPrinterDCImpl::wxPrinterDCImpl( wxPrinterDC *owner, const wxPrintData& rPrintData ) :
    wxPMDCImpl( owner )
{
    m_printData = rPrintData;
    m_isInteractive = false;
    m_hDC = wxGetPrinterDC(rPrintData);
    m_ok = (m_hDC != 0);
    if (m_hDC)
        SetMapMode(wxMM_TEXT);
    SetBrush(*wxBLACK_BRUSH);
    SetPen(*wxBLACK_PEN);
} // end of wxPrinterDC::wxPrinterDC

wxPrinterDCImpl::wxPrinterDCImpl( wxPrinterDC *owner, WXHDC hTheDC ) :
    wxPMDCImpl( owner )
{
    m_isInteractive = false;
    m_hDC = hTheDC;
    m_ok = true;
    if (m_hDC)
    {
        SetMapMode(wxMM_TEXT);
    }
    SetBrush(*wxBLACK_BRUSH);
    SetPen(*wxBLACK_PEN);
} // end of wxPrinterDC::wxPrinterDC

void wxPrinterDCImpl::Init()
{
    if (m_hDC)
    {
        SetMapMode(wxMM_TEXT);

        SetBrush(*wxBLACK_BRUSH);
        SetPen(*wxBLACK_PEN);
    }
} // end of wxPrinterDC::Init

bool wxPrinterDCImpl::StartDoc(const wxString& WXUNUSED(rsMessage))
{
/* TODO:  PM's implementation
   DOCINFO docinfo;
    docinfo.cbSize = sizeof(DOCINFO);
    docinfo.lpszDocName = (const wxChar*)message;

    wxString filename(m_printData.GetFilename());

    if (filename.empty())
        docinfo.lpszOutput = NULL;
    else
        docinfo.lpszOutput = (const wxChar *) filename;

#if defined(__WIN95__)
    docinfo.lpszDatatype = NULL;
    docinfo.fwType = 0;
#endif

    if (!m_hDC)
        return false;

    int ret =
#ifndef __WIN32__
        ::StartDoc((HDC) m_hDC, &docinfo);
#else
#ifdef UNICODE
    ::StartDocW((HDC) m_hDC, &docinfo);
#else
#ifdef __TWIN32__
    ::StartDoc((HDC) m_hDC, &docinfo);
#else
    ::StartDocA((HDC) m_hDC, &docinfo);
#endif
#endif
#endif

#ifndef __WIN16__
    if (ret <= 0)
    {
        DWORD lastError = GetLastError();
        wxLogDebug(wxT("wxDC::StartDoc failed with error: %d\n"), lastError);
    }
#endif
    return (ret > 0);
*/
    return true;
} // end of wxPrinterDC::StartDoc

void wxPrinterDCImpl::EndDoc()
{
//    if (m_hDC) ::EndDoc((HDC) m_hDC);
} // end of wxPrinterDC::EndDoc

void wxPrinterDCImpl::StartPage()
{
//    if (m_hDC)
//        ::StartPage((HDC) m_hDC);
} // end of wxPrinterDC::StartPage

void wxPrinterDCImpl::EndPage()
{
//    if (m_hDC)
//        ::EndPage((HDC) m_hDC);
} // end of wxPrinterDC::EndPage

wxRect wxPrinterDCImpl::GetPaperRect() const
{
    // Use page rect if we can't get paper rect.
    wxCoord w, h;
    GetSize(&w, &h);
    return wxRect(0, 0, w, h);
}

#if 0
// Returns default device and port names
static bool wxGetDefaultDeviceName( wxString& rsDeviceName, wxString& rsPortName )
{
    rsDeviceName = wxEmptyString;
/*
    LPDEVNAMES  lpDevNames;
    LPSTR       lpszDriverName;
    LPSTR       lpszDeviceName;
    LPSTR       lpszPortName;

    PRINTDLG    pd;

    // Cygwin has trouble believing PRINTDLG is 66 bytes - thinks it is 68
#ifdef __GNUWIN32__
    pd.lStructSize    = 66; // sizeof(PRINTDLG);
#else
    pd.lStructSize    = sizeof(PRINTDLG);
#endif

    pd.hwndOwner      = (HWND)NULL;
    pd.hDevMode       = NULL; // Will be created by PrintDlg
    pd.hDevNames      = NULL; // Ditto
    pd.Flags          = PD_RETURNDEFAULT;
    pd.nCopies        = 1;

    if (!PrintDlg((LPPRINTDLG)&pd))
    {
        if ( pd.hDevMode )
            GlobalFree(pd.hDevMode);
        if (pd.hDevNames)
            GlobalFree(pd.hDevNames);

        return false;
    }

    if (pd.hDevNames)
    {
        lpDevNames = (LPDEVNAMES)GlobalLock(pd.hDevNames);
        lpszDriverName = (LPSTR)lpDevNames + lpDevNames->wDriverOffset;
        lpszDeviceName = (LPSTR)lpDevNames + lpDevNames->wDeviceOffset;
        lpszPortName   = (LPSTR)lpDevNames + lpDevNames->wOutputOffset;
        GlobalUnlock(pd.hDevNames);
        GlobalFree(pd.hDevNames);
        pd.hDevNames=NULL;

        deviceName = lpszDeviceName;
        portName = lpszPortName;
    }

    if (pd.hDevMode)
    {
        GlobalFree(pd.hDevMode);
        pd.hDevMode=NULL;
    }
    return !deviceName.empty();
*/
    return true;
} // end of wxGetDefaultDeviceName
#endif

// Gets an HDC for the specified printer configuration
WXHDC WXDLLEXPORT wxGetPrinterDC( const wxPrintData& WXUNUSED(rPrintDataConst) )
{
    HDC   hDC = NULLHANDLE;
/*
    wxPrintData printData = printDataConst;
    printData.ConvertToNative();

    wxChar* driverName = NULL;

    wxString devNameStr = printData.GetPrinterName();
    wxChar* deviceName;
    wxChar* portName = NULL; // Obsolete in WIN32

    if (devNameStr.empty())
        deviceName = NULL;
    else
        deviceName = WXSTRINGCAST devNameStr;

    LPDEVMODE lpDevMode = (LPDEVMODE) NULL;

    HGLOBAL hDevMode = (HGLOBAL)(DWORD) printData.GetNativeData();

    if ( hDevMode )
        lpDevMode = (DEVMODE*) GlobalLock(hDevMode);

    if (devNameStr.empty())
    {
        // Retrieve the default device name
        wxString portName;
        bool ret = wxGetDefaultDeviceName(devNameStr, portName);

        wxASSERT_MSG( ret, wxT("Could not get default device name.") );

        deviceName = WXSTRINGCAST devNameStr;
    }

#ifdef __WIN32__
    HDC hDC = CreateDC(driverName, deviceName, portName, (DEVMODE *) lpDevMode);
#else
    HDC hDC = CreateDC(driverName, deviceName, portName, (LPSTR) lpDevMode);
#endif

    if (hDevMode && lpDevMode)
        GlobalUnlock(hDevMode);
*/
    return (WXHDC) hDC;
} // end of wxGetPrinterDC

void wxPrinterDCImpl::DoDrawBitmap( const wxBitmap& rBmp,
                                    wxCoord WXUNUSED(vX),
                                    wxCoord WXUNUSED(vY),
                                    bool WXUNUSED(bUseMask))
{
    wxCHECK_RET( rBmp.Ok(), wxT("invalid bitmap in wxPrinterDC::DrawBitmap") );

//    int                             nWidth  = rBmp.GetWidth();
//    int                             nHeight = rBmp.GetHeight();

    // TODO:

} // end of wxPrinterDC::DoDrawBitmap

bool wxPrinterDCImpl::DoBlit( wxCoord WXUNUSED(vXdest),
                              wxCoord WXUNUSED(vYdest),
                              wxCoord WXUNUSED(vWidth),
                              wxCoord WXUNUSED(vHeight),
                              wxDC* WXUNUSED(pSource),
                              wxCoord WXUNUSED(vXsrc),
                              wxCoord WXUNUSED(vYsrc),
                              wxRasterOperationMode WXUNUSED(nRop),
                              bool WXUNUSED(bUseMask),
                              wxCoord WXUNUSED(xsrcMask),
                              wxCoord WXUNUSED(ysrcMask) )
{
    bool bSuccess = true;

    // TODO:

    return bSuccess;
} // end of wxPrintDCImpl::DoBlit

#endif //wxUSE_PRINTING_ARCHITECTURE
