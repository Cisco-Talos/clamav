/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/icon.cpp
// Purpose:     wxIcon class
// Author:      David Webster
// Modified by:
// Created:     10/09/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/icon.h"

#ifndef WX_PRECOMP
    #include "wx/list.h"
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/log.h"
#endif

#include "wx/os2/private.h"
#include "assert.h"

IMPLEMENT_DYNAMIC_CLASS(wxIcon, wxGDIObject)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxIconRefData
// ----------------------------------------------------------------------------

void wxIconRefData::Free()
{
    if (m_hIcon)
        ::WinFreeFileIcon((HPOINTER)m_hIcon);
}

// ----------------------------------------------------------------------------
// wxIcon
// ----------------------------------------------------------------------------

wxIcon::wxIcon()
       :m_bIsXpm(false)
{
}

wxIcon::wxIcon( const char WXUNUSED(bits)[],
                int        WXUNUSED(nWidth),
                int        WXUNUSED(nHeight) )
       :m_bIsXpm(false)
{
}

wxIcon::wxIcon( const wxString& rIconFile,
                wxBitmapType    lFlags,
                int             nDesiredWidth,
                int             nDesiredHeight )
       :m_bIsXpm(false)
{
    //
    // A very poor hack, but we have to have separate icon files from windows
    // So we have a modified name where replace the last three characters
    // with os2.  Also need the extension.
    //
    wxString sOs2Name = rIconFile.Mid(0, rIconFile.length() - 3);

    sOs2Name += wxT("Os2.ico");
    LoadFile( sOs2Name
             ,lFlags
             ,nDesiredWidth
             ,nDesiredHeight
            );
}

wxIcon::~wxIcon()
{
}

void wxIcon::CreateIconFromXpm(const char* const* ppData)
{
    wxBitmap                        vBmp(ppData);

    CopyFromBitmap(vBmp);
    if (GetHICON())
    {
        m_bIsXpm = true;
        m_vXpmSrc = vBmp;
    }
} // end of wxIcon::CreateIconFromXpm

void wxIcon::CopyFromBitmap( const wxBitmap& rBmp )
{
    wxMask*                         pMask = rBmp.GetMask();
    HBITMAP                         hBmp = NULLHANDLE;
    HBITMAP                         hBmpMask = NULLHANDLE;
    HBITMAP                         hOldBitmap = NULLHANDLE;
    ERRORID                         vError;
    wxString                        sError;
    LONG                            lHits;

    if (!pMask)
    {
        //
        // We must have a mask for an icon, so even if it's probably incorrect,
        // do create it (grey is the "standard" transparent colour)
        //
        pMask = new wxMask( rBmp
                           ,*wxLIGHT_GREY
                          );
    }

    BITMAPINFOHEADER2 vHeader;
    SIZEL             vSize = {0, 0};
    DEVOPENSTRUC      vDop = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
    HDC               hDCSrc = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HDC               hDCDst = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HPS               hPSSrc = ::GpiCreatePS(vHabmain, hDCSrc, &vSize, PU_PELS | GPIA_ASSOC);
    HPS               hPSDst = ::GpiCreatePS(vHabmain, hDCDst, &vSize, PU_PELS | GPIA_ASSOC);
    POINTL            vPoint[4] = { {0, 0}, {rBmp.GetWidth(), rBmp.GetHeight()},
                                    {0, 0}, {rBmp.GetWidth(), rBmp.GetHeight()}
                                  };
    POINTL            vPointMask[4] = { {0, 0}, {rBmp.GetWidth(), rBmp.GetHeight() * 2},
                                        {0, 0}, {rBmp.GetWidth(), rBmp.GetHeight()}
                                    };
    POINTERINFO       vIconInfo;

    memset(&vIconInfo, '\0', sizeof(POINTERINFO));
    vIconInfo.fPointer = FALSE;  // we want an icon, not a pointer

    memset(&vHeader, '\0', 16);
    vHeader.cbFix           = 16;
    vHeader.cx              = (ULONG)rBmp.GetWidth();
    vHeader.cy              = (ULONG)rBmp.GetHeight();
    vHeader.cPlanes         = 1L;
    vHeader.cBitCount       = 24;

    hBmp = ::GpiCreateBitmap( hPSDst
                             ,&vHeader
                             ,0L
                             ,NULL
                             ,NULL
                            );

    if ((hOldBitmap = ::GpiSetBitmap(hPSDst, hBmp)) == HBM_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    if ((hOldBitmap = ::GpiSetBitmap(hPSSrc, (HBITMAP)rBmp.GetHBITMAP())) == HBM_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    if ((lHits = ::GpiBitBlt( hPSDst
                             ,hPSSrc
                             ,4L
                             ,vPoint
                             ,ROP_SRCCOPY
                             ,BBO_IGNORE
                            )) == GPI_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    if ((hOldBitmap = ::GpiSetBitmap(hPSDst, NULLHANDLE)) == HBM_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    if ((hOldBitmap = ::GpiSetBitmap(hPSSrc, NULLHANDLE)) == HBM_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    vIconInfo.hbmColor = hBmp;

    vHeader.cy              = (ULONG)rBmp.GetHeight() * 2;
    hBmpMask = ::GpiCreateBitmap( hPSDst
                                 ,&vHeader
                                 ,0L
                                 ,NULL
                                 ,NULL
                                );

    if ((hOldBitmap = ::GpiSetBitmap(hPSDst, hBmpMask)) == HBM_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    if ((hOldBitmap = ::GpiSetBitmap(hPSSrc, (HBITMAP)pMask->GetMaskBitmap())) == HBM_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    if ((lHits = ::GpiBitBlt( hPSDst
                             ,hPSSrc
                             ,4L
                             ,vPointMask
                             ,ROP_SRCCOPY
                             ,BBO_IGNORE
                            )) == GPI_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    if ((hOldBitmap = ::GpiSetBitmap(hPSSrc, NULLHANDLE)) == HBM_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    if ((hOldBitmap = ::GpiSetBitmap(hPSDst, NULLHANDLE)) == HBM_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }

    vIconInfo.hbmPointer = hBmpMask;

    HICON hIcon = ::WinCreatePointerIndirect( HWND_DESKTOP, &vIconInfo);

    if (!hIcon)
    {
        wxLogLastError(wxT("WinCreatePointerIndirect"));
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    else
    {
        SetHICON((WXHICON)hIcon);
        SetSize( rBmp.GetWidth()
                ,rBmp.GetHeight()
               );
    }

    if (!rBmp.GetMask())
    {
        //
        // We created the mask, now delete it
        //
        delete pMask;
    }
    ::GpiSetBitmap(hPSSrc, NULL);
    ::GpiSetBitmap(hPSDst, NULL);
    ::GpiDestroyPS(hPSSrc);
    ::GpiDestroyPS(hPSDst);
    ::DevCloseDC(hDCSrc);
    ::DevCloseDC(hDCDst);
} // end of wxIcon::CopyFromBitmap

bool wxIcon::LoadFile( const wxString& rFilename,
                       wxBitmapType lType,
                       int nDesiredWidth,
                       int nDesiredHeight )
{
    HPS                             hPs = NULLHANDLE;

    UnRef();

    wxGDIImageHandler*              pHandler = FindHandler(lType);

    if (pHandler)
        return(pHandler->Load( this
                              ,rFilename
                              ,hPs
                              ,lType
                              ,nDesiredWidth
                              ,nDesiredHeight
                             ));
    else
        return false;
}
