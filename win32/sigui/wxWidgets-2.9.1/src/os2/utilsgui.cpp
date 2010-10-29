///////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/utilsgui.cpp
// Purpose:     Various utility functions only available in GUI
// Author:      David Webster
// Modified by:
// Created:     20.08.2003 (extracted from os2/utils.cpp)
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/cursor.h"
    #include "wx/font.h"
    #include "wx/timer.h"
#endif //WX_PRECOMP

#include "wx/apptrait.h"
#include "wx/os2/private/timer.h"
#include "wx/evtloop.h"

#include "wx/os2/private.h"     // includes <windows.h>

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// functions to work with .INI files
// ----------------------------------------------------------------------------

// Sleep for nSecs seconds. Attempt a Windows implementation using timers.
static bool inTimer = false;

class wxSleepTimer: public wxTimer
{
public:
    inline void Notify()
    {
        inTimer = false;
        Stop();
    }
};

// ---------------------------------------------------------------------------
// helper functions for showing a "busy" cursor
// ---------------------------------------------------------------------------

HCURSOR gs_wxBusyCursor = 0;     // new, busy cursor
HCURSOR gs_wxBusyCursorOld = 0;  // old cursor
static int gs_wxBusyCursorCount = 0;

// Set the cursor to the busy cursor for all windows
void wxBeginBusyCursor(const wxCursor* pCursor)
{
    if ( gs_wxBusyCursorCount++ == 0 )
    {
        gs_wxBusyCursor = (HCURSOR)pCursor->GetHCURSOR();
        ::WinSetPointer(HWND_DESKTOP, (HPOINTER)gs_wxBusyCursor);
    }
    //else: nothing to do, already set
}

// Restore cursor to normal
void wxEndBusyCursor()
{
    wxCHECK_RET( gs_wxBusyCursorCount > 0
                ,wxT("no matching wxBeginBusyCursor() for wxEndBusyCursor()")
               );

    if (--gs_wxBusyCursorCount == 0)
    {
        ::WinSetPointer(HWND_DESKTOP, (HPOINTER)gs_wxBusyCursorOld);
        gs_wxBusyCursorOld = 0;
    }
}

// true if we're between the above two calls
bool wxIsBusy()
{
    return (gs_wxBusyCursorCount > 0);
}

// Check whether this window wants to process messages, e.g. Stop button
// in long calculations.
bool wxCheckForInterrupt( wxWindow* pWnd )
{
    if(pWnd)
    {
        QMSG vMsg;
        HAB  hab = 0;
        HWND hwndFilter = NULLHANDLE;

        while(::WinPeekMsg(hab, &vMsg, hwndFilter, 0, 0, PM_REMOVE))
        {
            ::WinDispatchMsg(hab, &vMsg);
        }
        return true;//*** temporary?
    }
    else
    {
        wxFAIL_MSG(wxT("pWnd==NULL !!!"));
        return false;//*** temporary?
    }
}

// ----------------------------------------------------------------------------
// get display info
// ----------------------------------------------------------------------------

// See also the wxGetMousePosition in window.cpp
// Deprecated: use wxPoint wxGetMousePosition() instead
void wxGetMousePosition(
  int*                              pX
, int*                              pY
)
{
    POINTL                          vPt;

    ::WinQueryPointerPos(HWND_DESKTOP, &vPt);
    *pX = vPt.x;
    *pY = vPt.y;
};

// Return true if we have a colour display
bool wxColourDisplay()
{
#if 0
    HPS                             hpsScreen;
    HDC                             hdcScreen;
    LONG                            lColors;

    hpsScreen = ::WinGetScreenPS(HWND_DESKTOP);
    hdcScreen = ::GpiQueryDevice(hpsScreen);
    ::DevQueryCaps(hdcScreen, CAPS_COLORS, 1L, &lColors);
    return(lColors > 1L);
#else
    // I don't see how the PM display could not be color. Besides, this
    // was leaking DCs and PSs!!!  MN
    return true;
#endif
}

// Returns depth of screen
int wxDisplayDepth()
{
    HPS                             hpsScreen;
    HDC                             hdcScreen;
    LONG                            lPlanes;
    LONG                            lBitsPerPixel;
    static LONG                     nDepth = 0;

    // The screen colordepth ain't gonna change. No reason to query
    // it over and over!
    if (!nDepth) {
        hpsScreen = ::WinGetScreenPS(HWND_DESKTOP);
        hdcScreen = ::GpiQueryDevice(hpsScreen);
        ::DevQueryCaps(hdcScreen, CAPS_COLOR_PLANES, 1L, &lPlanes);
        ::DevQueryCaps(hdcScreen, CAPS_COLOR_BITCOUNT, 1L, &lBitsPerPixel);

        nDepth = (int)(lPlanes * lBitsPerPixel);
        ::DevCloseDC(hdcScreen);
        ::WinReleasePS(hpsScreen);
    }
    return (nDepth);
}

// Get size of display
void wxDisplaySize(
  int*                              pWidth
, int*                              pHeight
)
{
    HPS                             hpsScreen;
    HDC                             hdcScreen;
    static LONG                     lWidth  = 0;
    static LONG                     lHeight = 0;

    // The screen size ain't gonna change either so just cache the values
    if (!lWidth) {
        hpsScreen = ::WinGetScreenPS(HWND_DESKTOP);
        hdcScreen = ::GpiQueryDevice(hpsScreen);
        ::DevQueryCaps(hdcScreen, CAPS_WIDTH, 1L, &lWidth);
        ::DevQueryCaps(hdcScreen, CAPS_HEIGHT, 1L, &lHeight);
        ::DevCloseDC(hdcScreen);
        ::WinReleasePS(hpsScreen);
    }
    if (pWidth)
        *pWidth = (int)lWidth;
    if (pHeight)
        *pHeight = (int)lHeight;
}

void wxDisplaySizeMM(
  int*                              pWidth
, int*                              pHeight
)
{
    HPS                             hpsScreen;
    HDC                             hdcScreen;

    hpsScreen = ::WinGetScreenPS(HWND_DESKTOP);
    hdcScreen = ::GpiQueryDevice(hpsScreen);

    if (pWidth)
        ::DevQueryCaps( hdcScreen
                       ,CAPS_HORIZONTAL_RESOLUTION
                       ,1L
                       ,(PLONG)pWidth
                      );
    if (pHeight)
        ::DevQueryCaps( hdcScreen
                       ,CAPS_VERTICAL_RESOLUTION
                       ,1L
                       ,(PLONG)pHeight
                      );
    ::DevCloseDC(hdcScreen);
    ::WinReleasePS(hpsScreen);
}

void wxClientDisplayRect(int *x, int *y, int *width, int *height)
{
    // This is supposed to return desktop dimensions minus any window
    // manager panels, menus, taskbars, etc.  If there is a way to do that
    // for this platform please fix this function, otherwise it defaults
    // to the entire desktop.
    if (x) *x = 0;
    if (y) *y = 0;
    wxDisplaySize(width, height);
}

void wxGUIAppTraits::InitializeGui(unsigned long &ulHab)
{
    ulHab = ::WinInitialize(0);
}

void wxGUIAppTraits::TerminateGui(unsigned long ulHab)
{
    ::WinTerminate(ulHab);
}

wxPortId wxGUIAppTraits::GetToolkitVersion(int *verMaj, int *verMin) const
{
    // How to get version of PM ? I guess, just reusing the OS version is OK.
    (void) wxGetOsVersion(verMaj, verMin);
    return wxPORT_OS2;
}

wxTimerImpl* wxGUIAppTraits::CreateTimerImpl(wxTimer *timer)
{
    return new wxOS2TimerImpl(timer);
}

wxEventLoopBase* wxGUIAppTraits::CreateEventLoop()
{
    return new wxEventLoop;
}

// ---------------------------------------------------------------------------
// window information functions
// ---------------------------------------------------------------------------

wxString WXDLLEXPORT wxGetWindowText( WXHWND hWnd )
{
    wxString vStr;

    if ( hWnd )
    {
        long lLen = ::WinQueryWindowTextLength((HWND)hWnd) + 1;
        ::WinQueryWindowText((HWND)hWnd, lLen, (PSZ)(wxChar*)wxStringBuffer(vStr, lLen));
    }

    return vStr;
}

wxString WXDLLEXPORT wxGetWindowClass( WXHWND hWnd )
{
    wxString vStr;
    if ( hWnd )
    {
        int nLen = 256; // some starting value

    for ( ;; )
    {
        int                     nCount = ::WinQueryClassName((HWND)hWnd, nLen, (PSZ)(wxChar*)wxStringBuffer(vStr, nLen));

        if (nCount == nLen )
        {
            // the class name might have been truncated, retry with larger
            // buffer
            nLen *= 2;
        }
        else
        {
            break;
        }
        }
    }
    return vStr;
}

WXWORD WXDLLEXPORT wxGetWindowId(
  WXHWND                            hWnd
)
{
    return ::WinQueryWindowUShort((HWND)hWnd, QWS_ID);
}

void wxDrawBorder(
  HPS                               hPS
, RECTL&                            rRect
, WXDWORD                           dwStyle
)
{
    POINTL                          vPoint[2];

    vPoint[0].x = rRect.xLeft;
    vPoint[0].y = rRect.yBottom;
    ::GpiMove(hPS, &vPoint[0]);
    if (dwStyle & wxSIMPLE_BORDER ||
        dwStyle & wxSTATIC_BORDER)
    {
        vPoint[1].x = rRect.xRight - 1;
        vPoint[1].y = rRect.yTop - 1;
        ::GpiBox( hPS
                 ,DRO_OUTLINE
                 ,&vPoint[1]
                 ,0L
                 ,0L
                );
    }
    if (dwStyle & wxSUNKEN_BORDER)
    {
        LINEBUNDLE                      vLineBundle;

        vLineBundle.lColor     = 0x00FFFFFF; // WHITE
        vLineBundle.usMixMode  = FM_OVERPAINT;
        vLineBundle.fxWidth    = 2;
        vLineBundle.lGeomWidth = 2;
        vLineBundle.usType     = LINETYPE_SOLID;
        vLineBundle.usEnd      = 0;
        vLineBundle.usJoin     = 0;
        ::GpiSetAttrs( hPS
                      ,PRIM_LINE
                      ,LBB_COLOR | LBB_MIX_MODE | LBB_WIDTH | LBB_GEOM_WIDTH | LBB_TYPE
                      ,0L
                      ,&vLineBundle
                     );
        vPoint[1].x = rRect.xRight - 1;
        vPoint[1].y = rRect.yTop - 1;
        ::GpiBox( hPS
                 ,DRO_OUTLINE
                 ,&vPoint[1]
                 ,0L
                 ,0L
                );
       vPoint[0].x = rRect.xLeft + 1;
       vPoint[0].y = rRect.yBottom + 1;
       ::GpiMove(hPS, &vPoint[0]);
        vPoint[1].x = rRect.xRight - 2;
        vPoint[1].y = rRect.yTop - 2;
        ::GpiBox( hPS
                 ,DRO_OUTLINE
                 ,&vPoint[1]
                 ,0L
                 ,0L
                );

        vLineBundle.lColor     = 0x00000000; // BLACK
        vLineBundle.usMixMode  = FM_OVERPAINT;
        vLineBundle.fxWidth    = 2;
        vLineBundle.lGeomWidth = 2;
        vLineBundle.usType     = LINETYPE_SOLID;
        vLineBundle.usEnd      = 0;
        vLineBundle.usJoin     = 0;
        ::GpiSetAttrs( hPS
                      ,PRIM_LINE
                      ,LBB_COLOR | LBB_MIX_MODE | LBB_WIDTH | LBB_GEOM_WIDTH | LBB_TYPE
                      ,0L
                      ,&vLineBundle
                     );
        vPoint[0].x = rRect.xLeft + 2;
        vPoint[0].y = rRect.yBottom + 2;
        ::GpiMove(hPS, &vPoint[0]);
        vPoint[1].x = rRect.xLeft + 2;
        vPoint[1].y = rRect.yTop - 3;
        ::GpiLine(hPS, &vPoint[1]);
        vPoint[1].x = rRect.xRight - 3;
        vPoint[1].y = rRect.yTop - 3;
        ::GpiLine(hPS, &vPoint[1]);

        vPoint[0].x = rRect.xLeft + 3;
        vPoint[0].y = rRect.yBottom + 3;
        ::GpiMove(hPS, &vPoint[0]);
        vPoint[1].x = rRect.xLeft + 3;
        vPoint[1].y = rRect.yTop - 4;
        ::GpiLine(hPS, &vPoint[1]);
        vPoint[1].x = rRect.xRight - 4;
        vPoint[1].y = rRect.yTop - 4;
        ::GpiLine(hPS, &vPoint[1]);
    }
    if (dwStyle & wxDOUBLE_BORDER)
    {
        LINEBUNDLE                      vLineBundle;

        vLineBundle.lColor     = 0x00FFFFFF; // WHITE
        vLineBundle.usMixMode  = FM_OVERPAINT;
        vLineBundle.fxWidth    = 2;
        vLineBundle.lGeomWidth = 2;
        vLineBundle.usType     = LINETYPE_SOLID;
        vLineBundle.usEnd      = 0;
        vLineBundle.usJoin     = 0;
        ::GpiSetAttrs( hPS
                      ,PRIM_LINE
                      ,LBB_COLOR | LBB_MIX_MODE | LBB_WIDTH | LBB_GEOM_WIDTH | LBB_TYPE
                      ,0L
                      ,&vLineBundle
                     );
        vPoint[1].x = rRect.xRight - 1;
        vPoint[1].y = rRect.yTop - 1;
        ::GpiBox( hPS
                 ,DRO_OUTLINE
                 ,&vPoint[1]
                 ,0L
                 ,0L
                );
        vLineBundle.lColor     = 0x00000000; // WHITE
        vLineBundle.usMixMode  = FM_OVERPAINT;
        vLineBundle.fxWidth    = 2;
        vLineBundle.lGeomWidth = 2;
        vLineBundle.usType     = LINETYPE_SOLID;
        vLineBundle.usEnd      = 0;
        vLineBundle.usJoin     = 0;
        ::GpiSetAttrs( hPS
                      ,PRIM_LINE
                      ,LBB_COLOR | LBB_MIX_MODE | LBB_WIDTH | LBB_GEOM_WIDTH | LBB_TYPE
                      ,0L
                      ,&vLineBundle
                     );
        vPoint[0].x = rRect.xLeft + 2;
        vPoint[0].y = rRect.yBottom + 2;
        ::GpiMove(hPS, &vPoint[0]);
        vPoint[1].x = rRect.xRight - 2;
        vPoint[1].y = rRect.yTop - 2;
        ::GpiBox( hPS
                 ,DRO_OUTLINE
                 ,&vPoint[1]
                 ,0L
                 ,0L
                );
        vLineBundle.lColor     = 0x00FFFFFF; // BLACK
        vLineBundle.usMixMode  = FM_OVERPAINT;
        vLineBundle.fxWidth    = 2;
        vLineBundle.lGeomWidth = 2;
        vLineBundle.usType     = LINETYPE_SOLID;
        vLineBundle.usEnd      = 0;
        vLineBundle.usJoin     = 0;
        ::GpiSetAttrs( hPS
                      ,PRIM_LINE
                      ,LBB_COLOR | LBB_MIX_MODE | LBB_WIDTH | LBB_GEOM_WIDTH | LBB_TYPE
                      ,0L
                      ,&vLineBundle
                     );
        vPoint[0].x = rRect.xLeft + 3;
        vPoint[0].y = rRect.yBottom + 3;
        ::GpiMove(hPS, &vPoint[0]);
        vPoint[1].x = rRect.xRight - 3;
        vPoint[1].y = rRect.yTop - 3;
        ::GpiBox( hPS
                 ,DRO_OUTLINE
                 ,&vPoint[1]
                 ,0L
                 ,0L
                );
    }
    if (dwStyle & wxRAISED_BORDER)
    {
        LINEBUNDLE                      vLineBundle;

        vLineBundle.lColor     = 0x00000000; // BLACK
        vLineBundle.usMixMode  = FM_OVERPAINT;
        vLineBundle.fxWidth    = 2;
        vLineBundle.lGeomWidth = 2;
        vLineBundle.usType     = LINETYPE_SOLID;
        vLineBundle.usEnd      = 0;
        vLineBundle.usJoin     = 0;
        ::GpiSetAttrs( hPS
                      ,PRIM_LINE
                      ,LBB_COLOR | LBB_MIX_MODE | LBB_WIDTH | LBB_GEOM_WIDTH | LBB_TYPE
                      ,0L
                      ,&vLineBundle
                     );
        vPoint[1].x = rRect.xRight - 1;
        vPoint[1].y = rRect.yTop - 1;
        ::GpiBox( hPS
                 ,DRO_OUTLINE
                 ,&vPoint[1]
                 ,0L
                 ,0L
                );
       vPoint[0].x = rRect.xLeft + 1;
       vPoint[0].y = rRect.yBottom + 1;
       ::GpiMove(hPS, &vPoint[0]);
        vPoint[1].x = rRect.xRight - 2;
        vPoint[1].y = rRect.yTop - 2;
        ::GpiBox( hPS
                 ,DRO_OUTLINE
                 ,&vPoint[1]
                 ,0L
                 ,0L
                );

        vLineBundle.lColor     = 0x00FFFFFF; // WHITE
        vLineBundle.usMixMode  = FM_OVERPAINT;
        vLineBundle.fxWidth    = 2;
        vLineBundle.lGeomWidth = 2;
        vLineBundle.usType     = LINETYPE_SOLID;
        vLineBundle.usEnd      = 0;
        vLineBundle.usJoin     = 0;
        ::GpiSetAttrs( hPS
                      ,PRIM_LINE
                      ,LBB_COLOR | LBB_MIX_MODE | LBB_WIDTH | LBB_GEOM_WIDTH | LBB_TYPE
                      ,0L
                      ,&vLineBundle
                     );
        vPoint[0].x = rRect.xLeft + 2;
        vPoint[0].y = rRect.yBottom + 2;
        ::GpiMove(hPS, &vPoint[0]);
        vPoint[1].x = rRect.xLeft + 2;
        vPoint[1].y = rRect.yTop - 3;
        ::GpiLine(hPS, &vPoint[1]);
        vPoint[1].x = rRect.xRight - 3;
        vPoint[1].y = rRect.yTop - 3;
        ::GpiLine(hPS, &vPoint[1]);

        vPoint[0].x = rRect.xLeft + 3;
        vPoint[0].y = rRect.yBottom + 3;
        ::GpiMove(hPS, &vPoint[0]);
        vPoint[1].x = rRect.xLeft + 3;
        vPoint[1].y = rRect.yTop - 4;
        ::GpiLine(hPS, &vPoint[1]);
        vPoint[1].x = rRect.xRight - 4;
        vPoint[1].y = rRect.yTop - 4;
        ::GpiLine(hPS, &vPoint[1]);
    }
} // end of wxDrawBorder

void wxOS2SetFont(
  HWND                              hWnd
, const wxFont&                     rFont
)
{
    char                            zFont[128];
    char                            zFacename[30];
    char                            zWeight[30];
    char                            zStyle[30];

    if (hWnd == NULLHANDLE)
        return;

    //
    // The fonts available for Presentation Params are just a few
    // outline fonts, the rest are available to the GPI, so we must
    // map the families to one of these three
    //
    switch(rFont.GetFamily())
    {
        case wxSCRIPT:
            strcpy(zFacename, "Script");
            break;

        case wxDECORATIVE:
            strcpy(zFacename, "WarpSans");
            break;

        case wxROMAN:
            strcpy(zFacename,"Times New Roman");
            break;

        case wxTELETYPE:
            strcpy(zFacename, "Courier New");
            break;

        case wxMODERN:
            strcpy(zFacename, "Courier New");
            break;

        case wxDEFAULT:
        default:
        case wxSWISS:
            strcpy(zFacename, "Helvetica");
            break;
    }

    switch(rFont.GetWeight())
    {
        default:
        case wxNORMAL:
        case wxLIGHT:
            zWeight[0] = '\0';
            break;

        case wxBOLD:
        case wxFONTWEIGHT_MAX:
            strcpy(zWeight, "Bold");
            break;
    }

    switch(rFont.GetStyle())
    {
        case wxITALIC:
        case wxSLANT:
            strcpy(zStyle, "Italic");
            break;

        default:
            zStyle[0] = '\0';
            break;
    }
    sprintf(zFont, "%d.%s", rFont.GetPointSize(), zFacename);
    if (zWeight[0] != '\0')
    {
        strcat(zFont, " ");
        strcat(zFont, zWeight);
    }
    if (zStyle[0] != '\0')
    {
        strcat(zFont, " ");
        strcat(zFont, zStyle);
    }
    ::WinSetPresParam(hWnd, PP_FONTNAMESIZE, strlen(zFont) + 1, (PVOID)zFont);
} // end of wxOS2SetFont

// ---------------------------------------------------------------------------
// Helper for taking a regular bitmap and giving it a disabled look
// ---------------------------------------------------------------------------
wxBitmap wxDisableBitmap(
  const wxBitmap&                   rBmp
, long                              lColor
)
{
    wxMask*                         pMask = rBmp.GetMask();

    if (!pMask)
        return(wxNullBitmap);

    DEVOPENSTRUC                    vDop  = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
    SIZEL                           vSize = {0, 0};
    HDC                             hDC   = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
    HPS                             hPS   = ::GpiCreatePS(vHabmain, hDC, &vSize, PU_PELS | GPIA_ASSOC);
    BITMAPINFOHEADER2               vHeader;
    BITMAPINFO2                     vInfo;
    ERRORID                         vError;
    wxString                        sError;
    HBITMAP                         hBitmap =  (HBITMAP)rBmp.GetHBITMAP();
    HBITMAP                         hOldBitmap = NULLHANDLE;
    HBITMAP                         hOldMask   = NULLHANDLE;
    HBITMAP                         hMask = (HBITMAP)rBmp.GetMask()->GetMaskBitmap();
    unsigned char*                  pucBits;     // buffer that will contain the bitmap data
    unsigned char*                  pucData;     // pointer to use to traverse bitmap data
    unsigned char*                  pucBitsMask; // buffer that will contain the mask data
    unsigned char*                  pucDataMask; // pointer to use to traverse mask data
    LONG                            lScans = 0L;
    LONG                            lScansSet = 0L;
    bool                            bpp16 = (wxDisplayDepth() == 16);

    memset(&vHeader, '\0', 16);
    vHeader.cbFix           = 16;

    memset(&vInfo, '\0', 16);
    vInfo.cbFix           = 16;
    vInfo.cx              = (ULONG)rBmp.GetWidth();
    vInfo.cy              = (ULONG)rBmp.GetHeight();
    vInfo.cPlanes         = 1;
    vInfo.cBitCount       = 24; // Set to desired count going in

    //
    // Create the buffers for data....all wxBitmaps are 24 bit internally
    //
    int                             nBytesPerLine = rBmp.GetWidth() * 3;
    int                             nSizeDWORD    = sizeof(DWORD);
    int                             nLineBoundary = nBytesPerLine % nSizeDWORD;
    int                             nPadding = 0;
    int                             i;
    int                             j;

    //
    // Bitmap must be in a double-word aligned address so we may
    // have some padding to worry about
    //
    if (nLineBoundary > 0)
    {
        nPadding     = nSizeDWORD - nLineBoundary;
        nBytesPerLine += nPadding;
    }
    pucBits = (unsigned char *)malloc(nBytesPerLine * rBmp.GetHeight());
    memset(pucBits, '\0', (nBytesPerLine * rBmp.GetHeight()));
    pucBitsMask = (unsigned char *)malloc(nBytesPerLine * rBmp.GetHeight());
    memset(pucBitsMask, '\0', (nBytesPerLine * rBmp.GetHeight()));

    //
    // Extract the bitmap and mask data
    //
    if ((hOldBitmap = ::GpiSetBitmap(hPS, hBitmap)) == HBM_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    ::GpiQueryBitmapInfoHeader(hBitmap, &vHeader);
    vInfo.cBitCount = 24;
    if ((lScans = ::GpiQueryBitmapBits( hPS
                                       ,0L
                                       ,(LONG)rBmp.GetHeight()
                                       ,(PBYTE)pucBits
                                       ,&vInfo
                                      )) == GPI_ALTERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    if ((hOldMask = ::GpiSetBitmap(hPS, hMask)) == HBM_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    ::GpiQueryBitmapInfoHeader(hMask, &vHeader);
    vInfo.cBitCount = 24;
    if ((lScans = ::GpiQueryBitmapBits( hPS
                                       ,0L
                                       ,(LONG)rBmp.GetHeight()
                                       ,(PBYTE)pucBitsMask
                                       ,&vInfo
                                      )) == GPI_ALTERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    if (( hMask = ::GpiSetBitmap(hPS, hOldMask)) == HBM_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    pucData     = pucBits;
    pucDataMask = pucBitsMask;

    //
    // Get the mask value
    //
    for (i = 0; i < rBmp.GetHeight(); i++)
    {
        for (j = 0; j < rBmp.GetWidth(); j++)
        {
            // Byte 1
            if (bpp16 && *pucDataMask == 0xF8) // 16 bit display gobblygook
            {
                *pucData = 0x7F;
                pucData++;
            }
            else if (*pucDataMask == 0xFF) // set to grey
            {
                *pucData = 0x7F;
                pucData++;
            }
            else
            {
                *pucData = ((unsigned char)(lColor >> 16));
                pucData++;
            }

            // Byte 2
            if (bpp16 && *(pucDataMask + 1) == 0xFC) // 16 bit display gobblygook
            {
                *pucData = 0x7F;
                pucData++;
            }
            else if (*(pucDataMask + 1) == 0xFF) // set to grey
            {
                *pucData = 0x7F;
                pucData++;
            }
            else
            {
                *pucData = ((unsigned char)(lColor >> 8));
                pucData++;
            }

            // Byte 3
            if (bpp16 && *(pucDataMask + 2) == 0xF8) // 16 bit display gobblygook
            {
                *pucData = 0x7F;
                pucData++;
            }
            else if (*(pucDataMask + 2) == 0xFF) // set to grey
            {
                *pucData = 0x7F;
                pucData++;
            }
            else
            {
                *pucData = ((unsigned char)lColor);
                pucData++;
            }
            pucDataMask += 3;
        }
        for (j = 0; j < nPadding; j++)
        {
            pucData++;
            pucDataMask++;
        }
    }

    //
    // Create a new bitmap and set the modified bits
    //
    wxBitmap                        vNewBmp( rBmp.GetWidth()
                                            ,rBmp.GetHeight()
                                            ,24
                                           );
    HBITMAP                         hNewBmp = (HBITMAP)vNewBmp.GetHBITMAP();

    if ((hOldBitmap = ::GpiSetBitmap(hPS, hNewBmp)) == HBM_ERROR)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    if ((lScansSet = ::GpiSetBitmapBits( hPS
                                        ,0L
                                        ,(LONG)rBmp.GetHeight()
                                        ,(PBYTE)pucBits
                                        ,&vInfo
                                       )) == GPI_ALTERROR)

    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
    }
    wxMask*                         pNewMask;

    pNewMask = new wxMask(pMask->GetMaskBitmap());
    vNewBmp.SetMask(pNewMask);
    free(pucBits);
    ::GpiSetBitmap(hPS, NULLHANDLE);
    ::GpiDestroyPS(hPS);
    ::DevCloseDC(hDC);
    if (vNewBmp.Ok())
        return(vNewBmp);
    return(wxNullBitmap);
} // end of wxDisableBitmap

COLORREF wxColourToRGB(
  const wxColour&                   rColor
)
{
    return(OS2RGB(rColor.Red(), rColor.Green(), rColor.Blue()));
} // end of wxColourToRGB
