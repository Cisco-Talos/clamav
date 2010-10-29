/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/dcclient.cpp
// Purpose:     wxClientDC class
// Author:      David Webster
// Modified by:
// Created:     09/21/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ===========================================================================
// declarations
// ===========================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/dcclient.h"
#include "wx/os2/dcclient.h"

#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/window.h"
#endif

#include "wx/os2/private.h"

// ----------------------------------------------------------------------------
// array/list types
// ----------------------------------------------------------------------------

struct WXDLLEXPORT wxPaintDCInfo
{
    wxPaintDCInfo( wxWindow* pWin
                  ,wxPaintDCImpl*     pDC
                 )
    {
        m_hWnd = pWin->GetHWND();
        m_hDC = pDC->GetHDC();
        m_nCount = 1;
    }

    WXHWND                          m_hWnd;   // window for this DC
    WXHDC                           m_hDC;    // the DC handle
    size_t                          m_nCount; // usage count
}; // end of wxPaintDCInfot

#include "wx/arrimpl.cpp"

WX_DEFINE_OBJARRAY(wxArrayDCInfo);

// ----------------------------------------------------------------------------
// global variables
// ----------------------------------------------------------------------------

static RECT        g_paintStruct;

#ifdef wxHAS_PAINT_DEBUG
    // a global variable which we check to verify that wxPaintDC are only
    // created in resopnse to WM_PAINT message - doing this from elsewhere is a
    // common programming error among wxWidgets programmers and might lead to
    // very subtle and difficult to debug refresh/repaint bugs.
    int g_isPainting = 0;
#endif // wxHAS_PAINT_DEBUG

// ===========================================================================
// implementation
// ===========================================================================

// ----------------------------------------------------------------------------
// wxWindowDCImpl
// ----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxWindowDCImpl, wxPMDCImpl)

wxWindowDCImpl::wxWindowDCImpl( wxDC *owner ) :
   wxPMDCImpl( owner )
{
    m_PageSize.cx = m_PageSize.cy = 0;
}

wxWindowDCImpl::wxWindowDCImpl( wxDC *owner, wxWindow* pTheCanvas) :
   wxPMDCImpl( owner )
{
    ERRORID                         vError;
    wxString                        sError;
    int                             nWidth, nHeight;

    m_pCanvas = pTheCanvas;
    DoGetSize(&nWidth, &nHeight);
    m_PageSize.cx = nWidth;
    m_PageSize.cy = nHeight;
    m_hDC = (WXHDC) ::WinOpenWindowDC(GetWinHwnd(pTheCanvas) );

    //
    // default under PM is that Window and Client DC's are the same
    // so we offer a separate Presentation Space to use for the
    // entire window.  Otherwise, calling BeginPaint will just create
    // chached-micro client presentation space
    //
     m_hPS = ::GpiCreatePS( vHabmain
                           ,m_hDC
                           ,&m_PageSize
                           ,PU_PELS | GPIF_LONG | GPIA_ASSOC
                          );
    if (!m_hPS)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
        wxLogError(wxT("Unable to create presentation space. Error: %s\n"), sError.c_str());
    }
    ::GpiAssociate(m_hPS, NULLHANDLE);
    ::GpiAssociate(m_hPS, m_hDC);

    //
    // Set the wxWidgets color table
    //
    if (!::GpiCreateLogColorTable( m_hPS
                                  ,0L
                                  ,LCOLF_CONSECRGB
                                  ,0L
                                  ,(LONG)wxTheColourDatabase->m_nSize
                                  ,(PLONG)wxTheColourDatabase->m_palTable
                                 ))
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
        wxLogError(wxT("Unable to set current color table (3). Error: %s\n"), sError.c_str());
    }
    ::GpiCreateLogColorTable( m_hPS
                             ,0L
                             ,LCOLF_RGB
                             ,0L
                             ,0L
                             ,NULL
                            );
    ::WinQueryWindowRect( GetWinHwnd(m_pCanvas)
                         ,&m_vRclPaint
                        );
    InitDC();
} // end of wxWindowDCImpl::wxWindowDCImpl

void wxWindowDCImpl::InitDC()
{

    //
    // The background mode is only used for text background and is set in
    // DrawText() to OPAQUE as required, otherwise always TRANSPARENT,
    //
    ::GpiSetBackMix(GetHPS(), BM_LEAVEALONE);

    //
    // Default bg colour is pne of the window
    //
    SetBackground(wxBrush(m_pCanvas->GetBackgroundColour(), wxSOLID));

    m_pen.SetColour(*wxBLACK);
    m_brush.SetColour(*wxWHITE);
    // since we are a window dc we need to grab the palette from the window
#if wxUSE_PALETTE
    InitializePalette();
#endif
    wxFont* pFont = new wxFont( 10, wxMODERN, wxNORMAL, wxBOLD );
    SetFont(*pFont);
    delete pFont;
    //
    // OS/2 default vertical character alignment needs to match the other OS's
    //
    ::GpiSetTextAlignment((HPS)GetHPS(), TA_NORMAL_HORIZ, TA_BOTTOM);

} // end of wxWindowDCImpl::InitDC

void wxWindowDCImpl::DoGetSize(
  int*                              pnWidth
, int*                              pnHeight
) const
{
    wxCHECK_RET( m_pCanvas, wxT("wxWindowDC without a window?") );
    m_pCanvas->GetSize( pnWidth
                       ,pnHeight
                      );
} // end of wxWindowDCImpl::DoGetSize

// ----------------------------------------------------------------------------
// wxClientDC
// ----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxClientDCImpl, wxWindowDCImpl)

wxClientDCImpl::wxClientDCImpl( wxDC *owner ) :
   wxWindowDCImpl( owner )
{
    m_pCanvas = NULL;
}

wxClientDCImpl::wxClientDCImpl( wxDC *owner, wxWindow *pTheCanvas) :
   wxWindowDCImpl( owner )
{
    SIZEL                           vSizl = { 0,0};
    ERRORID                         vError;
    wxString                        sError;

    m_pCanvas = pTheCanvas;

    //
    // default under PM is that Window and Client DC's are the same
    //

    m_hDC = (WXHDC) ::WinOpenWindowDC(GetWinHwnd(pTheCanvas));
    printf("Got WindowDC %X for window handle %X\n", m_hDC, pTheCanvas);

    m_hPS = ::GpiCreatePS( wxGetInstance()
                          ,m_hDC
                          ,&vSizl
                          ,PU_PELS | GPIF_LONG | GPIA_ASSOC
                         );
    ::GpiAssociate(m_hPS, NULLHANDLE);
    ::GpiAssociate(m_hPS, m_hDC);

    printf("Got m_hPS %X\n", m_hPS);
    // Set the wxWidgets color table
    if (!::GpiCreateLogColorTable( m_hPS
                                  ,0L
                                  ,LCOLF_CONSECRGB
                                  ,0L
                                  ,(LONG)wxTheColourDatabase->m_nSize
                                  ,(PLONG)wxTheColourDatabase->m_palTable
                                 ))
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
        wxLogError(wxT("Unable to set current color table (4). Error: %s\n"), sError.c_str());
    }
    ::GpiCreateLogColorTable( m_hPS
                             ,0L
                             ,LCOLF_RGB
                             ,0L
                             ,0L
                             ,NULL
                            );
    //
    // Set the DC/PS rectangle
    //
    ::WinQueryWindowRect( GetWinHwnd(m_pCanvas)
                         ,&m_vRclPaint
                        );
    InitDC();
} // end of wxClientDCImpl::wxClientDCImpl

void wxClientDCImpl::InitDC()
{
    wxWindowDCImpl::InitDC();

    // in wxUniv build we must manually do some DC adjustments usually
    // performed by Windows for us
#ifdef __WXUNIVERSAL__
    wxPoint ptOrigin = m_pCanvas->GetClientAreaOrigin();
    if ( ptOrigin.x || ptOrigin.y )
    {
        // no need to shift DC origin if shift is null
        SetDeviceOrigin(ptOrigin.x, ptOrigin.y);
    }

    // clip the DC to avoid overwriting the non client area
    SetClippingRegion(wxPoint(0, 0), m_pCanvas->GetClientSize());
#endif // __WXUNIVERSAL__
} // end of wxClientDCImpl::InitDC

wxClientDCImpl::~wxClientDCImpl()
{
} // end of wxClientDCImpl::~wxClientDCImpl

void wxClientDCImpl::DoGetSize(
  int*                              pnWidth
, int*                              pnHeight
) const
{
    wxCHECK_RET( m_pCanvas, wxT("wxWindowDC without a window?") );
    m_pCanvas->GetClientSize( pnWidth
                             ,pnHeight
                            );
} // end of wxClientDCImpl::DoGetSize

// ----------------------------------------------------------------------------
// wxPaintDC
// ----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxPaintDCImpl, wxWindowDCImpl)

wxArrayDCInfo wxPaintDCImpl::ms_cache;

wxPaintDCImpl::wxPaintDCImpl( wxDC *owner ) :
   wxClientDCImpl( owner )
{
    m_pCanvas = NULL;
    m_hDC = 0;
}

wxPaintDCImpl::wxPaintDCImpl( wxDC *owner, wxWindow *pCanvas) :
   wxClientDCImpl( owner )
{
    wxCHECK_RET(pCanvas, wxT("NULL canvas in wxPaintDC ctor"));

#ifdef wxHAS_PAINT_DEBUG
    if (g_isPainting <= 0)
    {
        wxFAIL_MSG( wxT("wxPaintDC may be created only in EVT_PAINT handler!") );
        return;
    }
#endif // wxHAS_PAINT_DEBUG

    m_pCanvas = pCanvas;

    //
    // Do we have a DC for this window in the cache?
    //
    wxPaintDCInfo*                  pInfo = FindInCache();

    if (pInfo)
    {
        m_hDC = pInfo->m_hDC;
        pInfo->m_nCount++;
    }
    else // not in cache, create a new one
    {
        HPS                         hPS;

        m_hDC = ::WinOpenWindowDC(GetWinHwnd(m_pCanvas));
        hPS = ::WinBeginPaint( GetWinHwnd(m_pCanvas)
                              ,NULLHANDLE
                              ,&g_paintStruct
                             );
        if(hPS)
        {
            ::GpiAssociate(hPS, m_hDC);
            m_hOldPS = m_hPS;
            m_hPS = hPS;
            ::GpiCreateLogColorTable( m_hPS
                                     ,0L
                                     ,LCOLF_CONSECRGB
                                     ,0L
                                     ,(LONG)wxTheColourDatabase->m_nSize
                                     ,(PLONG)wxTheColourDatabase->m_palTable
                                    );
            ::GpiCreateLogColorTable( m_hPS
                                     ,0L
                                     ,LCOLF_RGB
                                     ,0L
                                     ,0L
                                     ,NULL
                                    );

            ::WinFillRect(hPS, &g_paintStruct,  m_pCanvas->GetBackgroundColour().GetPixel());
            ::WinQueryWindowRect( GetWinHwnd(m_pCanvas)
                                 ,&m_vRclPaint
                                );
        }

        m_bIsPaintTime   = true;
        ms_cache.Add(new wxPaintDCInfo(m_pCanvas, this));
    }
    InitDC();
} // end of wxPaintDCImpl::wxPaintDCImpl

wxPaintDCImpl::~wxPaintDCImpl()
{
    if ( m_hDC )
    {
        SelectOldObjects(m_hDC);

        size_t                      nIndex;
        wxPaintDCInfo*              pInfo = FindInCache(&nIndex);

        wxCHECK_RET( pInfo, wxT("existing DC should have a cache entry") );

        if ( !--pInfo->m_nCount )
        {
            ::WinEndPaint(m_hPS);
            m_hPS          = m_hOldPS;
            m_bIsPaintTime = false;
            ms_cache.RemoveAt(nIndex);
        }
        //else: cached DC entry is still in use

        // prevent the base class dtor from ReleaseDC()ing it again
        m_hDC = 0;
    }
}

wxPaintDCInfo* wxPaintDCImpl::FindInCache(
  size_t*                           pIndex
) const
{
    wxPaintDCInfo*                  pInfo = NULL;
    size_t                          nCache = ms_cache.GetCount();

    for (size_t n = 0; n < nCache; n++)
    {
        pInfo = &ms_cache[n];
        if (pInfo->m_hWnd == m_pCanvas->GetHWND())
        {
            if (pIndex)
                *pIndex = n;
            break;
        }
    }
    return pInfo;
} // end of wxPaintDCImpl::FindInCache

// find the entry for this DC in the cache (keyed by the window)
WXHDC wxPaintDCImpl::FindDCInCache(
  wxWindow*                         pWin
)
{
    wxPaintDCInfo*                  pInfo = NULL;
    size_t                          nCache = ms_cache.GetCount();

    for (size_t n = 0; n < nCache; n++)
    {
        pInfo = &ms_cache[n];
        if (pInfo->m_hWnd == pWin->GetHWND())
        {
            return pInfo->m_hDC;
        }
    }
    return 0;
} // end of wxPaintDCImpl::FindInCache
