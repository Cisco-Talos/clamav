/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/statbmp.cpp
// Purpose:     wxStaticBitmap
// Author:      David Webster
// Modified by:
// Created:     11/27/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/statbmp.h"

#ifndef WX_PRECOMP
    #include "wx/icon.h"
    #include "wx/window.h"
    #include "wx/dcclient.h"
#endif

#include "wx/os2/private.h"

#include <stdio.h>

// ---------------------------------------------------------------------------
// macros
// ---------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxStaticBitmap, wxControl)

BEGIN_EVENT_TABLE(wxStaticBitmap, wxWindow)
    EVT_PAINT(wxStaticBitmap::OnPaint)
END_EVENT_TABLE()

static wxGDIImage* ConvertImage(
  const wxGDIImage&                 rBitmap
)
{
    bool                            bIsIcon = rBitmap.IsKindOf( CLASSINFO(wxIcon) );

    if(!bIsIcon )
    {
        wxASSERT_MSG( wxDynamicCast(&rBitmap, wxBitmap),
                      wxT("not an icon and not a bitmap?") );

        const wxBitmap&             rBmp = (const wxBitmap&)rBitmap;
        wxMask*                     pMask = rBmp.GetMask();

        if (pMask && pMask->GetMaskBitmap())
        {
            wxIcon*                 pIcon = new wxIcon;

            pIcon->CopyFromBitmap(rBmp);
            return pIcon;
        }
        return new wxBitmap(rBmp);
    }

    // copying a bitmap is a cheap operation
    return new wxIcon( (const wxIcon&)rBitmap );
} // end of ConvertImage

// ---------------------------------------------------------------------------
//  wxStaticBitmap
// ---------------------------------------------------------------------------

bool wxStaticBitmap::Create( wxWindow*         pParent,
                             wxWindowID        nId,
                             const wxGDIImage& rBitmap,
                             const wxPoint&    rPos,
                             const wxSize&     WXUNUSED(rSize),
                             long              lStyle,
                             const wxString&   rName )
{
    ERRORID                         vError;
    wxString                        sError;

    Init();

    SetName(rName);
    if (pParent)
        pParent->AddChild(this);

    if (nId == -1)
        m_windowId = (int)NewControlId();
    else
        m_windowId = nId;

    m_windowStyle = lStyle;

    int                             nX= rPos.x;
    int                             nY = rPos.y;
    char                            zId[16];

    m_windowStyle = lStyle;

    m_bIsIcon = rBitmap.IsKindOf(CLASSINFO(wxIcon));

    //
    // For now we only support an ICON
    //
    int                             nWinstyle = SS_ICON;

    m_hWnd = (WXHWND)::WinCreateWindow( pParent->GetHWND()
                                       ,(PSZ)wxCanvasClassName
                                       ,zId
                                       ,nWinstyle | WS_VISIBLE
                                       ,0,0,0,0
                                       ,pParent->GetHWND()
                                       ,HWND_TOP
                                       ,m_windowId
                                       ,NULL
                                       ,NULL
                                      );
    if (!m_hWnd)
    {
        vError = ::WinGetLastError(wxGetInstance());
        sError = wxPMErrorToStr(vError);
        return false;
    }
    wxCHECK_MSG( m_hWnd, false, wxT("Failed to create static bitmap") );
    m_pImage = ConvertImage(rBitmap);
    ::WinSendMsg(   m_hWnd,
                    SM_SETHANDLE,
                    MPFROMHWND(rBitmap.GetHandle()),
                    (MPARAM)0);

    // Subclass again for purposes of dialog editing mode
    SubclassWin(m_hWnd);
    SetSize(nX, nY, m_pImage->GetWidth(), m_pImage->GetHeight());

    return true;
} // end of wxStaticBitmap::Create

bool wxStaticBitmap::ImageIsOk() const
{
    return(m_pImage && m_pImage->Ok());
}

void wxStaticBitmap::Free()
{
    wxDELETE(m_pImage);
} // end of wxStaticBitmap::Free

wxSize wxStaticBitmap::DoGetBestSize() const
{
    //
    // Reuse the current size (as wxWindow does) instead of using some
    // arbitrary default size (as wxControl, our immediate base class, does)
    //
    return wxWindow::DoGetBestSize();
}

void wxStaticBitmap::OnPaint ( wxPaintEvent& WXUNUSED(rEvent) )
{
    wxPaintDC vDc(this);
    wxBitmap* pBitmap;

    if (m_pImage->IsKindOf(CLASSINFO(wxIcon)))
    {
        wxIcon*                     pIcon;

        pIcon = wxDynamicCast(m_pImage, wxIcon);
        pBitmap = new wxBitmap(*pIcon);
        vDc.DrawBitmap(*pBitmap, 0, 0);
        delete pBitmap;
    }
    else
    {
        pBitmap = wxDynamicCast(m_pImage, wxBitmap);
        vDc.DrawBitmap(*pBitmap, 0, 0);
    }
} // end of wxStaticBitmap::OnPaint

void wxStaticBitmap::SetImage( const wxGDIImage& rBitmap )
{
    int nX = 0;
    int nY = 0;
    int nWidth = 0;
    int nHeight = 0;

    Free();
    ::WinSendMsg( GetHwnd()
                 ,SM_SETHANDLE
                 ,MPFROMHWND(rBitmap.GetHandle())
                 ,NULL
                );
    m_pImage = ConvertImage(rBitmap);

    GetPosition(&nX, &nY);
    GetSize(&nWidth, &nHeight);
    // Convert to OS/2 coordinate system
    nY = wxWindow::GetOS2ParentHeight(GetParent()) - nY - nHeight;

    RECTL                           vRect;

    vRect.xLeft   = nX;
    vRect.yTop    = nY + nHeight;
    vRect.xRight  = nX + nWidth;
    vRect.yBottom = nY;

    ::WinInvalidateRect(GetHwndOf(GetParent()), &vRect, TRUE);
}

MRESULT wxStaticBitmap::OS2WindowProc(
  WXUINT                            uMsg
, WXWPARAM                          wParam
, WXLPARAM                          lParam
)
{
    return wxWindow::OS2WindowProc(uMsg, wParam, lParam);
} // end of wxStaticBitmap::OS2WindowProc
