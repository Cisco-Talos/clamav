/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/gauge.cpp
// Purpose:     wxGauge class
// Author:      David Webster
// Modified by:
// Created:     10/06/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_GAUGE

#include "wx/gauge.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/scrolwin.h"
#endif

#include "wx/os2/private.h"

static WXFARPROC fnWndProcGauge = (WXFARPROC)NULL;
extern void  wxAssociateWinWithHandle( HWND         hWnd
                                      ,wxWindowOS2* pWin
                                     );

IMPLEMENT_DYNAMIC_CLASS(wxGauge, wxGaugeBase)

MRESULT EXPENTRY wxGaugeWndProc( HWND hWnd,
                                 UINT uMessage,
                                 MPARAM wParam,
                                 MPARAM lParam )
{
    wxGauge*                        pGauge = (wxGauge *)::WinQueryWindowULong( hWnd
                                                                              ,QWL_USER
                                                                             );
    HPS hPS;
    RECTL vRect;
    RECTL vRect2;
    RECTL vRect3;
    double dPixelToRange = 0.0;
    double dRange = 0.0;

    switch (uMessage )
    {
        case WM_PAINT:
            hPS = ::WinBeginPaint( hWnd
                                  ,NULLHANDLE
                                  ,&vRect
                                 );
            if(hPS)
            {
                ::WinQueryWindowRect(hWnd, &vRect);
                ::GpiCreateLogColorTable( hPS
                                         ,0L
                                         ,LCOLF_CONSECRGB
                                         ,0L
                                         ,(LONG)wxTheColourDatabase->m_nSize
                                         ,(PLONG)wxTheColourDatabase->m_palTable
                                        );
                ::GpiCreateLogColorTable( hPS
                                         ,0L
                                         ,LCOLF_RGB
                                         ,0L
                                         ,0L
                                         ,NULL
                                        );
                //
                // Draw the guage box
                //
                LONG                lColor = 0x00FFFFFF; // White
                POINTL              vPoint = {vRect.xLeft + 1, vRect.yBottom + 1};

                ::GpiSetColor(hPS, lColor);
                ::GpiMove(hPS, &vPoint);
                vPoint.x = vRect.xRight - 1;
                ::GpiLine(hPS, &vPoint);
                vPoint.y = vRect.yTop - 1;
                ::GpiLine(hPS, &vPoint);
                lColor = 0x000C0C0C; // Darkish Grey to give depth feel
                ::GpiSetColor(hPS, lColor);
                vPoint.x = vRect.xLeft + 1;
                ::GpiLine(hPS, &vPoint);
                vPoint.y = vRect.yBottom + 1;
                ::GpiLine(hPS, &vPoint);
                vRect3.xLeft   = vRect.xLeft + 2;
                vRect3.xRight  = vRect.xRight - 2;
                vRect3.yTop    = vRect.yTop - 2;
                vRect3.yBottom = vRect.yBottom + 2;

                if (pGauge->GetWindowStyleFlag() & wxGA_VERTICAL)
                {
                    dRange = (double)(vRect3.yTop - vRect3.yBottom);
                    dPixelToRange  = dRange/(double)pGauge->GetRange();
                    vRect2.yTop    = (int)(pGauge->GetValue() * dPixelToRange);
                    vRect2.yBottom = vRect3.yBottom;
                    vRect2.xLeft   = vRect3.xLeft;
                    vRect2.xRight  = vRect3.xRight;
                    vRect3.yBottom  = vRect2.yTop;
                    if (vRect3.yBottom <= 1)
                         vRect3.yBottom = 2;
                    ::WinFillRect(hPS, &vRect3,  pGauge->GetBackgroundColour().GetPixel());
                    ::WinFillRect(hPS, &vRect2, pGauge->GetForegroundColour().GetPixel());
                }
                else
                {
                    dRange = (double)(vRect3.xRight - vRect3.xLeft);
                    dPixelToRange  = dRange/(double)pGauge->GetRange();
                    vRect2.yTop    = vRect3.yTop;
                    vRect2.yBottom = vRect3.yBottom;
                    vRect2.xLeft   = vRect3.xLeft;
                    vRect2.xRight  = (int)(pGauge->GetValue() * dPixelToRange);
                    vRect3.xLeft = vRect2.xRight;
                    if (vRect3.xLeft <= 1)
                        vRect3.xLeft = 2;
                    ::WinFillRect(hPS, &vRect3,  pGauge->GetBackgroundColour().GetPixel());
                    ::WinFillRect(hPS, &vRect2, pGauge->GetForegroundColour().GetPixel());
                }
                ::WinEndPaint(hPS);
            }
    }
    return (fnWndProcGauge( hWnd
                           ,(ULONG)uMessage
                           ,(MPARAM)wParam
                           ,(MPARAM)lParam
                          )
           );
} // end of wxGaugeWndProc

bool wxGauge::Create( wxWindowOS2* pParent,
                      wxWindowID vId,
                      int nRange,
                      const wxPoint& rPos,
                      const wxSize& rSize,
                      long lStyle,
                      const wxValidator& rValidator,
                      const wxString& rsName )
{
    int nX       = rPos.x;
    int nY       = rPos.y;
    int nWidth   = rSize.x;
    int nHeight  = rSize.y;
    long lMsStyle = 0L;
    SWP vSwp;

    SetName(rsName);
#if wxUSE_VALIDATORS
    SetValidator(rValidator);
#endif
    if (pParent)
        pParent->AddChild(this);
    m_backgroundColour.Set(wxString(wxT("LIGHT GREY")));
    m_foregroundColour.Set(wxString(wxT("NAVY")));

    m_nRangeMax   = nRange;
    m_nGaugePos   = 0;
    m_windowStyle = lStyle;

    if (vId == wxID_ANY)
        m_windowId = (int)NewControlId();
    else
        m_windowId = vId;

    if (m_windowStyle & wxCLIP_SIBLINGS )
        lMsStyle |= WS_CLIPSIBLINGS;

    //
    // OS/2 will use an edit control for this, since there is not a native gauge
    // Other choices include using an armless slider but they are more difficult
    // to control and manipulate
    //

    lMsStyle = WS_VISIBLE | ES_MARGIN | ES_LEFT | ES_READONLY;
    if (m_windowStyle & wxCLIP_SIBLINGS)
        lMsStyle |= WS_CLIPSIBLINGS;

    m_hWnd = (WXHWND)::WinCreateWindow( (HWND)GetHwndOf(pParent) // Parent window handle
                                       ,WC_ENTRYFIELD            // Window class
                                       ,(PSZ)NULL                // Initial Text
                                       ,(ULONG)lMsStyle          // Style flags
                                       ,0L, 0L, 0L, 0L           // Origin -- 0 size
                                       ,(HWND)GetHwndOf(pParent) // owner window handle (same as parent
                                       ,HWND_TOP                 // initial z position
                                       ,(HMENU)m_windowId        // Window identifier
                                       ,NULL                     // Slider control data
                                       ,NULL                     // no Presentation parameters
                                      );

    wxAssociateWinWithHandle( m_hWnd
                             ,(wxWindowOS2*)this
                            );
    ::WinSetWindowULong(GetHwnd(), QWL_USER, (LONG)this);
    fnWndProcGauge = (WXFARPROC)::WinSubclassWindow(m_hWnd, (PFNWP)wxGaugeWndProc);
    ::WinQueryWindowPos(m_hWnd, &vSwp);
    SetXComp(vSwp.x);
    SetYComp(vSwp.y);
    wxFont*                          pTextFont = new wxFont( 10
                                                            ,wxMODERN
                                                            ,wxNORMAL
                                                            ,wxNORMAL
                                                           );
    SetFont(*pTextFont);
    if (nWidth == -1L)
        nWidth = 50L;
    if (nHeight == -1L)
        nHeight = 28L;
    SetSize( nX
            ,nY
            ,nWidth
            ,nHeight
           );
    m_nWidth  = nWidth;     // Save for GetBestSize
    m_nHeight = nHeight;
    ::WinShowWindow((HWND)GetHWND(), TRUE);
    delete pTextFont;
    return true;
} // end of wxGauge::Create

int wxGauge::GetBezelFace() const
{
    return 0;
} // end of wxGauge::GetBezelFace

int wxGauge::GetRange() const
{
    return m_nRangeMax;
} // end of wxGauge::GetRange

int wxGauge::GetShadowWidth() const
{
    return 0;
} // end of wxGauge::GetShadowWidth

int wxGauge::GetValue() const
{
    return m_nGaugePos;
} // end of wxGauge::GetValue

bool wxGauge::SetBackgroundColour( const wxColour& rColour )
{
    if (!wxControl::SetBackgroundColour(rColour))
        return false;

    LONG                            lColor = (LONG)rColour.GetPixel();

    ::WinSetPresParam( GetHwnd()
                      ,PP_BACKGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    return true;
} // end of wxGauge::SetBackgroundColour

void wxGauge::SetBezelFace( int WXUNUSED(nWidth) )
{
} // end of wxGauge::SetBezelFace

bool wxGauge::SetForegroundColour( const wxColour& rColour )
{
    if (!wxControl::SetForegroundColour(rColour))
        return false;

    LONG lColor = (LONG)rColour.GetPixel();

    ::WinSetPresParam( GetHwnd()
                      ,PP_FOREGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );

    return true;
} // end of wxGauge::SetForegroundColour

void wxGauge::SetRange( int nRange )
{
    m_nRangeMax = nRange;
} // end of wxGauge::SetRange

void wxGauge::SetShadowWidth( int WXUNUSED(nWidth) )
{
} // end of wxGauge::SetShadowWidth

void wxGauge::SetValue( int nPos )
{
    RECT vRect;

    m_nGaugePos = nPos;
    ::WinQueryWindowRect(GetHwnd(), &vRect);
    ::WinInvalidateRect(GetHwnd(), &vRect, FALSE);
} // end of wxGauge::SetValue

wxSize wxGauge::DoGetBestSize() const
{
    return wxSize(m_nWidth,m_nHeight);
}

#endif // wxUSE_GAUGE
