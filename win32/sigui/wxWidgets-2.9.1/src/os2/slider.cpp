/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/slider.cpp
// Purpose:     wxSlider
// Author:      David Webster
// Modified by:
// Created:     10/15/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/utils.h"
    #include "wx/brush.h"
    #include "wx/scrolwin.h"
#endif

#if wxUSE_SLIDER

#include "wx/slider.h"
#include "wx/os2/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxSlider, wxControl)

wxSlider::wxSlider()
{
    m_hStaticValue = 0L;
    m_hStaticMin   = 0L;
    m_hStaticMax   = 0L;
    m_nPageSize    = 1;
    m_nLineSize    = 1;
    m_nRangeMax    = 0;
    m_nRangeMin    = 0;
    m_nTickFreq    = 0;
} // end of wxSlider::wxSlider

wxSlider::~wxSlider()
{
    if (m_hStaticMin)
        ::WinDestroyWindow((HWND)m_hStaticMin);
    if (m_hStaticMax)
        ::WinDestroyWindow((HWND)m_hStaticMax);
    if (m_hStaticValue)
        ::WinDestroyWindow((HWND)m_hStaticValue);
} // end of wxSlider::~wxSlider

void wxSlider::AdjustSubControls( int nX,
                                  int nY,
                                  int nWidth,
                                  int nHeight,
                                  int WXUNUSED(nSizeFlags) )
{
    int                             nXOffset = nX;
    int                             nYOffset = nY;
    int                             nCx;     // slider,min,max sizes
    int                             nCy;
    int                             nCyf;
    wxChar                          zBuf[300];
    wxFont                          vFont = this->GetFont();

    wxGetCharSize( GetHWND()
                  ,&nCx
                  ,&nCy
                  ,&vFont
                 );

    if ((m_windowStyle & wxSL_VERTICAL) != wxSL_VERTICAL)
    {
        if (m_windowStyle & wxSL_LABELS )
        {
            int                     nMinLen = 0;
            int                     nMaxLen = 0;

            ::WinQueryWindowText((HWND)m_hStaticMin, 300, (PSZ)zBuf);
            GetTextExtent(zBuf, &nMinLen, &nCyf, NULL, NULL, &vFont);

            ::WinQueryWindowText((HWND)m_hStaticMax, 300, (PSZ)zBuf);
            GetTextExtent(zBuf, &nMaxLen, &nCyf, NULL, NULL, &vFont);

            if (m_hStaticValue)
            {
                int                 nNewWidth = wxMax(nMinLen, nMaxLen);
                int                 nValueHeight = nCyf;

                ::WinSetWindowPos( (HWND)m_hStaticValue
                                  ,HWND_TOP
                                  ,(LONG)nXOffset - (nNewWidth + nCx + nMinLen + nCx)
                                  ,(LONG)nYOffset
                                  ,(LONG)nNewWidth
                                  ,(LONG)nValueHeight
                                  ,SWP_SIZE | SWP_MOVE
                                 );
            }
            ::WinSetWindowPos( (HWND)m_hStaticMin
                              ,HWND_TOP
                              ,(LONG)nXOffset - (nMinLen + nCx)
                              ,(LONG)nYOffset
                              ,(LONG)nMinLen
                              ,(LONG)nCyf
                              ,SWP_SIZE | SWP_MOVE
                             );
            nXOffset += nWidth + nCx;

            ::WinSetWindowPos( (HWND)m_hStaticMax
                              ,HWND_TOP
                              ,(LONG)nXOffset
                              ,(LONG)nYOffset
                              ,(LONG)nMaxLen
                              ,(LONG)nCyf
                              ,SWP_ZORDER | SWP_SHOW
                             );
        }
    }
    else
    {
        //
        // Now deal with a vertical slider
        //

        if (m_windowStyle & wxSL_LABELS )
        {
            int                     nMinLen = 0;
            int                     nMaxLen = 0;

            ::WinQueryWindowText((HWND)m_hStaticMin, 300, (PSZ)zBuf);
            GetTextExtent(zBuf, &nMinLen, &nCyf, NULL, NULL, &vFont);

            ::WinQueryWindowText((HWND)m_hStaticMax, 300, (PSZ)zBuf);
            GetTextExtent(zBuf, &nMaxLen, &nCyf, NULL, NULL, &vFont);

            if (m_hStaticValue)
            {
                int                 nNewWidth = (wxMax(nMinLen, nMaxLen));

                ::WinSetWindowPos( (HWND)m_hStaticValue
                                  ,HWND_TOP
                                  ,(LONG)nXOffset
                                  ,(LONG)nYOffset + nHeight + nCyf
                                  ,(LONG)nNewWidth
                                  ,(LONG)nCyf
                                  ,SWP_SIZE | SWP_MOVE
                                 );
            }
            ::WinSetWindowPos( (HWND)m_hStaticMax
                              ,HWND_TOP
                              ,(LONG)nXOffset
                              ,(LONG)nYOffset + nHeight
                              ,(LONG)nMaxLen
                              ,(LONG)nCyf
                              ,SWP_SIZE | SWP_MOVE
                             );
            ::WinSetWindowPos( (HWND)m_hStaticMin
                              ,HWND_TOP
                              ,(LONG)nXOffset
                              ,(LONG)nYOffset - nCyf
                              ,(LONG)nMinLen
                              ,(LONG)nCyf
                              ,SWP_SIZE | SWP_MOVE
                             );
        }
    }
} // end of wxSlider::AdjustSubControls

void wxSlider::ClearSel()
{
} // end of wxSlider::ClearSel

void wxSlider::ClearTicks()
{
} // end of wxSlider::ClearTicks

void wxSlider::Command (
  wxCommandEvent&                   rEvent
)
{
    SetValue(rEvent.GetInt());
    ProcessCommand(rEvent);
} // end of wxSlider::Command

bool wxSlider::ContainsHWND(
  WXHWND                            hWnd
) const
{
    return ( hWnd == GetStaticMin() ||
             hWnd == GetStaticMax() ||
             hWnd == GetEditValue()
           );
} // end of wxSlider::ContainsHWND

bool wxSlider::Create(
  wxWindow*                         pParent
, wxWindowID                        vId
, int                               nValue
, int                               nMinValue
, int                               nMaxValue
, const wxPoint&                    rPos
, const wxSize&                     rSize
, long                              lStyle
, const wxValidator&                rValidator
, const wxString&                   rsName
)
{
    int                             nX       = rPos.x;
    int                             nY       = rPos.y;
    int                             nWidth   = rSize.x;
    int                             nHeight  = rSize.y;
    long                            lMsStyle = 0L;
    long                            lWstyle  = 0L;

    SetName(rsName);
#if wxUSE_VALIDATORS
    SetValidator(rValidator);
#endif
    if (pParent)
        pParent->AddChild(this);
    SetBackgroundColour(pParent->GetBackgroundColour()) ;
    SetForegroundColour(pParent->GetForegroundColour()) ;

    m_hStaticValue = 0L;
    m_hStaticMin   = 0L;
    m_hStaticMax   = 0L;
    m_nPageSize    = 1;
    m_nLineSize    = 1;
    m_windowStyle  = lStyle;
    m_nTickFreq    = 0;

    if (vId == wxID_ANY)
        m_windowId = (int)NewControlId();
    else
        m_windowId = vId;

    if (m_windowStyle & wxCLIP_SIBLINGS )
        lMsStyle |= WS_CLIPSIBLINGS;

    if (m_windowStyle & wxSL_LABELS)
    {
        lMsStyle |= WS_VISIBLE | SS_TEXT | DT_VCENTER;

        m_hStaticValue = (WXHWND)::WinCreateWindow( (HWND)GetHwndOf(pParent) // Parent window handle
                                                   ,WC_STATIC                // Window class
                                                   ,(PSZ)NULL                // Initial Text
                                                   ,(ULONG)lMsStyle          // Style flags
                                                   ,0L, 0L, 0L, 0L           // Origin -- 0 size
                                                   ,(HWND)GetHwndOf(pParent) // owner window handle (same as parent
                                                   ,HWND_TOP                 // initial z position
                                                   ,(ULONG)NewControlId()    // Window identifier
                                                   ,NULL                     // no control data
                                                   ,NULL                     // no Presentation parameters
                                                  );

        //
        // Now create min static control
        //
        wxSprintf(wxBuffer, wxT("%d"), nMinValue);
        lWstyle = SS_TEXT|DT_LEFT|WS_VISIBLE;
        if (m_windowStyle & wxCLIP_SIBLINGS)
            lWstyle |= WS_CLIPSIBLINGS;

        m_hStaticMin = (WXHWND)::WinCreateWindow( (HWND)GetHwndOf(pParent) // Parent window handle
                                                 ,WC_STATIC                // Window class
                                                 ,(PSZ)wxBuffer            // Initial Text
                                                 ,(ULONG)lWstyle           // Style flags
                                                 ,0L, 0L, 0L, 0L           // Origin -- 0 size
                                                 ,(HWND)GetHwndOf(pParent) // owner window handle (same as parent
                                                 ,HWND_TOP                 // initial z position
                                                 ,(ULONG)NewControlId()    // Window identifier
                                                 ,NULL                     // no control data
                                                 ,NULL                     // no Presentation parameters
                                                );
    }
    lMsStyle = 0;

    SLDCDATA                        vSlData;

    vSlData.cbSize = sizeof(SLDCDATA);
    if (m_windowStyle & wxSL_VERTICAL)
        lMsStyle = SLS_VERTICAL | SLS_HOMEBOTTOM | WS_VISIBLE | WS_TABSTOP;
    else
        lMsStyle = SLS_HORIZONTAL | SLS_HOMELEFT | WS_VISIBLE | WS_TABSTOP;

    if (m_windowStyle & wxCLIP_SIBLINGS)
        lMsStyle |= WS_CLIPSIBLINGS;

    if (m_windowStyle & wxSL_AUTOTICKS)
    {
        vSlData.usScale1Spacing = 0;
        vSlData.usScale2Spacing = 0;
    }

    if (m_windowStyle & wxSL_LEFT)
        lMsStyle |= SLS_PRIMARYSCALE2; // if SLS_VERTICAL then SCALE2 is to the left
    else if (m_windowStyle & wxSL_RIGHT)
        lMsStyle |= SLS_PRIMARYSCALE1; // if SLS_VERTICAL then SCALE2 is to the right
    else if (m_windowStyle & wxSL_TOP)
        lMsStyle |= SLS_PRIMARYSCALE1; // if SLS_HORIZONTAL then SCALE1 is to the top
    else if (m_windowStyle & wxSL_BOTTOM )
        lMsStyle |= SLS_PRIMARYSCALE2; // if SLS_HORIZONTAL then SCALE1 is to the bottom
    else if ( m_windowStyle & wxSL_BOTH )
        lMsStyle |= SLS_PRIMARYSCALE1 | SLS_PRIMARYSCALE2;
    else
        lMsStyle |= SLS_PRIMARYSCALE2;
    lMsStyle |= SLS_RIBBONSTRIP;

    m_nPageSize = ((nMaxValue - nMinValue)/10);
    vSlData.usScale1Increments = (USHORT)m_nPageSize;
    vSlData.usScale2Increments = (USHORT)m_nPageSize;

    HWND hScrollBar = ::WinCreateWindow( (HWND)GetHwndOf(pParent) // Parent window handle
                                        ,WC_SLIDER                // Window class
                                        ,(PSZ)wxBuffer            // Initial Text
                                        ,(ULONG)lMsStyle          // Style flags
                                        ,0L, 0L, 0L, 0L           // Origin -- 0 size
                                        ,(HWND)GetHwndOf(pParent) // owner window handle (same as parent
                                        ,HWND_BOTTOM                 // initial z position
                                        ,(HMENU)m_windowId       // Window identifier
                                        ,&vSlData                 // Slider control data
                                        ,NULL                     // no Presentation parameters
                                       );
    m_nRangeMax = nMaxValue;
    m_nRangeMin = nMinValue;

    //
    // Set the size of the ticks ... default to 6 pixels
    //
    ::WinSendMsg( hScrollBar
                 ,SLM_SETTICKSIZE
                 ,MPFROM2SHORT(SMA_SETALLTICKS, (USHORT)12)
                 ,NULL
                );
    //
    // Set the position to the initial value
    //
    ::WinSendMsg( hScrollBar
                 ,SLM_SETSLIDERINFO
                 ,MPFROM2SHORT(SMA_SLIDERARMPOSITION, SMA_RANGEVALUE)
                 ,(MPARAM)nValue
                );

    m_hWnd = (WXHWND)hScrollBar;
    SubclassWin(GetHWND());
    ::WinSetWindowText((HWND)m_hWnd, "");

    SetFont(*wxSMALL_FONT);
    if (m_windowStyle & wxSL_LABELS)
    {
        //
        // Finally, create max value static item
        //
        wxSprintf(wxBuffer, wxT("%d"), nMaxValue);
        lWstyle = SS_TEXT|DT_LEFT|WS_VISIBLE;
        if (m_windowStyle & wxCLIP_SIBLINGS)
            lMsStyle |= WS_CLIPSIBLINGS;

        m_hStaticMax = (WXHWND)::WinCreateWindow( (HWND)GetHwndOf(pParent) // Parent window handle
                                                 ,WC_STATIC                // Window class
                                                 ,(PSZ)wxBuffer            // Initial Text
                                                 ,(ULONG)lWstyle           // Style flags
                                                 ,0L, 0L, 0L, 0L           // Origin -- 0 size
                                                 ,(HWND)GetHwndOf(pParent) // owner window handle (same as parent
                                                 ,HWND_TOP                 // initial z position
                                                 ,(ULONG)NewControlId()    // Window identifier
                                                 ,NULL                     // no control data
                                                 ,NULL                     // no Presentation parameters
                                                );
        if (GetFont().Ok())
        {
            if (GetFont().GetResourceHandle())
            {
                if (m_hStaticMin)
                    wxOS2SetFont( m_hStaticMin
                                 ,GetFont()
                                );
                if (m_hStaticMax)
                    wxOS2SetFont( m_hStaticMax
                                 ,GetFont()
                                );
                if (m_hStaticValue)
                    wxOS2SetFont( m_hStaticValue
                                 ,GetFont()
                                );
            }
        }
    }

    SetXComp(0);
    SetYComp(0);
    SetSize( nX
            ,nY
            ,nWidth
            ,nHeight
           );
    m_nThumbLength = SHORT1FROMMR(::WinSendMsg( GetHwnd()
                                               ,SLM_QUERYSLIDERINFO
                                               ,MPFROM2SHORT( SMA_SLIDERARMDIMENSIONS
                                                             ,SMA_RANGEVALUE
                                                            )
                                               ,(MPARAM)0
                                              )
                                 ) + 4; // for bordersizes

    wxColour vColour(*wxBLACK);

    LONG lColor = (LONG)vColour.GetPixel();

    ::WinSetPresParam( m_hStaticMin
                      ,PP_FOREGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    ::WinSetPresParam( m_hStaticMax
                      ,PP_FOREGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    ::WinSetPresParam( m_hStaticValue
                      ,PP_FOREGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    ::WinSetPresParam( m_hWnd
                      ,PP_FOREGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    lColor = (LONG)m_backgroundColour.GetPixel();
    ::WinSetPresParam( m_hStaticMin
                      ,PP_BACKGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    ::WinSetPresParam( m_hStaticMax
                      ,PP_BACKGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    ::WinSetPresParam( m_hStaticValue
                      ,PP_BACKGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    ::WinSetPresParam( m_hWnd
                      ,PP_BACKGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    vColour.Set(wxString(wxT("BLUE")));
    lColor = (LONG)vColour.GetPixel();
    ::WinSetPresParam( m_hWnd
                      ,PP_HILITEBACKGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    SetValue(nValue);
    return true;
} // end of wxSlider::Create

void wxSlider::DoSetSize( int nX,
                          int nY,
                          int nWidth,
                          int nHeight,
                          int nSizeFlags )
{
    int    nX1      = nX;
    int    nY1      = nY;
    int    nWidth1  = nWidth;
    int    nHeight1 = nHeight;
    int    nXOffset = nX;
    int    nYOffset = nY;
    int    nCx;     // slider,min,max sizes
    int    nCy;
    int    nCyf;
    int    nCurrentX;
    int    nCurrentY;
    wxChar zBuf[300];
    wxFont vFont = this->GetFont();

    //
    // Adjust for OS/2's reverse coordinate system
    //
    wxWindowOS2*                    pParent = (wxWindowOS2*)GetParent();
    int                             nUsedHeight = 0;
    int                             nOS2Height = nHeight;

    if (nOS2Height < 0)
        nOS2Height = 20;
    CacheBestSize(wxSize(nWidth,nOS2Height));

    if (pParent)
    {
        int nOS2ParentHeight = GetOS2ParentHeight(pParent);

        nYOffset = nOS2ParentHeight - (nYOffset + nOS2Height);
        if (nY != wxDefaultCoord)
            nY1 = nOS2ParentHeight - (nY1 + nOS2Height);
    }
    else
    {
        RECTL vRect;

        ::WinQueryWindowRect(HWND_DESKTOP, &vRect);
        nYOffset = vRect.yTop - (nYOffset + nOS2Height);
        if (nY != wxDefaultCoord)
            nY1 = vRect.yTop - (nY1 + nOS2Height);
    }
    m_nSizeFlags = nSizeFlags;

    GetPosition( &nCurrentX, &nCurrentY );
    if (nX == -1 && !(nSizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        nX1 = nCurrentX;
    if (nY == -1 && !(nSizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        nY1 = nCurrentY;

    AdjustForParentClientOrigin( nX1
                                ,nY1
                                ,nSizeFlags
                               );
    wxGetCharSize( GetHWND()
                  ,&nCx
                  ,&nCy
                  ,&vFont
                 );

    if ((m_windowStyle & wxSL_VERTICAL) != wxSL_VERTICAL)
    {
        if (m_windowStyle & wxSL_LABELS )
        {
            int                  nMinLen = 0;
            int                  nMaxLen = 0;

            ::WinQueryWindowText((HWND)m_hStaticMin, 300, (PSZ)zBuf);
            GetTextExtent(zBuf, &nMinLen, &nCyf, NULL, NULL, &vFont);
            ::WinQueryWindowText((HWND)m_hStaticMax, 300, (PSZ)zBuf);
            GetTextExtent(zBuf, &nMaxLen, &nCyf, NULL, NULL, &vFont);

            if (m_hStaticValue)
            {
                int              nNewWidth = (wxMax(nMinLen, nMaxLen));
                int              nValueHeight = nCyf;

                ::WinSetWindowPos( (HWND)m_hStaticValue
                                  ,HWND_TOP
                                  ,(LONG)nXOffset
                                  ,(LONG)nYOffset - (LONG)(nCyf * 1.2)
                                  ,(LONG)nNewWidth
                                  ,(LONG)nValueHeight
                                  ,SWP_ZORDER | SWP_SIZE | SWP_MOVE | SWP_SHOW
                                 );
                nXOffset += nNewWidth + nCx;
            }
            ::WinSetWindowPos( (HWND)m_hStaticMin
                              ,HWND_TOP
                              ,(LONG)nXOffset
                              ,(LONG)nYOffset - (LONG)(nCyf * 1.2)
                              ,(LONG)nMinLen
                              ,(LONG)nCy
                              ,SWP_ZORDER | SWP_SIZE | SWP_MOVE | SWP_SHOW
                             );
            nXOffset += nMinLen + nCx;

            int                  nSliderLength = nWidth1 - nXOffset - nMaxLen - nCx;
            int                  nSliderHeight = nHeight1;

            if (nSliderHeight < 0)
                nSliderHeight = 20;

            //
            // Slider must have a minimum/default length/height
            //
            if (nSliderLength < 100)
                nSliderLength = 100;

            ::WinSetWindowPos( GetHwnd()
                              ,HWND_TOP
                              ,(LONG)nXOffset
                              ,(LONG)nYOffset
                              ,(LONG)nSliderLength
                              ,(LONG)nSliderHeight
                              ,SWP_ZORDER | SWP_SIZE | SWP_MOVE | SWP_SHOW
                             );
            ::WinQueryWindowPos(GetHwnd(), GetSwp());
            ::WinSendMsg( GetHwnd()
                         ,SLM_SETSLIDERINFO
                         ,MPFROM2SHORT( SMA_SHAFTDIMENSIONS
                                       ,0
                                      )
                         ,MPFROMLONG((ULONG)(nSliderHeight/2))
                        );
            nXOffset += nSliderLength + nCx;

            ::WinSetWindowPos( (HWND)m_hStaticMax
                              ,HWND_TOP
                              ,(LONG)nXOffset
                              ,(LONG)nYOffset - (LONG)(nCyf * 1.2)
                              ,(LONG)nMaxLen
                              ,(LONG)nCy
                              ,SWP_ZORDER | SWP_SIZE | SWP_MOVE | SWP_SHOW
                             );
        }
        else
        {
            //
            // No labels
            // If we're prepared to use the existing size, then...
            //
            if (nWidth == -1 && nHeight == -1 &&
                ((nSizeFlags & wxSIZE_AUTO) != wxSIZE_AUTO))
            {
                GetSize( &nWidth1
                        ,&nHeight1
                       );
            }
            if (nWidth1 < 0)
                nWidth1 = 200;
            if (nHeight1 < 0)
                nHeight1 = 20;
            ::WinSetWindowPos( GetHwnd()
                              ,HWND_TOP
                              ,(LONG)nX1
                              ,(LONG)nY1
                              ,(LONG)nWidth1
                              ,(LONG)nHeight1
                              ,SWP_ZORDER | SWP_SIZE | SWP_MOVE | SWP_SHOW
                             );
        }
    }

    //
    // Now deal with a vertical slider
    //
    else
    {
        if (m_windowStyle & wxSL_LABELS )
        {
            int                  nMinLen;
            int                  nMaxLen;

            ::WinQueryWindowText((HWND)m_hStaticMin, 300, (PSZ)zBuf);
            GetTextExtent(zBuf, &nMinLen, &nCyf, NULL, NULL, &vFont);
            ::WinQueryWindowText((HWND)m_hStaticMax, 300, (PSZ)zBuf);
            GetTextExtent(zBuf, &nMaxLen, &nCyf, NULL, NULL, &vFont);
            if (m_hStaticValue)
            {
                int              nNewWidth = wxMax(nMinLen, nMaxLen);
                int              nValueHeight = nCyf;

                ::WinSetWindowPos( (HWND)m_hStaticValue
                                  ,HWND_TOP
                                  ,(LONG)nXOffset
                                  ,(LONG)nYOffset + nHeight
                                  ,(LONG)nNewWidth
                                  ,(LONG)nValueHeight
                                  ,SWP_ZORDER | SWP_SIZE | SWP_MOVE | SWP_SHOW
                                 );
                nUsedHeight += nCyf;
            }
            ::WinSetWindowPos( (HWND)m_hStaticMin
                              ,HWND_TOP
                              ,(LONG)nXOffset
                              ,(LONG)nYOffset + nHeight - nCyf
                              ,(LONG)nMinLen
                              ,(LONG)nCy
                              ,SWP_ZORDER | SWP_SIZE | SWP_MOVE | SWP_SHOW
                             );
            nUsedHeight += nCy;

            int                  nSliderLength = nHeight1 - (nUsedHeight + (2 * nCy));
            int                  nSliderWidth  = nWidth1;

            if (nSliderWidth < 0)
                nSliderWidth = 20;

            //
            // Slider must have a minimum/default length
            //
            if (nSliderLength < 100)
                nSliderLength = 100;

            ::WinSetWindowPos( GetHwnd()
                              ,HWND_TOP
                              ,(LONG)nXOffset
                              ,(LONG)nYOffset + nCyf
                              ,(LONG)nSliderWidth
                              ,(LONG)nSliderLength
                              ,SWP_ZORDER | SWP_SIZE | SWP_MOVE | SWP_SHOW
                             );
            ::WinQueryWindowPos(GetHwnd(), GetSwp());
            ::WinSendMsg( GetHwnd()
                         ,SLM_SETSLIDERINFO
                         ,MPFROM2SHORT( SMA_SHAFTDIMENSIONS
                                       ,0
                                      )
                         ,MPFROMLONG((ULONG)(nSliderWidth/2))
                        );
            nUsedHeight += nSliderLength;
            ::WinSetWindowPos( (HWND)m_hStaticMax
                              ,HWND_TOP
                              ,(LONG)nXOffset
                              ,(LONG)nYOffset - nCyf
                              ,(LONG)nMaxLen
                              ,(LONG)nCy
                              ,SWP_ZORDER | SWP_SIZE | SWP_MOVE | SWP_SHOW
                             );
        }
        else
        {
            //
            // No labels
            // If we're prepared to use the existing size, then...
            //
            if (nWidth == -1 && nHeight == -1 &&
                ((nSizeFlags & wxSIZE_AUTO) != wxSIZE_AUTO))
            {
                GetSize( &nWidth1
                        ,&nHeight1
                       );
            }
            if (nWidth1 < 0)
                nWidth1 = 20;
            if (nHeight1 < 0)
                nHeight1 = 200;
            ::WinSetWindowPos( GetHwnd()
                              ,HWND_TOP
                              ,(LONG)nX1
                              ,(LONG)nY1
                              ,(LONG)nWidth1
                              ,(LONG)nHeight1
                              ,SWP_ZORDER | SWP_SIZE | SWP_MOVE | SWP_SHOW
                             );
        }
    }
} // end of void wxSlider::DoSetSize

int wxSlider::GetLineSize() const
{
    return 1;
} // end of wxSlider::GetLineSize

int wxSlider::GetPageSize() const
{
    return m_nPageSize;
} // end of wxSlider::GetPageSize

void wxSlider::GetPosition(
  int*                              pnX
, int*                              pnY
) const
{
    wxWindowOS2*                    pParent = GetParent();
    RECTL                           vRect;

    vRect.xLeft   = -1;
    vRect.xRight  = -1;
    vRect.yTop    = -1;
    vRect.yBottom = -1;
    wxFindMaxSize( GetHWND()
                  ,&vRect
                 );

    if (m_hStaticMin)
        wxFindMaxSize( m_hStaticMin
                      ,&vRect
                     );
    if (m_hStaticMax)
        wxFindMaxSize( m_hStaticMax
                      ,&vRect
                     );
    if (m_hStaticValue)
        wxFindMaxSize( m_hStaticValue
                      ,&vRect
                     );

    //
    // Since we now have the absolute screen coords,
    // if there's a parent we must subtract its top left corner
    //
    POINTL                          vPoint;

    vPoint.x = vRect.xLeft;
    vPoint.y = vRect.yTop;

    if (pParent)
    {
        SWP                             vSwp;

        ::WinQueryWindowPos((HWND)pParent->GetHWND(), &vSwp);
        vPoint.x = vSwp.x;
        vPoint.y = vSwp.y;
    }

    //
    // We may be faking the client origin.
    // So a window that's really at (0, 30) may appear
    // (to wxWin apps) to be at (0, 0).
    //
    if (GetParent())
    {
        wxPoint                     vPt(GetParent()->GetClientAreaOrigin());

        vPoint.x -= vPt.x;
        vPoint.y -= vPt.y;
    }
    if (pnX)
        *pnX = vPoint.x;
    if (pnY)
        *pnY = vPoint.y;
} // end of wxSlider::GetPosition

int wxSlider::GetSelEnd() const
{
    return 0;
} // end of wxSlider::GetSelEnd

int wxSlider::GetSelStart() const
{
    return 0;
} // end of wxSlider::GetSelStart

void wxSlider::DoGetSize(
  int*                              pnWidth
, int*                              pnHeight
) const
{
    GetSize( pnWidth
            ,pnHeight
           );
} // end of wxSlider::DoGetSize

void wxSlider::GetSize(
  int*                              pnWidth
, int*                              pnHeight
) const
{
    RECTL                           vRect;

    vRect.xLeft   = -1;
    vRect.xRight  = -1;
    vRect.yTop    = -1;
    vRect.yBottom = -1;

    wxFindMaxSize( GetHWND()
                  ,&vRect
                 );

    if (m_hStaticMin)
        wxFindMaxSize( m_hStaticMin
                      ,&vRect
                     );
    if (m_hStaticMax)
        wxFindMaxSize( m_hStaticMax
                      ,&vRect
                     );
    if (m_hStaticValue)
        wxFindMaxSize( m_hStaticValue
                      ,&vRect
                     );
    if (pnWidth)
        *pnWidth  = vRect.xRight - vRect.xLeft;
    if (pnHeight)
        *pnHeight = vRect.yTop - vRect.yBottom;
} // end of wxSlider::GetSize

int wxSlider::GetThumbLength() const
{
    return m_nThumbLength;
} // end of wxSlider::GetThumbLength

int wxSlider::GetValue() const
{
    int                             nPixelRange = SHORT1FROMMR(::WinSendMsg( GetHwnd()
                                                                            ,SLM_QUERYSLIDERINFO
                                                                            ,MPFROM2SHORT( SMA_SHAFTDIMENSIONS
                                                                                          ,SMA_RANGEVALUE
                                                                                         )
                                                                            ,(MPARAM)0
                                                                           )
                                                              );
    double                          dPixelToRange = (double)(nPixelRange - m_nThumbLength)/(double)(m_nRangeMax - m_nRangeMin);
    int                             nNewPos = 0;
    int                             nPixelPos = SHORT1FROMMR(::WinSendMsg( GetHwnd()
                                                                          ,SLM_QUERYSLIDERINFO
                                                                          ,MPFROM2SHORT( SMA_SLIDERARMPOSITION
                                                                                        ,SMA_RANGEVALUE
                                                                                       )
                                                                          ,(MPARAM)0
                                                                         )
                                                            );
    nNewPos = (int)(nPixelPos/dPixelToRange);
    if (nNewPos > (m_nRangeMax - m_nRangeMin)/2)
        nNewPos++;
    return nNewPos;
} // end of wxSlider::GetValue

WXHBRUSH wxSlider::OnCtlColor(
  WXHDC                             hDC
, WXHWND                            hWnd
, WXUINT                            uCtlColor
, WXUINT                            uMessage
, WXWPARAM                          wParam
, WXLPARAM                          lParam
)
{
    return (wxControl::OnCtlColor( hDC
                                  ,hWnd
                                  ,uCtlColor
                                  ,uMessage
                                  ,wParam
                                  ,lParam
                                 )
           );
} // end of wxSlider::OnCtlColor

bool wxSlider::OS2OnScroll( int    WXUNUSED(nOrientation),
                            WXWORD wParam,
                            WXWORD WXUNUSED(wPos),
                            WXHWND WXUNUSED(hControl) )
{
    wxEventType eScrollEvent = wxEVT_NULL;

    switch (wParam)
    {
        case SLN_CHANGE:
            if (m_windowStyle & wxSL_TOP)
                eScrollEvent = wxEVT_SCROLL_TOP;
            else if (m_windowStyle & wxSL_BOTTOM)
                eScrollEvent = wxEVT_SCROLL_BOTTOM;
            break;

        case SLN_SLIDERTRACK:
            eScrollEvent = wxEVT_SCROLL_THUMBTRACK;
            break;

        default:
            return false;
    }

    int nPixelRange = SHORT1FROMMR(::WinSendMsg( GetHwnd()
                                               , SLM_QUERYSLIDERINFO
                                               , MPFROM2SHORT( SMA_SHAFTDIMENSIONS, SMA_RANGEVALUE )
                                               , (MPARAM)0
                                               )
                                  );
    m_dPixelToRange = (double)(nPixelRange - m_nThumbLength)/(double)(m_nRangeMax - m_nRangeMin);
    int nNewPos = 0;
    int nPixelPos = SHORT1FROMMR(::WinSendMsg( GetHwnd()
                                             , SLM_QUERYSLIDERINFO
                                             , MPFROM2SHORT( SMA_SLIDERARMPOSITION, SMA_RANGEVALUE )
                                             , (MPARAM)0
                                             )
                                );

    nNewPos = (int)(nPixelPos/m_dPixelToRange);
    if (nNewPos > (m_nRangeMax - m_nRangeMin)/2)
        nNewPos++;
    if ((nNewPos < GetMin()) || (nNewPos > GetMax()))
    {
        //
        // Out of range - but we did process it
        //
        return true;
    }
    SetValue(nNewPos);

    wxScrollEvent vEvent( eScrollEvent, m_windowId );

    vEvent.SetPosition(nNewPos);
    vEvent.SetEventObject(this);
    HandleWindowEvent(vEvent);

    wxCommandEvent vCevent( wxEVT_COMMAND_SLIDER_UPDATED, GetId() );

    vCevent.SetInt(nNewPos);
    vCevent.SetEventObject(this);
    return (HandleWindowEvent(vCevent));
} // end of wxSlider::OS2OnScroll

void wxSlider::SetLineSize( int nLineSize )
{
    m_nLineSize = nLineSize;
} // end of wxSlider::SetLineSize


void wxSlider::SetPageSize( int nPageSize )
{
    m_nPageSize = nPageSize;
} // end of wxSlider::SetPageSize

void wxSlider::SetRange(
  int                               nMinValue
, int                               nMaxValue
)
{
    wxChar                          zBuf[10];

    m_nRangeMin = nMinValue;
    m_nRangeMax = nMaxValue;

    int                             nPixelRange = SHORT1FROMMR(::WinSendMsg( GetHwnd()
                                                                            ,SLM_QUERYSLIDERINFO
                                                                            ,MPFROM2SHORT( SMA_SHAFTDIMENSIONS
                                                                                          ,SMA_RANGEVALUE
                                                                                         )
                                                                            ,(MPARAM)0
                                                                           )
                                                              );
    m_dPixelToRange = (double)(nPixelRange - m_nThumbLength)/(double)(m_nRangeMax - m_nRangeMin);
    if (m_hStaticMin)
    {
        wxSprintf(zBuf, wxT("%d"), m_nRangeMin);
        ::WinSetWindowText((HWND)m_hStaticMin, (PSZ)zBuf);
    }

    if (m_hStaticMax)
    {
        wxSprintf(zBuf, wxT("%d"), m_nRangeMax);
        ::WinSetWindowText((HWND)m_hStaticMax, (PSZ)zBuf);
    }
} // end of wxSlider::SetRange

void wxSlider::SetSelection(
  int                               WXUNUSED(nMinPos)
, int                               WXUNUSED(nMaxPos)
)
{
} // end of wxSlider::SetSelection

void wxSlider::SetThumbLength(
  int                               nLen
)
{
    int                             nBreadth;

    m_nThumbLength = SHORT1FROMMR(::WinSendMsg( GetHwnd()
                                               ,SLM_QUERYSLIDERINFO
                                               ,MPFROM2SHORT( SMA_SLIDERARMDIMENSIONS
                                                             ,SMA_RANGEVALUE
                                                            )
                                               ,(MPARAM)0
                                              )
                                 ) + 4; // for bordersizes
    nBreadth = SHORT2FROMMR(::WinSendMsg( GetHwnd()
                                         ,SLM_QUERYSLIDERINFO
                                         ,MPFROM2SHORT( SMA_SLIDERARMDIMENSIONS
                                                       ,SMA_RANGEVALUE
                                                      )
                                         ,(MPARAM)0
                                        )
                           );
    ::WinSendMsg( GetHwnd()
                 ,SLM_SETSLIDERINFO
                 ,MPFROM2SHORT( SMA_SLIDERARMDIMENSIONS
                               ,SMA_RANGEVALUE
                              )
                 ,MPFROM2SHORT(nLen, nBreadth)
                );
    m_nThumbLength = nLen + 4; // Borders
} // end of wxSlider::SetThumbLength

void wxSlider::SetTick(
  int                               nTickPos
)
{
    nTickPos = (int)(nTickPos * m_dPixelToRange);
    ::WinSendMsg( GetHwnd()
                 ,SLM_ADDDETENT
                 ,MPFROMSHORT(nTickPos)
                 ,NULL
                );
} // end of wxSlider::SetTick

// For trackbars only
void wxSlider::SetTickFreq( int n, int WXUNUSED(nPos) )
{
    SLDCDATA  vSlData;
    WNDPARAMS vWndParams;
    int       nPixelPos;
    int       i;

    vSlData.cbSize = sizeof(SLDCDATA);
    if (m_windowStyle & wxSL_AUTOTICKS)
    {
        vSlData.usScale1Spacing = 0;
        vSlData.usScale2Spacing = 0;
    }
    vSlData.usScale1Increments = (USHORT)((m_nRangeMax - m_nRangeMin)/n);
    vSlData.usScale2Increments = (USHORT)((m_nRangeMax - m_nRangeMin)/n);

    vWndParams.fsStatus = WPM_CTLDATA;
    vWndParams.cchText  = 0L;
    vWndParams.pszText  = NULL;
    vWndParams.cbPresParams = 0L;
    vWndParams.pPresParams = NULL;
    vWndParams.cbCtlData = vSlData.cbSize;
    vWndParams.pCtlData = (PVOID)&vSlData;
    ::WinSendMsg(GetHwnd(), WM_SETWINDOWPARAMS, (MPARAM)&vWndParams, (MPARAM)0);
    for (i = 1; i < (m_nRangeMax - m_nRangeMin)/n; i++)
    {
        nPixelPos = (int)(i * n * m_dPixelToRange);
        ::WinSendMsg( GetHwnd()
                     ,SLM_ADDDETENT
                     ,MPFROMSHORT(nPixelPos)
                     ,NULL
                    );
    }
} // end of wxSlider::SetTickFreq

void wxSlider::SetValue(
  int                               nValue
)
{
    int                             nPixelRange = SHORT1FROMMR(::WinSendMsg( GetHwnd()
                                                                            ,SLM_QUERYSLIDERINFO
                                                                            ,MPFROM2SHORT( SMA_SHAFTDIMENSIONS
                                                                                          ,SMA_RANGEVALUE
                                                                                         )
                                                                            ,(MPARAM)0
                                                                           )
                                                              );
    m_dPixelToRange = (double)(nPixelRange - m_nThumbLength)/(double)(m_nRangeMax - m_nRangeMin);
    int                             nNewPos = (int)(nValue * m_dPixelToRange);

    ::WinSendMsg( GetHwnd()
                 ,SLM_SETSLIDERINFO
                 ,MPFROM2SHORT( SMA_SLIDERARMPOSITION
                               ,SMA_RANGEVALUE
                              )
                 ,(MPARAM)nNewPos
                );
    if (m_hStaticValue)
    {
        wxSprintf(wxBuffer, wxT("%d"), nValue);
        ::WinSetWindowText((HWND)m_hStaticValue, (PSZ)wxBuffer);
    }
} // end of wxSlider::SetValue

bool wxSlider::Show(
  bool                              bShow
)
{
    wxWindowOS2::Show(bShow);
    if(m_hStaticValue)
        ::WinShowWindow((HWND)m_hStaticValue, bShow);
    if(m_hStaticMin)
        ::WinShowWindow((HWND)m_hStaticMin, bShow);
    if(m_hStaticMax)
        ::WinShowWindow((HWND)m_hStaticMax, bShow);
    return true;
} // end of wxSlider::Show

#endif // wxUSE_SLIDER
