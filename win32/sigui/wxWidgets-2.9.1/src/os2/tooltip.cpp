///////////////////////////////////////////////////////////////////////////////
// Name:        msw/tooltip.cpp
// Purpose:     wxToolTip class implementation for MSW
// Author:      David Webster
// Modified by:
// Created:     10/17/99
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

#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/wx.h"
#endif

#if wxUSE_TOOLTIPS

#include "wx/tooltip.h"
#include "wx/os2/private.h"

// ----------------------------------------------------------------------------
// global variables
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// ctor & dtor
// ----------------------------------------------------------------------------

wxToolTip::wxToolTip(
  const wxString&                   rsTip
)
: m_sText(rsTip)
, m_pWindow(NULL)
{
    Create(rsTip);
} // end of wxToolTip::wxToolTip

wxToolTip::~wxToolTip()
{
    if (m_hWnd)
        ::WinDestroyWindow(m_hWnd);
} // end of wxToolTip::~wxToolTip

void wxToolTip::Create(
  const wxString&                   rsTip
)
{
    ULONG                           lStyle = ES_READONLY | ES_MARGIN | ES_CENTER;
    LONG                            lColor;
    char                            zFont[128];

    m_hWnd = ::WinCreateWindow( HWND_DESKTOP
                               ,WC_ENTRYFIELD
                               ,rsTip.c_str()
                               ,lStyle
                               ,0, 0, 0, 0
                               ,NULLHANDLE
                               ,HWND_TOP
                               ,1
                               ,NULL
                               ,NULL
                              );
    if (!m_hWnd)
    {
        wxLogError(wxT("Unable to create tooltip window"));
    }

    wxColour                        vColor( wxT("YELLOW") );
    lColor = (LONG)vColor.GetPixel();
    ::WinSetPresParam( m_hWnd
                      ,PP_BACKGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    strcpy(zFont, "8.Helv");
    ::WinSetPresParam( m_hWnd
                      ,PP_FONTNAMESIZE
                      ,strlen(zFont) + 1
                      ,(PVOID)zFont
                     );
} // end of wxToolTip::Create

void wxToolTip::DisplayToolTipWindow(
  const wxPoint&                    rPoint
)
{
    LONG                            lX = rPoint.x;
    LONG                            lY = rPoint.y - 30;
    LONG                            lWidth = 0L;
    LONG                            lHeight = 0L;

    lWidth = m_sText.Length() * 8;
    lHeight = 15;
    ::WinSetWindowPos( m_hWnd
                      ,HWND_TOP
                      ,lX
                      ,lY
                      ,lWidth
                      ,lHeight
                      ,SWP_MOVE | SWP_SIZE | SWP_SHOW
                     );
} // end of wxToolTip::DisplayToolTipWindow

void wxToolTip::HideToolTipWindow()
{
    ::WinShowWindow(m_hWnd, FALSE);
} // end of wxToolTip::HideToolTipWindow

void wxToolTip::SetTip(
  const wxString&                   rsTip
)
{
    SWP                             vSwp;
    LONG                            lWidth = 0L;
    LONG                            lHeight = 0L;

    ::WinQueryWindowPos(m_hWnd, &vSwp);
    m_sText = rsTip;
    lWidth = rsTip.Length() * 8;
    lHeight = 15;
    ::WinSetWindowPos( m_hWnd
                      ,HWND_TOP
                      ,vSwp.cx
                      ,vSwp.cy
                      ,lWidth
                      ,lHeight
                      ,SWP_MOVE | SWP_SIZE | SWP_SHOW
                     );
} // end of wxToolTip::SetTip

#endif // wxUSE_TOOLTIPS
