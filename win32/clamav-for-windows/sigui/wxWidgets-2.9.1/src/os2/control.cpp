/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/control.cpp
// Purpose:     wxControl class
// Author:      David Webster
// Modified by:
// Created:     09/17/99
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/control.h"

#ifndef WX_PRECOMP
    #include "wx/event.h"
    #include "wx/app.h"
    #include "wx/dcclient.h"
    #include "wx/scrolwin.h"
    #include "wx/log.h"
#endif

#include "wx/os2/dc.h"
#include "wx/os2/private.h"

IMPLEMENT_ABSTRACT_CLASS(wxControl, wxWindow)

BEGIN_EVENT_TABLE(wxControl, wxWindow)
    EVT_ERASE_BACKGROUND(wxControl::OnEraseBackground)
END_EVENT_TABLE()

// Item members
wxControl::wxControl()
{
} // end of wxControl::wxControl

bool wxControl::Create( wxWindow*           pParent,
                        wxWindowID          vId,
                        const wxPoint&      rPos,
                        const wxSize&       rSize,
                        long                lStyle,
                        const wxValidator&  rValidator,
                        const wxString&     rsName )
{
    bool                            bRval = wxWindow::Create( pParent
                                                             ,vId
                                                             ,rPos
                                                             ,rSize
                                                             ,lStyle
                                                             ,rsName
                                                            );
    if (bRval)
    {
#if wxUSE_VALIDATORS
        SetValidator(rValidator);
#endif
    }
    return bRval;
} // end of wxControl::Create

bool wxControl::OS2CreateControl( const wxChar* zClassname,
                                  const wxString& rsLabel,
                                  const wxPoint& rPos,
                                  const wxSize& rSize,
                                  long lStyle )
{
    WXDWORD dwExstyle;
    WXDWORD dwStyle = OS2GetStyle( lStyle, &dwExstyle );

    return OS2CreateControl( zClassname
                            ,dwStyle
                            ,rPos
                            ,rSize
                            ,rsLabel
                            ,dwExstyle
                           );
} // end of wxControl::OS2CreateControl

bool wxControl::OS2CreateControl( const wxChar*   zClassname,
                                  WXDWORD         dwStyle,
                                  const wxPoint&  rPos,
                                  const wxSize&   rSize,
                                  const wxString& rsLabel,
                                  WXDWORD         dwExstyle )
{
    //
    // Doesn't do anything at all under OS/2
    //
    if (dwExstyle == (WXDWORD)-1)
    {
        dwExstyle = 0;
        (void) OS2GetStyle(GetWindowStyle(), &dwExstyle);
    }
    //
    // All controls should have these styles (wxWidgets creates all controls
    // visible by default)
    //
    if (m_isShown )
        dwStyle |= WS_VISIBLE;

    wxWindow* pParent = GetParent();
    PSZ zClass = "";

    if (!pParent)
        return false;

    if ((wxStrcmp(zClassname, wxT("COMBOBOX"))) == 0)
        zClass = WC_COMBOBOX;
    else if ((wxStrcmp(zClassname, wxT("STATIC"))) == 0)
        zClass = WC_STATIC;
    else if ((wxStrcmp(zClassname, wxT("BUTTON"))) == 0)
        zClass = WC_BUTTON;
    else if ((wxStrcmp(zClassname, wxT("NOTEBOOK"))) == 0)
        zClass = WC_NOTEBOOK;
    else if ((wxStrcmp(zClassname, wxT("CONTAINER"))) == 0)
        zClass = WC_CONTAINER;
    if ((zClass == WC_STATIC) || (zClass == WC_BUTTON))
        dwStyle |= DT_MNEMONIC;

    m_dwStyle = dwStyle;
    m_label = rsLabel;
    wxString label;
    if (dwStyle & DT_MNEMONIC)
        label = ::wxPMTextToLabel(m_label);
    else
        label = m_label;

    // clipping siblings does not yet work
    dwStyle &= ~WS_CLIPSIBLINGS;

    m_hWnd = (WXHWND)::WinCreateWindow( (HWND)GetHwndOf(pParent) // Parent window handle
                                       ,zClass              // Window class
                                       ,label.c_str()       // Initial Text
                                       ,(ULONG)dwStyle           // Style flags
                                       ,(LONG)0                  // X pos of origin
                                       ,(LONG)0                  // Y pos of origin
                                       ,(LONG)0                  // control width
                                       ,(LONG)0                  // control height
                                       ,(HWND)GetHwndOf(pParent) // owner window handle (same as parent
                                       ,HWND_TOP                 // initial z position
                                       ,(ULONG)GetId()           // Window identifier
                                       ,NULL                     // no control data
                                       ,NULL                     // no Presentation parameters
                                      );

    if ( !m_hWnd )
    {
        wxLogError(wxT("Failed to create a control of class '%s'"), zClassname);

        return false;
    }
    //
    // Subclass again for purposes of dialog editing mode
    //
    SubclassWin(m_hWnd);

    //
    // Controls use the same colours as their parent dialog by default
    //
    InheritAttributes();
    //
    // All OS/2 ctrls use the small font
    //
    SetFont(*wxSMALL_FONT);

    SetXComp(0);
    SetYComp(0);
    SetSize( rPos.x, rPos.y, rSize.x, rSize.y );
    return true;
} // end of wxControl::OS2CreateControl

wxSize wxControl::DoGetBestSize() const
{
    return wxSize(DEFAULT_ITEM_WIDTH, DEFAULT_ITEM_HEIGHT);
} // end of wxControl::DoGetBestSize

bool wxControl::ProcessCommand(wxCommandEvent& event)
{
    return HandleWindowEvent(event);
}

WXHBRUSH wxControl::OnCtlColor(WXHDC    hWxDC,
                               WXHWND   WXUNUSED(hWnd),
                               WXUINT   WXUNUSED(uCtlColor),
                               WXUINT   WXUNUSED(uMessage),
                               WXWPARAM WXUNUSED(wParam),
                               WXLPARAM WXUNUSED(lParam))
{
    HPS      hPS = (HPS)hWxDC; // pass in a PS handle in OS/2
    wxColour vColFore = GetForegroundColour();
    wxColour vColBack = GetBackgroundColour();

    if (GetParent()->GetTransparentBackground())
        ::GpiSetBackMix(hPS, BM_LEAVEALONE);
    else
        ::GpiSetBackMix(hPS, BM_OVERPAINT);

    ::GpiSetBackColor(hPS, vColBack.GetPixel());
    ::GpiSetColor(hPS, vColFore.GetPixel());

    wxBrush* pBrush = wxTheBrushList->FindOrCreateBrush( vColBack
                                                         ,wxSOLID
                                                       );
    return (WXHBRUSH)pBrush->GetResourceHandle();
} // end of wxControl::OnCtlColor

void wxControl::OnEraseBackground( wxEraseEvent& rEvent )
{
    RECTL                           vRect;
    wxPMDCImpl                     *impl = (wxPMDCImpl*) rEvent.GetDC()->GetImpl();
    HPS                             hPS = impl->GetHPS();
    SIZEL                           vSize = {0,0};

    ::GpiSetPS(hPS, &vSize, PU_PELS | GPIF_DEFAULT);
    ::WinQueryWindowRect((HWND)GetHwnd(), &vRect);
    ::WinFillRect(hPS, &vRect, GetBackgroundColour().GetPixel());
} // end of wxControl::OnEraseBackground

WXDWORD wxControl::OS2GetStyle( long lStyle, WXDWORD* pdwExstyle ) const
{
    long dwStyle = wxWindow::OS2GetStyle( lStyle, pdwExstyle );

    if (AcceptsFocusFromKeyboard())
    {
        dwStyle |= WS_TABSTOP;
    }
    return dwStyle;
} // end of wxControl::OS2GetStyle

void wxControl::SetLabel( const wxString& rsLabel )
{
    if(rsLabel != m_label)
    {
        m_label = rsLabel;
        wxString label;
        if (m_dwStyle & DT_MNEMONIC)
            label = ::wxPMTextToLabel(m_label);
        else
            label = m_label;
        ::WinSetWindowText(GetHwnd(), label.c_str());
    }
} // end of wxControl::SetLabel

// ---------------------------------------------------------------------------
// global functions
// ---------------------------------------------------------------------------

// Call this repeatedly for several wnds to find the overall size
// of the widget.
// Call it initially with -1 for all values in rect.
// Keep calling for other widgets, and rect will be modified
// to calculate largest bounding rectangle.
void wxFindMaxSize(
  WXHWND                            hWnd
, RECT*                             pRect
)
{
    int                             nLeft = pRect->xLeft;
    int                             nRight = pRect->xRight;
    int                             nTop = pRect->yTop;
    int                             nBottom = pRect->yBottom;

    ::WinQueryWindowRect((HWND)hWnd, pRect);

    if (nLeft < 0)
        return;

    if (nLeft < pRect->xLeft)
        pRect->xLeft = nLeft;

    if (nRight > pRect->xRight)
        pRect->xRight = nRight;

    if (nTop > pRect->yTop)
        pRect->yTop = nTop;

    if (nBottom < pRect->yBottom)
        pRect->yBottom = nBottom;
} // end of wxFindMaxSize
