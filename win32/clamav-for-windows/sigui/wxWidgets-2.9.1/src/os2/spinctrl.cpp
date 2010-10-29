/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/spinctrl.cpp
// Purpose:     wxSpinCtrl class implementation for OS/2
// Author:      David Webster
// Modified by:
// Created:     10/15/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"


#ifndef WX_PRECOMP
    #include "wx/wx.h"
#endif

#if wxUSE_SPINCTRL

#include "wx/spinctrl.h"
#include "wx/os2/private.h"

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

extern void  wxAssociateWinWithHandle( HWND         hWnd
                                      ,wxWindowOS2* pWin
                                     );
static WXFARPROC fnWndProcSpinCtrl = (WXFARPROC)NULL;
wxArraySpins                        wxSpinCtrl::m_svAllSpins;

IMPLEMENT_DYNAMIC_CLASS(wxSpinCtrl, wxControl)

BEGIN_EVENT_TABLE(wxSpinCtrl, wxSpinButton)
    EVT_CHAR(wxSpinCtrl::OnChar)
    EVT_SPIN(wxID_ANY, wxSpinCtrl::OnSpinChange)
    EVT_SET_FOCUS(wxSpinCtrl::OnSetFocus)
END_EVENT_TABLE()
// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// the margin between the up-down control and its buddy
static const int MARGIN_BETWEEN = 5;

// ============================================================================
// implementation
// ============================================================================
MRESULT EXPENTRY wxSpinCtrlWndProc(
  HWND                              hWnd
, UINT                              uMessage
, MPARAM                            wParam
, MPARAM                            lParam
)
{
    wxSpinCtrl*                    pSpin = (wxSpinCtrl *)::WinQueryWindowULong( hWnd
                                                                               ,QWL_USER
                                                                              );

    //
    // Forward some messages (the key ones only so far) to the spin ctrl
    //
    switch (uMessage )
    {
        case WM_CHAR:
            pSpin->OS2WindowProc( uMessage
                                 ,wParam
                                 ,lParam
                                );

            //
            // The control may have been deleted at this point, so check.
            //
            if (!(::WinIsWindow(vHabmain, hWnd) && ((wxSpinCtrl *)::WinQueryWindowULong( hWnd
                                                                                        ,QWL_USER
                                                                                       )
                                                   ) == pSpin))
                return 0;
            break;

    }
    return (fnWndProcSpinCtrl( hWnd
                              ,(ULONG)uMessage
                              ,(MPARAM)wParam
                              ,(MPARAM)lParam
                             )
           );
} // end of wxSpinCtrlWndProc

wxSpinCtrl::~wxSpinCtrl()
{
    m_svAllSpins.Remove(this);

    // This removes spurious memory leak reporting
    if (m_svAllSpins.GetCount() == 0)
        m_svAllSpins.Clear();
} // end of wxSpinCtrl::~wxSpinCtrl

// ----------------------------------------------------------------------------
// construction
// ----------------------------------------------------------------------------

bool wxSpinCtrl::Create( wxWindow*       pParent,
                         wxWindowID      vId,
                         const wxString& WXUNUSED(rsValue),
                         const wxPoint&  rPos,
                         const wxSize&   rSize,
                         long            lStyle,
                         int             nMin,
                         int             nMax,
                         int             nInitial,
                         const wxString& rsName )
{
    if (vId == wxID_ANY)
        m_windowId = NewControlId();
    else
        m_windowId = vId;
    if (pParent)
    {
        m_backgroundColour = pParent->GetBackgroundColour();
        m_foregroundColour = pParent->GetForegroundColour();
    }
    SetName(rsName);
    SetParent(pParent);
    m_windowStyle      = lStyle;

    int lSstyle = 0L;

    lSstyle = WS_VISIBLE      |
              WS_TABSTOP      |
              SPBS_MASTER     | // We use only single field spin buttons
              SPBS_NUMERICONLY; // We default to numeric data

    if (m_windowStyle & wxCLIP_SIBLINGS )
        lSstyle |= WS_CLIPSIBLINGS;

    SPBCDATA                        vCtrlData;

    vCtrlData.cbSize = sizeof(SPBCDATA);
    vCtrlData.ulTextLimit = 10L;
    vCtrlData.lLowerLimit = 0L;
    vCtrlData.lUpperLimit = 100L;
    vCtrlData.idMasterSpb = vId;
    vCtrlData.pHWXCtlData = NULL;

    m_hWnd = (WXHWND)::WinCreateWindow( GetWinHwnd(pParent)
                                       ,WC_SPINBUTTON
                                       ,(PSZ)NULL
                                       ,lSstyle
                                       ,0L, 0L, 0L, 0L
                                       ,GetWinHwnd(pParent)
                                       ,HWND_TOP
                                       ,(HMENU)vId
                                       ,(PVOID)&vCtrlData
                                       ,NULL
                                      );
    if (m_hWnd == 0)
    {
        return false;
    }
    m_hWndBuddy = m_hWnd; // One in the same for OS/2
    if(pParent)
        pParent->AddChild((wxSpinButton *)this);

    SetFont(*wxSMALL_FONT);
    SetXComp(0);
    SetYComp(0);
    SetSize( rPos.x, rPos.y, rSize.x, rSize.y );

    SetRange(nMin, nMax);
    SetValue(nInitial);

    //
    // For OS/2 we'll just set our handle into our long data
    //
    wxAssociateWinWithHandle( m_hWnd
                             ,(wxWindowOS2*)this
                            );
    ::WinSetWindowULong(GetHwnd(), QWL_USER, (LONG)this);
    fnWndProcSpinCtrl = (WXFARPROC)::WinSubclassWindow(m_hWnd, (PFNWP)wxSpinCtrlWndProc);
    m_svAllSpins.Add(this);
    return true;
} // end of wxSpinCtrl::Create

wxSize wxSpinCtrl::DoGetBestSize() const
{
    wxSize                          vSizeBtn = wxSpinButton::DoGetBestSize();
    int                             nHeight;
    wxFont                          vFont = (wxFont)GetFont();

    vSizeBtn.x += DEFAULT_ITEM_WIDTH + MARGIN_BETWEEN;

    wxGetCharSize( GetHWND()
                  ,NULL
                  ,&nHeight
                  ,&vFont
                 );
    nHeight = EDIT_HEIGHT_FROM_CHAR_HEIGHT(nHeight)+4;

    if (vSizeBtn.y < nHeight)
    {
        //
        // Make the text tall enough
        //
        vSizeBtn.y = nHeight;
    }
    return vSizeBtn;
} // end of wxSpinCtrl::DoGetBestSize

void wxSpinCtrl::DoGetPosition(
  int*                              pnX
, int*                              pnY
) const
{
    wxSpinButton::DoGetPosition( pnX,pnY );
} // end of wxpinCtrl::DoGetPosition

void wxSpinCtrl::DoGetSize(
  int*                              pnWidth
, int*                              pnHeight
) const
{
    RECTL                           vSpinrect;

    ::WinQueryWindowRect(GetHwnd(), &vSpinrect);

    if (pnWidth)
        *pnWidth = vSpinrect.xRight - vSpinrect.xLeft;
    if (pnHeight)
        *pnHeight = vSpinrect.yTop - vSpinrect.yBottom;
} // end of wxSpinCtrl::DoGetSize

void wxSpinCtrl::DoMoveWindow(
  int                               nX
, int                               nY
, int                               nWidth
, int                               nHeight
)
{
    wxWindowOS2*                    pParent = (wxWindowOS2*)GetParent();

    if (pParent)
    {
        int                         nOS2Height = GetOS2ParentHeight(pParent);

        nY = nOS2Height - (nY + nHeight);
    }
    else
    {
        RECTL                       vRect;

        ::WinQueryWindowRect(HWND_DESKTOP, &vRect);
        nY = vRect.yTop - (nY + nHeight);
    }
    ::WinSetWindowPos( GetHwnd()
                      ,HWND_TOP
                      ,nX
                      ,nY
                      ,nWidth
                      ,nHeight
                      ,SWP_SIZE | SWP_MOVE | SWP_ZORDER | SWP_SHOW
                     );
} // end of wxSpinCtrl::DoMoveWindow

bool wxSpinCtrl::Enable(
  bool                              bEnable
)
{
    if (!wxControl::Enable(bEnable))
    {
        return false;
    }
    ::WinEnableWindow(GetHwnd(), bEnable);
    return true;
} // end of wxSpinCtrl::Enable

wxSpinCtrl* wxSpinCtrl::GetSpinForTextCtrl(
  WXHWND                            hWndBuddy
)
{
    wxSpinCtrl*                     pSpin = (wxSpinCtrl *)::WinQueryWindowULong( (HWND)hWndBuddy
                                                                                ,QWL_USER
                                                                               );
    int                             i = m_svAllSpins.Index(pSpin);

    if (i == wxNOT_FOUND)
        return NULL;

    // sanity check
    wxASSERT_MSG( pSpin->m_hWndBuddy == hWndBuddy,
                  wxT("wxSpinCtrl has incorrect buddy HWND!") );

    return pSpin;
} // end of wxSpinCtrl::GetSpinForTextCtrl

int wxSpinCtrl::GetValue() const
{
    long                            lVal = 0L;
    char                            zVal[10];

    ::WinSendMsg( GetHwnd()
                 ,SPBM_QUERYVALUE
                 ,MPFROMP(zVal)
                 ,MPFROM2SHORT( (USHORT)10
                               ,SPBQ_UPDATEIFVALID
                              )
                );
    lVal = atol(zVal);
    return (int)lVal;
} // end of wxSpinCtrl::GetValue

void wxSpinCtrl::OnChar (
  wxKeyEvent&                       rEvent
)
{
    switch (rEvent.GetKeyCode())
    {
        case WXK_RETURN:
            {
                wxCommandEvent              vEvent( wxEVT_COMMAND_TEXT_ENTER
                                                   ,m_windowId
                                                  );
                wxString                    sVal = wxGetWindowText(m_hWndBuddy);

                InitCommandEvent(vEvent);
                vEvent.SetString(sVal);
                vEvent.SetInt(GetValue());
                if (HandleWindowEvent(vEvent))
                    return;
                break;
            }

        case WXK_TAB:
            //
            // Always produce navigation event - even if we process TAB
            // ourselves the fact that we got here means that the user code
            // decided to skip processing of this TAB - probably to let it
            // do its default job.
            //
            {
                wxNavigationKeyEvent        vEventNav;

                vEventNav.SetDirection(!rEvent.ShiftDown());
                vEventNav.SetWindowChange(rEvent.ControlDown());
                vEventNav.SetEventObject(this);
                if (GetParent()->HandleWindowEvent(vEventNav))
                    return;
            }
            break;
    }

    //
    // No, we didn't process it
    //
    rEvent.Skip();
} // end of wxSpinCtrl::OnChar

void wxSpinCtrl::OnSpinChange(
  wxSpinEvent&                      rEventSpin
)
{
    wxCommandEvent                  vEvent( wxEVT_COMMAND_SPINCTRL_UPDATED
                                           ,GetId()
                                          );

    vEvent.SetEventObject(this);
    vEvent.SetInt(rEventSpin.GetPosition());
    (void)HandleWindowEvent(vEvent);
    if (rEventSpin.GetSkipped())
    {
        vEvent.Skip();
    }
} // end of wxSpinCtrl::OnSpinChange

void wxSpinCtrl::OnSetFocus (
  wxFocusEvent&                     rEvent
)
{
    //
    // When we get focus, give it to our buddy window as it needs it more than
    // we do
    //
    ::WinSetFocus(HWND_DESKTOP, (HWND)m_hWndBuddy);
    rEvent.Skip();
} // end of wxSpinCtrl::OnSetFocus

bool wxSpinCtrl::ProcessTextCommand( WXWORD wCmd,
                                     WXWORD WXUNUSED(wId) )
{
    switch (wCmd)
    {
        case SPBN_CHANGE:
        {
            wxCommandEvent vEvent( wxEVT_COMMAND_TEXT_UPDATED, GetId() );
            vEvent.SetEventObject(this);

            wxString sVal = wxGetWindowText(m_hWndBuddy);

            vEvent.SetString(sVal);
            vEvent.SetInt(GetValue());
            return (HandleWindowEvent(vEvent));
        }

        case SPBN_SETFOCUS:
        case SPBN_KILLFOCUS:
        {
            wxFocusEvent vEvent( wCmd == EN_KILLFOCUS ? wxEVT_KILL_FOCUS : wxEVT_SET_FOCUS
                                ,m_windowId
                               );

            vEvent.SetEventObject(this);
            return(HandleWindowEvent(vEvent));
        }
        default:
            break;
    }

    //
    // Not processed
    //
    return false;
} // end of wxSpinCtrl::ProcessTextCommand

void wxSpinCtrl::SetFocus()
{
    ::WinSetFocus(HWND_DESKTOP, GetHwnd());
} // end of wxSpinCtrl::SetFocus

bool wxSpinCtrl::SetFont(
  const wxFont&                     rFont
)
{
    if (!wxWindowBase::SetFont(rFont))
    {
        // nothing to do
        return false;
    }

    wxOS2SetFont( m_hWnd
                 ,rFont
                );
    return true;
} // end of wxSpinCtrl::SetFont

void wxSpinCtrl::SetValue(
  const wxString&                   rsText
)
{
    long                            lVal;

    lVal = atol(rsText.c_str());
    wxSpinButton::SetValue(lVal);
} // end of wxSpinCtrl::SetValue

bool wxSpinCtrl::Show(
  bool                              bShow
)
{
    if (!wxControl::Show(bShow))
    {
        return false;
    }
    return true;
} // end of wxSpinCtrl::Show

void wxSpinCtrl::SetSelection (
  long                              lFrom
, long                              lTo
)
{
    //
    // If from and to are both -1, it means (in wxWidgets) that all text should
    // be selected - translate into Windows convention
    //
    if ((lFrom == -1) && (lTo == -1))
    {
        lFrom = 0;
    }
    ::WinSendMsg(m_hWnd, EM_SETSEL, MPFROM2SHORT((USHORT)lFrom, (USHORT)lTo), (MPARAM)0);
} // end of wxSpinCtrl::SetSelection

#endif //wxUSE_SPINCTRL
