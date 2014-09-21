/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/window.cpp
// Purpose:     wxWindow
// Author:      David Webster
// Modified by:
// Created:     10/12/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

//
// For compilers that support precompilation, includes "wx.h".
//
#include "wx/wxprec.h"

#include "wx/window.h"

#ifndef WX_PRECOMP
    #define INCL_DOS
    #define INCL_PM
    #include <os2.h>
    #include "wx/accel.h"
    #include "wx/menu.h"
    #include "wx/dc.h"
    #include "wx/dcclient.h"
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/panel.h"
    #include "wx/layout.h"
    #include "wx/checkbox.h"
    #include "wx/combobox.h"
    #include "wx/dialog.h"
    #include "wx/frame.h"
    #include "wx/listbox.h"
    #include "wx/button.h"
    #include "wx/bmpbuttn.h"
    #include "wx/msgdlg.h"
    #include "wx/scrolwin.h"
    #include "wx/radiobox.h"
    #include "wx/radiobut.h"
    #include "wx/slider.h"
    #include "wx/statbox.h"
    #include "wx/statusbr.h"
    #include "wx/toolbar.h"
    #include "wx/settings.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/textctrl.h"
    #include "wx/menuitem.h"
    #include <stdio.h>
#endif

#include "wx/os2/dcclient.h"

#if wxUSE_OWNER_DRAWN
    #include "wx/ownerdrw.h"
#endif

#if     wxUSE_DRAG_AND_DROP
    #include "wx/dnd.h"
#endif

#include "wx/os2/private.h"

#if wxUSE_TOOLTIPS
    #include "wx/tooltip.h"
#endif

#if wxUSE_NOTEBOOK
    #include "wx/notebook.h"
#endif

#if wxUSE_CARET
    #include "wx/caret.h"
#endif // wxUSE_CARET

#include <string.h>

//
// Place compiler, OS specific includes here
//

//
// Standard macros -- these are for OS/2 PM, but most GUI's have something similar
//
#ifndef GET_X_LPARAM
//
//  SHORT1FROMMP -- LOWORD
//
    #define GET_X_LPARAM(mp) ((unsigned short)(unsigned long)(mp))
//
//  SHORT2FROMMP -- HIWORD
//
    #define GET_Y_LPARAM(mp) ((unsigned short)(unsigned long)(mp >> 16))
#endif // GET_X_LPARAM

#ifndef CW_USEDEFAULT
#  define CW_USEDEFAULT    ((int)0x80000000)
#endif

#ifndef VK_OEM_1
    #define VK_OEM_1        0xBA
    #define VK_OEM_PLUS     0xBB
    #define VK_OEM_COMMA    0xBC
    #define VK_OEM_MINUS    0xBD
    #define VK_OEM_PERIOD   0xBE
    #define VK_OEM_2        0xBF
    #define VK_OEM_3        0xC0
    #define VK_OEM_4        0xDB
    #define VK_OEM_5        0xDC
    #define VK_OEM_6        0xDD
    #define VK_OEM_7        0xDE
#endif

// ---------------------------------------------------------------------------
// global variables
// ---------------------------------------------------------------------------

//
// The last PM message we got (MT-UNSAFE)
//
QMSG                      s_currentMsg;

#if wxUSE_MENUS_NATIVE
extern wxMenu*            wxCurrentPopupMenu;
#endif // wxUSE_MENUS_NATIVE

// ---------------------------------------------------------------------------
// private functions
// ---------------------------------------------------------------------------

//
// the window proc for all our windows; most gui's have something similar
//
MRESULT EXPENTRY wxWndProc( HWND hWnd
                           ,ULONG message
                           ,MPARAM mp1
                           ,MPARAM mp2
                          );

#ifdef  __WXDEBUG__
    const wxChar *wxGetMessageName(int message);
#endif  //__WXDEBUG__

wxWindowOS2* FindWindowForMouseEvent( wxWindow* pWin
                                     ,short*    pnX
                                     ,short*    pnY
                                    );
void         wxRemoveHandleAssociation(wxWindowOS2* pWin);
void         wxAssociateWinWithHandle( HWND         hWnd
                                      ,wxWindowOS2* pWin
                                     );
wxWindow* wxFindWinFromHandle(WXHWND hWnd);

//
// get the current state of SHIFT/CTRL keys
//
static inline bool IsKeyDown(LONG key) {return (::WinGetKeyState(HWND_DESKTOP, key) & 0x8000) != 0; }
static inline bool IsShiftDown() { return IsKeyDown(VK_SHIFT); }
static inline bool IsCtrlDown() { return IsKeyDown(VK_CTRL); }

static wxWindow*                    gpWinBeingCreated = NULL;

// ---------------------------------------------------------------------------
// event tables
// ---------------------------------------------------------------------------

// in wxUniv-OS/2 this class is abstract because it doesn't have DoPopupMenu()
// method
#ifdef __WXUNIVERSAL__
    IMPLEMENT_ABSTRACT_CLASS(wxWindowOS2, wxWindowBase)
#else // __WXPM__
    IMPLEMENT_DYNAMIC_CLASS(wxWindow, wxWindowBase)
#endif // __WXUNIVERSAL__/__WXPM__

BEGIN_EVENT_TABLE(wxWindowOS2, wxWindowBase)
    EVT_ERASE_BACKGROUND(wxWindowOS2::OnEraseBackground)
    EVT_SYS_COLOUR_CHANGED(wxWindowOS2::OnSysColourChanged)
    EVT_IDLE(wxWindowOS2::OnIdle)
    EVT_SET_FOCUS(wxWindowOS2::OnSetFocus)
END_EVENT_TABLE()

// ===========================================================================
// implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// wxWindow utility functions
// ---------------------------------------------------------------------------

//
// Find an item given the PM Window id
//
wxWindow* wxWindowOS2::FindItem(
  long                              lId
) const
{
#if wxUSE_CONTROLS
    wxControl*                      pItem = wxDynamicCast(this, wxControl);

    if (pItem)
    {
        //
        // I it we or one of our "internal" children?
        //
        if (pItem->GetId() == lId
#ifndef __WXUNIVERSAL__
            || (pItem->GetSubcontrols().Index(lId) != wxNOT_FOUND)
#endif
            )
        {
            return pItem;
        }
    }
#endif // wxUSE_CONTROLS

    wxWindowList::compatibility_iterator  current = GetChildren().GetFirst();

    while (current)
    {
        wxWindow*                   pChildWin = current->GetData();
        wxWindow*                   pWnd = pChildWin->FindItem(lId);

        if (pWnd)
            return pWnd;

        current = current->GetNext();
    }
    return(NULL);
} // end of wxWindowOS2::FindItem

//
// Find an item given the PM Window handle
//
wxWindow* wxWindowOS2::FindItemByHWND(
  WXHWND                            hWnd
, bool                              bControlOnly
) const
{
    wxWindowList::compatibility_iterator current = GetChildren().GetFirst();

    while (current)
    {
        wxWindow*                   pParent = current->GetData();

        //
        // Do a recursive search.
        //
        wxWindow*                   pWnd = pParent->FindItemByHWND(hWnd);

        if (pWnd)
            return(pWnd);

        if (!bControlOnly
#if wxUSE_CONTROLS
            || pParent->IsKindOf(CLASSINFO(wxControl))
#endif // wxUSE_CONTROLS
            )
        {
            wxWindow*               pItem = current->GetData();

            if (pItem->GetHWND() == hWnd)
                return(pItem);
            else
            {
                if (pItem->ContainsHWND(hWnd))
                    return(pItem);
            }
        }
        current = current->GetNext();
    }
    return(NULL);
} // end of wxWindowOS2::FindItemByHWND

//
// Default command handler
//
bool wxWindowOS2::OS2Command( WXUINT WXUNUSED(uParam),
                              WXWORD WXUNUSED(uId) )
{
    return false;
}

// ----------------------------------------------------------------------------
// constructors and such
// ----------------------------------------------------------------------------

void wxWindowOS2::Init()
{
    //
    // PM specific
    //
    m_bWinCaptured = false;

    m_fnOldWndProc          = NULL;
    m_bUseCtl3D             = false;
    m_bMouseInWindow        = false;
    m_bLastKeydownProcessed = false;

    //
    // wxWnd
    //
    m_hMenu             = 0L;
    m_hWnd              = 0L;
    m_hWndScrollBarHorz = 0L;
    m_hWndScrollBarVert = 0L;

    memset(&m_vWinSwp, '\0', sizeof (SWP));

    //
    // Pass WM_GETDLGCODE to DefWindowProc()
    //
    m_lDlgCode = 0;

    m_nXThumbSize = 0;
    m_nYThumbSize = 0;
    m_bBackgroundTransparent = false;

    //
    // As all windows are created with WS_VISIBLE style...
    //
    m_isShown = true;

#if wxUSE_MOUSEEVENT_HACK
    m_lLastMouseX =
    m_lLastMouseY = -1;
    m_nLastMouseEvent = -1;
#endif // wxUSE_MOUSEEVENT_HACK
} // wxWindowOS2::Init

//
// Destructor
//
wxWindowOS2::~wxWindowOS2()
{
    SendDestroyEvent();

    for (wxWindow* pWin = GetParent(); pWin; pWin = pWin->GetParent())
    {
        wxTopLevelWindow*           pFrame = wxDynamicCast(pWin, wxTopLevelWindow);

        if (pFrame)
        {
            if (pFrame->GetLastFocus() == this)
                pFrame->SetLastFocus(NULL);
        }
    }

    DestroyChildren();

    if (m_hWnd)
    {
        if(!::WinDestroyWindow(GetHWND()))
        {
            wxLogLastError(wxT("DestroyWindow"));
        }
        //
        // remove hWnd <-> wxWindow association
        //
        wxRemoveHandleAssociation(this);
    }
} // end of wxWindowOS2::~wxWindowOS2

// real construction (Init() must have been called before!)
bool wxWindowOS2::Create( wxWindow*       pParent,
                          wxWindowID      vId,
                          const wxPoint&  rPos,
                          const wxSize&   rSize,
                          long            lStyle,
                          const wxString& rName )
{
    HWND hParent = NULLHANDLE;
    ULONG ulCreateFlags = 0;
    WXDWORD dwExStyle = 0;

    wxCHECK_MSG(pParent, false, wxT("can't create wxWindow without parent"));

#if wxUSE_STATBOX
    //
    // wxGTK doesn't allow to create controls with static box as the parent so
    // this will result in a crash when the program is ported to wxGTK - warn
    // about it
    //
    // the correct solution is to create the controls as siblings of the
    // static box
    //
    wxASSERT_MSG( !wxDynamicCast(pParent, wxStaticBox),
                  wxT("wxStaticBox can't be used as a window parent!") );
#endif // wxUSE_STATBOX

     // Ensure groupbox backgrounds are painted
     if (IsKindOf(CLASSINFO(wxPanel)))
         lStyle &= ~wxCLIP_CHILDREN;

    if ( !CreateBase( pParent
                     ,vId
                     ,rPos
                     ,rSize
                     ,lStyle
                     ,wxDefaultValidator
                     ,rName
                    ))
        return false;

    if (pParent)
    {
        pParent->AddChild(this);
        hParent = GetWinHwnd(pParent);

        if (pParent->IsKindOf(CLASSINFO(wxScrolledWindow)))
            ulCreateFlags |= WS_CLIPSIBLINGS;
    }

    //
    // Most wxSTYLES are really PM Class specific styles and will be
    // set in those class create procs.  PM's basic windows styles are
    // very limited.
    //
    ulCreateFlags |=  OS2GetCreateWindowFlags(&dwExStyle);


#ifdef __WXUNIVERSAL__
    // no 3d effects, we draw them ourselves
    WXDWORD exStyle = 0;
#endif // !wxUniversal
    if (lStyle & wxPOPUP_WINDOW)
    {
        ulCreateFlags &= ~WS_VISIBLE;
        m_isShown = false;
    }
    else
    {
        ulCreateFlags |= WS_VISIBLE;
    }

    //
    // Generic OS/2 Windows have no Control Data but other classes
    // that call OS2Create may have some.
    //
    return(OS2Create( (PSZ)wxCanvasClassName
                     ,rName.c_str()
                     ,ulCreateFlags
                     ,rPos
                     ,rSize
                     ,NULL         // Control Data
                     ,dwExStyle
                     ,true         // Child
                    ));
} // end of wxWindowOS2::Create

// ---------------------------------------------------------------------------
// basic operations
// ---------------------------------------------------------------------------

void wxWindowOS2::SetFocus()
{
    HWND                            hWnd = GetHwnd();
    wxCHECK_RET( hWnd, wxT("can't set focus to invalid window") );

    if (hWnd)
        ::WinSetFocus(HWND_DESKTOP, hWnd);
} // end of wxWindowOS2::SetFocus

void wxWindowOS2::SetFocusFromKbd()
{
    //
    // Nothing else to do under OS/2
    //
    wxWindowBase::SetFocusFromKbd();
} // end of wxWindowOS2::SetFocus

wxWindow* wxWindowBase::DoFindFocus()
{
    HWND                            hWnd = ::WinQueryFocus(HWND_DESKTOP);

    if (hWnd)
    {
        return wxFindWinFromHandle((WXHWND)hWnd);
    }
    return NULL;
} // wxWindowBase::DoFindFocus

void wxWindowOS2::DoEnable( bool bEnable )
{
    HWND                            hWnd = GetHwnd();
    if ( hWnd )
        ::WinEnableWindow(hWnd, (BOOL)bEnable);
}

bool wxWindowOS2::Show( bool bShow )
{
    if (!wxWindowBase::Show(bShow))
        return false;

    HWND                            hWnd = GetHwnd();

    ::WinShowWindow(hWnd, bShow);

    if (bShow)
    {
        ::WinSetWindowPos(hWnd, HWND_TOP, 0, 0, 0, 0, SWP_ACTIVATE | SWP_ZORDER);
    }
    return true;
} // end of wxWindowOS2::Show

void wxWindowOS2::Raise()
{
    ::WinSetWindowPos(GetHwnd(), HWND_TOP, 0, 0, 0, 0, SWP_ZORDER | SWP_ACTIVATE);
} // end of wxWindowOS2::Raise

void wxWindowOS2::Lower()
{
    ::WinSetWindowPos(GetHwnd(), HWND_BOTTOM, 0, 0, 0, 0, SWP_ZORDER | SWP_DEACTIVATE);
} // end of wxWindowOS2::Lower

void wxWindowOS2::SetLabel( const wxString& label )
{
    ::WinSetWindowText(GetHwnd(), label.c_str());
} // end of wxWindowOS2::SetLabel

wxString wxWindowOS2::GetLabel() const
{
    return wxGetWindowText(GetHWND());
} // end of wxWindowOS2::GetLabel

void wxWindowOS2::DoCaptureMouse()
{
    HWND hWnd = GetHwnd();

    if (hWnd && !m_bWinCaptured)
    {
        ::WinSetCapture(HWND_DESKTOP, hWnd);
        m_bWinCaptured = true;
    }
} // end of wxWindowOS2::DoCaptureMouse

void wxWindowOS2::DoReleaseMouse()
{
    if (m_bWinCaptured)
    {
        ::WinSetCapture(HWND_DESKTOP, NULLHANDLE);
        m_bWinCaptured = false;
    }
} // end of wxWindowOS2::ReleaseMouse

/* static */ wxWindow* wxWindowBase::GetCapture()
{
    HWND hwnd = ::WinQueryCapture(HWND_DESKTOP);
    return hwnd ? wxFindWinFromHandle((WXHWND)hwnd) : NULL;
} // end of wxWindowBase::GetCapture

bool wxWindowOS2::SetFont( const wxFont& rFont )
{
    if (!wxWindowBase::SetFont(rFont))
    {
        // nothing to do
        return false;
    }

    HWND hWnd = GetHwnd();

    wxOS2SetFont( hWnd, rFont );
    return true;
} // end of wxWindowOS2::SetFont

// check if base implementation is OK
bool wxWindowOS2::SetCursor( const wxCursor& rCursor)
{
    if ( !wxWindowBase::SetCursor(rCursor))
    {
        // no change
        return false;
    }

    if ( m_cursor.Ok() ) {
        HWND                            hWnd = GetHwnd();
        POINTL                          vPoint;
        RECTL                           vRect;

        ::WinQueryPointerPos(HWND_DESKTOP, &vPoint);
        ::WinQueryWindowRect(hWnd, &vRect);

        if (::WinPtInRect(vHabmain, &vRect, &vPoint) && !wxIsBusy())
        {
            ::WinSetPointer(HWND_DESKTOP, (HPOINTER)m_cursor.GetHCURSOR());
        }
    }
    return true;
} // end of wxWindowOS2::SetCursor

void wxWindowOS2::WarpPointer(
  int                               nXPos
, int                               nYPos
)
{
    int                             nX = nXPos;
    int                             nY = nYPos;
    RECTL                           vRect;

    ::WinQueryWindowRect(GetHwnd(), &vRect);
    nX += vRect.xLeft;
    nY += vRect.yBottom;

    ::WinSetPointerPos(HWND_DESKTOP, (LONG)nX, (LONG)(nY));
} // end of wxWindowOS2::WarpPointer


// ---------------------------------------------------------------------------
// scrolling stuff
// ---------------------------------------------------------------------------

int  wxWindowOS2::GetScrollPos(
  int                               nOrient
) const
{
    if (nOrient == wxHORIZONTAL)
        return((int)::WinSendMsg(m_hWndScrollBarHorz, SBM_QUERYPOS, (MPARAM)NULL, (MPARAM)NULL));
    else
        return((int)::WinSendMsg(m_hWndScrollBarVert, SBM_QUERYPOS, (MPARAM)NULL, (MPARAM)NULL));
} // end of wxWindowOS2::GetScrollPos

int wxWindowOS2::GetScrollRange(
  int                               nOrient
) const
{
    MRESULT                         mr;

    if (nOrient == wxHORIZONTAL)
        mr = ::WinSendMsg(m_hWndScrollBarHorz, SBM_QUERYRANGE, (MPARAM)NULL, (MPARAM)NULL);
    else
        mr = ::WinSendMsg(m_hWndScrollBarVert, SBM_QUERYRANGE, (MPARAM)NULL, (MPARAM)NULL);
    return((int)SHORT2FROMMR(mr));
} // end of wxWindowOS2::GetScrollRange

int wxWindowOS2::GetScrollThumb(
  int                               nOrient
) const
{
    if (nOrient == wxHORIZONTAL )
        return m_nXThumbSize;
    else
        return m_nYThumbSize;
} // end of wxWindowOS2::GetScrollThumb

void wxWindowOS2::SetScrollPos(
  int                               nOrient
, int                               nPos
, bool                              WXUNUSED(bRefresh)
)
{
    if (nOrient == wxHORIZONTAL )
        ::WinSendMsg(m_hWndScrollBarHorz, SBM_SETPOS, (MPARAM)nPos, (MPARAM)NULL);
    else
        ::WinSendMsg(m_hWndScrollBarVert, SBM_SETPOS, (MPARAM)nPos, (MPARAM)NULL);
} // end of wxWindowOS2::SetScrollPos

void wxWindowOS2::SetScrollbar( int  nOrient,
                                int  nPos,
                                int  nThumbVisible,
                                int  nRange,
                                bool WXUNUSED(bRefresh) )
{
    HWND                            hWnd = GetHwnd();
    int                             nOldRange = nRange - nThumbVisible;
    int                             nRange1 = nOldRange;
    int                             nPageSize = nThumbVisible;
    int         nVSBWidth  = wxSystemSettingsNative::GetMetric(wxSYS_VSCROLL_X,
                                                               this);
    int         nHSBHeight = wxSystemSettingsNative::GetMetric(wxSYS_HSCROLL_Y,
                                                               this);

    SBCDATA                         vInfo;
    ULONG                           ulStyle = WS_VISIBLE | WS_SYNCPAINT;
    SWP                             vSwp;
    SWP                             vSwpOwner;
    HWND                            hWndParent;
    HWND                            hWndClient;
    wxWindow*                       pParent = GetParent();

    if (pParent && pParent->IsKindOf(CLASSINFO(wxFrame)))
    {
        wxFrame*                    pFrame;

        pFrame = wxDynamicCast(pParent, wxFrame);
        hWndParent = pFrame->GetFrame();
        hWndClient = GetHwndOf(pParent);
    }
    else
    {
        if (pParent)
            hWndParent = GetHwndOf(pParent);
        else
            hWndParent = GetHwnd();
        hWndClient = hWndParent;
    }
    ::WinQueryWindowPos(hWndClient, &vSwp);
    ::WinQueryWindowPos(hWnd, &vSwpOwner);

    if (nPageSize > 1 && nRange > 0)
    {
        nRange1 += (nPageSize - 1);
    }

    vInfo.cb = sizeof(SBCDATA);
    vInfo.posFirst = 0;
    vInfo.posLast = (SHORT)nRange1;
    vInfo.posThumb = (SHORT)nPos;

    if (nOrient == wxHORIZONTAL )
    {
        ulStyle |= SBS_HORZ;
        if (m_hWndScrollBarHorz == 0L)
        {
            //
            // Since the scrollbars are usually created before the owner is
            // sized either via an OnSize event directly or via sizers or
            // layout constraints, we will initially just use the coords of
            // the parent window (this is usually a frame client window). But
            // the bars themselves, are children of the parent frame (i.e
            // siblings of the frame client.  The owner, however is the actual
            // window being scrolled (or at least the one responsible for
            // handling the scroll events). The owner will be resized later,
            // as it is usually a child of a top level window, and when that
            // is done its scrollbars will be resized and repositioned as well.
            //
            m_hWndScrollBarHorz = ::WinCreateWindow( hWndParent
                                                    ,WC_SCROLLBAR
                                                    ,(PSZ)NULL
                                                    ,ulStyle
                                                    ,vSwp.x
                                                    ,vSwp.y
                                                    ,vSwp.cx - nVSBWidth
                                                    ,nHSBHeight
                                                    ,hWnd
                                                    ,HWND_TOP
                                                    ,60000
                                                    ,&vInfo
                                                    ,NULL
                                                   );
        }
        else
        {
            //
            // The owner (the scrolled window) is a child of the Frame's
            // client window, usually.  The scrollbars are children of the
            // frame, itself, and thus are positioned relative to the frame's
            // origin, not the frame's client window origin.
            // The starting x position is the same as the starting x position
            // of the owner, but in terms of the parent frame.
            // The starting y position is wxSYS_HSCROLL_Y pels below the
            // origin of the owner in terms of the parent frame.
            // The horz bar is the same width as the owner and wxSYS_HSCROLL_Y
            // pels high.
            //
            if (nRange1 >= nThumbVisible)
            {
                ::WinSetWindowPos( m_hWndScrollBarHorz
                                  ,HWND_TOP
                                  ,vSwp.x + vSwpOwner.x
                                  ,(vSwp.y + vSwpOwner.y) - nHSBHeight
                                  ,vSwpOwner.cx
                                  ,nHSBHeight
                                  ,SWP_MOVE | SWP_SIZE | SWP_SHOW | SWP_ACTIVATE | SWP_ZORDER
                                 );
                ::WinSendMsg( m_hWndScrollBarHorz
                             ,SBM_SETSCROLLBAR
                             ,(MPARAM)nPos
                             ,MPFROM2SHORT(0, (SHORT)nRange1)
                            );
                ::WinSendMsg( m_hWndScrollBarHorz
                             ,SBM_SETTHUMBSIZE
                             ,MPFROM2SHORT( (SHORT)nThumbVisible
                                           ,(SHORT)nRange1
                                          )
                             ,(MPARAM)0
                            );
            }
            else
                ::WinShowWindow(m_hWndScrollBarHorz, FALSE);
        }
    }
    else
    {
        ulStyle |= SBS_VERT;
        if (m_hWndScrollBarVert == 0L)
        {
            //
            // Since the scrollbars are usually created before the owner is
            // sized either via an OnSize event directly or via sizers or
            // layout constraints, we will initially just use the coords of
            // the parent window (this is usually a frame client window). But
            // the bars themselves, are children of the parent frame (i.e
            // siblings of the frame client.  The owner, however is the actual
            // window being scrolled (or at least the one responsible for
            // handling the scroll events). The owner will be resized later,
            // as it is usually a child of a top level window, and when that
            // is done its scrollbars will be resized and repositioned as well.
            //
            m_hWndScrollBarVert = ::WinCreateWindow( hWndParent
                                                    ,WC_SCROLLBAR
                                                    ,(PSZ)NULL
                                                    ,ulStyle
                                                    ,vSwp.x + vSwp.cx - nVSBWidth
                                                    ,vSwp.y + nHSBHeight
                                                    ,nVSBWidth
                                                    ,vSwp.cy - nHSBHeight
                                                    ,hWnd
                                                    ,HWND_TOP
                                                    ,60001
                                                    ,&vInfo
                                                    ,NULL
                                                   );
        }
        else
        {
            //
            // The owner (the scrolled window) is a child of the Frame's
            // client window, usually.  The scrollbars are children of the
            // frame, itself and thus are positioned relative to the frame's
            // origin, not the frame's client window's origin.
            // Thus, the x position will be frame client's x (usually a few
            // pels inside the parent frame, plus the width of the owner.
            // Since we may be using sizers or layout constraints for multiple
            // child scrolled windows, the y position will be the frame client's
            // y pos plus the scrolled windows y position, yielding the y
            // position of the scrollbar relative to the parent frame (the vert
            // scrollbar is on the right and starts at the bottom of the
            // owner window).
            // It is wxSYS_VSCROLL_X pels wide and the same height as the owner.
            //
            if (nRange1 >= nThumbVisible)
            {
                ::WinSetWindowPos( m_hWndScrollBarVert
                                  ,HWND_TOP
                                  ,vSwp.x + vSwpOwner.x + vSwpOwner.cx
                                  ,vSwp.y + vSwpOwner.y
                                  ,nVSBWidth
                                  ,vSwpOwner.cy
                                  ,SWP_ACTIVATE | SWP_MOVE | SWP_SIZE | SWP_SHOW
                                 );
                ::WinSendMsg( m_hWndScrollBarVert
                             ,SBM_SETSCROLLBAR
                             ,(MPARAM)nPos
                             ,MPFROM2SHORT(0, (SHORT)nRange1)
                            );
                ::WinSendMsg( m_hWndScrollBarVert
                             ,SBM_SETTHUMBSIZE
                             ,MPFROM2SHORT( (SHORT)nThumbVisible
                                           ,(SHORT)nRange1
                                          )
                             ,(MPARAM)0
                            );
            }
            else
                ::WinShowWindow(m_hWndScrollBarVert, FALSE);
        }
        m_nYThumbSize = nThumbVisible;
    }
} // end of wxWindowOS2::SetScrollbar


void wxWindowOS2::ScrollWindow( int nDx,
                                int nDy,
                                const wxRect* pRect )
{
    RECTL vRect;

    ::WinQueryWindowRect(GetHwnd(), &vRect);
    int height = vRect.yTop;
    if (pRect)
    {
        vRect.xLeft   = pRect->x;
        vRect.yTop    = height - pRect->y;
        vRect.xRight  = pRect->x + pRect->width;
        vRect.yBottom = vRect.yTop - pRect->height;
    }
    nDy *= -1; // flip the sign of Dy as OS/2 is opposite Windows.
    ::WinScrollWindow( GetHwnd()
                      ,(LONG)nDx
                      ,(LONG)nDy
                      ,&vRect
                      ,&vRect
                      ,NULL
                      ,NULL
                      ,SW_SCROLLCHILDREN | SW_INVALIDATERGN
                     );
} // end of wxWindowOS2::ScrollWindow

// ---------------------------------------------------------------------------
// subclassing
// ---------------------------------------------------------------------------

void wxWindowOS2::SubclassWin(
  WXHWND                            hWnd
)
{
    HWND                            hwnd = (HWND)hWnd;

    wxCHECK_RET(::WinIsWindow(vHabmain, hwnd), wxT("invalid HWND in SubclassWin") );
    wxAssociateWinWithHandle( hWnd
                             ,(wxWindow*)this
                            );
    if (!wxCheckWindowWndProc( hWnd
                              ,(WXFARPROC)wxWndProc
                             ))
    {
        m_fnOldWndProc = (WXFARPROC) ::WinSubclassWindow(hwnd, (PFNWP)wxWndProc);
    }
    else
    {
        m_fnOldWndProc = (WXFARPROC)NULL;
    }
} // end of wxWindowOS2::SubclassWin

void wxWindowOS2::UnsubclassWin()
{
    //
    // Restore old Window proc
    //
    HWND                            hwnd = GetHWND();

    if (m_hWnd)
    {
        wxCHECK_RET( ::WinIsWindow(vHabmain, hwnd), wxT("invalid HWND in UnsubclassWin") );

        PFNWP                       fnProc = (PFNWP)::WinQueryWindowPtr(hwnd, QWP_PFNWP);

        if ( (m_fnOldWndProc != 0) && (fnProc != (PFNWP) m_fnOldWndProc))
        {
            WinSubclassWindow(hwnd, (PFNWP)m_fnOldWndProc);
            m_fnOldWndProc = 0;
        }
    }
} // end of wxWindowOS2::UnsubclassWin

bool wxCheckWindowWndProc(
  WXHWND                            hWnd
, WXFARPROC                         fnWndProc
)
{
    static char                     zBuffer[512];
    CLASSINFO                       vCls;

    ::WinQueryClassName((HWND)hWnd, (LONG)512, (PCH)zBuffer);
    ::WinQueryClassInfo(wxGetInstance(), (PSZ)zBuffer, &vCls);
    return(fnWndProc == (WXFARPROC)vCls.pfnWindowProc);
} // end of WinGuiBase_CheckWindowWndProc

void wxWindowOS2::SetWindowStyleFlag(
  long                              lFlags
)
{
    long                            lFlagsOld = GetWindowStyleFlag();

    if (lFlags == lFlagsOld)
        return;

    //
    // Update the internal variable
    //
    wxWindowBase::SetWindowStyleFlag(lFlags);

    //
    // Now update the Windows style as well if needed - and if the window had
    // been already created
    //
    if (!GetHwnd())
        return;

    WXDWORD                         dwExstyle;
    WXDWORD                         dwExstyleOld;
    long                            lStyle = OS2GetStyle( lFlags
                                                         ,&dwExstyle
                                                        );
    long                            lStyleOld = OS2GetStyle( lFlagsOld
                                                            ,&dwExstyleOld
                                                           );

    if (lStyle != lStyleOld)
    {
        //
        // Some flags (e.g. WS_VISIBLE or WS_DISABLED) should not be changed by
        // this function so instead of simply setting the style to the new
        // value we clear the bits which were set in styleOld but are set in
        // the new one and set the ones which were not set before
        //
        long                        lStyleReal = ::WinQueryWindowULong(GetHwnd(), QWL_STYLE);

        lStyleReal &= ~lStyleOld;
        lStyleReal |= lStyle;

        ::WinSetWindowULong(GetHwnd(), QWL_STYLE, lStyleReal);
    }
} // end of wxWindowOS2::SetWindowStyleFlag

WXDWORD wxWindowOS2::OS2GetStyle( long     lFlags,
                                  WXDWORD* WXUNUSED(pdwExstyle) ) const
{
    WXDWORD                         dwStyle = 0L;

    if (lFlags & wxCLIP_CHILDREN )
        dwStyle |= WS_CLIPCHILDREN;

    if (lFlags & wxCLIP_SIBLINGS )
        dwStyle |= WS_CLIPSIBLINGS;

    return dwStyle;
} // end of wxWindowOS2::OS2GetStyle

//
// Make a Windows extended style from the given wxWidgets window style
//
WXDWORD wxWindowOS2::MakeExtendedStyle(
  long                              lStyle
, bool                              bEliminateBorders
)
{
   //
   // Simply fill out with wxWindow extended styles.  We'll conjure
   // something up in OS2Create and all window redrawing pieces later
   //
    WXDWORD                         dwStyle = 0;

    if (lStyle & wxTRANSPARENT_WINDOW )
        dwStyle |= wxTRANSPARENT_WINDOW;

    if (!bEliminateBorders)
    {
        if (lStyle & wxSUNKEN_BORDER)
            dwStyle |= wxSUNKEN_BORDER;
        if (lStyle & wxDOUBLE_BORDER)
            dwStyle |= wxDOUBLE_BORDER;
        if (lStyle & wxRAISED_BORDER )
            dwStyle |= wxRAISED_BORDER;
        if (lStyle & wxSTATIC_BORDER)
            dwStyle |= wxSTATIC_BORDER;
    }
    return dwStyle;
} // end of wxWindowOS2::MakeExtendedStyle

//
// Setup background and foreground colours correctly
//
void wxWindowOS2::SetupColours()
{
    if ( GetParent() )
        SetBackgroundColour(GetParent()->GetBackgroundColour());
} // end of wxWindowOS2::SetupColours

void wxWindowOS2::OnIdle(
  wxIdleEvent&                      WXUNUSED(rEvent)
)
{
    //
    // Check if we need to send a LEAVE event
    //
    if (m_bMouseInWindow)
    {
        POINTL                      vPoint;

        ::WinQueryPointerPos(HWND_DESKTOP, &vPoint);
        if (::WinWindowFromPoint(HWND_DESKTOP, &vPoint, FALSE) != (HWND)GetHwnd())
        {
            //
            // Generate a LEAVE event
            //
            m_bMouseInWindow = false;

            //
            // Unfortunately the mouse button and keyboard state may have changed
            // by the time the OnIdle function is called, so 'state' may be
            // meaningless.
            //
            int                     nState = 0;

            if (IsShiftDown())
                nState |= KC_SHIFT;
            if (IsCtrlDown())
                nState |= KC_CTRL;

            wxMouseEvent            rEvent(wxEVT_LEAVE_WINDOW);

            InitMouseEvent( rEvent
                           ,vPoint.x
                           ,vPoint.y
                           ,nState
                          );
            (void)HandleWindowEvent(rEvent);
        }
    }
    if (wxUpdateUIEvent::CanUpdate(this))
        UpdateWindowUI(wxUPDATE_UI_FROMIDLE);
} // end of wxWindowOS2::OnIdle

//
// Set this window to be the child of 'parent'.
//
bool wxWindowOS2::Reparent( wxWindowBase* pParent)
{
    if (!wxWindowBase::Reparent(pParent))
        return false;

    HWND hWndChild = GetHwnd();
    HWND hWndParent = GetParent() ? GetWinHwnd(GetParent()) : (HWND)0;

    ::WinSetParent(hWndChild, hWndParent, TRUE);
    return true;
} // end of wxWindowOS2::Reparent

void wxWindowOS2::Update()
{
    ::WinUpdateWindow(GetHwnd());
} // end of wxWindowOS2::Update

void wxWindowOS2::DoFreeze()
{
   ::WinSendMsg(GetHwnd(), WM_VRNDISABLED, (MPARAM)0, (MPARAM)0);
} // end of wxWindowOS2::Freeze

void wxWindowOS2::DoThaw()
{
   ::WinSendMsg(GetHwnd(), WM_VRNENABLED, (MPARAM)TRUE, (MPARAM)0);

    //
    // We need to refresh everything or otherwise he invalidated area is not
    // repainted.
    //
    Refresh();
} // end of wxWindowOS2::Thaw

void wxWindowOS2::Refresh( bool bEraseBack,
                           const wxRect* pRect )
{
    HWND hWnd = GetHwnd();

    if (hWnd)
    {
        if (pRect)
        {
            RECTL vOs2Rect;
            int   height;

            ::WinQueryWindowRect(GetHwnd(), &vOs2Rect);
            height = vOs2Rect.yTop;
            vOs2Rect.xLeft   = pRect->x;
            vOs2Rect.yTop    = height - pRect->y;
            vOs2Rect.xRight  = pRect->x + pRect->width;
            vOs2Rect.yBottom = vOs2Rect.yTop - pRect->height;

            ::WinInvalidateRect(hWnd, &vOs2Rect, bEraseBack);
        }
        else
            ::WinInvalidateRect(hWnd, NULL, bEraseBack);
        if (m_hWndScrollBarHorz != NULLHANDLE)
            ::WinInvalidateRect(m_hWndScrollBarHorz, NULL, TRUE);
        if (m_hWndScrollBarVert != NULLHANDLE)
            ::WinInvalidateRect(m_hWndScrollBarVert, NULL, TRUE);
    }
} // end of wxWindowOS2::Refresh

// ---------------------------------------------------------------------------
// drag and drop
// ---------------------------------------------------------------------------

#if wxUSE_DRAG_AND_DROP
void wxWindowOS2::SetDropTarget(
  wxDropTarget*                     pDropTarget
)
{
    m_dropTarget = pDropTarget;
} // end of wxWindowOS2::SetDropTarget
#endif

//
// old style file-manager drag&drop support: we retain the old-style
// DragAcceptFiles in parallel with SetDropTarget.
//
void wxWindowOS2::DragAcceptFiles(
  bool                              bAccept
)
{
    HWND                            hWnd = GetHwnd();

    if (hWnd && bAccept)
        ::DrgAcceptDroppedFiles(hWnd, NULL, NULL, DO_COPY, 0L);
} // end of wxWindowOS2::DragAcceptFiles

// ----------------------------------------------------------------------------
// tooltips
// ----------------------------------------------------------------------------

#if wxUSE_TOOLTIPS

void wxWindowOS2::DoSetToolTip(
  wxToolTip*                        pTooltip
)
{
    wxWindowBase::DoSetToolTip(pTooltip);

    if (m_tooltip)
        m_tooltip->SetWindow(this);
} // end of wxWindowOS2::DoSetToolTip

#endif // wxUSE_TOOLTIPS

// ---------------------------------------------------------------------------
// moving and resizing
// ---------------------------------------------------------------------------

// Get total size
void wxWindowOS2::DoGetSize(
  int*                              pWidth
, int*                              pHeight
) const
{
    HWND                            hWnd;
    RECTL                           vRect;

    if (IsKindOf(CLASSINFO(wxFrame)))
    {
        wxFrame*                    pFrame = wxDynamicCast(this, wxFrame);
        hWnd = pFrame->GetFrame();
    }
    else
        hWnd = GetHwnd();

    ::WinQueryWindowRect(hWnd, &vRect);

    if (pWidth)
        *pWidth = vRect.xRight - vRect.xLeft;
    if (pHeight )
        // OS/2 PM is backwards from windows
        *pHeight = vRect.yTop - vRect.yBottom;
} // end of wxWindowOS2::DoGetSize

void wxWindowOS2::DoGetPosition(
  int*                              pX
, int*                              pY
) const
{
    //
    // Return parameters assume wxWidgets coordinate system
    //
    HWND                            hWnd;
    SWP                             vSwp;
    POINTL                          vPoint;
    wxWindow*                       pParent = GetParent();

    //
    // It would seem that WinQueryWindowRect would be the correlary to
    // the WIN32 WinGetRect, but unlike WinGetRect which returns the window
    // origin position in screen coordinates, WinQueryWindowRect returns it
    // relative to itself, i.e. (0,0).  To get the same under PM we must
    // use WinQueryWindowPos.  This call, unlike the WIN32 call, however,
    // returns a position relative to it's parent, so no parent adujstments
    // are needed under OS/2.  Also, windows should be created using
    // wxWindow coordinates, i.e 0,0 is the TOP left.
    //
    if (IsKindOf(CLASSINFO(wxFrame)))
    {
        wxFrame*                    pFrame = wxDynamicCast(this, wxFrame);
        hWnd = pFrame->GetFrame();
    }
    else
        hWnd = GetHwnd();

    ::WinQueryWindowPos(hWnd, &vSwp);

    vPoint.x = vSwp.x;
    vPoint.y = vSwp.y;

    // We need to convert to wxWidgets coordinates
    int vHeight;
    DoGetSize(NULL,&vHeight);
    wxWindow* pWindow = wxDynamicCast(this,wxWindow);
    vPoint.y = pWindow->GetOS2ParentHeight(pParent) - vPoint.y - vHeight;

    //
    // We may be faking the client origin. So a window that's really at (0,
    // 30) may appear (to wxWin apps) to be at (0, 0).
    //
    if (pParent)
    {
        wxPoint                     vPt(pParent->GetClientAreaOrigin());

        vPoint.x -= vPt.x;
        vPoint.y -= vPt.y;
    }

    if (pX)
        *pX = vPoint.x;
    if  (pY)
        *pY = vPoint.y;
} // end of wxWindowOS2::DoGetPosition

void wxWindowOS2::DoScreenToClient(
  int*                              pX
, int*                              pY
) const
{
    HWND                            hWnd = GetHwnd();
    SWP                             vSwp;

    ::WinQueryWindowPos(hWnd, &vSwp);

    if (pX)
        *pX += vSwp.x;
    if (pY)
        *pY += vSwp.y;
} // end of wxWindowOS2::DoScreenToClient

void wxWindowOS2::DoClientToScreen(
  int*                              pX
, int*                              pY
) const
{
    HWND                            hWnd = GetHwnd();
    SWP                             vSwp;

    ::WinQueryWindowPos(hWnd, &vSwp);

    if (pX)
        *pX += vSwp.x;
    if (pY)
        *pY += vSwp.y;
} // end of wxWindowOS2::DoClientToScreen

//
// Get size *available for subwindows* i.e. excluding menu bar etc.
// Must be a frame type window
//
void wxWindowOS2::DoGetClientSize(
  int*                              pWidth
, int*                              pHeight
) const
{
    HWND                            hWnd = GetHwnd();
    RECTL                           vRect;

   ::WinQueryWindowRect(hWnd, &vRect);
    if (IsKindOf(CLASSINFO(wxDialog)))
    {
        RECTL                       vTitle;
        HWND                        hWndTitle;
        //
        // For a Dialog we have to explicitly request the client portion.
        // For a Frame the hWnd IS the client window
        //
        hWndTitle = ::WinWindowFromID(hWnd, FID_TITLEBAR);
        if (::WinQueryWindowRect(hWndTitle, &vTitle))
        {
            if (vTitle.yTop - vTitle.yBottom == 0)
            {
                //
                // Dialog has not been created yet, use a default
                //
                vTitle.yTop = 20;
            }
            vRect.yTop -= (vTitle.yTop - vTitle.yBottom);
        }

        ULONG                       uStyle = ::WinQueryWindowULong(hWnd, QWL_STYLE);

        //
        // Deal with borders
        //
        if (uStyle & FCF_DLGBORDER)
        {
            vRect.xLeft += 4;
            vRect.xRight -= 4;
            vRect.yTop -= 4;
            vRect.yBottom += 4;
        }
        else if (uStyle & FCF_SIZEBORDER)
        {
            vRect.xLeft += 4;
            vRect.xRight -= 4;
            vRect.yTop -= 4;
            vRect.yBottom += 4;
        }
        else if (uStyle & FCF_BORDER)
        {
            vRect.xLeft += 2;
            vRect.xRight -= 2;
            vRect.yTop -= 2;
            vRect.yBottom += 2;
        }
        else // make some kind of adjustment or top sizers ram into the titlebar!
        {
            vRect.xLeft += 3;
            vRect.xRight -= 3;
            vRect.yTop -= 3;
            vRect.yBottom += 3;
        }
    }
    if (pWidth)
        *pWidth  = vRect.xRight - vRect.xLeft;
    if (pHeight)
        *pHeight = vRect.yTop - vRect.yBottom;
} // end of wxWindowOS2::DoGetClientSize

void wxWindowOS2::DoMoveWindow(
  int                               nX
, int                               nY
, int                               nWidth
, int                               nHeight
)
{
    //
    // Input parameters assume wxWidgets coordinate system
    //
    RECTL                           vRect;
    wxWindow*                       pParent = GetParent();
    HWND                            hWnd = GetHwnd();

    if (pParent && !IsKindOf(CLASSINFO(wxDialog)))
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

    //
    // In the case of a frame whose client is sized, the client cannot be
    // large than its parent frame minus its borders! This usually happens
    // when using an autosizer to size a frame to precisely hold client
    // controls as in the notebook sample.
    //
    // In this case, we may need to resize both a frame and its client so we
    // need a quick calc of the frame border size, then if the frame
    // (less its borders) is smaller than the client, size the frame to
    // encompass the client with the appropriate border size.
    //
    if (IsKindOf(CLASSINFO(wxFrame)))
    {
        RECTL                       vFRect;
        int                         nWidthFrameDelta = 0;
        int                         nHeightFrameDelta = 0;
        wxFrame*                    pFrame;

        pFrame = wxDynamicCast(this, wxFrame);
        hWnd = pFrame->GetFrame();
        ::WinQueryWindowRect(hWnd, &vRect);
        ::WinMapWindowPoints(hWnd, HWND_DESKTOP, (PPOINTL)&vRect, 2);
        vFRect = vRect;
        ::WinCalcFrameRect(hWnd, &vRect, TRUE);
        nWidthFrameDelta = ((vRect.xLeft - vFRect.xLeft) + (vFRect.xRight - vRect.xRight));
        nHeightFrameDelta = ((vRect.yBottom - vFRect.yBottom) + (vFRect.yTop - vRect.yTop));
        // Input values refer to the window position relative to its parent
        // which may be the Desktop so we need to calculate
        // the new frame values to keep the wxWidgets frame origin constant
        nY -= nHeightFrameDelta;
        nWidth += nWidthFrameDelta;
        nHeight += nHeightFrameDelta;
    }
    ::WinSetWindowPos( hWnd
                      ,HWND_TOP
                      ,(LONG)nX
                      ,(LONG)nY
                      ,(LONG)nWidth
                      ,(LONG)nHeight
                      ,SWP_SIZE | SWP_MOVE
                     );
    if (m_vWinSwp.cx == 0 && m_vWinSwp.cy == 0 && m_vWinSwp.fl == 0)
        //
        // Uninitialized
        //
        ::WinQueryWindowPos(hWnd, &m_vWinSwp);
    else
    {
        //
        // Handle resizing of scrolled windows.  The target or window to
        // be scrolled is the owner (gets the scroll notifications).  The
        // parent is usually the parent frame of the scrolled panel window.
        // In order to show the scrollbars the target window will be shrunk
        // by the size of the scroll bar widths and moved in the X and Y
        // directon.  That value will be computed as part of the diff for
        // moving the children.  Everytime the window is sized the
        // toplevel OnSize is going to resize the panel to fit the client
        // or the whole sizer and will need to me resized. This will send
        // a WM_SIZE out which will be intercepted by the ScrollHelper
        // which will cause the scrollbars to be displayed via the SetScrollbar
        // call in CWindow.
        //
        if (IsKindOf(CLASSINFO(wxScrolledWindow)))
        {
            int                     nAdjustWidth  = 0;
            int                     nAdjustHeight = 0;
            int nHSBHeight = wxSystemSettingsNative::GetMetric(wxSYS_HSCROLL_Y,
                                                               this);
            int nVSBWidth  = wxSystemSettingsNative::GetMetric(wxSYS_VSCROLL_X,
                                                               this);
            SWP                     vSwpScroll;

            if (GetScrollBarHorz() == NULLHANDLE ||
                !WinIsWindowShowing(GetScrollBarHorz()))
                nAdjustHeight = 0L;
            else
                nAdjustHeight = nHSBHeight;
            if (GetScrollBarVert() == NULLHANDLE ||
                !WinIsWindowShowing(GetScrollBarVert()))
                nAdjustWidth = 0L;
            else
                nAdjustWidth = nVSBWidth;
            ::WinQueryWindowPos(hWnd, &vSwpScroll);
            ::WinSetWindowPos( hWnd
                              ,HWND_TOP
                              ,vSwpScroll.x
                              ,vSwpScroll.y + nAdjustHeight
                              ,vSwpScroll.cx - nAdjustWidth
                              ,vSwpScroll.cy - nAdjustHeight
                              ,SWP_MOVE | SWP_SIZE
                             );
        }
        ::WinQueryWindowPos(hWnd, &m_vWinSwp);
    }
} // end of wxWindowOS2::DoMoveWindow

//
// Set the size of the window: if the dimensions are positive, just use them,
// but if any of them is equal to -1, it means that we must find the value for
// it ourselves (unless sizeFlags contains wxSIZE_ALLOW_MINUS_ONE flag, in
// which case -1 is a valid value for x and y)
//
// If sizeFlags contains wxSIZE_AUTO_WIDTH/HEIGHT flags (default), we calculate
// the width/height to best suit our contents, otherwise we reuse the current
// width/height
//
void wxWindowOS2::DoSetSize( int nX,
                             int nY,
                             int nWidth,
                             int nHeight,
                             int nSizeFlags )
{
    //
    // Input & output parameters assume wxWidgets coordinate system
    //

    //
    // Get the current size and position...
    //
    int    nCurrentX;
    int    nCurrentY;
    int    nCurrentWidth;
    int    nCurrentHeight;
    wxSize vSize = wxDefaultSize;

    GetPosition(&nCurrentX, &nCurrentY);
    GetSize(&nCurrentWidth, &nCurrentHeight);

    //
    // ... and don't do anything (avoiding flicker) if it's already ok
    //
    if (nX == nCurrentX && nY == nCurrentY &&
        nWidth == nCurrentWidth && nHeight == nCurrentHeight)
    {
        return;
    }

    if (nX == wxDefaultCoord && !(nSizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        nX = nCurrentX;
    if (nY == wxDefaultCoord && !(nSizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        nY = nCurrentY;

    AdjustForParentClientOrigin(nX, nY, nSizeFlags);

    if (nWidth == wxDefaultCoord)
    {
        if (nSizeFlags & wxSIZE_AUTO_WIDTH)
        {
            vSize  = DoGetBestSize();
            nWidth = vSize.x;
        }
        else
        {
            //
            // Just take the current one
            //
            nWidth = nCurrentWidth;
        }
    }

    if (nHeight == wxDefaultCoord)
    {
        if (nSizeFlags & wxSIZE_AUTO_HEIGHT)
        {
            if (vSize.x == wxDefaultCoord)
            {
                vSize = DoGetBestSize();
            }
            nHeight = vSize.y;
        }
        else
        {
            // just take the current one
            nHeight = nCurrentHeight;
        }
    }

    DoMoveWindow( nX, nY, nWidth, nHeight );
} // end of wxWindowOS2::DoSetSize

void wxWindowOS2::DoSetClientSize( int nWidth,
                                   int nHeight )
{
    //
    // nX & nY assume wxWidgets coordinate system
    //
    int nX;
    int nY;

    GetPosition(&nX, &nY);

    DoMoveWindow( nX, nY, nWidth, nHeight );

    wxSize size( nWidth, nHeight );
    wxSizeEvent vEvent( size, m_windowId );
    vEvent.SetEventObject(this);
    HandleWindowEvent(vEvent);
} // end of wxWindowOS2::DoSetClientSize

// ---------------------------------------------------------------------------
// text metrics
// ---------------------------------------------------------------------------

int wxWindowOS2::GetCharHeight() const
{
    HPS                             hPs;
    FONTMETRICS                     vFontMetrics;

    hPs = ::WinGetPS(GetHwnd());

    if(!GpiQueryFontMetrics(hPs, sizeof(FONTMETRICS), &vFontMetrics))
    {
        ::WinReleasePS(hPs);
        return (0);
    }
    ::WinReleasePS(hPs);
    return(vFontMetrics.lMaxAscender + vFontMetrics.lMaxDescender);
} // end of wxWindowOS2::GetCharHeight

int wxWindowOS2::GetCharWidth() const
{
    HPS                             hPs;
    FONTMETRICS                     vFontMetrics;

    hPs = ::WinGetPS(GetHwnd());

    if(!GpiQueryFontMetrics(hPs, sizeof(FONTMETRICS), &vFontMetrics))
    {
        ::WinReleasePS(hPs);
        return (0);
    }
    ::WinReleasePS(hPs);
    return(vFontMetrics.lAveCharWidth);
} // end of wxWindowOS2::GetCharWidth

void wxWindowOS2::DoGetTextExtent( const wxString& rString,
                                   int* pX,
                                   int* pY,
                                   int* pDescent,
                                   int* pExternalLeading,
                                   const wxFont* WXUNUSED(pTheFont) ) const
{
    POINTL      avPoint[TXTBOX_COUNT];
    POINTL      vPtMin;
    POINTL      vPtMax;
    int         i;
    int         l;
    FONTMETRICS vFM; // metrics structure
    BOOL        bRc = FALSE;
    HPS         hPS;

    hPS = ::WinGetPS(GetHwnd());

    l = rString.length();
    if (l > 0L)
    {
        //
        // In world coordinates.
        //
        bRc = ::GpiQueryTextBox( hPS,
                                 l,
                                 (char*) rString.wx_str(),
                                 TXTBOX_COUNT,// return maximum information
                                 avPoint      // array of coordinates points
                                );
        if (bRc)
        {
            vPtMin.x = avPoint[0].x;
            vPtMax.x = avPoint[0].x;
            vPtMin.y = avPoint[0].y;
            vPtMax.y = avPoint[0].y;
            for (i = 1; i < 4; i++)
            {
                if(vPtMin.x > avPoint[i].x) vPtMin.x = avPoint[i].x;
                if(vPtMin.y > avPoint[i].y) vPtMin.y = avPoint[i].y;
                if(vPtMax.x < avPoint[i].x) vPtMax.x = avPoint[i].x;
                if(vPtMax.y < avPoint[i].y) vPtMax.y = avPoint[i].y;
            }
            bRc = ::GpiQueryFontMetrics( hPS
                                        ,sizeof(FONTMETRICS)
                                        ,&vFM
                                       );
            if (!bRc)
            {
                vPtMin.x = 0;
                vPtMin.y = 0;
                vPtMax.x = 0;
                vPtMax.y = 0;
            }
        }
        else
        {
            vPtMin.x = 0;
            vPtMin.y = 0;
            vPtMax.x = 0;
            vPtMax.y = 0;
        }
    }
    else
    {
        vPtMin.x = 0;
        vPtMin.y = 0;
        vPtMax.x = 0;
        vPtMax.y = 0;
    }
    if (pX)
        *pX = (vPtMax.x - vPtMin.x + 1);
    if (pY)
        *pY = (vPtMax.y - vPtMin.y + 1);
    if (pDescent)
    {
        if (bRc)
            *pDescent = vFM.lMaxDescender;
        else
            *pDescent = 0;
    }
    if (pExternalLeading)
    {
        if (bRc)
            *pExternalLeading = vFM.lExternalLeading;
        else
            *pExternalLeading = 0;
    }
    ::WinReleasePS(hPS);
} // end of wxWindow::DoGetTextExtent

bool wxWindowOS2::IsMouseInWindow() const
{
    //
    // Get the mouse position
    POINTL vPt;

    ::WinQueryPointerPos(HWND_DESKTOP, &vPt);

    //
    // Find the window which currently has the cursor and go up the window
    // chain until we find this window - or exhaust it
    //
    HWND hWnd = ::WinWindowFromPoint(HWND_DESKTOP, &vPt, TRUE);

    while (hWnd && (hWnd != GetHwnd()))
        hWnd = ::WinQueryWindow(hWnd, QW_PARENT);

    return hWnd != NULL;
} // end of wxWindowOS2::IsMouseInWindow


// ---------------------------------------------------------------------------
// popup menu
// ---------------------------------------------------------------------------
//
#if wxUSE_MENUS_NATIVE
bool wxWindowOS2::DoPopupMenu( wxMenu* pMenu, int nX, int nY )
{
    HWND hWndOwner = GetHwnd();
    HWND hWndParent = GetHwnd();
    HWND hMenu = GetHmenuOf(pMenu);
    bool bIsWaiting = true;
    int nHeight;

    pMenu->UpdateUI();

    if ( nX == -1 && nY == -1 )
    {
        wxPoint mouse = wxGetMousePosition();
        nX = mouse.x; nY = mouse.y;
    }
    else
    {
        DoClientToScreen( &nX
                         ,&nY
                        );
        DoGetSize(0,&nHeight);
        nY = nHeight - nY;
    }

    ::WinPopupMenu( hWndParent
                   ,hWndOwner
                   ,hMenu
                   ,nX
                   ,nY
                   ,0L
                   ,PU_HCONSTRAIN | PU_VCONSTRAIN | PU_MOUSEBUTTON1 | PU_KEYBOARD
                  );

    while(bIsWaiting)
    {
        QMSG                            vMsg;

        ::WinGetMsg(vHabmain,&vMsg, (HWND)0, 0, 0);
        if (vMsg.msg == WM_COMMAND)
            bIsWaiting = false;
        ::WinDispatchMsg(vHabmain, (PQMSG)&vMsg);
    }

    return true;
} // end of wxWindowOS2::DoPopupMenu
#endif // wxUSE_MENUS_NATIVE

// ===========================================================================
// pre/post message processing
// ===========================================================================

MRESULT wxWindowOS2::OS2DefWindowProc( WXUINT uMsg,
                                       WXWPARAM wParam,
                                       WXLPARAM lParam )
{
    if (m_fnOldWndProc)
        return (MRESULT)m_fnOldWndProc(GetHWND(), uMsg, (MPARAM)wParam, (MPARAM)lParam);
    else
        return ::WinDefWindowProc(GetHWND(), uMsg, (MPARAM)wParam, (MPARAM)lParam);
} // end of wxWindowOS2::OS2DefWindowProc

bool wxWindowOS2::OS2ProcessMessage( WXMSG* pMsg )
{
// wxUniversal implements tab traversal itself
#ifndef __WXUNIVERSAL__
    QMSG*                           pQMsg = (QMSG*)pMsg;

    if (m_hWnd != 0 && (GetWindowStyleFlag() & wxTAB_TRAVERSAL))
    {
        //
        // Intercept dialog navigation keys
        //
        bool   bProcess = true;
        USHORT uKeyFlags = SHORT1FROMMP(pQMsg->mp1);

        if (uKeyFlags & KC_KEYUP)
            bProcess = false;

        if (uKeyFlags & KC_ALT)
            bProcess = false;

        if (!(uKeyFlags & KC_VIRTUALKEY))
            bProcess = false;

        if (bProcess)
        {
            bool                    bCtrlDown = IsCtrlDown();
            bool                    bShiftDown = IsShiftDown();

            //
            // WM_QUERYDLGCODE: ask the control if it wants the key for itself,
            // don't process it if it's the case (except for Ctrl-Tab/Enter
            // combinations which are always processed)
            //
            ULONG                   ulDlgCode = 0;

            if (!bCtrlDown)
            {
                ulDlgCode = (ULONG)::WinSendMsg(pQMsg->hwnd, WM_QUERYDLGCODE, pQMsg, 0);
            }

            bool bForward = true;
            bool bWindowChange = false;

            switch (SHORT2FROMMP(pQMsg->mp2))
            {
                //
                // Going to make certain assumptions about specific types of controls
                // here, so we may have to alter some things later if they prove invalid
                //
                case VK_TAB:
                    //
                    // Shift tabl will always be a nav-key but tabs may be wanted
                    //
                    if (!bShiftDown)
                    {
                        bProcess = false;
                    }
                    else
                    {
                        //
                        // Entry Fields want tabs for themselve usually
                        //
                        switch (ulDlgCode)
                        {
                            case DLGC_ENTRYFIELD:
                            case DLGC_MLE:
                                bProcess = true;
                                break;

                            default:
                                bProcess = false;
                        }

                        //
                        // Ctrl-Tab cycles thru notebook pages
                        //
                        bWindowChange = bCtrlDown;
                        bForward = !bShiftDown;
                    }
                    break;

                case VK_UP:
                case VK_LEFT:
                    if (bCtrlDown)
                        bProcess = false;
                    else
                        bForward = false;
                    break;

                case VK_DOWN:
                case VK_RIGHT:
                    if (bCtrlDown)
                        bProcess = false;
                    break;

                case VK_ENTER:
                    {
                        if (bCtrlDown)
                        {
                            //
                            // ctrl-enter is not processed
                            //
                            return false;
                        }
                        else if (ulDlgCode & DLGC_BUTTON)
                        {
                            //
                            // buttons want process Enter themselevs
                            //
                            bProcess = false;
                        }
                        else
                        {
                            wxTopLevelWindow *tlw = wxDynamicCast(wxGetTopLevelParent(this), wxTopLevelWindow);
                            wxButton*   pBtn = NULL;

                            if (tlw)
                            {
                                pBtn = wxDynamicCast(tlw->GetDefaultItem(), wxButton);
                            }

                            if (pBtn && pBtn->IsEnabled())
                            {
                                //
                                // If we do have a default button, do press it
                                //
                                pBtn->OS2Command(BN_CLICKED, 0 /* unused */);
                                return true;
                            }
                            else if (!IsTopLevel())
                            {
                                //
                                // if not a top level window, let parent
                                // handle it
                                //
                                return false;
                            }
                            // else: but if it does not it makes sense to make
                            //       it work like a TAB - and that's what we do.
                            //       Note that Ctrl-Enter always works this way.
                        }
                    }
                    break;

                default:
                    bProcess = false;
            }

            if (bProcess)
            {
                wxNavigationKeyEvent    vEvent;

                vEvent.SetDirection(bForward);
                vEvent.SetWindowChange(bWindowChange);
                vEvent.SetEventObject(this);

                if (HandleWindowEvent(vEvent))
                {
                    wxButton*       pBtn = wxDynamicCast(FindFocus(), wxButton);

                    if (pBtn)
                    {
                        //
                        // The button which has focus should be default
                        //
                        pBtn->SetDefault();
                    }
                    return true;
                }
            }
        }
        //
        // Let Dialogs process
        //
        if (::WinSendMsg(pQMsg->hwnd, WM_QUERYDLGCODE, pQMsg, 0));
            return true;
    }
#else
    pMsg = pMsg; // just shut up the compiler
#endif // __WXUNIVERSAL__

    return false;
} // end of wxWindowOS2::OS2ProcessMessage

bool wxWindowOS2::OS2TranslateMessage( WXMSG* pMsg )
{
#if wxUSE_ACCEL && !defined(__WXUNIVERSAL__)
    return m_acceleratorTable.Translate(m_hWnd, pMsg);
#else
    pMsg = pMsg;
    return false;
#endif //wxUSE_ACCEL
} // end of wxWindowOS2::OS2TranslateMessage

bool wxWindowOS2::OS2ShouldPreProcessMessage( WXMSG* WXUNUSED(pMsg) )
{
    // preprocess all messages by default
    return true;
} // end of wxWindowOS2::OS2ShouldPreProcessMessage

// ---------------------------------------------------------------------------
// message params unpackers
// ---------------------------------------------------------------------------

void wxWindowOS2::UnpackCommand(
  WXWPARAM                          wParam
, WXLPARAM                          lParam
, WORD*                             pId
, WXHWND*                           phWnd
, WORD*                             pCmd
)
{
    *pId = LOWORD(wParam);
    *phWnd = NULL;  // or may be GetHWND() ?
    *pCmd = LOWORD(lParam);
} // end of wxWindowOS2::UnpackCommand

void wxWindowOS2::UnpackActivate(
  WXWPARAM                          wParam
, WXLPARAM                          lParam
, WXWORD*                           pState
, WXHWND*                           phWnd
)
{
    *pState     = LOWORD(wParam);
    *phWnd      = (WXHWND)lParam;
} // end of wxWindowOS2::UnpackActivate

void wxWindowOS2::UnpackScroll(
  WXWPARAM                          wParam
, WXLPARAM                          lParam
, WXWORD*                           pCode
, WXWORD*                           pPos
, WXHWND*                           phWnd
)
{
    ULONG                           ulId;
    HWND                            hWnd;

    ulId    = (ULONG)LONGFROMMP(wParam);
    hWnd = ::WinWindowFromID(GetHwnd(), ulId);
    if (hWnd == m_hWndScrollBarHorz || hWnd == m_hWndScrollBarVert)
        *phWnd = NULLHANDLE;
    else
        *phWnd = hWnd;

    *pPos  = SHORT1FROMMP(lParam);
    *pCode = SHORT2FROMMP(lParam);
} // end of wxWindowOS2::UnpackScroll

void wxWindowOS2::UnpackMenuSelect(
  WXWPARAM                          wParam
, WXLPARAM                          lParam
, WXWORD*                           pItem
, WXWORD*                           pFlags
, WXHMENU*                          phMenu
)
{
    *pItem = (WXWORD)LOWORD(wParam);
    *pFlags = HIWORD(wParam);
    *phMenu = (WXHMENU)lParam;
} // end of wxWindowOS2::UnpackMenuSelect

// ---------------------------------------------------------------------------
// Main wxWidgets window proc and the window proc for wxWindow
// ---------------------------------------------------------------------------

//
// Hook for new window just as it's being created, when the window isn't yet
// associated with the handle
//
wxWindowOS2*                         wxWndHook = NULL;

//
// Main window proc
//
MRESULT EXPENTRY wxWndProc(
  HWND                              hWnd
, ULONG                             ulMsg
, MPARAM                            wParam
, MPARAM                            lParam
)
{
    wxWindowOS2*                    pWnd = wxFindWinFromHandle((WXHWND)hWnd);

    //
    // When we get the first message for the HWND we just created, we associate
    // it with wxWindow stored in wxWndHook
    //
    if (!pWnd && wxWndHook)
    {
        wxAssociateWinWithHandle(hWnd, wxWndHook);
        pWnd = wxWndHook;
        wxWndHook = NULL;
        pWnd->SetHWND((WXHWND)hWnd);
    }

    MRESULT                         rc = (MRESULT)0;


    //
    // Stop right here if we don't have a valid handle in our wxWindow object.
    //
    if (pWnd && !pWnd->GetHWND())
    {
        pWnd->SetHWND((WXHWND) hWnd);
        rc = pWnd->OS2DefWindowProc(ulMsg, wParam, lParam );
        pWnd->SetHWND(0);
    }
    else
    {
        if (pWnd)
        {
            rc = pWnd->OS2WindowProc(ulMsg, wParam, lParam);
            if ( (pWnd->GetScrollBarHorz() != NULLHANDLE ||
                  pWnd->GetScrollBarVert() != NULLHANDLE) &&
                  ulMsg == WM_PAINT)
            {
                if (pWnd->GetScrollBarHorz() != NULLHANDLE)
                    ::WinInvalidateRect(pWnd->GetScrollBarHorz(), NULL, TRUE);
                if (pWnd->GetScrollBarVert() != NULLHANDLE)
                    ::WinInvalidateRect(pWnd->GetScrollBarVert(), NULL, TRUE);
            }
        }
        else
            rc = ::WinDefWindowProc(hWnd, ulMsg, wParam, lParam);
    }

    return rc;
} // end of wxWndProc

//
// We will add (or delete) messages we need to handle at this default
// level as we go
//
MRESULT wxWindowOS2::OS2WindowProc( WXUINT uMsg,
                                    WXWPARAM wParam,
                                    WXLPARAM lParam )
{
    //
    // Did we process the uMsg?
    //
    bool bProcessed = false;
    MRESULT mResult;

    //
    // For most messages we should return 0 when we do process the message
    //
    mResult = (MRESULT)0;

    switch (uMsg)
    {
        case WM_CREATE:
            {
                bool                bMayCreate;

                bProcessed = HandleCreate( (WXLPCREATESTRUCT)lParam
                                          ,&bMayCreate
                                         );
                if (bProcessed)
                {
                    //
                    // Return 0 to bAllow window creation
                    //
                    mResult = (MRESULT)(bMayCreate ? 0 : -1);
                }
            }
            break;

        case WM_DESTROY:
             HandleDestroy();
             bProcessed = true;
             break;

        case WM_MOVE:
            bProcessed = HandleMove( LOWORD(lParam)
                                    ,HIWORD(lParam)
                                   );
            break;

        case WM_SIZE:
            bProcessed = HandleSize( LOWORD(lParam)
                                    ,HIWORD(lParam)
                                    ,(WXUINT)wParam
                                   );
            break;

        case WM_WINDOWPOSCHANGED:

            //
            // Dialogs under OS/2 do not get WM_SIZE events at all.
            // Instead they get this, which can function much like WM_SIZE
            // PSWP contains the new sizes and positioning, PSWP+1 the old
            // We use this because ADJUSTWINDOWPOS comes BEFORE the new
            // position is added and our auto layout does a WinQueryWindowRect
            // to get the CURRENT client size.  That is the size used to position
            // child controls, so we need to already be sized
            // in order to get the child controls positoned properly.
            //
            if (IsKindOf(CLASSINFO(wxDialog)) || IsKindOf(CLASSINFO(wxFrame)))
            {
                PSWP                pSwp = (PSWP)PVOIDFROMMP(wParam);
                PSWP                pSwp2 = pSwp++;

                if (!(pSwp->cx == pSwp2->cx &&
                      pSwp->cy == pSwp2->cy))
                    bProcessed = HandleSize( pSwp->cx
                                            ,pSwp->cy
                                            ,(WXUINT)lParam
                                           );
                if (IsKindOf(CLASSINFO(wxFrame)))
                {
                    wxFrame*            pFrame = wxDynamicCast(this, wxFrame);

                    if (pFrame)
                    {
                        if (pFrame->GetStatusBar())
                            pFrame->PositionStatusBar();
                        if (pFrame->GetToolBar())
                            pFrame->PositionToolBar();
                    }
                }
            }
            break;

        case WM_ACTIVATE:
            {
                WXWORD              wState;
                WXHWND              hWnd;

                UnpackActivate( wParam
                               ,lParam
                               ,&wState
                               ,&hWnd
                              );

                bProcessed = HandleActivate( wState
                                            ,(WXHWND)hWnd
                                           );
                bProcessed = false;
            }
            break;

        case WM_SETFOCUS:
            if (SHORT1FROMMP((MPARAM)lParam) == TRUE)
                bProcessed = HandleSetFocus((WXHWND)(HWND)wParam);
            else
                bProcessed = HandleKillFocus((WXHWND)(HWND)wParam);
            break;

        case WM_PAINT:
            bProcessed = HandlePaint();
            break;

        case WM_CLOSE:
            //
            // Don't let the DefWindowProc() destroy our window - we'll do it
            // ourselves in ~wxWindow
            //
            bProcessed = true;
            mResult = (MRESULT)TRUE;
            break;

        case WM_SHOW:
            bProcessed = HandleShow(wParam != 0, (int)lParam);
            break;

        //
        // Under OS2 PM Joysticks are treated just like mouse events
        // The "Motion" events will be prevelent in joysticks
        //
        case WM_MOUSEMOVE:
        case WM_BUTTON1DOWN:
        case WM_BUTTON1UP:
        case WM_BUTTON1DBLCLK:
        case WM_BUTTON1MOTIONEND:
        case WM_BUTTON1MOTIONSTART:
        case WM_BUTTON2DOWN:
        case WM_BUTTON2UP:
        case WM_BUTTON2DBLCLK:
        case WM_BUTTON2MOTIONEND:
        case WM_BUTTON2MOTIONSTART:
        case WM_BUTTON3DOWN:
        case WM_BUTTON3UP:
        case WM_BUTTON3DBLCLK:
        case WM_BUTTON3MOTIONEND:
        case WM_BUTTON3MOTIONSTART:
            {
                short               nX = LOWORD(wParam);
                short               nY = HIWORD(wParam);

                //
                // Redirect the event to a static control if necessary
                //
                if (this == GetCapture())
                {
                    bProcessed = HandleMouseEvent( uMsg
                                                  ,nX
                                                  ,nY
                                                  ,(WXUINT)SHORT2FROMMP(lParam)
                                                 );
                }
                else
                {
                    wxWindow*       pWin = FindWindowForMouseEvent( this
                                                                   ,&nX
                                                                   ,&nY
                                                                  );
                    if (!pWin->IsOfStandardClass())
                    {
                        if (uMsg == WM_BUTTON1DOWN && pWin->CanAcceptFocus() )
                            pWin->SetFocus();
                    }
                    bProcessed = pWin->HandleMouseEvent( uMsg
                                                        ,nX
                                                        ,nY
                                                        ,(WXUINT)SHORT2FROMMP(lParam)
                                                       );
                }
            }
            break;

        case WM_SYSCOMMAND:
            bProcessed = HandleSysCommand(wParam, lParam);
            break;

        case WM_COMMAND:
            {
                WORD id, cmd;
                WXHWND hwnd;
                UnpackCommand(wParam, lParam, &id, &hwnd, &cmd);

                bProcessed = HandleCommand(id, cmd, hwnd);
            }
            break;

            //
            // For these messages we must return TRUE if process the message
            //
        case WM_DRAWITEM:
        case WM_MEASUREITEM:
            {
                int                 nIdCtrl = (UINT)wParam;

                if ( uMsg == WM_DRAWITEM )
                {
                    bProcessed = OS2OnDrawItem(nIdCtrl,
                                              (WXDRAWITEMSTRUCT *)lParam);
                }
                else
                {
                    return MRFROMLONG(OS2OnMeasureItem( nIdCtrl
                                                       ,(WXMEASUREITEMSTRUCT *)lParam
                                                      ));
                }

                if ( bProcessed )
                    mResult = (MRESULT)TRUE;
            }
            break;

        case WM_QUERYDLGCODE:
            if (!IsOfStandardClass())
            {
                if ( m_lDlgCode )
                {
                    mResult = (MRESULT)m_lDlgCode;
                    bProcessed = true;
                }
            }
            //
            //else: get the dlg code from the DefWindowProc()
            //
            break;

        //
        // In OS/2 PM all keyboard events are of the WM_CHAR type.  Virtual key and key-up
        // and key-down events are obtained from the WM_CHAR params.
        //
        case WM_CHAR:
            {
                USHORT                  uKeyFlags = SHORT1FROMMP((MPARAM)wParam);

                if (uKeyFlags & KC_KEYUP)
                {
                    //TODO: check if the cast to WXWORD isn't causing trouble
                    bProcessed = HandleKeyUp(wParam, lParam);
                    break;
                }
                else // keydown event
                {
                    m_bLastKeydownProcessed = false;
                    //
                    // If this has been processed by an event handler,
                    // return 0 now (we've handled it). DON't RETURN
                    // we still need to process further
                    //
                    m_bLastKeydownProcessed = HandleKeyDown(wParam, lParam);
                    if (uKeyFlags & KC_VIRTUALKEY)
                    {
                        USHORT          uVk = SHORT2FROMMP((MPARAM)lParam);

                        //
                        // We consider these message "not interesting" to OnChar
                        //
                        switch(uVk)
                        {
                            case VK_SHIFT:
                            case VK_CTRL:
                            case VK_MENU:
                            case VK_CAPSLOCK:
                            case VK_NUMLOCK:
                            case VK_SCRLLOCK:
                                bProcessed = true;
                                break;

                            // Avoid duplicate messages to OnChar for these ASCII keys: they
                            // will be translated by TranslateMessage() and received in WM_CHAR
                            case VK_ESC:
                            case VK_ENTER:
                            case VK_BACKSPACE:
                            case VK_TAB:
                                // But set processed to false, not true to still pass them to
                                // the control's default window proc - otherwise built-in
                                // keyboard handling won't work
                                bProcessed = false;
                                break;

                            default:
                                bProcessed = HandleChar(wParam, lParam);
                         }
                         break;
                    }
                    else // WM_CHAR -- Always an ASCII character
                    {
                        if (m_bLastKeydownProcessed)
                        {
                            //
                            // The key was handled in the EVT_KEY_DOWN and handling
                            // a key in an EVT_KEY_DOWN handler is meant, by
                            // design, to prevent EVT_CHARs from happening
                            //
                            m_bLastKeydownProcessed = false;
                            bProcessed = true;
                        }
                        else // do generate a CHAR event
                        {
                            bProcessed = HandleChar(wParam, lParam, true);
                            break;
                        }
                    }
                }
            }

        case WM_HSCROLL:
        case WM_VSCROLL:
            {
                WXWORD              wCode;
                WXWORD              wPos;
                WXHWND              hWnd;
                UnpackScroll( wParam
                             ,lParam
                             ,&wCode
                             ,&wPos
                             ,&hWnd
                            );

                bProcessed = OS2OnScroll( uMsg == WM_HSCROLL ? wxHORIZONTAL
                                                             : wxVERTICAL
                                         ,wCode
                                         ,wPos
                                         ,hWnd
                                        );
            }
            break;

        case WM_CONTROL:
            switch(SHORT2FROMMP(wParam))
            {
                case BN_PAINT:
                    {
                        HWND                hWnd = ::WinWindowFromID((HWND)GetHwnd(), SHORT1FROMMP(wParam));
                        wxWindowOS2*        pWin = wxFindWinFromHandle(hWnd);

                        if (!pWin)
                        {
                            bProcessed = false;
                            break;
                        }
                        if (pWin->IsKindOf(CLASSINFO(wxBitmapButton)))
                        {
                            wxBitmapButton*     pBitmapButton = wxDynamicCast(pWin, wxBitmapButton);

                            pBitmapButton->OS2OnDraw((WXDRAWITEMSTRUCT *)lParam);
                        }
                        return 0;
                    }
                    // break;

                case BKN_PAGESELECTEDPENDING:
                    {
                        PPAGESELECTNOTIFY  pPage = (PPAGESELECTNOTIFY)lParam;

                        if ((pPage->ulPageIdNew != pPage->ulPageIdCur) &&
                            (pPage->ulPageIdNew > 0L && pPage->ulPageIdCur > 0L))
                        {
                            wxWindowOS2*        pWin = wxFindWinFromHandle(pPage->hwndBook);
                            wxBookCtrlEvent     vEvent( wxEVT_COMMAND_NOTEBOOK_PAGE_CHANGED
                                                       ,(int)SHORT1FROMMP(wParam)
                                                       ,(int)pPage->ulPageIdNew
                                                       ,(int)pPage->ulPageIdCur
                                                      );
                            if (!pWin)
                            {
                                bProcessed = false;
                                break;
                            }
                            if (pWin->IsKindOf(CLASSINFO(wxNotebook)))
                            {
                                wxNotebook*         pNotebook = wxDynamicCast(pWin, wxNotebook);

                                vEvent.SetEventObject(pWin);
                                pNotebook->OnSelChange(vEvent);
                                bProcessed = true;
                            }
                            else
                                bProcessed = false;
                        }
                        else
                            bProcessed = false;
                    }
                    break;

                case CBN_LBSELECT:
                case BN_CLICKED: // Dups as LN_SELECT and CBN_LBSELECT
                    {
                        HWND                hWnd = ::WinWindowFromID((HWND)GetHwnd(), SHORT1FROMMP(wParam));
                        wxWindowOS2*        pWin = wxFindWinFromHandle(hWnd);

                        if (!pWin)
                        {
                            bProcessed = false;
                            break;
                        }
                        //
                        // Simulate a WM_COMMAND here, as wxWidgets expects all control
                        // button clicks to generate WM_COMMAND msgs, not WM_CONTROL
                        //
                        if (pWin->IsKindOf(CLASSINFO(wxRadioBox)))
                        {
                            wxRadioBox*         pRadioBox = wxDynamicCast(pWin, wxRadioBox);

                            pRadioBox->OS2Command( (WXUINT)SHORT2FROMMP(wParam)
                                                  ,(WXWORD)SHORT1FROMMP(wParam)
                                                 );
                        }
                        if (pWin->IsKindOf(CLASSINFO(wxRadioButton)))
                        {
                            wxRadioButton*      pRadioButton = wxDynamicCast(pWin, wxRadioButton);

                            pRadioButton->OS2Command( (WXUINT)SHORT2FROMMP(wParam)
                                                     ,(WXWORD)SHORT1FROMMP(wParam)
                                                    );
                        }
                        if (pWin->IsKindOf(CLASSINFO(wxCheckBox)))
                        {
                            wxCheckBox*         pCheckBox = wxDynamicCast(pWin, wxCheckBox);

                            pCheckBox->OS2Command( (WXUINT)SHORT2FROMMP(wParam)
                                                  ,(WXWORD)SHORT1FROMMP(wParam)
                                                 );
                        }
                        if (pWin->IsKindOf(CLASSINFO(wxListBox)))
                        {
                            wxListBox*          pListBox = wxDynamicCast(pWin, wxListBox);

                            pListBox->OS2Command( (WXUINT)SHORT2FROMMP(wParam)
                                                 ,(WXWORD)SHORT1FROMMP(wParam)
                                                );
                            if (pListBox->GetWindowStyle() & wxLB_OWNERDRAW)
                                Refresh();
                        }
                        if (pWin->IsKindOf(CLASSINFO(wxComboBox)))
                        {
                            wxComboBox*          pComboBox = wxDynamicCast(pWin, wxComboBox);

                            pComboBox->OS2Command( (WXUINT)SHORT2FROMMP(wParam)
                                                  ,(WXWORD)SHORT1FROMMP(wParam)
                                                 );
                        }
                        if (pWin->IsKindOf(CLASSINFO(wxChoice)))
                        {
                            wxChoice*           pChoice = wxDynamicCast(pWin, wxChoice);

                            pChoice->OS2Command( (WXUINT)SHORT2FROMMP(wParam)
                                                ,(WXWORD)SHORT1FROMMP(wParam)
                                               );
                        }
                        return 0;
                    }
                    // break;

                case LN_ENTER:
                    {
                        HWND                hWnd = HWNDFROMMP(lParam);
                        wxWindowOS2*        pWin = wxFindWinFromHandle(hWnd);

                        if (!pWin)
                        {
                            bProcessed = false;
                            break;
                        }
                        //
                        // Simulate a WM_COMMAND here, as wxWidgets expects all control
                        // button clicks to generate WM_COMMAND msgs, not WM_CONTROL
                        //
                        if (pWin->IsKindOf(CLASSINFO(wxListBox)))
                        {
                            wxListBox*          pListBox = wxDynamicCast(pWin, wxListBox);

                            pListBox->OS2Command( (WXUINT)SHORT2FROMMP(wParam)
                                                 ,(WXWORD)SHORT1FROMMP(wParam)
                                                );
                            if (pListBox->GetWindowStyle() & wxLB_OWNERDRAW)
                                Refresh();

                        }
                        if (pWin->IsKindOf(CLASSINFO(wxComboBox)))
                        {
                            wxComboBox*          pComboBox = wxDynamicCast(pWin, wxComboBox);

                            pComboBox->OS2Command( (WXUINT)SHORT2FROMMP(wParam)
                                                  ,(WXWORD)SHORT1FROMMP(wParam)
                                                 );
                        }
                        return 0;
                    }
                    // break;

                case SPBN_UPARROW:
                case SPBN_DOWNARROW:
                case SPBN_CHANGE:
                    {
                        char zVal[10];
                        long lVal;

                        ::WinSendMsg( HWNDFROMMP(lParam)
                                     ,SPBM_QUERYVALUE
                                     ,&zVal[0]
                                     ,MPFROM2SHORT( (USHORT)10
                                                   ,(USHORT)SPBQ_UPDATEIFVALID
                                                  )
                                    );
                        lVal = atol(zVal);
                        bProcessed = OS2OnScroll( wxVERTICAL
                                                 ,(WXWORD)SHORT2FROMMP(wParam)
                                                 ,(WXWORD)lVal
                                                 ,HWNDFROMMP(lParam)
                                                );
                    }
                    break;

                case SLN_SLIDERTRACK:
                    {
                        HWND         hWnd = ::WinWindowFromID(GetHWND(), SHORT1FROMMP(wParam));
                        wxWindowOS2* pChild = wxFindWinFromHandle(hWnd);

                        if (!pChild)
                        {
                            bProcessed = false;
                            break;
                        }
                        if (pChild->IsKindOf(CLASSINFO(wxSlider)))
                            bProcessed = OS2OnScroll( wxVERTICAL
                                                     ,(WXWORD)SHORT2FROMMP(wParam)
                                                     ,(WXWORD)LONGFROMMP(lParam)
                                                     ,hWnd
                                                    );
                    }
                    break;
            }
            break;

#if defined(__VISAGECPP__) && (__IBMCPP__ >= 400)
        case WM_CTLCOLORCHANGE:
            {
                bProcessed = HandleCtlColor(&hBrush);
            }
            break;
#endif
        case WM_ERASEBACKGROUND:
            //
            // Returning TRUE to requestw PM to paint the window background
            // in SYSCLR_WINDOW. We don't really want that
            //
            bProcessed = HandleEraseBkgnd((WXHDC)(HPS)wParam);
            mResult = (MRESULT)(FALSE);
            break;

            // the return value for this message is ignored
        case WM_SYSCOLORCHANGE:
            bProcessed = HandleSysColorChange();
            break;

        case WM_REALIZEPALETTE:
            bProcessed = HandlePaletteChanged();
            break;

        // move all drag and drops to wxDrg
        case WM_ENDDRAG:
            bProcessed = HandleEndDrag(wParam);
            break;

        case WM_INITDLG:
            bProcessed = HandleInitDialog((WXHWND)(HWND)wParam);

            if ( bProcessed )
            {
                // we never set focus from here
                mResult = (MRESULT)FALSE;
            }
            break;

        // wxFrame specific message
        case WM_MINMAXFRAME:
            bProcessed = HandleGetMinMaxInfo((PSWP)wParam);
            break;

        case WM_SYSVALUECHANGED:
            // TODO: do something
            mResult = (MRESULT)TRUE;
            break;

        //
        // Comparable to WM_SETPOINTER for windows, only for just controls
        //
        case WM_CONTROLPOINTER:
            bProcessed = HandleSetCursor( SHORT1FROMMP(wParam) // Control ID
                                         ,(HWND)lParam         // Cursor Handle
                                        );
            if (bProcessed )
            {
                //
                // Returning TRUE stops the DefWindowProc() from further
                // processing this message - exactly what we need because we've
                // just set the cursor.
                //
                mResult = (MRESULT)TRUE;
            }
            break;

#if wxUSE_MENUS_NATIVE
         case WM_MENUEND:
            if (wxCurrentPopupMenu)
            {
                if (GetHmenuOf(wxCurrentPopupMenu) == (HWND)lParam)
                {
                    // Break out of msg loop in DoPopupMenu
                    ::WinPostMsg((HWND)lParam,WM_COMMAND,wParam,0);
                }
            }
            break;
#endif // wxUSE_MENUS_NATIVE

    }
    if (!bProcessed)
    {
#ifdef __WXDEBUG__
        wxLogTrace(wxTraceMessages, wxT("Forwarding %s to DefWindowProc."),
                   wxGetMessageName(uMsg));
#endif // __WXDEBUG__
        if (IsKindOf(CLASSINFO(wxFrame)))
            mResult = ::WinDefWindowProc(m_hWnd, uMsg, wParam, lParam);
        else if (IsKindOf(CLASSINFO(wxDialog)))
            mResult = ::WinDefDlgProc( m_hWnd, uMsg, wParam, lParam);
        else
            mResult = OS2DefWindowProc(uMsg, wParam, lParam);
    }
    return mResult;
} // end of wxWindowOS2::OS2WindowProc

// ----------------------------------------------------------------------------
// wxWindow <-> HWND map
// ----------------------------------------------------------------------------

wxWinHashTable *wxWinHandleHash = NULL;

wxWindow* wxFindWinFromHandle(
  WXHWND                            hWnd
)
{
    return (wxWindow *)wxWinHandleHash->Get((long)hWnd);
} // end of wxFindWinFromHandle

void wxAssociateWinWithHandle(
  HWND                              hWnd
, wxWindowOS2*                      pWin
)
{
    //
    // Adding NULL hWnd is (first) surely a result of an error and
    // (secondly) breaks menu command processing
    //
    wxCHECK_RET( hWnd != (HWND)NULL,
                 wxT("attempt to add a NULL hWnd to window list ignored") );

    wxWindow*                       pOldWin = wxFindWinFromHandle((WXHWND) hWnd);

    if (pOldWin && (pOldWin != pWin))
    {
        wxString  Newstr(pWin->GetClassInfo()->GetClassName());
        wxString Oldstr(pOldWin->GetClassInfo()->GetClassName());
        wxLogError( wxT("Bug! New window of class %s has same HWND %X as old window of class %s"),
                    Newstr.c_str(),
                    (int)hWnd,
                    Oldstr.c_str()
                  );
    }
    else if (!pOldWin)
    {
        wxWinHandleHash->Put( (long)hWnd
                             ,(wxWindow *)pWin
                            );
    }
} // end of wxAssociateWinWithHandle

void wxRemoveHandleAssociation( wxWindowOS2* pWin )
{
    wxWinHandleHash->Delete((long)pWin->GetHWND());
} // end of wxRemoveHandleAssociation

//
// Default destroyer - override if you destroy it in some other way
// (e.g. with MDI child windows)
//
void wxWindowOS2::OS2DestroyWindow()
{
}

bool wxWindowOS2::OS2GetCreateWindowCoords( const wxPoint& rPos,
                                            const wxSize&  rSize,
                                            int& rnX,
                                            int& rnY,
                                            int& rnWidth,
                                            int& rnHeight ) const
{
    bool bNonDefault = false;
    static const int DEFAULT_Y = 200;
    static const int DEFAULT_H = 250;

    if (rPos.x == wxDefaultCoord)
    {
        rnX = rnY = CW_USEDEFAULT;
    }
    else
    {
        rnX = rPos.x;
        rnY = rPos.y == wxDefaultCoord ? DEFAULT_Y : rPos.y;
        bNonDefault = true;
    }
    if (rSize.x == wxDefaultCoord)
    {
        rnWidth = rnHeight = CW_USEDEFAULT;
    }
    else
    {
        rnWidth  = rSize.x;
        rnHeight = rSize.y == wxDefaultCoord ? DEFAULT_H : rSize.y;
        bNonDefault = true;
    }
    return bNonDefault;
} // end of wxWindowOS2::OS2GetCreateWindowCoords

WXHWND wxWindowOS2::OS2GetParent() const
{
    return m_parent ? m_parent->GetHWND() : NULL;
}

bool wxWindowOS2::OS2Create( PSZ            zClass,
                             const wxChar*  zTitle,
                             WXDWORD        dwStyle,
                             const wxPoint& rPos,
                             const wxSize&  rSize,
                             void*          pCtlData,
                             WXDWORD        WXUNUSED(dwExStyle),
                             bool           bIsChild )
{
    ERRORID              vError;
    wxString             sError;
    int                  nX      = 0L;
    int                  nY      = 0L;
    int                  nWidth  = 0L;
    int                  nHeight = 0L;
    long                 lControlId = 0L;
    wxWindowCreationHook vHook(this);
    wxString             sClassName((wxChar*)zClass);
    wxString             sTitle(zTitle ? zTitle : wxEmptyString);

    OS2GetCreateWindowCoords( rPos
                             ,rSize
                             ,nX
                             ,nY
                             ,nWidth
                             ,nHeight
                            );

    if (bIsChild)
    {
        lControlId = GetId();
        if (GetWindowStyleFlag() & wxCLIP_SIBLINGS)
        {
            dwStyle |= WS_CLIPSIBLINGS;
        }
    }
    //
    // For each class "Foo" we have we also have "FooNR" ("no repaint") class
    // which is the same but without CS_[HV]REDRAW class styles so using it
    // ensures that the window is not fully repainted on each resize
    //
    if (!HasFlag(wxFULL_REPAINT_ON_RESIZE))
    {
        sClassName += wxT("NR");
    }
    m_hWnd = (WXHWND)::WinCreateWindow( (HWND)OS2GetParent()
                                       ,sClassName.c_str()
                                       ,sTitle.c_str()
                                       ,(ULONG)dwStyle
                                       ,(LONG)0L
                                       ,(LONG)0L
                                       ,(LONG)0L
                                       ,(LONG)0L
                                       ,NULLHANDLE
                                       ,HWND_TOP
                                       ,(ULONG)lControlId
                                       ,pCtlData
                                       ,NULL
                                      );
    if (!m_hWnd)
    {
        vError = ::WinGetLastError(wxGetInstance());
        sError = wxPMErrorToStr(vError);
        return false;
    }
    SubclassWin(m_hWnd);
    SetFont(wxSystemSettings::GetFont(wxSYS_DEFAULT_GUI_FONT));

    SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_APPWORKSPACE));

    LONG lColor = (LONG)m_backgroundColour.GetPixel();

    if (!::WinSetPresParam( m_hWnd
                           ,PP_BACKGROUNDCOLOR
                           ,sizeof(LONG)
                           ,(PVOID)&lColor
                          ))
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
        wxLogError(wxT("Error creating frame. Error: %s\n"), sError.c_str());
        return false;
    }
    SetSize( nX
            ,nY
            ,nWidth
            ,nHeight
           );
    return true;
} // end of wxWindowOS2::OS2Create

// ===========================================================================
// OS2 PM message handlers
// ===========================================================================

// ---------------------------------------------------------------------------
// window creation/destruction
// ---------------------------------------------------------------------------

bool wxWindowOS2::HandleCreate( WXLPCREATESTRUCT WXUNUSED(vCs),
                                bool* pbMayCreate )
{
    wxWindowCreateEvent             vEvent((wxWindow*)this);

    (void)HandleWindowEvent(vEvent);
    *pbMayCreate = true;
    return true;
} // end of wxWindowOS2::HandleCreate

bool wxWindowOS2::HandleDestroy()
{
    wxWindowDestroyEvent            vEvent((wxWindow*)this);
    vEvent.SetId(GetId());
    (void)HandleWindowEvent(vEvent);

    //
    // Delete our drop target if we've got one
    //
#if wxUSE_DRAG_AND_DROP
    wxDELETE(m_dropTarget);
#endif // wxUSE_DRAG_AND_DROP

    //
    // WM_DESTROY handled
    //
    return true;
} // end of wxWindowOS2::HandleDestroy

// ---------------------------------------------------------------------------
// activation/focus
// ---------------------------------------------------------------------------
void wxWindowOS2::OnSetFocus(
  wxFocusEvent&                     rEvent
)
{
    rEvent.Skip();
} // end of wxWindowOS2::OnSetFocus

bool wxWindowOS2::HandleActivate(
  int                               nState
, WXHWND                            WXUNUSED(hActivate)
)
{
    wxActivateEvent                 vEvent( wxEVT_ACTIVATE
                                           ,(bool)nState
                                           ,m_windowId
                                          );
    vEvent.SetEventObject(this);
    return HandleWindowEvent(vEvent);
} // end of wxWindowOS2::HandleActivate

bool wxWindowOS2::HandleSetFocus( WXHWND WXUNUSED(hWnd) )
{
    //
    // Notify the parent keeping track of focus for the kbd navigation
    // purposes that we got it
    //
    wxChildFocusEvent               vEventFocus((wxWindow *)this);
    (void)HandleWindowEvent(vEventFocus);

#if wxUSE_CARET
    //
    // Deal with caret
    //
    if (m_caret)
    {
        m_caret->OnSetFocus();
    }
#endif // wxUSE_CARET

#if wxUSE_TEXTCTRL
    // If it's a wxTextCtrl don't send the event as it will be done
    // after the control gets to process it from EN_FOCUS handler
    if ( wxDynamicCastThis(wxTextCtrl) )
    {
        return false;
    }
#endif // wxUSE_TEXTCTRL

    wxFocusEvent                    vEvent(wxEVT_SET_FOCUS, m_windowId);

    vEvent.SetEventObject(this);
    return HandleWindowEvent(vEvent);
} // end of wxWindowOS2::HandleSetFocus

bool wxWindowOS2::HandleKillFocus( WXHWND hWnd )
{
#if wxUSE_CARET
    //
    // Deal with caret
    //
    if (m_caret)
    {
        m_caret->OnKillFocus();
    }
#endif // wxUSE_CARET

#if wxUSE_TEXTCTRL
    //
    // If it's a wxTextCtrl don't send the event as it will be done
    // after the control gets to process it.
    //
    wxTextCtrl*                     pCtrl = wxDynamicCastThis(wxTextCtrl);

    if (pCtrl)
    {
        return false;
    }
#endif

    //
    // Don't send the event when in the process of being deleted.  This can
    // only cause problems if the event handler tries to access the object.
    //
    if ( m_isBeingDeleted )
    {
        return false;
    }

    wxFocusEvent                    vEvent( wxEVT_KILL_FOCUS
                                           ,m_windowId
                                          );

    vEvent.SetEventObject(this);

    //
    // wxFindWinFromHandle() may return NULL, it is ok
    //
    vEvent.SetWindow(wxFindWinFromHandle(hWnd));
    return HandleWindowEvent(vEvent);
} // end of wxWindowOS2::HandleKillFocus

// ---------------------------------------------------------------------------
// miscellaneous
// ---------------------------------------------------------------------------

bool wxWindowOS2::HandleShow(
  bool                              bShow
, int                               WXUNUSED(nStatus)
)
{
    wxShowEvent                     vEvent(GetId(), bShow);

    vEvent.SetEventObject(this);
    return HandleWindowEvent(vEvent);
} // end of wxWindowOS2::HandleShow

bool wxWindowOS2::HandleInitDialog( WXHWND WXUNUSED(hWndFocus) )
{
    wxInitDialogEvent               vEvent(GetId());

    vEvent.SetEventObject(this);
    return HandleWindowEvent(vEvent);
} // end of wxWindowOS2::HandleInitDialog

bool wxWindowOS2::HandleEndDrag(WXWPARAM WXUNUSED(wParam))
{
   // TODO: We'll handle drag and drop later
    return false;
}

bool wxWindowOS2::HandleSetCursor( USHORT WXUNUSED(vId),
                                   WXHWND hPointer )
{
    //
    // Under OS/2 PM this allows the pointer to be changed
    // as it passes over a control
    //
    ::WinSetPointer(HWND_DESKTOP, (HPOINTER)hPointer);
    return true;
} // end of wxWindowOS2::HandleSetCursor

// ---------------------------------------------------------------------------
// owner drawn stuff
// ---------------------------------------------------------------------------
bool wxWindowOS2::OS2OnDrawItem( int vId,
                                 WXDRAWITEMSTRUCT* pItemStruct )
{
#if wxUSE_OWNER_DRAWN
    wxClientDC                      vDc(this);

#if wxUSE_MENUS_NATIVE
    //
    // Is it a menu item?
    //
    if (vId == 0)
    {
        ERRORID                     vError;
        wxString                    sError;
        POWNERITEM                  pMeasureStruct = (POWNERITEM)pItemStruct;
        wxFrame*                    pFrame = (wxFrame*)this;
        wxMenuItem*                 pMenuItem = pFrame->GetMenuBar()->FindItem(pMeasureStruct->idItem, pMeasureStruct->hItem);
        HDC                         hDC = ::GpiQueryDevice(pMeasureStruct->hps);
        wxRect                      vRect( pMeasureStruct->rclItem.xLeft
                                          ,pMeasureStruct->rclItem.yBottom
                                          ,pMeasureStruct->rclItem.xRight - pMeasureStruct->rclItem.xLeft
                                          ,pMeasureStruct->rclItem.yTop - pMeasureStruct->rclItem.yBottom
                                         );

        wxPMDCImpl *impl = (wxPMDCImpl*) vDc.GetImpl();
        impl->SetHDC( hDC, false );
        impl->SetHPS( pMeasureStruct->hps );
        //
        // Load the wxWidgets Pallete and set to RGB mode
        //
        if (!::GpiCreateLogColorTable( pMeasureStruct->hps
                                      ,0L
                                      ,LCOLF_CONSECRGB
                                      ,0L
                                      ,(LONG)wxTheColourDatabase->m_nSize
                                      ,(PLONG)wxTheColourDatabase->m_palTable
                                     ))
        {
            vError = ::WinGetLastError(vHabmain);
            sError = wxPMErrorToStr(vError);
            wxLogError(wxT("Unable to set current color table (1). Error: %s\n"), sError.c_str());
        }
        //
        // Set the color table to RGB mode
        //
        if (!::GpiCreateLogColorTable( pMeasureStruct->hps
                                      ,0L
                                      ,LCOLF_RGB
                                      ,0L
                                      ,0L
                                      ,NULL
                                     ))
        {
            vError = ::WinGetLastError(vHabmain);
            sError = wxPMErrorToStr(vError);
            wxLogError(wxT("Unable to set current color table (2). Error: %s\n"), sError.c_str());
        }

        wxCHECK( pMenuItem->IsKindOf(CLASSINFO(wxMenuItem)), FALSE );

        int eAction = 0;
        int eStatus = 0;

        if (pMeasureStruct->fsAttribute == pMeasureStruct->fsAttributeOld)
        {
            //
            // Entire Item needs to be redrawn (either it has reappeared from
            // behind another window or is being displayed for the first time
            //
            eAction = wxOwnerDrawn::wxODDrawAll;

            if (pMeasureStruct->fsAttribute & MIA_HILITED)
            {
                //
                // If it is currently selected we let the system handle it
                //
                eStatus |= wxOwnerDrawn::wxODSelected;
            }
            if (pMeasureStruct->fsAttribute & MIA_CHECKED)
            {
                //
                // If it is currently checked we draw our own
                //
                eStatus |= wxOwnerDrawn::wxODChecked;
                pMeasureStruct->fsAttributeOld = pMeasureStruct->fsAttribute &= ~MIA_CHECKED;
            }
            if (pMeasureStruct->fsAttribute & MIA_DISABLED)
            {
                //
                // If it is currently disabled we let the system handle it
                //
                eStatus |= wxOwnerDrawn::wxODDisabled;
            }
            //
            // Don't really care about framed (indicationg focus) or NoDismiss
            //
        }
        else
        {
            if (pMeasureStruct->fsAttribute & MIA_HILITED)
            {
                eAction = wxOwnerDrawn::wxODDrawAll;
                eStatus |= wxOwnerDrawn::wxODSelected;
                //
                // Keep the system from trying to highlight with its bogus colors
                //
                pMeasureStruct->fsAttributeOld = pMeasureStruct->fsAttribute &= ~MIA_HILITED;
            }
            else if (!(pMeasureStruct->fsAttribute & MIA_HILITED))
            {
                eAction = wxOwnerDrawn::wxODDrawAll;
                eStatus = 0;
                //
                // Keep the system from trying to highlight with its bogus colors
                //
                pMeasureStruct->fsAttribute = pMeasureStruct->fsAttributeOld &= ~MIA_HILITED;
            }
            else
            {
                //
                // For now we don't care about anything else
                // just ignore the entire message!
                //
                return true;
            }
        }
        //
        // Now redraw the item
        //
        return(pMenuItem->OnDrawItem( vDc
                                     ,vRect
                                     ,(wxOwnerDrawn::wxODAction)eAction
                                     ,(wxOwnerDrawn::wxODStatus)eStatus
                                    ));
        //
        // leave the fsAttribute and fsOldAttribute unchanged.  If different,
        // the system will do the highlight or fraeming or disabling for us,
        // otherwise, we'd have to do it ourselves.
        //
    }
#endif // wxUSE_MENUS_NATIVE

    wxWindow*                       pItem = FindItem(vId);

    if (pItem && pItem->IsKindOf(CLASSINFO(wxControl)))
    {
        return ((wxControl *)pItem)->OS2OnDraw(pItemStruct);
    }
#else
    vId = vId;
    pItemStruct = pItemStruct;
#endif
    return false;
} // end of wxWindowOS2::OS2OnDrawItem

long wxWindowOS2::OS2OnMeasureItem( int lId,
                                    WXMEASUREITEMSTRUCT* pItemStruct )
{
#if wxUSE_OWNER_DRAWN
    //
    // Is it a menu item?
    //
    if (lId == 65536) // I really don't like this...has to be a better indicator
    {
        if (IsKindOf(CLASSINFO(wxFrame))) // we'll assume if Frame then a menu
        {
            size_t                  nWidth;
            size_t                  nHeight;
            POWNERITEM              pMeasureStruct = (POWNERITEM)pItemStruct;
            wxFrame*                pFrame = (wxFrame*)this;
            wxMenuItem*             pMenuItem = pFrame->GetMenuBar()->FindItem(pMeasureStruct->idItem, pMeasureStruct->hItem);

            wxCHECK( pMenuItem->IsKindOf(CLASSINFO(wxMenuItem)), FALSE );
            nWidth  = 0L;
            nHeight = 0L;
            if (pMenuItem->OnMeasureItem( &nWidth
                                         ,&nHeight
                                        ))
            {
                MRESULT             mRc;

                pMeasureStruct->rclItem.xRight  = nWidth;
                pMeasureStruct->rclItem.xLeft   = 0L;
                pMeasureStruct->rclItem.yTop    = nHeight;
                pMeasureStruct->rclItem.yBottom = 0L;
                mRc = MRFROM2SHORT(nHeight, nWidth);
                return LONGFROMMR(mRc);
            }
            return 0L;
        }
    }
    wxWindow*                      pItem = FindItem(lId);

    if (pItem && pItem->IsKindOf(CLASSINFO(wxControl)))
    {
        OWNERITEM                   vItem;

        vItem.idItem = (LONG)pItemStruct;
        return ((wxControl *)pItem)->OS2OnMeasure((WXMEASUREITEMSTRUCT*)&vItem);
    }
#else
    lId = lId;
    pItemStruct = pItemStruct;
#endif // wxUSE_OWNER_DRAWN
    return FALSE;
}

// ---------------------------------------------------------------------------
// colours and palettes
// ---------------------------------------------------------------------------

bool wxWindowOS2::HandleSysColorChange()
{
    wxSysColourChangedEvent         vEvent;

    vEvent.SetEventObject(this);
    return HandleWindowEvent(vEvent);
} // end of wxWindowOS2::HandleSysColorChange

bool wxWindowOS2::HandleCtlColor( WXHBRUSH* WXUNUSED(phBrush) )
{
    //
    // Not much provided with message. So not sure I can do anything with it
    //
    return true;
} // end of wxWindowOS2::HandleCtlColor


// Define for each class of dialog and control
WXHBRUSH wxWindowOS2::OnCtlColor(WXHDC WXUNUSED(hDC),
                                 WXHWND WXUNUSED(hWnd),
                                 WXUINT WXUNUSED(nCtlColor),
                                 WXUINT WXUNUSED(message),
                                 WXWPARAM WXUNUSED(wParam),
                                 WXLPARAM WXUNUSED(lParam))
{
    return (WXHBRUSH)0;
}

bool wxWindowOS2::HandlePaletteChanged()
{
    // need to set this to something first
    WXHWND                          hWndPalChange = NULLHANDLE;

    wxPaletteChangedEvent           vEvent(GetId());

    vEvent.SetEventObject(this);
    vEvent.SetChangedWindow(wxFindWinFromHandle(hWndPalChange));

    return HandleWindowEvent(vEvent);
} // end of wxWindowOS2::HandlePaletteChanged

//
// Responds to colour changes: passes event on to children.
//
void wxWindowOS2::OnSysColourChanged(
  wxSysColourChangedEvent&          rEvent
)
{
    wxWindowList::compatibility_iterator node = GetChildren().GetFirst();

    while (node)
    {
        //
        // Only propagate to non-top-level windows
        //
        wxWindow*                   pWin = (wxWindow *)node->GetData();

        if (pWin->GetParent())
        {
            wxSysColourChangedEvent vEvent;

            rEvent.SetEventObject(pWin);
            pWin->HandleWindowEvent(vEvent);
        }
        node = node->GetNext();
    }
} // end of wxWindowOS2::OnSysColourChanged

// ---------------------------------------------------------------------------
// painting
// ---------------------------------------------------------------------------

void wxWindow::OnPaint (
  wxPaintEvent&                     rEvent
)
{
    HDC                             hDC = (HDC)wxPaintDCImpl::FindDCInCache((wxWindow*) rEvent.GetEventObject());

    if (hDC != 0)
    {
        OS2DefWindowProc( (WXUINT)WM_PAINT
                         ,(WXWPARAM)hDC
                         ,(WXLPARAM)0
                        );
    }
} // end of wxWindow::OnPaint

bool wxWindowOS2::HandlePaint()
{
    HRGN                            hRgn;
    wxPaintEvent                    vEvent(m_windowId);
    HPS                             hPS;
    bool                            bProcessed;

    // Create empty region
    // TODO: get HPS somewhere else if possible
    hPS  = ::WinGetPS(GetHwnd());
    hRgn = ::GpiCreateRegion(hPS, 0, NULL);

    if (::WinQueryUpdateRegion(GetHwnd(), hRgn) == RGN_ERROR)
    {
         wxLogLastError(wxT("CreateRectRgn"));
         return false;
    }
    // Get all the rectangles from the region, convert the individual
    // rectangles to "the other" coordinate system and reassemble a
    // region from the rectangles, to be feed into m_updateRegion.
    //
    RGNRECT                     vRgnData;
    PRECTL                      pUpdateRects = NULL;
    vRgnData.ulDirection = RECTDIR_LFRT_TOPBOT;
    if (::GpiQueryRegionRects( hPS          // Pres space
                              ,hRgn         // Handle of region to query
                              ,NULL         // Return all RECTs
                              ,&vRgnData    // Will contain number or RECTs in region
                              ,NULL         // NULL to return number of RECTs
                             ))
    {
        pUpdateRects = new RECTL[vRgnData.crcReturned];
        vRgnData.crc = vRgnData.crcReturned;
        vRgnData.ircStart = 1;
        if (::GpiQueryRegionRects( hPS      // Pres space of source
                                  ,hRgn     // Handle of source region
                                  ,NULL     // Return all RECTs
                                  ,&vRgnData // Operations set to return rects
                                  ,pUpdateRects // Will contain the actual RECTS
                                 ))
        {
            int                     height;
            RECT                    vRect;
            ::WinQueryWindowRect(GetHwnd(), &vRect);
            height = vRect.yTop;

            for(size_t i = 0; i < vRgnData.crc; i++)
            {
                int                 rectHeight;
                rectHeight = pUpdateRects[i].yTop - pUpdateRects[i].yBottom;
                pUpdateRects[i].yBottom = height - pUpdateRects[i].yTop;
                pUpdateRects[i].yTop = pUpdateRects[i].yBottom + rectHeight;
            }
            ::GpiSetRegion(hPS, hRgn, vRgnData.crc, pUpdateRects);
            delete [] pUpdateRects;
        }
    }
    m_updateRegion = wxRegion(hRgn, hPS);

    vEvent.SetEventObject(this);
    bProcessed = HandleWindowEvent(vEvent);

    if (!bProcessed &&
         IsKindOf(CLASSINFO(wxPanel)) &&
         GetChildren().GetCount() == 0
       )
    {
        //
        // OS/2 needs to process this right here, not by the default proc
        // Window's default proc correctly paints everything, OS/2 does not.
        // For decorative panels that typically have no children, we draw
        // borders.
        //
        HPS                         hPS;
        RECTL                       vRect;

        hPS = ::WinBeginPaint( GetHwnd()
                              ,NULLHANDLE
                              ,&vRect
                             );
        if(hPS)
        {
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
            if (::WinIsWindowVisible(GetHWND()))
                ::WinFillRect(hPS, &vRect,  GetBackgroundColour().GetPixel());
            if (m_dwExStyle)
            {
                LINEBUNDLE      vLineBundle;

                vLineBundle.lColor     = 0x00000000; // Black
                vLineBundle.usMixMode  = FM_OVERPAINT;
                vLineBundle.fxWidth    = 1;
                vLineBundle.lGeomWidth = 1;
                vLineBundle.usType     = LINETYPE_SOLID;
                vLineBundle.usEnd      = 0;
                vLineBundle.usJoin     = 0;
                ::GpiSetAttrs( hPS
                              ,PRIM_LINE
                              ,LBB_COLOR | LBB_MIX_MODE | LBB_WIDTH | LBB_GEOM_WIDTH | LBB_TYPE
                              ,0L
                              ,&vLineBundle
                             );
                ::WinQueryWindowRect(GetHwnd(), &vRect);
                wxDrawBorder( hPS
                             ,vRect
                             ,m_dwExStyle
                            );
            }
        }
        ::WinEndPaint(hPS);
        bProcessed = true;
    }
    else if (!bProcessed &&
             IsKindOf(CLASSINFO(wxPanel))
            )
    {
        //
        // Panel with children, usually fills a frame client so no borders.
        //
        HPS hPS;
        RECTL vRect;

        hPS = ::WinBeginPaint( GetHwnd()
                              ,NULLHANDLE
                              ,&vRect
                             );
        if(hPS)
        {
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

            if (::WinIsWindowVisible(GetHWND()))
                ::WinFillRect(hPS, &vRect,  GetBackgroundColour().GetPixel());
        }
        ::WinEndPaint(hPS);
        bProcessed = true;
    }
    return bProcessed;
} // end of wxWindowOS2::HandlePaint

bool wxWindowOS2::HandleEraseBkgnd( WXHDC hDC )
{
    SWP vSwp;
    bool rc;

    ::WinQueryWindowPos(GetHwnd(), &vSwp);
    if (vSwp.fl & SWP_MINIMIZE)
        return true;

    wxClientDC vDC(this);
    wxPMDCImpl *impl = (wxPMDCImpl*) vDC.GetImpl();
    impl->SetHDC(hDC);
    impl->SetHPS((HPS)hDC); // this is really a PS

    wxEraseEvent vEvent(m_windowId, &vDC);

    vEvent.SetEventObject(this);

    rc = HandleWindowEvent(vEvent);

    impl->SetHPS(NULLHANDLE);
    return true;
} // end of wxWindowOS2::HandleEraseBkgnd

void wxWindowOS2::OnEraseBackground(wxEraseEvent& rEvent)
{
    RECTL   vRect;
    wxPMDCImpl *impl = (wxPMDCImpl*) rEvent.GetDC()->GetImpl();
    HPS     hPS = impl->GetHPS();
    APIRET  rc;
    LONG    lColor = m_backgroundColour.GetPixel();

    rc = ::WinQueryWindowRect(GetHwnd(), &vRect);
    rc = ::WinFillRect(hPS, &vRect, lColor);
}  // end of wxWindowOS2::OnEraseBackground

// ---------------------------------------------------------------------------
// moving and resizing
// ---------------------------------------------------------------------------

bool wxWindowOS2::HandleMinimize()
{
    wxIconizeEvent                  vEvent(m_windowId);

    vEvent.SetEventObject(this);
    return HandleWindowEvent(vEvent);
} // end of wxWindowOS2::HandleMinimize

bool wxWindowOS2::HandleMaximize()
{
    wxMaximizeEvent                 vEvent(m_windowId);

    vEvent.SetEventObject(this);
    return HandleWindowEvent(vEvent);
} // end of wxWindowOS2::HandleMaximize

bool wxWindowOS2::HandleMove( int nX, int nY )
{
    wxPoint pt(nX, nY);
    wxMoveEvent vEvent(pt, m_windowId);

    vEvent.SetEventObject(this);
    return HandleWindowEvent(vEvent);
}  // end of wxWindowOS2::HandleMove

bool wxWindowOS2::HandleSize( int    nWidth,
                              int    nHeight,
                              WXUINT WXUNUSED(nFlag) )
{
    wxSize sz(nWidth, nHeight);
    wxSizeEvent vEvent(sz, m_windowId);

    vEvent.SetEventObject(this);
    return HandleWindowEvent(vEvent);
} // end of wxWindowOS2::HandleSize

bool wxWindowOS2::HandleGetMinMaxInfo( PSWP pSwp )
{
    POINTL                          vPoint;

    switch(pSwp->fl)
    {
        case SWP_MAXIMIZE:
            ::WinGetMaxPosition(GetHwnd(), pSwp);
            m_maxWidth = pSwp->cx;
            m_maxHeight = pSwp->cy;
            break;

        case SWP_MINIMIZE:
            ::WinGetMinPosition(GetHwnd(), pSwp, &vPoint);
            m_minWidth = pSwp->cx;
            m_minHeight = pSwp->cy;
            break;

        default:
            return false;
    }
    return true;
} // end of wxWindowOS2::HandleGetMinMaxInfo

// ---------------------------------------------------------------------------
// command messages
// ---------------------------------------------------------------------------
bool wxWindowOS2::HandleCommand( WXWORD wId,
                                 WXWORD wCmd,
                                 WXHWND hControl )
{
#if wxUSE_MENUS_NATIVE
    if (wxCurrentPopupMenu)
    {
        wxMenu*                     pPopupMenu = wxCurrentPopupMenu;

        wxCurrentPopupMenu = NULL;
        return pPopupMenu->OS2Command(wCmd, wId);
    }
#endif // wxUSE_MENUS_NATIVE

    wxWindow*                       pWin = FindItem(wId);

    if (!pWin)
    {
        pWin = wxFindWinFromHandle(hControl);
    }

    if (pWin)
        return pWin->OS2Command(wCmd, wId);

    return false;
} // end of wxWindowOS2::HandleCommand

bool wxWindowOS2::HandleSysCommand( WXWPARAM wParam,
                                    WXLPARAM WXUNUSED(lParam) )
{
    //
    // 4 bits are reserved
    //
    switch (SHORT1FROMMP(wParam))
    {
        case SC_MAXIMIZE:
            return HandleMaximize();

        case SC_MINIMIZE:
            return HandleMinimize();
    }
    return false;
} // end of wxWindowOS2::HandleSysCommand

// ---------------------------------------------------------------------------
// mouse events
// ---------------------------------------------------------------------------
//TODO: check against MSW
void wxWindowOS2::InitMouseEvent(
  wxMouseEvent&                     rEvent
, int                               nX
, int                               nY
, WXUINT                            uFlags
)
{
    int                                 nHeight;
    DoGetSize(0, &nHeight);
    rEvent.m_x           = nX;
    // Convert to wxWidgets standard coordinate system!
    rEvent.m_y           = nHeight - nY;
    rEvent.m_shiftDown   = ((uFlags & KC_SHIFT) != 0);
    rEvent.m_controlDown = ((uFlags & KC_CTRL) != 0);
    rEvent.m_altDown     = ((uFlags & KC_ALT) != 0);
    rEvent.m_leftDown    = IsKeyDown(VK_BUTTON1);
    rEvent.m_middleDown  = IsKeyDown(VK_BUTTON3);
    rEvent.m_rightDown   = IsKeyDown(VK_BUTTON2);
    rEvent.SetTimestamp(s_currentMsg.time);
    rEvent.SetEventObject(this);
    rEvent.SetId(GetId());

#if wxUSE_MOUSEEVENT_HACK
    m_lastMouseX = nX;
    m_lastMouseY = nY;
    m_lastMouseEvent = rEvent.GetEventType();
#endif // wxUSE_MOUSEEVENT_HACK
} // end of wxWindowOS2::InitMouseEvent

bool wxWindowOS2::HandleMouseEvent( WXUINT uMsg,
                                    int    nX,
                                    int    nY,
                                    WXUINT uFlags )
{
    bool bProcessed = false;

    //
    // The mouse events take consecutive IDs from WM_MOUSEFIRST to
    // WM_MOUSELAST, so it's enough to subtract WM_MOUSEMOVE == WM_MOUSEFIRST
    // from the message id and take the value in the table to get wxWin event
    // id
    //
    static const wxEventType eventsMouse[] =
    {
        wxEVT_MOTION,
        wxEVT_LEFT_DOWN,
        wxEVT_LEFT_UP,
        wxEVT_LEFT_DCLICK,
        wxEVT_RIGHT_DOWN,
        wxEVT_RIGHT_UP,
        wxEVT_RIGHT_DCLICK,
        wxEVT_MIDDLE_DOWN,
        wxEVT_MIDDLE_UP,
        wxEVT_MIDDLE_DCLICK
    };

    // Bounds check
    if ((uMsg >= WM_MOUSEMOVE) && (uMsg <= WM_BUTTON3DBLCLK))
    {
        wxMouseEvent vEvent(eventsMouse[uMsg - WM_MOUSEMOVE]);

        InitMouseEvent( vEvent
                       ,nX
                       ,nY
                       ,uFlags
                       );

        bProcessed = HandleWindowEvent(vEvent);
        if (!bProcessed)
        {
            HPOINTER hCursor = (HPOINTER)GetCursor().GetHCURSOR();

            if (hCursor != NULLHANDLE)
            {
                ::WinSetPointer(HWND_DESKTOP, hCursor);
                bProcessed = true;
            }
        }
    }
    return bProcessed;
} // end of wxWindowOS2::HandleMouseEvent

bool wxWindowOS2::HandleMouseMove( int nX,
                                   int nY,
                                   WXUINT uFlags )
{
    if (!m_bMouseInWindow)
    {
        //
        // Generate an ENTER event
        //
        m_bMouseInWindow = true;

        wxMouseEvent vEvent(wxEVT_ENTER_WINDOW);

        InitMouseEvent( vEvent
                       ,nX
                       ,nY
                       ,uFlags
                      );

        (void)HandleWindowEvent(vEvent);
    }
    return HandleMouseEvent( WM_MOUSEMOVE
                            ,nX
                            ,nY
                            ,uFlags
                           );
} // end of wxWindowOS2::HandleMouseMove

// ---------------------------------------------------------------------------
// keyboard handling
// ---------------------------------------------------------------------------

//
// Create the key event of the given type for the given key - used by
// HandleChar and HandleKeyDown/Up
//
wxKeyEvent wxWindowOS2::CreateKeyEvent(
  wxEventType                       eType
, int                               nId
, WXLPARAM                          lParam
, WXWPARAM                          wParam
) const
{
    wxKeyEvent                      vEvent(eType);

    vEvent.SetId(GetId());
    vEvent.m_shiftDown   = IsShiftDown();
    vEvent.m_controlDown = IsCtrlDown();
    vEvent.m_altDown     = (HIWORD(lParam) & KC_ALT) == KC_ALT;

    vEvent.SetEventObject((wxWindow *)this); // const_cast
    vEvent.m_keyCode     = nId;
    vEvent.m_rawCode = (wxUint32)wParam;
    vEvent.m_rawFlags = (wxUint32)lParam;
    vEvent.SetTimestamp(s_currentMsg.time);

    //
    // Translate the position to client coords
    //
    POINTL                          vPoint;
    RECTL                           vRect;

    ::WinQueryPointerPos(HWND_DESKTOP, &vPoint);
    ::WinQueryWindowRect( GetHwnd()
                         ,&vRect
                        );

    vPoint.x -= vRect.xLeft;
    vPoint.y -= vRect.yBottom;

    vEvent.m_x = vPoint.x;
    vEvent.m_y = vPoint.y;

    return vEvent;
} // end of wxWindowOS2::CreateKeyEvent

//
// isASCII is true only when we're called from WM_CHAR handler and not from
// WM_KEYDOWN one
//
bool wxWindowOS2::HandleChar( WXWPARAM WXUNUSED(wParam),
                              WXLPARAM lParam,
                              bool     isASCII )
{
    bool bCtrlDown = false;
    int  vId;

    if (m_bLastKeydownProcessed)
    {
        //
        // The key was handled in the EVT_KEY_DOWN.  Handling a key in an
        // EVT_KEY_DOWN handler is meant, by design, to prevent EVT_CHARs
        // from happening, so just bail out at this point.
        //
        m_bLastKeydownProcessed = false;
        return true;
    }
    if (isASCII)
    {
        //
        // If 1 -> 26, translate to either special keycode or just set
        // ctrlDown.  IOW, Ctrl-C should result in keycode == 3 and
        // ControlDown() == true.
        //
        vId = SHORT1FROMMP(lParam);
        if ((vId > 0) && (vId < 27))
        {
            switch (vId)
            {
                case 13:
                    vId = WXK_RETURN;
                    break;

                case 8:
                    vId = WXK_BACK;
                    break;

                case 9:
                    vId = WXK_TAB;
                    break;

                default:
                    bCtrlDown = true;
                    break;
            }
        }
    }
    else  // we're called from WM_KEYDOWN
    {
        vId = wxCharCodeOS2ToWX((int)SHORT2FROMMP(lParam));
        if (vId == 0)
            return false;
    }

    wxKeyEvent vEvent(CreateKeyEvent( wxEVT_CHAR, vId, lParam ));

    if (bCtrlDown)
    {
        vEvent.m_controlDown = true;
    }

    return (HandleWindowEvent(vEvent));
}

bool wxWindowOS2::HandleKeyDown( WXWPARAM wParam,
                                 WXLPARAM lParam )
{
    int nId = wxCharCodeOS2ToWX((int)SHORT2FROMMP(lParam));

    if (!nId)
    {
        //
        // Normal ASCII char
        //
        nId = SHORT1FROMMP(lParam);
    }

    if (nId != -1)
    {
        wxKeyEvent  vEvent(CreateKeyEvent( wxEVT_KEY_DOWN
                                          ,nId
                                          ,(MPARAM)lParam
                                          ,(MPARAM)wParam
                                         ));

        if (HandleWindowEvent(vEvent))
        {
            return true;
        }
    }
    return false;
} // end of wxWindowOS2::HandleKeyDown

bool wxWindowOS2::HandleKeyUp( WXWPARAM wParam,
                               WXLPARAM lParam )
{
    int nId = wxCharCodeOS2ToWX((int)SHORT2FROMMP(lParam));

    if (!nId)
    {
        //
        // Normal ASCII char
        //
        nId = CHAR1FROMMP(lParam);
    }

    if (nId != -1)
    {
        wxKeyEvent vEvent(CreateKeyEvent( wxEVT_KEY_UP
                                         ,nId
                                         ,(MPARAM)lParam
                                         ,(MPARAM)wParam
                                        ));

        if (HandleWindowEvent(vEvent))
            return true;
    }
    return false;
} // end of wxWindowOS2::HandleKeyUp

// ---------------------------------------------------------------------------
// joystick
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// scrolling
// ---------------------------------------------------------------------------

bool wxWindowOS2::OS2OnScroll( int nOrientation,
                               WXWORD wParam,
                               WXWORD wPos,
                               WXHWND hControl )
{
    if (hControl)
    {
        wxWindow*                   pChild = wxFindWinFromHandle(hControl);

        if (pChild )
            return pChild->OS2OnScroll( nOrientation
                                       ,wParam
                                       ,wPos
                                       ,hControl
                                      );
    }

    wxScrollWinEvent                vEvent;

    vEvent.SetPosition(wPos);
    vEvent.SetOrientation(nOrientation);
    vEvent.SetEventObject(this);

    switch (wParam)
    {
        case SB_LINEUP:
            vEvent.SetEventType(wxEVT_SCROLLWIN_LINEUP);
            break;

        case SB_LINEDOWN:
            vEvent.SetEventType(wxEVT_SCROLLWIN_LINEDOWN);
            break;

        case SB_PAGEUP:
            vEvent.SetEventType(wxEVT_SCROLLWIN_PAGEUP);
            break;

        case SB_PAGEDOWN:
            vEvent.SetEventType(wxEVT_SCROLLWIN_PAGEDOWN);
            break;

        case SB_SLIDERPOSITION:
            vEvent.SetEventType(wxEVT_SCROLLWIN_THUMBRELEASE);
            break;

        case SB_SLIDERTRACK:
            vEvent.SetEventType(wxEVT_SCROLLWIN_THUMBTRACK);
            break;

        default:
            return false;
    }
    return HandleWindowEvent(vEvent);
} // end of wxWindowOS2::OS2OnScroll

//
//  Getting the Y position for a window, like a control, is a real
//  pain.  There are three situations we must deal with in determining
//  the OS2 to wxWidgets Y coordinate.
//
//  1)  The controls are created in a dialog.
//      This is the easiest since a dialog is created with its original
//      size so the standard: Y = ParentHeight - (Y + ControlHeight);
//
//  2)  The controls are direct children of a frame
//      In this instance the controls are actually children of the Frame's
//      client.  During creation the frame's client resizes several times
//      during creation of the status bar and toolbars.  The CFrame class
//      will take care of this using its AlterChildPos proc.
//
//  3)  The controls are children of a panel, which in turn is a child of
//      a frame.
//      The panel may be one of many, in which case the same treatment
//      as 1 applies. It may be the only child, though.
//      This is the nastiest case.  A panel is created as the only child of
//      the frame and as such, when a frame has only one child, the child is
//      expanded to fit the entire client area of the frame.  Because the
//      controls are created BEFORE this occurs their positions are totally
//      whacked and any call to WinQueryWindowPos will return invalid
//      coordinates.  So for this situation we have to compare the size of
//      the panel at control creation time with that of the frame client.  If
//      they are the same we can use the standard Y position equation.  If
//      not, then we must use the Frame Client's dimensions to position them
//      as that will be the eventual size of the panel after the frame resizes
//      it!
//
int wxWindowOS2::GetOS2ParentHeight( wxWindowOS2* pParent )
{
    if (pParent)
    {
    //
    // Case 1
    //
        if (pParent->IsKindOf(CLASSINFO(wxDialog)))
            return(pParent->GetClientSize().y);

    //
    // Case 2 -- if we are one of the separately built standard Frame
    //           children, like a statusbar, menubar, or toolbar we want to
    //           use the frame, itself, for positioning.  Otherwise we are
    //           child window and want to use the Frame's client.
    //
        else if (pParent->IsKindOf(CLASSINFO(wxFrame)))
        {
            if (IsKindOf(CLASSINFO(wxStatusBar)) ||
                IsKindOf(CLASSINFO(wxMenuBar))   ||
                IsKindOf(CLASSINFO(wxToolBar))
               )
            {
                if (IsKindOf(CLASSINFO(wxToolBar)))
                {
                    wxFrame*        pFrame = wxDynamicCast(GetParent(), wxFrame);

                    if (pFrame->GetToolBar() == this)
                        return(pParent->GetSize().y);
                    else
                        return(pParent->GetClientSize().y);
                }
                else
                    return(pParent->GetSize().y);
            }
            else
                return(pParent->GetClientSize().y);
        }
        //
        // Case -- this is for any window that is the sole child of a Frame.
        //         The grandparent must exist and it must be of type CFrame
        //         and it's height must be different. Otherwise the standard
        //         applies.
        //
        else
            return(pParent->GetClientSize().y);
    }
    else // We must be a child of the screen
    {
        int nHeight;
        wxDisplaySize(NULL,&nHeight);
        return(nHeight);
    }
} // end of wxWindowOS2::GetOS2ParentHeight

//
// OS/2 needs a lot extra manipulation to deal with layouts
// for canvas windows, particularly scrolled ones.
//
wxWindowCreationHook::wxWindowCreationHook(
  wxWindow*                         pWinBeingCreated
)
{
    gpWinBeingCreated = pWinBeingCreated;
} // end of wxWindowCreationHook::wxWindowCreationHook

wxWindowCreationHook::~wxWindowCreationHook()
{
    gpWinBeingCreated = NULL;
} // end of wxWindowCreationHook::~wxWindowCreationHook

// ===========================================================================
// global functions
// ===========================================================================

void wxGetCharSize(
  WXHWND                            hWnd
, int*                              pX
, int*                              pY
,wxFont*                            WXUNUSED(pTheFont)
)
{
    FONTMETRICS                     vFM;
    HPS                             hPS;
    BOOL                            rc;

    hPS =::WinGetPS(hWnd);

    rc = ::GpiQueryFontMetrics(hPS, sizeof(FONTMETRICS), &vFM);
    if (rc)
    {
        if (pX)
            *pX = vFM.lAveCharWidth;
        if (pY)
            *pY = vFM.lEmHeight + vFM.lExternalLeading;
    }
    else
    {
        if (pX)
            *pX = 10;
        if (pY)
            *pY = 15;
    }
    ::WinReleasePS(hPS);
} // end of wxGetCharSize

//
// Returns 0 if was a normal ASCII value, not a special key. This indicates that
// the key should be ignored by WM_KEYDOWN and processed by WM_CHAR instead.
//
int wxCharCodeOS2ToWX(
  int                               nKeySym
)
{
    int                             nId = 0;

    switch (nKeySym)
    {
        case VK_BACKTAB:    nId = WXK_BACK; break;
        case VK_TAB:        nId = WXK_TAB; break;
        case VK_CLEAR:      nId = WXK_CLEAR; break;
        case VK_ENTER:      nId = WXK_RETURN; break;
        case VK_SHIFT:      nId = WXK_SHIFT; break;
        case VK_CTRL:       nId = WXK_CONTROL; break;
        case VK_PAUSE:      nId = WXK_PAUSE; break;
        case VK_SPACE:      nId = WXK_SPACE; break;
        case VK_PAGEUP:     nId = WXK_PAGEUP; break;
        case VK_PAGEDOWN:   nId = WXK_PAGEDOWN; break;
        case VK_ESC:        nId = WXK_ESCAPE; break;
        case VK_END:        nId = WXK_END; break;
        case VK_HOME :      nId = WXK_HOME; break;
        case VK_LEFT :      nId = WXK_LEFT; break;
        case VK_UP:         nId = WXK_UP; break;
        case VK_RIGHT:      nId = WXK_RIGHT; break;
        case VK_DOWN :      nId = WXK_DOWN; break;
        case VK_PRINTSCRN:  nId = WXK_PRINT; break;
        case VK_INSERT:     nId = WXK_INSERT; break;
        case VK_DELETE:     nId = WXK_DELETE; break;
        case VK_CAPSLOCK:   nId = WXK_CAPITAL; break;
        case VK_F1:         nId = WXK_F1; break;
        case VK_F2:         nId = WXK_F2; break;
        case VK_F3:         nId = WXK_F3; break;
        case VK_F4:         nId = WXK_F4; break;
        case VK_F5:         nId = WXK_F5; break;
        case VK_F6:         nId = WXK_F6; break;
        case VK_F7:         nId = WXK_F7; break;
        case VK_F8:         nId = WXK_F8; break;
        case VK_F9:         nId = WXK_F9; break;
        case VK_F10:        nId = WXK_F10; break;
        case VK_F11:        nId = WXK_F11; break;
        case VK_F12:        nId = WXK_F12; break;
        case VK_F13:        nId = WXK_F13; break;
        case VK_F14:        nId = WXK_F14; break;
        case VK_F15:        nId = WXK_F15; break;
        case VK_F16:        nId = WXK_F16; break;
        case VK_F17:        nId = WXK_F17; break;
        case VK_F18:        nId = WXK_F18; break;
        case VK_F19:        nId = WXK_F19; break;
        case VK_F20:        nId = WXK_F20; break;
        case VK_F21:        nId = WXK_F21; break;
        case VK_F22:        nId = WXK_F22; break;
        case VK_F23:        nId = WXK_F23; break;
        case VK_F24:        nId = WXK_F24; break;
        case VK_OEM_1:      nId = ';'; break;
        case VK_OEM_PLUS:   nId = '+'; break;
        case VK_OEM_COMMA:  nId = ','; break;
        case VK_OEM_MINUS:  nId = '-'; break;
        case VK_OEM_PERIOD: nId = '.'; break;
        case VK_OEM_2:      nId = '/'; break;
        case VK_OEM_3:      nId = '~'; break;
        case VK_OEM_4:      nId = '['; break;
        case VK_OEM_5:      nId = '\\'; break;
        case VK_OEM_6:      nId = ']'; break;
        case VK_OEM_7:      nId = '\''; break;
        case VK_NUMLOCK:    nId = WXK_NUMLOCK; break;
        case VK_SCRLLOCK:   nId = WXK_SCROLL; break;
        default:
        {
            return 0;
        }
    }
    return nId;
} // end of wxCharCodeOS2ToWX

int wxCharCodeWXToOS2( int nId,
                       bool* bIsVirtual)
{
    int nKeySym = 0;

    if ( bIsVirtual )
        *bIsVirtual = true;
    switch (nId)
    {
        case WXK_CLEAR:     nKeySym = VK_CLEAR; break;
        case WXK_SHIFT:     nKeySym = VK_SHIFT; break;
        case WXK_CONTROL:   nKeySym = VK_CTRL; break;
        case WXK_PAUSE:     nKeySym = VK_PAUSE; break;
        case WXK_PAGEUP:    nKeySym = VK_PAGEUP; break;
        case WXK_PAGEDOWN:  nKeySym = VK_PAGEDOWN; break;
        case WXK_END:       nKeySym = VK_END; break;
        case WXK_HOME :     nKeySym = VK_HOME; break;
        case WXK_LEFT :     nKeySym = VK_LEFT; break;
        case WXK_UP:        nKeySym = VK_UP; break;
        case WXK_RIGHT:     nKeySym = VK_RIGHT; break;
        case WXK_DOWN :     nKeySym = VK_DOWN; break;
        case WXK_PRINT:     nKeySym = VK_PRINTSCRN; break;
        case WXK_INSERT:    nKeySym = VK_INSERT; break;
        case WXK_DELETE:    nKeySym = VK_DELETE; break;
        case WXK_F1:        nKeySym = VK_F1; break;
        case WXK_F2:        nKeySym = VK_F2; break;
        case WXK_F3:        nKeySym = VK_F3; break;
        case WXK_F4:        nKeySym = VK_F4; break;
        case WXK_F5:        nKeySym = VK_F5; break;
        case WXK_F6:        nKeySym = VK_F6; break;
        case WXK_F7:        nKeySym = VK_F7; break;
        case WXK_F8:        nKeySym = VK_F8; break;
        case WXK_F9:        nKeySym = VK_F9; break;
        case WXK_F10:       nKeySym = VK_F10; break;
        case WXK_F11:       nKeySym = VK_F11; break;
        case WXK_F12:       nKeySym = VK_F12; break;
        case WXK_F13:       nKeySym = VK_F13; break;
        case WXK_F14:       nKeySym = VK_F14; break;
        case WXK_F15:       nKeySym = VK_F15; break;
        case WXK_F16:       nKeySym = VK_F16; break;
        case WXK_F17:       nKeySym = VK_F17; break;
        case WXK_F18:       nKeySym = VK_F18; break;
        case WXK_F19:       nKeySym = VK_F19; break;
        case WXK_F20:       nKeySym = VK_F20; break;
        case WXK_F21:       nKeySym = VK_F21; break;
        case WXK_F22:       nKeySym = VK_F22; break;
        case WXK_F23:       nKeySym = VK_F23; break;
        case WXK_F24:       nKeySym = VK_F24; break;
        case WXK_NUMLOCK:   nKeySym = VK_NUMLOCK; break;
        case WXK_SCROLL:    nKeySym = VK_SCRLLOCK; break;
        default:
        {
            if ( bIsVirtual )
                *bIsVirtual = false;
            nKeySym = nId;
            break;
        }
    }
    return nKeySym;
} // end of wxCharCodeWXToOS2


bool wxGetKeyState(wxKeyCode key)
{
    wxASSERT_MSG(key != WXK_LBUTTON && key != WXK_RBUTTON && key !=
        WXK_MBUTTON, wxT("can't use wxGetKeyState() for mouse buttons"));

    const LONG vk = wxCharCodeWXToOS2(key);
    // if the requested key is a LED key, return true if the led is pressed
    if ( key == WXK_NUMLOCK || key == WXK_CAPITAL || key == WXK_SCROLL )
    {
        // low order bit means LED is highlighted and high order one means the
        // key is down; for compatibility with the other ports return true if
        // either one is set
        return ::WinGetKeyState(HWND_DESKTOP, vk) != 0;

    }
    else // normal key
    {
        return IsKeyDown(vk);
    }
}


wxWindow* wxGetActiveWindow()
{
    HWND                            hWnd = ::WinQueryActiveWindow(HWND_DESKTOP);

    if (hWnd != 0)
    {
        return wxFindWinFromHandle((WXHWND)hWnd);
    }
    return NULL;
} // end of wxGetActiveWindow

#ifdef __WXDEBUG__
const wxChar* wxGetMessageName( int nMessage )
{
    switch (nMessage)
    {
        case 0x0000: return wxT("WM_NULL");
        case 0x0001: return wxT("WM_CREATE");
        case 0x0002: return wxT("WM_DESTROY");
        case 0x0004: return wxT("WM_ENABLE");
        case 0x0005: return wxT("WM_SHOW");
        case 0x0006: return wxT("WM_MOVE");
        case 0x0007: return wxT("WM_SIZE");
        case 0x0008: return wxT("WM_ADJUSTWINDOWPOS");
        case 0x0009: return wxT("WM_CALCVALIDRECTS");
        case 0x000A: return wxT("WM_SETWINDOWPARAMS");
        case 0x000B: return wxT("WM_QUERYWINDOWPARAMS");
        case 0x000C: return wxT("WM_HITTEST");
        case 0x000D: return wxT("WM_ACTIVATE");
        case 0x000F: return wxT("WM_SETFOCUS");
        case 0x0010: return wxT("WM_SETSELECTION");
        case 0x0011: return wxT("WM_PPAINT");
        case 0x0012: return wxT("WM_PSETFOCUS");
        case 0x0013: return wxT("WM_PSYSCOLORCHANGE");
        case 0x0014: return wxT("WM_PSIZE");
        case 0x0015: return wxT("WM_PACTIVATE");
        case 0x0016: return wxT("WM_PCONTROL");
        case 0x0020: return wxT("WM_COMMAND");
        case 0x0021: return wxT("WM_SYSCOMMAND");
        case 0x0022: return wxT("WM_HELP");
        case 0x0023: return wxT("WM_PAINT");
        case 0x0024: return wxT("WM_TIMER");
        case 0x0025: return wxT("WM_SEM1");
        case 0x0026: return wxT("WM_SEM2");
        case 0x0027: return wxT("WM_SEM3");
        case 0x0028: return wxT("WM_SEM4");
        case 0x0029: return wxT("WM_CLOSE");
        case 0x002A: return wxT("WM_QUIT");
        case 0x002B: return wxT("WM_SYSCOLORCHANGE");
        case 0x002D: return wxT("WM_SYSVALUECHANGE");
        case 0x002E: return wxT("WM_APPTERMINATENOTIFY");
        case 0x002F: return wxT("WM_PRESPARAMCHANGED");
        // Control notification messages
        case 0x0030: return wxT("WM_CONTROL");
        case 0x0031: return wxT("WM_VSCROLL");
        case 0x0032: return wxT("WM_HSCROLL");
        case 0x0033: return wxT("WM_INITMENU");
        case 0x0034: return wxT("WM_MENUSELECT");
        case 0x0035: return wxT("WM_MENUSEND");
        case 0x0036: return wxT("WM_DRAWITEM");
        case 0x0037: return wxT("WM_MEASUREITEM");
        case 0x0038: return wxT("WM_CONTROLPOINTER");
        case 0x003A: return wxT("WM_QUERYDLGCODE");
        case 0x003B: return wxT("WM_INITDLG");
        case 0x003C: return wxT("WM_SUBSTITUTESTRING");
        case 0x003D: return wxT("WM_MATCHMNEMONIC");
        case 0x003E: return wxT("WM_SAVEAPPLICATION");
        case 0x0129: return wxT("WM_CTLCOLORCHANGE");
        case 0x0130: return wxT("WM_QUERYCTLTYPE");
        // Frame messages
        case 0x0040: return wxT("WM_FLASHWINDOW");
        case 0x0041: return wxT("WM_FORMATFRAME");
        case 0x0042: return wxT("WM_UPDATEFRAME");
        case 0x0043: return wxT("WM_FOCUSCHANGE");
        case 0x0044: return wxT("WM_SETBORDERSIZE");
        case 0x0045: return wxT("WM_TRACKFRAME");
        case 0x0046: return wxT("WM_MINMAXFRAME");
        case 0x0047: return wxT("WM_SETICON");
        case 0x0048: return wxT("WM_QUERYICON");
        case 0x0049: return wxT("WM_SETACCELTABLE");
        case 0x004A: return wxT("WM_QUERYACCELTABLE");
        case 0x004B: return wxT("WM_TRANSLATEACCEL");
        case 0x004C: return wxT("WM_QUERYTRACKINFO");
        case 0x004D: return wxT("WM_QUERYBORDERSIZE");
        case 0x004E: return wxT("WM_NEXTMENU");
        case 0x004F: return wxT("WM_ERASEBACKGROUND");
        case 0x0050: return wxT("WM_QUERYFRAMEINFO");
        case 0x0051: return wxT("WM_QUERYFOCUSCHAIN");
        case 0x0052: return wxT("WM_OWNERPOSCHANGE");
        case 0x0053: return wxT("WM_CACLFRAMERECT");
        case 0x0055: return wxT("WM_WINDOWPOSCHANGED");
        case 0x0056: return wxT("WM_ADJUSTFRAMEPOS");
        case 0x0059: return wxT("WM_QUERYFRAMECTLCOUNT");
        case 0x005B: return wxT("WM_QUERYHELPINFO");
        case 0x005C: return wxT("WM_SETHELPINFO");
        case 0x005D: return wxT("WM_ERROR");
        case 0x005E: return wxT("WM_REALIZEPALETTE");
        // Clipboard messages
        case 0x0060: return wxT("WM_RENDERFMT");
        case 0x0061: return wxT("WM_RENDERALLFMTS");
        case 0x0062: return wxT("WM_DESTROYCLIPBOARD");
        case 0x0063: return wxT("WM_PAINTCLIPBOARD");
        case 0x0064: return wxT("WM_SIZECLIPBOARD");
        case 0x0065: return wxT("WM_HSCROLLCLIPBOARD");
        case 0x0066: return wxT("WM_VSCROLLCLIPBOARD");
        case 0x0067: return wxT("WM_DRAWCLIPBOARD");
        // mouse messages
        case 0x0070: return wxT("WM_MOUSEMOVE");
        case 0x0071: return wxT("WM_BUTTON1DOWN");
        case 0x0072: return wxT("WM_BUTTON1UP");
        case 0x0073: return wxT("WM_BUTTON1DBLCLK");
        case 0x0074: return wxT("WM_BUTTON2DOWN");
        case 0x0075: return wxT("WM_BUTTON2UP");
        case 0x0076: return wxT("WM_BUTTON2DBLCLK");
        case 0x0077: return wxT("WM_BUTTON3DOWN");
        case 0x0078: return wxT("WM_BUTTON3UP");
        case 0x0079: return wxT("WM_BUTTON3DBLCLK");
        case 0x007D: return wxT("WM_MOUSEMAP");
        case 0x007E: return wxT("WM_VRNDISABLED");
        case 0x007F: return wxT("WM_VRNENABLED");
        case 0x0410: return wxT("WM_CHORD");
        case 0x0411: return wxT("WM_BUTTON1MOTIONSTART");
        case 0x0412: return wxT("WM_BUTTON1MOTIONEND");
        case 0x0413: return wxT("WM_BUTTON1CLICK");
        case 0x0414: return wxT("WM_BUTTON2MOTIONSTART");
        case 0x0415: return wxT("WM_BUTTON2MOTIONEND");
        case 0x0416: return wxT("WM_BUTTON2CLICK");
        case 0x0417: return wxT("WM_BUTTON3MOTIONSTART");
        case 0x0418: return wxT("WM_BUTTON3MOTIONEND");
        case 0x0419: return wxT("WM_BUTTON3CLICK");
        case 0x0420: return wxT("WM_BEGINDRAG");
        case 0x0421: return wxT("WM_ENDDRAG");
        case 0x0422: return wxT("WM_SINGLESELECT");
        case 0x0423: return wxT("WM_OPEN");
        case 0x0424: return wxT("WM_CONTEXTMENU");
        case 0x0425: return wxT("WM_CONTEXTHELP");
        case 0x0426: return wxT("WM_TEXTEDIT");
        case 0x0427: return wxT("WM_BEGINSELECT");
        case 0x0228: return wxT("WM_ENDSELECT");
        case 0x0429: return wxT("WM_PICKUP");
        case 0x04C0: return wxT("WM_PENFIRST");
        case 0x04FF: return wxT("WM_PENLAST");
        case 0x0500: return wxT("WM_MMPMFIRST");
        case 0x05FF: return wxT("WM_MMPMLAST");
        case 0x0600: return wxT("WM_STDDLGFIRST");
        case 0x06FF: return wxT("WM_STDDLGLAST");
        case 0x0BD0: return wxT("WM_BIDI_FIRST");
        case 0x0BFF: return wxT("WM_BIDI_LAST");
        // keyboard input
        case 0x007A: return wxT("WM_CHAR");
        case 0x007B: return wxT("WM_VIOCHAR");
        // DDE messages
        case 0x00A0: return wxT("WM_DDE_INITIATE");
        case 0x00A1: return wxT("WM_DDE_REQUEST");
        case 0x00A2: return wxT("WM_DDE_ACK");
        case 0x00A3: return wxT("WM_DDE_DATA");
        case 0x00A4: return wxT("WM_DDE_ADVISE");
        case 0x00A5: return wxT("WM_DDE_UNADVISE");
        case 0x00A6: return wxT("WM_DDE_POKE");
        case 0x00A7: return wxT("WM_DDE_EXECUTE");
        case 0x00A8: return wxT("WM_DDE_TERMINATE");
        case 0x00A9: return wxT("WM_DDE_INITIATEACK");
        case 0x00AF: return wxT("WM_DDE_LAST");
        // Buttons
        case 0x0120: return wxT("BM_CLICK");
        case 0x0121: return wxT("BM_QUERYCHECKINDEX");
        case 0x0122: return wxT("BM_QUERYHILITE");
        case 0x0123: return wxT("BM_SETHILITE");
        case 0x0124: return wxT("BM_QUERYCHECK");
        case 0x0125: return wxT("BM_SETCHECK");
        case 0x0126: return wxT("BM_SETDEFAULT");
        case 0x0128: return wxT("BM_AUTOSIZE");
        // Combo boxes
        case 0x029A: return wxT("CBID_LIST");
        case 0x029B: return wxT("CBID_EDIT");
        case 0x0170: return wxT("CBM_SHOWLIST");
        case 0x0171: return wxT("CBM_HILITE");
        case 0x0172: return wxT("CBM_ISLISTSHOWING");
        // Edit fields
        case 0x0140: return wxT("EM_QUERYCHANGED");
        case 0x0141: return wxT("EM_QUERYSEL");
        case 0x0142: return wxT("EM_SETSEL");
        case 0x0143: return wxT("EM_SETTEXTLIMIT");
        case 0x0144: return wxT("EM_CUT");
        case 0x0145: return wxT("EM_COPY");
        case 0x0146: return wxT("EM_CLEAR");
        case 0x0147: return wxT("EM_PASTE");
        case 0x0148: return wxT("EM_QUERYFIRSTCHAR");
        case 0x0149: return wxT("EM_SETFIRSTCHAR");
        case 0x014A: return wxT("EM_QUERYREADONLY");
        case 0x014B: return wxT("EM_SETREADONLY");
        case 0x014C: return wxT("EM_SETINSERTMODE");
        // Listboxes
        case 0x0160: return wxT("LM_QUERYITEMCOUNT");
        case 0x0161: return wxT("LM_INSERTITEM");
        case 0x0162: return wxT("LM_SETOPENINDEX");
        case 0x0163: return wxT("LM_DELETEITEM");
        case 0x0164: return wxT("LM_SELECTITEM");
        case 0x0165: return wxT("LM_QUERYSELECTION");
        case 0x0166: return wxT("LM_SETITEMTEXT");
        case 0x0167: return wxT("LM_QUERYITEMTEXTLENGTH");
        case 0x0168: return wxT("LM_QUERYITEMTEXT");
        case 0x0169: return wxT("LM_SETITEMHANDLE");
        case 0x016A: return wxT("LM_QUERYITEMHANDLE");
        case 0x016B: return wxT("LM_SEARCHSTRING");
        case 0x016C: return wxT("LM_SETITEMHEIGHT");
        case 0x016D: return wxT("LM_QUERYTOPINDEX");
        case 0x016E: return wxT("LM_DELETEALL");
        case 0x016F: return wxT("LM_INSERTMULITEMS");
        case 0x0660: return wxT("LM_SETITEMWIDTH");
        // Menus
        case 0x0180: return wxT("MM_INSERTITEM");
        case 0x0181: return wxT("MM_DELETEITEM");
        case 0x0182: return wxT("MM_QUERYITEM");
        case 0x0183: return wxT("MM_SETITEM");
        case 0x0184: return wxT("MM_QUERYITEMCOUNT");
        case 0x0185: return wxT("MM_STARTMENUMODE");
        case 0x0186: return wxT("MM_ENDMENUMODE");
        case 0x0188: return wxT("MM_REMOVEITEM");
        case 0x0189: return wxT("MM_SELECTITEM");
        case 0x018A: return wxT("MM_QUERYSELITEMID");
        case 0x018B: return wxT("MM_QUERYITEMTEXT");
        case 0x018C: return wxT("MM_QUERYITEMTEXTLENGTH");
        case 0x018D: return wxT("MM_SETITEMHANDLE");
        case 0x018E: return wxT("MM_SETITEMTEXT");
        case 0x018F: return wxT("MM_ITEMPOSITIONFROMID");
        case 0x0190: return wxT("MM_ITEMIDFROMPOSITION");
        case 0x0191: return wxT("MM_QUERYITEMATTR");
        case 0x0192: return wxT("MM_SETITEMATTR");
        case 0x0193: return wxT("MM_ISITEMVALID");
        case 0x0194: return wxT("MM_QUERYITEMRECT");
        case 0x0431: return wxT("MM_QUERYDEFAULTITEMID");
        case 0x0432: return wxT("MM_SETDEFAULTITEMID");
        // Scrollbars
        case 0x01A0: return wxT("SBM_SETSCROLLBAR");
        case 0x01A1: return wxT("SBM_SETPOS");
        case 0x01A2: return wxT("SBM_QUERYPOS");
        case 0x01A3: return wxT("SBM_QUERYRANGE");
        case 0x01A6: return wxT("SBM_SETTHUMBSIZE");

        // Help messages
        case 0x0F00: return wxT("WM_HELPBASE");
        case 0x0FFF: return wxT("WM_HELPTOP");
        // Beginning of user defined messages
        case 0x1000: return wxT("WM_USER");

        // wxWidgets user defined types

        // listview
        // case 0x1000 + 0: return wxT("LVM_GETBKCOLOR");
        case 0x1000 + 1: return wxT("LVM_SETBKCOLOR");
        case 0x1000 + 2: return wxT("LVM_GETIMAGELIST");
        case 0x1000 + 3: return wxT("LVM_SETIMAGELIST");
        case 0x1000 + 4: return wxT("LVM_GETITEMCOUNT");
        case 0x1000 + 5: return wxT("LVM_GETITEMA");
        case 0x1000 + 75: return wxT("LVM_GETITEMW");
        case 0x1000 + 6: return wxT("LVM_SETITEMA");
        case 0x1000 + 76: return wxT("LVM_SETITEMW");
        case 0x1000 + 7: return wxT("LVM_INSERTITEMA");
        case 0x1000 + 77: return wxT("LVM_INSERTITEMW");
        case 0x1000 + 8: return wxT("LVM_DELETEITEM");
        case 0x1000 + 9: return wxT("LVM_DELETEALLITEMS");
        case 0x1000 + 10: return wxT("LVM_GETCALLBACKMASK");
        case 0x1000 + 11: return wxT("LVM_SETCALLBACKMASK");
        case 0x1000 + 12: return wxT("LVM_GETNEXTITEM");
        case 0x1000 + 13: return wxT("LVM_FINDITEMA");
        case 0x1000 + 83: return wxT("LVM_FINDITEMW");
        case 0x1000 + 14: return wxT("LVM_GETITEMRECT");
        case 0x1000 + 15: return wxT("LVM_SETITEMPOSITION");
        case 0x1000 + 16: return wxT("LVM_GETITEMPOSITION");
        case 0x1000 + 17: return wxT("LVM_GETSTRINGWIDTHA");
        case 0x1000 + 87: return wxT("LVM_GETSTRINGWIDTHW");
        case 0x1000 + 18: return wxT("LVM_HITTEST");
        case 0x1000 + 19: return wxT("LVM_ENSUREVISIBLE");
        case 0x1000 + 20: return wxT("LVM_SCROLL");
        case 0x1000 + 21: return wxT("LVM_REDRAWITEMS");
        case 0x1000 + 22: return wxT("LVM_ARRANGE");
        case 0x1000 + 23: return wxT("LVM_EDITLABELA");
        case 0x1000 + 118: return wxT("LVM_EDITLABELW");
        case 0x1000 + 24: return wxT("LVM_GETEDITCONTROL");
        case 0x1000 + 25: return wxT("LVM_GETCOLUMNA");
        case 0x1000 + 95: return wxT("LVM_GETCOLUMNW");
        case 0x1000 + 26: return wxT("LVM_SETCOLUMNA");
        case 0x1000 + 96: return wxT("LVM_SETCOLUMNW");
        case 0x1000 + 27: return wxT("LVM_INSERTCOLUMNA");
        case 0x1000 + 97: return wxT("LVM_INSERTCOLUMNW");
        case 0x1000 + 28: return wxT("LVM_DELETECOLUMN");
        case 0x1000 + 29: return wxT("LVM_GETCOLUMNWIDTH");
        case 0x1000 + 30: return wxT("LVM_SETCOLUMNWIDTH");
        case 0x1000 + 31: return wxT("LVM_GETHEADER");
        case 0x1000 + 33: return wxT("LVM_CREATEDRAGIMAGE");
        case 0x1000 + 34: return wxT("LVM_GETVIEWRECT");
        case 0x1000 + 35: return wxT("LVM_GETTEXTCOLOR");
        case 0x1000 + 36: return wxT("LVM_SETTEXTCOLOR");
        case 0x1000 + 37: return wxT("LVM_GETTEXTBKCOLOR");
        case 0x1000 + 38: return wxT("LVM_SETTEXTBKCOLOR");
        case 0x1000 + 39: return wxT("LVM_GETTOPINDEX");
        case 0x1000 + 40: return wxT("LVM_GETCOUNTPERPAGE");
        case 0x1000 + 41: return wxT("LVM_GETORIGIN");
        case 0x1000 + 42: return wxT("LVM_UPDATE");
        case 0x1000 + 43: return wxT("LVM_SETITEMSTATE");
        case 0x1000 + 44: return wxT("LVM_GETITEMSTATE");
        case 0x1000 + 45: return wxT("LVM_GETITEMTEXTA");
        case 0x1000 + 115: return wxT("LVM_GETITEMTEXTW");
        case 0x1000 + 46: return wxT("LVM_SETITEMTEXTA");
        case 0x1000 + 116: return wxT("LVM_SETITEMTEXTW");
        case 0x1000 + 47: return wxT("LVM_SETITEMCOUNT");
        case 0x1000 + 48: return wxT("LVM_SORTITEMS");
        case 0x1000 + 49: return wxT("LVM_SETITEMPOSITION32");
        case 0x1000 + 50: return wxT("LVM_GETSELECTEDCOUNT");
        case 0x1000 + 51: return wxT("LVM_GETITEMSPACING");
        case 0x1000 + 52: return wxT("LVM_GETISEARCHSTRINGA");
        case 0x1000 + 117: return wxT("LVM_GETISEARCHSTRINGW");
        case 0x1000 + 53: return wxT("LVM_SETICONSPACING");
        case 0x1000 + 54: return wxT("LVM_SETEXTENDEDLISTVIEWSTYLE");
        case 0x1000 + 55: return wxT("LVM_GETEXTENDEDLISTVIEWSTYLE");
        case 0x1000 + 56: return wxT("LVM_GETSUBITEMRECT");
        case 0x1000 + 57: return wxT("LVM_SUBITEMHITTEST");
        case 0x1000 + 58: return wxT("LVM_SETCOLUMNORDERARRAY");
        case 0x1000 + 59: return wxT("LVM_GETCOLUMNORDERARRAY");
        case 0x1000 + 60: return wxT("LVM_SETHOTITEM");
        case 0x1000 + 61: return wxT("LVM_GETHOTITEM");
        case 0x1000 + 62: return wxT("LVM_SETHOTCURSOR");
        case 0x1000 + 63: return wxT("LVM_GETHOTCURSOR");
        case 0x1000 + 64: return wxT("LVM_APPROXIMATEVIEWRECT");
        case 0x1000 + 65: return wxT("LVM_SETWORKAREA");

        // tree view
        case 0x1100 + 0: return wxT("TVM_INSERTITEMA");
        case 0x1100 + 50: return wxT("TVM_INSERTITEMW");
        case 0x1100 + 1: return wxT("TVM_DELETEITEM");
        case 0x1100 + 2: return wxT("TVM_EXPAND");
        case 0x1100 + 4: return wxT("TVM_GETITEMRECT");
        case 0x1100 + 5: return wxT("TVM_GETCOUNT");
        case 0x1100 + 6: return wxT("TVM_GETINDENT");
        case 0x1100 + 7: return wxT("TVM_SETINDENT");
        case 0x1100 + 8: return wxT("TVM_GETIMAGELIST");
        case 0x1100 + 9: return wxT("TVM_SETIMAGELIST");
        case 0x1100 + 10: return wxT("TVM_GETNEXTITEM");
        case 0x1100 + 11: return wxT("TVM_SELECTITEM");
        case 0x1100 + 12: return wxT("TVM_GETITEMA");
        case 0x1100 + 62: return wxT("TVM_GETITEMW");
        case 0x1100 + 13: return wxT("TVM_SETITEMA");
        case 0x1100 + 63: return wxT("TVM_SETITEMW");
        case 0x1100 + 14: return wxT("TVM_EDITLABELA");
        case 0x1100 + 65: return wxT("TVM_EDITLABELW");
        case 0x1100 + 15: return wxT("TVM_GETEDITCONTROL");
        case 0x1100 + 16: return wxT("TVM_GETVISIBLECOUNT");
        case 0x1100 + 17: return wxT("TVM_HITTEST");
        case 0x1100 + 18: return wxT("TVM_CREATEDRAGIMAGE");
        case 0x1100 + 19: return wxT("TVM_SORTCHILDREN");
        case 0x1100 + 20: return wxT("TVM_ENSUREVISIBLE");
        case 0x1100 + 21: return wxT("TVM_SORTCHILDRENCB");
        case 0x1100 + 22: return wxT("TVM_ENDEDITLABELNOW");
        case 0x1100 + 23: return wxT("TVM_GETISEARCHSTRINGA");
        case 0x1100 + 64: return wxT("TVM_GETISEARCHSTRINGW");
        case 0x1100 + 24: return wxT("TVM_SETTOOLTIPS");
        case 0x1100 + 25: return wxT("TVM_GETTOOLTIPS");

        // header
        case 0x1200 + 0: return wxT("HDM_GETITEMCOUNT");
        case 0x1200 + 1: return wxT("HDM_INSERTITEMA");
        case 0x1200 + 10: return wxT("HDM_INSERTITEMW");
        case 0x1200 + 2: return wxT("HDM_DELETEITEM");
        case 0x1200 + 3: return wxT("HDM_GETITEMA");
        case 0x1200 + 11: return wxT("HDM_GETITEMW");
        case 0x1200 + 4: return wxT("HDM_SETITEMA");
        case 0x1200 + 12: return wxT("HDM_SETITEMW");
        case 0x1200 + 5: return wxT("HDM_LAYOUT");
        case 0x1200 + 6: return wxT("HDM_HITTEST");
        case 0x1200 + 7: return wxT("HDM_GETITEMRECT");
        case 0x1200 + 8: return wxT("HDM_SETIMAGELIST");
        case 0x1200 + 9: return wxT("HDM_GETIMAGELIST");
        case 0x1200 + 15: return wxT("HDM_ORDERTOINDEX");
        case 0x1200 + 16: return wxT("HDM_CREATEDRAGIMAGE");
        case 0x1200 + 17: return wxT("HDM_GETORDERARRAY");
        case 0x1200 + 18: return wxT("HDM_SETORDERARRAY");
        case 0x1200 + 19: return wxT("HDM_SETHOTDIVIDER");

        // tab control
        case 0x1300 + 2: return wxT("TCM_GETIMAGELIST");
        case 0x1300 + 3: return wxT("TCM_SETIMAGELIST");
        case 0x1300 + 4: return wxT("TCM_GETITEMCOUNT");
        case 0x1300 + 5: return wxT("TCM_GETITEMA");
        case 0x1300 + 60: return wxT("TCM_GETITEMW");
        case 0x1300 + 6: return wxT("TCM_SETITEMA");
        case 0x1300 + 61: return wxT("TCM_SETITEMW");
        case 0x1300 + 7: return wxT("TCM_INSERTITEMA");
        case 0x1300 + 62: return wxT("TCM_INSERTITEMW");
        case 0x1300 + 8: return wxT("TCM_DELETEITEM");
        case 0x1300 + 9: return wxT("TCM_DELETEALLITEMS");
        case 0x1300 + 10: return wxT("TCM_GETITEMRECT");
        case 0x1300 + 11: return wxT("TCM_GETCURSEL");
        case 0x1300 + 12: return wxT("TCM_SETCURSEL");
        case 0x1300 + 13: return wxT("TCM_HITTEST");
        case 0x1300 + 14: return wxT("TCM_SETITEMEXTRA");
        case 0x1300 + 40: return wxT("TCM_ADJUSTRECT");
        case 0x1300 + 41: return wxT("TCM_SETITEMSIZE");
        case 0x1300 + 42: return wxT("TCM_REMOVEIMAGE");
        case 0x1300 + 43: return wxT("TCM_SETPADDING");
        case 0x1300 + 44: return wxT("TCM_GETROWCOUNT");
        case 0x1300 + 45: return wxT("TCM_GETTOOLTIPS");
        case 0x1300 + 46: return wxT("TCM_SETTOOLTIPS");
        case 0x1300 + 47: return wxT("TCM_GETCURFOCUS");
        case 0x1300 + 48: return wxT("TCM_SETCURFOCUS");
        case 0x1300 + 49: return wxT("TCM_SETMINTABWIDTH");
        case 0x1300 + 50: return wxT("TCM_DESELECTALL");

        // toolbar
        case WM_USER+1000+1: return wxT("TB_ENABLEBUTTON");
        case WM_USER+1000+2: return wxT("TB_CHECKBUTTON");
        case WM_USER+1000+3: return wxT("TB_PRESSBUTTON");
        case WM_USER+1000+4: return wxT("TB_HIDEBUTTON");
        case WM_USER+1000+5: return wxT("TB_INDETERMINATE");
        case WM_USER+1000+9: return wxT("TB_ISBUTTONENABLED");
        case WM_USER+1000+10: return wxT("TB_ISBUTTONCHECKED");
        case WM_USER+1000+11: return wxT("TB_ISBUTTONPRESSED");
        case WM_USER+1000+12: return wxT("TB_ISBUTTONHIDDEN");
        case WM_USER+1000+13: return wxT("TB_ISBUTTONINDETERMINATE");
        case WM_USER+1000+17: return wxT("TB_SETSTATE");
        case WM_USER+1000+18: return wxT("TB_GETSTATE");
        case WM_USER+1000+19: return wxT("TB_ADDBITMAP");
        case WM_USER+1000+20: return wxT("TB_ADDBUTTONS");
        case WM_USER+1000+21: return wxT("TB_INSERTBUTTON");
        case WM_USER+1000+22: return wxT("TB_DELETEBUTTON");
        case WM_USER+1000+23: return wxT("TB_GETBUTTON");
        case WM_USER+1000+24: return wxT("TB_BUTTONCOUNT");
        case WM_USER+1000+25: return wxT("TB_COMMANDTOINDEX");
        case WM_USER+1000+26: return wxT("TB_SAVERESTOREA");
        case WM_USER+1000+76: return wxT("TB_SAVERESTOREW");
        case WM_USER+1000+27: return wxT("TB_CUSTOMIZE");
        case WM_USER+1000+28: return wxT("TB_ADDSTRINGA");
        case WM_USER+1000+77: return wxT("TB_ADDSTRINGW");
        case WM_USER+1000+29: return wxT("TB_GETITEMRECT");
        case WM_USER+1000+30: return wxT("TB_BUTTONSTRUCTSIZE");
        case WM_USER+1000+31: return wxT("TB_SETBUTTONSIZE");
        case WM_USER+1000+32: return wxT("TB_SETBITMAPSIZE");
        case WM_USER+1000+33: return wxT("TB_AUTOSIZE");
        case WM_USER+1000+35: return wxT("TB_GETTOOLTIPS");
        case WM_USER+1000+36: return wxT("TB_SETTOOLTIPS");
        case WM_USER+1000+37: return wxT("TB_SETPARENT");
        case WM_USER+1000+39: return wxT("TB_SETROWS");
        case WM_USER+1000+40: return wxT("TB_GETROWS");
        case WM_USER+1000+42: return wxT("TB_SETCMDID");
        case WM_USER+1000+43: return wxT("TB_CHANGEBITMAP");
        case WM_USER+1000+44: return wxT("TB_GETBITMAP");
        case WM_USER+1000+45: return wxT("TB_GETBUTTONTEXTA");
        case WM_USER+1000+75: return wxT("TB_GETBUTTONTEXTW");
        case WM_USER+1000+46: return wxT("TB_REPLACEBITMAP");
        case WM_USER+1000+47: return wxT("TB_SETINDENT");
        case WM_USER+1000+48: return wxT("TB_SETIMAGELIST");
        case WM_USER+1000+49: return wxT("TB_GETIMAGELIST");
        case WM_USER+1000+50: return wxT("TB_LOADIMAGES");
        case WM_USER+1000+51: return wxT("TB_GETRECT");
        case WM_USER+1000+52: return wxT("TB_SETHOTIMAGELIST");
        case WM_USER+1000+53: return wxT("TB_GETHOTIMAGELIST");
        case WM_USER+1000+54: return wxT("TB_SETDISABLEDIMAGELIST");
        case WM_USER+1000+55: return wxT("TB_GETDISABLEDIMAGELIST");
        case WM_USER+1000+56: return wxT("TB_SETSTYLE");
        case WM_USER+1000+57: return wxT("TB_GETSTYLE");
        case WM_USER+1000+58: return wxT("TB_GETBUTTONSIZE");
        case WM_USER+1000+59: return wxT("TB_SETBUTTONWIDTH");
        case WM_USER+1000+60: return wxT("TB_SETMAXTEXTROWS");
        case WM_USER+1000+61: return wxT("TB_GETTEXTROWS");
        case WM_USER+1000+41: return wxT("TB_GETBITMAPFLAGS");
    }

    static wxString s_szBuf;
    s_szBuf.Printf(wxT("<unknown message = %d>"), nMessage);
    return s_szBuf.c_str();

} // end of wxGetMessageName

#endif // __WXDEBUG__

// Unused?
#if 0
static void TranslateKbdEventToMouse(
  wxWindow*                         pWin
, int*                              pX
, int*                              pY
, ULONG*                            pFlags
)
{
    //
    // Construct the key mask
    ULONG&                          fwKeys = *pFlags;

    fwKeys = VK_BUTTON2;
    if ((::WinGetKeyState(HWND_DESKTOP, VK_CTRL) & 0x100) != 0)
        fwKeys |= VK_CTRL;
    if ((::WinGetKeyState(HWND_DESKTOP, VK_SHIFT) & 0x100) != 0)
        fwKeys |= VK_SHIFT;

    //
    // Simulate right mouse button click
    //
    POINTL                          vPoint;

    ::WinQueryMsgPos(vHabmain, &vPoint);
    *pX = vPoint.x;
    *pY = vPoint.y;

    pWin->ScreenToClient(pX, pY);
} // end of TranslateKbdEventToMouse
#endif

// Find the wxWindow at the current mouse position, returning the mouse
// position.
wxWindow* wxFindWindowAtPointer(wxPoint& WXUNUSED(rPt))
{
    return wxFindWindowAtPoint(wxGetMousePosition());
}

wxWindow* wxFindWindowAtPoint(const wxPoint& rPt)
{
    POINTL vPt2;

    vPt2.x = rPt.x;
    vPt2.y = rPt.y;

    HWND      hWndHit = ::WinWindowFromPoint(HWND_DESKTOP, &vPt2, FALSE);
    wxWindow* pWin = wxFindWinFromHandle((WXHWND)hWndHit) ;
    HWND      hWnd = hWndHit;

    //
    // Try to find a window with a wxWindow associated with it
    //
    while (!pWin && (hWnd != 0))
    {
        hWnd = ::WinQueryWindow(hWnd, QW_PARENT);
        pWin = wxFindWinFromHandle((WXHWND)hWnd) ;
    }
    return pWin;
}

// Get the current mouse position.
wxPoint wxGetMousePosition()
{
    POINTL vPt;

    ::WinQueryPointerPos(HWND_DESKTOP, &vPt);
    return wxPoint(vPt.x, vPt.y);
}

wxMouseState wxGetMouseState()
{
    wxMouseState ms;
    wxPoint pt = wxGetMousePosition();
    ms.SetX(pt.x);
    ms.SetY(pt.y);
    ms.SetLeftDown(IsKeyDown(VK_BUTTON1));
    ms.SetMiddleDown(IsKeyDown(VK_BUTTON3));
    ms.SetRightDown(IsKeyDown(VK_BUTTON2));
    ms.SetControlDown(IsCtrlDown());
    ms.SetShiftDown(IsShiftDown());
    ms.SetAltDown(IsKeyDown(VK_ALT)|IsKeyDown(VK_ALTGRAF));
    ms.SetMetaDown(IsKeyDown(VK_ALTGRAF));
    return ms;
}


wxWindowOS2* FindWindowForMouseEvent( wxWindow* pWin,
                                      short*    WXUNUSED(pnX),
                                      short*    WXUNUSED(pnY) )
{
    HWND   hWnd = GetHwndOf(pWin);
    HWND   hWndUnderMouse;
    POINTL vPoint;
    BOOL   rcEnabled = FALSE;
    BOOL   rcVisible = FALSE;

    ::WinQueryPointerPos(HWND_DESKTOP, &vPoint);
    hWndUnderMouse = ::WinWindowFromPoint(HWND_DESKTOP, &vPoint, TRUE);
    if (hWndUnderMouse != HWND_DESKTOP)
    {
        wxWindow*                   pWinUnderMouse = wxFindWinFromHandle((WXHWND)hWndUnderMouse);

        if (pWinUnderMouse)
        {
            wxWindowList::compatibility_iterator current = pWinUnderMouse->GetChildren().GetFirst();
            wxWindow*               pGrandChild = NULL;
            RECTL                   vRect;
            POINTL                  vPoint2;

            ::WinMapWindowPoints(HWND_DESKTOP, hWndUnderMouse, &vPoint, 1);
            //
            // Find a child window mouse might be under
            //
            while (current)
            {
                wxWindow*                   pChild = current->GetData();

                vPoint2.x = vPoint.x;
                vPoint2.y = vPoint.y;
                ::WinMapWindowPoints(hWndUnderMouse, pChild->GetHWND(), &vPoint2, 1);
                ::WinQueryWindowRect(pChild->GetHWND(), &vRect);
                if (::WinPtInRect(vHabmain, &vRect, &vPoint2))
                {
                    if (pChild->IsTopLevel())
                    {
                        POINTL                  vPoint3;
                        wxWindowList::compatibility_iterator current2 =pChild->GetChildren().GetFirst();

                        while (current2)
                        {
                            wxWindow*           pGrandChild = current2->GetData();

                            vPoint3.x = vPoint2.x;
                            vPoint3.y = vPoint2.y;
                            ::WinMapWindowPoints( pChild->GetHWND()
                                                 ,pGrandChild->GetHWND()
                                                 ,&vPoint3
                                                 ,1
                                                );
                            ::WinQueryWindowRect(pGrandChild->GetHWND(), &vRect);
                            if (::WinPtInRect(vHabmain, &vRect, &vPoint3))
                            {
                                hWndUnderMouse = GetHwndOf(pGrandChild);
                                pWinUnderMouse = pGrandChild;
                                break;
                            }
                            current2 = current2->GetNext();
                        }
                        if (pGrandChild)
                            break;
                    }
                    hWndUnderMouse = GetHwndOf(pChild);
                    pWinUnderMouse = pChild;
                    rcVisible = ::WinIsWindowVisible(hWndUnderMouse);
                    rcEnabled = ::WinIsWindowEnabled(hWndUnderMouse);
                    if (rcVisible && rcEnabled)
                        break;
                }
                current = current->GetNext();
            }
        }
    }
    rcVisible = ::WinIsWindowVisible(hWndUnderMouse);
    rcEnabled = ::WinIsWindowEnabled(hWndUnderMouse);


    //
    // Check that we have a child window which is susceptible to receive mouse
    // events: for this it must be shown and enabled
    //
    if ( hWndUnderMouse &&
         hWndUnderMouse != hWnd &&
         rcVisible && rcEnabled)
    {
        wxWindow*                       pWinUnderMouse = wxFindWinFromHandle((WXHWND)hWndUnderMouse);

        if (pWinUnderMouse)
        {
            //
            // Translate the mouse coords to the other window coords
            //
            pWin = pWinUnderMouse;
        }
    }
    return pWin;
} // end of FindWindowForMouseEvent
