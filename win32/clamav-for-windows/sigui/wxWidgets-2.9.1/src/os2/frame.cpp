/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/frame.cpp
// Purpose:     wxFrame
// Author:      David Webster
// Modified by:
// Created:     10/27/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/object.h"
    #include "wx/dynarray.h"
    #include "wx/list.h"
    #include "wx/hash.h"
    #include "wx/string.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/event.h"
    #include "wx/frame.h"
    #include "wx/menu.h"
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/dialog.h"
    #include "wx/settings.h"
    #include "wx/dcclient.h"
    #include "wx/mdi.h"
    #include "wx/toolbar.h"
    #include "wx/statusbr.h"
    #include "wx/menuitem.h"
#endif // WX_PRECOMP

#include "wx/os2/private.h"

// ----------------------------------------------------------------------------
// globals
// ----------------------------------------------------------------------------

#if wxUSE_MENUS_NATIVE
extern wxMenu *wxCurrentPopupMenu;
#endif

// ----------------------------------------------------------------------------
// event tables
// ----------------------------------------------------------------------------

BEGIN_EVENT_TABLE(wxFrame, wxFrameBase)
    EVT_SYS_COLOUR_CHANGED(wxFrame::OnSysColourChanged)
END_EVENT_TABLE()

IMPLEMENT_DYNAMIC_CLASS(wxFrame, wxWindow)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// static class members
// ----------------------------------------------------------------------------
#if wxUSE_STATUSBAR

#if wxUSE_NATIVE_STATUSBAR
    bool wxFrame::m_bUseNativeStatusBar = true;
#else
    bool wxFrame::m_bUseNativeStatusBar = false;
#endif

#endif //wxUSE_STATUSBAR

// ----------------------------------------------------------------------------
// creation/destruction
// ----------------------------------------------------------------------------

void wxFrame::Init()
{
    m_nFsStatusBarFields = 0;
    m_nFsStatusBarHeight = 0;
    m_nFsToolBarHeight   = 0;
    m_hWndToolTip        = 0L;
    m_bWasMinimized      = false;


    m_frameMenuBar   = NULL;
    m_frameToolBar   = NULL;
    m_frameStatusBar = NULL;

    m_hTitleBar = NULLHANDLE;
    m_hHScroll  = NULLHANDLE;
    m_hVScroll  = NULLHANDLE;

    //
    // Initialize SWP's
    //
    memset(&m_vSwpTitleBar, 0, sizeof(SWP));
    memset(&m_vSwpMenuBar, 0, sizeof(SWP));
    memset(&m_vSwpHScroll, 0, sizeof(SWP));
    memset(&m_vSwpVScroll, 0, sizeof(SWP));
    memset(&m_vSwpStatusBar, 0, sizeof(SWP));
    memset(&m_vSwpToolBar, 0, sizeof(SWP));
    m_bIconized = false;

} // end of wxFrame::Init

bool wxFrame::Create( wxWindow*       pParent,
                      wxWindowID      vId,
                      const wxString& rsTitle,
                      const wxPoint&  rPos,
                      const wxSize&   rSize,
                      long            lStyle,
                      const wxString& rsName )
{
    if (!wxTopLevelWindow::Create( pParent
                                  ,vId
                                  ,rsTitle
                                  ,rPos
                                  ,rSize
                                  ,lStyle
                                  ,rsName
                                 ))
        return false;
    return true;
} // end of wxFrame::Create

wxFrame::~wxFrame()
{
    SendDestroyEvent();

    DeleteAllBars();
} // end of wxFrame::~wxFrame

//
// Get size *available for subwindows* i.e. excluding menu bar, toolbar etc.
//
void wxFrame::DoGetClientSize(
  int*                              pX
, int*                              pY
) const
{
    wxTopLevelWindow::DoGetClientSize( pX
                                      ,pY
                                     );
    //
    // No need to use statusbar code as in WIN32 as the FORMATFRAME
    // window procedure ensures PM knows about the new frame client
    // size internally.  A ::WinQueryWindowRect (that is called in
    // wxWindow's GetClient size from above) is all that is needed!
    //
} // end of wxFrame::DoGetClientSize

//
// Set the client size (i.e. leave the calculation of borders etc.
// to wxWidgets)
//
void wxFrame::DoSetClientSize(
  int                               nWidth
, int                               nHeight
)
{
    //
    // Statusbars are not part of the OS/2 Client but parent frame
    // so no statusbar consideration
    //
    wxTopLevelWindow::DoSetClientSize( nWidth
                                      ,nHeight
                                     );
} // end of wxFrame::DoSetClientSize

// ----------------------------------------------------------------------------
// wxFrame: various geometry-related functions
// ----------------------------------------------------------------------------

void wxFrame::Raise()
{
    wxFrameBase::Raise();
    ::WinSetWindowPos( (HWND) GetParent()->GetHWND()
                      ,HWND_TOP
                      ,0
                      ,0
                      ,0
                      ,0
                      ,SWP_ZORDER
                     );
}

#if wxUSE_STATUSBAR
wxStatusBar* wxFrame::OnCreateStatusBar(
  int                               nNumber
, long                              lulStyle
, wxWindowID                        vId
, const wxString&                   rName
)
{
    wxStatusBar*                    pStatusBar = NULL;
    wxString                        sError;

    pStatusBar = wxFrameBase::OnCreateStatusBar( nNumber
                                                ,lulStyle
                                                ,vId
                                                ,rName
                                                 );

    if( !pStatusBar )
        return NULL;

    wxClientDC                      vDC(pStatusBar);
    int                             nY;

    //
    // Set the height according to the font and the border size
    //
    vDC.SetFont(pStatusBar->GetFont()); // Screws up the menues for some reason
    vDC.GetTextExtent( wxT("X")
                      ,NULL
                      ,&nY
                     );

    int                             nHeight = ((11 * nY) / 10 + 2 * pStatusBar->GetBorderY());

    pStatusBar->SetSize( wxDefaultCoord
                        ,wxDefaultCoord
                        ,wxDefaultCoord
                        ,nHeight
                       );

    ::WinSetParent( pStatusBar->GetHWND(), m_hFrame, FALSE );
    ::WinSetOwner( pStatusBar->GetHWND(), m_hFrame);
    //
    // to show statusbar
    //
    if(::WinIsWindowShowing(m_hFrame))
        ::WinSendMsg(m_hFrame, WM_UPDATEFRAME, (MPARAM)~0, 0);

    return pStatusBar;
} // end of wxFrame::OnCreateStatusBar

void wxFrame::PositionStatusBar()
{
    SWP                             vSwp;
    ERRORID                         vError;
    wxString                        sError;

    //
    // Native status bar positions itself
    //
    if (m_frameStatusBar)
    {
        int                         nWidth;
        int                         nY;
        int                         nStatbarWidth;
        int                         nStatbarHeight;
        RECTL                       vRect;
        RECTL                       vFRect;

        ::WinQueryWindowRect(m_hFrame, &vRect);
        nY = vRect.yTop;
        ::WinMapWindowPoints(m_hFrame, HWND_DESKTOP, (PPOINTL)&vRect, 2);
        vFRect = vRect;
        ::WinCalcFrameRect(m_hFrame, &vRect, TRUE);
        nWidth = vRect.xRight - vRect.xLeft;
        nY = nY - (vRect.yBottom - vFRect.yBottom);

        m_frameStatusBar->GetSize( &nStatbarWidth
                                  ,&nStatbarHeight
                                 );

        nY= nY - nStatbarHeight;
        //
        // Since we wish the status bar to be directly under the client area,
        // we use the adjusted sizes without using wxSIZE_NO_ADJUSTMENTS.
        //
        m_frameStatusBar->SetSize( vRect.xLeft - vFRect.xLeft
                                  ,nY
                                  ,nWidth
                                  ,nStatbarHeight
                                 );
        if (!::WinQueryWindowPos(m_frameStatusBar->GetHWND(), &vSwp))
        {
            vError = ::WinGetLastError(vHabmain);
            sError = wxPMErrorToStr(vError);
            wxLogError(wxT("Error setting parent for StatusBar. Error: %s\n"), sError.c_str());
            return;
        }
    }
} // end of wxFrame::PositionStatusBar
#endif // wxUSE_STATUSBAR

#if wxUSE_TOOLBAR
wxToolBar* wxFrame::OnCreateToolBar( long lStyle, wxWindowID vId, const wxString& rsName )
{
    wxToolBar*                      pToolBar = wxFrameBase::OnCreateToolBar( lStyle
                                                                            ,vId
                                                                            ,rsName
                                                                           );

    ::WinSetParent( pToolBar->GetHWND(), m_hFrame, FALSE);
    ::WinSetOwner( pToolBar->GetHWND(), m_hFrame);
    return pToolBar;
} // end of WinGuiBase_CFrame::OnCreateToolBar
#endif

#if wxUSE_MENUS_NATIVE
void wxFrame::DetachMenuBar()
{
    if (m_frameMenuBar)
    {
        m_frameMenuBar->Detach();
        m_frameMenuBar = NULL;
    }
} // end of wxFrame::DetachMenuBar

void wxFrame::SetMenuBar(
  wxMenuBar*                        pMenuBar
)
{
    wxString                        sError;

    if (!pMenuBar)
    {
        DetachMenuBar();

        //
        // Actually remove the menu from the frame
        //
        m_hMenu = (WXHMENU)0;
        InternalSetMenuBar();
    }
    else // set new non NULL menu bar
    {
        m_frameMenuBar = NULL;

        //
        // Can set a menubar several times.
        // TODO: how to prevent a memory leak if you have a currently-unattached
        // menubar? wxWidgets assumes that the frame will delete the menu (otherwise
        // there are problems for MDI).
        //
        if (pMenuBar->GetHMenu())
        {
            m_hMenu = pMenuBar->GetHMenu();
        }
        else
        {
            pMenuBar->Detach();
            m_hMenu = pMenuBar->Create();
            if (!m_hMenu)
                return;
        }
        InternalSetMenuBar();
        m_frameMenuBar = pMenuBar;
        pMenuBar->Attach((wxFrame*)this);
    }
} // end of wxFrame::SetMenuBar

void wxFrame::AttachMenuBar(
  wxMenuBar*                        pMenubar
)
{
    wxFrameBase::AttachMenuBar(pMenubar);

    m_frameMenuBar = pMenubar;

    if (!pMenubar)
    {
        //
        // Actually remove the menu from the frame
        //
        m_hMenu = (WXHMENU)0;
        InternalSetMenuBar();
    }
    else // Set new non NULL menu bar
    {
        //
        // Can set a menubar several times.
        //
        if (pMenubar->GetHMenu())
        {
            m_hMenu = pMenubar->GetHMenu();
        }
        else
        {
            if (pMenubar->IsAttached())
                pMenubar->Detach();

            m_hMenu = pMenubar->Create();

            if (!m_hMenu)
                return;
        }
        InternalSetMenuBar();
    }
} // end of wxFrame::AttachMenuBar

void wxFrame::InternalSetMenuBar()
{
    ERRORID                         vError;
    wxString                        sError;
    //
    // Set the parent and owner of the menubar to be the frame
    //
    if (!::WinSetParent(m_hMenu, m_hFrame, FALSE))
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
        wxLogError(wxT("Error setting parent for submenu. Error: %s\n"), sError.c_str());
    }

    if (!::WinSetOwner(m_hMenu, m_hFrame))
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
        wxLogError(wxT("Error setting parent for submenu. Error: %s\n"), sError.c_str());
    }
    ::WinSendMsg(m_hFrame, WM_UPDATEFRAME, (MPARAM)FCF_MENU, (MPARAM)0);
} // end of wxFrame::InternalSetMenuBar
#endif // wxUSE_MENUS_NATIVE

//
// Responds to colour changes, and passes event on to children
//
void wxFrame::OnSysColourChanged(
  wxSysColourChangedEvent&          rEvent
)
{
    SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_APPWORKSPACE));
    Refresh();

#if wxUSE_STATUSBAR
    if (m_frameStatusBar)
    {
        wxSysColourChangedEvent     vEvent2;

        vEvent2.SetEventObject(m_frameStatusBar);
        m_frameStatusBar->HandleWindowEvent(vEvent2);
    }
#endif //wxUSE_STATUSBAR

    //
    // Propagate the event to the non-top-level children
    //
    wxWindow::OnSysColourChanged(rEvent);
} // end of wxFrame::OnSysColourChanged

// Pass true to show full screen, false to restore.
bool wxFrame::ShowFullScreen( bool bShow, long lStyle )
{
    if (bShow)
    {
        if (IsFullScreen())
            return false;

        m_bFsIsShowing = true;
        m_lFsStyle = lStyle;

#if wxUSE_TOOLBAR
        wxToolBar*                  pTheToolBar = GetToolBar();
#endif //wxUSE_TOOLBAR

#if wxUSE_STATUSBAR
        wxStatusBar*                pTheStatusBar = GetStatusBar();
#endif //wxUSE_STATUSBAR

        int                         nDummyWidth;

#if wxUSE_TOOLBAR
        if (pTheToolBar)
            pTheToolBar->GetSize(&nDummyWidth, &m_nFsToolBarHeight);
#endif //wxUSE_TOOLBAR

#if wxUSE_STATUSBAR
        if (pTheStatusBar)
            pTheStatusBar->GetSize(&nDummyWidth, &m_nFsStatusBarHeight);
#endif //wxUSE_STATUSBAR

#if wxUSE_TOOLBAR
        //
        // Zap the toolbar, menubar, and statusbar
        //
        if ((lStyle & wxFULLSCREEN_NOTOOLBAR) && pTheToolBar)
        {
            pTheToolBar->SetSize(wxDefaultCoord,0);
            pTheToolBar->Show(false);
        }
#endif //wxUSE_TOOLBAR

        if (lStyle & wxFULLSCREEN_NOMENUBAR)
        {
            ::WinSetParent(m_hMenu, m_hFrame, FALSE);
            ::WinSetOwner(m_hMenu, m_hFrame);
            ::WinSendMsg((HWND)m_hFrame, WM_UPDATEFRAME, (MPARAM)FCF_MENU, (MPARAM)0);
        }

#if wxUSE_STATUSBAR
        //
        // Save the number of fields in the statusbar
        //
        if ((lStyle & wxFULLSCREEN_NOSTATUSBAR) && pTheStatusBar)
        {
            m_nFsStatusBarFields = pTheStatusBar->GetFieldsCount();
            SetStatusBar(NULL);
            delete pTheStatusBar;
        }
        else
            m_nFsStatusBarFields = 0;
#endif //wxUSE_STATUSBAR

        //
        // Zap the frame borders
        //

        //
        // Save the 'normal' window style
        //
        m_lFsOldWindowStyle = ::WinQueryWindowULong(m_hFrame, QWL_STYLE);

        //
        // Save the old position, width & height, maximize state
        //
        m_vFsOldSize = GetRect();
        m_bFsIsMaximized = IsMaximized();

        //
        // Decide which window style flags to turn off
        //
        LONG lNewStyle = m_lFsOldWindowStyle;
        LONG lOffFlags = 0;

        if (lStyle & wxFULLSCREEN_NOBORDER)
            lOffFlags |= FCF_BORDER;
        if (lStyle & wxFULLSCREEN_NOCAPTION)
            lOffFlags |= (FCF_TASKLIST | FCF_SYSMENU);

        lNewStyle &= (~lOffFlags);

        //
        // Change our window style to be compatible with full-screen mode
        //
        ::WinSetWindowULong((HWND)m_hFrame, QWL_STYLE, (ULONG)lNewStyle);

        //
        // Resize to the size of the desktop
        int                         nWidth;
        int                         nHeight;

        RECTL                       vRect;

        ::WinQueryWindowRect(HWND_DESKTOP, &vRect);
        nWidth = vRect.xRight - vRect.xLeft;
        //
        // Remember OS/2 is backwards!
        //
        nHeight = vRect.yTop - vRect.yBottom;

        SetSize( nWidth, nHeight);

        //
        // Now flush the window style cache and actually go full-screen
        //
        ::WinSetWindowPos( (HWND) GetParent()->GetHWND()
                          ,HWND_TOP
                          ,0
                          ,0
                          ,nWidth
                          ,nHeight
                          ,SWP_SIZE | SWP_SHOW
                         );

        wxSize sz( nWidth, nHeight );
        wxSizeEvent vEvent( sz, GetId() );

        HandleWindowEvent(vEvent);
        return true;
    }
    else
    {
        if (!IsFullScreen())
            return false;

        m_bFsIsShowing = false;

#if wxUSE_TOOLBAR
        wxToolBar*                  pTheToolBar = GetToolBar();

        //
        // Restore the toolbar, menubar, and statusbar
        //
        if (pTheToolBar && (m_lFsStyle & wxFULLSCREEN_NOTOOLBAR))
        {
            pTheToolBar->SetSize(wxDefaultCoord, m_nFsToolBarHeight);
            pTheToolBar->Show(true);
        }
#endif //wxUSE_TOOLBAR

#if wxUSE_STATUSBAR
        if ((m_lFsStyle & wxFULLSCREEN_NOSTATUSBAR) && (m_nFsStatusBarFields > 0))
        {
            CreateStatusBar(m_nFsStatusBarFields);
//          PositionStatusBar();
        }
#endif //wxUSE_STATUSBAR

        if ((m_lFsStyle & wxFULLSCREEN_NOMENUBAR) && (m_hMenu != 0))
        {
            ::WinSetParent(m_hMenu, m_hFrame, FALSE);
            ::WinSetOwner(m_hMenu, m_hFrame);
            ::WinSendMsg(m_hFrame, WM_UPDATEFRAME, (MPARAM)FCF_MENU, (MPARAM)0);
        }
        Maximize(m_bFsIsMaximized);

        ::WinSetWindowULong( m_hFrame
                            ,QWL_STYLE
                            ,(ULONG)m_lFsOldWindowStyle
                           );
        ::WinSetWindowPos( (HWND) GetParent()->GetHWND()
                          ,HWND_TOP
                          ,m_vFsOldSize.x
                          ,m_vFsOldSize.y
                          ,m_vFsOldSize.width
                          ,m_vFsOldSize.height
                          ,SWP_SIZE | SWP_SHOW
                         );
    }
    return wxFrameBase::ShowFullScreen(bShow, lStyle);
} // end of wxFrame::ShowFullScreen

//
// Frame window
//
// ----------------------------------------------------------------------------
// wxFrame size management: we exclude the areas taken by menu/status/toolbars
// from the client area, so the client area is what's really available for the
// frame contents
// ----------------------------------------------------------------------------

// Checks if there is a toolbar, and returns the first free client position
wxPoint wxFrame::GetClientAreaOrigin() const
{
    wxPoint                         vPoint = wxTopLevelWindow::GetClientAreaOrigin();

    //
    // In OS/2 the toolbar and statusbar are frame extensions so there is no
    // adjustment.  The client is supposedly resized for a toolbar in OS/2
    // as it is for the status bar.
    //
    return vPoint;
} // end of wxFrame::GetClientAreaOrigin

// ----------------------------------------------------------------------------
// tool/status bar stuff
// ----------------------------------------------------------------------------

#if wxUSE_TOOLBAR

wxToolBar* wxFrame::CreateToolBar(
  long                              lStyle
, wxWindowID                        vId
, const wxString&                   rName
)
{
    if (wxFrameBase::CreateToolBar( lStyle
                                   ,vId
                                   ,rName
                                  ))
    {
        PositionToolBar();
    }
    return m_frameToolBar;
} // end of wxFrame::CreateToolBar

void wxFrame::PositionToolBar()
{
    wxToolBar*                      pToolBar = GetToolBar();
    wxCoord                         vWidth;
    wxCoord                         vHeight;
    wxCoord                         vTWidth;
    wxCoord                         vTHeight;

    if (!pToolBar)
        return;

    RECTL                           vRect;
    RECTL                           vFRect;
    wxPoint                         vPos;

    ::WinQueryWindowRect(m_hFrame, &vRect);
    vPos.y = (wxCoord)vRect.yTop;
    ::WinMapWindowPoints(m_hFrame, HWND_DESKTOP, (PPOINTL)&vRect, 2);
    vFRect = vRect;
    ::WinCalcFrameRect(m_hFrame, &vRect, TRUE);

    vPos.y = (wxCoord)(vFRect.yTop - vRect.yTop);
    pToolBar->GetSize( &vTWidth
                      ,&vTHeight
                     );

    if (pToolBar->GetWindowStyleFlag() & wxTB_TOP)
    {
        vWidth = (wxCoord)(vRect.xRight - vRect.xLeft);
        pToolBar->SetSize( vRect.xLeft - vFRect.xLeft
                          ,vPos.y
                          ,vWidth
                          ,vTHeight
                         );
    }
    else if (pToolBar->GetWindowStyleFlag() & wxTB_BOTTOM)
    {
        wxCoord                     vSwidth = 0;
        wxCoord                     vSheight = 0;

        if (m_frameStatusBar)
            m_frameStatusBar->GetSize( &vSwidth
                                      ,&vSheight
                                     );
        vWidth = (wxCoord)(vRect.xRight - vRect.xLeft);
        pToolBar->SetSize( vRect.xLeft - vFRect.xLeft
                          ,vFRect.yTop - vRect.yBottom - vTHeight - vSheight
                          ,vWidth
                          ,vTHeight
                         );
    }
    else if (pToolBar->GetWindowStyleFlag() & wxTB_LEFT)
    {
        wxCoord                     vSwidth = 0;
        wxCoord                     vSheight = 0;

        if (m_frameStatusBar)
            m_frameStatusBar->GetSize( &vSwidth
                                      ,&vSheight
                                     );
        vHeight = (wxCoord)(vRect.yTop - vRect.yBottom);
        pToolBar->SetSize( vRect.xLeft - vRect.xLeft
                          ,vPos.y
                          ,vTWidth
                          ,vHeight - vSheight
                         );
    }
    else
    {
        wxCoord                     vSwidth = 0;
        wxCoord                     vSheight = 0;

        if (m_frameStatusBar)
            m_frameStatusBar->GetSize( &vSwidth
                                      ,&vSheight
                                     );
        vHeight = (wxCoord)(vRect.yTop - vRect.yBottom);
        pToolBar->SetSize( vRect.xRight - vFRect.xLeft - vTWidth
                          ,vPos.y
                          ,vTWidth
                          ,vHeight - vSheight
                         );
    }
    if( ::WinIsWindowShowing(m_hFrame) )
        ::WinSendMsg(m_hFrame, WM_UPDATEFRAME, (MPARAM)~0, 0);
} // end of wxFrame::PositionToolBar
#endif // wxUSE_TOOLBAR

// ----------------------------------------------------------------------------
// frame state (iconized/maximized/...)
// ----------------------------------------------------------------------------

//
// propagate our state change to all child frames: this allows us to emulate X
// Windows behaviour where child frames float independently of the parent one
// on the desktop, but are iconized/restored with it
//
void wxFrame::IconizeChildFrames( bool WXUNUSED(bIconize) )
{
  // FIXME: Generic MDI does not use Frames for the Childs, so this does _not_
  //        work. Possibly, the right thing is simply to eliminate this
  //        functions and all the calls to it from within this file.
#if 0
    for (wxWindowList::Node* pNode = GetChildren().GetFirst();
         pNode;
         pNode = pNode->GetNext() )
    {
        wxWindow*                   pWin = pNode->GetData();
        wxFrame*                    pFrame = wxDynamicCast(pWin, wxFrame);

        if ( pFrame
#if wxUSE_MDI_ARCHITECTURE
                && !wxDynamicCast(pFrame, wxMDIChildFrame)
#endif // wxUSE_MDI_ARCHITECTURE
           )
        {
            //
            // We don't want to restore the child frames which had been
            // iconized even before we were iconized, so save the child frame
            // status when iconizing the parent frame and check it when
            // restoring it.
            //
            if (bIconize)
            {
                pFrame->m_bWasMinimized = pFrame->IsIconized();
            }

            //
            // This test works for both iconizing and restoring
            //
            if (!pFrame->m_bWasMinimized)
                pFrame->Iconize(bIconize);
        }
    }
#endif
} // end of wxFrame::IconizeChildFrames

WXHICON wxFrame::GetDefaultIcon() const
{
    return (WXHICON)(wxSTD_FRAME_ICON ? wxSTD_FRAME_ICON
                                      : wxDEFAULT_FRAME_ICON);
}
// ===========================================================================
// message processing
// ===========================================================================

// ---------------------------------------------------------------------------
// preprocessing
// ---------------------------------------------------------------------------
bool wxFrame::OS2TranslateMessage( WXMSG* pMsg )
{
    //
    // try the menu bar accels
    //
    wxMenuBar* pMenuBar = GetMenuBar();

    if (!pMenuBar)
        return false;

#if wxUSE_ACCEL && wxUSE_MENUS_NATIVE
    const wxAcceleratorTable&       rAcceleratorTable = pMenuBar->GetAccelTable();
    return rAcceleratorTable.Translate(GetHWND(), pMsg);
#else
    return false;
#endif //wxUSE_ACCEL
} // end of wxFrame::OS2TranslateMessage

// ---------------------------------------------------------------------------
// our private (non virtual) message handlers
// ---------------------------------------------------------------------------
bool wxFrame::HandlePaint()
{
    RECTL vRect;

    if (::WinQueryUpdateRect(GetHWND(), &vRect))
    {
        if (m_bIconized)
        {
            //
            // Icons in PM are the same as "pointers"
            //
            const wxIcon&           vIcon = GetIcon();
            HPOINTER                hIcon;

            if (vIcon.Ok())
                hIcon = (HPOINTER)::WinSendMsg(m_hFrame, WM_QUERYICON, 0L, 0L);
            else
                hIcon = (HPOINTER)m_hDefaultIcon;

            //
            // Hold a pointer to the dc so long as the OnPaint() message
            // is being processed
            //
            RECTL                   vRect2;
            HPS                     hPs = ::WinBeginPaint(GetHwnd(), NULLHANDLE, &vRect2);

            //
            // Erase background before painting or we get white background
            //
            OS2DefWindowProc(WM_ERASEBACKGROUND, (MPARAM)hPs, (MPARAM)&vRect2);

            if (hIcon)
            {
                RECTL                           vRect3;

                ::WinQueryWindowRect(GetHwnd(), &vRect3);

                static const int    nIconWidth = 32;
                static const int    nIconHeight = 32;
                int                 nIconX = (int)((vRect3.xRight - nIconWidth)/2);
                int                 nIconY = (int)((vRect3.yBottom + nIconHeight)/2);

                ::WinDrawPointer(hPs, nIconX, nIconY, hIcon, DP_NORMAL);
            }
            ::WinEndPaint(hPs);
        }
        else
        {
            if (!wxWindow::HandlePaint())
            {
                HPS                     hPS;
                RECTL                   vRect;

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

                    ::WinFillRect( hPS
                                  ,&vRect
                                  ,GetBackgroundColour().GetPixel()
                                 );
                    ::WinEndPaint(hPS);
                }
            }
        }
    }

    return true;
} // end of wxFrame::HandlePaint

bool wxFrame::HandleSize( int nX, int nY, WXUINT nId )
{
    bool bProcessed = false;

    switch (nId)
    {
        case kSizeNormal:
            //
            // Only do it it if we were iconized before, otherwise resizing the
            // parent frame has a curious side effect of bringing it under it's
            // children
            if (!m_bIconized )
                break;

            //
            // restore all child frames too
            //
            IconizeChildFrames(false);
            (void)SendIconizeEvent(false);

            //
            // fall through
            //

        case kSizeMax:
            m_bIconized = false;
            break;

        case kSizeMin:
            //
            // Iconize all child frames too
            //
            IconizeChildFrames(true);
            (void)SendIconizeEvent();
            m_bIconized = true;
            break;
    }

    if (!m_bIconized)
    {
        //
        // forward WM_SIZE to status bar control
        //
#if wxUSE_NATIVE_STATUSBAR
        if (m_frameStatusBar && m_frameStatusBar->IsKindOf(CLASSINFO(wxStatusBar95)))
        {
            wxSizeEvent             vEvent( wxSize( nX
                                                   ,nY
                                                  )
                                           ,m_frameStatusBar->GetId()
                                          );

            vEvent.SetEventObject(m_frameStatusBar);
            m_frameStatusBar->OnSize(vEvent);
        }
#endif // wxUSE_NATIVE_STATUSBAR

        PositionStatusBar();
#if  wxUSE_TOOLBAR
        PositionToolBar();
#endif // wxUSE_TOOLBAR

        bProcessed = wxWindow::HandleSize( nX
                                          ,nY
                                          ,nId
                                         );
    }
    return bProcessed;
} // end of wxFrame::HandleSize

bool wxFrame::HandleCommand( WXWORD nId,
                             WXWORD nCmd,
                             WXHWND hControl )
{
    if (hControl)
    {
        //
        // In case it's e.g. a toolbar.
        //
        wxWindow*                   pWin = wxFindWinFromHandle(hControl);

        if (pWin)
            return pWin->OS2Command( nCmd, nId );
    }

    //
    // Handle here commands from menus and accelerators
    //
    if (nCmd == CMDSRC_MENU || nCmd == CMDSRC_ACCELERATOR)
    {
#if wxUSE_MENUS_NATIVE
        if (wxCurrentPopupMenu)
        {
            wxMenu*                 pPopupMenu = wxCurrentPopupMenu;

            wxCurrentPopupMenu = NULL;

            return pPopupMenu->OS2Command( nCmd, nId );
        }
#endif

        if (ProcessCommand(nId))
        {
            return true;
        }
    }
    return false;
} // end of wxFrame::HandleCommand

bool wxFrame::HandleMenuSelect( WXWORD nItem,
                                WXWORD nFlags,
                                WXHMENU hMenu )
{
    if( !nFlags )
    {
        MENUITEM mItem;
        MRESULT  rc;

        rc = ::WinSendMsg(hMenu, MM_QUERYITEM, MPFROM2SHORT(nItem, TRUE), (MPARAM)&mItem);

        if(rc && !(mItem.afStyle & (MIS_SUBMENU | MIS_SEPARATOR)))
        {
            wxMenuEvent                     vEvent(wxEVT_MENU_HIGHLIGHT, nItem);

            vEvent.SetEventObject(this);
            HandleWindowEvent(vEvent); // return value would be ignored by PM
        }
        else
        {
            DoGiveHelp(wxEmptyString, true);
            return false;
        }
    }
    return true;
} // end of wxFrame::HandleMenuSelect

// ---------------------------------------------------------------------------
// Main Frame window proc
// ---------------------------------------------------------------------------
MRESULT EXPENTRY wxFrameMainWndProc( HWND   hWnd,
                                     ULONG  ulMsg,
                                     MPARAM wParam,
                                     MPARAM lParam )
{
    MRESULT  rc = (MRESULT)0;
    bool     bProcessed = false;
    wxFrame* pWnd  = NULL;

    pWnd = (wxFrame*) wxFindWinFromHandle((WXHWND) hWnd);
    switch (ulMsg)
    {
        case WM_QUERYFRAMECTLCOUNT:
            if(pWnd && pWnd->m_fnOldWndProc)
            {
                USHORT              uItemCount = SHORT1FROMMR(pWnd->m_fnOldWndProc(hWnd, ulMsg, wParam, lParam));

                rc = MRFROMSHORT(uItemCount);
            }
            break;

        case WM_FORMATFRAME:
/////////////////////////////////////////////////////////////////////////////////
// Applications that subclass frame controls may find that the frame is already
// subclassed the number of frame controls is variable.
// The WM_FORMATFRAME and WM_QUERYFRAMECTLCOUNT messages must always be
// subclassed by calling the previous window procedure and modifying its result.
////////////////////////////////////////////////////////////////////////////////
            {
                int                 nItemCount;
                int                 i;
                PSWP                pSWP = NULL;
                RECTL               vRectl;
                RECTL               vRstb;
                RECTL               vRtlb;
                int                 nHeight = 0;
                int                 nHeight2 = 0;
                int                 nWidth = 0;

                pSWP = (PSWP)PVOIDFROMMP(wParam);
                nItemCount = SHORT1FROMMR(pWnd->m_fnOldWndProc(hWnd, ulMsg, wParam, lParam));
                if(pWnd->m_frameStatusBar)
                {
                    ::WinQueryWindowRect(pWnd->m_frameStatusBar->GetHWND(), &vRstb);
                    pWnd->m_frameStatusBar->GetSize(NULL, &nHeight);
                }
                if(pWnd->m_frameToolBar)
                {
                    ::WinQueryWindowRect(pWnd->m_frameToolBar->GetHWND(), &vRtlb);
                    pWnd->m_frameToolBar->GetSize(&nWidth, &nHeight2);
                }
                ::WinQueryWindowRect(pWnd->m_hFrame, &vRectl);
                ::WinMapWindowPoints(pWnd->m_hFrame, HWND_DESKTOP, (PPOINTL)&vRectl, 2);
                ::WinCalcFrameRect(pWnd->m_hFrame, &vRectl, TRUE);
                ::WinMapWindowPoints(HWND_DESKTOP, pWnd->m_hFrame, (PPOINTL)&vRectl, 2);
                for(i = 0; i < nItemCount; i++)
                {
                    if(pWnd->m_hWnd && pSWP[i].hwnd == pWnd->m_hWnd)
                    {
                        if (pWnd->m_frameToolBar && pWnd->m_frameToolBar->GetWindowStyleFlag() & wxTB_TOP)
                        {
                            pSWP[i].x    = vRectl.xLeft;
                            pSWP[i].y    = vRectl.yBottom + nHeight;
                            pSWP[i].cx   = vRectl.xRight - vRectl.xLeft;
                            pSWP[i].cy   = vRectl.yTop - vRectl.yBottom - (nHeight + nHeight2);
                        }
                        else if (pWnd->m_frameToolBar && pWnd->m_frameToolBar->GetWindowStyleFlag() & wxTB_BOTTOM)
                        {
                            pSWP[i].x    = vRectl.xLeft;
                            pSWP[i].y    = vRectl.yBottom + nHeight + nHeight2;
                            pSWP[i].cx   = vRectl.xRight - vRectl.xLeft;
                            pSWP[i].cy   = vRectl.yTop - vRectl.yBottom - (nHeight + nHeight2);
                         }
                        else if (pWnd->m_frameToolBar && pWnd->m_frameToolBar->GetWindowStyleFlag() & wxTB_LEFT)
                        {
                            pSWP[i].x    = vRectl.xLeft + nWidth;
                            pSWP[i].y    = vRectl.yBottom + nHeight;
                            pSWP[i].cx   = vRectl.xRight - (vRectl.xLeft + nWidth);
                            pSWP[i].cy   = vRectl.yTop - vRectl.yBottom - nHeight;
                        }
                        else
                        {
                            pSWP[i].x    = vRectl.xLeft;
                            pSWP[i].y    = vRectl.yBottom + nHeight;
                            pSWP[i].cx   = vRectl.xRight - (vRectl.xLeft + nWidth);
                            pSWP[i].cy   = vRectl.yTop - vRectl.yBottom - nHeight;
                        }
                        pSWP[i].fl   = SWP_SIZE | SWP_MOVE | SWP_SHOW;
                        pSWP[i].hwndInsertBehind = HWND_TOP;
                    }
                }
                bProcessed = true;
                rc = MRFROMSHORT(nItemCount);
            }
            break;

       default:
            if(pWnd && pWnd->m_fnOldWndProc)
                rc = pWnd->m_fnOldWndProc(hWnd, ulMsg, wParam, lParam);
            else
                rc = ::WinDefWindowProc(hWnd, ulMsg, wParam, lParam);
    }
    return rc;
} // end of wxFrameMainWndProc

MRESULT EXPENTRY wxFrameWndProc(
  HWND                              hWnd
, ULONG                             ulMsg
, MPARAM                            wParam
, MPARAM                            lParam
)
{
    //
    // Trace all ulMsgs - useful for the debugging
    //
    HWND                            parentHwnd;
    wxFrame*                        pWnd  = NULL;

    parentHwnd  = WinQueryWindow(hWnd,QW_PARENT);
    pWnd = (wxFrame*) wxFindWinFromHandle((WXHWND) hWnd);

    //
    // When we get the first message for the HWND we just created, we associate
    // it with wxWindow stored in wxWndHook
    //

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
            rc = pWnd->OS2WindowProc(ulMsg, wParam, lParam);
        else
            rc = ::WinDefWindowProc(hWnd, ulMsg, wParam, lParam);
    }
    return rc;
} // end of wxFrameWndProc

MRESULT wxFrame::OS2WindowProc( WXUINT uMessage,
                                WXWPARAM wParam,
                                WXLPARAM lParam )
{
    MRESULT mRc = 0L;
    bool    bProcessed = false;

    switch (uMessage)
    {
        case WM_CLOSE:
            //
            // If we can't close, tell the system that we processed the
            // message - otherwise it would close us
            //
            bProcessed = !Close();
            break;

        case WM_PAINT:
            bProcessed = HandlePaint();
            mRc = (MRESULT)FALSE;
            break;

         case WM_ERASEBACKGROUND:
            //
            // Returning TRUE to requests PM to paint the window background
            // in SYSCLR_WINDOW. We capture this here because the PS returned
            // in Frames is the PS for the whole frame, which we can't really
            // use at all. If you want to paint a different background, do it
            // in an OnPaint using a wxPaintDC.
            //
            mRc = (MRESULT)(TRUE);
            break;

      case WM_COMMAND:
            {
                WORD                wId;
                WORD                wCmd;
                WXHWND              hWnd;

                UnpackCommand( (WXWPARAM)wParam
                              ,(WXLPARAM)lParam
                              ,&wId
                              ,&hWnd
                              ,&wCmd
                             );

                bProcessed = HandleCommand( wId
                                           ,wCmd
                                           ,(WXHWND)hWnd
                                          );
            }
            break;

        case WM_MENUSELECT:
            {
                WXWORD              wItem;
                WXWORD              wFlags;
                WXHMENU             hMenu;

                UnpackMenuSelect( wParam
                                 ,lParam
                                 ,&wItem
                                 ,&wFlags
                                 ,&hMenu
                                );
                bProcessed = HandleMenuSelect( wItem
                                              ,wFlags
                                              ,hMenu
                                             );
                mRc = (MRESULT)TRUE;
            }
            break;

        case WM_SIZE:
            {
                SHORT               nScxnew = SHORT1FROMMP(lParam); // New horizontal size.
                SHORT               nScynew = SHORT2FROMMP(lParam); // New vertical size.

                lParam = MRFROM2SHORT( nScxnew - 20
                                      ,nScynew - 30
                                     );
            }
            bProcessed = HandleSize(LOWORD(lParam), HIWORD(lParam), (WXUINT)wParam);
            mRc = (MRESULT)FALSE;
            break;

        case CM_QUERYDRAGIMAGE:
            {
                const wxIcon&           vIcon = GetIcon();
                HPOINTER                hIcon;

                if (vIcon.Ok())
                    hIcon = (HPOINTER)::WinSendMsg(GetHWND(), WM_QUERYICON, 0L, 0L);
                else
                    hIcon = (HPOINTER)m_hDefaultIcon;
                mRc = (MRESULT)hIcon;
                bProcessed = mRc != 0;
            }
            break;
    }

    if (!bProcessed )
        mRc = wxWindow::OS2WindowProc( uMessage
                                      ,wParam
                                      ,lParam
                                     );
    return (MRESULT)mRc;
} // wxFrame::OS2WindowProc

void wxFrame::SetClient(WXHWND WXUNUSED(c_Hwnd))
{
   // Duh...nothing to do under OS/2
}

void wxFrame::SetClient( wxWindow* pWindow )
{
    wxWindow* pOldClient      = this->GetClient();
    bool      bClientHasFocus = pOldClient && (pOldClient == wxWindow::FindFocus());

    if(pOldClient == pWindow)  // nothing to do
        return;
    if(pWindow == NULL) // just need to remove old client
    {
        if(pOldClient == NULL) // nothing to do
            return;

        if(bClientHasFocus )
            this->SetFocus();

        pOldClient->Enable( false );
        pOldClient->Show( false );
        ::WinSetWindowUShort(pOldClient->GetHWND(), QWS_ID, (USHORT)pOldClient->GetId());
        // to avoid OS/2 bug need to update frame
        ::WinSendMsg((HWND)this->GetFrame(), WM_UPDATEFRAME, (MPARAM)~0, 0);
        return;
    }

    //
    // Else need to change client
    //
    if(bClientHasFocus)
         this->SetFocus();

    ::WinEnableWindowUpdate((HWND)GetHWND(), FALSE);
    if(pOldClient)
    {
        pOldClient->Enable(false);
        pOldClient->Show(false);
        ::WinSetWindowUShort(pOldClient->GetHWND(), QWS_ID, (USHORT)pOldClient->GetId());
    }
    pWindow->Reparent(this);
    ::WinSetWindowUShort(pWindow->GetHWND(), QWS_ID, FID_CLIENT);
    ::WinEnableWindowUpdate((HWND)GetHWND(), TRUE);
    pWindow->Enable();
    pWindow->Show();   // ensure client is showing
    if( this->IsShown() )
    {
        this->Show();
        ::WinSendMsg(m_hFrame, WM_UPDATEFRAME, (MPARAM)~0, 0);
    }
}

wxWindow* wxFrame::GetClient()
{
    return wxFindWinFromHandle((WXHWND)::WinWindowFromID(m_hFrame, FID_CLIENT));
}

