///////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/toplevel.cpp
// Purpose:     implements wxTopLevelWindow for OS/2
// Author:      Vadim Zeitlin
// Modified by:
// Created:     30.12.01
// RCS-ID:      $Id$
// Copyright:   (c) 2001 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/toplevel.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/dialog.h"
    #include "wx/string.h"
    #include "wx/log.h"
    #include "wx/intl.h"
    #include "wx/frame.h"
    #include "wx/control.h"
    #include "wx/containr.h"        // wxSetFocusToChild()
    #include "wx/settings.h"
    #include "wx/module.h"        // wxSetFocusToChild()
#endif //WX_PRECOMP

#include "wx/os2/private.h"

// ----------------------------------------------------------------------------
// stubs for missing functions under MicroWindows
// ----------------------------------------------------------------------------


// ----------------------------------------------------------------------------
// globals
// ----------------------------------------------------------------------------

// the name of the default wxWidgets class
extern void wxAssociateWinWithHandle( HWND hWnd, wxWindowOS2* pWin );

bool wxTopLevelWindowOS2::m_sbInitialized = false;
wxWindow* wxTopLevelWindowOS2::m_spHiddenParent = NULL;

// ============================================================================
// wxTopLevelWindowOS2 implementation
// ============================================================================

BEGIN_EVENT_TABLE(wxTopLevelWindowOS2, wxTopLevelWindowBase)
    EVT_ACTIVATE(wxTopLevelWindowOS2::OnActivate)
END_EVENT_TABLE()

// ============================================================================
// wxTopLevelWindowMSW implementation
// ============================================================================

// Dialog window proc
MRESULT EXPENTRY wxDlgProc( HWND WXUNUSED(hWnd)
                           ,UINT uMessage
                           ,void * WXUNUSED(wParam)
                           ,void * WXUNUSED(lParam)
                          )
{
    switch(uMessage)
    {
        case WM_INITDLG:
            //
            // For this message, returning TRUE tells system to set focus to
            // the first control in the dialog box, but we set the focus
            // ourselves, however in OS/2 we must return true to enable the dialog
            //
            return (MRESULT)TRUE;
        default:
            //
            // For all the other ones, FALSE means that we didn't process the
            // message
            //
            return (MRESULT)FALSE;
    }
} // end of wxDlgProc

// ----------------------------------------------------------------------------
// wxTLWHiddenParentModule: used to manage the hidden parent window (we need a
// module to ensure that the window is always deleted)
// ----------------------------------------------------------------------------

class wxTLWHiddenParentModule : public wxModule
{
public:
    //
    // Module init/finalize
    //
    virtual bool OnInit(void);
    virtual void OnExit(void);

    //
    // Get the hidden window (creates on demand)
    //
    static HWND GetHWND(void);

private:
    //
    // The HWND of the hidden parent
    //
    static HWND m_shWnd;

    //
    // The class used to create it
    //
    static const wxChar* m_szClassName;
    DECLARE_DYNAMIC_CLASS(wxTLWHiddenParentModule)
}; // end of CLASS wxTLWHiddenParentModule

IMPLEMENT_DYNAMIC_CLASS(wxTLWHiddenParentModule, wxModule)

// ----------------------------------------------------------------------------
// wxTopLevelWindowOS2 creation
// ----------------------------------------------------------------------------

void wxTopLevelWindowOS2::Init()
{
    m_bIconized = m_bMaximizeOnShow = false;

    //
    // Unlike (almost?) all other windows, frames are created hidden
    //
    m_isShown = false;

    //
    // Data to save/restore when calling ShowFullScreen
    m_lFsStyle          = 0;
    m_lFsOldWindowStyle = 0;
    m_bFsIsMaximized    = false;
    m_bFsIsShowing      = false;

    m_hFrame    = NULLHANDLE;
    memset(&m_vSwp, 0, sizeof(SWP));
    memset(&m_vSwpClient, 0, sizeof(SWP));
    m_pWinLastFocused = NULL;
} // end of wxTopLevelWindowIOS2::Init

void wxTopLevelWindowOS2::OnActivate(
  wxActivateEvent&                  rEvent
)
{
    if (rEvent.GetActive())
    {
        //
        // Restore focus to the child which was last focused
        //
        wxLogTrace(wxT("focus"), wxT("wxTLW %08lx activated."), m_hWnd);

        wxWindow*                   pParent = m_pWinLastFocused ? m_pWinLastFocused->GetParent()
                                                                : NULL;
        if (!pParent)
        {
            pParent = this;
        }

        wxSetFocusToChild( pParent
                          ,&m_pWinLastFocused
                         );
    }
    else // deactivating
    {
        //
        // Remember the last focused child if it is our child
        //
        m_pWinLastFocused = FindFocus();

        //
        // So we NULL it out if it's a child from some other frame
        //
        wxWindow*                   pWin = m_pWinLastFocused;

        while (pWin)
        {
            if (pWin->IsTopLevel())
            {
                if (pWin != this)
                {
                    m_pWinLastFocused = NULL;
                }
                break;
            }
            pWin = pWin->GetParent();
        }

        wxLogTrace(wxT("focus"),
                   wxT("wxTLW %08lx deactivated, last focused: %08lx."),
                   m_hWnd,
                   m_pWinLastFocused ? GetHwndOf(m_pWinLastFocused)
                                     : NULL);
        rEvent.Skip();
    }
} // end of wxTopLevelWindowOS2::OnActivate

WXDWORD wxTopLevelWindowOS2::OS2GetStyle(
  long                              lStyle
, WXDWORD*                          pdwExflags
) const
{
    long                            lMsflags = wxWindow::OS2GetStyle( (lStyle & ~wxBORDER_MASK) | wxBORDER_NONE
                                                                     ,pdwExflags
                                                                    );

    if ((lStyle & wxDEFAULT_FRAME_STYLE) == wxDEFAULT_FRAME_STYLE)
        lMsflags |= FCF_SIZEBORDER | FCF_TITLEBAR | FCF_SYSMENU |
                    FCF_MINMAX | FCF_TASKLIST;

    if ((lStyle & wxCAPTION) == wxCAPTION)
        lMsflags |= FCF_TASKLIST;
    else
        lMsflags |= FCF_NOMOVEWITHOWNER;

    if ((lStyle & wxVSCROLL) == wxVSCROLL)
        lMsflags |= FCF_VERTSCROLL;
    if ((lStyle & wxHSCROLL) == wxHSCROLL)
        lMsflags |= FCF_HORZSCROLL;
    if (lStyle & wxMINIMIZE_BOX)
        lMsflags |= FCF_MINBUTTON;
    if (lStyle & wxMAXIMIZE_BOX)
        lMsflags |= FCF_MAXBUTTON;
    if (lStyle & wxRESIZE_BORDER)
        lMsflags |= FCF_DLGBORDER;
    if (lStyle & wxSYSTEM_MENU)
        lMsflags |= FCF_SYSMENU;
    if (lStyle & wxCAPTION)
        lMsflags |= FCF_TASKLIST;
    if (lStyle & wxCLIP_CHILDREN)
    {
        // Invalid for frame windows under PM
    }

    if (lStyle & wxTINY_CAPTION)
        lMsflags |= FCF_TASKLIST;

    if ((lStyle & wxRESIZE_BORDER) == 0)
        lMsflags |= FCF_BORDER;
    if (lStyle & wxFRAME_TOOL_WINDOW)
        *pdwExflags = kFrameToolWindow;

    if (lStyle & wxSTAY_ON_TOP)
        lMsflags |= FCF_SYSMODAL;

    return lMsflags;
} // end of wxTopLevelWindowOS2::OS2GetCreateWindowFlags

WXHWND wxTopLevelWindowOS2::OS2GetParent() const
{
    HWND                            hWndParent = NULL;

    //
    // For the frames without wxFRAME_FLOAT_ON_PARENT style we should use NULL
    // parent HWND or it would be always on top of its parent which is not what
    // we usually want (in fact, we only want it for frames with the
    // wxFRAME_FLOAT_ON_PARENT flag)
    //
    if (HasFlag(wxFRAME_FLOAT_ON_PARENT) )
    {
        const wxWindow*             pParent = GetParent();

        if (!pParent)
        {
            //
            // This flag doesn't make sense then and will be ignored
            //
            wxFAIL_MSG( wxT("wxFRAME_FLOAT_ON_PARENT but no parent?") );
        }
        else
        {
            hWndParent = GetHwndOf(pParent);
        }
    }
    //else: don't float on parent, must not be owned

    //
    // Now deal with the 2nd taskbar-related problem (see comments above in
    // OS2GetStyle())
    //
    if (HasFlag(wxFRAME_NO_TASKBAR) && !hWndParent)
    {
        //
        // Use hidden parent
        //
        hWndParent = wxTLWHiddenParentModule::GetHWND();
    }
    return (WXHWND)hWndParent;
} // end of wxTopLevelWindowOS2::OS2GetParent


bool wxTopLevelWindowOS2::CreateDialog( ULONG           ulDlgTemplate,
                                        const wxString& WXUNUSED(rsTitle),
                                        const wxPoint&  rPos,
                                        const wxSize&   rSize )
{
    wxWindow*                       pParent = GetParent();

    //
    // For the dialogs without wxDIALOG_NO_PARENT style, use the top level
    // app window as parent - this avoids creating modal dialogs without
    // parent
    //
    if (!pParent && !(GetWindowStyleFlag() & wxDIALOG_NO_PARENT))
    {
        pParent = wxTheApp->GetTopWindow();

        if (pParent)
        {
            //
            // Don't use transient windows as parents, this is dangerous as it
            // can lead to a crash if the parent is destroyed before the child
            //
            // also don't use the window which is currently hidden as then the
            // dialog would be hidden as well
            if ((pParent->GetExtraStyle() & wxWS_EX_TRANSIENT) ||
                 !pParent->IsShown())
            {
                pParent = NULL;
            }
        }
    }

    HWND                            hWndDlg;
    HWND                            hWndOwner;

    if (pParent)
        hWndOwner = GetHwndOf(pParent);
    else
        hWndOwner = HWND_DESKTOP;

    hWndDlg = ::WinLoadDlg( HWND_DESKTOP
                           ,hWndOwner
                           ,(PFNWP)wxDlgProc
                           ,NULL
                           ,(ULONG)ulDlgTemplate
                           ,(PVOID)this
                          );

    m_hWnd = (WXHWND) hWndDlg;

    if ( !m_hWnd )
    {
        wxFAIL_MSG(wxT("Did you forget to include wx/os2/wx.rc in your resources?"));

        wxLogSysError(wxT("Can't create dialog using template '%ld'"), ulDlgTemplate);

        return false;
    }

    //
    // Move the dialog to its initial position without forcing repainting
    //
    int                             nX;
    int                             nY;
    int                             nWidth;
    int                             nHeight;

    if (!OS2GetCreateWindowCoords( rPos
                                  ,rSize
                                  ,nX
                                  ,nY
                                  ,nWidth
                                  ,nHeight
                                 ))
    {
        nX = nWidth = (int)CW_USEDEFAULT;
    }

    //
    // We can't use CW_USEDEFAULT here as we're not calling CreateWindow()
    // and passing CW_USEDEFAULT to MoveWindow() results in resizing the
    // window to (0, 0) size which breaks quite a lot of things, e.g. the
    // sizer calculation in wxSizer::Fit()
    //
    if (nWidth == (int)CW_USEDEFAULT)
    {
        //
        // The exact number doesn't matter, the dialog will be resized
        // again soon anyhow but it should be big enough to allow
        // calculation relying on "totalSize - clientSize > 0" work, i.e.
        // at least greater than the title bar height
        //
        nWidth = nHeight = 100;
    }
    if (nX == (int)CW_USEDEFAULT)
    {
        //
        // Centre it on the screen - what else can we do?
        //
        wxSize                      vSizeDpy = wxGetDisplaySize();

        nX = (vSizeDpy.x - nWidth) / 2;
        nY = (vSizeDpy.y - nHeight) / 2;
    }
    SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_APPWORKSPACE));

    LONG                            lColor = (LONG)m_backgroundColour.GetPixel();

    if (!::WinSetPresParam( m_hWnd
                           ,PP_BACKGROUNDCOLOR
                           ,sizeof(LONG)
                           ,(PVOID)&lColor
                          ))
    {
        return false;
    }

    // Convert to OS/2 coordinates
    nY = GetOS2ParentHeight(pParent) - nY - nHeight;

    ::WinSetWindowPos( GetHwnd()
                      ,HWND_TOP
                      ,nX
                      ,nY
                      ,nWidth
                      ,nHeight
                      ,SWP_MOVE | SWP_SIZE | SWP_ZORDER | SWP_SHOW | SWP_ACTIVATE
                     );
    ::WinQueryWindowPos(GetHwnd(), GetSwp());
    m_hFrame = m_hWnd;
    SubclassWin(m_hWnd);
    return true;
} // end of wxTopLevelWindowOS2::CreateDialog

bool wxTopLevelWindowOS2::CreateFrame( const wxString& rsTitle,
                                       const wxPoint& rPos,
                                       const wxSize& rSize )
{
    WXDWORD    lExflags;
    WXDWORD    lFlags = OS2GetCreateWindowFlags(&lExflags);
    long       lStyle = GetWindowStyleFlag();
    int        nX = rPos.x;
    int        nY = rPos.y;
    int        nWidth = rSize.x;
    int        nHeight = rSize.y;
    ULONG      ulStyleFlags = 0L;
    ERRORID    vError;
    wxString   sError;
    wxWindow*  pParent = GetParent();
    HWND       hParent;
    HWND       hFrame;
    HWND       hClient;

    if (pParent)
        hParent = GetHwndOf(pParent);
    else
        hParent = HWND_DESKTOP;

    if ((lStyle & wxMINIMIZE) || (lStyle & wxICONIZE))
        ulStyleFlags |= WS_MINIMIZED;
    if (lStyle & wxMAXIMIZE)
        ulStyleFlags |= WS_MAXIMIZED;

    //
    // Clear the visible flag, we always call show
    //
    ulStyleFlags &= (unsigned long)~WS_VISIBLE;
    m_bIconized = false;

    //
    // Create the frame window:  We break ranks with other ports now
    // and instead of calling down into the base wxWindow class' OS2Create
    // we do all our own stuff here.  We will set the needed pieces
    // of wxWindow manually, here.
    //

     hFrame = ::WinCreateStdWindow( hParent
                                   ,ulStyleFlags          // frame-window style
                                   ,(PULONG)&lFlags       // window style
                                   ,wxString(wxFrameClassName).c_str() // class name
                                   ,rsTitle.c_str()       // window title
                                   ,0L                    // default client style
                                   ,NULLHANDLE            // resource in executable file
                                   ,0                     // resource id
                                   ,&hClient              // receives client window handle
                                  );
    if (!hFrame)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
        wxLogError(wxT("Error creating frame. Error: %s\n"), sError.c_str());
        return false;
    }

    //
    // wxWindow class' m_hWnd set here and needed associations
    //
    m_hFrame = hFrame;
    m_hWnd   = hClient;
    wxAssociateWinWithHandle(m_hWnd, this);
    wxAssociateWinWithHandle(m_hFrame, this);

    SetBackgroundColour(wxSystemSettings::GetColour(wxSYS_COLOUR_APPWORKSPACE));

    LONG                            lColor = (LONG)m_backgroundColour.GetPixel();

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

    //
    // Now need to subclass window.  Instead of calling the SubClassWin in wxWindow
    // we manually subclass here because we don't want to use the main wxWndProc
    // by default
    //
    m_fnOldWndProc = (WXFARPROC) ::WinSubclassWindow(m_hFrame, (PFNWP)wxFrameMainWndProc);

    //
    // Now size everything.  If adding a menu the client will need to be resized.
    //

    if (!OS2GetCreateWindowCoords( rPos
                                  ,rSize
                                  ,nX
                                  ,nY
                                  ,nWidth
                                  ,nHeight
                                 ))
    {
        nX = nWidth = (int)CW_USEDEFAULT;
    }

    //
    // We can't use CW_USEDEFAULT here as we're not calling CreateWindow()
    // and passing CW_USEDEFAULT to MoveWindow() results in resizing the
    // window to (0, 0) size which breaks quite a lot of things, e.g. the
    // sizer calculation in wxSizer::Fit()
    //
    if (nWidth == (int)CW_USEDEFAULT)
    {
        //
        // The exact number doesn't matter, the dialog will be resized
        // again soon anyhow but it should be big enough to allow
        // calculation relying on "totalSize - clientSize > 0" work, i.e.
        // at least greater than the title bar height
        //
        nWidth = nHeight = 100;
    }
    if (nX == (int)CW_USEDEFAULT)
    {
        //
        // Centre it on the screen for now - what else can we do?
        // TODO: We could try FCF_SHELLPOSITION but it will require moving
        //       things around a bit.
        //
        wxSize                      vSizeDpy = wxGetDisplaySize();

        nX = (vSizeDpy.x - nWidth) / 2;
        nY = (vSizeDpy.y - nHeight) / 2;
    }

    // Convert to OS/2 coordinates
    nY = GetOS2ParentHeight(pParent) - nY - nHeight;

    if (!::WinSetWindowPos( m_hFrame
                           ,HWND_TOP
                           ,nX
                           ,nY
                           ,nWidth
                           ,nHeight
                           ,SWP_SIZE | SWP_MOVE | SWP_ACTIVATE | SWP_ZORDER
                          ))
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
        wxLogError(wxT("Error sizing frame. Error: %s\n"), sError.c_str());
        return false;
    }
    lStyle =  ::WinQueryWindowULong( m_hWnd
                                    ,QWL_STYLE
                                   );
    lStyle |= WS_CLIPCHILDREN;
    ::WinSetWindowULong( m_hWnd
                        ,QWL_STYLE
                        ,lStyle
                       );
    return true;
} // end of wxTopLevelWindowOS2::CreateFrame

bool wxTopLevelWindowOS2::Create(
  wxWindow*                         pParent
, wxWindowID                        vId
, const wxString&                   rsTitle
, const wxPoint&                    rPos
, const wxSize&                     rSizeOrig
, long                              lStyle
, const wxString&                   rsName
)
{
    //
    // Init our fields
    //
    Init();
    m_windowStyle = lStyle;
    SetName(rsName);
    m_windowId = vId == -1 ? NewControlId() : vId;

    // always create a frame of some reasonable, even if arbitrary, size (at
    // least for MSW compatibility)
    wxSize rSize = rSizeOrig;
    if ( rSize.x == -1 || rSize.y == -1 )
    {
        wxSize sizeDpy = wxGetDisplaySize();
        if ( rSize.x == -1 )
            rSize.x = sizeDpy.x / 3;
        if ( rSize.y == -1 )
            rSize.y = sizeDpy.y / 5;
    }

    wxTopLevelWindows.Append(this);
    if (pParent)
        pParent->AddChild(this);

    if (GetExtraStyle() & wxTOPLEVEL_EX_DIALOG)
    {
        //
        // We have different dialog templates to allow creation of dialogs
        // with & without captions under OS2indows, resizeable or not (but a
        // resizeable dialog always has caption - otherwise it would look too
        // strange)
        //
        ULONG                       ulDlgTemplate;

        if (lStyle & wxRESIZE_BORDER)
            ulDlgTemplate = (ULONG)kResizeableDialog;
        else if (lStyle & wxCAPTION)
            ulDlgTemplate = (ULONG)kCaptionDialog;
        else
            ulDlgTemplate = (ULONG)kNoCaptionDialog;
        return CreateDialog( ulDlgTemplate
                            ,rsTitle
                            ,rPos
                            ,rSize
                           );
    }
    else // !dialog
    {
        return CreateFrame( rsTitle
                           ,rPos
                           ,rSize
                          );
    }
} // end of wxTopLevelWindowOS2::Create

wxTopLevelWindowOS2::~wxTopLevelWindowOS2()
{
    //
    // After destroying an owned window, Windows activates the next top level
    // window in Z order but it may be different from our owner (to reproduce
    // this simply Alt-TAB to another application and back before closing the
    // owned frame) whereas we always want to yield activation to our parent
    //
    if (HasFlag(wxFRAME_FLOAT_ON_PARENT))
    {
        wxWindow*                   pParent = GetParent();

        if (pParent)
        {
            ::WinSetWindowPos( GetHwndOf(pParent)
                              ,HWND_TOP
                              ,0, 0, 0, 0
                              ,SWP_ZORDER
                             );
        }
    }
} // end of wxTopLevelWindowOS2::~wxTopLevelWindowOS2

// ----------------------------------------------------------------------------
// wxTopLevelWindowOS2 client size
// ----------------------------------------------------------------------------

void wxTopLevelWindowOS2::DoSetClientSize(
  int                               nWidth
, int                               nHeight
)
{
    //
    // Call GetClientAreaOrigin() to take the toolbar into account
    //
    wxPoint                         vPt = GetClientAreaOrigin();

    nWidth  += vPt.x;
    nHeight += vPt.y;

    wxWindow::DoSetClientSize( nWidth
                              ,nHeight
                             );
} // end of wxTopLevelWindowOS2::DoSetClientSize

void wxTopLevelWindowOS2::DoGetClientSize(
  int*                              pnX
, int*                              pnY
) const
{
    wxWindow::DoGetClientSize( pnX
                              ,pnY
                             );

    wxPoint                         vPt = GetClientAreaOrigin();

    if (pnX)
        *pnX -= vPt.x;

    if (pnY)
        *pnY += vPt.y;
} // end of wxTopLevelWindowOS2::DoGetClientSize

// ----------------------------------------------------------------------------
// wxTopLevelWindowOS2 showing
// ----------------------------------------------------------------------------

void wxTopLevelWindowOS2::DoShowWindow(
  int                               nShowCmd
)
{
    ::WinShowWindow(m_hFrame, (BOOL)(nShowCmd & SWP_SHOW));

    //
    // Need to artificially send a size event as wxApps often expect to do some
    // final child control sizing
    SendSizeEvent();
    m_bIconized = nShowCmd == SWP_MINIMIZE;
} // end of wxTopLevelWindowOS2::DoShowWindow

bool wxTopLevelWindowOS2::Show( bool bShow )
{
    int nShowCmd;
    SWP vSwp;

    if (bShow != IsShown() )
    {
        m_isShown = bShow;
    }
    else
    {
        return false;
    }
    if (bShow)
    {
        if (m_bMaximizeOnShow)
        {
            nShowCmd = SWP_MAXIMIZE;
            m_bMaximizeOnShow = false;
        }
        else
        {
            nShowCmd = SWP_SHOW;
        }
    }
    else // hide
    {
        nShowCmd = SWP_HIDE;
    }
    DoShowWindow(nShowCmd);

    if (bShow)
    {
        wxActivateEvent vEvent(wxEVT_ACTIVATE, true, m_windowId);

        ::WinQueryWindowPos(m_hFrame, &vSwp);
        m_bIconized = ( vSwp.fl & SWP_MINIMIZE ) == SWP_MINIMIZE ;
        ::WinQueryWindowPos(m_hWnd, &m_vSwpClient);
        ::WinSendMsg(m_hFrame, WM_UPDATEFRAME, (MPARAM)~0, 0);
        ::WinQueryWindowPos(m_hWnd, &vSwp);
        ::WinEnableWindow(m_hFrame, TRUE);

        vEvent.SetEventObject(this);
        HandleWindowEvent(vEvent);
    }
    else
    {
        //
        // Try to highlight the correct window (the parent)
        //
        if (GetParent())
        {
            HWND hWndParent = GetHwndOf(GetParent());

            ::WinQueryWindowPos(hWndParent, &vSwp);
            m_bIconized = (vSwp.fl & SWP_MINIMIZE)==SWP_MINIMIZE;
            ::WinEnableWindow(hWndParent, TRUE);
        }
    }
    return true;
} // end of wxTopLevelWindowOS2::Show

// ----------------------------------------------------------------------------
// wxTopLevelWindowOS2 maximize/minimize
// ----------------------------------------------------------------------------

void wxTopLevelWindowOS2::Maximize(
  bool                              bMaximize
)
{
    if (IsShown())
    {
        //
        // Just maximize it directly
        //
        DoShowWindow(bMaximize ? SWP_MAXIMIZE : SWP_RESTORE);
    }
    else // hidden
    {
        //
        // We can't maximize the hidden frame because it shows it as well, so
        // just remember that we should do it later in this case
        //
        m_bMaximizeOnShow = bMaximize;
    }
} // end of wxTopLevelWindowOS2::Maximize

bool wxTopLevelWindowOS2::IsMaximized() const
{
    ::WinQueryWindowPos(m_hFrame, (PSWP)&m_vSwp);
    return (m_vSwp.fl & SWP_MAXIMIZE) == SWP_MAXIMIZE;
} // end of wxTopLevelWindowOS2::IsMaximized

void wxTopLevelWindowOS2::SetTitle( const wxString& title)
{
    SetLabel(title);
}

wxString wxTopLevelWindowOS2::GetTitle() const
{
    return GetLabel();
}

void wxTopLevelWindowOS2::Iconize( bool bIconize )
{
    DoShowWindow(bIconize ? SWP_MINIMIZE : SWP_RESTORE);
} // end of wxTopLevelWindowOS2::Iconize

bool wxTopLevelWindowOS2::IsIconized() const
{
    // also update the current state
    ::WinQueryWindowPos(m_hFrame, (PSWP)&m_vSwp);
    if (m_vSwp.fl & SWP_MINIMIZE)
        ((wxTopLevelWindow*)this)->m_bIconized = true;
    else
        ((wxTopLevelWindow*)this)->m_bIconized = false;
    return m_bIconized;
} // end of wxTopLevelWindowOS2::IsIconized

void wxTopLevelWindowOS2::Restore()
{
    DoShowWindow(SWP_RESTORE);
} // end of wxTopLevelWindowOS2::Restore

// generate an artificial resize event
void wxTopLevelWindowOS2::SendSizeEvent(int flags)
{
    if (!m_bIconized)
    {
        RECTL                       vRect = wxGetWindowRect(GetHwnd());

        if ( flags & wxSEND_EVENT_POST )
        {
            (void)::WinPostMsg( m_hFrame
                               ,WM_SIZE
                               ,MPFROM2SHORT(vRect.xRight - vRect.xLeft, vRect.yTop - vRect.yBottom)
                               ,MPFROM2SHORT(vRect.xRight - vRect.xLeft, vRect.yTop - vRect.yBottom)
                              );
        }
        else // send it
        {
            (void)::WinSendMsg( m_hFrame
                               ,WM_SIZE
                               ,MPFROM2SHORT(vRect.xRight - vRect.xLeft, vRect.yTop - vRect.yBottom)
                               ,MPFROM2SHORT(vRect.xRight - vRect.xLeft, vRect.yTop - vRect.yBottom)
                              );
        }
    }
} // end of wxTopLevelWindowOS2::SendSizeEvent

// ----------------------------------------------------------------------------
// wxTopLevelWindowOS2 fullscreen
// ----------------------------------------------------------------------------

bool wxTopLevelWindowOS2::ShowFullScreen( bool bShow,
                                          long lStyle )
{
    if (bShow)
    {
        if (IsFullScreen())
            return false;

        m_bFsIsShowing = true;
        m_lFsStyle = lStyle;

        //
        // Zap the frame borders
        //

        //
        // Save the 'normal' window lStyle
        //
        m_lFsOldWindowStyle = ::WinQueryWindowULong( (HWND)GetHWND()
                                                    ,QWL_STYLE
                                                   );

        //
        // Save the old position, width & height, maximize state
        //
        m_vFsOldSize = GetRect();
        m_bFsIsMaximized = IsMaximized();

        //
        // Decide which window lStyle flags to turn off
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
        ::WinSetWindowULong( (HWND)GetHWND()
                            ,QWL_STYLE
                            ,lNewStyle
                           );

        //
        // Resize to the size of the desktop
        //
        int   nWidth;
        int   nHeight;
        RECTL vRect = wxGetWindowRect(HWND_DESKTOP);

        nWidth = vRect.xRight - vRect.xLeft;
        nHeight = vRect.yTop - vRect.yBottom;

        SetSize( nWidth, nHeight );

        //
        // Now flush the window style cache and actually go full-screen
        //
        ::WinSetWindowPos( m_hFrame
                          ,HWND_TOP
                          ,0
                          ,0
                          ,nWidth
                          ,nHeight
                          ,SWP_SIZE | SWP_MOVE
                         );

        wxSize full( nWidth, nHeight );
        wxSizeEvent vEvent( full, GetId() );
        HandleWindowEvent(vEvent);
        return true;
    }
    else
    {
        if (!IsFullScreen())
            return false;

        m_bFsIsShowing = false;
        Maximize(m_bFsIsMaximized);
        ::WinSetWindowULong( (HWND)GetHWND()
                            ,QWL_STYLE
                            ,m_lFsOldWindowStyle
                           );
        ::WinSetWindowPos( m_hFrame
                          ,HWND_TOP
                          ,m_vFsOldSize.x
                          ,m_vFsOldSize.y
                          ,m_vFsOldSize.width
                          ,m_vFsOldSize.height
                          ,SWP_SIZE | SWP_MOVE
                         );
        return true;
    }
} // end of wxTopLevelWindowOS2::ShowFullScreen

// ----------------------------------------------------------------------------
// wxTopLevelWindowOS2 misc
// ----------------------------------------------------------------------------

void wxTopLevelWindowOS2::SetIcons(
  const wxIconBundle&               rIcons
)
{
    //
    // This sets m_icon
    //
    wxTopLevelWindowBase::SetIcons(rIcons);

    const wxIcon& vIcon = rIcons.GetIconOfExactSize(32);

    if (vIcon.Ok())
    {
        ::WinSendMsg( m_hFrame
                     ,WM_SETICON
                     ,(MPARAM)((HPOINTER)vIcon.GetHICON())
                     ,NULL
                    );
        ::WinSendMsg( m_hFrame
                     ,WM_UPDATEFRAME
                     ,(MPARAM)FCF_ICON
                     ,(MPARAM)0
                    );
    }
} // end of wxTopLevelWindowOS2::SetIcon

bool wxTopLevelWindowOS2::EnableCloseButton( bool bEnable )
{
    //
    // Get system (a.k.a. window) menu
    //
    HMENU hMenu = ::WinWindowFromID(m_hFrame, FID_SYSMENU);

    if (!hMenu)
    {
        wxLogLastError(wxT("GetSystemMenu"));
        return false;
    }

    //
    // Enabling/disabling the close item from it also automatically
    // disables/enables the close title bar button
    //
    if (bEnable)
        (void)::WinSendMsg( hMenu
                           ,MM_SETITEMATTR
                           ,MPFROM2SHORT(SC_CLOSE, FALSE)
                           ,MPFROM2SHORT(MIA_DISABLED, FALSE)
                          );
    else
        (void)::WinSendMsg( hMenu
                           ,MM_SETITEMATTR
                           ,MPFROM2SHORT(SC_CLOSE, FALSE)
                           ,MPFROM2SHORT(MIA_DISABLED, MIA_DISABLED)
                          );

    //
    // Update appearance immediately
    //
    ::WinSendMsg( m_hFrame
                 ,WM_UPDATEFRAME
                 ,(MPARAM)FCF_MENU
                 ,(MPARAM)0
                );
    return true;
} // end of wxTopLevelWindowOS2::EnableCloseButton

// ============================================================================
// wxTLWHiddenParentModule implementation
// ============================================================================

HWND          wxTLWHiddenParentModule::m_shWnd = NULL;
const wxChar* wxTLWHiddenParentModule::m_szClassName = NULL;

bool wxTLWHiddenParentModule::OnInit()
{
    m_shWnd = NULL;
    m_szClassName = NULL;
    return true;
} // end of wxTLWHiddenParentModule::OnInit

void wxTLWHiddenParentModule::OnExit()
{
    if (m_shWnd)
    {
        if (!::WinDestroyWindow(m_shWnd))
        {
            wxLogLastError(wxT("DestroyWindow(hidden TLW parent)"));
        }
        m_shWnd = NULL;
    }

    m_szClassName = NULL;
} // end of wxTLWHiddenParentModule::OnExit

/* static */
HWND wxTLWHiddenParentModule::GetHWND()
{
    if (!m_shWnd)
    {
        if (!m_szClassName)
        {
            static const wxChar*    zHIDDEN_PARENT_CLASS = wxT("wxTLWHiddenParent");

            if (!::WinRegisterClass( wxGetInstance()
                                    ,(PSZ)zHIDDEN_PARENT_CLASS
                                    ,NULL
                                    ,0
                                    ,sizeof(ULONG)
                                   ))
            {
                wxLogLastError(wxT("RegisterClass(\"wxTLWHiddenParent\")"));
            }
            else
            {
                m_szClassName = zHIDDEN_PARENT_CLASS;
            }
        }
        m_shWnd = ::WinCreateWindow( HWND_DESKTOP,
                                     (PSZ)m_szClassName,
                                     "",
                                     0L,
                                     (LONG)0L,
                                     (LONG)0L,
                                     (LONG)0L,
                                     (LONG)0L,
                                     NULLHANDLE,
                                     HWND_TOP,
                                     0L,
                                     NULL,
                                     NULL );
        if (!m_shWnd)
        {
            wxLogLastError(wxT("CreateWindow(hidden TLW parent)"));
        }
    }
    return m_shWnd;
} // end of wxTLWHiddenParentModule::GetHWND
