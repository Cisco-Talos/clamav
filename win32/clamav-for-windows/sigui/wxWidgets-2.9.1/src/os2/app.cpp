/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/app.cpp
// Purpose:     wxApp
// Author:      David Webster
// Modified by:
// Created:     10/13/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/app.h"

#ifndef WX_PRECOMP
    #include "wx/dynarray.h"
    #include "wx/frame.h"
    #include "wx/utils.h"
    #include "wx/gdicmn.h"
    #include "wx/pen.h"
    #include "wx/brush.h"
    #include "wx/cursor.h"
    #include "wx/icon.h"
    #include "wx/palette.h"
    #include "wx/dc.h"
    #include "wx/dialog.h"
    #include "wx/msgdlg.h"
    #include "wx/intl.h"
    #include "wx/crt.h"
    #include "wx/log.h"
    #include "wx/module.h"
#endif

#include "wx/stdpaths.h"
#include "wx/filename.h"
#include "wx/evtloop.h"

#include "wx/os2/private.h"

#ifdef __EMX__

#include <sys/ioctl.h>
#include <sys/select.h>

#else

#include <nerrno.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>

#endif //

#if defined(__WATCOMC__)

#include <tcpustd.h>

#elif !defined(__EMX__)

#define select(a,b,c,d,e) bsdselect(a,b,c,d,e)
extern "C" int _System bsdselect(int,
                                 struct fd_set *,
                                 struct fd_set *,
                                 struct fd_set *,
                                 struct timeval *);
#endif

#if wxUSE_THREADS
    #include "wx/thread.h"
#endif // wxUSE_THREADS

#if wxUSE_TOOLTIPS
    #include "wx/tooltip.h"
#endif // wxUSE_TOOLTIPS

#include <string.h>
#include <ctype.h>

// ---------------------------------------------------------------------------
// global variables
// ---------------------------------------------------------------------------

WXDLLEXPORT_DATA(wxChar*) wxBuffer;
extern wxCursor*                    g_globalCursor;

HAB                                 vHabmain = NULLHANDLE;


HICON wxSTD_FRAME_ICON          = (HICON) NULL;
HICON wxSTD_MDICHILDFRAME_ICON  = (HICON) NULL;
HICON wxSTD_MDIPARENTFRAME_ICON = (HICON) NULL;

HICON wxDEFAULT_FRAME_ICON           = (HICON) NULL;
HICON wxDEFAULT_MDICHILDFRAME_ICON   = (HICON) NULL;
HICON wxDEFAULT_MDIPARENTFRAME_ICON  = (HICON) NULL;

HBRUSH wxDisableButtonBrush = (HBRUSH) 0;

MRESULT EXPENTRY wxWndProc( HWND hWnd,ULONG message,MPARAM mp1,MPARAM mp2);
MRESULT EXPENTRY wxFrameWndProc( HWND hWnd,ULONG message,MPARAM mp1,MPARAM mp2);

// ===========================================================================
// implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// helper struct and functions for socket handling
// ---------------------------------------------------------------------------

struct GsocketCallbackInfo{
    void (*proc)(void *);
    int type;
    int handle;
    void* gsock;
};

// These defines are used here and in gsockpm.cpp
#define wxSockReadMask  0x01
#define wxSockWriteMask 0x02

void wxApp::HandleSockets()
{
    bool pendingEvent = false;

    // Check whether it's time for Gsocket operation
    if (m_maxSocketHandles > 0 && m_maxSocketNr > 0)
    {
        fd_set readfds = m_readfds;
        fd_set writefds = m_writefds;
        struct timeval timeout;
        int i;
        struct GsocketCallbackInfo
          *CallbackInfo = (struct GsocketCallbackInfo *)m_sockCallbackInfo;
        timeout.tv_sec = 0;
        timeout.tv_usec = 0;
        if ( select(m_maxSocketNr, &readfds, &writefds, 0, &timeout) > 0)
        {
            for (i = m_lastUsedHandle + 1; i != m_lastUsedHandle;
                 (i < m_maxSocketNr - 1) ? i++ : (i = 0))
            {
                if (FD_ISSET(i, &readfds))
                {
                    int r;
                    for (r = 0; r < m_maxSocketHandles; r++){
                        if(CallbackInfo[r].handle == i &&
                           CallbackInfo[r].type == wxSockReadMask)
                            break;
                    }
                    if (r < m_maxSocketHandles)
                    {
                        CallbackInfo[r].proc(CallbackInfo[r].gsock);
                        pendingEvent = true;
                    }
                }
                if (FD_ISSET(i, &writefds))
                {
                    int r;
                    for (r = 0; r < m_maxSocketHandles; r++)
                        if(CallbackInfo[r].handle == i &&
                           CallbackInfo[r].type == wxSockWriteMask)
                            break;
                    if (r < m_maxSocketHandles)
                    {
                        CallbackInfo[r].proc(CallbackInfo[r].gsock);
                        pendingEvent = true;
                    }
                }
            }
            m_lastUsedHandle = i;
        }
        if (pendingEvent)
            ProcessPendingEvents();
    }
}
// ---------------------------------------------------------------------------
// wxApp
// ---------------------------------------------------------------------------

    IMPLEMENT_DYNAMIC_CLASS(wxApp, wxEvtHandler)

    BEGIN_EVENT_TABLE(wxApp, wxEvtHandler)
        EVT_IDLE(wxApp::OnIdle)
        EVT_END_SESSION(wxApp::OnEndSession)
        EVT_QUERY_END_SESSION(wxApp::OnQueryEndSession)
    END_EVENT_TABLE()

//
// Initialize
//
bool wxApp::Initialize(int& argc, wxChar **argv)
{
    if ( !wxAppBase::Initialize(argc, argv) )
        return false;

#if defined(wxUSE_CONSOLEDEBUG)
  #if wxUSE_CONSOLEDEBUG
/***********************************************/
/* Code for using stdout debug                 */
/* To use it you mast link app as "Window" - EK*/
/***********************************************/
  {
     PPIB pib;
     PTIB tib;

    printf("In console\n");

  DosGetInfoBlocks(&tib, &pib);
/* Try morphing into a PM application. */
//  if(pib->pib_ultype == 2)    /* VIO */
    pib->pib_ultype = 3;
   }
/**********************************************/
/**********************************************/
  #endif //wxUSE_CONSOLEDEBUG
#endif

    //
    // OS2 has to have an anchorblock
    //
    vHabmain = WinInitialize(0);
    wxFileName GetPrefix(argv[0]);
    GetPrefix.MakeAbsolute();
    wxStandardPaths::SetInstallPrefix(GetPrefix.GetPath());
    if (!vHabmain)
    {
        // TODO: at least give some error message here...
        wxAppBase::CleanUp();

        return false;
    }

    wxBuffer = new wxChar[1500]; // FIXME; why?

    // Some people may wish to use this, but
    // probably it shouldn't be here by default.
    //    wxRedirectIOToConsole();

    wxWinHandleHash = new wxWinHashTable(wxKEY_INTEGER, 100);

    // This is to foil optimizations in Visual C++ that throw out dummy.obj.
    // PLEASE DO NOT ALTER THIS.
#if !defined(WXMAKINGDLL) && defined(__VISAGECPP__)
    extern char wxDummyChar;
    if (wxDummyChar) wxDummyChar++;
#endif

    // wxSetKeyboardHook(TRUE);

    RegisterWindowClasses(vHabmain);

    return true;
} // end of wxApp::Initialize

const char*                         CANTREGISTERCLASS = " Can't register Class ";
// ---------------------------------------------------------------------------
// RegisterWindowClasses
// ---------------------------------------------------------------------------

bool wxApp::RegisterWindowClasses( HAB vHab )
{
    ERRORID vError = 0L;
    wxString sError;

    if (!::WinRegisterClass( vHab
                            ,(PSZ)wxFrameClassName
                            ,wxFrameWndProc
                            ,CS_SIZEREDRAW | CS_SYNCPAINT
                            ,sizeof(ULONG)
                           ))
    {
        vError = ::WinGetLastError(vHab);
        sError = wxPMErrorToStr(vError);
        wxLogLastError(sError.c_str());
        return false;
    }

    if (!::WinRegisterClass( vHab
                            ,(PSZ)wxFrameClassNameNoRedraw
                            ,wxWndProc
                            ,0
                            ,sizeof(ULONG)
                           ))
    {
        vError = ::WinGetLastError(vHab);
        sError = wxPMErrorToStr(vError);
        wxLogLastError(sError.c_str());
        return false;
    }

    if (!::WinRegisterClass( vHab
                            ,(PSZ)wxMDIFrameClassName
                            ,wxWndProc
                            ,CS_SIZEREDRAW | CS_MOVENOTIFY | CS_SYNCPAINT
                            ,sizeof(ULONG)
                           ))
    {
        vError = ::WinGetLastError(vHab);
        sError = wxPMErrorToStr(vError);
        wxLogLastError(sError.c_str());
        return false;
    }

    if (!::WinRegisterClass( vHab
                            ,(PSZ)wxMDIFrameClassNameNoRedraw
                            ,wxWndProc
                            ,0
                            ,sizeof(ULONG)
                           ))
    {
        vError = ::WinGetLastError(vHab);
        sError = wxPMErrorToStr(vError);
        wxLogLastError(sError.c_str());
        return false;
    }

    if (!::WinRegisterClass( vHab
                            ,(PSZ)wxMDIChildFrameClassName
                            ,wxWndProc
                            ,CS_MOVENOTIFY | CS_SIZEREDRAW | CS_SYNCPAINT | CS_HITTEST
                            ,sizeof(ULONG)
                           ))
    {
        vError = ::WinGetLastError(vHab);
        sError = wxPMErrorToStr(vError);
        wxLogLastError(sError.c_str());
        return false;
    }

    if (!::WinRegisterClass( vHab
                            ,(PSZ)wxMDIChildFrameClassNameNoRedraw
                            ,wxWndProc
                            ,CS_HITTEST
                            ,sizeof(ULONG)
                           ))
    {
        vError = ::WinGetLastError(vHab);
        sError = wxPMErrorToStr(vError);
        wxLogLastError(sError.c_str());
        return false;
    }

    if (!::WinRegisterClass( vHab
                            ,(PSZ)wxPanelClassName
                            ,wxWndProc
                            ,CS_MOVENOTIFY | CS_SIZEREDRAW | CS_HITTEST | CS_SAVEBITS | CS_SYNCPAINT
                            ,sizeof(ULONG)
                           ))
    {
        vError = ::WinGetLastError(vHab);
        sError = wxPMErrorToStr(vError);
        wxLogLastError(sError.c_str());
        return false;
    }

    if (!::WinRegisterClass( vHab
                            ,(PSZ)wxCanvasClassName
                            ,wxWndProc
                            ,CS_SIZEREDRAW | CS_HITTEST | CS_SYNCPAINT
                            ,sizeof(ULONG)
                           ))
    {
        vError = ::WinGetLastError(vHab);
        sError = wxPMErrorToStr(vError);
        wxLogLastError(sError.c_str());
        return false;
    }
    if (!::WinRegisterClass( vHab
                            ,(PSZ)wxCanvasClassNameNR
                            ,wxWndProc
                            ,CS_HITTEST | CS_SYNCPAINT
                            ,sizeof(ULONG)
                           ))
    {
        vError = ::WinGetLastError(vHab);
        sError = wxPMErrorToStr(vError);
        wxLogLastError(sError.c_str());
        return false;
    }
    return true;
} // end of wxApp::RegisterWindowClasses

//
// Cleans up any wxWidgets internal structures left lying around
//
void wxApp::CleanUp()
{
    wxDELETEA(wxBuffer);

    //
    // PM-SPECIFIC CLEANUP
    //

    // wxSetKeyboardHook(false);

    if (wxSTD_FRAME_ICON)
        ::WinFreeFileIcon(wxSTD_FRAME_ICON);
    if (wxSTD_MDICHILDFRAME_ICON)
        ::WinFreeFileIcon(wxSTD_MDICHILDFRAME_ICON);
    if (wxSTD_MDIPARENTFRAME_ICON)
        ::WinFreeFileIcon(wxSTD_MDIPARENTFRAME_ICON);

    if (wxDEFAULT_FRAME_ICON)
        ::WinFreeFileIcon(wxDEFAULT_FRAME_ICON);
    if (wxDEFAULT_MDICHILDFRAME_ICON)
        ::WinFreeFileIcon(wxDEFAULT_MDICHILDFRAME_ICON);
    if (wxDEFAULT_MDIPARENTFRAME_ICON)
        ::WinFreeFileIcon(wxDEFAULT_MDIPARENTFRAME_ICON);

    if ( wxDisableButtonBrush )
    {
// TODO:        ::DeleteObject( wxDisableButtonBrush );
    }

    wxDELETE(wxWinHandleHash);

    // Delete Message queue
    if (wxTheApp->m_hMq)
        ::WinDestroyMsgQueue(wxTheApp->m_hMq);

    wxAppBase::CleanUp();
} // end of wxApp::CleanUp

bool wxApp::OnInitGui()
{
    ERRORID vError;
    wxString sError;

    if (!wxAppBase::OnInitGui())
        return false;

    m_hMq = ::WinCreateMsgQueue(vHabmain, 0);
    if (!m_hMq)
    {
        vError = ::WinGetLastError(vHabmain);
        sError = wxPMErrorToStr(vError);
        wxLogDebug(sError);
        return false;
    }

    return true;
} // end of wxApp::OnInitGui

wxApp::wxApp()
{
    m_nPrintMode = wxPRINT_WINDOWS;
    m_hMq = 0;
    m_maxSocketHandles = 0;
    m_maxSocketNr = 0;
    m_sockCallbackInfo = 0;
} // end of wxApp::wxApp

wxApp::~wxApp()
{
} // end of wxApp::~wxApp

bool gbInOnIdle = false;

void wxApp::OnIdle( wxIdleEvent& WXUNUSED(rEvent) )
{
    //
    // Avoid recursion (via ProcessEvent default case)
    //
    if (gbInOnIdle)
        return;

    gbInOnIdle = true;

#if wxUSE_DC_CACHEING
    // automated DC cache management: clear the cached DCs and bitmap
    // if it's likely that the app has finished with them, that is, we
    // get an idle event and we're not dragging anything.
    if (!::WinGetKeyState(HWND_DESKTOP, VK_BUTTON1) &&
        !::WinGetKeyState(HWND_DESKTOP, VK_BUTTON3) &&
        !::WinGetKeyState(HWND_DESKTOP, VK_BUTTON2))
        wxDC::ClearCache();
#endif // wxUSE_DC_CACHEING

    gbInOnIdle = false;
} // end of wxApp::OnIdle

void wxApp::OnEndSession(
  wxCloseEvent&                     WXUNUSED(rEvent))
{
    if (GetTopWindow())
        GetTopWindow()->Close(true);
} // end of wxApp::OnEndSession

//
// Default behaviour: close the application with prompts. The
// user can veto the close, and therefore the end session.
//
void wxApp::OnQueryEndSession( wxCloseEvent& rEvent )
{
    if (GetTopWindow())
    {
        if (!GetTopWindow()->Close(!rEvent.CanVeto()))
            rEvent.Veto(true);
    }
} // end of wxApp::OnQueryEndSession

int wxApp::AddSocketHandler(int handle, int mask,
                            void (*callback)(void*), void * gsock)
{
    int find;
    struct GsocketCallbackInfo
        *CallbackInfo = (struct GsocketCallbackInfo *)m_sockCallbackInfo;

    for (find = 0; find < m_maxSocketHandles; find++)
        if (CallbackInfo[find].handle == -1)
            break;
    if (find == m_maxSocketHandles)
    {
        // Allocate new memory
        m_sockCallbackInfo = realloc(m_sockCallbackInfo,
                                     (m_maxSocketHandles+=10)*
                                     sizeof(struct GsocketCallbackInfo));
        CallbackInfo = (struct GsocketCallbackInfo *)m_sockCallbackInfo;
        for (find = m_maxSocketHandles - 10; find < m_maxSocketHandles; find++)
            CallbackInfo[find].handle = -1;
        find = m_maxSocketHandles - 10;
    }
    CallbackInfo[find].proc = callback;
    CallbackInfo[find].type = mask;
    CallbackInfo[find].handle = handle;
    CallbackInfo[find].gsock = gsock;
    if (mask & wxSockReadMask)
        FD_SET(handle, &m_readfds);
    if (mask & wxSockWriteMask)
        FD_SET(handle, &m_writefds);
    if (handle >= m_maxSocketNr)
        m_maxSocketNr = handle + 1;
    return find;
}

void wxApp::RemoveSocketHandler(int handle)
{
    struct GsocketCallbackInfo
        *CallbackInfo = (struct GsocketCallbackInfo *)m_sockCallbackInfo;
    if (handle < m_maxSocketHandles)
    {
        if (CallbackInfo[handle].type & wxSockReadMask)
            FD_CLR(CallbackInfo[handle].handle, &m_readfds);
        if (CallbackInfo[handle].type & wxSockWriteMask)
            FD_CLR(CallbackInfo[handle].handle, &m_writefds);
        CallbackInfo[handle].handle = -1;
    }
}

//-----------------------------------------------------------------------------
// wxWakeUpIdle
//-----------------------------------------------------------------------------

void wxApp::WakeUpIdle()
{
    //
    // Send the top window a dummy message so idle handler processing will
    // start up again.  Doing it this way ensures that the idle handler
    // wakes up in the right thread (see also wxWakeUpMainThread() which does
    // the same for the main app thread only)
    //
    wxWindow*                       pTopWindow = wxTheApp->GetTopWindow();

    if (pTopWindow)
    {
        if ( !::WinPostMsg(GetHwndOf(pTopWindow), WM_NULL, (MPARAM)0, (MPARAM)0))
        {
            //
            // Should never happen
            //
            wxLogLastError(wxT("PostMessage(WM_NULL)"));
        }
    }
} // end of wxWakeUpIdle

HAB wxGetInstance()
{
    return vHabmain;
}

void wxSetInstance( HAB vHab )
{
    vHabmain = vHab;
}
