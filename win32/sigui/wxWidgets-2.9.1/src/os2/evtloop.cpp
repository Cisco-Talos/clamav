///////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/evtloop.cpp
// Purpose:     implements wxGUIEventLoop for PM
// Author:      Vadim Zeitlin
// Modified by:
// Created:     01.06.01
// RCS-ID:      $Id$
// Copyright:   (c) 2001 Vadim Zeitlin <zeitlin@dptmaths.ens-cachan.fr>
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

#ifndef WX_PRECOMP
    #include "wx/window.h"
    #include "wx/app.h"
    #include "wx/timer.h"
    #include "wx/log.h"
#endif //WX_PRECOMP

#include "wx/evtloop.h"
#include "wx/tooltip.h"
#include "wx/scopedptr.h"

#include "wx/os2/private.h"
#include "wx/os2/private/timer.h"       // for wxTimerProc

#if wxUSE_THREADS
    // define the array of QMSG strutures
    WX_DECLARE_OBJARRAY(QMSG, wxMsgArray);

    #include "wx/arrimpl.cpp"

    WX_DEFINE_OBJARRAY(wxMsgArray);
#endif

extern HAB vHabmain;

// ----------------------------------------------------------------------------
// wxEventLoopImpl
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxEventLoopImpl
{
public:
    // ctor
    wxEventLoopImpl() { SetExitCode(0); }

    // process a message
    void ProcessMessage(QMSG *msg);

    // generate an idle message, return TRUE if more idle time requested
    bool SendIdleMessage();

    // set/get the exit code
    void SetExitCode(int exitcode) { m_exitcode = exitcode; }
    int GetExitCode() const { return m_exitcode; }

private:
    // preprocess a message, return TRUE if processed (i.e. no further
    // dispatching required)
    bool PreProcessMessage(QMSG *msg);

    // the exit code of the event loop
    int m_exitcode;
};

// ----------------------------------------------------------------------------
// helper class
// ----------------------------------------------------------------------------

wxDEFINE_TIED_SCOPED_PTR_TYPE(wxEventLoopImpl);

// ============================================================================
// wxEventLoopImpl implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxEventLoopImpl message processing
// ----------------------------------------------------------------------------

void wxEventLoopImpl::ProcessMessage(QMSG *msg)
{
    // give us the chance to preprocess the message first
    if ( !PreProcessMessage(msg) )
    {
        // if it wasn't done, dispatch it to the corresponding window
        ::WinDispatchMsg(vHabmain, msg);
    }
}

bool wxEventLoopImpl::PreProcessMessage(QMSG *pMsg)
{
    HWND hWnd = pMsg->hwnd;
    wxWindow *pWndThis = wxFindWinFromHandle((WXHWND)hWnd);
    wxWindow *pWnd;

    //
    // Pass non-system timer messages to the wxTimerProc
    //
    if (pMsg->msg == WM_TIMER &&
        (SHORT1FROMMP(pMsg->mp1) != TID_CURSOR &&
         SHORT1FROMMP(pMsg->mp1) != TID_FLASHWINDOW &&
         SHORT1FROMMP(pMsg->mp1) != TID_SCROLL &&
         SHORT1FROMMP(pMsg->mp1) != 0x0000
        ))
        wxTimerProc(NULL, 0, (int)pMsg->mp1, 0);

    // Allow the window to prevent certain messages from being
    // translated/processed (this is currently used by wxTextCtrl to always
    // grab Ctrl-C/V/X, even if they are also accelerators in some parent)
    //
    if (pWndThis && !pWndThis->OS2ShouldPreProcessMessage((WXMSG*)pMsg))
    {
        return FALSE;
    }

    //
    // For some composite controls (like a combobox), wndThis might be NULL
    // because the subcontrol is not a wxWindow, but only the control itself
    // is - try to catch this case
    //
    while (hWnd && !pWndThis)
    {
        hWnd = ::WinQueryWindow(hWnd, QW_PARENT);
        pWndThis = wxFindWinFromHandle((WXHWND)hWnd);
    }


    //
    // Try translations first; find the youngest window with
    // a translation table. OS/2 has case sensiive accels, so
    // this block, coded by BK, removes that and helps make them
    // case insensitive.
    //
    if(pMsg->msg == WM_CHAR)
    {
       PBYTE                        pChmsg = (PBYTE)&(pMsg->msg);
       USHORT                       uSch  = CHARMSG(pChmsg)->chr;
       bool                         bRc = FALSE;

       //
       // Do not process keyup events
       //
       if(!(CHARMSG(pChmsg)->fs & KC_KEYUP))
       {
           if((CHARMSG(pChmsg)->fs & (KC_ALT | KC_CTRL)) && CHARMSG(pChmsg)->chr != 0)
                CHARMSG(pChmsg)->chr = (USHORT)wxToupper((UCHAR)uSch);


           for(pWnd = pWndThis; pWnd; pWnd = pWnd->GetParent() )
           {
               if((bRc = pWnd->OS2TranslateMessage((WXMSG*)pMsg)) == TRUE)
                   break;
               // stop at first top level window, i.e. don't try to process the
               // key strokes originating in a dialog using the accelerators of
               // the parent frame - this doesn't make much sense
               if ( pWnd->IsTopLevel() )
                   break;
           }

            if(!bRc)    // untranslated, should restore original value
                CHARMSG(pChmsg)->chr = uSch;
        }
    }
    //
    // Anyone for a non-translation message? Try youngest descendants first.
    //
//  for (pWnd = pWndThis->GetParent(); pWnd; pWnd = pWnd->GetParent())
//  {
//      if (pWnd->OS2ProcessMessage(pWxmsg))
//          return TRUE;
//  }
    return FALSE;
}

// ----------------------------------------------------------------------------
// wxEventLoopImpl idle event processing
// ----------------------------------------------------------------------------

bool wxEventLoopImpl::SendIdleMessage()
{
    return wxTheApp->ProcessIdle() ;
}

// ============================================================================
// wxGUIEventLoop implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxGUIEventLoop running and exiting
// ----------------------------------------------------------------------------

wxGUIEventLoop::~wxGUIEventLoop()
{
    wxASSERT_MSG( !m_impl, wxT("should have been deleted in Run()") );
}

//////////////////////////////////////////////////////////////////////////////
//
// Keep trying to process messages until WM_QUIT
// received.
//
// If there are messages to be processed, they will all be
// processed and OnIdle will not be called.
// When there are no more messages, OnIdle is called.
// If OnIdle requests more time,
// it will be repeatedly called so long as there are no pending messages.
// A 'feature' of this is that once OnIdle has decided that no more processing
// is required, then it won't get processing time until further messages
// are processed (it'll sit in Dispatch).
//
//////////////////////////////////////////////////////////////////////////////
class CallEventLoopMethod
{
public:
    typedef void (wxGUIEventLoop::*FuncType)();

    CallEventLoopMethod(wxGUIEventLoop *evtLoop, FuncType fn)
        : m_evtLoop(evtLoop), m_fn(fn) { }
    ~CallEventLoopMethod() { (m_evtLoop->*m_fn)(); }

private:
    wxGUIEventLoop *m_evtLoop;
    FuncType m_fn;
};

int wxGUIEventLoop::Run()
{
    // event loops are not recursive, you need to create another loop!
    wxCHECK_MSG( !IsRunning(), -1, wxT("can't reenter a message loop") );

    // SendIdleMessage() and Dispatch() below may throw so the code here should
    // be exception-safe, hence we must use local objects for all actions we
    // should undo
    wxEventLoopActivator activate(this);
    wxEventLoopImplTiedPtr impl(&m_impl, new wxEventLoopImpl);

    CallEventLoopMethod  callOnExit(this, &wxGUIEventLoop::OnExit);

    for ( ;; )
    {
#if wxUSE_THREADS
        wxMutexGuiLeaveOrEnter();
#endif // wxUSE_THREADS

        // generate and process idle events for as long as we don't have
        // anything else to do
        while ( !Pending() && m_impl->SendIdleMessage() )
        {
            wxTheApp->HandleSockets();
            wxMilliSleep(10);
        }

        wxTheApp->HandleSockets();
        if (Pending())
        {
            if ( !Dispatch() )
            {
                // we got WM_QUIT
                break;
            }
        }
        else
            wxMilliSleep(10);
    }

    OnExit();

    return m_impl->GetExitCode();
}

void wxGUIEventLoop::Exit(int rc)
{
    wxCHECK_RET( IsRunning(), wxT("can't call Exit() if not running") );

    m_impl->SetExitCode(rc);

    ::WinPostMsg(NULL, WM_QUIT, 0, 0);
}

// ----------------------------------------------------------------------------
// wxGUIEventLoop message processing dispatching
// ----------------------------------------------------------------------------

bool wxGUIEventLoop::Pending() const
{
    QMSG msg;
    return ::WinPeekMsg(vHabmain, &msg, 0, 0, 0, PM_NOREMOVE) != 0;
}

bool wxGUIEventLoop::Dispatch()
{
    wxCHECK_MSG( IsRunning(), false, wxT("can't call Dispatch() if not running") );

    QMSG msg;
    BOOL bRc = ::WinGetMsg(vHabmain, &msg, (HWND) NULL, 0, 0);

    if ( bRc == 0 )
    {
        // got WM_QUIT
        return false;
    }

#if wxUSE_THREADS
    wxASSERT_MSG( wxThread::IsMain(),
                  wxT("only the main thread can process Windows messages") );

    static bool s_hadGuiLock = true;
    static wxMsgArray s_aSavedMessages;

    // if a secondary thread owning the mutex is doing GUI calls, save all
    // messages for later processing - we can't process them right now because
    // it will lead to recursive library calls (and we're not reentrant)
    if ( !wxGuiOwnedByMainThread() )
    {
        s_hadGuiLock = false;

        // leave out WM_COMMAND messages: too dangerous, sometimes
        // the message will be processed twice
        if ( !wxIsWaitingForThread() || msg.msg != WM_COMMAND )
        {
            s_aSavedMessages.Add(msg);
        }

        return true;
    }
    else
    {
        // have we just regained the GUI lock? if so, post all of the saved
        // messages
        //
        // FIXME of course, it's not _exactly_ the same as processing the
        //       messages normally - expect some things to break...
        if ( !s_hadGuiLock )
        {
            s_hadGuiLock = true;

            size_t count = s_aSavedMessages.Count();
            for ( size_t n = 0; n < count; n++ )
            {
                QMSG& msg = s_aSavedMessages[n];
                m_impl->ProcessMessage(&msg);
            }

            s_aSavedMessages.Empty();
        }
    }
#endif // wxUSE_THREADS

    m_impl->ProcessMessage(&msg);

    return true;
}

//
// Yield to incoming messages
//
bool wxGUIEventLoop::YieldFor(long eventsToProcess)
{
    HAB vHab = 0;
    QMSG vMsg;

    //
    // Disable log flushing from here because a call to wxYield() shouldn't
    // normally result in message boxes popping up &c
    //
    wxLog::Suspend();

    m_isInsideYield = true;
    m_eventsToProcessInsideYield = eventsToProcess;

    //
    // We want to go back to the main message loop
    // if we see a WM_QUIT. (?)
    //
    while (::WinPeekMsg(vHab, &vMsg, (HWND)NULL, 0, 0, PM_NOREMOVE) && vMsg.msg != WM_QUIT)
    {
        // TODO: implement event filtering using the eventsToProcess mask

#if wxUSE_THREADS
        wxMutexGuiLeaveOrEnter();
#endif // wxUSE_THREADS
        if (!wxTheApp->Dispatch())
            break;
    }

    //
    // If they are pending events, we must process them.
    //
    if (wxTheApp)
    {
        wxTheApp->ProcessPendingEvents();
        wxTheApp->HandleSockets();
    }

    //
    // Let the logs be flashed again
    //
    wxLog::Resume();
    m_isInsideYield = false;

    return true;
} // end of wxYield
