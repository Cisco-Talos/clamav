///////////////////////////////////////////////////////////////////////////////
// Name:        src/mgl/evtloop.cpp
// Purpose:     implements wxEventLoop for MGL
// Author:      Vaclav Slavik
// RCS-ID:      $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

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
    #include "wx/thread.h"
    #include "wx/timer.h"
#endif //WX_PRECOMP

#include "wx/evtloop.h"

#include "wx/generic/private/timer.h"
#include "wx/mgl/private.h"

// ----------------------------------------------------------------------------
// wxEventLoopImpl
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxEventLoopImpl
{
public:
    // ctor
    wxEventLoopImpl()
        {
            SetExitCode(0);
            SetKeepLooping(true);
        }

    // process an event
    void Dispatch();

    // generate an idle event, return true if more idle time requested
    bool SendIdleEvent();

    // set/get the exit code
    void SetExitCode(int exitcode) { m_exitcode = exitcode; }
    int GetExitCode() const { return m_exitcode; }

    void SetKeepLooping(bool k) { m_keepLooping = k; }
    bool GetKeepLooping() const { return m_keepLooping; }

private:

    // the exit code of the event loop
    int m_exitcode;
    // false if the loop should end
    bool m_keepLooping;
};

// ============================================================================
// wxEventLoopImpl implementation
// ============================================================================

void wxEventLoopImpl::Dispatch()
{
    event_t evt;

    // VS: The code bellow is equal to MGL's EVT_halt implementation, with
    //     two things added: sleeping (busy waiting is stupid, lets make CPU's
    //     life a bit easier) and timers updating

    // EVT_halt(&evt, EVT_EVERYEVT);
    for (;;)
    {
#if wxUSE_TIMER
        wxGenericTimerImpl::NotifyTimers();
#endif
        MGL_wmUpdateDC(g_winMng);

        EVT_pollJoystick();
        if ( EVT_getNext(&evt, EVT_EVERYEVT) ) break;
        PM_sleep(10);
    }
    // end of EVT_halt

    MGL_wmProcessEvent(g_winMng, &evt);
}

bool wxEventLoopImpl::SendIdleEvent()
{
    return wxTheApp->ProcessIdle();
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

int wxGUIEventLoop::Run()
{
    // event loops are not recursive, you need to create another loop!
    wxCHECK_MSG( !IsRunning(), -1, wxT("can't reenter a message loop") );

    m_impl = new wxEventLoopImpl;

    wxEventLoopActivator activate(this);

    for ( ;; )
    {
#if wxUSE_THREADS
        //wxMutexGuiLeaveOrEnter(); // FIXME_MGL - huh?
#endif // wxUSE_THREADS

        // generate and process idle events for as long as we don't have
        // anything else to do
        while ( !Pending() && m_impl->SendIdleEvent() ) {}

        // a message came or no more idle processing to do, sit in Dispatch()
        // waiting for the next message
        if ( !Dispatch() )
        {
            // app terminated
            break;
        }
    }

    OnExit();

    int exitcode = m_impl->GetExitCode();
    wxDELETE(m_impl);

    return exitcode;
}

void wxGUIEventLoop::Exit(int rc)
{
    wxCHECK_RET( IsRunning(), wxT("can't call Exit() if not running") );

    m_impl->SetExitCode(rc);
    m_impl->SetKeepLooping(false);

    // Send a dummy event so that the app won't block in EVT_halt if there
    // are no user-generated events in the queue:
    EVT_post(0, EVT_USEREVT, 0, 0);
}

// ----------------------------------------------------------------------------
// wxEventLoop message processing dispatching
// ----------------------------------------------------------------------------

bool wxGUIEventLoop::Pending() const
{
    // update the display here, so that wxYield refreshes display and
    // changes take effect immediately, not after emptying events queue:
    MGL_wmUpdateDC(g_winMng);

    // is there an event in the queue?
    event_t evt;
    return (bool)(EVT_peekNext(&evt, EVT_EVERYEVT));
}

bool wxGUIEventLoop::Dispatch()
{
    wxCHECK_MSG( IsRunning(), false, wxT("can't call Dispatch() if not running") );

    m_impl->Dispatch();
    return m_impl->GetKeepLooping();
}


//-----------------------------------------------------------------------------
// wxYield
//-----------------------------------------------------------------------------

bool wxGUIEventLoop::YieldFor(long eventsToProcess)
{
#if wxUSE_THREADS
    if ( !wxThread::IsMain() )
    {
        // can't process events from other threads, MGL is thread-unsafe
        return true;
    }
#endif // wxUSE_THREADS

    m_isInsideYield = true;
    m_eventsToProcessInsideYield = eventsToProcess;

    wxLog::Suspend();

    // TODO: implement event filtering using the eventsToProcess mask

    while (Pending())
        Dispatch();

    /* it's necessary to call ProcessIdle() to update the frames sizes which
       might have been changed (it also will update other things set from
       OnUpdateUI() which is a nice (and desired) side effect) */
    while (wxTheApp->ProcessIdle()) { }

    wxLog::Resume();

    m_isInsideYield = false;

    return true;
}
