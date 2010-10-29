///////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/evtloop.cpp
// Purpose:     implements wxEventLoop for X11
// Author:      Julian Smart
// Modified by:
// Created:     01.06.01
// RCS-ID:      $Id$
// Copyright:   (c) 2002 Julian Smart
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/evtloop.h"

#ifndef WX_PRECOMP
    #include "wx/hash.h"
    #include "wx/app.h"
    #include "wx/window.h"
    #include "wx/module.h"
#endif

#include "wx/private/fdiodispatcher.h"
#include "wx/unix/private.h"
#include "wx/x11/private.h"
#include "wx/generic/private/timer.h"

#if wxUSE_THREADS
    #include "wx/thread.h"
#endif

#include <X11/Xlib.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef HAVE_SYS_SELECT_H
#   include <sys/select.h>
#endif

// ----------------------------------------------------------------------------
// wxEventLoopImpl
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxEventLoopImpl
{
public:
    // ctor
    wxEventLoopImpl() { SetExitCode(0); m_keepGoing = false; }

    // process an XEvent, return true if it was processed
    bool ProcessEvent(XEvent* event);

    // generate an idle message, return true if more idle time requested
    bool SendIdleEvent();

    // set/get the exit code
    void SetExitCode(int exitcode) { m_exitcode = exitcode; }
    int GetExitCode() const { return m_exitcode; }

public:
    // preprocess an event, return true if processed (i.e. no further
    // dispatching required)
    bool PreProcessEvent(XEvent* event);

    // the exit code of the event loop
    int m_exitcode;

    bool m_keepGoing;
};

// ============================================================================
// wxEventLoopImpl implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxEventLoopImpl message processing
// ----------------------------------------------------------------------------

bool wxEventLoopImpl::ProcessEvent(XEvent *event)
{
    // give us the chance to preprocess the message first
    if ( PreProcessEvent(event) )
        return true;

    // if it wasn't done, dispatch it to the corresponding window
    if (wxTheApp)
        return wxTheApp->ProcessXEvent((WXEvent*) event);

    return false;
}

bool wxEventLoopImpl::PreProcessEvent(XEvent *WXUNUSED(event))
{
    return false;
}

// ----------------------------------------------------------------------------
// wxEventLoopImpl idle event processing
// ----------------------------------------------------------------------------

bool wxEventLoopImpl::SendIdleEvent()
{
    return wxTheApp->ProcessIdle();
}

// ============================================================================
// wxEventLoop implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxEventLoop running and exiting
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

    m_impl->m_keepGoing = true;
    while ( m_impl->m_keepGoing )
    {
        // generate and process idle events for as long as we don't have
        // anything else to do
        while ( ! Pending() )
        {
#if wxUSE_TIMER
            wxGenericTimerImpl::NotifyTimers(); // TODO: is this the correct place for it?
#endif
            if (!m_impl->SendIdleEvent())
            {
                // Break out of while loop
                break;
            }
        }

        // a message came or no more idle processing to do, sit in Dispatch()
        // waiting for the next message
        if ( !Dispatch() )
        {
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
    m_impl->m_keepGoing = false;
}

// ----------------------------------------------------------------------------
// wxEventLoop message processing dispatching
// ----------------------------------------------------------------------------

bool wxGUIEventLoop::Pending() const
{
    XFlush( wxGlobalDisplay() );
    return (XPending( wxGlobalDisplay() ) > 0);
}

bool wxGUIEventLoop::Dispatch()
{
    // see comment in wxEventLoopManual::ProcessEvents()
    if ( wxTheApp )
        wxTheApp->ProcessPendingEvents();

    XEvent event;

    // TODO allowing for threads, as per e.g. wxMSW

    // This now waits until either an X event is received,
    // or the select times out. So we should now process
    // wxTimers in a reasonably timely fashion. However it
    // does also mean that idle processing will happen more
    // often, so we should probably limit idle processing to
    // not be repeated more than every N milliseconds.

    if (XPending( wxGlobalDisplay() ) == 0)
    {
#if wxUSE_NANOX
        GR_TIMEOUT timeout = 10; // Milliseconds
        // Wait for next event, or timeout
        GrGetNextEventTimeout(& event, timeout);

        // Fall through to ProcessEvent.
        // we'll assume that ProcessEvent will just ignore
        // the event if there was a timeout and no event.

#else
        struct timeval tv;
        tv.tv_sec=0;
        tv.tv_usec=10000; // TODO make this configurable
        int fd = ConnectionNumber( wxGlobalDisplay() );

        fd_set readset;
        fd_set writeset;
        wxFD_ZERO(&readset);
        wxFD_ZERO(&writeset);
        wxFD_SET(fd, &readset);

        if (select( fd+1, &readset, &writeset, NULL, &tv ) != 0)
        {
            // An X11 event was pending, get it
            if (wxFD_ISSET( fd, &readset ))
                XNextEvent( wxGlobalDisplay(), &event );
        }
#endif
    }
    else
    {
        XNextEvent( wxGlobalDisplay(), &event );
    }

#if wxUSE_SOCKETS
    // handle any pending socket events:
    wxFDIODispatcher::DispatchPending();
#endif

    (void) m_impl->ProcessEvent( &event );
    return true;
}

bool wxGUIEventLoop::YieldFor(long eventsToProcess)
{
    // Sometimes only 2 yields seem
    // to do the trick, e.g. in the
    // progress dialog
    int i;
    for (i = 0; i < 2; i++)
    {
        m_isInsideYield = true;
        m_eventsToProcessInsideYield = eventsToProcess;

        // Call dispatch at least once so that sockets
        // can be tested
        wxTheApp->Dispatch();

        // TODO: implement event filtering using the eventsToProcess mask
        while (wxTheApp && wxTheApp->Pending())
            wxTheApp->Dispatch();

#if wxUSE_TIMER
        wxGenericTimerImpl::NotifyTimers();
#endif
        ProcessIdle();

        m_isInsideYield = false;
    }

    return true;
}
