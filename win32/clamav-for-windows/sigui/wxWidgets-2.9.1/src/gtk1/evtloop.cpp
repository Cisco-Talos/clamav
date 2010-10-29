///////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/evtloop.cpp
// Purpose:     implements wxEventLoop for GTK+
// Author:      Vadim Zeitlin
// Modified by:
// Created:     10.07.01
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

#include "wx/evtloop.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/log.h"
#endif // WX_PRECOMP

#include <gtk/gtk.h>

// ----------------------------------------------------------------------------
// wxEventLoopImpl
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxEventLoopImpl
{
public:
    // ctor
    wxEventLoopImpl() { SetExitCode(0); }

    // set/get the exit code
    void SetExitCode(int exitcode) { m_exitcode = exitcode; }
    int GetExitCode() const { return m_exitcode; }

private:
    // the exit code of the event loop
    int m_exitcode;
};

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

    wxEventLoopActivator activate(this);

    m_impl = new wxEventLoopImpl;

    gtk_main();

    OnExit();

    int exitcode = m_impl->GetExitCode();
    wxDELETE(m_impl);

    return exitcode;
}

void wxGUIEventLoop::Exit(int rc)
{
    wxCHECK_RET( IsRunning(), wxT("can't call Exit() if not running") );

    m_impl->SetExitCode(rc);

    gtk_main_quit();
}

// ----------------------------------------------------------------------------
// wxEventLoop message processing dispatching
// ----------------------------------------------------------------------------

bool wxGUIEventLoop::Pending() const
{
    if (wxTheApp)
    {
        // We need to remove idle callbacks or gtk_events_pending will
        // never return false.
        wxTheApp->RemoveIdleTag();
    }

    return gtk_events_pending();
}

bool wxGUIEventLoop::Dispatch()
{
    wxCHECK_MSG( IsRunning(), false, wxT("can't call Dispatch() if not running") );

    gtk_main_iteration();

    return true;
}

//-----------------------------------------------------------------------------
// wxYield
//-----------------------------------------------------------------------------

bool wxGUIEventLoop::YieldFor(long eventsToProcess)
{
#if wxUSE_THREADS
    if ( !wxThread::IsMain() )
    {
        // can't call gtk_main_iteration() from other threads like this
        return true;
    }
#endif // wxUSE_THREADS

    m_isInsideYield = true;
    m_eventsToProcessInsideYield = eventsToProcess;

    // We need to remove idle callbacks or the loop will
    // never finish.
    wxTheApp->RemoveIdleTag();

#if wxUSE_LOG
    // disable log flushing from here because a call to wxYield() shouldn't
    // normally result in message boxes popping up &c
    wxLog::Suspend();
#endif

    // TODO: implement event filtering using the eventsToProcess mask
    while (gtk_events_pending())
        gtk_main_iteration();

    // It's necessary to call ProcessIdle() to update the frames sizes which
    // might have been changed (it also will update other things set from
    // OnUpdateUI() which is a nice (and desired) side effect). But we
    // call ProcessIdle() only once since this is not meant for longish
    // background jobs (controlled by wxIdleEvent::RequestMore() and the
    // return value of Processidle().
    ProcessIdle();

#if wxUSE_LOG
    // let the logs be flashed again
    wxLog::Resume();
#endif

    m_isInsideYield = false;

    return true;
}
