///////////////////////////////////////////////////////////////////////////////
// Name:        src/osx/core/evtloop_cf.cpp
// Purpose:     wxEventLoop implementation common to both Carbon and Cocoa
// Author:      Vadim Zeitlin
// Created:     2009-10-18
// RCS-ID:      $Id$
// Copyright:   (c) 2009 Vadim Zeitlin <vadim@wxwidgets.org>
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

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/evtloop.h"

#if wxUSE_EVENTLOOP_SOURCE

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
#endif

#include "wx/evtloopsrc.h"

#include "wx/scopedptr.h"

#include "wx/osx/private.h"
#include "wx/osx/core/cfref.h"

#if wxUSE_GUI
    #include "wx/nonownedwnd.h"
#endif

// ============================================================================
// wxCFEventLoopSource and wxCFEventLoop implementation
// ============================================================================

#if MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_5
namespace
{

void EnableDescriptorCallBacks(CFFileDescriptorRef cffd, int flags)
{
    if ( flags & wxEVENT_SOURCE_INPUT )
        CFFileDescriptorEnableCallBacks(cffd, kCFFileDescriptorReadCallBack);
    if ( flags & wxEVENT_SOURCE_OUTPUT )
        CFFileDescriptorEnableCallBacks(cffd, kCFFileDescriptorWriteCallBack);
}

void
wx_cffiledescriptor_callback(CFFileDescriptorRef cffd,
                             CFOptionFlags flags,
                             void *ctxData)
{
    wxLogTrace(wxTRACE_EVT_SOURCE,
               "CFFileDescriptor callback, flags=%d", flags);

    wxCFEventLoopSource * const
        source = static_cast<wxCFEventLoopSource *>(ctxData);

    wxEventLoopSourceHandler * const
        handler = source->GetHandler();
    if ( flags & kCFFileDescriptorReadCallBack )
        handler->OnReadWaiting();
    if ( flags & kCFFileDescriptorWriteCallBack )
        handler->OnWriteWaiting();

    // we need to re-enable callbacks to be called again
    EnableDescriptorCallBacks(cffd, source->GetFlags());
}

} // anonymous namespace

wxEventLoopSource *
wxCFEventLoop::AddSourceForFD(int fd,
                              wxEventLoopSourceHandler *handler,
                              int flags)
{
    wxCHECK_MSG( fd != -1, NULL, "can't monitor invalid fd" );

    wxScopedPtr<wxCFEventLoopSource>
        source(new wxCFEventLoopSource(handler, flags));

    CFFileDescriptorContext ctx = { 0, source.get(), NULL, NULL, NULL };
    wxCFRef<CFFileDescriptorRef>
        cffd(CFFileDescriptorCreate
             (
                  kCFAllocatorDefault,
                  fd,
                  true,   // close on invalidate
                  wx_cffiledescriptor_callback,
                  &ctx
             ));
    if ( !cffd )
        return NULL;

    source->SetFileDescriptor(cffd.release());

    wxCFRef<CFRunLoopSourceRef>
        cfsrc(CFFileDescriptorCreateRunLoopSource(kCFAllocatorDefault, cffd, 0));
    if ( !cfsrc )
        return NULL;

    CFRunLoopRef cfloop = CFGetCurrentRunLoop();
    CFRunLoopAddSource(cfloop, cfsrc, kCFRunLoopDefaultMode);

    return source.release();
}

void wxCFEventLoopSource::SetFileDescriptor(CFFileDescriptorRef cffd)
{
    wxASSERT_MSG( !m_cffd, "shouldn't be called more than once" );

    m_cffd = cffd;
}

wxCFEventLoopSource::~wxCFEventLoopSource()
{
    if ( m_cffd )
        CFRelease(m_cffd);
}

#else // OS X < 10.5

wxEventLoopSource *
wxCFEventLoop::AddSourceForFD(int WXUNUSED(fd),
                              wxEventLoopSourceHandler * WXUNUSED(handler),
                              int WXUNUSED(flags))
{
    return NULL;
}

#endif // MAC_OS_X_VERSION_MAX_ALLOWED

#endif // wxUSE_EVENTLOOP_SOURCE

extern "C" void wxObserverCallBack(CFRunLoopObserverRef observer, CFRunLoopActivity activity, void *info)
{
    wxCFEventLoop * eventloop = static_cast<wxCFEventLoop *>(info);
    if ( eventloop )
        eventloop->ObserverCallBack(observer, activity);
}

void wxCFEventLoop::ObserverCallBack(CFRunLoopObserverRef WXUNUSED(observer), int activity)
{
    if ( activity & kCFRunLoopBeforeTimers )
    {
        // process pending wx events first as they correspond to low-level events
        // which happened before, i.e. typically pending events were queued by a
        // previous call to Dispatch() and if we didn't process them now the next
        // call to it might enqueue them again (as happens with e.g. socket events
        // which would be generated as long as there is input available on socket
        // and this input is only removed from it when pending event handlers are
        // executed)

        if ( wxTheApp )
            wxTheApp->ProcessPendingEvents();
    }

    if ( activity & kCFRunLoopBeforeWaiting )
    {
        if ( ProcessIdle() )
        {
            WakeUp();
        }
        else
        {
#if wxUSE_THREADS
            wxMutexGuiLeave();
            wxMilliSleep(20);
            wxMutexGuiEnter();
#endif
        }
    }
}

wxCFEventLoop::wxCFEventLoop()
{
    m_shouldExit = false;

    m_runLoop = CFGetCurrentRunLoop();

    CFRunLoopObserverContext ctxt;
    bzero( &ctxt, sizeof(ctxt) );
    ctxt.info = this;
    m_runLoopObserver = CFRunLoopObserverCreate( kCFAllocatorDefault, kCFRunLoopBeforeTimers | kCFRunLoopBeforeWaiting , true /* repeats */, 0,
                                            wxObserverCallBack, &ctxt );
    CFRunLoopAddObserver(m_runLoop, m_runLoopObserver, kCFRunLoopCommonModes);
    CFRelease(m_runLoopObserver);
}

wxCFEventLoop::~wxCFEventLoop()
{
    CFRunLoopRemoveObserver(m_runLoop, m_runLoopObserver, kCFRunLoopCommonModes);
}


CFRunLoopRef wxCFEventLoop::CFGetCurrentRunLoop() const
{
    return CFRunLoopGetCurrent();
}

void wxCFEventLoop::WakeUp()
{
    CFRunLoopWakeUp(m_runLoop);
}

#if wxUSE_BASE

void wxMacWakeUp()
{
    wxEventLoopBase * const loop = wxEventLoopBase::GetActive();
    
    if ( loop )
        loop->WakeUp();
}

#endif

bool wxCFEventLoop::YieldFor(long eventsToProcess)
{
#if wxUSE_THREADS
    // Yielding from a non-gui thread needs to bail out, otherwise we end up
    // possibly sending events in the thread too.
    if ( !wxThread::IsMain() )
    {
        return true;
    }
#endif // wxUSE_THREADS

    m_isInsideYield = true;
    m_eventsToProcessInsideYield = eventsToProcess;

#if wxUSE_LOG
    // disable log flushing from here because a call to wxYield() shouldn't
    // normally result in message boxes popping up &c
    wxLog::Suspend();
#endif // wxUSE_LOG

    // process all pending events:
    while ( DoProcessEvents() == 1 )
        ;

    // it's necessary to call ProcessIdle() to update the frames sizes which
    // might have been changed (it also will update other things set from
    // OnUpdateUI() which is a nice (and desired) side effect)
    while ( ProcessIdle() ) {}

    // if there are pending events, we must process them.
    if (wxTheApp)
        wxTheApp->ProcessPendingEvents();

#if wxUSE_LOG
    wxLog::Resume();
#endif // wxUSE_LOG
    m_isInsideYield = false;

    return true;
}

// implement/override base class pure virtual
bool wxCFEventLoop::Pending() const
{
    return true;
}

int wxCFEventLoop::DoProcessEvents()
{
    return DispatchTimeout( 1000 );
}

bool wxCFEventLoop::Dispatch()
{
    return DoProcessEvents() != 0;
}

int wxCFEventLoop::DispatchTimeout(unsigned long timeout)
{
    if ( !wxTheApp )
        return 0;

    int status = DoDispatchTimeout(timeout);

    switch( status )
    {
        case 0:
            break;
        case -1:
            if ( m_shouldExit )
                return 0;

            break;
        case 1:
            break;
    }

    return status;
}

int wxCFEventLoop::DoDispatchTimeout(unsigned long timeout)
{
    SInt32 status = CFRunLoopRunInMode(kCFRunLoopDefaultMode, timeout / 1000.0 , true);
    switch( status )
    {
        case kCFRunLoopRunFinished:
            wxFAIL_MSG( "incorrect run loop state" );
            break;
        case kCFRunLoopRunStopped:
            return 0;
            break;
        case kCFRunLoopRunTimedOut:
            return -1;
            break;
        case kCFRunLoopRunHandledSource:
        default:
            break;
    }
    return 1;
}

void wxCFEventLoop::DoRun()
{
    for ( ;; )
    {
        // generate and process idle events for as long as we don't
        // have anything else to do
        DoProcessEvents();

        // if the "should exit" flag is set, the loop should terminate
        // but not before processing any remaining messages so while
        // Pending() returns true, do process them
        if ( m_shouldExit )
        {
            while ( DoProcessEvents() == 1 )
                ;

            break;
        }
    }
}

void wxCFEventLoop::DoStop()
{
    CFRunLoopStop(CFGetCurrentRunLoop());
}

// enters a loop calling OnNextIteration(), Pending() and Dispatch() and
// terminating when Exit() is called
int wxCFEventLoop::Run()
{
    // event loops are not recursive, you need to create another loop!
    wxCHECK_MSG( !IsRunning(), -1, wxT("can't reenter a message loop") );

    // ProcessIdle() and ProcessEvents() below may throw so the code here should
    // be exception-safe, hence we must use local objects for all actions we
    // should undo
    wxEventLoopActivator activate(this);

    // we must ensure that OnExit() is called even if an exception is thrown
    // from inside ProcessEvents() but we must call it from Exit() in normal
    // situations because it is supposed to be called synchronously,
    // wxModalEventLoop depends on this (so we can't just use ON_BLOCK_EXIT or
    // something similar here)
#if wxUSE_EXCEPTIONS
    for ( ;; )
    {
        try
        {
#endif // wxUSE_EXCEPTIONS

            DoRun();

#if wxUSE_EXCEPTIONS
            // exit the outer loop as well
            break;
        }
        catch ( ... )
        {
            try
            {
                if ( !wxTheApp || !wxTheApp->OnExceptionInMainLoop() )
                {
                    OnExit();
                    break;
                }
                //else: continue running the event loop
            }
            catch ( ... )
            {
                // OnException() throwed, possibly rethrowing the same
                // exception again: very good, but we still need OnExit() to
                // be called
                OnExit();
                throw;
            }
        }
    }
#endif // wxUSE_EXCEPTIONS

    return m_exitcode;
}

// sets the "should exit" flag and wakes up the loop so that it terminates
// soon
void wxCFEventLoop::Exit(int rc)
{
    m_exitcode = rc;
    m_shouldExit = true;
    DoStop();
}
