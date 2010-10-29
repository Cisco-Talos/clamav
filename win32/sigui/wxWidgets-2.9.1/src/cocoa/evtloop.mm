///////////////////////////////////////////////////////////////////////////////
// Name:        cocoa/evtloop.mm
// Purpose:     implements wxEventLoop for Cocoa
// Author:      David Elliott
// Modified by:
// Created:     2003/10/02
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott <dfe@cox.net>
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#include "wx/evtloop.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
#endif //WX_PRECOMP

#import <AppKit/NSApplication.h>
#import <AppKit/NSEvent.h>
#import <Foundation/NSRunLoop.h>

// ========================================================================
// wxGUIEventLoop
// ========================================================================

// ----------------------------------------------------------------------------
// wxGUIEventLoop running and exiting
// ----------------------------------------------------------------------------

int wxGUIEventLoop::Run()
{
    // event loops are not recursive, you need to create another loop!
    wxCHECK_MSG( !IsRunning(), -1, wxT("can't reenter a message loop") );

    wxEventLoopActivator activate(this);

    [[NSApplication sharedApplication] run];

    OnExit();

    return m_exitcode;
}

void wxGUIEventLoop::Exit(int rc)
{
    wxCHECK_RET( IsRunning(), wxT("can't call Exit() if not running") );

    m_exitcode = rc;

    NSApplication *cocoaApp = [NSApplication sharedApplication];
    wxLogTrace(wxTRACE_COCOA,wxT("wxEventLoop::Exit isRunning=%d"), (int)[cocoaApp isRunning]);
    wxTheApp->WakeUpIdle();
    /* Notes:
    If we're being called from idle time (which occurs while checking the
    queue for new events) there may or may not be any events in the queue.
    In order to successfully stop the event loop, at least one event must
    be processed.  To ensure this always happens, WakeUpIdle is called.

    If the application was active when closed then this is unnecessary
    because it would receive a deactivate event anyway.  However, if the
    application was not active when closed, then no events would be
    added to the queue by Cocoa and thus the application would wait
    indefinitely for the next event.
    */
    [cocoaApp stop: cocoaApp];
}

// ----------------------------------------------------------------------------
// wxEventLoop message processing dispatching
// ----------------------------------------------------------------------------

bool wxGUIEventLoop::Pending() const
{
    // a pointer to the event is returned if there is one, or nil if not
    return [[NSApplication sharedApplication]
            nextEventMatchingMask: NSAnyEventMask
            untilDate: nil /* Equivalent to [NSDate distantPast] */
            inMode: NSDefaultRunLoopMode
            dequeue: NO];
}

bool wxGUIEventLoop::Dispatch()
{
    // This check is required by wxGTK but probably not really for wxCocoa
    // Keep it here to encourage developers to write cross-platform code
    wxCHECK_MSG( IsRunning(), false, wxT("can't call Dispatch() if not running") );
    NSApplication *cocoaApp = [NSApplication sharedApplication];
    // Block to retrieve an event then send it
    if(NSEvent *event = [cocoaApp
                nextEventMatchingMask:NSAnyEventMask
                untilDate:[NSDate distantFuture]
                inMode:NSDefaultRunLoopMode
                dequeue: YES])
    {
        [cocoaApp sendEvent: event];
    }

    return true;
}

int wxGUIEventLoop::DispatchTimeout(unsigned long timeout)
{
    NSApplication *cocoaApp = [NSApplication sharedApplication];
    NSEvent *event = [cocoaApp
                nextEventMatchingMask:NSAnyEventMask
                untilDate:[[NSDate alloc] initWithTimeIntervalSinceNow:timeout/1000]
                inMode:NSDefaultRunLoopMode
                dequeue: YES];
    if ( !event )
        return -1;

    [cocoaApp sendEvent: event];

    return true;
}

bool wxGUIEventLoop::YieldFor(long eventsToProcess)
{
#if wxUSE_LOG
    // disable log flushing from here because a call to wxYield() shouldn't
    // normally result in message boxes popping up &c
    wxLog::Suspend();
#endif // wxUSE_LOG

    m_isInsideYield = true;
    m_eventsToProcessInsideYield = eventsToProcess;

    // Run the event loop until it is out of events
    while (1)
    {
        // TODO: implement event filtering using the eventsToProcess mask

        wxAutoNSAutoreleasePool pool;
        /*  NOTE: It may be better to use something like
            NSEventTrackingRunLoopMode since we don't necessarily want all
            timers/sources/observers to run, only those which would
            run while tracking events.  However, it should be noted that
            NSEventTrackingRunLoopMode is in the common set of modes
            so it may not effectively make much of a difference.
         */
        NSEvent *event = [GetNSApplication()
                nextEventMatchingMask:NSAnyEventMask
                untilDate:[NSDate distantPast]
                inMode:NSDefaultRunLoopMode
                dequeue: YES];
        if(!event)
            break;
        [GetNSApplication() sendEvent: event];
    }

    /*
        Because we just told NSApplication to avoid blocking it will in turn
        run the CFRunLoop with a timeout of 0 seconds.  In that case, our
        run loop observer on kCFRunLoopBeforeWaiting never fires because
        no waiting occurs.  Therefore, no idle events are sent.

        Believe it or not, this is actually desirable because we do not want
        to process idle from here.  However, we do want to process pending
        events because some user code expects to do work in a thread while
        the main thread waits and then notify the main thread by posting
        an event.
     */
    if (wxTheApp)
        wxTheApp->ProcessPendingEvents();

#if wxUSE_LOG
    // let the logs be flashed again
    wxLog::Resume();
#endif // wxUSE_LOG

    m_isInsideYield = false;

    return true;
}
