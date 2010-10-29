///////////////////////////////////////////////////////////////////////////////
// Name:        src/osx/cocoa/evtloop.mm
// Purpose:     implementation of wxEventLoop for OS X
// Author:      Vadim Zeitlin, Stefan Csomor
// Modified by:
// Created:     2006-01-12
// RCS-ID:      $Id: evtloop.cpp 54845 2008-07-30 14:52:41Z SC $
// Copyright:   (c) 2006 Vadim Zeitlin <vadim@wxwindows.org>
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

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/nonownedwnd.h"
#endif // WX_PRECOMP

#include "wx/log.h"

#include "wx/osx/private.h"

// ============================================================================
// wxEventLoop implementation
// ============================================================================

/*
static int CalculateNSEventMaskFromEventCategory(wxEventCategory cat)
{
	NSLeftMouseDownMask	|
	NSLeftMouseUpMask |
	NSRightMouseDownMask |
	NSRightMouseUpMask		= 1 << NSRightMouseUp,
	NSMouseMovedMask		= 1 << NSMouseMoved,
	NSLeftMouseDraggedMask		= 1 << NSLeftMouseDragged,
	NSRightMouseDraggedMask		= 1 << NSRightMouseDragged,
	NSMouseEnteredMask		= 1 << NSMouseEntered,
	NSMouseExitedMask		= 1 << NSMouseExited,
        NSScrollWheelMask		= 1 << NSScrollWheel,
#if MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_4
	NSTabletPointMask		= 1 << NSTabletPoint,
	NSTabletProximityMask		= 1 << NSTabletProximity,
#endif
	NSOtherMouseDownMask		= 1 << NSOtherMouseDown,
	NSOtherMouseUpMask		= 1 << NSOtherMouseUp,
	NSOtherMouseDraggedMask		= 1 << NSOtherMouseDragged,



	NSKeyDownMask			= 1 << NSKeyDown,
	NSKeyUpMask			= 1 << NSKeyUp,
	NSFlagsChangedMask		= 1 << NSFlagsChanged,

	NSAppKitDefinedMask		= 1 << NSAppKitDefined,
	NSSystemDefinedMask		= 1 << NSSystemDefined,
	NSApplicationDefinedMask	= 1 << NSApplicationDefined,
	NSPeriodicMask			= 1 << NSPeriodic,
	NSCursorUpdateMask		= 1 << NSCursorUpdate,

	NSAnyEventMask			= 0xffffffffU
}
*/

wxGUIEventLoop::wxGUIEventLoop()
{
}

//-----------------------------------------------------------------------------
// events dispatch and loop handling
//-----------------------------------------------------------------------------

#if 0

bool wxGUIEventLoop::Pending() const
{
#if 0
    // this code doesn't reliably detect pending events
    // so better return true and have the dispatch deal with it
    // as otherwise we end up in a tight loop when idle events are responded
    // to by RequestMore(true)
    wxMacAutoreleasePool autoreleasepool;
  
    return [[NSApplication sharedApplication]
            nextEventMatchingMask: NSAnyEventMask
            untilDate: nil
            inMode: NSDefaultRunLoopMode
            dequeue: NO] != nil;
#else
    return true;
#endif
}

bool wxGUIEventLoop::Dispatch()
{
    if ( !wxTheApp )
        return false;

    wxMacAutoreleasePool autoreleasepool;

    if(NSEvent *event = [NSApp
                nextEventMatchingMask:NSAnyEventMask
                untilDate:[NSDate dateWithTimeIntervalSinceNow: m_sleepTime]
                inMode:NSDefaultRunLoopMode
                dequeue: YES])
    {
        WXEVENTREF formerEvent = wxTheApp == NULL ? NULL : wxTheApp->MacGetCurrentEvent();
        WXEVENTHANDLERCALLREF formerHandler = wxTheApp == NULL ? NULL : wxTheApp->MacGetCurrentEventHandlerCallRef();

        if (wxTheApp)
            wxTheApp->MacSetCurrentEvent(event, NULL);
        m_sleepTime = 0.0;
        [NSApp sendEvent: event];

        if (wxTheApp)
            wxTheApp->MacSetCurrentEvent(formerEvent , formerHandler);
    }
    else
    {
        if (wxTheApp)
            wxTheApp->ProcessPendingEvents();
        
        if ( wxTheApp->ProcessIdle() )
            m_sleepTime = 0.0 ;
        else
        {
            m_sleepTime = 1.0;
#if wxUSE_THREADS
            wxMutexGuiLeave();
            wxMilliSleep(20);
            wxMutexGuiEnter();
#endif
        }
    }

    return true;
}

#endif

int wxGUIEventLoop::DoDispatchTimeout(unsigned long timeout)
{
    wxMacAutoreleasePool autoreleasepool;

    NSEvent *event = [NSApp
                nextEventMatchingMask:NSAnyEventMask
                untilDate:[NSDate dateWithTimeIntervalSinceNow: timeout/1000]
                inMode:NSDefaultRunLoopMode
                dequeue: YES];
    
    if ( event == nil )
        return -1;

    [NSApp sendEvent: event];

    return 1;
}

void wxGUIEventLoop::DoRun()
{
    wxMacAutoreleasePool autoreleasepool;
    [NSApp run];
}

void wxGUIEventLoop::DoStop()
{
    [NSApp stop:0];
}

CFRunLoopRef wxGUIEventLoop::CFGetCurrentRunLoop() const
{
    NSRunLoop* nsloop = [NSRunLoop currentRunLoop];
    return [nsloop getCFRunLoop];
}


// TODO move into a evtloop_osx.cpp

wxModalEventLoop::wxModalEventLoop(wxWindow *modalWindow)
{
    m_modalWindow = dynamic_cast<wxNonOwnedWindow*> (modalWindow);
    wxASSERT_MSG( m_modalWindow != NULL, "must pass in a toplevel window for modal event loop" );
    m_modalNativeWindow = m_modalWindow->GetWXWindow();
}

wxModalEventLoop::wxModalEventLoop(WXWindow modalNativeWindow)
{
    m_modalWindow = NULL;
    wxASSERT_MSG( modalNativeWindow != NULL, "must pass in a toplevel window for modal event loop" );
    m_modalNativeWindow = modalNativeWindow;
}

// END move into a evtloop_osx.cpp

void wxModalEventLoop::DoRun()
{
    wxMacAutoreleasePool pool;

    // If the app hasn't started, flush the event queue
    // If we don't do this, the Dock doesn't get the message that
    // the app has started so will refuse to activate it.
    [NSApplication sharedApplication];
    if (![NSApp isRunning])
    {
        while(NSEvent *event = [NSApp nextEventMatchingMask:NSAnyEventMask untilDate:nil inMode:NSDefaultRunLoopMode dequeue:YES])
        {
            [NSApp sendEvent:event];
        }
    }
    
    [NSApp runModalForWindow:m_modalNativeWindow];
}

void wxModalEventLoop::DoStop()
{
    [NSApp stopModal];
}

