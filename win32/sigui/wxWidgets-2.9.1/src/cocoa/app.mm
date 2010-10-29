/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/app.mm
// Purpose:     wxApp
// Author:      David Elliott
// Modified by:
// Created:     2002/11/27
// RCS-ID:      $Id$
// Copyright:   (c) David Elliott
//              Software 2000 Ltd.
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#include "wx/app.h"

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/module.h"
#endif

#include "wx/cocoa/ObjcRef.h"
#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/mbarman.h"
#include "wx/cocoa/NSApplication.h"

#include "wx/cocoa/dc.h"

#import <AppKit/NSApplication.h>
#import <Foundation/NSRunLoop.h>
#import <Foundation/NSThread.h>
#import <AppKit/NSEvent.h>
#import <Foundation/NSString.h>
#import <Foundation/NSNotification.h>
#import <AppKit/NSCell.h>

bool      wxApp::sm_isEmbedded = false; // Normally we're not a plugin

// wxNSApplicationObserver singleton.
static wxObjcAutoRefFromAlloc<wxNSApplicationObserver*> sg_cocoaAppObserver = [[WX_GET_OBJC_CLASS(wxNSApplicationObserver) alloc] init];

// ========================================================================
// wxNSApplicationDelegate
// ========================================================================
@implementation wxNSApplicationDelegate : NSObject

// NOTE: Terminate means that the event loop does NOT return and thus
// cleanup code doesn't properly execute.  Furthermore, wxWidgets has its
// own exit on frame delete mechanism.
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)theApplication
{
    return NO;
}

@end // implementation wxNSApplicationDelegate : NSObject
WX_IMPLEMENT_GET_OBJC_CLASS(wxNSApplicationDelegate,NSObject)

// ========================================================================
// wxNSApplicationObserver
// ========================================================================
@implementation wxNSApplicationObserver : NSObject

- (void)applicationWillBecomeActive:(NSNotification *)notification
{
    wxTheApp->CocoaDelegate_applicationWillBecomeActive();
}

- (void)applicationDidBecomeActive:(NSNotification *)notification
{
    wxTheApp->CocoaDelegate_applicationDidBecomeActive();
}

- (void)applicationWillResignActive:(NSNotification *)notification
{
    wxTheApp->CocoaDelegate_applicationWillResignActive();
}

- (void)applicationDidResignActive:(NSNotification *)notification
{
    wxTheApp->CocoaDelegate_applicationDidResignActive();
}

- (void)applicationWillUpdate:(NSNotification *)notification;
{
    wxTheApp->CocoaDelegate_applicationWillUpdate();
}

- (void)controlTintChanged:(NSNotification *)notification
{
    wxLogDebug(wxT("TODO: send EVT_SYS_COLOUR_CHANGED as appropriate"));
}

@end // implementation wxNSApplicationObserver : NSObject
WX_IMPLEMENT_GET_OBJC_CLASS(wxNSApplicationObserver,NSObject)

// ========================================================================
// wxApp
// ========================================================================

// ----------------------------------------------------------------------------
// wxApp Static member initialization
// ----------------------------------------------------------------------------
IMPLEMENT_DYNAMIC_CLASS(wxApp, wxEvtHandler)

// ----------------------------------------------------------------------------
// wxApp initialization/cleanup
// ----------------------------------------------------------------------------
bool wxApp::Initialize(int& argc, wxChar **argv)
{
    wxAutoNSAutoreleasePool pool;
    m_cocoaMainThread = [NSThread currentThread];
    // Mac OS X passes a process serial number command line argument when
    // the application is launched from the Finder. This argument must be
    // removed from the command line arguments before being handled by the
    // application (otherwise applications would need to handle it)
    if ( argc > 1 )
    {
        static const wxChar *ARG_PSN = wxT("-psn_");
        if ( wxStrncmp(argv[1], ARG_PSN, wxStrlen(ARG_PSN)) == 0 )
        {
            // remove this argument
            --argc;
            memmove(argv + 1, argv + 2, argc * sizeof(wxChar *));
        }
    }

    /*
        Cocoa supports -Key value options which set the user defaults key "Key"
        to the value "value"  Some of them are very handy for debugging like
        -NSShowAllViews YES.  Cocoa picks these up from the real argv so
        our removal of them from the wx copy of it does not affect Cocoa's
        ability to see them.

        We basically just assume that any "-NS" option and its following
        argument needs to be removed from argv.  We hope that user code does
        not expect to see -NS options and indeed it's probably a safe bet
        since most user code accepting options is probably using the
        double-dash GNU-style syntax.
     */
    for(int i=1; i < argc; ++i)
    {
        static const wxChar *ARG_NS = wxT("-NS");
        static const int ARG_NS_LEN = wxStrlen(ARG_NS);
        if( wxStrncmp(argv[i], ARG_NS, ARG_NS_LEN) == 0 )
        {
            // Only eat this option if it has an argument
            if( (i + 1) < argc )
            {
                argc -= 2;
                memmove(argv + i, argv + i + 2, argc * sizeof(wxChar*));
                // drop back one position so the next run through the loop
                // reprocesses the argument at our current index.
                --i;
            }
        }
    }

    return wxAppBase::Initialize(argc, argv);
}

void wxApp::CleanUp()
{
    wxAutoNSAutoreleasePool pool;

    wxCocoaDCImpl::CocoaShutdownTextSystem();
    wxMenuBarManager::DestroyInstance();

    [[NSNotificationCenter defaultCenter] removeObserver:sg_cocoaAppObserver];
    if(!sm_isEmbedded)
    {
        [m_cocoaApp setDelegate:nil];
        [m_cocoaAppDelegate release];
        m_cocoaAppDelegate = NULL;
    }

    wxAppBase::CleanUp();
}

// ----------------------------------------------------------------------------
// wxApp creation
// ----------------------------------------------------------------------------
wxApp::wxApp()
{
    m_topWindow = NULL;

    argc = 0;
#if !wxUSE_UNICODE
    argv = NULL;
#endif
    m_cocoaApp = NULL;
    m_cocoaAppDelegate = NULL;
}

void wxApp::CocoaDelegate_applicationWillBecomeActive()
{
}

void wxApp::CocoaDelegate_applicationDidBecomeActive()
{
}

void wxApp::CocoaDelegate_applicationWillResignActive()
{
    wxTopLevelWindowCocoa::DeactivatePendingWindow();
}

void wxApp::CocoaDelegate_applicationDidResignActive()
{
}

bool wxApp::OnInitGui()
{
    wxAutoNSAutoreleasePool pool;
    if(!wxAppBase::OnInitGui())
        return false;

    // Create the app using the sharedApplication method
    m_cocoaApp = [NSApplication sharedApplication];

    if(!sm_isEmbedded)
    {
        // Enable response to application delegate messages
        m_cocoaAppDelegate = [[WX_GET_OBJC_CLASS(wxNSApplicationDelegate) alloc] init];
        [m_cocoaApp setDelegate:m_cocoaAppDelegate];
    }

    // Enable response to "delegate" messages on the notification observer
    [[NSNotificationCenter defaultCenter] addObserver:sg_cocoaAppObserver
        selector:@selector(applicationWillBecomeActive:)
        name:NSApplicationWillBecomeActiveNotification object:nil];

    [[NSNotificationCenter defaultCenter] addObserver:sg_cocoaAppObserver
        selector:@selector(applicationDidBecomeActive:)
        name:NSApplicationDidBecomeActiveNotification object:nil];

    [[NSNotificationCenter defaultCenter] addObserver:sg_cocoaAppObserver
        selector:@selector(applicationWillResignActive:)
        name:NSApplicationWillResignActiveNotification object:nil];

    [[NSNotificationCenter defaultCenter] addObserver:sg_cocoaAppObserver
        selector:@selector(applicationDidResignActive:)
        name:NSApplicationDidResignActiveNotification object:nil];

    [[NSNotificationCenter defaultCenter] addObserver:sg_cocoaAppObserver
        selector:@selector(applicationWillUpdate:)
        name:NSApplicationWillUpdateNotification object:nil];

    // Enable response to system notifications
    [[NSNotificationCenter defaultCenter] addObserver:sg_cocoaAppObserver
        selector:@selector(controlTintChanged:)
        name:NSControlTintDidChangeNotification object:nil];

    if(!sm_isEmbedded)
        wxMenuBarManager::CreateInstance();

    wxCocoaDCImpl::CocoaInitializeTextSystem();
    return true;
}

wxApp::~wxApp()
{
    if(m_cfRunLoopIdleObserver != NULL)
    {
        // Invalidate the observer which also removes it from the run loop.
        CFRunLoopObserverInvalidate(m_cfRunLoopIdleObserver);
        // Release the ref as we don't need it anymore.
        m_cfRunLoopIdleObserver.reset();
    }
}

bool wxApp::CallOnInit()
{
//    wxAutoNSAutoreleasePool pool;
    return OnInit();
}

bool wxApp::OnInit()
{
    if(!wxAppBase::OnInit())
        return false;

    return true;
}

void wxApp::Exit()
{
    wxApp::CleanUp();

    wxAppConsole::Exit();
}

void wxApp::WakeUpIdle()
{
    /*  When called from the main thread the NSAutoreleasePool managed by
        the [NSApplication run] method would ordinarily be in place and so
        one would think a pool here would be unnecessary.

        However, when called from a different thread there is usually no
        NSAutoreleasePool in place because wxThread has no knowledge of
        wxCocoa.  The pool here is generally only ever going to contain
        the NSEvent we create with the factory method.  As soon as we add
        it to the main event queue with postEvent:atStart: it is retained
        and so safe for our pool to release.
     */
    wxAutoNSAutoreleasePool pool;
    /*  NOTE: This is a little heavy handed.  What this does is cause an
        AppKit NSEvent to be added to NSApplication's queue (which is always
        on the main thread).  This will cause the main thread runloop to
        exit which returns control to nextEventMatchingMask which returns
        the event which is then sent with sendEvent: and essentially dropped
        since it's not for a window (windowNumber 0) and NSApplication
        certainly doesn't understand it.

        With the exception of wxEventLoop::Exit which uses us to cause the
        runloop to exit and return to the NSApplication event loop, most
        callers only need wx idle to happen, or more specifically only really
        need to ensure that ProcessPendingEvents is called which is currently
        done without exiting the runloop.

        Be careful if you decide to change the implementation of this method
        as wxEventLoop::Exit depends on the current behavior.
     */
    [m_cocoaApp postEvent:[NSEvent otherEventWithType:NSApplicationDefined
            location:NSZeroPoint modifierFlags:NSAnyEventMask
            timestamp:0 windowNumber:0 context:nil
            subtype:0 data1:0 data2:0] atStart:NO];
}

extern "C" static void ObserveMainRunLoopBeforeWaiting(CFRunLoopObserverRef observer, CFRunLoopActivity activity, void *info);
extern "C" static void ObserveMainRunLoopBeforeWaiting(CFRunLoopObserverRef observer, CFRunLoopActivity activity, void *info)
{
    static_cast<wxApp*>(info)->CF_ObserveMainRunLoopBeforeWaiting(observer, activity);
}

#if 0
static int sg_cApplicationWillUpdate = 0;
#endif

/*!
    Invoked from the applicationWillUpdate notification observer.  See the
    NSApplication documentation for the official statement on when this
    will be called.  Since it can be hard to understand for a Cocoa newbie
    I'll try to explain it here as it relates to wxCocoa.

    Basically, we get called from within nextEventMatchingMask if and only
    if any user code told the application to send the update notification
    (sort of like a request for idle events).  However, unlike wx idle events,
    this notification is sent quite often, nearly every time through the loop
    because nearly every control tells the application to send it.

    Because wx idle events are only supposed to be sent when the event loop
    is about to block we instead schedule a function to be called just
    before the run loop waits and send the idle events from there.

    It also has the desirable effect of only sending the wx idle events when
    the event loop is actualy going to block.  If the event loop is being
    pumped manualy (e.g. like a PeekMessage) then the kCFRunLoopBeforeWaiting
    observer never fires.  Our Yield() method depends on this because sending
    idle events from within Yield would be bad.

    Normally you might think that we could just set the observer up once and
    leave it attached.  However, this is problematic because our run loop
    observer calls user code (the idle handlers) which can actually display
    modal dialogs.  Displaying a modal dialog causes reentry of the event
    loop, usually in a different run loop mode than the main loop (e.g. in
    modal-dialog mode instead of default mode).  Because we only register the
    observer with the run loop mode at the time of this call, it won't be
    called from a modal loop.

    We want it to be called and thus we need a new observer.
 */
void wxApp::CocoaDelegate_applicationWillUpdate()
{
    wxLogTrace(wxTRACE_COCOA,wxT("applicationWillUpdate"));

//    CFRunLoopRef cfRunLoop = [[NSRunLoop currentRunLoop] getCFRunLoop];
    CFRunLoopRef cfRunLoop = CFRunLoopGetCurrent();
    wxCFRef<CFStringRef> cfRunLoopMode(CFRunLoopCopyCurrentMode(cfRunLoop));

    /*  If we have an observer and that observer is for the wrong run loop
        mode then invalidate it and release it.
     */
    if(m_cfRunLoopIdleObserver != NULL && m_cfObservedRunLoopMode != cfRunLoopMode)
    {
        CFRunLoopObserverInvalidate(m_cfRunLoopIdleObserver);
        m_cfRunLoopIdleObserver.reset();
    }
#if 0
    ++sg_cApplicationWillUpdate;
#endif
    /*  This will be true either on the first call or when the above code has
        invalidated and released the exisiting observer.
     */
    if(m_cfRunLoopIdleObserver == NULL)
    {
        // Enable idle event handling
        CFRunLoopObserverContext observerContext =
        {   0
        ,   this
        ,   NULL
        ,   NULL
        ,   NULL
        };
        /*  NOTE: I can't recall why we don't just let the observer repeat
            instead of invalidating itself each time it fires thus requiring
            it to be recreated for each shot but there was if I remember
            some good (but very obscure) reason for it.

            On the other hand, I could be wrong so don't take that as gospel.
         */
        m_cfRunLoopIdleObserver.reset(CFRunLoopObserverCreate(kCFAllocatorDefault, kCFRunLoopBeforeWaiting, /*repeats*/FALSE, /*priority*/0, ObserveMainRunLoopBeforeWaiting, &observerContext));
        m_cfObservedRunLoopMode = cfRunLoopMode;
        CFRunLoopAddObserver(cfRunLoop, m_cfRunLoopIdleObserver, m_cfObservedRunLoopMode);
    }
}

static inline bool FakeNeedMoreIdle()
{
#if 0
// Return true on every 10th call.
    static int idleCount = 0;
    return ++idleCount % 10;
#else
    return false;
#endif
}

/*!
    Called by CFRunLoop just before waiting.  This is the appropriate time to
    send idle events.  Unlike other ports, we don't peek the queue for events
    and stop idling if there is one.  Instead, if the user requests more idle
    events we tell Cocoa to send us an applicationWillUpdate notification
    which will cause our observer of that notification to tell CFRunLoop to
    call us before waiting which will cause us to be fired again but only
    after exhausting the event queue.

    The reason we do it this way is that peeking for an event causes CFRunLoop
    to reenter and fire off its timers, observers, and sources which we're
    better off avoiding.  Doing it this way, we basically let CFRunLoop do the
    work of peeking for the next event which is much nicer.
 */
void wxApp::CF_ObserveMainRunLoopBeforeWaiting(CFRunLoopObserverRef observer, int activity)
{
    // Ensure that CocoaDelegate_applicationWillUpdate will recreate us.
    // We've already been invalidated by CFRunLoop because we are one-shot.
    m_cfRunLoopIdleObserver.reset();
#if 0
    wxLogTrace(wxTRACE_COCOA,wxT("Idle BEGIN (%d)"), sg_cApplicationWillUpdate);
    sg_cApplicationWillUpdate = 0;
#else
    wxLogTrace(wxTRACE_COCOA,wxT("Idle BEGIN"));
#endif
    if( ProcessIdle() || FakeNeedMoreIdle() )
    {
        wxLogTrace(wxTRACE_COCOA, wxT("Idle REQUEST MORE"));
        [NSApp setWindowsNeedUpdate:YES];
    }
    else
    {
        wxLogTrace(wxTRACE_COCOA, wxT("Idle END"));
    }
}

/*  A note about Cocoa's event loops vs. run loops:

    It's important to understand that Cocoa has a two-level event loop.  The
    outer level is run by NSApplication and can only ever happen on the main
    thread. The nextEventMatchingMask:untilDate:inMode:dequeue: method returns
    the next event which is then given to sendEvent: to send it.  These
    methods are defined in NSApplication and are thus part of AppKit.

    Events (NSEvent) are only sent due to actual user actions like clicking
    the mouse or moving the mouse or pressing a key and so on.  There are no
    paint events; there are no timer events; there are no socket events; there
    are no idle events.

    All of those types of "events" have nothing to do with the GUI at all.
    That is why Cocoa's AppKit doesn't implement them.  Instead, they are
    implemented in Foundation's NSRunLoop which on OS X uses CFRunLoop
    to do the actual work.

    How NSApplication uses NSRunLoop is rather interesting.  Basically, it
    interacts with NSRunLoop only from within the nextEventMatchingMask
    method.  It passes its inMode: argument almost directly to NSRunLoop
    and thus CFRunLoop.  The run loop then runs (e.g. loops) until it
    is told to exit.  The run loop calls the callout functions directly.
    From within those callout functions the run loop is considered to
    be running.  Presumably, the AppKit installs a run loop source to
    receive messages from the window server over the mach port (like a
    socket).  For some messages (e.g. need to paint) the AppKit will
    call application code like drawRect: without exiting the run loop.
    For other messages (ones that can be encapsulated in an NSEvent)
    the AppKit tells the run loop to exit which returns control to
    the nextEventMatchingMask method which then returns the NSEvent
    object.  It's important to note that once the runloop has exited
    it is no longer considered running and thus if you ask it which
    mode it is running in it will return nil.

    When manually pumping the event loop care should be taken to
    tell it to run in the correct mode.  For instance, if you are
    using it to run a modal dialog then you want to run it in
    the modal panel run loop mode.  AppKit presumably has sources
    or timers or observers that specifically don't listen on this
    mode.  Another interesting mode is the connection reply mode.
    This allows Cocoa to wait for a response from a distributed
    objects message without firing off user code that may result
    in a DO call being made thus recursing.  So basically, the
    mode is a way for Cocoa to attempt to avoid run loop recursion
    but to allow it under certain circumstances.
 */

