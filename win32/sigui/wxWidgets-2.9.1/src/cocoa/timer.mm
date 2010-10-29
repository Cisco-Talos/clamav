/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/timer.mm
// Purpose:     wxTimer for wxCocoa
// Author:      Ryan Norton
// Modified by: David Elliott
// Created:     2005-02-04
// RCS-ID:      $Id$
// Copyright:   (c) Ryan Norton
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_TIMER

#include "wx/cocoa/private/timer.h"
#include "wx/cocoa/autorelease.h"

#include "wx/cocoa/objc/objc_uniquifying.h"

#import <Foundation/NSTimer.h>

// ========================================================================
// wxNSTimerData
// ========================================================================
@interface wxNSTimerData : NSObject
{
    wxCocoaTimerImpl* m_timer;
}

- (id)init;
- (id)initWithWxTimer:(wxCocoaTimerImpl*)theTimer;
- (wxCocoaTimerImpl*)timer;
- (void)onNotify:(NSTimer *)theTimer;
@end // interface wxNSTimerData : NSObject
WX_DECLARE_GET_OBJC_CLASS(wxNSTimerData,NSObject)

@implementation wxNSTimerData : NSObject
- (id)init
{
    if(!(self = [super init]))
        return nil;
    m_timer = NULL;
    return self;
}

- (id)initWithWxTimer:(wxCocoaTimerImpl*)theTimer;
{
    if(!(self = [super init]))
        return nil;
    m_timer = theTimer;
    return self;
}

- (wxCocoaTimerImpl*)timer
{
    return m_timer;
}

- (void)onNotify:(NSTimer *)theTimer
{
    m_timer->Notify();
}
@end
WX_IMPLEMENT_GET_OBJC_CLASS(wxNSTimerData,NSObject)

// ----------------------------------------------------------------------------
// wxCocoaTimerImpl
// ----------------------------------------------------------------------------

wxCocoaTimerImpl::~wxCocoaTimerImpl()
{
    Stop();
}

void wxCocoaTimerImpl::Init()
{
    m_cocoaNSTimer = NULL;
}

bool wxCocoaTimerImpl::Start(int millisecs, bool oneShot)
{
    Stop();

    wxAutoNSAutoreleasePool thePool;

    wxNSTimerData *timerData = [[WX_GET_OBJC_CLASS(wxNSTimerData) alloc] initWithWxTimer:this];
    m_cocoaNSTimer =     [[NSTimer
            scheduledTimerWithTimeInterval: millisecs / 1000.0 //seconds
            target:     timerData
            selector:   @selector(onNotify:)
            userInfo:   nil
            repeats:    oneShot == false] retain];
    [timerData release];

    return IsRunning();
}

void wxCocoaTimerImpl::Stop()
{
    if (m_cocoaNSTimer)
    {
        // FIXME: Is this safe to do if !isValid ?
        [m_cocoaNSTimer invalidate];
        [m_cocoaNSTimer release];
        m_cocoaNSTimer = NULL;
    }
}

bool wxCocoaTimerImpl::IsRunning() const
{
    return m_cocoaNSTimer != NULL && [m_cocoaNSTimer isValid];
}

#endif // wxUSE_TIMER

