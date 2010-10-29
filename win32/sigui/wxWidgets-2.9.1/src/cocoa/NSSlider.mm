/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/NSSlider.mm
// Purpose:     wxCocoaNSSlider class
// Author:      Mark Oxenham
// Modified by: David Elliott
// Created:     2007/08/10
// RCS-ID:      $Id$
// Copyright:   (c) 2007 Software 2000 Ltd. All rights reserved.
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
#endif // WX_PRECOMP

#include "wx/cocoa/NSSlider.h"

#import <Foundation/NSNotification.h>
#import <Foundation/NSString.h>
#import <AppKit/NSEvent.h>
#include "wx/cocoa/objc/NSSlider.h"

WX_IMPLEMENT_OBJC_INTERFACE_HASHMAP(NSSlider)

class wxCocoaNSSliderLastSelectorChanger
{
public:
    wxCocoaNSSliderLastSelectorChanger(SEL newSelector)
    {
        m_savedResponderSelector = wxCocoaNSSlider::sm_lastResponderSelector;
        wxCocoaNSSlider::sm_lastResponderSelector = newSelector;
    }
    ~wxCocoaNSSliderLastSelectorChanger()
    {
        wxCocoaNSSlider::sm_lastResponderSelector = m_savedResponderSelector;
    }
private:
    SEL m_savedResponderSelector;
// Don't allow any default or copy construction
    wxCocoaNSSliderLastSelectorChanger();
    wxCocoaNSSliderLastSelectorChanger(const wxCocoaNSSliderLastSelectorChanger&);
    void operator=(const wxCocoaNSSliderLastSelectorChanger&);
};

// ============================================================================
// @class WXNSSlider
// ============================================================================

@implementation WXNSSlider : NSSlider

// Override to ensure that WXNSSlider gets created with a WXNSSliderCell
+ (Class)cellClass
{
    return [WX_GET_OBJC_CLASS(WXNSSliderCell) class];
}

// The following methods are all NSResponder methods which NSSlider responds
// to in order to change its state and send the action message.  We override
// them simply to record which one was called.  This allows code listening
// only for the action message to determine what caused the action.
// Note that this is perfectly fine being a global because Cocoa processes
// events synchronously and only in the main thread.

- (void)keyDown:(NSEvent *)theEvent
{
    wxCocoaNSSliderLastSelectorChanger savedSelector(_cmd);
    [super keyDown:theEvent];
}

- (void)moveUp:(id)sender
{
    wxCocoaNSSliderLastSelectorChanger savedSelector(_cmd);
    [super moveUp:sender];
}

- (void)moveDown:(id)sender
{
    wxCocoaNSSliderLastSelectorChanger savedSelector(_cmd);
    [super moveDown:sender];
}

- (void)moveLeft:(id)sender
{
    wxCocoaNSSliderLastSelectorChanger savedSelector(_cmd);
    [super moveLeft:sender];
}

- (void)moveRight:(id)sender
{
    wxCocoaNSSliderLastSelectorChanger savedSelector(_cmd);
    [super moveRight:sender];
}

- (void)pageUp:(id)sender
{
    wxCocoaNSSliderLastSelectorChanger savedSelector(_cmd);
    [super pageUp:sender];
}

- (void)pageDown:(id)sender
{
    wxCocoaNSSliderLastSelectorChanger savedSelector(_cmd);
    [super pageDown:sender];
}

@end
WX_IMPLEMENT_GET_OBJC_CLASS(WXNSSlider,NSSlider)

// ============================================================================
// @class WXNSSliderCell
// ============================================================================

@implementation WXNSSliderCell : NSSliderCell
- (BOOL)startTrackingAt:(NSPoint)startPoint inView:(NSView *)controlView
{
    BOOL result = [super startTrackingAt:startPoint inView:controlView];

    wxCocoaNSSlider *slider = wxCocoaNSSlider::GetFromCocoa(controlView);
    if(slider)
        slider->CocoaNotification_startTracking(NULL);

    return result;
}

- (BOOL)continueTracking:(NSPoint)lastPoint at:(NSPoint)currentPoint inView:(NSView *)controlView
{
    BOOL result = [super continueTracking:lastPoint at:currentPoint inView:controlView];

    wxCocoaNSSlider *slider = wxCocoaNSSlider::GetFromCocoa(controlView);
    if(slider)
        slider->CocoaNotification_continueTracking(NULL);

    return result;
}

- (void)stopTracking:(NSPoint)lastPoint at:(NSPoint)stopPoint inView:(NSView *)controlView mouseIsUp:(BOOL)flag
{
    [super stopTracking:lastPoint at:stopPoint inView:controlView mouseIsUp:flag];

    wxCocoaNSSlider *slider = wxCocoaNSSlider::GetFromCocoa(controlView);
    if(slider)
        slider->CocoaNotification_stopTracking(NULL);
}
@end
WX_IMPLEMENT_GET_OBJC_CLASS(WXNSSliderCell,NSSliderCell)

// ============================================================================
// class wxCocoaNSSlider
// ============================================================================

SEL wxCocoaNSSlider::sm_lastResponderSelector;

void wxCocoaNSSlider::AssociateNSSlider(WX_NSSlider cocoaNSSlider)
{
    if(cocoaNSSlider)
    {
        sm_cocoaHash.insert(wxCocoaNSSliderHash::value_type(cocoaNSSlider,this));
    }
}

void wxCocoaNSSlider::DisassociateNSSlider(WX_NSSlider cocoaNSSlider)
{
    if(cocoaNSSlider)
    {
        sm_cocoaHash.erase(cocoaNSSlider);
    }
}
