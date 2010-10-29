/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/slider.mm
// Purpose:     wxSlider
// Author:      David Elliott
//              Mark Oxenham
// Modified by:
// Created:     2003/06/19
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
//              (c) 2007 Software 2000 Ltd.
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_SLIDER

#include "wx/slider.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif //WX_PRECOMP

#import <Foundation/NSString.h>
#include "wx/cocoa/objc/NSSlider.h"
#import <AppKit/NSEvent.h>
#import <AppKit/NSWindow.h>

IMPLEMENT_DYNAMIC_CLASS(wxSlider, wxControl)
    BEGIN_EVENT_TABLE(wxSlider, wxSliderBase)
END_EVENT_TABLE()
WX_IMPLEMENT_COCOA_OWNER(wxSlider,NSSlider,NSControl,NSView)


inline void AdjustDimension(
                bool            isTicksStyle,
                int             &pos,
                wxSize          &size,
                int             (wxSize::*GetDimension)() const,
                void            (wxSize::*SetDimension)(int))
{
    const int dimension = (size.*GetDimension)();
    const int minSize = (isTicksStyle) ? 23 : 20;

    // prevent clipping of overly "thin" sliders
    if (dimension < minSize)
    {
        (size.*SetDimension)(minSize);
    }

    // move the slider control to the middle of the dimension that is not
    // being used to define its length
    pos += (dimension - (size.*GetDimension)() + 1) / 2;
}

bool wxSlider::Create(wxWindow *parent, wxWindowID winid,
            int value, int minValue, int maxValue,
            const wxPoint& pos, const wxSize& size, long style,
            const wxValidator& validator, const wxString& name)
{
    wxSize adjustedSize(size);
    wxPoint adjustedPos(pos);
    const bool isTicksStyle = (style & wxSL_TICKS) != 0;

    if ((style & wxSL_HORIZONTAL) && (size.GetHeight() != wxDefaultCoord))
    {
        AdjustDimension(isTicksStyle, adjustedPos.y, adjustedSize, &wxSize::GetHeight, &wxSize::SetHeight);
    }
    else if ((style & wxSL_VERTICAL) && (size.GetWidth() != wxDefaultCoord))
    {
        AdjustDimension(isTicksStyle, adjustedPos.x, adjustedSize, &wxSize::GetWidth, &wxSize::SetWidth);
    }
    
    if(!CreateControl(parent,winid,adjustedPos,adjustedSize,style,validator,name))
        return false;
    SetNSSlider([[WX_GET_OBJC_CLASS(WXNSSlider) alloc] initWithFrame: MakeDefaultNSRect(adjustedSize)]);
    [m_cocoaNSView release];
    
    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(adjustedPos,adjustedSize);
    
    SetRange(minValue, maxValue);
    SetValue(value);
    
    // -1 default for wxSL_AUTOTICKS == false
    int tickMarks = -1;
    // minValue > maxValue not handled, tickMarks set to 0
    if ( style & wxSL_AUTOTICKS )
        tickMarks = ((maxValue - minValue >= 0) ? (maxValue - minValue) : 0);
    // arg2 needed a value, doesnt do anything
    SetTickFreq(tickMarks,1);

    return true;
}

wxSlider::~wxSlider()
{
    DisassociateNSSlider(GetNSSlider());
}

void wxSlider::AssociateNSSlider(WX_NSSlider theSlider)
{
    wxCocoaNSSlider::AssociateNSSlider(theSlider);
    // Set the target/action.. we don't really need to unset these
    [theSlider setTarget:wxCocoaNSControl::sm_cocoaTarget];
    [theSlider setAction:@selector(wxNSControlAction:)];
}

void wxSlider::ProcessEventType(wxEventType commandType)
{
    wxScrollEvent event(commandType, GetId(), GetValue(), HasFlag(wxSL_VERTICAL)?wxVERTICAL:wxHORIZONTAL);
    event.SetEventObject(this);
    HandleWindowEvent(event);
}

static inline wxEventType wxSliderEventTypeForKeyFromEvent(NSEvent *theEvent)
{
    NSString *theEventCharacters = [theEvent charactersIgnoringModifiers];

    if ([theEventCharacters length] == 1)
    {
        switch ([theEventCharacters characterAtIndex:0])
        {
            case NSUpArrowFunctionKey:
            case NSRightArrowFunctionKey:   return wxEVT_SCROLL_PAGEDOWN;
            case NSDownArrowFunctionKey:
            case NSLeftArrowFunctionKey:    return wxEVT_SCROLL_PAGEUP;
            case NSPageUpFunctionKey:       return wxEVT_SCROLL_BOTTOM;
            case NSPageDownFunctionKey:     return wxEVT_SCROLL_TOP;
        }
    }
    // Overload wxEVT_ANY to mean we can't determine the event type.
    return wxEVT_ANY;
}

void wxSlider::CocoaTarget_action()
{
    wxEventType sliderEventType;
    SEL theSelector = wxCocoaNSSlider::GetLastResponderSelector();
    
    if(         theSelector == @selector(moveUp:)
            ||  theSelector == @selector(moveRight:))
        sliderEventType = wxEVT_SCROLL_PAGEDOWN;
    else if(    theSelector == @selector(moveDown:)
            ||  theSelector == @selector(moveLeft:))
        sliderEventType = wxEVT_SCROLL_PAGEUP;
    else if(    theSelector == @selector(pageUp:))
        sliderEventType = wxEVT_SCROLL_BOTTOM;
    else if(    theSelector == @selector(pageDown:))
        sliderEventType = wxEVT_SCROLL_TOP;
    else if(    theSelector == @selector(keyDown:))
        // This case should ideally never be reached.
        sliderEventType = wxSliderEventTypeForKeyFromEvent([[GetNSSlider() window] currentEvent]);
    else
        // Don't generate an event.
        return;
    if(sliderEventType != wxEVT_ANY)
        ProcessEventType(sliderEventType);
}

void wxSlider::CocoaNotification_startTracking(WX_NSNotification notification)
{
    CocoaNotification_continueTracking(notification);
}

void wxSlider::CocoaNotification_continueTracking(WX_NSNotification notification)
{
    const double realValue = [GetNSSlider() doubleValue];

    if (realValue != [GetNSSlider() intValue])
    {
        SetValue(rint(realValue));
    }

    ProcessEventType(wxEVT_SCROLL_THUMBTRACK);
}

void wxSlider::CocoaNotification_stopTracking(WX_NSNotification notification)
{
    ProcessEventType(wxEVT_SCROLL_THUMBRELEASE);
}

int wxSlider::GetValue() const
{
    return [GetNSSlider() intValue];
}

void wxSlider::SetValue(int value)
{
    [GetNSSlider() setIntValue:value];
}

void wxSlider::SetRange(int minValue, int maxValue)
{
    [GetNSSlider() setMinValue:minValue];
    [GetNSSlider() setMaxValue:maxValue];
}

int wxSlider::GetMin() const
{
    return [GetNSSlider() minValue];
}

int wxSlider::GetMax() const
{
    return [GetNSSlider() maxValue];
}

void wxSlider::SetTickFreq(int n, int pos)
{
    const int numTicks = (n > 0) ? ((GetMax() - GetMin()) / n) + 1 : 0;
    [GetNSSlider() setNumberOfTickMarks:numTicks];
}

int wxSlider::GetTickFreq() const
{
    const int numTicks = [GetNSSlider() numberOfTickMarks];
    return ((numTicks != 0) ? (GetMax() - GetMin()) / (numTicks - 1) : 0);
}

void wxSlider::SetTickPos(int pos)
{
    NSTickMarkPosition thePos = NSTickMarkBelow;
    wxSize size = GetSize();

    if (size.GetWidth() < size.GetHeight()) // NSSlider isVertical method can return -1 if it has not been displayed.
    {
        thePos = (pos != 1) ? NSTickMarkLeft : NSTickMarkRight;
    }
    else
    {
        thePos = (pos != 1) ? NSTickMarkBelow : NSTickMarkAbove;
    }

    [GetNSSlider() setTickMarkPosition:thePos];
}

void wxSlider::SetLineSize(int lineSize)
{
    // to do
}

void wxSlider::SetPageSize(int pageSize)
{
    // to do
}

int wxSlider::GetLineSize() const
{
    return 1;
}

int wxSlider::GetPageSize() const
{
    return 1;
}

int wxSlider::GetThumbLength() const
{
    return 1;
}

void wxSlider::SetThumbLength(int lenPixels)
{
    // to do
}

#endif // wxUSE_SLIDER
