/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/window.mm
// Purpose:     wxWindowCocoa
// Author:      David Elliott
// Modified by:
// Created:     2002/12/26
// RCS-ID:      $Id$
// Copyright:   (c) 2002 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/window.h"
    #include "wx/dc.h"
    #include "wx/dcclient.h"
    #include "wx/utils.h"
#endif //WX_PRECOMP

#include "wx/tooltip.h"

#include "wx/cocoa/dc.h"
#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"
#include "wx/cocoa/trackingrectmanager.h"
#include "wx/cocoa/private/scrollview.h"
#include "wx/osx/core/cfref.h"
#include "wx/cocoa/ObjcRef.h"

#import <Foundation/NSArray.h>
#import <Foundation/NSRunLoop.h>
#include "wx/cocoa/objc/NSView.h"
#import <AppKit/NSEvent.h>
#import <AppKit/NSScrollView.h>
#import <AppKit/NSScroller.h>
#import <AppKit/NSColor.h>
#import <AppKit/NSClipView.h>
#import <Foundation/NSException.h>
#import <AppKit/NSApplication.h>
#import <AppKit/NSWindow.h>
#import <AppKit/NSScreen.h>

// Turn this on to paint green over the dummy views for debugging
#undef WXCOCOA_FILL_DUMMY_VIEW

#ifdef WXCOCOA_FILL_DUMMY_VIEW
#import <AppKit/NSBezierPath.h>
#endif //def WXCOCOA_FILL_DUMMY_VIEW

// STL list used by wxCocoaMouseMovedEventSynthesizer
#include <list>

/* NSComparisonResult is typedef'd as an enum pre-Leopard but typedef'd as
 * NSInteger post-Leopard.  Pre-Leopard the Cocoa toolkit expects a function
 * returning int and not NSComparisonResult.  Post-Leopard the Cocoa toolkit
 * expects a function returning the new non-enum NSComparsionResult.
 * Hence we create a typedef named CocoaWindowCompareFunctionResult.
 */
#if defined(NSINTEGER_DEFINED)
typedef NSComparisonResult CocoaWindowCompareFunctionResult;
#else
typedef int CocoaWindowCompareFunctionResult;
#endif

// A category for methods that are only present in Panther's SDK
@interface NSView(wxNSViewPrePantherCompatibility)
- (void)getRectsBeingDrawn:(const NSRect **)rects count:(int *)count;
@end

// ========================================================================
// Helper functions for converting to/from wxWidgets coordinates and a
// specified NSView's coordinate system.
// ========================================================================
NSPoint CocoaTransformNSViewBoundsToWx(NSView *nsview, NSPoint pointBounds)
{
    wxCHECK_MSG(nsview, pointBounds, wxT("Need to have a Cocoa view to do translation"));
    if([nsview isFlipped])
        return pointBounds;
    NSRect ourBounds = [nsview bounds];
    return NSMakePoint
    (   pointBounds.x
    ,   ourBounds.size.height - pointBounds.y
    );
}

NSRect CocoaTransformNSViewBoundsToWx(NSView *nsview, NSRect rectBounds)
{
    wxCHECK_MSG(nsview, rectBounds, wxT("Need to have a Cocoa view to do translation"));
    if([nsview isFlipped])
        return rectBounds;
    NSRect ourBounds = [nsview bounds];
    return NSMakeRect
    (   rectBounds.origin.x
    ,   ourBounds.size.height - (rectBounds.origin.y + rectBounds.size.height)
    ,   rectBounds.size.width
    ,   rectBounds.size.height
    );
}

NSPoint CocoaTransformNSViewWxToBounds(NSView *nsview, NSPoint pointWx)
{
    wxCHECK_MSG(nsview, pointWx, wxT("Need to have a Cocoa view to do translation"));
    if([nsview isFlipped])
        return pointWx;
    NSRect ourBounds = [nsview bounds];
    return NSMakePoint
    (   pointWx.x
    ,   ourBounds.size.height - pointWx.y
    );
}

NSRect CocoaTransformNSViewWxToBounds(NSView *nsview, NSRect rectWx)
{
    wxCHECK_MSG(nsview, rectWx, wxT("Need to have a Cocoa view to do translation"));
    if([nsview isFlipped])
        return rectWx;
    NSRect ourBounds = [nsview bounds];
    return NSMakeRect
    (   rectWx.origin.x
    ,   ourBounds.size.height - (rectWx.origin.y + rectWx.size.height)
    ,   rectWx.size.width
    ,   rectWx.size.height
    );
}

// ============================================================================
// Screen coordinate helpers
// ============================================================================

/*
General observation about Cocoa screen coordinates:
It is documented that the first object of the [NSScreen screens] array is the screen with the menubar.

It is not documented (but true as far as I can tell) that (0,0) in Cocoa screen coordinates is always
the BOTTOM-right corner of this screen.  Recall that Cocoa uses cartesian coordinates so y-increase is up.

It isn't clearly documented but visibleFrame returns a rectangle in screen coordinates, not a rectangle
relative to that screen's frame.  The only real way to test this is to configure two screens one atop
the other such that the menubar screen is on top.  The Dock at the bottom of the screen will then
eat into the visibleFrame of screen 1 by incrementing it's y-origin.  Thus if you arrange two
1920x1200 screens top/bottom then screen 1 (the bottom screen) will have frame origin (0,-1200) and
visibleFrame origin (0,-1149) which is exactly 51 pixels higher than the full frame origin.

In wxCocoa, we somewhat arbitrarily declare that wx (0,0) is the TOP-left of screen 0's frame (the entire screen).
However, this isn't entirely arbitrary because the Quartz Display Services (CGDisplay) uses this same scheme.
This works out nicely because wxCocoa's wxDisplay is implemented using Quartz Display Services instead of NSScreen.
*/

namespace { // file namespace

class wxCocoaPrivateScreenCoordinateTransformer
{
    wxDECLARE_NO_COPY_CLASS(wxCocoaPrivateScreenCoordinateTransformer);
public:
    wxCocoaPrivateScreenCoordinateTransformer();
    ~wxCocoaPrivateScreenCoordinateTransformer();
    wxPoint OriginInWxDisplayCoordinatesForRectInCocoaScreenCoordinates(NSRect windowFrame);
    NSPoint OriginInCocoaScreenCoordinatesForRectInWxDisplayCoordinates(wxCoord x, wxCoord y, wxCoord width, wxCoord height, bool keepOriginVisible);

protected:
    NSScreen *m_screenZero;
    NSRect m_screenZeroFrame;
};

// NOTE: This is intended to be a short-lived object.  A future enhancment might
// make it a global and reconfigure it upon some notification that the screen layout
// has changed.
inline wxCocoaPrivateScreenCoordinateTransformer::wxCocoaPrivateScreenCoordinateTransformer()
{
    NSArray *screens = [NSScreen screens];

    [screens retain];

    m_screenZero = nil;
    if(screens != nil && [screens count] > 0)
        m_screenZero = [[screens objectAtIndex:0] retain];

    [screens release];

    if(m_screenZero != nil)
        m_screenZeroFrame = [m_screenZero frame];
    else
    {
        wxLogWarning(wxT("Can't translate to/from wx screen coordinates and Cocoa screen coordinates"));
        // Just blindly assume 1024x768 so that at least we can sort of flip things around into
        // Cocoa coordinates.
        // NOTE: Theoretically this case should never happen anyway.
        m_screenZeroFrame = NSMakeRect(0,0,1024,768);
    }
}

inline wxCocoaPrivateScreenCoordinateTransformer::~wxCocoaPrivateScreenCoordinateTransformer()
{
    [m_screenZero release];
    m_screenZero = nil;
}

inline wxPoint wxCocoaPrivateScreenCoordinateTransformer::OriginInWxDisplayCoordinatesForRectInCocoaScreenCoordinates(NSRect windowFrame)
{
    // x and y are in wx screen coordinates which we're going to arbitrarily define such that
    // (0,0) is the TOP-left of screen 0 (the one with the menubar)
    // NOTE WELL: This means that (0,0) is _NOT_ an appropriate position for a window.

    wxPoint theWxOrigin;

    // Working in Cocoa's screen coordinates we must realize that the x coordinate we want is
    // the distance between the left side (origin.x) of the window's frame and the left side of
    // screen zero's frame.
    theWxOrigin.x = windowFrame.origin.x - m_screenZeroFrame.origin.x;

    // Working in Cocoa's screen coordinates we must realize that the y coordinate we want is
    // actually the distance between the top-left of the screen zero frame and the top-left
    // of the window's frame.

    theWxOrigin.y = (m_screenZeroFrame.origin.y + m_screenZeroFrame.size.height) - (windowFrame.origin.y + windowFrame.size.height);

    return theWxOrigin;
}

inline NSPoint wxCocoaPrivateScreenCoordinateTransformer::OriginInCocoaScreenCoordinatesForRectInWxDisplayCoordinates(wxCoord x, wxCoord y, wxCoord width, wxCoord height, bool keepOriginVisible)
{
    NSPoint theCocoaOrigin;

    // The position is in wx screen coordinates which we're going to arbitrarily define such that
    // (0,0) is the TOP-left of screen 0 (the one with the menubar)

    // NOTE: The usable rectangle is smaller and hence we have the keepOriginVisible flag
    // which will move the origin downward and/or left as necessary if the origin is
    // inside the screen0 rectangle (i.e. x/y >= 0 in wx coordinates) and outside the
    // visible frame (i.e. x/y < the top/left of the screen0 visible frame in wx coordinates)
    // We don't munge origin coordinates < 0 because it actually is possible that the menubar is on
    // the top of the bottom screen and thus that origin is completely valid!
    if(keepOriginVisible && (m_screenZero != nil))
    {
        // Do al of this in wx coordinates because it's far simpler since we're dealing with top/left points
        wxPoint visibleOrigin = OriginInWxDisplayCoordinatesForRectInCocoaScreenCoordinates([m_screenZero visibleFrame]);
        if(x >= 0 && x < visibleOrigin.x)
            x = visibleOrigin.x;
        if(y >= 0 && y < visibleOrigin.y)
            y = visibleOrigin.y;
    }

    // The x coordinate is simple as it's just relative to screen zero's frame
    theCocoaOrigin.x = m_screenZeroFrame.origin.x + x;
    // Working in Cocoa's coordinates think to start at the bottom of screen zero's frame and add
    // the height of that rect which gives us the coordinate for the top of the visible rect.  Now realize that
    // the wx coordinates are flipped so if y is say 10 then we want to be 10 pixels down from that and thus
    // we subtract y.  But then we still need to take into account the size of the window which is h and subtract
    // that to get the bottom-left origin of the rectangle.
    theCocoaOrigin.y = m_screenZeroFrame.origin.y + m_screenZeroFrame.size.height - y - height;

    return theCocoaOrigin;
}

} // namespace

wxPoint wxWindowCocoa::OriginInWxDisplayCoordinatesForRectInCocoaScreenCoordinates(NSRect windowFrame)
{
    wxCocoaPrivateScreenCoordinateTransformer transformer;
    return transformer.OriginInWxDisplayCoordinatesForRectInCocoaScreenCoordinates(windowFrame);
}

NSPoint wxWindowCocoa::OriginInCocoaScreenCoordinatesForRectInWxDisplayCoordinates(wxCoord x, wxCoord y, wxCoord width, wxCoord height, bool keepOriginVisible)
{
    wxCocoaPrivateScreenCoordinateTransformer transformer;
    return transformer.OriginInCocoaScreenCoordinatesForRectInWxDisplayCoordinates(x,y,width,height,keepOriginVisible);
}

// ========================================================================
// wxWindowCocoaHider
// ========================================================================
class wxWindowCocoaHider: protected wxCocoaNSView
{
    wxDECLARE_NO_COPY_CLASS(wxWindowCocoaHider);
public:
    wxWindowCocoaHider(wxWindow *owner);
    virtual ~wxWindowCocoaHider();
    inline WX_NSView GetNSView() { return m_dummyNSView; }
protected:
    wxWindowCocoa *m_owner;
    WX_NSView m_dummyNSView;
    virtual void Cocoa_FrameChanged(void);
    virtual void Cocoa_synthesizeMouseMoved(void) {}
#ifdef WXCOCOA_FILL_DUMMY_VIEW
    virtual bool Cocoa_drawRect(const NSRect& rect);
#endif //def WXCOCOA_FILL_DUMMY_VIEW
private:
    wxWindowCocoaHider();
};

// ========================================================================
// wxDummyNSView
// ========================================================================
@interface wxDummyNSView : NSView
- (NSView *)hitTest:(NSPoint)aPoint;
@end
WX_DECLARE_GET_OBJC_CLASS(wxDummyNSView,NSView)

@implementation wxDummyNSView : NSView
- (NSView *)hitTest:(NSPoint)aPoint
{
    return nil;
}

@end
WX_IMPLEMENT_GET_OBJC_CLASS(wxDummyNSView,NSView)

// ========================================================================
// wxWindowCocoaHider
//  NOTE: This class and method of hiding predates setHidden: support in
//  the toolkit.  The hack used here is to replace the view with a stand-in
//  that will be subject to the usual Cocoa resizing rules.
//  When possible (i.e. when running on 10.3 or higher) we make it hidden
//  mostly as an optimization so Cocoa doesn't have to consider it when
//  drawing or finding key views.
// ========================================================================
wxWindowCocoaHider::wxWindowCocoaHider(wxWindow *owner)
:   m_owner(owner)
{
    wxASSERT(owner);
    wxASSERT(owner->GetNSViewForHiding());
    m_dummyNSView = [[WX_GET_OBJC_CLASS(wxDummyNSView) alloc]
        initWithFrame:[owner->GetNSViewForHiding() frame]];
    [m_dummyNSView setAutoresizingMask: [owner->GetNSViewForHiding() autoresizingMask]];
    AssociateNSView(m_dummyNSView);

    if([m_dummyNSView respondsToSelector:@selector(setHidden:)])
        [m_dummyNSView setHidden:YES];
}

wxWindowCocoaHider::~wxWindowCocoaHider()
{
    DisassociateNSView(m_dummyNSView);
    [m_dummyNSView release];
}

void wxWindowCocoaHider::Cocoa_FrameChanged(void)
{
    // Keep the real window in synch with the dummy
    wxASSERT(m_dummyNSView);
    [m_owner->GetNSViewForHiding() setFrame:[m_dummyNSView frame]];
}


#ifdef WXCOCOA_FILL_DUMMY_VIEW
bool wxWindowCocoaHider::Cocoa_drawRect(const NSRect& rect)
{
    NSBezierPath *bezpath = [NSBezierPath bezierPathWithRect:rect];
    [[NSColor greenColor] set];
    [bezpath stroke];
    [bezpath fill];
    return true;
}
#endif //def WXCOCOA_FILL_DUMMY_VIEW


/*! @class WXManualScrollView
    @abstract   An NSScrollView subclass which implements wx scroll behavior
    @discussion
    Overrides default behavior of NSScrollView such that this class receives
    the scroller action messages and allows the wxCocoaScrollView to act
    on them accordingly.  In particular, because the NSScrollView will not
    receive action messages from the scroller, it will not adjust the
    document view.  This must be done manually using the ScrollWindow
    method of wxWindow.
 */
@interface WXManualScrollView : NSScrollView
{
    /*! @field      m_wxCocoaScrollView
     */
    wxWindowCocoaScrollView *m_wxCocoaScrollView;
}

// Override these to set up the target/action correctly
- (void)setHorizontalScroller:(NSScroller *)aScroller;
- (void)setVerticalScroller:(NSScroller *)aScroller;
- (void)setHasHorizontalScroller:(BOOL)flag;
- (void)setHasVerticalScroller:(BOOL)flag;

// NOTE: _wx_ prefix means "private" method like _ that Apple (and only Apple) uses.
- (wxWindowCocoaScrollView*)_wx_wxCocoaScrollView;
- (void)_wx_setWxCocoaScrollView:(wxWindowCocoaScrollView*)theWxScrollView;

/*! @method     _wx_doScroller
    @abstract   Handles action messages from the scrollers
    @discussion
    Similar to Apple's _doScroller: method which is private and not documented.
    We do not, however, call that method.  Instead, we effectively override
    it entirely.  We don't override it by naming ourself the same thing because
    the base class code may or may not call that method for other reasons we
    simply cannot know about.
 */
- (void)_wx_doScroller:(id)sender;

@end


@implementation WXManualScrollView : NSScrollView

static inline void WXManualScrollView_DoSetScrollerTargetAction(WXManualScrollView *self, NSScroller *aScroller)
{
    if(aScroller != NULL && [self _wx_wxCocoaScrollView] != NULL)
    {
        [aScroller setTarget:self];
        [aScroller setAction:@selector(_wx_doScroller:)];
    }
}

- (void)setHorizontalScroller:(NSScroller *)aScroller
{
    [super setHorizontalScroller:aScroller];
    WXManualScrollView_DoSetScrollerTargetAction(self, aScroller);
}

- (void)setVerticalScroller:(NSScroller *)aScroller
{
    [super setVerticalScroller:aScroller];
    WXManualScrollView_DoSetScrollerTargetAction(self, aScroller);
}

- (void)setHasHorizontalScroller:(BOOL)flag
{
    [super setHasHorizontalScroller:flag];
    WXManualScrollView_DoSetScrollerTargetAction(self, [self horizontalScroller]);
}

- (void)setHasVerticalScroller:(BOOL)flag
{
    [super setHasVerticalScroller:flag];
    WXManualScrollView_DoSetScrollerTargetAction(self, [self verticalScroller]);
}

- (wxWindowCocoaScrollView*)_wx_wxCocoaScrollView
{   return m_wxCocoaScrollView; }

- (void)_wx_setWxCocoaScrollView:(wxWindowCocoaScrollView*)theWxScrollView
{
    m_wxCocoaScrollView = theWxScrollView;
    [self setHorizontalScroller:[self horizontalScroller]];
    [self setVerticalScroller:[self verticalScroller]];
}

- (void)_wx_doScroller:(id)sender
{
    if(m_wxCocoaScrollView != NULL)
        m_wxCocoaScrollView->_wx_doScroller(sender);
    else
        wxLogError(wxT("Unexpected action message received from NSScroller"));
}

- (void)reflectScrolledClipView:(NSClipView *)aClipView
{
    struct _ScrollerBackup
    {
        _ScrollerBackup(NSScroller *aScroller)
        :   m_scroller(aScroller)
        ,   m_floatValue(aScroller!=nil?[aScroller floatValue]:0.0)
        ,   m_knobProportion(aScroller!=nil?[aScroller knobProportion]:1.0)
        ,   m_isEnabled(aScroller!=nil?[aScroller isEnabled]:false)
        {
        }
        NSScroller *m_scroller;
        CGFloat m_floatValue;
        CGFloat m_knobProportion;
        BOOL m_isEnabled;
        ~_ScrollerBackup()
        {
            if(m_scroller != nil)
            {
                [m_scroller setFloatValue:m_floatValue knobProportion:m_knobProportion];
                [m_scroller setEnabled:m_isEnabled];
            }
        }
    private:
        _ScrollerBackup();
        _ScrollerBackup(_ScrollerBackup const&);
        _ScrollerBackup& operator=(_ScrollerBackup const&);
    };
    _ScrollerBackup _horizontalBackup([self horizontalScroller]);
    _ScrollerBackup _verticalBackup([self verticalScroller]);
    // We MUST call super's implementation or else nothing seems to work right at all.
    // However, we need our scrollers not to change values due to the document window
    // moving so we cheat and save/restore their values across this call.
    [super reflectScrolledClipView: aClipView];
}

@end
WX_IMPLEMENT_GET_OBJC_CLASS(WXManualScrollView,NSScrollView)

// ========================================================================
// wxFlippedNSClipView
// ========================================================================
@interface wxFlippedNSClipView : NSClipView
- (BOOL)isFlipped;
@end
WX_DECLARE_GET_OBJC_CLASS(wxFlippedNSClipView,NSClipView)

@implementation wxFlippedNSClipView : NSClipView
- (BOOL)isFlipped
{
    return YES;
}

@end
WX_IMPLEMENT_GET_OBJC_CLASS(wxFlippedNSClipView,NSClipView)

// ========================================================================
// wxWindowCocoaScrollView
// ========================================================================
wxWindowCocoaScrollView::wxWindowCocoaScrollView(wxWindow *owner)
:   m_owner(owner)
,   m_cocoaNSScrollView() // nil
,   m_scrollRange() // {0,0}
,   m_scrollThumb() // {0,0}
,   m_virtualOrigin(0,0)
{
    wxAutoNSAutoreleasePool pool;
    wxASSERT(owner);
    wxASSERT(owner->GetNSView());
    m_isNativeView = ![owner->GetNSView() isKindOfClass:[WX_GET_OBJC_CLASS(WXNSView) class]];
    m_cocoaNSScrollView = [(m_isNativeView?[NSScrollView alloc]:[WXManualScrollView alloc])
        initWithFrame:[owner->GetNSView() frame]];
    AssociateNSView(m_cocoaNSScrollView);
    if(m_isNativeView)
    {
        /*  Set a bezel border around the entire thing because it looks funny without it.
            TODO: Be sure to undo any borders on the real view (if any) and apply them
            to this view if necessary. Right now, there is no border support in wxCocoa
            so this isn't an issue.
         */
        [m_cocoaNSScrollView setBorderType:NSBezelBorder];
    }
    else
    {
        [(WXManualScrollView*)m_cocoaNSScrollView _wx_setWxCocoaScrollView: this];
        // Don't set a bezel because we might be creating a scroll view due to being
        // the "target window" of a wxScrolledWindow.  That is to say that the user
        // has absolutely no intention of scrolling the clip view used by this
        // NSScrollView.
    }

    /* Replace the default NSClipView with a flipped one.  This ensures
       scrolling is "pinned" to the top-left instead of bottom-right. */
    NSClipView *flippedClip = [[WX_GET_OBJC_CLASS(wxFlippedNSClipView) alloc]
        initWithFrame: [[m_cocoaNSScrollView contentView] frame]];
    [m_cocoaNSScrollView setContentView:flippedClip];
    [flippedClip release];

    // In all cases we must encapsulate the real NSView properly
    Encapsulate();
}

void wxWindowCocoaScrollView::Encapsulate()
{
    // Set the scroll view autoresizingMask to match the current NSView
    [m_cocoaNSScrollView setAutoresizingMask: [m_owner->GetNSView() autoresizingMask]];
    [m_owner->GetNSView() setAutoresizingMask: NSViewNotSizable];
    // NOTE: replaceSubView will cause m_cocaNSView to be released
    // except when it hasn't been added into an NSView hierarchy in which
    // case it doesn't need to be and this should work out to a no-op
    m_owner->CocoaReplaceView(m_owner->GetNSView(), m_cocoaNSScrollView);
    // The NSView is still retained by owner
    [m_cocoaNSScrollView setDocumentView: m_owner->GetNSView()];
    // Now it's also retained by the NSScrollView
}

void wxWindowCocoaScrollView::Unencapsulate()
{
    [m_cocoaNSScrollView setDocumentView: nil];
    m_owner->CocoaReplaceView(m_cocoaNSScrollView, m_owner->GetNSView());
    if(![[m_owner->GetNSView() superview] isFlipped])
        [m_owner->GetNSView() setAutoresizingMask: NSViewMinYMargin];
}

wxWindowCocoaScrollView::~wxWindowCocoaScrollView()
{
    DisassociateNSView(m_cocoaNSScrollView);
    if(!m_isNativeView)
    {
        [(WXManualScrollView*)m_cocoaNSScrollView _wx_setWxCocoaScrollView:NULL];
    }
    [m_cocoaNSScrollView release];
}

void wxWindowCocoaScrollView::ClientSizeToSize(int &width, int &height)
{
    NSSize frameSize = [NSScrollView
        frameSizeForContentSize: NSMakeSize(width,height)
        hasHorizontalScroller: [m_cocoaNSScrollView hasHorizontalScroller]
        hasVerticalScroller: [m_cocoaNSScrollView hasVerticalScroller]
        borderType: [m_cocoaNSScrollView borderType]];
    width = (int)frameSize.width;
    height = (int)frameSize.height;
}

void wxWindowCocoaScrollView::DoGetClientSize(int *x, int *y) const
{
    NSSize nssize = [m_cocoaNSScrollView contentSize];
    if(x)
        *x = (int)nssize.width;
    if(y)
        *y = (int)nssize.height;
}

static inline void SetCocoaScroller(NSScroller *aScroller, int WXUNUSED(orientation), int position, int thumbSize, int range)
{
    wxCHECK_RET(aScroller != nil, wxT("Expected the NSScrollView to have a scroller"));

    // NOTE: thumbSize is already ensured to be >= 1 and <= range by our caller
    // unless range = 0 in which case we shouldn't have been be called.
    wxCHECK_RET(range > 0, wxT("Internal wxCocoa bug: shouldn't have been called with 0 range"));

    // Range of valid position values is from 0 to effectiveRange
    // NOTE: if thumbSize == range then effectiveRange is 0.
    // thumbSize is at least 1 which gives range from 0 to range - 1 inclusive
    // which is exactly what we want.
    int effectiveRange = range - thumbSize;

    // knobProportion is hopefully easy to understand
    // Note that thumbSize is already guaranteed >= 1 by our caller.
    CGFloat const knobProportion = CGFloat(thumbSize)/CGFloat(range);

    // NOTE: When effectiveRange is zero there really is no valid position
    // We arbitrarily pick 0.0 which is the same as a scroller in the home position.
    CGFloat const floatValue = (effectiveRange != 0)?CGFloat(position)/CGFloat(effectiveRange):0.0;

    [aScroller setFloatValue:floatValue knobProportion: knobProportion];
    // Make sure it's visibly working
    [aScroller setEnabled:YES];
}

void wxWindowCocoaScrollView::SetScrollPos(wxOrientation orientation, int position)
{
    // NOTE: Rather than using only setFloatValue: (which we could do) we instead
    // simply share the SetCocoaScroller call because all but the knobProportion
    // calculations have to be done anyway.
    if(orientation & wxHORIZONTAL)
    {
        NSScroller *aScroller = [m_cocoaNSScrollView horizontalScroller];
        if(aScroller != nil)
            SetCocoaScroller(aScroller, orientation, position, m_scrollThumb[0], m_scrollRange[0]);
    }
    if(orientation & wxVERTICAL)
    {
        NSScroller *aScroller = [m_cocoaNSScrollView verticalScroller];
        if(aScroller != nil)
            SetCocoaScroller(aScroller, orientation, position, m_scrollThumb[1], m_scrollRange[1]);
    }
}

void wxWindowCocoaScrollView::SetScrollbar(int orientation, int position, int thumbSize, int range)
{
    // FIXME: API assumptions:
    // 1. If the user wants to remove a scroller he gives range 0.
    // 2. If the user wants to disable a scroller he sets thumbSize == range
    //    in which case it is logically impossible to scroll.
    //    The scroller shall still be displayed.

    // Ensure that range is >= 0.
    wxASSERT(range >= 0);
    if(range < 0)
        range = 0;

    // Ensure that thumbSize <= range
    wxASSERT(thumbSize <= range);
    // Also ensure thumbSize >= 1 but don't complain if it isn't
    if(thumbSize < 1)
        thumbSize = 1;
    // Now make sure it's really less than range, even if we just set it to 1
    if(thumbSize > range)
        thumbSize = range;

    bool needScroller = (range != 0);

    // Can potentially set both horizontal and vertical at the same time although this is
    // probably not very useful.
    if(orientation & wxHORIZONTAL)
    {
        m_scrollRange[0] = range;
        m_scrollThumb[0] = thumbSize;
        if(!m_isNativeView)
        {
            [m_cocoaNSScrollView setHasHorizontalScroller:needScroller];
            if(needScroller)
                SetCocoaScroller([m_cocoaNSScrollView horizontalScroller], orientation, position, thumbSize, range);
        }
    }

    if(orientation & wxVERTICAL)
    {
        m_scrollRange[1] = range;
        m_scrollThumb[1] = thumbSize;
        if(!m_isNativeView)
        {
            [m_cocoaNSScrollView setHasVerticalScroller:needScroller];
            if(needScroller)
                SetCocoaScroller([m_cocoaNSScrollView verticalScroller], orientation, position, thumbSize, range);
        }
    }
}

int wxWindowCocoaScrollView::GetScrollPos(wxOrientation orient)
{
    if((orient & wxBOTH) == wxBOTH)
    {
        wxLogError(wxT("GetScrollPos called for wxHORIZONTAL and wxVERTICAL together which makes no sense"));
        return 0;
    }
    int effectiveScrollRange;
    NSScroller *cocoaScroller;
    if(orient & wxHORIZONTAL)
    {
        effectiveScrollRange = m_scrollRange[0] - m_scrollThumb[0];
        cocoaScroller = [m_cocoaNSScrollView horizontalScroller];
    }
    else if(orient & wxVERTICAL)
    {
        effectiveScrollRange = m_scrollRange[1] - m_scrollThumb[1];
        cocoaScroller = [m_cocoaNSScrollView verticalScroller];
    }
    else
    {
        wxLogError(wxT("GetScrollPos called without an orientation which makes no sense"));
        return 0;
    }
    if(cocoaScroller == nil)
    {   // Document is not scrolled
        return 0;
    }
    /*
        The effective range of a scroll bar as defined by wxWidgets is from 0 to (range - thumbSize).
        That is a scroller at the left/top position is at 0 and a scroller at the bottom/right
        position is at range-thumbsize.

        The range of an NSScroller is 0.0 to 1.0.  Much easier! NOTE: Apple doesn't really specify
        but GNUStep docs do say that 0.0 is top/left and 1.0 is bottom/right.  This is actualy
        in contrast to NSSlider which generally has 1.0 at the TOP when it's done vertically.
     */
    CGFloat cocoaScrollPos = [cocoaScroller floatValue];
    return effectiveScrollRange * cocoaScrollPos;
}

int wxWindowCocoaScrollView::GetScrollRange(wxOrientation orient)
{
    if((orient & wxBOTH) == wxBOTH)
    {
        wxLogError(wxT("GetScrollRange called for wxHORIZONTAL and wxVERTICAL together which makes no sense"));
        return 0;
    }
    if(orient & wxHORIZONTAL)
    {
        return m_scrollRange[0];
    }
    else if(orient & wxVERTICAL)
    {
        return m_scrollRange[1];
    }
    else
    {
        wxLogError(wxT("GetScrollPos called without an orientation which makes no sense"));
        return 0;
    }
}

int wxWindowCocoaScrollView::GetScrollThumb(wxOrientation orient)
{
    if((orient & wxBOTH) == wxBOTH)
    {
        wxLogError(wxT("GetScrollThumb called for wxHORIZONTAL and wxVERTICAL together which makes no sense"));
        return 0;
    }
    if(orient & wxHORIZONTAL)
    {
        return m_scrollThumb[0];
    }
    else if(orient & wxVERTICAL)
    {
        return m_scrollThumb[1];
    }
    else
    {
        wxLogError(wxT("GetScrollThumb called without an orientation which makes no sense"));
        return 0;
    }
}

/*!
    Moves the contents (all existing drawing as well as all all child wxWindow) by the specified
    amount expressed in the wxWindow's own coordinate system.  This is used to implement scrolling
    but the usage is rather interesting.  When scrolling right (e.g. increasing the value of
    the scroller) you must give a negative delta x (e.g. moving the contents LEFT).  Likewise,
    when scrolling the window down, increasing the value of the scroller, you give a negative
    delta y which moves the contents up.

    wxCocoa notes: To accomplish this trick in Cocoa we basically do what NSScrollView would
    have done and that is adjust the content view's bounds origin.  The content view is somewhat
    confusingly the NSClipView which is more or less sort of the pImpl for NSScrollView
    The real NSView with the user's content (e.g. the "virtual area" in wxWidgets parlance)
    is called the document view in NSScrollView parlance.

    The bounds origin is basically the exact opposite concept.  Whereas in Windows the client
    coordinate system remains constant and the content must shift left/up for increases
    of scrolling, in Cocoa the coordinate system is actually the virtual one.  So we must
    instead shift the bounds rectangle right/down to get the effect of the content moving
    left/up.  Basically, it's a higher level interface than that provided by wxWidgets
    so essentially we're implementing the low-level move content interface in terms of
    the high-level move the viewport (the bounds) over top that content (the document
    view which is the virtual area to wx).

    For all intents and purposes that basically just means that we subtract the deltas
    from the bounds origin and thus a negative delta actually increases the bounds origin
    and a positive delta actually decreases it.  This is absolutely true for the horizontal
    axis but there's a catch in the vertical axis.  If the content view (the clip view) is
    flipped (and we do this by default) then it works exactly like the horizontal axis.
    If it is not flipped (i.e. it is in postscript coordinates which are opposite to
    wxWidgets) then the sense needs to be reversed.

    However, this plays hell with window positions.  The frame rects of any child views
    do not change origin and this is actually important because if they did, the views
    would send frame changed notifications, not to mention that Cocoa just doesn't really
    do scrolling that way, it does it the way we do it here.

    To fix this we implement GetPosition for child windows to not merely consult its
    superview at the Cocoa level in order to do proper Cocoa->wx coordinate transform
    but to actually consult is parent wxWindow because it makes a big difference if
    the parent is scrolled. Argh.  (FIXME: This isn't actually implemented yet)
 */
void wxWindowCocoaScrollView::ScrollWindow(int dx, int dy, const wxRect*)
{
    // Update our internal origin so we know how much the application code
    // expects us to have been scrolled.
    m_virtualOrigin.x += dx;
    m_virtualOrigin.y += dy;

    // Scroll the window using the standard Cocoa method of adjusting the
    // clip view's bounds in the opposite fashion.
    NSClipView *contentView = [m_cocoaNSScrollView contentView];
    NSRect clipViewBoundsRect = [contentView bounds];
    clipViewBoundsRect.origin.x -= dx;
    if([contentView isFlipped])
        clipViewBoundsRect.origin.y -= dy;
    else
        clipViewBoundsRect.origin.y += dy;
    [contentView scrollToPoint:clipViewBoundsRect.origin];
}

void wxWindowCocoaScrollView::_wx_doScroller(NSScroller *sender)
{
    wxOrientation orientation;
    if(sender == [m_cocoaNSScrollView horizontalScroller])
        orientation = wxHORIZONTAL;
    else if(sender == [m_cocoaNSScrollView verticalScroller])
        orientation = wxVERTICAL;
    else
    {
        wxLogDebug(wxT("Received action message from unexpected NSScroller"));
        return;
    }
    // NOTE: Cocoa does not move the scroller for page up/down or line
    // up/down events.  That means the value will be the old value.
    // For thumbtrack events, the value is the new value.
    int scrollpos = GetScrollPos(orientation);
    int commandType;
    switch([sender hitPart])
    {
    default:
    case NSScrollerNoPart:
    case NSScrollerKnob:        // Drag of knob
    case NSScrollerKnobSlot:    // Jump directly to position
        commandType = wxEVT_SCROLLWIN_THUMBTRACK;
        break;
    case NSScrollerDecrementPage:
        commandType = wxEVT_SCROLLWIN_PAGEUP;
        break;
    case NSScrollerIncrementPage:
        commandType = wxEVT_SCROLLWIN_PAGEDOWN;
        break;
    case NSScrollerDecrementLine:
        commandType = wxEVT_SCROLLWIN_LINEUP;
        break;
    case NSScrollerIncrementLine:
        commandType = wxEVT_SCROLLWIN_LINEDOWN;
        break;
    }
    wxScrollWinEvent event(commandType, scrollpos, orientation);
    event.SetEventObject(m_owner);
    m_owner->HandleWindowEvent(event);
}

void wxWindowCocoaScrollView::UpdateSizes()
{
    // Using the virtual size, figure out what the document frame size should be
    // NOTE: Assume that the passed in virtualSize is already >= the client size
    wxSize virtualSize = m_owner->GetVirtualSize();

    // Get the document's current frame
    NSRect documentViewFrame = [m_owner->GetNSView() frame];
    NSRect newFrame = documentViewFrame;
    newFrame.size = NSMakeSize(virtualSize.x, virtualSize.y);

    if(!NSEqualRects(newFrame, documentViewFrame))
    {
        [m_owner->GetNSView() setFrame:newFrame];
    }
}

void wxWindowCocoaScrollView::Cocoa_FrameChanged(void)
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxWindowCocoaScrollView=%p::Cocoa_FrameChanged for wxWindow %p"), this, m_owner);
    wxSizeEvent event(m_owner->GetSize(), m_owner->GetId());
    event.SetEventObject(m_owner);
    m_owner->HandleWindowEvent(event);

    /*  If the view is not a native one then it's being managed by wx.  In this case the control
        may decide to change its virtual size and we must update the document view's size to
        match.  For native views the virtual size will never have been set so we do not want
        to use it at all.
     */
    if(!m_isNativeView)
        UpdateSizes();
}

// ========================================================================
// wxWindowCocoa
// ========================================================================
// normally the base classes aren't included, but wxWindow is special
#ifdef __WXUNIVERSAL__
IMPLEMENT_ABSTRACT_CLASS(wxWindowCocoa, wxWindowBase)
#else
IMPLEMENT_DYNAMIC_CLASS(wxWindow, wxWindowBase)
#endif

BEGIN_EVENT_TABLE(wxWindowCocoa, wxWindowBase)
END_EVENT_TABLE()

wxWindow *wxWindowCocoa::sm_capturedWindow = NULL;

// Constructor
void wxWindowCocoa::Init()
{
    m_cocoaNSView = NULL;
    m_cocoaHider = NULL;
    m_wxCocoaScrollView = NULL;
    m_isInPaint = false;
    m_visibleTrackingRectManager = NULL;
}

// Constructor
bool wxWindow::Create(wxWindow *parent, wxWindowID winid,
           const wxPoint& pos,
           const wxSize& size,
           long style,
           const wxString& name)
{
    if(!CreateBase(parent,winid,pos,size,style,wxDefaultValidator,name))
        return false;

    // TODO: create the window
    m_cocoaNSView = NULL;
    SetNSView([[WX_GET_OBJC_CLASS(WXNSView) alloc] initWithFrame: MakeDefaultNSRect(size)]);
    [m_cocoaNSView release];

    if (m_parent)
    {
        m_parent->AddChild(this);
        m_parent->CocoaAddChild(this);
        SetInitialFrameRect(pos,size);
    }

    return true;
}

// Destructor
wxWindow::~wxWindow()
{
    wxAutoNSAutoreleasePool pool;
    DestroyChildren();

    // Make sure our parent (in the wxWidgets sense) is our superview
    // before we go removing from it.
    if(m_parent && m_parent->GetNSView()==[GetNSViewForSuperview() superview])
        CocoaRemoveFromParent();
    delete m_cocoaHider;
    delete m_wxCocoaScrollView;
    if(m_cocoaNSView)
        SendDestroyEvent();
    SetNSView(NULL);
}

void wxWindowCocoa::CocoaAddChild(wxWindowCocoa *child)
{
    // Pool here due to lack of one during wx init phase
    wxAutoNSAutoreleasePool pool;

    NSView *childView = child->GetNSViewForSuperview();

    wxASSERT(childView);
    [m_cocoaNSView addSubview: childView];
}

void wxWindowCocoa::CocoaRemoveFromParent(void)
{
    [GetNSViewForSuperview() removeFromSuperview];
}

void wxWindowCocoa::SetNSView(WX_NSView cocoaNSView)
{
    // Clear the visible area tracking rect if we have one.
    delete m_visibleTrackingRectManager;
    m_visibleTrackingRectManager = NULL;

    bool need_debug = cocoaNSView || m_cocoaNSView;
    if(need_debug) wxLogTrace(wxTRACE_COCOA_RetainRelease,wxT("wxWindowCocoa=%p::SetNSView [m_cocoaNSView=%p retainCount]=%d"),this,m_cocoaNSView,[m_cocoaNSView retainCount]);
    DisassociateNSView(m_cocoaNSView);
    wxGCSafeRetain(cocoaNSView);
    wxGCSafeRelease(m_cocoaNSView);
    m_cocoaNSView = cocoaNSView;
    AssociateNSView(m_cocoaNSView);
    if(need_debug) wxLogTrace(wxTRACE_COCOA_RetainRelease,wxT("wxWindowCocoa=%p::SetNSView [cocoaNSView=%p retainCount]=%d"),this,cocoaNSView,[cocoaNSView retainCount]);
}

WX_NSView wxWindowCocoa::GetNSViewForSuperview() const
{
    return m_cocoaHider
        ?   m_cocoaHider->GetNSView()
        :   m_wxCocoaScrollView
            ?   m_wxCocoaScrollView->GetNSScrollView()
            :   m_cocoaNSView;
}

WX_NSView wxWindowCocoa::GetNSViewForHiding() const
{
    return m_wxCocoaScrollView
        ?   m_wxCocoaScrollView->GetNSScrollView()
        :   m_cocoaNSView;
}

NSPoint wxWindowCocoa::CocoaTransformBoundsToWx(NSPoint pointBounds)
{
    // TODO: Handle scrolling offset
    return CocoaTransformNSViewBoundsToWx(GetNSView(), pointBounds);
}

NSRect wxWindowCocoa::CocoaTransformBoundsToWx(NSRect rectBounds)
{
    // TODO: Handle scrolling offset
    return CocoaTransformNSViewBoundsToWx(GetNSView(), rectBounds);
}

NSPoint wxWindowCocoa::CocoaTransformWxToBounds(NSPoint pointWx)
{
    // TODO: Handle scrolling offset
    return CocoaTransformNSViewWxToBounds(GetNSView(), pointWx);
}

NSRect wxWindowCocoa::CocoaTransformWxToBounds(NSRect rectWx)
{
    // TODO: Handle scrolling offset
    return CocoaTransformNSViewWxToBounds(GetNSView(), rectWx);
}

WX_NSAffineTransform wxWindowCocoa::CocoaGetWxToBoundsTransform()
{
    // TODO: Handle scrolling offset
    NSAffineTransform *transform = wxCocoaDCImpl::CocoaGetWxToBoundsTransform([GetNSView() isFlipped], [GetNSView() bounds].size.height);
    return transform;
}

bool wxWindowCocoa::Cocoa_drawRect(const NSRect &rect)
{
    wxLogTrace(wxTRACE_COCOA,wxT("Cocoa_drawRect"));
    // Recursion can happen if the event loop runs from within the paint
    // handler.  For instance, if an assertion dialog is shown.
    // FIXME: This seems less than ideal.
    if(m_isInPaint)
    {
        wxLogDebug(wxT("Paint event recursion!"));
        return false;
    }
    m_isInPaint = true;

    // Set m_updateRegion
    const NSRect *rects = &rect; // The bounding box of the region
    NSInteger countRects = 1;
    // Try replacing the larger rectangle with a list of smaller ones:
    if ([GetNSView() respondsToSelector:@selector(getRectsBeingDrawn:count:)])
        [GetNSView() getRectsBeingDrawn:&rects count:&countRects];

    NSRect *transformedRects = (NSRect*)malloc(sizeof(NSRect)*countRects);
    for(int i=0; i<countRects; i++)
    {
        transformedRects[i] = CocoaTransformBoundsToWx(rects[i]);
    }
    m_updateRegion = wxRegion(transformedRects,countRects);
    free(transformedRects);

    wxPaintEvent event(m_windowId);
    event.SetEventObject(this);
    bool ret = HandleWindowEvent(event);
    m_isInPaint = false;
    return ret;
}

void wxWindowCocoa::InitMouseEvent(wxMouseEvent& event, WX_NSEvent cocoaEvent)
{
    wxASSERT_MSG([m_cocoaNSView window]==[cocoaEvent window],wxT("Mouse event for different NSWindow"));
    // Mouse events happen at the NSWindow level so we need to convert
    // into our bounds coordinates then convert to wx coordinates.
    NSPoint cocoaPoint = [m_cocoaNSView convertPoint:[(NSEvent*)cocoaEvent locationInWindow] fromView:nil];
    if( m_wxCocoaScrollView != NULL)
    {
        // This gets the wx client area (i.e. the visible portion of the content) in
        // the coordinate system of our (the doucment) view.
	NSRect documentVisibleRect = [[m_wxCocoaScrollView->GetNSScrollView() contentView] documentVisibleRect];
        // For horizontal, simply subtract the origin.
        // e.g. if the origin is at 123 and the user clicks as far left as possible then
        // the coordinate that wx wants is 0.
	cocoaPoint.x -= documentVisibleRect.origin.x;
        if([m_cocoaNSView isFlipped])
        {
            // In the flipped view case this works exactly like horizontal.
            cocoaPoint.y -= documentVisibleRect.origin.y;
        }
        // For vertical we have to mind non-flipped (e.g. y=0 at bottom) views.
        // We also need to mind the fact that we're still in Cocoa coordinates
        // and not wx coordinates.  The wx coordinate translation will still occur
        // and that is going to be wxY = boundsH - cocoaY for non-flipped views.

        // When we consider scrolling we are truly interested in how far the top
        // edge of the bounds rectangle is scrolled off the screen.
        // Assuming the bounds origin is 0 (which is an assumption we make in
        // wxCocoa since wxWidgets has no analog to it) then the top edge of
        // the bounds rectangle is simply its height.  The top edge of the
        // documentVisibleRect (e.g. the client area) is its height plus
        // its origin.
        // Thus, we simply need add the distance between the bounds top
        // and the client (docuemntVisibleRect) top.
        // Or putting it another way, we subtract the distance between the
        // client top and the bounds top.
        else
        {
            NSRect bounds = [m_cocoaNSView bounds];
            CGFloat scrollYOrigin = (bounds.size.height - (documentVisibleRect.origin.y + documentVisibleRect.size.height));
            cocoaPoint.y += scrollYOrigin;
        }
    }

    NSPoint pointWx = CocoaTransformBoundsToWx(cocoaPoint);
    // FIXME: Should we be adjusting for client area origin?
    const wxPoint &clientorigin = GetClientAreaOrigin();
    event.m_x = (wxCoord)pointWx.x - clientorigin.x;
    event.m_y = (wxCoord)pointWx.y - clientorigin.y;

    event.m_shiftDown = [cocoaEvent modifierFlags] & NSShiftKeyMask;
    event.m_controlDown = [cocoaEvent modifierFlags] & NSControlKeyMask;
    event.m_altDown = [cocoaEvent modifierFlags] & NSAlternateKeyMask;
    event.m_metaDown = [cocoaEvent modifierFlags] & NSCommandKeyMask;

    // TODO: set timestamp?
    event.SetEventObject(this);
    event.SetId(GetId());
}

bool wxWindowCocoa::Cocoa_mouseMoved(WX_NSEvent theEvent)
{
    wxMouseEvent event(wxEVT_MOTION);
    InitMouseEvent(event,theEvent);
    wxLogTrace(wxTRACE_COCOA,wxT("wxWindow=%p::Cocoa_mouseMoved @%d,%d"),this,event.m_x,event.m_y);
    return HandleWindowEvent(event);
}

void wxWindowCocoa::Cocoa_synthesizeMouseMoved()
{
    wxMouseEvent event(wxEVT_MOTION);
    NSWindow *window = [GetNSView() window];
    NSPoint locationInWindow = [window mouseLocationOutsideOfEventStream];
    NSPoint cocoaPoint = [m_cocoaNSView convertPoint:locationInWindow fromView:nil];

    NSPoint pointWx = CocoaTransformBoundsToWx(cocoaPoint);
    // FIXME: Should we be adjusting for client area origin?
    const wxPoint &clientorigin = GetClientAreaOrigin();
    event.m_x = (wxCoord)pointWx.x - clientorigin.x;
    event.m_y = (wxCoord)pointWx.y - clientorigin.y;

    // TODO: Handle shift, control, alt, meta flags
    event.SetEventObject(this);
    event.SetId(GetId());

    wxLogTrace(wxTRACE_COCOA,wxT("wxwin=%p Synthesized Mouse Moved @%d,%d"),this,event.m_x,event.m_y);
    HandleWindowEvent(event);
}

bool wxWindowCocoa::Cocoa_mouseEntered(WX_NSEvent theEvent)
{
    if(m_visibleTrackingRectManager != NULL && m_visibleTrackingRectManager->IsOwnerOfEvent(theEvent))
    {
        m_visibleTrackingRectManager->BeginSynthesizingEvents();

        // Although we synthesize the mouse moved events we don't poll for them but rather send them only when
        // some other event comes in.  That other event is (guess what) mouse moved events that will be sent
        // to the NSWindow which will forward them on to the first responder.  We are not likely to be the
        // first responder, so the mouseMoved: events are effectively discarded.
        [[GetNSView() window] setAcceptsMouseMovedEvents:YES];

        wxMouseEvent event(wxEVT_ENTER_WINDOW);
        InitMouseEvent(event,theEvent);
        wxLogTrace(wxTRACE_COCOA_TrackingRect,wxT("wxwin=%p Mouse Entered TR#%d @%d,%d"),this,[theEvent trackingNumber], event.m_x,event.m_y);
        return HandleWindowEvent(event);
    }
    else
        return false;
}

bool wxWindowCocoa::Cocoa_mouseExited(WX_NSEvent theEvent)
{
    if(m_visibleTrackingRectManager != NULL && m_visibleTrackingRectManager->IsOwnerOfEvent(theEvent))
    {
        m_visibleTrackingRectManager->StopSynthesizingEvents();

        wxMouseEvent event(wxEVT_LEAVE_WINDOW);
        InitMouseEvent(event,theEvent);
        wxLogTrace(wxTRACE_COCOA_TrackingRect,wxT("wxwin=%p Mouse Exited TR#%d @%d,%d"),this,[theEvent trackingNumber],event.m_x,event.m_y);
        return HandleWindowEvent(event);
    }
    else
        return false;
}

bool wxWindowCocoa::Cocoa_mouseDown(WX_NSEvent theEvent)
{
    wxMouseEvent event([theEvent clickCount]<2?wxEVT_LEFT_DOWN:wxEVT_LEFT_DCLICK);
    InitMouseEvent(event,theEvent);
    wxLogTrace(wxTRACE_COCOA,wxT("Mouse Down @%d,%d num clicks=%d"),event.m_x,event.m_y,[theEvent clickCount]);
    return HandleWindowEvent(event);
}

bool wxWindowCocoa::Cocoa_mouseDragged(WX_NSEvent theEvent)
{
    wxMouseEvent event(wxEVT_MOTION);
    InitMouseEvent(event,theEvent);
    event.m_leftDown = true;
    wxLogTrace(wxTRACE_COCOA,wxT("Mouse Drag @%d,%d"),event.m_x,event.m_y);
    return HandleWindowEvent(event);
}

bool wxWindowCocoa::Cocoa_mouseUp(WX_NSEvent theEvent)
{
    wxMouseEvent event(wxEVT_LEFT_UP);
    InitMouseEvent(event,theEvent);
    wxLogTrace(wxTRACE_COCOA,wxT("Mouse Up @%d,%d"),event.m_x,event.m_y);
    return HandleWindowEvent(event);
}

bool wxWindowCocoa::Cocoa_rightMouseDown(WX_NSEvent theEvent)
{
    wxMouseEvent event([theEvent clickCount]<2?wxEVT_RIGHT_DOWN:wxEVT_RIGHT_DCLICK);
    InitMouseEvent(event,theEvent);
    wxLogDebug(wxT("Mouse Down @%d,%d num clicks=%d"),event.m_x,event.m_y,[theEvent clickCount]);
    return HandleWindowEvent(event);
}

bool wxWindowCocoa::Cocoa_rightMouseDragged(WX_NSEvent theEvent)
{
    wxMouseEvent event(wxEVT_MOTION);
    InitMouseEvent(event,theEvent);
    event.m_rightDown = true;
    wxLogDebug(wxT("Mouse Drag @%d,%d"),event.m_x,event.m_y);
    return HandleWindowEvent(event);
}

bool wxWindowCocoa::Cocoa_rightMouseUp(WX_NSEvent theEvent)
{
    wxMouseEvent event(wxEVT_RIGHT_UP);
    InitMouseEvent(event,theEvent);
    wxLogDebug(wxT("Mouse Up @%d,%d"),event.m_x,event.m_y);
    return HandleWindowEvent(event);
}

bool wxWindowCocoa::Cocoa_otherMouseDown(WX_NSEvent theEvent)
{
    return false;
}

bool wxWindowCocoa::Cocoa_otherMouseDragged(WX_NSEvent theEvent)
{
    return false;
}

bool wxWindowCocoa::Cocoa_otherMouseUp(WX_NSEvent theEvent)
{
    return false;
}

void wxWindowCocoa::Cocoa_FrameChanged(void)
{
    // We always get this message for the real NSView which may have been
    // enclosed in an NSScrollView.  If that's the case then what we're
    // effectively getting here is a notifcation that the
    // virtual sized changed.. which we don't need to send on since
    // wx has no concept of this whatsoever.
    bool isViewForSuperview = (m_wxCocoaScrollView == NULL);
    if(isViewForSuperview)
    {
        wxLogTrace(wxTRACE_COCOA,wxT("wxWindow=%p::Cocoa_FrameChanged"),this);
        if(m_visibleTrackingRectManager != NULL)
            m_visibleTrackingRectManager->RebuildTrackingRect();
        wxSizeEvent event(GetSize(), m_windowId);
        event.SetEventObject(this);
        HandleWindowEvent(event);
    }
    else
    {
        wxLogTrace(wxTRACE_COCOA,wxT("wxWindow=%p::Cocoa_FrameChanged ignored"),this);
    }
}

bool wxWindowCocoa::Cocoa_resetCursorRects()
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxWindow=%p::Cocoa_resetCursorRects"),this);

    // When we are called there may be a queued tracking rect event (mouse entered or exited) and
    // we won't know it.  A specific example is wxGenericHyperlinkCtrl changing the cursor from its
    // mouse exited event.  If the control happens to share the edge with its parent window which is
    // also tracking mouse events then Cocoa receives two mouse exited events from the window server.
    // The first one will cause wxGenericHyperlinkCtrl to call wxWindow::SetCursor which will
    // invaildate the cursor rect causing Cocoa to schedule cursor rect reset with the run loop
    // which willl in turn call us before exiting for the next user event.

    // If we are the parent window then rebuilding our tracking rectangle will cause us to miss
    // our mouse exited event because the already queued event will have the old tracking rect
    // tag.  The simple solution is to only rebuild our tracking rect if we need to.

    if(m_visibleTrackingRectManager != NULL)
        m_visibleTrackingRectManager->RebuildTrackingRectIfNeeded();

    if(!m_cursor.GetNSCursor())
        return false;

    [GetNSView() addCursorRect: [GetNSView() visibleRect]  cursor: m_cursor.GetNSCursor()];

    return true;
}

bool wxWindowCocoa::SetCursor(const wxCursor &cursor)
{
    if(!wxWindowBase::SetCursor(cursor))
        return false;

    // Set up the cursor rect so that invalidateCursorRectsForView: will destroy it.
    // If we don't do this then Cocoa thinks (rightly) that we don't have any cursor
    // rects and thus won't ever call resetCursorRects.
    [GetNSView() addCursorRect: [GetNSView() visibleRect]  cursor: m_cursor.GetNSCursor()];

    // Invalidate the cursor rects so the cursor will change
    // Note that it is not enough to remove the old one (if any) and add the new one.
    // For the rects to work properly, Cocoa itself must call resetCursorRects.
    [[GetNSView() window] invalidateCursorRectsForView:GetNSView()];
    return true;
}

bool wxWindowCocoa::Cocoa_viewDidMoveToWindow()
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxWindow=%p::viewDidMoveToWindow"),this);
    // Set up new tracking rects.  I am reasonably sure the new window must be set before doing this.
    if(m_visibleTrackingRectManager != NULL)
        m_visibleTrackingRectManager->BuildTrackingRect();
    return false;
}

bool wxWindowCocoa::Cocoa_viewWillMoveToWindow(WX_NSWindow newWindow)
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxWindow=%p::viewWillMoveToWindow:%p"),this, newWindow);
    // Clear tracking rects.  It is imperative this be done before the new window is set.
    if(m_visibleTrackingRectManager != NULL)
        m_visibleTrackingRectManager->ClearTrackingRect();
    return false;
}

bool wxWindow::Close(bool force)
{
    // The only reason this function exists is that it is virtual and
    // wxTopLevelWindowCocoa will override it.
    return wxWindowBase::Close(force);
}

void wxWindow::CocoaReplaceView(WX_NSView oldView, WX_NSView newView)
{
    [[oldView superview] replaceSubview:oldView with:newView];
}

void wxWindow::DoEnable(bool enable)
{
	CocoaSetEnabled(enable);
}

bool wxWindow::Show(bool show)
{
    wxAutoNSAutoreleasePool pool;
    // If the window is marked as visible, then it shouldn't have a dummy view
    // If the window is marked hidden, then it should have a dummy view
    // wxSpinCtrl (generic) abuses m_isShown, don't use it for any logic
//    wxASSERT_MSG( (m_isShown && !m_dummyNSView) || (!m_isShown && m_dummyNSView),wxT("wxWindow: m_isShown does not agree with m_dummyNSView"));
    // Return false if there isn't a window to show or hide
    NSView *cocoaView = GetNSViewForHiding();
    if(!cocoaView)
        return false;
    if(show)
    {
        // If state isn't changing, return false
        if(!m_cocoaHider)
            return false;

        // Replace the stand-in view with the real one and destroy the dummy view
        CocoaReplaceView(m_cocoaHider->GetNSView(), cocoaView);
        wxASSERT(![m_cocoaHider->GetNSView() superview]);
        delete m_cocoaHider;
        m_cocoaHider = NULL;
        wxASSERT([cocoaView superview]);

        // Schedule an update of the key view loop (NOTE: 10.4+ only.. argh)
        NSWindow *window = [cocoaView window];
        if(window != nil)
        {
            // Delay this until returning to the event loop for a couple of reasons:
            // 1. If a lot of stuff is shown/hidden we avoid recalculating needlessly
            // 2. NSWindow does not seem to see the newly shown views if we do it right now.
            if([window respondsToSelector:@selector(recalculateKeyViewLoop)])
                [window performSelector:@selector(recalculateKeyViewLoop) withObject:nil afterDelay:0.0];
        }
    }
    else
    {
        // If state isn't changing, return false
        if(m_cocoaHider)
            return false;

        // Handle the first responder
        NSWindow *window = [cocoaView window];
        if(window != nil)
        {
            NSResponder *firstResponder = [window firstResponder];
            if([firstResponder isKindOfClass:[NSView class]] && [(NSView*)firstResponder isDescendantOf:cocoaView])
            {
                BOOL didResign = [window makeFirstResponder:nil];
                // If the current first responder (one of our subviews) refuses to give
                // up its status, then fail now and don't hide this view
                if(didResign == NO)
                    return false;
            }
        }

        // Create a new view to stand in for the real one (via wxWindowCocoaHider) and replace
        // the real one with the stand in.
        m_cocoaHider = new wxWindowCocoaHider(this);
        // NOTE: replaceSubview:with will cause m_cocaNSView to be
        // (auto)released which balances out addSubview
        CocoaReplaceView(cocoaView, m_cocoaHider->GetNSView());
        // m_coocaNSView is now only retained by us
        wxASSERT([m_cocoaHider->GetNSView() superview]);
        wxASSERT(![cocoaView superview]);
    }
    m_isShown = show;
    return true;
}

void wxWindowCocoa::DoSetSize(int x, int y, int width, int height, int sizeFlags)
{
    wxLogTrace(wxTRACE_COCOA_Window_Size,wxT("wxWindow=%p::DoSetSizeWindow(%d,%d,%d,%d,Auto: %s%s)"),this,x,y,width,height,(sizeFlags&wxSIZE_AUTO_WIDTH)?"W":".",sizeFlags&wxSIZE_AUTO_HEIGHT?"H":".");
    int currentX, currentY;
    int currentW, currentH;
    DoGetPosition(&currentX, &currentY);
    DoGetSize(&currentW, &currentH);
    if((x==-1) && !(sizeFlags&wxSIZE_ALLOW_MINUS_ONE))
        x=currentX;
    if((y==-1) && !(sizeFlags&wxSIZE_ALLOW_MINUS_ONE))
        y=currentY;

    AdjustForParentClientOrigin(x,y,sizeFlags);

    wxSize size(wxDefaultSize);

    if((width==-1)&&!(sizeFlags&wxSIZE_ALLOW_MINUS_ONE))
    {
        if(sizeFlags&wxSIZE_AUTO_WIDTH)
        {
            size=DoGetBestSize();
            width=size.x;
        }
        else
            width=currentW;
    }
    if((height==-1)&&!(sizeFlags&wxSIZE_ALLOW_MINUS_ONE))
    {
        if(sizeFlags&wxSIZE_AUTO_HEIGHT)
        {
            if(size.x==-1)
                size=DoGetBestSize();
            height=size.y;
        }
        else
            height=currentH;
    }
    DoMoveWindow(x,y,width,height);
}

#if wxUSE_TOOLTIPS

void wxWindowCocoa::DoSetToolTip( wxToolTip *tip )
{
    wxWindowBase::DoSetToolTip(tip);

    if ( m_tooltip )
    {
        m_tooltip->SetWindow((wxWindow *)this);
    }
}

#endif

void wxWindowCocoa::DoMoveWindow(int x, int y, int width, int height)
{
    wxAutoNSAutoreleasePool pool;
    wxLogTrace(wxTRACE_COCOA_Window_Size,wxT("wxWindow=%p::DoMoveWindow(%d,%d,%d,%d)"),this,x,y,width,height);

    NSView *nsview = GetNSViewForSuperview();
    NSView *superview = [nsview superview];

    wxCHECK_RET(GetParent(), wxT("Window can only be placed correctly when it has a parent"));

    NSRect oldFrameRect = [nsview frame];
    NSRect newFrameRect = GetParent()->CocoaTransformWxToBounds(NSMakeRect(x,y,width,height));
    [nsview setFrame:newFrameRect];
    // Be sure to redraw the parent to reflect the changed position
    [superview setNeedsDisplayInRect:oldFrameRect];
    [superview setNeedsDisplayInRect:newFrameRect];
}

void wxWindowCocoa::SetInitialFrameRect(const wxPoint& pos, const wxSize& size)
{
    NSView *nsview = GetNSViewForSuperview();
    NSView *superview = [nsview superview];
    wxCHECK_RET(superview,wxT("NSView does not have a superview"));
    wxCHECK_RET(GetParent(), wxT("Window can only be placed correctly when it has a parent"));
    NSRect frameRect = [nsview frame];
    if(size.x!=-1)
        frameRect.size.width = size.x;
    if(size.y!=-1)
        frameRect.size.height = size.y;
    frameRect.origin.x = pos.x;
    frameRect.origin.y = pos.y;
    // Tell Cocoa to change the margin between the bottom of the superview
    // and the bottom of the control.  Keeps the control pinned to the top
    // of its superview so that its position in the wxWidgets coordinate
    // system doesn't change.
    if(![superview isFlipped])
        [nsview setAutoresizingMask: NSViewMinYMargin];
    // MUST set the mask before setFrame: which can generate a size event
    // and cause a scroller to be added!
    frameRect = GetParent()->CocoaTransformWxToBounds(frameRect);
    [nsview setFrame: frameRect];
}

// Get total size
void wxWindow::DoGetSize(int *w, int *h) const
{
    NSRect cocoaRect = [GetNSViewForSuperview() frame];
    if(w)
        *w=(int)cocoaRect.size.width;
    if(h)
        *h=(int)cocoaRect.size.height;
    wxLogTrace(wxTRACE_COCOA_Window_Size,wxT("wxWindow=%p::DoGetSize = (%d,%d)"),this,(int)cocoaRect.size.width,(int)cocoaRect.size.height);
}

void wxWindow::DoGetPosition(int *x, int *y) const
{
    NSView *nsview = GetNSViewForSuperview();

    NSRect cocoaRect = [nsview frame];
    NSRect rectWx = GetParent()->CocoaTransformBoundsToWx(cocoaRect);
    if(x)
        *x=(int)rectWx.origin.x;
    if(y)
        *y=(int)rectWx.origin.y;
    wxLogTrace(wxTRACE_COCOA_Window_Size,wxT("wxWindow=%p::DoGetPosition = (%d,%d)"),this,(int)cocoaRect.origin.x,(int)cocoaRect.origin.y);
}

WXWidget wxWindow::GetHandle() const
{
    return m_cocoaNSView;
}

wxWindow* wxWindow::GetWxWindow() const
{
    return (wxWindow*) this;
}

void wxWindow::Refresh(bool eraseBack, const wxRect *rect)
{
    [m_cocoaNSView setNeedsDisplay:YES];
}

void wxWindow::SetFocus()
{
    if([GetNSView() acceptsFirstResponder])
        [[GetNSView() window] makeFirstResponder: GetNSView()];
}

void wxWindow::DoCaptureMouse()
{
    // TODO
    sm_capturedWindow = this;
}

void wxWindow::DoReleaseMouse()
{
    // TODO
    sm_capturedWindow = NULL;
}

void wxWindow::DoScreenToClient(int *x, int *y) const
{
    // Point in cocoa screen coordinates:
    NSPoint cocoaScreenPoint = OriginInCocoaScreenCoordinatesForRectInWxDisplayCoordinates(x!=NULL?*x:0, y!=NULL?*y:0, 0, 0, false);
    NSView *clientView = const_cast<wxWindow*>(this)->GetNSView();
    NSWindow *theWindow = [clientView window];

    // Point in window's base coordinate system:
    NSPoint windowPoint = [theWindow convertScreenToBase:cocoaScreenPoint];
    // Point in view's bounds coordinate system
    NSPoint boundsPoint = [clientView convertPoint:windowPoint fromView:nil];
    // Point in wx client coordinates:
    NSPoint theWxClientPoint = CocoaTransformNSViewBoundsToWx(clientView, boundsPoint);
    if(x!=NULL)
        *x = theWxClientPoint.x;
    if(y!=NULL)
        *y = theWxClientPoint.y;
}

void wxWindow::DoClientToScreen(int *x, int *y) const
{
    // Point in wx client coordinates
    NSPoint theWxClientPoint = NSMakePoint(x!=NULL?*x:0, y!=NULL?*y:0);

    NSView *clientView = const_cast<wxWindow*>(this)->GetNSView();

    // Point in the view's bounds coordinate system
    NSPoint boundsPoint = CocoaTransformNSViewWxToBounds(clientView, theWxClientPoint);

    // Point in the window's base coordinate system
    NSPoint windowPoint = [clientView convertPoint:boundsPoint toView:nil];

    NSWindow *theWindow = [clientView window];
    // Point in Cocoa's screen coordinates
    NSPoint screenPoint = [theWindow convertBaseToScreen:windowPoint];

    // Act as though this was the origin of a 0x0 rectangle
    NSRect screenPointRect = NSMakeRect(screenPoint.x, screenPoint.y, 0, 0);

    // Convert that rectangle to wx coordinates
    wxPoint theWxScreenPoint = OriginInWxDisplayCoordinatesForRectInCocoaScreenCoordinates(screenPointRect);
    if(*x)
        *x = theWxScreenPoint.x;
    if(*y)
        *y = theWxScreenPoint.y;
}

// Get size *available for subwindows* i.e. excluding menu bar etc.
void wxWindow::DoGetClientSize(int *x, int *y) const
{
    wxLogTrace(wxTRACE_COCOA,wxT("DoGetClientSize:"));
    if(m_wxCocoaScrollView)
        m_wxCocoaScrollView->DoGetClientSize(x,y);
    else
        wxWindowCocoa::DoGetSize(x,y);
}

void wxWindow::DoSetClientSize(int width, int height)
{
    wxLogTrace(wxTRACE_COCOA_Window_Size,wxT("DoSetClientSize=(%d,%d)"),width,height);
    if(m_wxCocoaScrollView)
        m_wxCocoaScrollView->ClientSizeToSize(width,height);
    CocoaSetWxWindowSize(width,height);
}

void wxWindow::CocoaSetWxWindowSize(int width, int height)
{
    wxWindowCocoa::DoSetSize(wxDefaultCoord,wxDefaultCoord,width,height,wxSIZE_USE_EXISTING);
}

void wxWindow::SetLabel(const wxString& WXUNUSED(label))
{
    // Intentional no-op.
}

wxString wxWindow::GetLabel() const
{
    // General Get/Set of labels is implemented in wxControlBase
    wxLogDebug(wxT("wxWindow::GetLabel: Should be overridden if needed."));
    return wxEmptyString;
}

int wxWindow::GetCharHeight() const
{
    // TODO
    return 10;
}

int wxWindow::GetCharWidth() const
{
    // TODO
    return 5;
}

void wxWindow::DoGetTextExtent(const wxString& string, int *outX, int *outY,
        int *outDescent, int *outExternalLeading, const wxFont *inFont) const
{
    // FIXME: This obviously ignores the window's font (if any) along with any size
    // transformations.  However, it's better than nothing.
    // We don't create a wxClientDC because we don't want to accidently be able to use
    // it for drawing.
    wxClientDC tmpdc(const_cast<wxWindow*>(this));
    return tmpdc.GetTextExtent(string, outX, outY, outDescent, outExternalLeading, inFont);
}

// Coordinates relative to the window
void wxWindow::WarpPointer (int x_pos, int y_pos)
{
    // TODO
}

int wxWindow::GetScrollPos(int orient) const
{
    if(m_wxCocoaScrollView != NULL)
        return m_wxCocoaScrollView->GetScrollPos(static_cast<wxOrientation>(orient & wxBOTH));
    else
        return 0;
}

// This now returns the whole range, not just the number
// of positions that we can scroll.
int wxWindow::GetScrollRange(int orient) const
{
    if(m_wxCocoaScrollView != NULL)
        return m_wxCocoaScrollView->GetScrollRange(static_cast<wxOrientation>(orient & wxBOTH));
    else
        return 0;
}

int wxWindow::GetScrollThumb(int orient) const
{
    if(m_wxCocoaScrollView != NULL)
        return m_wxCocoaScrollView->GetScrollThumb(static_cast<wxOrientation>(orient & wxBOTH));
    else
        return 0;
}

void wxWindow::SetScrollPos(int orient, int pos, bool refresh)
{
    if(m_wxCocoaScrollView != NULL)
        return m_wxCocoaScrollView->SetScrollPos(static_cast<wxOrientation>(orient & wxBOTH), pos);
}

void wxWindow::CocoaCreateNSScrollView()
{
    if(!m_wxCocoaScrollView)
    {
        m_wxCocoaScrollView = new wxWindowCocoaScrollView(this);
    }
}

// New function that will replace some of the above.
void wxWindow::SetScrollbar(int orient, int pos, int thumbVisible,
    int range, bool refresh)
{
    CocoaCreateNSScrollView();
    m_wxCocoaScrollView->SetScrollbar(orient, pos, thumbVisible, range);
    // TODO: Handle refresh (if we even need to)
}

// Does a physical scroll
void wxWindow::ScrollWindow(int dx, int dy, const wxRect *rect)
{
    if(m_wxCocoaScrollView != NULL)
        m_wxCocoaScrollView->ScrollWindow(dx, dy, rect);
}

void wxWindow::DoSetVirtualSize( int x, int y )
{
    // Call wxWindowBase method which will set m_virtualSize to the appropriate value,
    // possibly not what the caller passed in.  For example, the current implementation
    // clamps the width and height to within the min/max virtual ranges.
    // wxDefaultCoord is passed through unchanged but then GetVirtualSize() will correct
    // that by returning effectively max(virtual, client)
    wxWindowBase::DoSetVirtualSize(x,y);
    // Create the scroll view if it hasn't been already.
    CocoaCreateNSScrollView();

    // The GetVirtualSize automatically increases the size to max(client,virtual)
    m_wxCocoaScrollView->UpdateSizes();
}

bool wxWindow::SetFont(const wxFont& font)
{
    // FIXME: We may need to handle wx font inheritance.
    return wxWindowBase::SetFont(font);
}

#if 0 // these are used when debugging the algorithm.
static char const * const comparisonresultStrings[] =
{   "<"
,   "=="
,   ">"
};
#endif

class CocoaWindowCompareContext
{
    wxDECLARE_NO_COPY_CLASS(CocoaWindowCompareContext);
public:
    CocoaWindowCompareContext(); // Not implemented
    CocoaWindowCompareContext(NSView *target, NSArray *subviews)
    {
        m_target = target;
        // Cocoa sorts subviews in-place.. make a copy
        m_subviews = [subviews copy];
    }
    ~CocoaWindowCompareContext()
    {   // release the copy
        [m_subviews release];
    }
    NSView* target()
    {   return m_target; }
    NSArray* subviews()
    {   return m_subviews; }
    /* Helper function that returns the comparison based off of the original ordering */
    CocoaWindowCompareFunctionResult CompareUsingOriginalOrdering(id first, id second)
    {
        NSUInteger firstI = [m_subviews indexOfObjectIdenticalTo:first];
        NSUInteger secondI = [m_subviews indexOfObjectIdenticalTo:second];
        // NOTE: If either firstI or secondI is NSNotFound then it will be NSIntegerMax and thus will
        // likely compare higher than the other view which is reasonable considering the only way that
        // can happen is if the subview was added after our call to subviews but before the call to
        // sortSubviewsUsingFunction:context:.  Thus we don't bother checking.  Particularly because
        // that case should never occur anyway because that would imply a multi-threaded GUI call
        // which is a big no-no with Cocoa.

        // Subviews are ordered from back to front meaning one that is already lower will have an lower index.
        NSComparisonResult result = (firstI < secondI)
            ?   NSOrderedAscending /* -1 */
            :   (firstI > secondI)
                ?   NSOrderedDescending /* 1 */
                :   NSOrderedSame /* 0 */;

#if 0 // Enable this if you need to debug the algorithm.
        NSLog(@"%@ [%d] %s %@ [%d]\n", first, firstI, comparisonresultStrings[result+1], second, secondI);
#endif
        return result;
    }
private:
    /* The subview we are trying to Raise or Lower */
    NSView *m_target;
    /* A copy of the original array of subviews */
    NSArray *m_subviews;
};

/* Causes Cocoa to raise the target view to the top of the Z-Order by telling the sort function that
 * the target view is always higher than every other view.  When comparing two views neither of
 * which is the target, it returns the correct response based on the original ordering
 */
static CocoaWindowCompareFunctionResult CocoaRaiseWindowCompareFunction(id first, id second, void *ctx)
{
    CocoaWindowCompareContext *compareContext = (CocoaWindowCompareContext*)ctx;
    // first should be ordered higher
    if(first==compareContext->target())
        return NSOrderedDescending;
    // second should be ordered higher
    if(second==compareContext->target())
        return NSOrderedAscending;
    return compareContext->CompareUsingOriginalOrdering(first,second);
}

// Raise the window to the top of the Z order
void wxWindow::Raise()
{
//    wxAutoNSAutoreleasePool pool;
    NSView *nsview = GetNSViewForSuperview();
    NSView *superview = [nsview superview];
    CocoaWindowCompareContext compareContext(nsview, [superview subviews]);

    [superview sortSubviewsUsingFunction:
            CocoaRaiseWindowCompareFunction
        context: &compareContext];
}

/* Causes Cocoa to lower the target view to the bottom of the Z-Order by telling the sort function that
 * the target view is always lower than every other view.  When comparing two views neither of
 * which is the target, it returns the correct response based on the original ordering
 */
static CocoaWindowCompareFunctionResult CocoaLowerWindowCompareFunction(id first, id second, void *ctx)
{
    CocoaWindowCompareContext *compareContext = (CocoaWindowCompareContext*)ctx;
    // first should be ordered lower
    if(first==compareContext->target())
        return NSOrderedAscending;
    // second should be ordered lower
    if(second==compareContext->target())
        return NSOrderedDescending;
    return compareContext->CompareUsingOriginalOrdering(first,second);
}

// Lower the window to the bottom of the Z order
void wxWindow::Lower()
{
    NSView *nsview = GetNSViewForSuperview();
    NSView *superview = [nsview superview];
    CocoaWindowCompareContext compareContext(nsview, [superview subviews]);

#if 0
    NSLog(@"Target:\n%@\n", nsview);
    NSLog(@"Before:\n%@\n", compareContext.subviews());
#endif
    [superview sortSubviewsUsingFunction:
            CocoaLowerWindowCompareFunction
        context: &compareContext];
#if 0
    NSLog(@"After:\n%@\n", [superview subviews]);
#endif
}

bool wxWindow::DoPopupMenu(wxMenu *menu, int x, int y)
{
    return false;
}

// Get the window with the focus
wxWindow *wxWindowBase::DoFindFocus()
{
    // Basically we are somewhat emulating the responder chain here except
    // we are only loking for the first responder in the key window or
    // upon failing to find one if the main window is different we look
    // for the first responder in the main window.

    // Note that the firstResponder doesn't necessarily have to be an
    // NSView but wxCocoaNSView::GetFromCocoa() will simply return
    // NULL unless it finds its argument in its hash map.

    wxCocoaNSView *win;

    NSWindow *keyWindow = [[NSApplication sharedApplication] keyWindow];
    win = wxCocoaNSView::GetFromCocoa(static_cast<NSView*>([keyWindow firstResponder]));
    if(win)
        return win->GetWxWindow();

    NSWindow *mainWindow = [[NSApplication sharedApplication] keyWindow];
    if(mainWindow == keyWindow)
        return NULL;
    win = wxCocoaNSView::GetFromCocoa(static_cast<NSView*>([mainWindow firstResponder]));
    if(win)
        return win->GetWxWindow();

    return NULL;
}

/* static */ wxWindow *wxWindowBase::GetCapture()
{
    // TODO
    return wxWindowCocoa::sm_capturedWindow;
}

wxWindow *wxGetActiveWindow()
{
    // TODO
    return NULL;
}

wxPoint wxGetMousePosition()
{
    // TODO
    return wxDefaultPosition;
}

wxMouseState wxGetMouseState()
{
    wxMouseState ms;
    // TODO
    return ms;
}

wxWindow* wxFindWindowAtPointer(wxPoint& pt)
{
    pt = wxGetMousePosition();
    return NULL;
}

// ========================================================================
// wxCocoaMouseMovedEventSynthesizer
// ========================================================================

#define wxTRACE_COCOA_MouseMovedSynthesizer wxT("COCOA_MouseMovedSynthesizer")

/* This class registers one run loop observer to cover all windows registered with it.
 *  It will register the observer when the first view is registerd and unregister the
 * observer when the last view is unregistered.
 * It is instantiated as a static s_mouseMovedSynthesizer in this file although there
 * is no reason it couldn't be instantiated multiple times.
 */
class wxCocoaMouseMovedEventSynthesizer
{
    wxDECLARE_NO_COPY_CLASS(wxCocoaMouseMovedEventSynthesizer);
public:
    wxCocoaMouseMovedEventSynthesizer()
    {   m_lastScreenMouseLocation = NSZeroPoint;
    }
    ~wxCocoaMouseMovedEventSynthesizer();
    void RegisterWxCocoaView(wxCocoaNSView *aView);
    void UnregisterWxCocoaView(wxCocoaNSView *aView);
    void SynthesizeMouseMovedEvent();
    
protected:
    void AddRunLoopObserver();
    void RemoveRunLoopObserver();
    wxCFRef<CFRunLoopObserverRef> m_runLoopObserver;
    std::list<wxCocoaNSView*> m_registeredViews;
    NSPoint m_lastScreenMouseLocation;
    static void SynthesizeMouseMovedEvent(CFRunLoopObserverRef observer, CFRunLoopActivity activity, void *info);
};

void wxCocoaMouseMovedEventSynthesizer::RegisterWxCocoaView(wxCocoaNSView *aView)
{
    m_registeredViews.push_back(aView);
    wxLogTrace(wxTRACE_COCOA_MouseMovedSynthesizer, wxT("Registered wxCocoaNSView=%p"), aView);

    if(!m_registeredViews.empty() && m_runLoopObserver == NULL)
    {
        AddRunLoopObserver();
    }
}

void wxCocoaMouseMovedEventSynthesizer::UnregisterWxCocoaView(wxCocoaNSView *aView)
{
    m_registeredViews.remove(aView);
    wxLogTrace(wxTRACE_COCOA_MouseMovedSynthesizer, wxT("Unregistered wxCocoaNSView=%p"), aView);
    if(m_registeredViews.empty() && m_runLoopObserver != NULL)
    {
        RemoveRunLoopObserver();
    }
}

wxCocoaMouseMovedEventSynthesizer::~wxCocoaMouseMovedEventSynthesizer()
{
    if(!m_registeredViews.empty())
    {
        // This means failure to clean up so we report on it as a debug message.
        wxLogDebug(wxT("There are still %d wxCocoaNSView registered to receive mouse moved events at static destruction time"), m_registeredViews.size());
        m_registeredViews.clear();
    }
    if(m_runLoopObserver != NULL)
    {
        // This should not occur unless m_registeredViews was not empty since the last object unregistered should have done this.
        wxLogDebug(wxT("Removing run loop observer during static destruction time."));
        RemoveRunLoopObserver();
    }
}

void wxCocoaMouseMovedEventSynthesizer::SynthesizeMouseMovedEvent(CFRunLoopObserverRef observer, CFRunLoopActivity activity, void *info)
{
    reinterpret_cast<wxCocoaMouseMovedEventSynthesizer*>(info)->SynthesizeMouseMovedEvent();
}

void wxCocoaMouseMovedEventSynthesizer::AddRunLoopObserver()
{
    CFRunLoopObserverContext observerContext =
    {   0
    ,   this
    ,   NULL
    ,   NULL
    ,   NULL
    };

    // The kCFRunLoopExit observation point is used such that we hook the run loop after it has already decided that
    // it is going to exit which is generally for the purpose of letting the event loop process the next Cocoa event.

    // Executing our procedure within the run loop (e.g. kCFRunLoopBeforeWaiting which was used before) results
    // in our observer procedure being called before the run loop has decided that it is going to return control to
    // the Cocoa event loop.  One major problem is uncovered by the wxGenericHyperlinkCtrl (consider this to be "user
    // code") which changes the window's cursor and thus causes the cursor rectangle's to be invalidated.

    // Cocoa implements this invalidation using a delayed notification scheme whereby the resetCursorRects method
    // won't be called until the CFRunLoop gets around to it.  If the CFRunLoop has not yet exited then it will get
    // around to it before letting the event loop do its work.  This has some very odd effects on the way the
    // newly created tracking rects function.  In particular, we will often miss the mouseExited: message if the
    // user flicks the mouse quickly enough such that the mouse is already outside of the tracking rect by the
    // time the new one is built.

    // Observing from the kCFRunLoopExit point gives Cocoa's event loop an opportunity to chew some events before it cedes
    // control back to the CFRunLoop, thus causing the delayed notifications to fire at an appropriate time and
    // the mouseExited: message to be sent properly.

    m_runLoopObserver.reset(CFRunLoopObserverCreate(kCFAllocatorDefault, kCFRunLoopExit, TRUE, 0, SynthesizeMouseMovedEvent, &observerContext));
    CFRunLoopAddObserver([[NSRunLoop currentRunLoop] getCFRunLoop], m_runLoopObserver, kCFRunLoopCommonModes);
    wxLogTrace(wxTRACE_COCOA_TrackingRect, wxT("Added tracking rect run loop observer"));
}

void wxCocoaMouseMovedEventSynthesizer::RemoveRunLoopObserver()
{
    CFRunLoopRemoveObserver([[NSRunLoop currentRunLoop] getCFRunLoop], m_runLoopObserver, kCFRunLoopCommonModes);
    m_runLoopObserver.reset();
    wxLogTrace(wxTRACE_COCOA_TrackingRect, wxT("Removed tracking rect run loop observer"));
}

void wxCocoaMouseMovedEventSynthesizer::SynthesizeMouseMovedEvent()
{
    NSPoint screenMouseLocation = [NSEvent mouseLocation];
    // Checking the last mouse location is done for a few reasons:
    // 1. We are observing every iteration of the event loop so we'd be sending out a lot of extraneous events
    //    telling the app the mouse moved when the user hit a key for instance.
    // 2. When handling the mouse moved event, user code can do something to the view which will cause Cocoa to
    //    call resetCursorRects.  Cocoa does this by using a delayed notification which means the event loop gets
    //    pumped once which would mean that if we didn't check the mouse location we'd get into a never-ending
    //    loop causing the tracking rectangles to constantly be reset.
    if(screenMouseLocation.x != m_lastScreenMouseLocation.x || screenMouseLocation.y != m_lastScreenMouseLocation.y)
    {
        m_lastScreenMouseLocation = screenMouseLocation;
        wxLogTrace(wxTRACE_COCOA_TrackingRect, wxT("Synthesizing mouse moved at screen (%f,%f)"), screenMouseLocation.x, screenMouseLocation.y);
        for(std::list<wxCocoaNSView*>::iterator i = m_registeredViews.begin(); i != m_registeredViews.end(); ++i)
        {
            (*i)->Cocoa_synthesizeMouseMoved();
        }
    }
}

// Singleton used for all views:
static wxCocoaMouseMovedEventSynthesizer s_mouseMovedSynthesizer;

// ========================================================================
// wxCocoaTrackingRectManager
// ========================================================================

wxCocoaTrackingRectManager::wxCocoaTrackingRectManager(wxWindow *window)
:   m_window(window)
{
    m_isTrackingRectActive = false;
    BuildTrackingRect();
}

void wxCocoaTrackingRectManager::ClearTrackingRect()
{
    if(m_isTrackingRectActive)
    {
        [m_window->GetNSView() removeTrackingRect:m_trackingRectTag];
        m_isTrackingRectActive = false;
        wxLogTrace(wxTRACE_COCOA_TrackingRect, wxT("%s@%p: Removed tracking rect #%d"), m_window->GetClassInfo()->GetClassName(), m_window, m_trackingRectTag);
    }
    // If we were doing periodic events we need to clear those too
    StopSynthesizingEvents();
}

void wxCocoaTrackingRectManager::StopSynthesizingEvents()
{
    s_mouseMovedSynthesizer.UnregisterWxCocoaView(m_window);
}

void wxCocoaTrackingRectManager::BuildTrackingRect()
{
    // Pool here due to lack of one during wx init phase
    wxAutoNSAutoreleasePool pool;

    wxASSERT_MSG(!m_isTrackingRectActive, wxT("Tracking rect was not cleared"));

    NSView *theView = m_window->GetNSView();

    if([theView window] != nil)
    {
        NSRect visibleRect = [theView visibleRect];

        m_trackingRectTag = [theView addTrackingRect:visibleRect owner:theView userData:NULL assumeInside:NO];
        m_trackingRectInWindowCoordinates = [theView convertRect:visibleRect toView:nil];
        m_isTrackingRectActive = true;

        wxLogTrace(wxTRACE_COCOA_TrackingRect, wxT("%s@%p: Added tracking rect #%d"), m_window->GetClassInfo()->GetClassName(), m_window, m_trackingRectTag);
    }
}

void wxCocoaTrackingRectManager::BeginSynthesizingEvents()
{
    s_mouseMovedSynthesizer.RegisterWxCocoaView(m_window);
}

void wxCocoaTrackingRectManager::RebuildTrackingRectIfNeeded()
{
    if(m_isTrackingRectActive)
    {
        NSView *theView = m_window->GetNSView();
        NSRect currentRect = [theView convertRect:[theView visibleRect] toView:nil];
        if(NSEqualRects(m_trackingRectInWindowCoordinates,currentRect))
        {
            wxLogTrace(wxTRACE_COCOA_TrackingRect, wxT("Ignored request to rebuild TR#%d"), m_trackingRectTag);
            return;
        }
    }
    RebuildTrackingRect();
}

void wxCocoaTrackingRectManager::RebuildTrackingRect()
{
    ClearTrackingRect();
    BuildTrackingRect();
}

wxCocoaTrackingRectManager::~wxCocoaTrackingRectManager()
{
    ClearTrackingRect();
}

bool wxCocoaTrackingRectManager::IsOwnerOfEvent(NSEvent *anEvent)
{
    return m_isTrackingRectActive && (m_trackingRectTag == [anEvent trackingNumber]);
}

