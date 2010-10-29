/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/tooltip.mm
// Purpose:     Cocoa tooltips
// Author:      Ryan Norton
// Modified by:
// Created:     2004-10-03
// RCS-ID:      $Id$
// Copyright:   (c) Ryan Norton
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

// ===========================================================================
// declarations
// ===========================================================================

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

#if wxUSE_TOOLTIPS

#ifndef WX_PRECOMP
    #include "wx/window.h"
#endif

#include "wx/tooltip.h"

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"

#import <AppKit/NSView.h>

//
// Private object in AppKit - exists in 10.2 at least -
// most likely exists earlier too
//
@interface NSToolTipManager : NSObject
{
/*
    NSWindow *toolTipWindow;
    NSMutableArray *toolTips;
    double toolTipDelay;
    NSDate *timeToolTipRemovedFromScreen;
    struct __CFRunLoopTimer *toolTipDisplayTimer;
    NSToolTip *currentDisplayedToolTip;
    NSToolTip *currentFadingToolTip;
    float currentFadeValue;
    NSTimer *fadeTimer;
    NSWindow *lastToolTipWindow;
*/
}

+ (id)sharedToolTipManager;
- (int)_addTrackingRect:(struct _NSRect)fp12 andStartToolTipIfNecessary:(BOOL)fp28 view:(id)fp32 owner:(id)fp32 toolTip:(id)fp36;
- (void)_checkToolTipDelay;
- (void)_removeToolTip:(id)fp12 stopTimerIfNecessary:(BOOL)fp16;
- (void)_removeTrackingRectForToolTip:(id)fp12 stopTimerIfNecessary:(BOOL)fp16;
- (int)_setToolTip:(id)fp12 forView:(id)fp16 cell:(id)fp20 rect:(struct _NSRect)fp20 owner:(id)fp36 ownerIsDisplayDelegate:(BOOL)fp43 userData:(void *)fp44;
- (void)_stopTimerIfRunningForToolTip:(id)fp12;
- (void)abortToolTip;
- (void)addTrackingRectForToolTip:(id)fp12;
- (void)dealloc;
- (void)displayToolTip:(id)fp12;
- (void)fadeToolTip:(id)fp12;
- (id)init;
- (void)mouseEntered:(id)fp12;
- (void)mouseEnteredToolTip:(id)fp12 inWindow:(id)fp16 withEvent:(id)fp20;
- (void)mouseExited:(id)fp12;
- (void)orderOutToolTip;
- (void)orderOutToolTipImmediately:(BOOL)fp12;
- (void)recomputeToolTipsForView:(id)fp12 remove:(BOOL)fp16 add:(BOOL)fp20;
- (void)removeAllToolTipsForView:(id)fp12;
- (void)removeToolTipForView:(id)fp12 tag:(int)fp16;
- (void)setInitialToolTipDelay:(double)fp40;
- (void)setToolTip:(id)fp12 forView:(id)fp16 cell:(id)fp20;
- (int)setToolTipForView:(id)fp12 rect:(struct _NSRect)fp16 displayDelegate:(id)fp32 userData:(void *)fp32;
- (int)setToolTipForView:(id)fp12 rect:(struct _NSRect)fp16 owner:(id)fp32 userData:(void *)fp32;
- (void)setToolTipWithOwner:(id)fp12 forView:(id)fp16 cell:(id)fp20;
- (void)startTimer:(float)fp40 userInfo:(id)fp16;
- (void)stopTimer;
- (id)toolTipForView:(id)fp12 cell:(id)fp16;
- (BOOL)viewHasToolTips:(id)fp12;

@end

//-----------------------------------------------------------------------------
// wxToolTip
//-----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxToolTip, wxObject)

wxToolTip::wxToolTip(const wxString &tip) :
    m_text(tip), m_window(0)
{
}

wxToolTip::~wxToolTip()
{
}

void wxToolTip::SetTip(const wxString& tip)
{
    m_text = tip;
}

const wxString& wxToolTip::GetTip() const
{
    return m_text;
}

// the window we're associated with
wxWindow *wxToolTip::GetWindow() const
{
    return m_window;
}

// enable or disable the tooltips globally
//static
    void wxToolTip::Enable(bool flag)
{
    //TODO
    wxFAIL_MSG(wxT("Not implemented"));
}

// set the delay after which the tooltip appears
//static
    void wxToolTip::SetDelay(long milliseconds)
{
    [[NSToolTipManager sharedToolTipManager] setInitialToolTipDelay: ((double)milliseconds) / 1000.0];
}

void wxToolTip::SetWindow(wxWindow* window)
{
    wxAutoNSAutoreleasePool pool;

    m_window = window;

    //set the tooltip - empty string means remove
    if (m_text.empty())
        [m_window->GetNSView() setToolTip:nil];
    else
        [m_window->GetNSView() setToolTip:wxNSStringWithWxString(m_text)];
}

#endif //wxUSE_TOOLTIPS
