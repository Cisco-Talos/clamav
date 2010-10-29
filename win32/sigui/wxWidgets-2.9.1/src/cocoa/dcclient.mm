/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/dcclient.mm
// Purpose:     wxWindowDCImpl, wxPaintDCImpl, and wxClientDCImpl classes
// Author:      David Elliott
// Modified by:
// Created:     2003/04/01
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:   	wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"
#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/window.h"
#endif //WX_PRECOMP

#include "wx/cocoa/dcclient.h"

#import <AppKit/NSView.h>
#import <AppKit/NSAffineTransform.h>
#import <AppKit/NSColor.h>
#import <AppKit/NSGraphicsContext.h>
#import <AppKit/NSBezierPath.h>
#import <AppKit/NSWindow.h>

/*
 * wxWindowDCImpl
 */
IMPLEMENT_ABSTRACT_CLASS(wxWindowDCImpl, wxCocoaDCImpl)

wxWindowDCImpl::wxWindowDCImpl(wxDC *owner)
:   wxCocoaDCImpl(owner)
,   m_window(NULL)
,   m_lockedNSView(NULL)
{
};

wxWindowDCImpl::wxWindowDCImpl(wxDC *owner, wxWindow *window)
:   wxCocoaDCImpl(owner)
,   m_window(window)
,   m_lockedNSView(NULL)
{
    wxLogDebug(wxT("non-client window DC's are not supported, oh well"));
};

wxWindowDCImpl::~wxWindowDCImpl(void)
{
    CocoaUnwindStackAndLoseFocus();
};

bool wxWindowDCImpl::CocoaLockFocusOnNSView(WX_NSView nsview)
{
    if([nsview lockFocusIfCanDraw])
    {
        sm_cocoaDCStack.Insert(this);
        CocoaApplyTransformations();
        m_lockedNSView = nsview;
        return true;
    }
    wxLogDebug(wxT("focus lock failed!"));
    return false;
}

bool wxWindowDCImpl::CocoaUnlockFocusOnNSView()
{
    [[m_lockedNSView window] flushWindow];
    [m_lockedNSView unlockFocus];
    m_lockedNSView = NULL;
    return true;
}

bool wxWindowDCImpl::CocoaLockFocus()
{
    wxLogTrace(wxTRACE_COCOA,wxT("Locking focus on wxWindowDCImpl=%p, NSView=%p"),this, m_window->GetNonClientNSView());
    NSAffineTransform *newTransform = CocoaGetWxToBoundsTransform([m_window->GetNonClientNSView() isFlipped], [m_window->GetNonClientNSView() bounds].size.height);
    [newTransform retain];
    [m_cocoaWxToBoundsTransform release];
    m_cocoaWxToBoundsTransform = newTransform;
    return CocoaLockFocusOnNSView(m_window->GetNonClientNSView());
}

bool wxWindowDCImpl::CocoaUnlockFocus()
{
    wxLogTrace(wxTRACE_COCOA,wxT("Unlocking focus on wxWindowDCImpl=%p, NSView=%p"),this, m_window->GetNonClientNSView());
    return CocoaUnlockFocusOnNSView();
}

bool wxWindowDCImpl::CocoaGetBounds(void *rectData)
{
    if(!rectData)
        return false;
    if(!m_lockedNSView)
        return false;
    NSRect *pRect = (NSRect*)rectData;
    *pRect = [m_lockedNSView bounds];
    return true;
}

/*
 * wxClientDCImpl
 */
IMPLEMENT_ABSTRACT_CLASS(wxClientDCImpl, wxWindowDCImpl)

wxClientDCImpl::wxClientDCImpl(wxDC *owner)
:   wxWindowDCImpl(owner)
{
};

wxClientDCImpl::wxClientDCImpl(wxDC *owner, wxWindow *window)
:   wxWindowDCImpl(owner)
{
    m_window = window;
};

wxClientDCImpl::~wxClientDCImpl(void)
{
    CocoaUnwindStackAndLoseFocus();
};

bool wxClientDCImpl::CocoaLockFocus()
{
    wxLogTrace(wxTRACE_COCOA,wxT("Locking focus on wxClientDCImpl=%p, NSView=%p"),this, m_window->GetNSView());
    NSAffineTransform *newTransform = m_window->CocoaGetWxToBoundsTransform();
    [newTransform retain];
    [m_cocoaWxToBoundsTransform release];
    m_cocoaWxToBoundsTransform = newTransform;
    return CocoaLockFocusOnNSView(m_window->GetNSView());
}

bool wxClientDCImpl::CocoaUnlockFocus()
{
    wxLogTrace(wxTRACE_COCOA,wxT("Unlocking focus on wxClientDCImpl=%p, NSView=%p"),this, m_window->GetNSView());
    return CocoaUnlockFocusOnNSView();
}

/*
 * wxPaintDCImpl
 */
IMPLEMENT_ABSTRACT_CLASS(wxPaintDCImpl, wxWindowDCImpl)

wxPaintDCImpl::wxPaintDCImpl(wxDC *owner)
:   wxWindowDCImpl(owner)
{
};

wxPaintDCImpl::wxPaintDCImpl(wxDC *owner, wxWindow *window)
:   wxWindowDCImpl(owner)
{
    m_window = window;
    wxASSERT_MSG([NSView focusView]==window->GetNSView(), wxT("PaintDC's NSView does not have focus.  Please use wxPaintDCImpl only as the first DC created in a paint handler"));
    sm_cocoaDCStack.Insert(this);
    m_lockedNSView = window->GetNSView();
    NSAffineTransform *newTransform = window->CocoaGetWxToBoundsTransform();
    [newTransform retain];
    [m_cocoaWxToBoundsTransform release];
    m_cocoaWxToBoundsTransform = newTransform;
    CocoaApplyTransformations();
};

wxPaintDCImpl::~wxPaintDCImpl(void)
{
    CocoaUnwindStackAndLoseFocus();
};

bool wxPaintDCImpl::CocoaLockFocus()
{
    wxFAIL_MSG(wxT("wxPaintDCImpl cannot be asked to lock focus!"));
    return false;
}

bool wxPaintDCImpl::CocoaUnlockFocus()
{
    // wxPaintDCImpl focus can never be unlocked.
    return false;
}

