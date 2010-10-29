/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/control.mm
// Purpose:     wxControl class
// Author:      David Elliiott
// Modified by:
// Created:     2003/02/15
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#include "wx/control.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
#endif

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"
#include "wx/cocoa/trackingrectmanager.h"
#include "wx/cocoa/objc/objc_uniquifying.h"
#include "wx/cocoa/objc/NSView.h"

#import <AppKit/NSControl.h>
#import <AppKit/NSCell.h>
#import <Foundation/NSException.h>

#include <math.h>

IMPLEMENT_ABSTRACT_CLASS(wxControl, wxWindow)
BEGIN_EVENT_TABLE(wxControl, wxControlBase)
END_EVENT_TABLE()
WX_IMPLEMENT_COCOA_OWNER(wxControl,NSControl,NSView,NSView)

bool wxControl::Create(wxWindow *parent, wxWindowID winid,
            const wxPoint& pos, const wxSize& size, long style,
            const wxValidator& validator, const wxString& name)
{
    wxLogTrace(wxTRACE_COCOA,wxT("Creating control with id=%d"),winid);
    if(!CreateControl(parent,winid,pos,size,style,validator,name))
        return false;
    wxLogTrace(wxTRACE_COCOA,wxT("Created control with id=%d"),GetId());
    m_cocoaNSView = NULL;
    SetNSControl([[WX_GET_OBJC_CLASS(WXNSView) alloc] initWithFrame: MakeDefaultNSRect(size)]);
    // NOTE: YES we want to release this (to match the alloc).
    // DoAddChild(this) will retain us again since addSubView doesn't.
    [m_cocoaNSView release];

    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    // Controls should have a viewable-area tracking rect by default
    m_visibleTrackingRectManager = new wxCocoaTrackingRectManager(this);

    return true;
}

wxControl::~wxControl()
{
    DisassociateNSControl(GetNSControl());
}

wxSize wxControl::DoGetBestSize() const
{
    wxAutoNSAutoreleasePool pool;
    wxASSERT(GetNSControl());
    /* We can ask single-celled controls for their cell and get its size */
    NSCell *cell = nil;
    if([GetNSControl() respondsToSelector:@selector(cell)])
        cell = [GetNSControl() cell];
    if(cell)
    {
        NSSize cellSize = [cell cellSize];
        wxSize size((int)ceil(cellSize.width),(int)ceil(cellSize.height));
        wxLogTrace(wxTRACE_COCOA_Window_Size,wxT("wxControl=%p::DoGetBestSize()==(%d,%d) from NSCell"),this,size.x,size.y);
        return size;
    }

    /* multi-celled control? size to fit, get the size, then set it back */
    if([GetNSControl() respondsToSelector:@selector(sizeToFit)])
    {
        NSRect storedRect = [m_cocoaNSView frame];
        [GetNSControl() sizeToFit];
        NSRect cocoaRect = [m_cocoaNSView frame];
        wxSize size((int)ceil(cocoaRect.size.width),(int)ceil(cocoaRect.size.height));
        [m_cocoaNSView setFrame: storedRect];
        wxLogTrace(wxTRACE_COCOA_Window_Size,wxT("wxControl=%p::DoGetBestSize()==(%d,%d) from sizeToFit"),this,size.x,size.y);
        return size;
    }
    // Cocoa can't tell us the size, probably not an NSControl.
    wxLogDebug(wxT("Class %s (or superclass still below wxControl) should implement DoGetBestSize()"),GetClassInfo()->GetClassName());
    return wxControlBase::DoGetBestSize();
}

bool wxControl::ProcessCommand(wxCommandEvent& event)
{
    return HandleWindowEvent(event);
}

void wxControl::CocoaSetEnabled(bool enable)
{
    if([GetNSControl() respondsToSelector:@selector(setEnabled:)])
        [GetNSControl() setEnabled: enable];
}

/*static*/ void wxControl::CocoaSetLabelForObject(const wxString& label, struct objc_object *aView)
{
    [aView setTitle:wxNSStringWithWxString(GetLabelText(label))];
}

