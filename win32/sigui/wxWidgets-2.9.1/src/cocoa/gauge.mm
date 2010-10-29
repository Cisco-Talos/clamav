/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/gauge.mm
// Purpose:     wxGauge
// Author:      David Elliott
// Modified by:
// Created:     2003/07/15
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_GAUGE

#include "wx/gauge.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/log.h"
#endif //WX_PRECOMP

#include "wx/cocoa/autorelease.h"

#import <AppKit/NSProgressIndicator.h>
#import <Foundation/NSException.h>

#include <math.h>

IMPLEMENT_DYNAMIC_CLASS(wxGauge, wxControl)

BEGIN_EVENT_TABLE(wxGauge, wxGaugeBase)
END_EVENT_TABLE()
// WX_IMPLEMENT_COCOA_OWNER(wxGauge,NSProgressIndicator,NSView,NSView)

bool wxGauge::Create(wxWindow *parent, wxWindowID winid, int range,
            const wxPoint& pos, const wxSize& size, long style,
            const wxValidator& validator, const wxString& name)
{
    // NOTE: wxGA_SMOOTH flag is simply ignored (gauges are ALWAYS smooth)
    if(!CreateControl(parent,winid,pos,size,style,validator,name))
        return false;
    SetNSView([[NSProgressIndicator alloc] initWithFrame: MakeDefaultNSRect(size)]);
    [m_cocoaNSView release];

    // TODO: DoGetBestSize is likely totally wrong for vertical gauges but
    // this actually makes the widgets sample work so it's better than nothing.
    if(style & wxGA_VERTICAL)
    {
        wxLogDebug(wxT("wxGA_VERTICAL may not work correctly.  See src/cocoa/gauge.mm"));
        [m_cocoaNSView setBoundsRotation:-90.0];
    }

    [(NSProgressIndicator*)m_cocoaNSView setMaxValue:range];
    [(NSProgressIndicator*)m_cocoaNSView setIndeterminate:NO];

    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    return true;
}

wxGauge::~wxGauge()
{
}

int wxGauge::GetValue() const
{
    return (int)[(NSProgressIndicator*)m_cocoaNSView doubleValue];
}

void wxGauge::SetValue(int value)
{
    [(NSProgressIndicator*)m_cocoaNSView setDoubleValue:value];
}

int wxGauge::GetRange() const
{
    return (int)[(NSProgressIndicator*)m_cocoaNSView maxValue];
}

void wxGauge::SetRange(int maxValue)
{
    [(NSProgressIndicator*)m_cocoaNSView setMinValue:0.0];
    [(NSProgressIndicator*)m_cocoaNSView setMaxValue:maxValue];
}

// NSProgressIndicator is not an NSControl but does respond to
// sizeToFit on OS X >= 10.2
wxSize wxGauge::DoGetBestSize() const
{
    wxAutoNSAutoreleasePool pool;
    wxASSERT(GetNSProgressIndicator());
    NSRect storedRect = [m_cocoaNSView frame];
    bool didFit = false;
NS_DURING
    [GetNSProgressIndicator() sizeToFit];
    didFit = true;
NS_HANDLER
    // TODO: if anything other than method not implemented, re-raise
NS_ENDHANDLER
    if(didFit)
    {
        NSRect cocoaRect = [m_cocoaNSView frame];
        wxSize size((int)ceil(cocoaRect.size.width),(int)ceil(cocoaRect.size.height));
        [m_cocoaNSView setFrame: storedRect];
        wxLogTrace(wxTRACE_COCOA_Window_Size,wxT("wxControl=%p::DoGetBestSize()==(%d,%d) from sizeToFit"),this,size.x,size.y);
        return /*wxConstCast(this, wxControl)->m_bestSize =*/ size;
    }
    // Cocoa can't tell us the size
    float height = NSProgressIndicatorPreferredAquaThickness;
    return wxSize((int)(height*2),(int)height);
}

#endif // wxUSE_GAUGE
