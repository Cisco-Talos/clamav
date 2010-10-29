/////////////////////////////////////////////////////////////////////////////
// Name:        cocoa/spinbutt.mm
// Purpose:     wxSpinButton
// Author:      David Elliott
// Modified by:
// Created:     2003/07/14
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:   	wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"
#if wxUSE_SPINBTN

#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif //WX_PRECOMP
#include "wx/spinbutt.h"

#import <AppKit/NSStepper.h>

IMPLEMENT_DYNAMIC_CLASS(wxSpinEvent, wxNotifyEvent)

IMPLEMENT_DYNAMIC_CLASS(wxSpinButton, wxControl)
BEGIN_EVENT_TABLE(wxSpinButton, wxSpinButtonBase)
END_EVENT_TABLE()
// WX_IMPLEMENT_COCOA_OWNER(wxSpinButton,NSStepper,NSControl,NSView)

bool wxSpinButton::Create(wxWindow *parent, wxWindowID winid,
            const wxPoint& pos, const wxSize& size, long style,
            const wxString& name)
{
    //bad flag checking
    wxASSERT_MSG( !(style & wxSP_HORIZONTAL), wxT("Horizontal wxSpinButton not supported in cocoa"));
    if(!CreateControl(parent,winid,pos,size,style,wxDefaultValidator,name))
        return false;
    SetNSControl([[NSStepper alloc] initWithFrame: MakeDefaultNSRect(size)]);
    [m_cocoaNSView release];
    
    //flag handling
    [(NSStepper*)m_cocoaNSView setValueWraps:style & wxSP_WRAP]; //default == true, evidently
    
    //final setup
    [(NSStepper*)m_cocoaNSView setTarget: sm_cocoaTarget];
    [(NSStepper*)m_cocoaNSView setAction:@selector(wxNSControlAction:)];
    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    return true;
}

wxSpinButton::~wxSpinButton()
{
    [(NSStepper*)m_cocoaNSView setTarget: nil];
    [(NSStepper*)m_cocoaNSView setAction: nil];
}

int wxSpinButton::GetValue() const
{
    return [(NSStepper*)m_cocoaNSView intValue];
}

void wxSpinButton::SetValue(int value)
{
    [(NSStepper*)m_cocoaNSView setIntValue:value];
}

void wxSpinButton::SetRange(int minValue, int maxValue)
{
    [(NSStepper*)m_cocoaNSView setMinValue:minValue];
    [(NSStepper*)m_cocoaNSView setMaxValue:maxValue];
    wxSpinButtonBase::SetRange(minValue,maxValue);
}

void wxSpinButton::CocoaTarget_action()
{
    /* TODO: up/down events */
    /* This sends the changed event (not specific on up or down) */
    wxSpinEvent event(wxEVT_SCROLL_THUMBTRACK, GetId());
    event.SetPosition(GetValue());
    event.SetEventObject(this);
    HandleWindowEvent(event);
}

#endif // wxUSE_SPINBTN
