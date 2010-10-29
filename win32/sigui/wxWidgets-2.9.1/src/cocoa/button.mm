/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/button.mm
// Purpose:     wxButton
// Author:      David Elliott
// Modified by:
// Created:     2002/12/30
// RCS-ID:      $Id$
// Copyright:   (c) 2002 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#include "wx/button.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
#endif

#include "wx/stockitem.h"
#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"

#import <AppKit/NSButton.h>
#import <math.h>

IMPLEMENT_DYNAMIC_CLASS(wxButton, wxControl)
BEGIN_EVENT_TABLE(wxButton, wxButtonBase)
END_EVENT_TABLE()
WX_IMPLEMENT_COCOA_OWNER(wxButton,NSButton,NSControl,NSView)

bool wxButton::Create(wxWindow *parent, wxWindowID winid,
            const wxString& lbl, const wxPoint& pos,
            const wxSize& size, long style,
            const wxValidator& validator, const wxString& name)
{
    wxString label((lbl.empty() && wxIsStockID(winid))?wxGetStockLabel(winid):lbl);

    wxAutoNSAutoreleasePool pool;
    wxLogTrace(wxTRACE_COCOA,wxT("Creating control with id=%d"),winid);
    if(!CreateControl(parent,winid,pos,size,style,validator,name))
        return false;
    wxLogTrace(wxTRACE_COCOA,wxT("Created control with id=%d"),GetId());
    m_cocoaNSView = NULL;
    SetNSButton([[NSButton alloc] initWithFrame: MakeDefaultNSRect(size)]);
    // NOTE: YES we want to release this (to match the alloc).
    // DoAddChild(this) will retain us again since addSubView doesn't.
    [m_cocoaNSView release];

    [GetNSButton() setBezelStyle:NSRoundedBezelStyle];
    CocoaSetLabelForObject(label, GetNSButton());

    do
    {
        NSTextAlignment mode;
        if ((style & wxBU_LEFT) && !(style & wxBU_RIGHT))
            mode = NSLeftTextAlignment;
        else if ((style & wxBU_RIGHT) && !(style & wxBU_LEFT))
            mode = NSRightTextAlignment;
        else
            break;
        [GetNSControl() setAlignment:mode];
    } while(0);

    [GetNSControl() sizeToFit];

    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    return true;
}

wxButton::~wxButton()
{
    DisassociateNSButton(GetNSButton());
}

void wxButton::Cocoa_wxNSButtonAction(void)
{
    wxLogTrace(wxTRACE_COCOA,wxT("YAY!"));
    wxCommandEvent event(wxEVT_COMMAND_BUTTON_CLICKED, GetId());
    InitCommandEvent(event); //    event.SetEventObject(this);
    Command(event);
}

wxString wxButton::GetLabel() const
{
    return wxStringWithNSString([GetNSButton() title]);
}

void wxButton::SetLabel(const wxString& label)
{
    CocoaSetLabelForObject(label, GetNSButton());
}

wxSize wxButton::DoGetBestSize() const
{
    wxSize size = wxButtonBase::DoGetBestSize();
    if(!HasFlag(wxBU_EXACTFIT))
    {
        if(size.x<68)
            size.x = 68;
    }
    return size;
}

static NSRect MakeNSButtonDefaultRect()
{
    // create at (10.0,10.0) with size 20.0x20.0 (just bogus values)
    wxObjcAutoRefFromAlloc<NSButton*> defaultButton = [[NSButton alloc]
            initWithFrame:NSMakeRect(10.0,10.0,20.0,20.0)];
    [static_cast<NSButton*>(defaultButton) setBezelStyle:NSRoundedBezelStyle];
    [static_cast<NSButton*>(defaultButton) setTitle:@""];
    [static_cast<NSButton*>(defaultButton) sizeToFit];
    return [static_cast<NSButton*>(defaultButton) frame];
}

wxSize wxButtonBase::GetDefaultSize()
{
    static NSRect cocoaRect = MakeNSButtonDefaultRect();
    // Apple HIG says OK/Cancel buttons have default width of 68.
    return wxSize(68,(int)ceil(cocoaRect.size.height));
}
