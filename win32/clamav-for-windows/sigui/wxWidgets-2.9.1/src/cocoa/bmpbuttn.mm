/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/bmpbuttn.mm
// Purpose:     wxBitmapButton
// Author:      David Elliott
// Modified by:
// Created:     2003/03/16
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_BMPBUTTON

#include "wx/bmpbuttn.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
#endif

#include "wx/cocoa/autorelease.h"

#import <AppKit/NSButton.h>
#import <Foundation/NSString.h>

IMPLEMENT_DYNAMIC_CLASS(wxBitmapButton, wxControl)
BEGIN_EVENT_TABLE(wxBitmapButton, wxBitmapButtonBase)
END_EVENT_TABLE()
WX_IMPLEMENT_COCOA_OWNER(wxBitmapButton,NSButton,NSControl,NSView)

bool wxBitmapButton::Create(wxWindow *parent, wxWindowID winid,
            const wxBitmap& bitmap, const wxPoint& pos,
            const wxSize& size, long style,
            const wxValidator& validator, const wxString& name)
{
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

    [GetNSButton() setBezelStyle: NSRegularSquareBezelStyle];
    [GetNSButton() setImage:bitmap.GetNSImage(true)];
    [GetNSControl() sizeToFit];

    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    return true;
}

wxBitmapButton::~wxBitmapButton()
{
    DisassociateNSButton(GetNSButton());
}

void wxBitmapButton::Cocoa_wxNSButtonAction(void)
{
    wxLogTrace(wxTRACE_COCOA,wxT("YAY!"));
    wxCommandEvent event(wxEVT_COMMAND_BUTTON_CLICKED, GetId());
    InitCommandEvent(event); //    event.SetEventObject(this);
    Command(event);
}

#endif
