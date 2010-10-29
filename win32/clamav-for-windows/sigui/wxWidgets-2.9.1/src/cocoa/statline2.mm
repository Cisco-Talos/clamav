/////////////////////////////////////////////////////////////////////////////
// Name:        cocoa/statline.mm
// Purpose:     wxStaticLine
// Author:      David Elliott
// Modified by:
// Created:     2003/02/15
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"
#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif //WX_PRECOMP
#include "wx/statline.h"

#include "wx/cocoa/autorelease.h"

#import <AppKit/NSBox.h>

IMPLEMENT_DYNAMIC_CLASS(wxStaticLine, wxControl)
BEGIN_EVENT_TABLE(wxStaticLine, wxStaticLineBase)
END_EVENT_TABLE()
// WX_IMPLEMENT_COCOA_OWNER(wxStaticLine,NSTextField,NSControl,NSView)

bool wxStaticLine::Create(wxWindow *parent, wxWindowID winid,
           const wxPoint& pos,
           const wxSize& size,
           long style,
           const wxString& name)
{
    wxAutoNSAutoreleasePool pool;
    if(!CreateControl(parent,winid,pos,size,style,wxDefaultValidator,name))
        return false;
    SetNSView([[NSBox alloc] initWithFrame: MakeDefaultNSRect(size)]);
    [m_cocoaNSView release];
    [(NSBox*)m_cocoaNSView setBoxType: NSBoxSeparator];
    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    return true;
}

wxStaticLine::~wxStaticLine()
{
}

