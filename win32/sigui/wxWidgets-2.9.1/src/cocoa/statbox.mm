/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/statbox.mm
// Purpose:     wxStaticBox
// Author:      David Elliott
// Modified by:
// Created:     2003/02/15
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#include "wx/statbox.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif //WX_PRECOMP

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"

#import <AppKit/NSBox.h>
#import <Foundation/NSString.h>

IMPLEMENT_DYNAMIC_CLASS(wxStaticBox, wxControl)
BEGIN_EVENT_TABLE(wxStaticBox, wxStaticBoxBase)
END_EVENT_TABLE()
WX_IMPLEMENT_COCOA_OWNER(wxStaticBox,NSBox,NSView,NSView)

bool wxStaticBox::Create(wxWindow *parent, wxWindowID winid,
           const wxString& title, const wxPoint& pos, const wxSize& size,
           long style, const wxString& name)
{
    wxAutoNSAutoreleasePool pool;
    if(!CreateControl(parent,winid,pos,size,style,wxDefaultValidator,name))
        return false;
    m_cocoaNSView = NULL;
    SetNSBox([[NSBox alloc] initWithFrame:MakeDefaultNSRect(size)]);
    CocoaSetLabelForObject(title, GetNSBox());
    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    return true;
}

wxStaticBox::~wxStaticBox()
{
    DisassociateNSBox(GetNSBox());
}

void wxStaticBox::GetBordersForSizer(int *borderTop, int *borderOther) const
{
    NSRect contentRect = [[GetNSBox() contentView] frame];
    NSRect thisRect = [m_cocoaNSView frame];
    *borderTop = (int)(thisRect.size.height - (contentRect.origin.y+contentRect.size.height));
    *borderOther = (int)(thisRect.size.width - (contentRect.origin.x+contentRect.size.width));
    int nextBorder = (int)contentRect.origin.y;
    if(nextBorder > *borderOther)
        *borderOther = nextBorder;
    nextBorder = (int)contentRect.origin.x;
    if(nextBorder > *borderOther)
        *borderOther = nextBorder;
}

void wxStaticBox::SetLabel(const wxString& label)
{
   wxAutoNSAutoreleasePool pool;
   CocoaSetLabelForObject(label, GetNSBox());
}

wxString wxStaticBox::GetLabel() const
{
   wxAutoNSAutoreleasePool pool;
   return wxStringWithNSString([GetNSBox() title]);
}
