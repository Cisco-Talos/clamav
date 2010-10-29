/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/stattext.mm
// Purpose:     wxStaticText
// Author:      David Elliott
// Modified by:
// Created:     2003/02/15
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#include "wx/stattext.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/log.h"
#endif //WX_PRECOMP

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"
#include "wx/cocoa/log.h"

#import <Foundation/NSString.h>
#import <AppKit/NSTextField.h>
#include <math.h>

IMPLEMENT_DYNAMIC_CLASS(wxStaticText, wxControl)
BEGIN_EVENT_TABLE(wxStaticText, wxControl)
END_EVENT_TABLE()
WX_IMPLEMENT_COCOA_OWNER(wxStaticText,NSTextField,NSControl,NSView)

bool wxStaticText::Create(wxWindow *parent, wxWindowID winid,
           const wxString& label,
           const wxPoint& pos,
           const wxSize& size,
           long style,
           const wxString& name)
{
    wxAutoNSAutoreleasePool pool;
    if(!CreateControl(parent,winid,pos,size,style,wxDefaultValidator,name))
        return false;
    m_cocoaNSView = NULL;
    SetNSTextField([[NSTextField alloc] initWithFrame:MakeDefaultNSRect(size)]);
    [m_cocoaNSView release];
    [GetNSTextField() setStringValue:wxNSStringWithWxString(GetLabelText(label))];
//    [GetNSTextField() setBordered: NO];
    [GetNSTextField() setBezeled: NO];
    [GetNSTextField() setEditable: NO];
    [GetNSTextField() setDrawsBackground: NO];

    NSTextAlignment alignStyle;
    if (style & wxALIGN_RIGHT)
        alignStyle = NSRightTextAlignment;
    else if (style & wxALIGN_CENTRE)
        alignStyle = NSCenterTextAlignment;
    else // default to wxALIGN_LEFT because it is 0 and can't be tested
        alignStyle = NSLeftTextAlignment;
    [GetNSControl() setAlignment:(NSTextAlignment)alignStyle];

    [GetNSControl() sizeToFit];
    // Round-up to next integer size
    NSRect nsrect = [m_cocoaNSView frame];
    nsrect.size.width = ceil(nsrect.size.width);
    [m_cocoaNSView setFrameSize: nsrect.size];

    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    return true;
}

wxStaticText::~wxStaticText()
{
    DisassociateNSTextField(GetNSTextField());
}

void wxStaticText::SetLabel(const wxString& label)
{
    [GetNSTextField() setStringValue:wxNSStringWithWxString(GetLabelText(label))];
    NSRect oldFrameRect = [GetNSTextField() frame];
    NSView *superview = [GetNSTextField() superview];

    if(!(GetWindowStyle() & wxST_NO_AUTORESIZE))
    {
        wxLogTrace(wxTRACE_COCOA_Window_Size, wxT("wxStaticText::SetLabel Old Position: (%d,%d)"), GetPosition().x, GetPosition().y);
        [GetNSTextField() sizeToFit];
        NSRect newFrameRect = [GetNSTextField() frame];
        // Ensure new size is an integer so GetSize returns valid data
        newFrameRect.size.height = ceil(newFrameRect.size.height);
        newFrameRect.size.width = ceil(newFrameRect.size.width);
        if(![superview isFlipped])
        {
            newFrameRect.origin.y = oldFrameRect.origin.y + oldFrameRect.size.height - newFrameRect.size.height;
        }
        [GetNSTextField() setFrame:newFrameRect];
        // New origin (wx coords) should always match old origin
        wxLogTrace(wxTRACE_COCOA_Window_Size, wxT("wxStaticText::SetLabel New Position: (%d,%d)"), GetPosition().x, GetPosition().y);
        [superview setNeedsDisplayInRect:newFrameRect];
    }

    [superview setNeedsDisplayInRect:oldFrameRect];
}

wxString wxStaticText::GetLabel() const
{
    wxAutoNSAutoreleasePool pool;
    return wxStringWithNSString([GetNSTextField() stringValue]);
}

void wxStaticText::Cocoa_didChangeText(void)
{
}
