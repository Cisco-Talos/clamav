/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/checkbox.mm
// Purpose:     wxCheckBox
// Author:      David Elliott
// Modified by:
// Created:     2003/03/16
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_CHECKBOX

#include "wx/checkbox.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
#endif //WX_PRECOMP

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"

#import <AppKit/NSButton.h>
#import <Foundation/NSString.h>

IMPLEMENT_DYNAMIC_CLASS(wxCheckBox, wxControl)
BEGIN_EVENT_TABLE(wxCheckBox, wxCheckBoxBase)
END_EVENT_TABLE()
WX_IMPLEMENT_COCOA_OWNER(wxCheckBox,NSButton,NSControl,NSView)

bool wxCheckBox::Create(wxWindow *parent, wxWindowID winid,
           const wxString& label,
           const wxPoint& pos,
           const wxSize& size,
           long style,
           const wxValidator& validator,
           const wxString& name)
{
    wxAutoNSAutoreleasePool pool;
    if(!CreateControl(parent,winid,pos,size,style,validator,name))
        return false;
    m_cocoaNSView = NULL;
    SetNSButton([[NSButton alloc] initWithFrame: MakeDefaultNSRect(size)]);
    [m_cocoaNSView release];
    [GetNSButton() setButtonType: NSSwitchButton];
    [GetNSButton() setAllowsMixedState: Is3State()];
    CocoaSetLabelForObject(label, GetNSButton());
    [GetNSControl() sizeToFit];

    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    return true;
}

wxCheckBox::~wxCheckBox()
{
    DisassociateNSButton(GetNSButton());
}

void wxCheckBox::SetValue(bool value)
{
    [GetNSButton() setState: value?NSOnState:NSOffState];
}

void wxCheckBox::DoSet3StateValue(wxCheckBoxState state)
{
    int cocoaState;
    switch(state)
    {
    case wxCHK_UNCHECKED:
        cocoaState = NSOffState;
        break;
    case wxCHK_CHECKED:
        cocoaState = NSOnState;
        break;
    case wxCHK_UNDETERMINED:
        // Base class would have already set state to wxCHK_UNCHECKED
//        wxASSERT_MSG(Is3State(),"Use the wxCHK_3STATE style flag");
        cocoaState = NSMixedState;
        break;
    default:
        wxFAIL_MSG(wxT("Invalid state in wxCheckBox::DoSet3StateValue"));
        return;
    }
    [GetNSButton() setState:cocoaState];
}

bool wxCheckBox::GetValue() const
{
    int state = [GetNSButton() state];
    wxASSERT_MSG(state!=NSMixedState || Is3State(),
        wxT("NSMixedState returned from a 2-state checkbox"));
    return state!=NSOffState;
}

wxCheckBoxState wxCheckBox::DoGet3StateValue() const
{
    switch([GetNSButton() state])
    {
    case NSOffState:
        return wxCHK_UNCHECKED;
    case NSOnState:
        return wxCHK_CHECKED;
    default:
        wxFAIL_MSG(wxT("[NSButton -state] returned an invalid state!"));
    case NSMixedState:
        // Base class handles this assertion for us
//        wxASSERT_MSG(Is3State(),wxT("NSMixedState returned from a 2-state checkbox"));
        return wxCHK_UNDETERMINED;
    }
}

void wxCheckBox::Cocoa_wxNSButtonAction(void)
{
    wxLogTrace(wxTRACE_COCOA,wxT("Checkbox"));
    // What we really want to do is override [NSCell -nextState] to return
    // NSOnState in lieu of NSMixedState but this works (aside from the
    // very slightly noticeable drawing of - and then a check) -DE

    // Cocoa always allows a 3-state button to transition into
    // the mixed/undetermined state by clicking, we don't
    if ( !Is3rdStateAllowedForUser()
         && [GetNSButton() state] == NSMixedState )
    {
        // Cocoa's sequence is on/off/mixed
        // skip mixed, go right back to on
        [GetNSButton() setState: NSOnState];
    }
    wxCommandEvent event(wxEVT_COMMAND_CHECKBOX_CLICKED, GetId());
    InitCommandEvent(event); //    event.SetEventObject(this);
    event.SetInt(Get3StateValue());
    Command(event);
}

void wxCheckBox::SetLabel(const wxString& s)
{
    wxAutoNSAutoreleasePool pool;
    CocoaSetLabelForObject(s, GetNSButton());
}

wxString wxCheckBox::GetLabel() const
{
    wxAutoNSAutoreleasePool pool;
    return wxStringWithNSString([GetNSButton() title]);

}

#endif // wxUSE_CHECKBOX
