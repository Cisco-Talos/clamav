/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/radiobut.mm
// Purpose:     wxRadioButton
// Author:      David Elliott
// Modified by:
// Created:     2003/03/16
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_RADIOBTN

#include "wx/radiobut.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
#endif //WX_PRECOMP

#import <AppKit/NSButton.h>
#include "wx/cocoa/string.h"
#include "wx/cocoa/autorelease.h"

#include "wx/listimpl.cpp"

WX_DEFINE_LIST(wxRadioButtonList);

IMPLEMENT_DYNAMIC_CLASS(wxRadioButton, wxControl)
// wxRadioButtonBase == wxControl
BEGIN_EVENT_TABLE(wxRadioButton, wxControl)
END_EVENT_TABLE()
WX_IMPLEMENT_COCOA_OWNER(wxRadioButton,NSButton,NSControl,NSView)

bool wxRadioButton::Create(wxWindow *parent, wxWindowID winid,
           const wxString& label,
           const wxPoint& pos,
           const wxSize& size,
           long style,
           const wxValidator& validator,
           const wxString& name)
{
    wxAutoNSAutoreleasePool pool;
    m_radioMaster = NULL;
    if(!CreateControl(parent,winid,pos,size,style,validator,name))
        return false;
    if(style&wxRB_GROUP)
    {
        m_radioMaster = this;
        m_radioSlaves.Append(this);
    }
    else if(style&wxRB_SINGLE)
        m_radioMaster = NULL;
    else
    {
        for(wxWindowList::compatibility_iterator siblingNode= GetParent()->GetChildren().GetLast();
            siblingNode;
            siblingNode = siblingNode->GetPrevious())
        {
            wxRadioButton *radioButton  = wxDynamicCast(siblingNode->GetData(),wxRadioButton);
            if(radioButton && radioButton!=this)
            {
                m_radioMaster = radioButton->m_radioMaster;
                wxASSERT_MSG(m_radioMaster,
                    wxT("Previous radio button should be part of a group"));
                // Don't crash, assume user meant wxRB_SINGLE
                if(m_radioMaster)
                    m_radioMaster->m_radioSlaves.Append(this);
                break;
            }
        }
    }

    m_cocoaNSView = NULL;
    SetNSButton([[NSButton alloc] initWithFrame: MakeDefaultNSRect(size)]);
    [m_cocoaNSView release];
    [GetNSButton() setButtonType: NSRadioButton];
    CocoaSetLabelForObject(label, GetNSButton());
    // If it's the first in a group, it should be selected
    if(style&wxRB_GROUP)
        [GetNSButton() setState: NSOnState];
    [GetNSControl() sizeToFit];

    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    return true;
}

wxRadioButton::~wxRadioButton()
{
    if(m_radioMaster==this)
    {
        // First get rid of ourselves (we should ALWAYS be at the head)
        wxRadioButtonList::compatibility_iterator slaveNode =
            m_radioSlaves.GetFirst();
        wxASSERT(slaveNode);
        wxASSERT(slaveNode->GetData() == this);
        m_radioSlaves.Erase(slaveNode);

        // Now find the new master
        wxRadioButton *newMaster = NULL;
        slaveNode = m_radioSlaves.GetFirst();
        if(slaveNode)
            newMaster = slaveNode->GetData();

        // For each node (including the new master) set the master, remove
        // it from this list, and add it to the new master's list
        for(; slaveNode; slaveNode = m_radioSlaves.GetFirst())
        {
            wxRadioButton *radioButton = slaveNode->GetData();
            wxASSERT(radioButton->m_radioMaster == this);
            radioButton->m_radioMaster = newMaster;
            newMaster->m_radioSlaves.Append(radioButton);
            m_radioSlaves.Erase(slaveNode);
        }
    }
    else if(m_radioMaster)
    {
        m_radioMaster->m_radioSlaves.DeleteObject(this);
        m_radioMaster = NULL;
    }
    // normal stuff
    DisassociateNSButton(GetNSButton());
}

void wxRadioButton::SetValue(bool value)
{
    if(value)
    {
        [GetNSButton() setState: NSOnState];
        Cocoa_DeselectOtherButtonsInTheGroup();
    }
    else
        [GetNSButton() setState: NSOffState];
}

bool wxRadioButton::GetValue() const
{
    int state = [GetNSButton() state];
    wxASSERT(state!=NSMixedState);
    return state==NSOnState;
}

void wxRadioButton::SetLabel(const wxString& label)
{
    wxAutoNSAutoreleasePool pool;
    CocoaSetLabelForObject(label, GetNSButton());
}

wxString wxRadioButton::GetLabel() const 
{    
    return wxStringWithNSString([GetNSButton() title]);
}

/**
 * If this radio button is part of a group, this method turns off every other
 * button in the group.  If this radio button is not part of a group, this
 * method does absolutely nothing.
 */
void wxRadioButton::Cocoa_DeselectOtherButtonsInTheGroup(void)
{
    if(m_radioMaster)
    {
        for(wxRadioButtonList::compatibility_iterator slaveNode =
                m_radioMaster->m_radioSlaves.GetFirst();
            slaveNode; slaveNode = slaveNode->GetNext())
        {
            wxRadioButton *radioButton = slaveNode->GetData();
            if(radioButton!=this)
                radioButton->SetValue(false);
        }
    }
}

void wxRadioButton::Cocoa_wxNSButtonAction(void)
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxRadioButton"));
    if([GetNSButton() state] == NSOnState)
    {
        Cocoa_DeselectOtherButtonsInTheGroup();
    }
    wxCommandEvent event(wxEVT_COMMAND_RADIOBUTTON_SELECTED, GetId());
    InitCommandEvent(event); //    event.SetEventObject(this);
    event.SetInt(GetValue());
    Command(event);
}

#endif
