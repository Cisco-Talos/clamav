/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/choice.mm
// Purpose:     wxChoice
// Author:      David Elliott
// Modified by:
// Created:     2003/03/16
// Id:          $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_CHOICE

#include "wx/choice.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/arrstr.h"
#endif //WX_PRECOMP

#include "wx/cocoa/string.h"
#include "wx/cocoa/autorelease.h"

#import <AppKit/NSPopUpButton.h>
#import <AppKit/NSMenu.h>
#import <Foundation/NSNotification.h>
#import <Foundation/NSDictionary.h>

IMPLEMENT_DYNAMIC_CLASS(wxChoice, wxControlWithItems)
BEGIN_EVENT_TABLE(wxChoice, wxChoiceBase)
END_EVENT_TABLE()
// WX_IMPLEMENT_COCOA_OWNER(wxChoice,NSButton,NSControl,NSView)

void wxChoice::Init()
{
    m_sortedStrings = NULL;
}

bool wxChoice::Create(wxWindow *parent, wxWindowID winid,
            const wxPoint& pos,
            const wxSize& size,
            const wxArrayString& choices,
            long style,
            const wxValidator& validator,
            const wxString& name)
{
    wxCArrayString chs(choices);

    return Create(parent, winid, pos, size, chs.GetCount(), chs.GetStrings(),
                  style, validator, name);
}

bool wxChoice::Create(wxWindow *parent, wxWindowID winid,
            const wxPoint& pos,
            const wxSize& size,
            int n, const wxString choices[],
            long style,
            const wxValidator& validator,
            const wxString& name)
{
    wxAutoNSAutoreleasePool pool;
    if(!CreateControl(parent,winid,pos,size,style,validator,name))
        return false;

    SetNSView([[NSPopUpButton alloc] initWithFrame:MakeDefaultNSRect(size)
        pullsDown: NO]);
    [m_cocoaNSView release];

    NSMenu *nsmenu = [(NSPopUpButton*)m_cocoaNSView menu];
    AssociateNSMenu(nsmenu, OBSERVE_DidSendAction);

    if(style&wxCB_SORT)
    {
        m_sortedStrings = new wxSortedArrayString;
        for(int i=0; i<n; i++)
        {
            m_sortedStrings->Add(choices[i]);
        }
        for(unsigned int i=0; i < m_sortedStrings->GetCount(); i++)
        {
            [nsmenu addItemWithTitle:wxNSStringWithWxString(
                    m_sortedStrings->Item(i))
                action: nil keyEquivalent:@""];
        }
    }
    else
    {
        for(int i=0; i<n; i++)
        {
            [nsmenu addItemWithTitle:wxNSStringWithWxString(choices[i])
                action: nil keyEquivalent:@""];
        }
    }
    m_itemsClientData.SetCount(n);

    [(NSPopUpButton*)m_cocoaNSView sizeToFit];
    if(m_parent)
        m_parent->CocoaAddChild(this);
    SetInitialFrameRect(pos,size);

    return true;
}

wxChoice::~wxChoice()
{
    DisassociateNSMenu([(NSPopUpButton*)m_cocoaNSView menu]);

    Clear();
}

void wxChoice::CocoaNotification_menuDidSendAction(WX_NSNotification notification)
{
    NSDictionary *userInfo = [notification userInfo];
    NSMenuItem *menuitem = [userInfo objectForKey:@"MenuItem"];
    int index = [[(NSPopUpButton*)m_cocoaNSView menu] indexOfItem: menuitem];
    int selectedItem = [(NSPopUpButton*)m_cocoaNSView indexOfSelectedItem];
    wxLogTrace(wxTRACE_COCOA,wxT("menuDidSendAction, index=%d, selectedItem=%d"), index, selectedItem);
    wxCommandEvent event(wxEVT_COMMAND_CHOICE_SELECTED, m_windowId);
    event.SetInt(index);
    event.SetEventObject(this);
    event.SetString(GetStringSelection());
    HandleWindowEvent(event);
}

void wxChoice::DoClear()
{
    if(m_sortedStrings)
        m_sortedStrings->Clear();
    m_itemsClientData.Clear();
    [(NSPopUpButton*)m_cocoaNSView removeAllItems];
}

void wxChoice::DoDeleteOneItem(unsigned int n)
{
    if(m_sortedStrings)
        m_sortedStrings->RemoveAt(n);
    m_itemsClientData.RemoveAt(n);
    [(NSPopUpButton*)m_cocoaNSView removeItemAtIndex:n];
}

unsigned int wxChoice::GetCount() const
{
    return (unsigned int)[(NSPopUpButton*)m_cocoaNSView numberOfItems];
}

wxString wxChoice::GetString(unsigned int n) const
{
    wxAutoNSAutoreleasePool pool;
    return wxStringWithNSString([(NSPopUpButton*)m_cocoaNSView itemTitleAtIndex:n]);
}

void wxChoice::SetString(unsigned int n, const wxString& title)
{
    NSMenuItem *item = [(NSPopUpButton*)m_cocoaNSView itemAtIndex:n];
    [item setTitle:wxNSStringWithWxString(title)];
}

int wxChoice::FindString(const wxString& title, bool bCase) const
{
    // FIXME: use wxItemContainerImmutable::FindString for bCase parameter
    return [(NSPopUpButton*)m_cocoaNSView indexOfItemWithTitle:
        wxNSStringWithWxString(title)];
}

int wxChoice::GetSelection() const
{
    return [(NSPopUpButton*)m_cocoaNSView indexOfSelectedItem];
}

int wxChoice::DoInsertItems(const wxArrayStringsAdapter & items,
                            unsigned int pos,
                            void **clientData, wxClientDataType type)
{
    NSMenu *nsmenu = [(NSPopUpButton*)m_cocoaNSView menu];
    NSMenuItem *item = NULL;

    unsigned int numItems = items.GetCount();
    for ( unsigned int i = 0; i < numItems; ++i, ++pos )
    {
        const wxString& str = items[i];
        int idx = m_sortedStrings ? m_sortedStrings->Add(str) : pos;

        item = [nsmenu insertItemWithTitle:wxNSStringWithWxString(str)
            action: nil keyEquivalent:@"" atIndex:idx];
        m_itemsClientData.Insert(NULL, idx);
        AssignNewItemClientData(idx, clientData, i, type);
    }
    return [nsmenu indexOfItem:item];
}

void wxChoice::DoSetItemClientData(unsigned int n, void *data)
{
    m_itemsClientData[n] = data;
}

void* wxChoice::DoGetItemClientData(unsigned int n) const
{
    return m_itemsClientData[n];
}

void wxChoice::SetSelection(int n)
{
    wxAutoNSAutoreleasePool pool;
    [(NSPopUpButton*)m_cocoaNSView selectItemAtIndex:n];
}

#endif // wxUSE_CHOICE
