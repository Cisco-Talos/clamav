/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/menu.cpp
// Purpose:     wxMenu and wxMenuBar implementation
// Author:      David Elliott
// Modified by:
// Created:     2002/12/09
// RCS-ID:      $Id$
// Copyright:   (c) 2002 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/wxprec.h"

#include "wx/menu.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
#endif // WX_PRECOMP

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"

#import <Foundation/NSString.h>
#include "wx/cocoa/objc/NSMenu.h"

#if wxUSE_MENUS

// ----------------------------------------------------------------------------
// globals
// ----------------------------------------------------------------------------

// ============================================================================
// wxMenu implementation
// ============================================================================

IMPLEMENT_DYNAMIC_CLASS(wxMenu,wxEvtHandler)

bool wxMenu::Create(const wxString& title, long style)
{
    wxAutoNSAutoreleasePool pool;
    m_cocoaNSMenu = [[WX_GET_OBJC_CLASS(WXNSMenu) alloc] initWithTitle: wxNSStringWithWxString(title)];
    AssociateNSMenu(m_cocoaNSMenu);
    return true;
}

wxMenu::~wxMenu()
{
    DisassociateNSMenu(m_cocoaNSMenu);
    if(!m_cocoaDeletes)
        [m_cocoaNSMenu release];
}

wxMenuItem* wxMenu::DoAppend(wxMenuItem *item)
{
    wxAutoNSAutoreleasePool pool;
    if(!wxMenuBase::DoAppend(item))
        return NULL;
    [m_cocoaNSMenu addItem: item->GetNSMenuItem()];
    return item;
}

wxMenuItem* wxMenu::DoInsert(unsigned long pos, wxMenuItem *item)
{
    wxAutoNSAutoreleasePool pool;
    if(!wxMenuBase::DoInsert(pos,item))
        return NULL;
    [m_cocoaNSMenu insertItem:item->GetNSMenuItem() atIndex:pos];
    return item;
}

wxMenuItem* wxMenu::DoRemove(wxMenuItem *item)
{
    wxAutoNSAutoreleasePool pool;
    wxMenuItem *retitem = wxMenuBase::DoRemove(item);
    wxASSERT(retitem->GetNSMenuItem());
    [m_cocoaNSMenu removeItem:retitem->GetNSMenuItem()];
    return retitem;
}

// This autoreleases the menu on the assumption that something is
// going to retain it shortly (for instance, it is going to be returned from
// an overloaded [NSStatusItem menu] or from the applicationDockMenu:
// NSApplication delegate method.
//
// It then sets a bool flag m_cocoaDeletes.  When the NSMenu is dealloc'd
// (dealloc is the Cocoa destructor) we delete ourselves.  In this manner we
// can be available for Cocoa calls until Cocoa is finished with us.
//
// I can see very few reasons to undo this.  Nevertheless, it is implemented.
void wxMenu::SetCocoaDeletes(bool cocoaDeletes)
{
    if(m_cocoaDeletes==cocoaDeletes)
        return;
    m_cocoaDeletes = cocoaDeletes;
    if(m_cocoaDeletes)
        [m_cocoaNSMenu autorelease];
    else
        [m_cocoaNSMenu retain];
}

void wxMenu::Cocoa_dealloc()
{
    if(m_cocoaDeletes)
        delete this;
}

// ============================================================================
// wxMenuBar implementation
// ============================================================================
IMPLEMENT_DYNAMIC_CLASS(wxMenuBar,wxWindow)

bool wxMenuBar::Create(long style)
{
    wxAutoNSAutoreleasePool pool;
    m_cocoaNSMenu = [[NSMenu alloc] initWithTitle: @"wxMenuBar"];

    NSMenuItem *dummyItem = [[NSMenuItem alloc] initWithTitle:@"App menu"
        /* Note: title gets clobbered by app name anyway */
        action:nil keyEquivalent:@""];
    [m_cocoaNSMenu addItem:dummyItem];
    [dummyItem release];
    return true;
}

wxMenuBar::wxMenuBar(size_t n,
                     wxMenu *menus[],
                     const wxString titles[],
                     long style)
{
    Create(style);

    for ( size_t i = 0; i < n; ++i )
        Append(menus[i], titles[i]);
}

wxMenuBar::~wxMenuBar()
{
    [m_cocoaNSMenu release];
}

bool wxMenuBar::Append( wxMenu *menu, const wxString &title )
{
    wxAutoNSAutoreleasePool pool;
    wxLogTrace(wxTRACE_COCOA,wxT("append menu=%p, title=%s"),menu,title.c_str());
    if(!wxMenuBarBase::Append(menu,title))
        return false;
    wxASSERT(menu);
    wxASSERT(menu->GetNSMenu());
    NSString *menuTitle = wxInitNSStringWithWxString([NSString alloc], wxStripMenuCodes(title));
    NSMenuItem *newItem = [[NSMenuItem alloc] initWithTitle:menuTitle action:NULL keyEquivalent:@""];
    [menu->GetNSMenu() setTitle:menuTitle];
    [newItem setSubmenu:menu->GetNSMenu()];

    [m_cocoaNSMenu addItem:newItem];

    [menuTitle release];
    [newItem release];
    return true;
}

bool wxMenuBar::Insert(size_t pos, wxMenu *menu, const wxString& title)
{
    wxAutoNSAutoreleasePool pool;
    wxLogTrace(wxTRACE_COCOA,wxT("insert pos=%lu, menu=%p, title=%s"),pos,menu,title.c_str());
    // Get the current menu at this position
    wxMenu *nextmenu = GetMenu(pos);
    if(!wxMenuBarBase::Insert(pos,menu,title))
        return false;
    wxASSERT(menu);
    wxASSERT(menu->GetNSMenu());
    NSString *menuTitle = wxInitNSStringWithWxString([NSString alloc], title);
    NSMenuItem *newItem = [[NSMenuItem alloc] initWithTitle:menuTitle action:NULL keyEquivalent:@""];
    [menu->GetNSMenu() setTitle:menuTitle];
    [newItem setSubmenu:menu->GetNSMenu()];

    int itemindex = [m_cocoaNSMenu indexOfItemWithSubmenu:nextmenu->GetNSMenu()];
    wxASSERT(itemindex>=0);
    [m_cocoaNSMenu insertItem:newItem atIndex:itemindex];

    [menuTitle release];
    [newItem release];
    return true;
}

wxMenu *wxMenuBar::Replace(size_t pos, wxMenu *menu, const wxString& title)
{
    return NULL;
}

wxMenu *wxMenuBar::Remove(size_t pos)
{
    wxMenu *menu = wxMenuBarBase::Remove(pos);
    wxASSERT(menu);
    int itemindex = [GetNSMenu() indexOfItemWithSubmenu:menu->GetNSMenu()];
    wxASSERT(itemindex>=0);
    [m_cocoaNSMenu removeItemAtIndex:itemindex];
    return menu;
}


void wxMenuBar::EnableTop(size_t pos, bool enable)
{
}

bool wxMenuBar::IsEnabledTop(size_t pos) const
{
    return false;
}

void wxMenuBar::SetMenuLabel(size_t pos, const wxString& label)
{
}

wxString wxMenuBar::GetMenuLabel(size_t pos) const
{
    wxMenu *menu = GetMenu(pos);
    int itemindex = [m_cocoaNSMenu indexOfItemWithSubmenu:menu->GetNSMenu()];
    wxASSERT(itemindex>=0);
    return wxStringWithNSString([[m_cocoaNSMenu itemAtIndex:itemindex] title]);
}

void wxMenuBar::Attach(wxFrame *frame)
{
    wxMenuBarBase::Attach(frame);
}

void wxMenuBar::Detach()
{
    wxMenuBarBase::Detach();
}

wxSize wxMenuBar::DoGetBestClientSize() const
{
    return wxDefaultSize;
}

#endif // wxUSE_MENUS
