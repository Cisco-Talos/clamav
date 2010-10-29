///////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/menuitem.mm
// Purpose:     wxMenuItem implementation
// Author:      David Elliott
// Modified by:
// Created:     2002/12/15
// RCS-ID:      $Id$
// Copyright:   2002-2004 David Elliott
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/wxprec.h"

#if wxUSE_MENUS

#include "wx/menuitem.h"

#include "wx/cocoa/objc/objc_uniquifying.h"

#ifndef WX_PRECOMP
    #include "wx/menu.h"
    #include "wx/utils.h"
    #include "wx/frame.h"
    #include "wx/log.h"
#endif

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"

#import <AppKit/NSMenuItem.h>
#import <AppKit/NSMenu.h>
#import <Foundation/NSString.h>
#import <AppKit/NSCell.h> // NSOnState, NSOffState
#import <AppKit/NSEvent.h> // modifier key masks

// ----------------------------------------------------------------------------
// functions prototypes
// ----------------------------------------------------------------------------

// ============================================================================
// @class wxNSMenuItemTarget
// ============================================================================
@interface wxNSMenuItemTarget : NSObject
{
}

- (void)wxMenuItemAction: (id)sender;
- (BOOL)validateMenuItem: (id)menuItem;
@end //interface wxNSMenuItemTarget
WX_DECLARE_GET_OBJC_CLASS(wxNSMenuItemTarget,NSObject)

@implementation wxNSMenuItemTarget : NSObject

- (void)wxMenuItemAction: (id)sender
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxMenuItemAction"));
    wxMenuItem *item = wxMenuItem::GetFromCocoa(sender);
    wxCHECK_RET(item,wxT("wxMenuItemAction received but no wxMenuItem exists!"));
    item->CocoaItemSelected();
}

- (BOOL)validateMenuItem: (id)menuItem
{
    // TODO: Do wxWidgets validation here and avoid sending during idle time
    wxLogTrace(wxTRACE_COCOA,wxT("wxMenuItemAction"));
    wxMenuItem *item = wxMenuItem::GetFromCocoa(menuItem);
    wxCHECK_MSG(item,NO,wxT("validateMenuItem received but no wxMenuItem exists!"));
    return item->Cocoa_validateMenuItem();
}

@end //implementation wxNSMenuItemTarget
WX_IMPLEMENT_GET_OBJC_CLASS(wxNSMenuItemTarget,NSObject)

// ============================================================================
// wxMenuItemCocoa implementation
// ============================================================================
IMPLEMENT_DYNAMIC_CLASS(wxMenuItem, wxObject)
wxMenuItemCocoaHash wxMenuItemCocoa::sm_cocoaHash;

wxObjcAutoRefFromAlloc<struct objc_object *> wxMenuItemCocoa::sm_cocoaTarget = [[WX_GET_OBJC_CLASS(wxNSMenuItemTarget) alloc] init];

// ----------------------------------------------------------------------------
// wxMenuItemBase
// ----------------------------------------------------------------------------

wxMenuItem *wxMenuItemBase::New(wxMenu *parentMenu,
                                int itemid,
                                const wxString& name,
                                const wxString& help,
                                wxItemKind kind,
                                wxMenu *subMenu)
{
    return new wxMenuItem(parentMenu, itemid, name, help, kind, subMenu);
}

void wxMenuItemCocoa::CocoaSetKeyEquivalent()
{
    wxAcceleratorEntry *accel = GetAccel();
    if(!accel)
        return;

    int accelFlags = accel->GetFlags();
    int keyModifierMask = 0;
    if(accelFlags & wxACCEL_ALT)
        keyModifierMask |= NSAlternateKeyMask;
    if(accelFlags & wxACCEL_CTRL)
        keyModifierMask |= NSCommandKeyMask;
    int keyCode = accel->GetKeyCode();
    if(isalpha(keyCode))
    {   // For alpha characters use upper/lower rather than NSShiftKeyMask
        char alphaChar;
        if(accelFlags & wxACCEL_SHIFT)
            alphaChar = toupper(keyCode);
        else
            alphaChar = tolower(keyCode);
        [m_cocoaNSMenuItem setKeyEquivalent:[NSString stringWithCString:&alphaChar length:1]];
        [m_cocoaNSMenuItem setKeyEquivalentModifierMask:keyModifierMask];
    }
    else
    {
        if(accelFlags & wxACCEL_SHIFT)
            keyModifierMask |= NSShiftKeyMask;
        if(keyCode < 128) // low ASCII includes backspace/tab/etc.
        {   char alphaChar = keyCode;
            [m_cocoaNSMenuItem setKeyEquivalent:[NSString stringWithCString:&alphaChar length:1]];
        }
        else
        {   // TODO
        }
        [m_cocoaNSMenuItem setKeyEquivalentModifierMask:keyModifierMask];
    }
}

// ----------------------------------------------------------------------------
// ctor & dtor
// ----------------------------------------------------------------------------
wxMenuItemCocoa::wxMenuItemCocoa(wxMenu *pParentMenu,
                       int itemid,
                       const wxString& strName,
                       const wxString& strHelp,
                       wxItemKind kind,
                       wxMenu *pSubMenu)
          : wxMenuItemBase(pParentMenu, itemid, strName, strHelp, kind, pSubMenu)
{
    wxAutoNSAutoreleasePool pool;
    if(m_kind == wxITEM_SEPARATOR)
        m_cocoaNSMenuItem = [[NSMenuItem separatorItem] retain];
    else
    {
        NSString *menuTitle = wxInitNSStringWithWxString([NSString alloc],wxStripMenuCodes(strName));
        SEL action;
        if(pSubMenu)
            action = nil;
        else
            action = @selector(wxMenuItemAction:);
        m_cocoaNSMenuItem = [[NSMenuItem alloc] initWithTitle:menuTitle action:action keyEquivalent:@""];
        sm_cocoaHash.insert(wxMenuItemCocoaHash::value_type(m_cocoaNSMenuItem,this));
        if(pSubMenu)
        {
            wxASSERT(pSubMenu->GetNSMenu());
            [pSubMenu->GetNSMenu() setTitle:menuTitle];
            [m_cocoaNSMenuItem setSubmenu:pSubMenu->GetNSMenu()];
        }
        else
            [m_cocoaNSMenuItem setTarget: sm_cocoaTarget];
        [menuTitle release];
        CocoaSetKeyEquivalent();
    }
}

wxMenuItem::~wxMenuItem()
{
    sm_cocoaHash.erase(m_cocoaNSMenuItem);
    [m_cocoaNSMenuItem release];
}

void wxMenuItem::CocoaItemSelected()
{
    wxMenu *menu = GetMenu();
    wxCHECK_RET(menu,wxT("wxMenuItemAction received but wxMenuItem is not in a wxMenu"));
    wxMenuBar *menubar = menu->GetMenuBar();
    if(menubar)
    {
        wxFrame *frame = menubar->GetFrame();
        wxCHECK_RET(frame, wxT("wxMenuBar MUST be attached to a wxFrame!"));
        frame->ProcessCommand(GetId());
    }
    else
    {
        if(IsCheckable())
            Toggle();
        GetMenu()->SendEvent(GetId(), IsCheckable()?IsChecked():-1);
    }
}

bool wxMenuItem::Cocoa_validateMenuItem()
{
    // TODO: do more sanity checking
    // TODO: Do wxWindows validation here and avoid sending during idle time
    return IsEnabled();
}

// ----------------------------------------------------------------------------
// misc
// ----------------------------------------------------------------------------

void wxMenuItem::SetBitmaps(const wxBitmap& bmpChecked,
        const wxBitmap& bmpUnchecked)
{
    wxCHECK_RET(m_kind != wxITEM_SEPARATOR, wxT("Separator items do not have bitmaps."));
    wxAutoNSAutoreleasePool pool;
    m_bmpChecked = bmpChecked;
    m_bmpUnchecked = bmpUnchecked;
    if(IsCheckable())
    {
        [m_cocoaNSMenuItem setOnStateImage: bmpChecked.GetNSImage(true)];
        [m_cocoaNSMenuItem setOffStateImage: bmpUnchecked.GetNSImage(true)];
    }
    else
    {
        wxASSERT_MSG(!bmpUnchecked.Ok(),wxT("Normal menu items should only have one bitmap"));
        [m_cocoaNSMenuItem setImage: bmpChecked.GetNSImage(true)];
    }
}

// change item state
// -----------------

void wxMenuItem::Enable(bool bDoEnable)
{
    wxMenuItemBase::Enable(bDoEnable);
    // NOTE: Nothing to do, we respond to validateMenuItem instead
}

void wxMenuItem::Check(bool check)
{
    wxCHECK_RET( IsCheckable(), wxT("only checkable items may be checked") );
    if(m_isChecked == check)
        return;
    wxAutoNSAutoreleasePool pool;
    if(GetKind() == wxITEM_RADIO)
    {
        // it doesn't make sense to uncheck a radio item - what would this do?
        if(!check)
            return;
        const wxMenuItemList& items = m_parentMenu->GetMenuItems();
        // First search backwards for other radio items
        wxMenuItemList::compatibility_iterator radioStart = items.Find(this);
        for(wxMenuItemList::compatibility_iterator prevNode = radioStart;
            prevNode && (prevNode->GetData()->GetKind() == wxITEM_RADIO);
            prevNode = prevNode->GetPrevious())
        {
            radioStart = prevNode;
        }
        // Now starting there set the state of every item until we're
        // out of radio items to set.
        for(wxMenuItemList::compatibility_iterator node = radioStart;
            node && (node->GetData()->GetKind() == wxITEM_RADIO);
            node = node->GetNext())
        {
            wxMenuItem *item = node->GetData();
            bool checkItem = (item == this);
            item->wxMenuItemBase::Check(checkItem);
            [item->m_cocoaNSMenuItem setState: checkItem?NSOnState:NSOffState];
        }
    }
    else // normal check (non-radio) item
    {
        wxMenuItemBase::Check(check);
        [m_cocoaNSMenuItem setState: check?NSOnState:NSOffState];
    }
}

void wxMenuItem::SetItemLabel(const wxString& label)
{
    wxMenuItemBase::SetItemLabel(label);
    wxCHECK_RET(m_kind != wxITEM_SEPARATOR, wxT("Separator items do not have titles."));
    [m_cocoaNSMenuItem setTitle: wxNSStringWithWxString(wxStripMenuCodes(label))];
    CocoaSetKeyEquivalent();
}

void wxMenuItem::SetCheckable(bool checkable)
{
    wxCHECK_RET(m_kind != wxITEM_SEPARATOR, wxT("Separator items cannot be turned into normal menu items."));
    wxMenuItemBase::SetCheckable(checkable);
    // NOTE: Cocoa does not discern between unchecked and normal items
}

#endif // wxUSE_MENUS
