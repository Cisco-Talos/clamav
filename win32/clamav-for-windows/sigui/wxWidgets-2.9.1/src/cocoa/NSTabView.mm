/////////////////////////////////////////////////////////////////////////////
// Name:        cocoa/NSTabView.mm
// Purpose:     wxCocoaNSTabView
// Author:      David Elliott
// Modified by:
// Created:     2004/04/08
// RCS-ID:      $Id$
// Copyright:   (c) 2004 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"
#ifndef WX_PRECOMP
#endif // WX_PRECOMP

#include "wx/cocoa/NSTabView.h"

#include "wx/cocoa/objc/objc_uniquifying.h"

#include <AppKit/NSTabView.h>

// ============================================================================
// @class wxNSTabViewDelegate
// ============================================================================
@interface wxNSTabViewDelegate : NSObject
{
}

- (void)tabView:(NSTabView*)tabView didSelectTabViewItem:(NSTabViewItem*)tabViewItem;
- (BOOL)tabView:(NSTabView*)tabView shouldSelectTabViewItem:(NSTabViewItem*)tabViewItem;
@end // interface wxNSTabViewDelegate : NSObject
WX_DECLARE_GET_OBJC_CLASS(wxNSTabViewDelegate,NSObject)

@implementation wxNSTabViewDelegate : NSObject
- (void)tabView:(NSTabView*)tabView didSelectTabViewItem:(NSTabViewItem*)tabViewItem
{
    wxCocoaNSTabView *notebook = wxCocoaNSTabView::GetFromCocoa(tabView);
    wxCHECK_RET(notebook, wxT("This delegate is for use only with wxCocoa NSTabViews"));
    notebook->CocoaDelegate_tabView_didSelectTabViewItem(tabViewItem);

}

- (BOOL)tabView:(NSTabView*)tabView shouldSelectTabViewItem:(NSTabViewItem*)tabViewItem
{
    wxCocoaNSTabView *notebook = wxCocoaNSTabView::GetFromCocoa(tabView);
    wxCHECK_MSG(notebook, true, wxT("This delegate is for use only with wxCocoa NSTabViews"));
    return notebook->CocoaDelegate_tabView_shouldSelectTabViewItem(tabViewItem);
}

@end // implementation wxNSTabViewDelegate : NSObject
WX_IMPLEMENT_GET_OBJC_CLASS(wxNSTabViewDelegate,NSObject)

// ============================================================================
// class wxCocoaNSTabView
// ============================================================================
WX_IMPLEMENT_OBJC_INTERFACE_HASHMAP(NSTabView)

wxObjcAutoRefFromAlloc<struct objc_object*> wxCocoaNSTabView::sm_cocoaDelegate = [[WX_GET_OBJC_CLASS(wxNSTabViewDelegate) alloc] init];

void wxCocoaNSTabView::AssociateNSTabView(WX_NSTabView cocoaNSTabView)
{
    if(cocoaNSTabView)
    {
        sm_cocoaHash.insert(wxCocoaNSTabViewHash::value_type(cocoaNSTabView,this));
        [cocoaNSTabView setDelegate: sm_cocoaDelegate];
    }
}

void wxCocoaNSTabView::DisassociateNSTabView(WX_NSTabView cocoaNSTabView)
{
    if(cocoaNSTabView)
    {
        [cocoaNSTabView setDelegate: nil];
        sm_cocoaHash.erase(cocoaNSTabView);
    }
}

