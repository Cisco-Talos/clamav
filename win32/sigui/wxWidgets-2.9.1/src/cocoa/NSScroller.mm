/////////////////////////////////////////////////////////////////////////////
// Name:        cocoa/NSScroller.mm
// Purpose:     wxCocoaNSScroller
// Author:      David Elliott
// Modified by:
// Created:     2004/04/27
// RCS-ID:      $Id$
// Copyright:   (c) 2004 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"
#ifndef WX_PRECOMP
    #include "wx/log.h"
#endif // WX_PRECOMP

#include "wx/cocoa/objc/objc_uniquifying.h"

#include "wx/cocoa/NSScroller.h"
#import <AppKit/NSScroller.h>

WX_IMPLEMENT_OBJC_INTERFACE_HASHMAP(NSScroller)

// ============================================================================
// @class wxNSScrollerTarget
// ============================================================================
@interface wxNSScrollerTarget : NSObject
{
}

- (void)wxNSScrollerAction: (id)sender;
@end // wxNSScrollerTarget
WX_DECLARE_GET_OBJC_CLASS(wxNSScrollerTarget,NSObject)

@implementation wxNSScrollerTarget : NSObject
- (void)wxNSScrollerAction: (id)sender
{
    wxCocoaNSScroller *scroller = wxCocoaNSScroller::GetFromCocoa(sender);
    wxCHECK_RET(scroller,wxT("wxNSScrollerAction received without associated wx object"));
    scroller->Cocoa_wxNSScrollerAction();
}

@end // implementation wxNSScrollerTarget
WX_IMPLEMENT_GET_OBJC_CLASS(wxNSScrollerTarget,NSObject)

// ============================================================================
// class wxCocoaNSScroller
// ============================================================================
const wxObjcAutoRefFromAlloc<struct objc_object*> wxCocoaNSScroller::sm_cocoaTarget = [[WX_GET_OBJC_CLASS(wxNSScrollerTarget) alloc] init];

void wxCocoaNSScroller::AssociateNSScroller(WX_NSScroller cocoaNSScroller)
{
    if(cocoaNSScroller)
    {
        sm_cocoaHash.insert(wxCocoaNSScrollerHash::value_type(cocoaNSScroller,this));
        [cocoaNSScroller setTarget: sm_cocoaTarget];
        [cocoaNSScroller setAction: @selector(wxNSScrollerAction:)];
    }
}

