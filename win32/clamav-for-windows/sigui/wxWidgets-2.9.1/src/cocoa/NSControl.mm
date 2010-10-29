/////////////////////////////////////////////////////////////////////////////
// Name:        cocoa/NSControl.cpp
// Purpose:     wxCocoaNSControl
// Author:      David Elliott
// Modified by:
// Created:     2003/02/15
// RCS-ID:      $Id$
// Copyright:   (c) 2003 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/wxprec.h"
#ifndef WX_PRECOMP
    #include "wx/log.h"
#endif // WX_PRECOMP

#include "wx/cocoa/objc/objc_uniquifying.h"
#include "wx/cocoa/ObjcRef.h"
#include "wx/cocoa/NSControl.h"

#import <Foundation/NSObject.h>

// ============================================================================
// @class wxNSControlTarget
// ============================================================================
@interface wxNSControlTarget : NSObject
{
}

- (void)wxNSControlAction: (id)sender;
@end //interface wxNSControlTarget
WX_DECLARE_GET_OBJC_CLASS(wxNSControlTarget,NSObject)

@implementation wxNSControlTarget : NSObject

- (void)wxNSControlAction: (id)sender
{
    wxLogTrace(wxTRACE_COCOA,wxT("wxNSControlAction"));
    wxCocoaNSControl *wxcontrol = wxCocoaNSControl::GetFromCocoa(sender);
    wxCHECK_RET(wxcontrol,wxT("wxNSControlAction received but no wxCocoaNSControl exists!"));
    wxcontrol->CocoaTarget_action();
}

@end //implementation wxNSControlTarget
WX_IMPLEMENT_GET_OBJC_CLASS(wxNSControlTarget,NSObject)

// ============================================================================
// wxNSControl
// ============================================================================
WX_IMPLEMENT_OBJC_INTERFACE(NSControl)

// New CF-retained observer (this should have been using wxObjcAutoRefFromAlloc to begin with)
wxObjcAutoRefFromAlloc<wxNSControlTarget*> s_cocoaNSControlTarget = [[WX_GET_OBJC_CLASS(wxNSControlTarget) alloc] init];
// For compatibility with old code
struct objc_object *wxCocoaNSControl::sm_cocoaTarget = s_cocoaNSControlTarget;

