/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/region.mm
// Purpose:     wxRegion class
// Author:      David Elliott
// Modified by:
// Created:     2004/04/12
// RCS-ID:      $Id$
// Copyright:   (c) 2004 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/region.h"

#import <Foundation/NSGeometry.h>

IMPLEMENT_DYNAMIC_CLASS(wxRegion, wxGDIObject);

inline wxRect NSRectToWxRect(const NSRect& rect)
{
    return wxRect((wxCoord)rect.origin.x, (wxCoord)rect.origin.y,
        (wxCoord)rect.size.width, (wxCoord)rect.size.height);
}

wxRegion::wxRegion(const NSRect& rect)
{
    Union(NSRectToWxRect(rect));
}

wxRegion::wxRegion(const NSRect *rects, int count)
{
    for(int i=0; i<count; i++)
    {
        Union(NSRectToWxRect(rects[i]));
    }
}
