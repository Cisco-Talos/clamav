/////////////////////////////////////////////////////////////////////////////
// Name:        src/osx/cocoa/colour.mm
// Purpose:     Cocoa additions to wxColour class
// Author:      Kevin Ollivier
// Modified by:
// Created:     2009-10-31
// RCS-ID:      $Id: colour.cpp 61724 2009-08-21 10:41:26Z VZ $
// Copyright:   (c) Kevin Ollivier
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#include "wx/colour.h"

#ifndef WX_PRECOMP
    #include "wx/gdicmn.h"
#endif

#include "wx/osx/private.h"

#if wxOSX_USE_COCOA
wxColour::wxColour(WX_NSColor col)
{
    size_t noComp = [col numberOfComponents];
    
    CGFloat *components = NULL;
    if ( noComp >= 1 && noComp <= 4 )
    {
        // TODO verify whether we really are on a RGB color space
        m_alpha = wxALPHA_OPAQUE;
        [col getComponents: components];
    }
    InitFromComponents(const_cast<const CGFloat*>(components), noComp);
}

WX_NSColor wxColour::OSXGetNSColor()
{
    return [NSColor colorWithDeviceRed:m_red / 255.0 green:m_green / 255.0 blue:m_blue / 255.0 alpha:m_alpha / 255.0]; 
}
#endif