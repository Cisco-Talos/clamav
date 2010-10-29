/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/settings.mm
// Purpose:     wxSettings
// Author:      David Elliott
// Modified by:
// Created:     2005/01/11
// RCS-ID:      $Id$
// Copyright:   (c) 2005 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#include "wx/settings.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/gdicmn.h"
#endif

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/private/fontfactory.h"

#import <AppKit/NSColor.h>
#import <AppKit/NSFont.h>

// ----------------------------------------------------------------------------
// wxSystemSettingsNative
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// colours
// ----------------------------------------------------------------------------

wxColour wxSystemSettingsNative::GetColour(wxSystemColour index)
{
    wxAutoNSAutoreleasePool pool;
    switch( index )
    {
    case wxSYS_COLOUR_SCROLLBAR:
        return wxColour([NSColor scrollBarColor]); // color of slot
    case wxSYS_COLOUR_BACKGROUND: // No idea how to get desktop background
        break; // break so we return an invalid colour.
    case wxSYS_COLOUR_ACTIVECAPTION: // No idea how to get this
        // fall through, window background is reasonable
    case wxSYS_COLOUR_INACTIVECAPTION: // No idea how to get this
        // fall through, window background is reasonable
    case wxSYS_COLOUR_MENU:
    case wxSYS_COLOUR_MENUBAR:
    case wxSYS_COLOUR_WINDOW:
    case wxSYS_COLOUR_WINDOWFRAME:
    case wxSYS_COLOUR_ACTIVEBORDER:
    case wxSYS_COLOUR_INACTIVEBORDER:
        return wxColour([NSColor windowFrameColor]);
    case wxSYS_COLOUR_BTNFACE:
        return wxColour([NSColor knobColor]); // close enough?
    case wxSYS_COLOUR_LISTBOX:
        return wxColour([NSColor controlBackgroundColor]);
    case wxSYS_COLOUR_BTNSHADOW:
        return wxColour([NSColor controlShadowColor]);
    case wxSYS_COLOUR_BTNTEXT:
    case wxSYS_COLOUR_MENUTEXT:
    case wxSYS_COLOUR_WINDOWTEXT:
    case wxSYS_COLOUR_CAPTIONTEXT:
    case wxSYS_COLOUR_INFOTEXT:
    case wxSYS_COLOUR_INACTIVECAPTIONTEXT:
        return wxColour([NSColor controlTextColor]);
    case wxSYS_COLOUR_HIGHLIGHT:
        return wxColour([NSColor selectedControlColor]);
    case wxSYS_COLOUR_BTNHIGHLIGHT:
        return wxColour([NSColor controlHighlightColor]);
    case wxSYS_COLOUR_GRAYTEXT:
        return wxColour([NSColor disabledControlTextColor]);
    case wxSYS_COLOUR_3DDKSHADOW:
        return wxColour([NSColor controlShadowColor]);
    case wxSYS_COLOUR_3DLIGHT:
        return wxColour([NSColor controlHighlightColor]);
    case wxSYS_COLOUR_HIGHLIGHTTEXT:
        return wxColour([NSColor selectedControlTextColor]);
    case wxSYS_COLOUR_INFOBK:
        // tooltip (bogus)
        return wxColour([NSColor controlBackgroundColor]);
    case wxSYS_COLOUR_APPWORKSPACE:
        // MDI window color (bogus)
        return wxColour([NSColor windowBackgroundColor]);
    case wxSYS_COLOUR_HOTLIGHT:
        break; // what is this?
    case wxSYS_COLOUR_GRADIENTACTIVECAPTION:
    case wxSYS_COLOUR_GRADIENTINACTIVECAPTION:
        break; // Doesn't really apply to Cocoa.
    case wxSYS_COLOUR_MENUHILIGHT:
        return wxColour([NSColor selectedMenuItemColor]);
    case wxSYS_COLOUR_MAX:
    default:
        if(index>=wxSYS_COLOUR_MAX)
        {
            wxFAIL_MSG(wxT("Invalid system colour index"));
            return wxColour();
        }
    }
    wxFAIL_MSG(wxT("Unimplemented system colour index"));
    return wxColour();
}

// ----------------------------------------------------------------------------
// fonts
// ----------------------------------------------------------------------------

wxFont wxSystemSettingsNative::GetFont(wxSystemFont index)
{
    // Return the system font for now
    {   wxAutoNSAutoreleasePool pool;
        return wxCocoaFontFactory::InstanceForNSFont([NSFont systemFontOfSize:0.0], false);
    }
    switch (index)
    {
        case wxSYS_ANSI_VAR_FONT :
        case wxSYS_SYSTEM_FONT :
        case wxSYS_DEVICE_DEFAULT_FONT :
        case wxSYS_DEFAULT_GUI_FONT :
            {
                return *wxSMALL_FONT ;
                    } ;
            break ;
        case wxSYS_OEM_FIXED_FONT :
        case wxSYS_ANSI_FIXED_FONT :
        case wxSYS_SYSTEM_FIXED_FONT :
        default :
            {
                return *wxNORMAL_FONT ;
                    } ;
            break ;

    }
    return *wxNORMAL_FONT;
}

// ----------------------------------------------------------------------------
// system metrics/features
// ----------------------------------------------------------------------------

// Get a system metric, e.g. scrollbar size
int wxSystemSettingsNative::GetMetric(wxSystemMetric index, wxWindow *WXUNUSED(win))
{
    switch ( index)
    {
        case wxSYS_MOUSE_BUTTONS:
                    return 2; // we emulate a two button mouse (ctrl + click = right button )

        // TODO case wxSYS_BORDER_X:
        // TODO case wxSYS_BORDER_Y:
        // TODO case wxSYS_CURSOR_X:
        // TODO case wxSYS_CURSOR_Y:
        // TODO case wxSYS_DCLICK_X:
        // TODO case wxSYS_DCLICK_Y:
        // TODO case wxSYS_DRAG_X:
        // TODO case wxSYS_DRAG_Y:
        // TODO case wxSYS_EDGE_X:
        // TODO case wxSYS_EDGE_Y:

        case wxSYS_HSCROLL_ARROW_X:
            return 16;
        case wxSYS_HSCROLL_ARROW_Y:
            return 16;
        case wxSYS_HTHUMB_X:
            return 16;

        // TODO case wxSYS_ICON_X:
        // TODO case wxSYS_ICON_Y:
        // TODO case wxSYS_ICONSPACING_X:
        // TODO case wxSYS_ICONSPACING_Y:
        // TODO case wxSYS_WINDOWMIN_X:
        // TODO case wxSYS_WINDOWMIN_Y:
        // TODO case wxSYS_SCREEN_X:
        // TODO case wxSYS_SCREEN_Y:
        // TODO case wxSYS_FRAMESIZE_X:
        // TODO case wxSYS_FRAMESIZE_Y:
        // TODO case wxSYS_SMALLICON_X:
        // TODO case wxSYS_SMALLICON_Y:

        case wxSYS_HSCROLL_Y:
            return 16;
        case wxSYS_VSCROLL_X:
            return 16;
        case wxSYS_VSCROLL_ARROW_X:
            return 16;
        case wxSYS_VSCROLL_ARROW_Y:
            return 16;
        case wxSYS_VTHUMB_Y:
            return 16;

        // TODO case wxSYS_CAPTION_Y:
        // TODO case wxSYS_MENU_Y:
        // TODO case wxSYS_NETWORK_PRESENT:

        case wxSYS_PENWINDOWS_PRESENT:
            return 0;

        // TODO case wxSYS_SHOW_SOUNDS:

        case wxSYS_SWAP_BUTTONS:
            return 0;

        default:
            return -1;  // unsupported metric
    }
    return 0;
}

bool wxSystemSettingsNative::HasFeature(wxSystemFeature index)
{
    switch (index)
    {
        case wxSYS_CAN_ICONIZE_FRAME:
        case wxSYS_CAN_DRAW_FRAME_DECORATIONS:
            return true;

        default:
            return false;
    }
}
