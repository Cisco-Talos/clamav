/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/settings.cpp
// Purpose:     wxSettings
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// TODO: these settings should probably be configurable from some central or
// per-user file, which can be edited using a Windows-control-panel clone.
// Also they should be documented better. Some are very MS Windows-ish.

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/settings.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/gdicmn.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#include <Xm/PushB.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/x11/privx.h"

// To correctly read the resources from the database, we create a
// sample widget. This has the application shell as the parent and
// so will be destroyed when the applicaion is closed.
static Widget but_setting_wid = NULL;

wxColour wxSystemSettingsNative::GetColour(wxSystemColour index)
{
  if (NULL == but_setting_wid && wxTheApp && wxTheApp->GetTopLevelWidget())
  {
    but_setting_wid = XtVaCreateWidget("settings_button", xmPushButtonWidgetClass,
                                       (Widget)wxTheApp->GetTopLevelWidget(), NULL);
  }

  switch (index)
  {
    case wxSYS_COLOUR_WINDOW:
    {
        return *wxWHITE;
    }
    case wxSYS_COLOUR_SCROLLBAR:
      //    case wxSYS_COLOUR_DESKTOP:          // Same as wxSYS_COLOUR_BACKGROUND
    case wxSYS_COLOUR_BACKGROUND:
    case wxSYS_COLOUR_ACTIVECAPTION:
    case wxSYS_COLOUR_INACTIVECAPTION:
    case wxSYS_COLOUR_MENU:
    case wxSYS_COLOUR_MENUBAR:
    case wxSYS_COLOUR_WINDOWFRAME:
    case wxSYS_COLOUR_ACTIVEBORDER:
    case wxSYS_COLOUR_INACTIVEBORDER:
    case wxSYS_COLOUR_BTNFACE:
      //    case wxSYS_COLOUR_3DFACE:           // Same as wxSYS_COLOUR_BTNFACE
    case wxSYS_COLOUR_GRAYTEXT:
    {
        if (but_setting_wid)
        {
            XColor bg;
            XtVaGetValues(but_setting_wid,
                        XtVaTypedArg, XmNbackground, XtRColor, &bg, sizeof(bg),
                        NULL);
            return wxColor((unsigned char)(bg.red >> 8),
                           (unsigned char)(bg.green >> 8),
                           (unsigned char)(bg.blue >> 8));
        }
        else
        {
            return wxColour("LIGHT GREY");
        }
    }
    case wxSYS_COLOUR_BTNSHADOW:
      //    case wxSYS_COLOUR_3DSHADOW:         // Same as wxSYS_COLOUR_BTNSHADOW
    {
        return wxColour("GREY");
    }
    case wxSYS_COLOUR_3DDKSHADOW:
    {
        return *wxBLACK;
    }
    case wxSYS_COLOUR_HIGHLIGHT:
    {
        return *wxBLUE;
    }
    case wxSYS_COLOUR_BTNHIGHLIGHT:
    case wxSYS_COLOUR_LISTBOX:
       //    case wxSYS_COLOUR_3DHIGHLIGHT:      // Same as wxSYS_COLOUR_BTNHIGHLIGHT
    {
        return *wxWHITE;
    }
    case wxSYS_COLOUR_3DLIGHT:
    {
        return wxColour("LIGHT GREY");
    }
    case wxSYS_COLOUR_MENUTEXT:
    case wxSYS_COLOUR_WINDOWTEXT:
    case wxSYS_COLOUR_CAPTIONTEXT:
    case wxSYS_COLOUR_INACTIVECAPTIONTEXT:
    case wxSYS_COLOUR_BTNTEXT:
    case wxSYS_COLOUR_INFOTEXT:
    {
        if (but_setting_wid)
        {
            XColor fg;
            XtVaGetValues(but_setting_wid,
                        XtVaTypedArg, XmNforeground, XtRColor, &fg, sizeof(fg),
                        NULL);
            return wxColor((unsigned char)(fg.red >> 8),
                           (unsigned char)(fg.green >> 8),
                           (unsigned char)(fg.blue >> 8));
        }
        else
        {
            return *wxBLACK;
        }
    }
    case wxSYS_COLOUR_HIGHLIGHTTEXT:
    {
        return *wxWHITE;
    }
    case wxSYS_COLOUR_INFOBK:
    case wxSYS_COLOUR_APPWORKSPACE:
    {
        if (but_setting_wid)
        {
            XColor bg;
            XtVaGetValues(but_setting_wid,
                        XtVaTypedArg, XmNbackground, XtRColor, &bg, sizeof(bg),
                        NULL);
            return wxColor((unsigned char)(bg.red >> 8),
                           (unsigned char)(bg.green >> 8),
                           (unsigned char)(bg.blue >> 8));
        }
        else
        {
            return wxColour("LIGHT GREY");
        }
    }

    case wxSYS_COLOUR_HOTLIGHT:
    case wxSYS_COLOUR_GRADIENTACTIVECAPTION:
    case wxSYS_COLOUR_GRADIENTINACTIVECAPTION:
    case wxSYS_COLOUR_MENUHILIGHT:
        // TODO
        return wxColour("LIGHT GREY");

    default:
    case wxSYS_COLOUR_MAX:
        wxFAIL_MSG( wxT("unknown colour") );
  }
  return *wxWHITE;
}

wxFont wxSystemSettingsNative::GetFont(wxSystemFont index)
{
    int pointSize = 12;

    if (   wxFont::GetDefaultEncoding() == wxFONTENCODING_SHIFT_JIS
        || wxFont::GetDefaultEncoding() == wxFONTENCODING_EUC_JP)
        pointSize = 15;

    wxFont font;

    switch (index)
    {
        case wxSYS_SYSTEM_FIXED_FONT:
        {
            font = wxFont(pointSize, wxMODERN, wxNORMAL, wxNORMAL, false);
            break;
        }
        case wxSYS_DEVICE_DEFAULT_FONT:
        case wxSYS_SYSTEM_FONT:
        case wxSYS_DEFAULT_GUI_FONT:
        default:
        {
            font = wxFont(pointSize, wxSWISS, wxNORMAL, wxNORMAL, false);
            break;
        }
    }

    return font;
}

// Get a system metric, e.g. scrollbar size
int wxSystemSettingsNative::GetMetric(wxSystemMetric index, wxWindow* WXUNUSED(win))
{
    int return_value = 0;

    switch ( index)
    {
        case wxSYS_HSCROLL_Y:
        case wxSYS_VSCROLL_X:
            return 15;

        case wxSYS_SCREEN_X:
            return_value = DisplayWidth( wxGlobalDisplay(), 0 );
            break;
        case wxSYS_SCREEN_Y:
            return_value = DisplayHeight( wxGlobalDisplay(), 0 );
            break;

        // TODO case wxSYS_MOUSE_BUTTONS:
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
        // TODO case wxSYS_HSCROLL_ARROW_X:
        // TODO case wxSYS_HSCROLL_ARROW_Y:
        // TODO case wxSYS_HTHUMB_X:
        // TODO case wxSYS_ICON_X:
        // TODO case wxSYS_ICON_Y:
        // TODO case wxSYS_ICONSPACING_X:
        // TODO case wxSYS_ICONSPACING_Y:
        // TODO case wxSYS_WINDOWMIN_X:
        // TODO case wxSYS_WINDOWMIN_Y:
        // TODO case wxSYS_FRAMESIZE_X:
        // TODO case wxSYS_FRAMESIZE_Y:
        // TODO case wxSYS_SMALLICON_X:
        // TODO case wxSYS_SMALLICON_Y:
        // TODO case wxSYS_VSCROLL_ARROW_X:
        // TODO case wxSYS_VSCROLL_ARROW_Y:
        // TODO case wxSYS_VTHUMB_Y:
        // TODO case wxSYS_CAPTION_Y:
        // TODO case wxSYS_MENU_Y:
        // TODO case wxSYS_NETWORK_PRESENT:
        // TODO case wxSYS_PENWINDOWS_PRESENT:
        // TODO case wxSYS_SHOW_SOUNDS:
        // TODO case wxSYS_SWAP_BUTTONS:

        default:
            return_value = -1; // unsuported metric
    }

    return return_value;
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
