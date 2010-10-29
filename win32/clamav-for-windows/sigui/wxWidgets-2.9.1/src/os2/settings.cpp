/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/settings.cpp
// Purpose:     wxSettings
// Author:      David Webster
// Modified by:
// Created:     10/15/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include <stdio.h>
    #include "wx/pen.h"
    #include "wx/brush.h"
    #include "wx/gdicmn.h"
    #include "wx/window.h"
    #include "wx/settings.h"
    #include "wx/module.h"
#endif

#include "wx/fontutil.h"

#include "wx/os2/private.h"

// the module which is used to clean up wxSystemSettings data (this is a
// singleton class so it can't be done in the dtor)
class wxSystemSettingsModule : public wxModule
{
    friend class wxSystemSettings;
public:
    virtual bool OnInit();
    virtual void OnExit();

private:
    DECLARE_DYNAMIC_CLASS(wxSystemSettingsModule)

    static wxArrayString   sm_optionNames;
    static wxArrayString   sm_optionValues;
};

// ----------------------------------------------------------------------------
// global data
// ----------------------------------------------------------------------------

static wxFont *gs_fontDefault = NULL;

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxSystemSettingsModule
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxSystemSettingsModule, wxModule)

wxArrayString wxSystemSettingsModule::sm_optionNames;
wxArrayString wxSystemSettingsModule::sm_optionValues;

bool wxSystemSettingsModule::OnInit()
{
    return true;
}

void wxSystemSettingsModule::OnExit()
{
    sm_optionNames.Clear();
    sm_optionValues.Clear();
    wxDELETE(gs_fontDefault);
}

wxColour wxSystemSettingsNative::GetColour(
  wxSystemColour                    nIndex
)
{
    COLORREF                        vRef;
    wxColour                        vCol;
    LONG                            vSysClr;
    switch (nIndex)
    {
        //
        // PM actually has values for these
        //
        case wxSYS_COLOUR_WINDOW:
            vSysClr = SYSCLR_WINDOW;
            break;

        case wxSYS_COLOUR_WINDOWFRAME:
            vSysClr = SYSCLR_WINDOWFRAME;
            break;

        case wxSYS_COLOUR_MENUTEXT:
            vSysClr = SYSCLR_MENUTEXT;
            break;

        case wxSYS_COLOUR_MENUHILIGHT:
            vSysClr = SYSCLR_MENUHILITE;
            break;

        case wxSYS_COLOUR_BTNFACE:
            vSysClr = SYSCLR_BUTTONMIDDLE;
            break;

        case wxSYS_COLOUR_BTNSHADOW:
            vSysClr = SYSCLR_BUTTONDARK;
            break;

        case wxSYS_COLOUR_BTNHIGHLIGHT:
            vSysClr = SYSCLR_BUTTONLIGHT;
            break;

        case wxSYS_COLOUR_BACKGROUND:
            vSysClr = SYSCLR_BACKGROUND;
            break;

        case wxSYS_COLOUR_APPWORKSPACE:
            vSysClr = SYSCLR_APPWORKSPACE;
            break;

        case wxSYS_COLOUR_MENUBAR:
        case wxSYS_COLOUR_MENU:
            vSysClr = SYSCLR_MENU;
            break;

        case wxSYS_COLOUR_INACTIVECAPTION:
            vSysClr = SYSCLR_INACTIVETITLE;
            break;

        case wxSYS_COLOUR_INACTIVEBORDER:
            vSysClr = SYSCLR_INACTIVEBORDER;
            break;

        case wxSYS_COLOUR_LISTBOX:
            vSysClr = SYSCLR_ENTRYFIELD;
            break;

        case wxSYS_COLOUR_CAPTIONTEXT:
            vSysClr = SYSCLR_TITLETEXT;
            break;

        case wxSYS_COLOUR_INACTIVECAPTIONTEXT:
            vSysClr = SYSCLR_INACTIVETITLETEXT;
            break;

        case wxSYS_COLOUR_WINDOWTEXT:
        case wxSYS_COLOUR_BTNTEXT:
            vSysClr = SYSCLR_WINDOWTEXT;
            break;

        case wxSYS_COLOUR_INFOTEXT:
            vSysClr = SYSCLR_HELPTEXT;
            break;

        case wxSYS_COLOUR_ACTIVECAPTION:
            vSysClr = SYSCLR_ACTIVETITLE;
            break;

        case wxSYS_COLOUR_ACTIVEBORDER:
            vSysClr = SYSCLR_ACTIVEBORDER;
            break;

        case wxSYS_COLOUR_HIGHLIGHT:
            vSysClr = SYSCLR_HILITEBACKGROUND;
            break;

        case wxSYS_COLOUR_SCROLLBAR:
            vSysClr = SYSCLR_SCROLLBAR;
            break;

        case wxSYS_COLOUR_HIGHLIGHTTEXT:
            vSysClr = SYSCLR_HILITEFOREGROUND;
            break;

        case wxSYS_COLOUR_INFOBK:
            vSysClr = SYSCLR_HELPBACKGROUND;
            break;

        // Don't know what these should be, so leave them grey (normally)
        case wxSYS_COLOUR_GRAYTEXT:
        case wxSYS_COLOUR_3DDKSHADOW:
        case wxSYS_COLOUR_3DLIGHT:
        case wxSYS_COLOUR_HOTLIGHT:
        case wxSYS_COLOUR_GRADIENTACTIVECAPTION:
        case wxSYS_COLOUR_GRADIENTINACTIVECAPTION:
            vSysClr = SYSCLR_BUTTONMIDDLE;
            break;

        default:
            vSysClr = SYSCLR_WINDOW;
            break;
    }
    vRef = (ULONG)::WinQuerySysColor(   HWND_DESKTOP,
                                        vSysClr,
                                        0L  );
    vCol.Set(   GetRValue(vRef),
                GetGValue(vRef),
                GetBValue(vRef)  );
    return(vCol);
} // end of wxSystemSettingsNative::GetColour

// ----------------------------------------------------------------------------
// fonts
// ----------------------------------------------------------------------------

wxFont wxSystemSettingsNative::GetFont(
  wxSystemFont                      index
)
{
    const bool isDefaultRequested = index == wxSYS_DEFAULT_GUI_FONT;
    if ( isDefaultRequested )
    {
        if ( gs_fontDefault )
            return *gs_fontDefault;
    }

    wxFont font;
    // FIXME: The mapping could be improved and also OS/2 system fonts
    // should be taken into account e.g. by using PrfQueryProfileString
    // to look for PM_System_Fonts in HINI_USERPROFILE.
    // FIXME2: Creating a font from the native font info does not
    // seem to work properly.
    switch (index)
    {
        case wxSYS_SYSTEM_FIXED_FONT:
        case wxSYS_OEM_FIXED_FONT:
        case wxSYS_ANSI_FIXED_FONT:
                font.Create(  10,
                              wxFONTFAMILY_TELETYPE,
                              wxFONTSTYLE_NORMAL,
                              wxFONTWEIGHT_NORMAL   );
                break;
        case wxSYS_ANSI_VAR_FONT:
                font.Create(  10,
                              wxFONTFAMILY_MODERN,
                              wxFONTSTYLE_NORMAL,
                              wxFONTWEIGHT_NORMAL   );
                break;
        case wxSYS_SYSTEM_FONT:
        case wxSYS_DEFAULT_GUI_FONT:
                font.Create(  10,
                              wxFONTFAMILY_SWISS,
                              wxFONTSTYLE_NORMAL,
                              wxFONTWEIGHT_NORMAL   );
                break;
        default:
                wxFAIL_MSG( wxT("stock font not found") );
                return GetFont(wxSYS_ANSI_VAR_FONT);
    }


    if ( isDefaultRequested )
    {
        // if we got here it means we hadn't cached it yet - do now
        gs_fontDefault = new wxFont(font);
    }

    return font;
}

// Get a system metric, e.g. scrollbar size
int wxSystemSettingsNative::GetMetric( wxSystemMetric index,
                                       wxWindow*      WXUNUSED(win) )
{
    switch ( index)
    {
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

        case wxSYS_SCREEN_X:
            return ::WinQuerySysValue(HWND_DESKTOP,SV_CXSCREEN);
        case wxSYS_SCREEN_Y:
            return ::WinQuerySysValue(HWND_DESKTOP,SV_CYSCREEN);

        // TODO case wxSYS_FRAMESIZE_X:
        // TODO case wxSYS_FRAMESIZE_Y:
        // TODO case wxSYS_SMALLICON_X:
        // TODO case wxSYS_SMALLICON_Y:

        case wxSYS_HSCROLL_Y:
            return ::WinQuerySysValue(HWND_DESKTOP,SV_CYHSCROLL);
        case wxSYS_VSCROLL_X:
            return ::WinQuerySysValue(HWND_DESKTOP,SV_CXVSCROLL);

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
            break;
    }
    return -1;  // unsupported metric
}

bool wxSystemSettingsNative::HasFeature( wxSystemFeature index )
{
    switch (index)
    {
        case wxSYS_CAN_ICONIZE_FRAME:
            return true;

        // TODO case wxSYS_CAN_DRAW_FRAME_DECORATIONS:
        // TODO case wxSYS_TABLET_PRESENT:

        default:
            break;
    }

    return false;
}
