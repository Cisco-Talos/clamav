/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/settings.cpp
// Purpose:     wxSystemSettings implementation
// Author:      Vaclav Slavik
// Created:     2006-08-08
// RCS-ID:      $Id$
// Copyright:   (c) 2006 REA Elektronik GmbH
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/settings.h"

#ifndef WX_PRECOMP
    #include "wx/colour.h"
    #include "wx/font.h"
    #include "wx/gdicmn.h"
#endif


wxColour wxSystemSettingsNative::GetColour(wxSystemColour WXUNUSED(index))
{
    // overridden by wxSystemSettings::GetColour in wxUniversal
    return wxColour(0,0,0);
}

wxFont wxSystemSettingsNative::GetFont(wxSystemFont index)
{
    switch (index)
    {
        case wxSYS_OEM_FIXED_FONT:
        case wxSYS_ANSI_FIXED_FONT:
        case wxSYS_SYSTEM_FIXED_FONT:
        {
            // FIXME_DFB
            return wxFont(12,
                          wxFONTFAMILY_TELETYPE,
                          wxFONTSTYLE_NORMAL,
                          wxFONTWEIGHT_NORMAL);
        }

        case wxSYS_ANSI_VAR_FONT:
        case wxSYS_SYSTEM_FONT:
        case wxSYS_DEVICE_DEFAULT_FONT:
        case wxSYS_DEFAULT_GUI_FONT:
        {
            // FIXME_DFB
            return wxFont(12,
                          wxFONTFAMILY_DEFAULT,
                          wxFONTSTYLE_NORMAL,
                          wxFONTWEIGHT_NORMAL);
        }

        default:
            wxFAIL_MSG( "unknown font type" );
            return wxNullFont;
    }
}

int wxSystemSettingsNative::GetMetric(wxSystemMetric index,
                                      wxWindow* WXUNUSED(win))
{
    int val;

    switch (index)
    {
        case wxSYS_SCREEN_X:
            wxDisplaySize(&val, NULL);
            return val;
        case wxSYS_SCREEN_Y:
            wxDisplaySize(NULL, &val);
            return val;

        default:
            return -1;
    }
}

bool wxSystemSettingsNative::HasFeature(wxSystemFeature index)
{
    switch (index)
    {
        case wxSYS_CAN_ICONIZE_FRAME:
        case wxSYS_CAN_DRAW_FRAME_DECORATIONS:
        case wxSYS_TABLET_PRESENT:
            return false;

        default:
            wxFAIL_MSG( "unknown feature" );
            return false;
    }
}
