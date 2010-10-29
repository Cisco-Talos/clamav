/////////////////////////////////////////////////////////////////////////
// File:        src/palmos/taskbar.cpp
// Purpose:     Implements wxTaskBarIcon class for manipulating icons on
//              the task bar.
// Author:      Julian Smart
// Modified by: Vaclav Slavik
// Created:     24/3/98
// RCS-ID:      $Id$
// Copyright:   (c)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_TASKBARICON

#ifndef WX_PRECOMP
    #include "wx/window.h"
    #include "wx/frame.h"
    #include "wx/utils.h"
    #include "wx/menu.h"
#endif

#if defined(__WIN95__)

#include <string.h>
#include "wx/taskbar.h"

IMPLEMENT_DYNAMIC_CLASS(wxTaskBarIcon, wxEvtHandler)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxTaskBarIconWindow: helper window
// ----------------------------------------------------------------------------

// NB: this class serves two purposes:
//     1. win32 needs a HWND associated with taskbar icon, this provides it
//     2. we need wxTopLevelWindow so that the app doesn't exit when
//        last frame is closed but there still is a taskbar icon
class wxTaskBarIconWindow : public wxFrame
{
public:
    wxTaskBarIconWindow(wxTaskBarIcon *icon)
        : wxFrame(NULL, wxID_ANY, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0),
          m_icon(icon)
    {
    }

    WXLRESULT MSWWindowProc(WXUINT msg,
                            WXWPARAM wParam, WXLPARAM lParam)
    {
        return 0;
    }

private:
    wxTaskBarIcon *m_icon;
};

// ----------------------------------------------------------------------------
// wxTaskBarIcon
// ----------------------------------------------------------------------------

wxTaskBarIcon::wxTaskBarIcon()
{
}

wxTaskBarIcon::~wxTaskBarIcon()
{
}

// Operations
bool wxTaskBarIcon::SetIcon(const wxIcon& icon, const wxString& tooltip)
{
    return false;
}

bool wxTaskBarIcon::RemoveIcon()
{
    return false;
}

bool wxTaskBarIcon::PopupMenu(wxMenu *menu)
{
    return false;
}

void wxTaskBarIcon::RegisterWindowMessages()
{
}

// ----------------------------------------------------------------------------
// wxTaskBarIcon window proc
// ----------------------------------------------------------------------------

long wxTaskBarIcon::WindowProc(unsigned int msg,
                               unsigned int WXUNUSED(wParam),
                               long lParam)
{
    return 0;
}

#endif // __WIN95__

#endif // wxUSE_TASKBARICON
