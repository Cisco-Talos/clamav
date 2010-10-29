/////////////////////////////////////////////////////////////////////////////
// Name:        src/msw/uiaction.cpp
// Purpose:     wxUIActionSimulator implementation
// Author:      Kevin Ollivier
// Modified by:
// Created:     2010-03-06
// RCS-ID:      $Id: menu.cpp 54129 2008-06-11 19:30:52Z SC $
// Copyright:   (c) Kevin Ollivier
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_UIACTIONSIMULATOR

#include "wx/uiaction.h"

#include "wx/msw/wrapwin.h"

DWORD EventTypeForMouseButton(int button, bool isDown)
{
    switch (button)
    {
        case wxMOUSE_BTN_LEFT:
            if (isDown)
                return MOUSEEVENTF_LEFTDOWN;
            else
                return MOUSEEVENTF_LEFTUP;
        case wxMOUSE_BTN_RIGHT:
            if (isDown)
                return MOUSEEVENTF_RIGHTDOWN;
            else
                return MOUSEEVENTF_RIGHTUP;
        case wxMOUSE_BTN_MIDDLE:
            if (isDown)
                return MOUSEEVENTF_MIDDLEDOWN;
            else
                return MOUSEEVENTF_MIDDLEUP;

        default:
            wxFAIL_MSG("Unsupported button passed in.");
            return -1;
    }
}

bool wxUIActionSimulator::MouseDown(int button)
{
    POINT p;
    GetCursorPos(&p);
    mouse_event(EventTypeForMouseButton(button, true), p.x, p.y, 0, 0);
    return true;
}

bool wxUIActionSimulator::MouseMove(long x, long y)
{
    mouse_event(MOUSEEVENTF_MOVE, x, y, 0, 0);
    return true;
}

bool wxUIActionSimulator::MouseUp(int button)
{
    POINT p;
    GetCursorPos(&p);
    mouse_event(EventTypeForMouseButton(button, false), p.x, p.y, 0, 0);
    return true;
}

bool wxUIActionSimulator::Key(int keycode, bool isDown, bool shiftDown, bool cmdDown, bool altDown)
{
    DWORD flags = 0;
    if (!isDown)
        flags = KEYEVENTF_KEYUP;
    keybd_event(keycode, 0, flags, 0);
    return true;
}

#endif // wxUSE_UIACTIONSIMULATOR
