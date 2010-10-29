/////////////////////////////////////////////////////////////////////////////
// Name:        src/osx/uiaction_osx.cpp
// Purpose:     wxUIActionSimulator implementation
// Author:      Kevin Ollivier
// Modified by:
// Created:     2010-03-06
// RCS-ID:      $Id: menu.cpp 54129 2008-06-11 19:30:52Z SC $
// Copyright:   (c) Kevin Ollivier
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/defs.h"

#if wxUSE_UIACTIONSIMULATOR

#include "wx/uiaction.h"

#include <ApplicationServices/ApplicationServices.h>

CGEventTapLocation tap = kCGSessionEventTap;

CGEventType CGEventTypeForMouseButton(int button, bool isDown)
{
    switch (button)
    {
        case wxMOUSE_BTN_LEFT:
            if (isDown)
                return kCGEventLeftMouseDown;
            else
                return kCGEventLeftMouseUp;
        case wxMOUSE_BTN_RIGHT:
            if (isDown)
                return kCGEventRightMouseDown;
            else
                return kCGEventRightMouseUp;

        // Apparently all other buttons use the constant OtherMouseDown

        default:
            if (isDown)
                return kCGEventOtherMouseDown;
            else
                return kCGEventOtherMouseUp;
    }
}

void SendCharCode(CGCharCode keycode, bool isDown)
{
    CGEventRef event = CGEventCreateKeyboardEvent(NULL, keycode, isDown);
    if (event)
    {
        CGEventPost(kCGHIDEventTap, event);
    }
    CFRelease(event);
}

bool wxUIActionSimulator::MouseDown(int button)
{
    CGPoint pos;
    int x, y;
    wxGetMousePosition(&x, &y);
    pos.x = x;
    pos.y = y;
    CGEventType type = CGEventTypeForMouseButton(button, true);
    CGEventRef event = CGEventCreateMouseEvent(NULL, type, pos, button);
    CGEventSetType(event, type);

    if (event)
    {
        CGEventPost(tap, event);
    }
    CFRelease(event);
    return true;
}

bool wxUIActionSimulator::MouseMove(long x, long y)
{
    CGPoint pos;
    pos.x = x;
    pos.y = y;
    CGEventType type = kCGEventMouseMoved;
    CGEventRef event = CGEventCreateMouseEvent(NULL, type, pos, kCGMouseButtonLeft);
    CGEventSetType(event, type);

    if (event)
    {
        CGEventPost(tap, event);
    }
    CFRelease(event);

    return true;
}

bool wxUIActionSimulator::MouseUp(int button)
{
    CGPoint pos;
    int x, y;
    wxGetMousePosition(&x, &y);
    pos.x = x;
    pos.y = y;
    CGEventType type = CGEventTypeForMouseButton(button, false);
    CGEventRef event = CGEventCreateMouseEvent(NULL, type, pos, button);
    CGEventSetType(event, type);

    if (event)
    {
        CGEventPost(tap, event);
    }
    CFRelease(event);

    return true;
}

bool wxUIActionSimulator::Key(int keycode, bool isDown, bool shiftDown, bool cmdDown, bool altDown)
{
    if (shiftDown)
        SendCharCode((CGCharCode)56, true);
    if (altDown)
        SendCharCode((CGCharCode)58, true);
    if (cmdDown)
        SendCharCode((CGCharCode)55, true);

    SendCharCode((CGCharCode)keycode, isDown);

    if (shiftDown)
        SendCharCode((CGCharCode)56, false);
    if (altDown)
        SendCharCode((CGCharCode)58, false);
    if (cmdDown)
        SendCharCode((CGCharCode)55, false);

    return true;
}

#endif // wxUSE_UIACTIONSIMULATOR

