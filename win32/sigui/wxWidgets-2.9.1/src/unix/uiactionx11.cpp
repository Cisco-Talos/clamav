/////////////////////////////////////////////////////////////////////////////
// Name:        src/unix/uiactionx11.cpp
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

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/extensions/XTest.h>

void SendButtonEvent(int button, bool isDown)
{
    int xbutton = 0;
    switch (button)
    {
        case wxMOUSE_BTN_LEFT:
            xbutton = 1;
            break;
        case wxMOUSE_BTN_RIGHT:
            xbutton = 2;
            break;
        case wxMOUSE_BTN_MIDDLE:
            xbutton = 3;
            break;
        default:
            wxFAIL_MSG("Unsupported button passed in.");
    }

    XEvent event;

    Display *display = XOpenDisplay(0);
    wxASSERT_MSG(display, "No display available!");

    memset(&event, 0x00, sizeof(event));

    if (isDown)
        event.type = ButtonPress;
    else
        event.type = ButtonRelease;

    event.xbutton.button = xbutton;
    event.xbutton.same_screen = True;

    XQueryPointer(display, RootWindow(display, DefaultScreen(display)), &event.xbutton.root, &event.xbutton.window, &event.xbutton.x_root, &event.xbutton.y_root, &event.xbutton.x, &event.xbutton.y, &event.xbutton.state);
    event.xbutton.subwindow = event.xbutton.window;

    while (event.xbutton.subwindow)
    {
        event.xbutton.window = event.xbutton.subwindow;
        XQueryPointer(display, event.xbutton.window, &event.xbutton.root, &event.xbutton.subwindow, &event.xbutton.x_root, &event.xbutton.y_root, &event.xbutton.x, &event.xbutton.y, &event.xbutton.state);
    }

    XSendEvent(display, PointerWindow, True, 0xfff, &event);
    XFlush(display);
    XCloseDisplay(display);
}

bool wxUIActionSimulator::MouseDown(int button)
{
    SendButtonEvent(button, true);
    return true;
}

bool wxUIActionSimulator::MouseMove(long x, long y)
{
    Display *display = XOpenDisplay(0);
    wxASSERT_MSG(display, "No display available!");
    Window root = DefaultRootWindow(display);
    XWarpPointer(display, None, root, 0, 0, 0, 0, x, y);
    XFlush(display);
    XCloseDisplay(display);
    return true;
}

bool wxUIActionSimulator::MouseUp(int button)
{
    SendButtonEvent(button, false);
    return true;
}

bool wxUIActionSimulator::Key(int keycode, bool isDown, bool WXUNUSED(shiftDown), bool WXUNUSED(cmdDown), bool WXUNUSED(altDown))
{
    Display *display = XOpenDisplay(0);
    wxASSERT_MSG(display, "No display available!");

    XKeyEvent event;
    int mask = 0xfff;
    memset(&event, 0x00, sizeof(event));

    if (isDown) {
        event.type = KeyPress;
        mask = KeyPressMask;
    }
    else {
        event.type = KeyRelease;
        mask = KeyReleaseMask;
    }
    event.same_screen = True;

    XQueryPointer(display, RootWindow(display, DefaultScreen(display)), &event.root, &event.window, &event.x_root, &event.y_root, &event.x, &event.y, &event.state);
    event.subwindow = event.window;

    while (event.subwindow)
    {
        event.window = event.subwindow;
        XQueryPointer(display, event.window, &event.root, &event.subwindow, &event.x_root, &event.y_root, &event.x, &event.y, &event.state);
    }

    XSendEvent(display, PointerWindow, True, mask, (XEvent*) &event);
    XFlush(display);
    XCloseDisplay(display);

    return true;
}

#endif // wxUSE_UIACTIONSIMULATOR
