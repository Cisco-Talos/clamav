/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/dcscreen.cpp
// Purpose:     wxScreenDCImpl class
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/window.h"
    #include "wx/frame.h"
    #include "wx/dcscreen.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"
#include "wx/motif/dcscreen.h"

IMPLEMENT_ABSTRACT_CLASS(wxScreenDCImpl, wxWindowDCImpl)

WXWindow wxScreenDCImpl::sm_overlayWindow = 0;
int wxScreenDCImpl::sm_overlayWindowX = 0;
int wxScreenDCImpl::sm_overlayWindowY = 0;

// Create a DC representing the whole screen
wxScreenDCImpl::wxScreenDCImpl(wxScreenDC *owner)
              : wxWindowDCImpl(owner)
{
    m_display = wxGetDisplay();
    Display* display = (Display*) m_display;

    if (sm_overlayWindow)
    {
        m_pixmap = sm_overlayWindow;
        m_deviceOriginX = - sm_overlayWindowX;
        m_deviceOriginY = - sm_overlayWindowY;
    }
    else
        m_pixmap = (WXPixmap) RootWindow(display, DefaultScreen(display));

    XGCValues gcvalues;
    gcvalues.foreground = BlackPixel (display, DefaultScreen (display));
    gcvalues.background = WhitePixel (display, DefaultScreen (display));
    gcvalues.graphics_exposures = False;
    gcvalues.subwindow_mode = IncludeInferiors;
    gcvalues.line_width = 1;
    m_gc = XCreateGC (display, RootWindow (display, DefaultScreen (display)),
        GCForeground | GCBackground | GCGraphicsExposures | GCLineWidth | GCSubwindowMode,
        &gcvalues);

    m_backgroundPixel = gcvalues.background;
    m_ok = true;
}

wxScreenDCImpl::~wxScreenDCImpl()
{
    EndDrawingOnTop();
}

bool wxScreenDCImpl::StartDrawingOnTop(wxWindow* window)
{
    wxRect rect;
    int x, y, width, height;
    window->GetPosition(& x, & y);
    if (window->GetParent() && !window->IsKindOf(CLASSINFO(wxFrame)))
        window->GetParent()->ClientToScreen(& x, & y);
    window->GetSize(& width, & height);
    rect.x = x; rect.y = y;
    rect.width = width; rect.height = height;

    return StartDrawingOnTop(& rect);
}

bool wxScreenDCImpl::StartDrawingOnTop(wxRect* rect)
{
    if (sm_overlayWindow)
        return false;

    Display *dpy = (Display*) wxGetDisplay();
    Pixmap screenPixmap = RootWindow(dpy, DefaultScreen(dpy));

    int x = 0;
    int y = 0;
    int width, height;
    wxDisplaySize(&width, &height);

    if (rect)
    {
        x = rect->x; y = rect->y;
        width = rect->width; height = rect->height;
    }
    sm_overlayWindowX = x;
    sm_overlayWindowY = y;

    XSetWindowAttributes attributes;
    attributes.override_redirect = True;
    unsigned long valueMask = CWOverrideRedirect;

    sm_overlayWindow = (WXWindow) XCreateWindow(dpy, screenPixmap, x, y, width, height, 0,
        wxDisplayDepth(), InputOutput,
        DefaultVisual(dpy, 0), valueMask,
        & attributes);

    if (sm_overlayWindow)
    {
        XMapWindow(dpy, (Window) sm_overlayWindow);
        return true;
    }
    else
        return false;
}

bool wxScreenDCImpl::EndDrawingOnTop()
{
    if (sm_overlayWindow)
    {
        XDestroyWindow((Display*) wxGetDisplay(), (Window) sm_overlayWindow);
        sm_overlayWindow = 0;
        return true;
    }
    else
        return false;
}
