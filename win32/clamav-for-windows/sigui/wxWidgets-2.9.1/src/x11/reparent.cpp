/////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/reparent.cpp
// Purpose:     wxWindow
// Author:      Julian Smart
// Modified by:
// Created:     2002-03-09
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if defined(__BORLANDC__)
#pragma hdrstop
#endif

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#if !wxUSE_NANOX

#include "wx/x11/reparent.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/timer.h"
#endif

#include "wx/evtloop.h"

#include "wx/x11/private.h"
#include "X11/Xatom.h"

#include "wx/generic/private/timer.h"

/*
 * wxAdoptedWindow
 */

wxAdoptedWindow::wxAdoptedWindow()
{
}

wxAdoptedWindow::wxAdoptedWindow(WXWindow window)
{
    m_mainWindow = window;
}

wxAdoptedWindow::~wxAdoptedWindow()
{
}

/*
 * wxReparenter
 */

static bool Xerror;
static Atom WM_STATE = 0;
bool wxReparenter::sm_done = false;
wxAdoptedWindow* wxReparenter::sm_toReparent = NULL;
wxWindow* wxReparenter::sm_newParent = NULL;
wxString wxReparenter::sm_name;
bool wxReparenter::sm_exactMatch = false;

static int ErrorHandler(Display* WXUNUSED(dpy), XErrorEvent* WXUNUSED(event))
{
    Xerror = True;
    return False;
}

// We assume that toReparent has had its X window set
// appropriately.
bool wxReparenter::Reparent(wxWindow* newParent, wxAdoptedWindow* toReparent)
{
    XWindowAttributes xwa;
    Window *children;
    unsigned int numchildren, each;
    Window returnroot, returnparent;
    XErrorHandler old;
    int parentOffset = 0;

    old = XSetErrorHandler(ErrorHandler);
    XReparentWindow( wxGlobalDisplay(),
                     (Window) toReparent->X11GetMainWindow(),
                     (Window) newParent->X11GetMainWindow(),
                     0, 0);

    if (!XQueryTree( wxGlobalDisplay(),
                     (Window) toReparent->X11GetMainWindow(),
                     &returnroot, &returnparent,
                     &children, &numchildren) || Xerror)
    {
        XSetErrorHandler(old);
        return true;
    }

    if (numchildren > 0)
    {
        // TEST: see if we can get away with reparenting just
        // first one
        if (numchildren > 1)
        {
            wxLogDebug(wxT("Found %d, but only reparenting 1 child."), numchildren);
            numchildren = 1;
        }
        wxLogDebug(wxT("Reparenting %d children."), numchildren);
        /* Stacking order is preserved since XQueryTree returns its children in
           bottommost to topmost order
         */
        for (each=0; each<numchildren; each++)
        {
            XGetWindowAttributes( wxGlobalDisplay(),
                                  children[each], &xwa);
            fprintf(stderr,
              "Reparenting child at offset %d and position %d, %d.\n",
               parentOffset, parentOffset+xwa.x, parentOffset+xwa.y);
            XReparentWindow( wxGlobalDisplay(),
                             children[each], (Window) newParent->X11GetMainWindow(),
                             xwa.x, xwa.y);
        }
    }

    XSetErrorHandler(old);
    return true;
}

// Wait for an appropriate window to be created.
// If exactMatch is false, a substring match is OK.
// If windowName is empty, then wait for the next overrideRedirect window.
bool wxReparenter::WaitAndReparent(wxWindow* newParent, wxAdoptedWindow* toReparent,
                                   const wxString& windowName,
                                   bool exactMatch)
{
    sm_newParent = newParent;
    sm_toReparent = toReparent;
    sm_exactMatch = exactMatch;
    sm_name = windowName;

    Display* display = wxGlobalDisplay();
    XSelectInput(display,
        RootWindowOfScreen(DefaultScreenOfDisplay(display)),
        SubstructureNotifyMask);

    if (!WM_STATE)
        WM_STATE = XInternAtom(display, "WM_STATE", False);

    sm_done = false;

    wxEventLoop eventLoop;
    while (!sm_done)
    {
        if (eventLoop.Pending())
        {
            XEvent xevent;
            XNextEvent(display, & xevent);
            if (!wxTheApp->ProcessXEvent((WXEvent*) & xevent))
            {
                // Do the local event processing
                ProcessXEvent((WXEvent*) & xevent);
            }
        }
        else
        {
#if wxUSE_TIMER
            wxGenericTimerImpl::NotifyTimers();
            wxTheApp->ProcessIdle();
#endif
        }
    }
    return true;
}

bool wxReparenter::ProcessXEvent(WXEvent* event)
{
    XEvent* xevent = (XEvent*) event;
    Window client;

    if (!sm_done)
    {
        if (xevent->type == MapNotify)
        {
            wxLogDebug(wxT("Window was mapped"));
        }

        if (xevent->type == MapNotify && !xevent->xmap.override_redirect &&
            (client = (Window) FindAClientWindow((WXWindow) xevent->xmap.window, sm_name)))
        {
            wxLogDebug(wxT("Found a client window, about to reparent"));
            wxASSERT(sm_toReparent->GetParent() == NULL);

            sm_toReparent->SetHandle((WXWindow) client);
            sm_newParent->AddChild(sm_toReparent);
            sm_done = Reparent(sm_newParent, sm_toReparent);
            return sm_done;
        } else if (xevent->type == MapNotify &&
                   xevent->xmap.override_redirect &&
                   xevent->xmap.window)
        {
            wxLogDebug(wxT("Found an override redirect window, about to reparent"));
            sm_toReparent->SetHandle((WXWindow) xevent->xmap.window);
            sm_newParent->AddChild(sm_toReparent);
            wxASSERT(sm_toReparent->GetParent() == NULL);

            sm_done = Reparent(sm_newParent, sm_toReparent);
            return sm_done;
        }
    }
    return false;
}

WXWindow wxReparenter::FindAClientWindow(WXWindow window, const wxString& name)
{
    int rvalue, i;
    Atom actualtype;
    int actualformat;
    unsigned long nitems, bytesafter;
    unsigned char *propreturn;
    Window *children;
    unsigned int numchildren;
    Window returnroot, returnparent;
    Window result = 0;
    XErrorHandler old;
    char *clientName;

    Xerror = False;
    old = XSetErrorHandler(ErrorHandler);
    rvalue = XGetWindowProperty((Display*) wxGetDisplay(),
        (Window) window, WM_STATE,
        0, 1, False,
        AnyPropertyType, &actualtype, &actualformat,
        &nitems, &bytesafter, &propreturn);

    XSetErrorHandler(old);

    if (!Xerror && rvalue == Success && actualtype != None)
    {
        if (rvalue == Success)
        {
            XFree((char *) propreturn);
        }
        XFetchName((Display*) wxGetDisplay(), (Window) window, &clientName);

        wxString str1(name);
        wxString str2 = wxString::FromAscii(clientName);
        str1.Lower();
        str2.Lower();

        bool matches;
        if (sm_exactMatch)
            matches = (name == wxString::FromAscii(clientName));
        else
            matches = (str1.Contains(str2) || str2.Contains(str1));

        XFree(clientName);

        if (matches)
            return (WXWindow) window;
        else
            return NULL;
    }

    old = XSetErrorHandler(ErrorHandler);
    if (!XQueryTree((Display*) wxGetDisplay(), (Window) window, &returnroot, &returnparent,
        &children, &numchildren) || Xerror)
    {
        XSetErrorHandler(old);
        return NULL;
    }
    XSetErrorHandler(old);

    result = 0;
    for (i=0; i<(int)numchildren && !result ;i++) {
        result = (Window) FindAClientWindow((WXWindow) children[i], name);
    }
    if (numchildren) {
        XFree((char *) children);
    } return (WXWindow) result;
}

#endif // !wxUSE_NANOX
