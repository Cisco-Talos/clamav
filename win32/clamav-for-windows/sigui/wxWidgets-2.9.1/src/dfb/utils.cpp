/////////////////////////////////////////////////////////////////////////////
// Name:        src/dfb/utils.cpp
// Purpose:     Miscellaneous utility functions and classes
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

#include "wx/utils.h"
#include "wx/evtloop.h"
#include "wx/apptrait.h"
#include "wx/unix/execute.h"
#include "wx/unix/private/timer.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif

#include "wx/dfb/private.h"
#include <directfb_version.h>

// ----------------------------------------------------------------------------
// toolkit info
// ----------------------------------------------------------------------------

wxPortId wxGUIAppTraits::GetToolkitVersion(int *verMaj, int *verMin) const
{
    if ( verMaj ) *verMaj = DIRECTFB_MAJOR_VERSION;
    if ( verMin ) *verMaj = DIRECTFB_MINOR_VERSION;

    return wxPORT_DFB;
}


wxEventLoopBase* wxGUIAppTraits::CreateEventLoop()
{
    return new wxEventLoop;
}

wxTimerImpl *wxGUIAppTraits::CreateTimerImpl(wxTimer *timer)
{
    return new wxUnixTimerImpl(timer);
}

// ----------------------------------------------------------------------------
// display characteristics
// ----------------------------------------------------------------------------

bool wxColourDisplay()
{
    #warning "FIXME: wxColourDisplay"
    return true;
}

int wxDisplayDepth()
{
    return wxTheApp->GetDisplayMode().bpp;
}

void wxDisplaySize(int *width, int *height)
{
    wxVideoMode mode(wxTheApp->GetDisplayMode());
    if ( width ) *width = mode.w;
    if ( height ) *height = mode.h;
}

void wxDisplaySizeMM(int *width, int *height)
{
    // FIXME: there's no way to get physical resolution using the DirectDB
    //        API, we hardcode a commonly used value of 72dpi
    #define DPI          72.0
    #define PX_TO_MM(x)  (int(((x) / DPI) * inches2mm))

    wxDisplaySize(width, height);
    if ( width ) *width = PX_TO_MM(*width);
    if ( height ) *height = PX_TO_MM(*height);

    #undef DPI
    #undef PX_TO_MM
}

void wxClientDisplayRect(int *x, int *y, int *width, int *height)
{
    // return desktop dimensions minus any panels, menus, trays:
    if (x) *x = 0;
    if (y) *y = 0;
    wxDisplaySize(width, height);
}


//-----------------------------------------------------------------------------
// mouse
//-----------------------------------------------------------------------------

void wxGetMousePosition(int *x, int *y)
{
    wxIDirectFBDisplayLayerPtr layer(wxIDirectFB::Get()->GetDisplayLayer());
    if ( layer )
        layer->GetCursorPosition(x, y);
}

wxPoint wxGetMousePosition()
{
    wxPoint pt;
    wxGetMousePosition(&pt.x, &pt.y);
    return pt;
}

//-----------------------------------------------------------------------------
// keyboard
//-----------------------------------------------------------------------------

bool wxGetKeyState(wxKeyCode key)
{
    wxASSERT_MSG(key != WXK_LBUTTON && key != WXK_RBUTTON && key != WXK_MBUTTON,
                 "can't use wxGetKeyState() for mouse buttons");

    return false; // FIXME
}

//----------------------------------------------------------------------------
// misc.
//----------------------------------------------------------------------------

void wxBell()
{
}
