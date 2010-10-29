///////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/tooltip.cpp
// Purpose:     wxToolTip class implementation for Palm OS
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/wx.h"
#endif

#if wxUSE_TOOLTIPS

#include "wx/tooltip.h"
#include "wx/palmos/private.h"

#include "wx/palmos/wrapcctl.h"

// VZ: normally, the trick with subclassing the tooltip control and processing
//     TTM_WINDOWFROMPOINT should work but, somehow, it doesn't. I leave the
//     code here for now (but it's not compiled) in case we need it later.
//
//     For now I use an ugly workaround and process TTN_NEEDTEXT directly in
//     radio button wnd proc - fixing TTM_WINDOWFROMPOINT code would be nice
//     because it would then work for all controls, not only radioboxes but for
//     now I don't understand what's wrong with it...
#define wxUSE_TTM_WINDOWFROMPOINT   0

// ----------------------------------------------------------------------------
// global variables
// ----------------------------------------------------------------------------

// the tooltip parent window
WXHWND wxToolTip::ms_hwndTT = (WXHWND)NULL;

#if wxUSE_TTM_WINDOWFROMPOINT

// the tooltip window proc
static WNDPROC gs_wndprocToolTip = (WNDPROC)NULL;

#endif // wxUSE_TTM_WINDOWFROMPOINT

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

// send a message to the tooltip control
inline LRESULT SendTooltipMessage(WXHWND hwnd,
                                  UINT msg,
                                  WPARAM wParam,
                                  void *lParam)
{
    return 0;
}

// send a message to all existing tooltip controls
static void SendTooltipMessageToAll(WXHWND hwnd,
                                    UINT msg,
                                    WPARAM wParam,
                                    LPARAM lParam)
{
}

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// static functions
// ----------------------------------------------------------------------------

void wxToolTip::Enable(bool flag)
{
}

void wxToolTip::SetDelay(long milliseconds)
{
}

void wxToolTip::SetAutoPop( long WXUNUSED(milliseconds) )
{
}

void wxToolTip::SetReshow( long WXUNUSED(milliseconds) )
{
}

// ---------------------------------------------------------------------------
// implementation helpers
// ---------------------------------------------------------------------------

// create the tooltip ctrl for our parent frame if it doesn't exist yet
WXHWND wxToolTip::GetToolTipCtrl()
{
    return (WXHWND) 0;
}

void wxToolTip::RelayEvent(WXMSG *msg)
{
}

// ----------------------------------------------------------------------------
// ctor & dtor
// ----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxToolTip, wxObject)

wxToolTip::wxToolTip(const wxString &tip)
         : m_text(tip)
{
}

wxToolTip::~wxToolTip()
{
}

// ----------------------------------------------------------------------------
// others
// ----------------------------------------------------------------------------

void wxToolTip::Remove()
{
}

void wxToolTip::Add(WXHWND hWnd)
{
}

void wxToolTip::SetWindow(wxWindow *win)
{
}

void wxToolTip::SetTip(const wxString& tip)
{
}

#endif // wxUSE_TOOLTIPS
