///////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/popupwin.cpp
// Purpose:     implements wxPopupWindow for Palm OS
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

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_POPUPWIN

#ifndef WX_PRECOMP
#endif //WX_PRECOMP

#include "wx/popupwin.h"

#include "wx/palmos/private.h"     // for GetDesktopWindow()

IMPLEMENT_DYNAMIC_CLASS(wxPopupWindow, wxWindow)

// ============================================================================
// implementation
// ============================================================================

bool wxPopupWindow::Create(wxWindow *parent, int flags)
{
    return false;
}

void wxPopupWindow::DoGetPosition(int *x, int *y) const
{
}

WXDWORD wxPopupWindow::MSWGetStyle(long flags, WXDWORD *exstyle) const
{
    return 0;
}

WXHWND wxPopupWindow::MSWGetParent() const
{
    return (WXHWND) 0;
}

bool wxPopupWindow::Show(bool show)
{
    return false;
}

#endif // #if wxUSE_POPUPWIN
