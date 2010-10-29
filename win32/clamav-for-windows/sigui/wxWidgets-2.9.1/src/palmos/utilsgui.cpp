///////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/utilsgui.cpp
// Purpose:     Various utility functions only available in GUI
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

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/cursor.h"
    #include "wx/window.h"
    #include "wx/utils.h"
#endif //WX_PRECOMP

// ============================================================================
// implementation
// ============================================================================

// ---------------------------------------------------------------------------
// helper functions for showing a "busy" cursor
// ---------------------------------------------------------------------------

static int gs_wxBusyCursorCount = 0;

// Set the cursor to the busy cursor for all windows
void wxBeginBusyCursor(const wxCursor *cursor)
{
}

// Restore cursor to normal
void wxEndBusyCursor()
{
}

// true if we're between the above two calls
bool wxIsBusy()
{
    return false;
}

// Check whether this window wants to process messages, e.g. Stop button
// in long calculations.
bool wxCheckForInterrupt(wxWindow *wnd)
{
    return false;
}

// MSW only: get user-defined resource from the .res file.
// Returns NULL or newly-allocated memory, so use delete[] to clean up.

wxChar *wxLoadUserResource(const wxString& resourceName, const wxString& resourceType)
{
    return NULL;
}

// ----------------------------------------------------------------------------
// get display info
// ----------------------------------------------------------------------------

// See also the wxGetMousePosition in window.cpp
// Deprecated: use wxPoint wxGetMousePosition() instead
void wxGetMousePosition( int* x, int* y )
{
};

// Return true if we have a colour display
bool wxColourDisplay()
{
    return false;
}

// Returns depth of screen
int wxDisplayDepth()
{
    return 0;
}

// Get size of display
void wxDisplaySize(int *width, int *height)
{
}

void wxDisplaySizeMM(int *width, int *height)
{
}

void wxClientDisplayRect(int *x, int *y, int *width, int *height)
{
}
