/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/cursor.cpp
// Purpose:     wxCursor class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

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

#include "wx/cursor.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/bitmap.h"
    #include "wx/icon.h"
    #include "wx/settings.h"
    #include "wx/intl.h"
    #include "wx/image.h"
    #include "wx/module.h"
#endif

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------


// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxCursor, wxGDIObject)

// ----------------------------------------------------------------------------
// globals
// ----------------------------------------------------------------------------

// Current cursor, in order to hang on to cursor handle when setting the cursor
// globally
static wxCursor *gs_globalCursor = NULL;

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------


// ============================================================================
// implementation
// ============================================================================


// ----------------------------------------------------------------------------
// Cursors
// ----------------------------------------------------------------------------

wxCursor::wxCursor()
{
}

#if wxUSE_IMAGE
wxCursor::wxCursor(const wxImage& image)
{
}
#endif

wxCursor::wxCursor(const wxString& filename,
                   wxBitmapType kind,
                   int hotSpotX,
                   int hotSpotY)
{
}

// Cursors by stock number
void wxCursor::InitFromStock(wxStockCursor idCursor)
{
}

wxCursor::~wxCursor()
{
}

// ----------------------------------------------------------------------------
// other wxCursor functions
// ----------------------------------------------------------------------------

wxGDIImageRefData *wxCursor::CreateData() const
{
    return NULL;
}

// ----------------------------------------------------------------------------
// Global cursor setting
// ----------------------------------------------------------------------------

const wxCursor *wxGetGlobalCursor()
{
    return NULL;
}

void wxSetCursor(const wxCursor& cursor)
{
}
