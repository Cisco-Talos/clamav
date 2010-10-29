/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/brush.cpp
// Purpose:     wxBrush
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

#ifndef WX_PRECOMP
    #include "wx/list.h"
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/brush.h"
    #include "wx/colour.h"
#endif // WX_PRECOMP

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------

// ============================================================================
// wxBrush implementation
// ============================================================================

IMPLEMENT_DYNAMIC_CLASS(wxBrush, wxGDIObject)

// ----------------------------------------------------------------------------
// wxBrush ctors/dtor
// ----------------------------------------------------------------------------

wxBrush::wxBrush()
{
}

wxBrush::wxBrush(const wxColour& col, wxBrushStyle style)
{
}

wxBrush::wxBrush(const wxBitmap& stipple)
{
}

wxBrush::~wxBrush()
{
}

// ----------------------------------------------------------------------------
// wxBrush house keeping stuff
// ----------------------------------------------------------------------------

bool wxBrush::operator==(const wxBrush& brush) const
{
    return false;
}

wxGDIRefData *wxBrush::CreateGDIRefData() const
{
    return NULL;
}

wxGDIRefData *wxBrush::CloneGDIRefData(const wxGDIRefData *data) const
{
    return NULL;
}

// ----------------------------------------------------------------------------
// wxBrush accessors
// ----------------------------------------------------------------------------

wxColour wxBrush::GetColour() const
{
    return wxNullColour;
}

wxBrushStyle wxBrush::GetStyle() const
{
    return -1;
}

wxBitmap *wxBrush::GetStipple() const
{
    return NULL;
}

WXHANDLE wxBrush::GetResourceHandle() const
{
    return (WXHANDLE)0;
}

// ----------------------------------------------------------------------------
// wxBrush setters
// ----------------------------------------------------------------------------

void wxBrush::SetColour(const wxColour& WXUNUSED(col))
{
}

void wxBrush::SetColour(unsigned char WXUNUSED(r), unsigned char WXUNUSED(g), unsigned char WXUNUSED(b))
{
}

void wxBrush::SetStyle(wxBrushStyle WXUNUSED(style))
{
}

void wxBrush::SetStipple(const wxBitmap& WXUNUSED(stipple))
{
}
