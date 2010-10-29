/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/region.cpp
// Purpose:     wxRegion implementation
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

#include "wx/region.h"

#ifndef WX_PRECOMP
    #include "wx/gdicmn.h"
#endif

IMPLEMENT_DYNAMIC_CLASS(wxRegion, wxGDIObject)
IMPLEMENT_DYNAMIC_CLASS(wxRegionIterator, wxObject)

// ----------------------------------------------------------------------------
// wxRegionRefData implementation
// ----------------------------------------------------------------------------

// ============================================================================
// wxRegion implementation
// ============================================================================

// ----------------------------------------------------------------------------
// ctors and dtor
// ----------------------------------------------------------------------------

wxRegion::wxRegion()
{
}

wxRegion::wxRegion(WXHRGN hRegion)
{
}

wxRegion::wxRegion(wxCoord x, wxCoord y, wxCoord w, wxCoord h)
{
}

wxRegion::wxRegion(const wxPoint& topLeft, const wxPoint& bottomRight)
{
}

wxRegion::wxRegion(const wxRect& rect)
{
}

wxRegion::wxRegion(size_t n, const wxPoint *points, wxPolygonFillMode fillStyle)
{
}

wxRegion::~wxRegion()
{
}

wxGDIRefData *wxRegion::CreateGDIRefData() const
{
    return NULL;
}

wxGDIRefData *wxRegion::CloneGDIRefData(const wxGDIRefData *data) const
{
    return NULL;
}

// ----------------------------------------------------------------------------
// wxRegion operations
// ----------------------------------------------------------------------------

// Clear current region
void wxRegion::Clear()
{
}

bool wxRegion::DoOffset(wxCoord x, wxCoord y)
{
    return false;
}

// combine another region with this one
bool wxRegion::DoCombine(const wxRegion& rgn, wxRegionOp op)
{
    return false;
}

// ----------------------------------------------------------------------------
// wxRegion bounding box
// ----------------------------------------------------------------------------

// Outer bounds of region
bool wxRegion::DoGetBox(wxCoord& x, wxCoord& y, wxCoord&w, wxCoord &h) const
{
    return false;
}

// Is region empty?
bool wxRegion::IsEmpty() const
{
    return true;
}

bool wxRegion::DoIsEqual(const wxRegion& region) const
{
    return false;
}

// ----------------------------------------------------------------------------
// wxRegion hit testing
// ----------------------------------------------------------------------------

// Does the region contain the point (x,y)?
wxRegionContain wxRegion::DoContainsPoint(wxCoord x, wxCoord y) const
{
    return wxOutRegion;
}

// Does the region contain the rectangle rect
wxRegionContain wxRegion::DoContainsRect(const wxRect& rect) const
{
    return wxOutRegion;
}

// Get internal region handle
WXHRGN wxRegion::GetHRGN() const
{
    return 0;
}

// ============================================================================
// wxRegionIterator implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxRegionIterator ctors/dtor
// ----------------------------------------------------------------------------

void wxRegionIterator::Init()
{
}

wxRegionIterator::~wxRegionIterator()
{
}

// Initialize iterator for region
wxRegionIterator::wxRegionIterator(const wxRegion& region)
{
}

wxRegionIterator& wxRegionIterator::operator=(const wxRegionIterator& ri)
{
    return *this;
}

// ----------------------------------------------------------------------------
// wxRegionIterator operations
// ----------------------------------------------------------------------------

// Reset iterator for a new region.
void wxRegionIterator::Reset(const wxRegion& region)
{
}

wxRegionIterator& wxRegionIterator::operator++()
{
    return *this;
}

wxRegionIterator wxRegionIterator::operator ++ (int)
{
    return *this;
}

// ----------------------------------------------------------------------------
// wxRegionIterator accessors
// ----------------------------------------------------------------------------

wxCoord wxRegionIterator::GetX() const
{
    return 0;
}

wxCoord wxRegionIterator::GetY() const
{
    return 0;
}

wxCoord wxRegionIterator::GetW() const
{
    return 0;
}

wxCoord wxRegionIterator::GetH() const
{
    return 0;
}
