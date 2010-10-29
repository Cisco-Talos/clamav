/////////////////////////////////////////////////////////////////////////////
// Name:      src/mgl/region.cpp
// Purpose:   Region handling for wxWidgets/DFB
// Author:    Vaclav Slavik
// Created:   2006-08-08
// RCS-ID:    $Id$
// Copyright: (c) 2006 REA Elektronik GmbH
// Licence:   wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/region.h"

IMPLEMENT_DYNAMIC_CLASS(wxRegion, wxGDIObject)
IMPLEMENT_DYNAMIC_CLASS(wxRegionIterator, wxObject)

//-----------------------------------------------------------------------------
// wxRegionRefData
//-----------------------------------------------------------------------------

class WXDLLEXPORT wxRegionRefData : public wxGDIRefData
{
public:
    wxRegionRefData() {}
    wxRegionRefData(const wxRect& rect) : m_rect(rect) {}
    wxRegionRefData(const wxRegionRefData& data) : m_rect(data.m_rect) {}

    ~wxRegionRefData() {}

    // default assignment and comparision operators are OK

    wxRect m_rect;
};

#define M_REGION_OF(r) ((wxRegionRefData*)((r).m_refData))
#define M_REGION       M_REGION_OF(*this)

//-----------------------------------------------------------------------------
// wxRegion
//-----------------------------------------------------------------------------

wxGDIRefData *wxRegion::CreateGDIRefData() const
{
    return new wxRegionRefData;
}

wxGDIRefData *wxRegion::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxRegionRefData(*(wxRegionRefData *)data);
}

wxRegion::wxRegion()
{
    m_refData = NULL;
}

wxRegion::wxRegion(wxCoord x, wxCoord y, wxCoord w, wxCoord h)
{
    m_refData = new wxRegionRefData(wxRect(x, y, w, h));
}

wxRegion::wxRegion(const wxPoint& topLeft, const wxPoint& bottomRight)
{
    m_refData = new wxRegionRefData(wxRect(topLeft, bottomRight));
}

wxRegion::wxRegion(const wxRect& r)
{
    m_refData = new wxRegionRefData(r);
}

wxRegion::~wxRegion()
{
    // m_refData unrefed in ~wxObject
}

//-----------------------------------------------------------------------------
// Information about the region
//-----------------------------------------------------------------------------

bool wxRegion::DoIsEqual(const wxRegion& region) const
{
    return M_REGION->m_rect == M_REGION_OF(region)->m_rect;
}

bool wxRegion::DoGetBox(wxCoord& x, wxCoord& y, wxCoord&w, wxCoord &h) const
{
    if ( !m_refData )
        return false;

    const wxRect& r = M_REGION->m_rect;
    x = r.GetX();
    y = r.GetY();
    w = r.GetWidth();
    h = r.GetHeight();

    return true;
}

bool wxRegion::IsEmpty() const
{
    if (!m_refData)
        return true;

    return M_REGION->m_rect.IsEmpty();
}

//-----------------------------------------------------------------------------
// Modifications
//-----------------------------------------------------------------------------

void wxRegion::Clear()
{
    UnRef();
}

bool wxRegion::DoOffset(wxCoord x, wxCoord y)
{
    AllocExclusive();
    M_REGION->m_rect.Offset(x, y);
    return true;
}

bool wxRegion::DoUnionWithRect(const wxRect& rect)
{
    AllocExclusive();

    if ( M_REGION->m_rect.Contains(rect) )
    {
        return true;
    }
    else if ( rect.Contains(M_REGION->m_rect) )
    {
        M_REGION->m_rect = rect;
        return true;
    }
    else
    {
        wxFAIL_MSG( "only rectangular regions are supported" );
        return false;
    }
}

bool wxRegion::DoUnionWithRegion(const wxRegion& region)
{
    wxCHECK_MSG( region.Ok(), false, "invalid region" );
    return DoUnionWithRect(M_REGION_OF(region)->m_rect);
}

bool wxRegion::DoIntersect(const wxRegion& region)
{
    wxCHECK_MSG( region.Ok(), false, "invalid region" );

    AllocExclusive();
    M_REGION->m_rect.Intersect(M_REGION_OF(region)->m_rect);
    return true;
}

bool wxRegion::DoSubtract(const wxRegion& region)
{
    wxCHECK_MSG( region.Ok(), false, "invalid region" );
    wxCHECK_MSG( Ok(), false, "invalid region" );

    const wxRect& rect = M_REGION_OF(region)->m_rect;

    if ( rect.Contains(M_REGION->m_rect) )
    {
        // subtracted rectangle contains this one, so the result is empty
        // rectangle
        M_REGION->m_rect = wxRect();
        return true;
    }
    else if ( !M_REGION->m_rect.Intersects(rect) )
    {
        // the rectangles are disjoint, so substracting has no effect
        return true;
    }
    else
    {
        wxFAIL_MSG( "only rectangular regions implemented" );
        return false;
    }
}

bool wxRegion::DoXor(const wxRegion& region)
{
    wxCHECK_MSG( region.Ok(), false, "invalid region" );
    wxFAIL_MSG( "Xor not implemented" );
    return false;
}


//-----------------------------------------------------------------------------
// Tests
//-----------------------------------------------------------------------------

wxRegionContain wxRegion::DoContainsPoint(wxCoord x, wxCoord y) const
{
    wxCHECK_MSG( Ok(), wxOutRegion, "invalid region" );

    if (M_REGION->m_rect.Contains(x, y))
        return wxInRegion;
    else
        return wxOutRegion;
}

wxRegionContain wxRegion::DoContainsRect(const wxRect& rect) const
{
    wxCHECK_MSG( Ok(), wxOutRegion, "invalid region" );

    // 1) is the rectangle entirely covered by the region?
    if (M_REGION->m_rect.Contains(rect))
        return wxInRegion;

    // 2) is the rectangle completely outside the region?
    if (!M_REGION->m_rect.Intersects(rect))
        return wxOutRegion;

    // 3) neither case happened => it is partially covered:
    return wxPartRegion;
}

//-----------------------------------------------------------------------------
// wxRegionIterator
//-----------------------------------------------------------------------------

void wxRegionIterator::Reset(const wxRegion& region)
{
    wxRegionRefData *d = M_REGION_OF(region);
    m_rect = d ? d->m_rect : wxRect();
}

wxRegionIterator& wxRegionIterator::operator++()
{
    // there's only one rectangle in the iterator, so iterating always
    // reaches the end:
    Reset();
    return *this;
}

wxRegionIterator wxRegionIterator::operator++(int)
{
    wxRegionIterator tmp = *this;

    // there's only one rectangle in the iterator, so iterating always
    // reaches the end:
    Reset();

    return tmp;
}
