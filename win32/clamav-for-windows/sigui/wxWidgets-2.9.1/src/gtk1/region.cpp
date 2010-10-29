/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/region.cpp
// Purpose:
// Author:      Robert Roebling
// Modified:    VZ at 05.10.00: use AllocExclusive(), comparison fixed
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
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

#include "wx/region.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
#endif

#include "wx/gtk1/private.h"


// ----------------------------------------------------------------------------
// wxGdkRegion: creates a new region in ctor and destroys in dtor
// ----------------------------------------------------------------------------

class wxGdkRegion
{
public:
    wxGdkRegion() { m_region = gdk_region_new(); }
    ~wxGdkRegion() { gdk_region_destroy(m_region); }

    operator GdkRegion *() const { return m_region; }

private:
    GdkRegion *m_region;
};


// ----------------------------------------------------------------------------
// wxRegionRefData: private class containing the information about the region
// ----------------------------------------------------------------------------

class wxRegionRefData : public wxGDIRefData
{
public:
    wxRegionRefData()
    {
        m_region = NULL;
    }

    wxRegionRefData(const wxRegionRefData& refData)
        : wxGDIRefData()
    {
        m_region = gdk_regions_union(wxGdkRegion(), refData.m_region);
    }

    virtual ~wxRegionRefData()
    {
        if (m_region)
            gdk_region_destroy( m_region );
    }

    GdkRegion  *m_region;
};

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

#define M_REGIONDATA ((wxRegionRefData *)m_refData)
#define M_REGIONDATA_OF(rgn) ((wxRegionRefData *)(rgn.m_refData))

IMPLEMENT_DYNAMIC_CLASS(wxRegion, wxGDIObject)
IMPLEMENT_DYNAMIC_CLASS(wxRegionIterator,wxObject)

// ----------------------------------------------------------------------------
// wxRegion construction
// ----------------------------------------------------------------------------

#define M_REGIONDATA ((wxRegionRefData *)m_refData)

void wxRegion::InitRect(wxCoord x, wxCoord y, wxCoord w, wxCoord h)
{
    GdkRectangle rect;
    rect.x = x;
    rect.y = y;
    rect.width = w;
    rect.height = h;

    m_refData = new wxRegionRefData();

    M_REGIONDATA->m_region = gdk_region_union_with_rect( wxGdkRegion(), &rect );
}

wxRegion::wxRegion( GdkRegion *region )
{
    m_refData = new wxRegionRefData();
    M_REGIONDATA->m_region = gdk_regions_union(wxGdkRegion(), region);
}

wxRegion::wxRegion( size_t n, const wxPoint *points, wxPolygonFillMode fillStyle )
{
    GdkPoint *gdkpoints = new GdkPoint[n];
    for ( size_t i = 0 ; i < n ; i++ )
    {
        gdkpoints[i].x = points[i].x;
        gdkpoints[i].y = points[i].y;
    }

    m_refData = new wxRegionRefData();

    GdkRegion* reg = gdk_region_polygon
                     (
                        gdkpoints,
                        n,
                        fillStyle == wxWINDING_RULE ? GDK_WINDING_RULE
                                                    : GDK_EVEN_ODD_RULE
                     );

    M_REGIONDATA->m_region = reg;

    delete [] gdkpoints;
}

wxRegion::~wxRegion()
{
    // m_refData unrefed in ~wxObject
}

wxGDIRefData *wxRegion::CreateGDIRefData() const
{
    return new wxRegionRefData;
}

wxGDIRefData *wxRegion::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxRegionRefData(*(wxRegionRefData *)data);
}

// ----------------------------------------------------------------------------
// wxRegion comparison
// ----------------------------------------------------------------------------

bool wxRegion::DoIsEqual(const wxRegion& region) const
{
    return gdk_region_equal(M_REGIONDATA->m_region,
                            M_REGIONDATA_OF(region)->m_region);
}

// ----------------------------------------------------------------------------
// wxRegion operations
// ----------------------------------------------------------------------------

void wxRegion::Clear()
{
    UnRef();
}

bool wxRegion::DoUnionWithRect(const wxRect& r)
{
    // workaround for a strange GTK/X11 bug: taking union with an empty
    // rectangle results in an empty region which is definitely not what we
    // want
    if ( r.IsEmpty() )
        return TRUE;

    if ( !m_refData )
    {
        InitRect(r.x, r.y, r.width, r.height);
    }
    else
    {
        AllocExclusive();

        GdkRectangle rect;
        rect.x = r.x;
        rect.y = r.y;
        rect.width = r.width;
        rect.height = r.height;

        GdkRegion *reg = gdk_region_union_with_rect( M_REGIONDATA->m_region, &rect );
        gdk_region_destroy( M_REGIONDATA->m_region );
        M_REGIONDATA->m_region = reg;
    }

    return TRUE;
}

bool wxRegion::DoUnionWithRegion( const wxRegion& region )
{
    if (region.IsNull())
        return FALSE;

    if (!m_refData)
    {
        m_refData = new wxRegionRefData();
        M_REGIONDATA->m_region = gdk_region_new();
    }
    else
    {
        AllocExclusive();
    }

    GdkRegion *reg = gdk_regions_union( M_REGIONDATA->m_region, region.GetRegion() );
    gdk_region_destroy( M_REGIONDATA->m_region );
    M_REGIONDATA->m_region = reg;

    return TRUE;
}

bool wxRegion::DoIntersect( const wxRegion& region )
{
    wxCHECK_MSG( region.Ok(), false, wxT("invalid region") );

    if (!m_refData)
    {
        // intersecting with invalid region doesn't make sense
        return FALSE;
    }

    AllocExclusive();

    GdkRegion *reg = gdk_regions_intersect( M_REGIONDATA->m_region, region.GetRegion() );
    gdk_region_destroy( M_REGIONDATA->m_region );
    M_REGIONDATA->m_region = reg;

    return TRUE;
}

bool wxRegion::DoSubtract( const wxRegion& region )
{
    wxCHECK_MSG( region.Ok(), false, wxT("invalid region") );

    if (!m_refData)
    {
        // subtracting from an invalid region doesn't make sense
        return FALSE;
    }

    AllocExclusive();

    GdkRegion *reg = gdk_regions_subtract( M_REGIONDATA->m_region, region.GetRegion() );
    gdk_region_destroy( M_REGIONDATA->m_region );
    M_REGIONDATA->m_region = reg;

    return TRUE;
}

bool wxRegion::DoXor( const wxRegion& region )
{
    wxCHECK_MSG( region.Ok(), false, wxT("invalid region") );

    if (!m_refData)
    {
        return FALSE;
    }

    AllocExclusive();

    GdkRegion *reg = gdk_regions_xor( M_REGIONDATA->m_region, region.GetRegion() );
    gdk_region_destroy( M_REGIONDATA->m_region );
    M_REGIONDATA->m_region = reg;

    return TRUE;
}

bool wxRegion::DoOffset( wxCoord x, wxCoord y )
{
    if (!m_refData)
        return FALSE;

    AllocExclusive();

    gdk_region_offset( M_REGIONDATA->m_region, x, y );

    return TRUE;
}

// ----------------------------------------------------------------------------
// wxRegion tests
// ----------------------------------------------------------------------------

bool wxRegion::DoGetBox( wxCoord &x, wxCoord &y, wxCoord &w, wxCoord &h ) const
{
    if ( m_refData )
    {
        GdkRectangle rect;
        gdk_region_get_clipbox( M_REGIONDATA->m_region, &rect );
        x = rect.x;
        y = rect.y;
        w = rect.width;
        h = rect.height;

        return true;
    }
    else
    {
        x = 0;
        y = 0;
        w = -1;
        h = -1;

        return false;
    }
}

bool wxRegion::IsEmpty() const
{
    if (!m_refData)
        return TRUE;

    return gdk_region_empty( M_REGIONDATA->m_region );
}

wxRegionContain wxRegion::DoContainsPoint( wxCoord x, wxCoord y ) const
{
    if (!m_refData)
        return wxOutRegion;

    if (gdk_region_point_in( M_REGIONDATA->m_region, x, y ))
        return wxInRegion;
    else
        return wxOutRegion;
}

wxRegionContain wxRegion::DoContainsRect(const wxRect& r) const
{
    if (!m_refData)
        return wxOutRegion;

    GdkRectangle rect;
    rect.x = r.x;
    rect.y = r.y;
    rect.width = r.width;
    rect.height = r.height;
    GdkOverlapType res = gdk_region_rect_in( M_REGIONDATA->m_region, &rect );
    switch (res)
    {
        case GDK_OVERLAP_RECTANGLE_IN:   return wxInRegion;
        case GDK_OVERLAP_RECTANGLE_OUT:  return wxOutRegion;
        case GDK_OVERLAP_RECTANGLE_PART: return wxPartRegion;
    }
    return wxOutRegion;
}

GdkRegion *wxRegion::GetRegion() const
{
    if (!m_refData)
        return NULL;

    return M_REGIONDATA->m_region;
}

// ----------------------------------------------------------------------------
// wxRegionIterator
// ----------------------------------------------------------------------------

// the following structures must match the private structures
// in X11 region code ( xc/lib/X11/region.h )

// this makes the Region type transparent
// and we have access to the region rectangles

#include <gdk/gdkprivate.h>

struct _XBox {
    short x1, x2, y1, y2;
};

struct _XRegion {
    long   size , numRects;
    _XBox *rects, extents;
};


class wxRIRefData : public wxGDIRefData
{
public:
    wxRIRefData() { Init(); }
    virtual ~wxRIRefData();

    void CreateRects( const wxRegion& r );

    void Init() { m_rects = NULL; m_numRects = 0; }

    wxRect *m_rects;
    size_t  m_numRects;
};

wxRIRefData::~wxRIRefData()
{
    delete [] m_rects;
}

void wxRIRefData::CreateRects( const wxRegion& region )
{
    delete [] m_rects;

    Init();

    GdkRegion *gdkregion = region.GetRegion();
    if (!gdkregion)
        return;

    Region r = ((GdkRegionPrivate *)gdkregion)->xregion;
    if (r)
    {
        m_numRects = r->numRects;
        if (m_numRects)
        {
            m_rects = new wxRect[m_numRects];
            for (size_t i=0; i < m_numRects; ++i)
            {
                _XBox &xr = r->rects[i];
                wxRect &wr = m_rects[i];
                wr.x = xr.x1;
                wr.y = xr.y1;
                wr.width = xr.x2-xr.x1;
                wr.height = xr.y2-xr.y1;
            }
        }
    }
}

wxRegionIterator::wxRegionIterator()
{
    m_refData = new wxRIRefData();
    Reset();
}

wxRegionIterator::wxRegionIterator( const wxRegion& region )
{
    m_refData = new wxRIRefData();
    Reset(region);
}

void wxRegionIterator::Reset( const wxRegion& region )
{
    m_region = region;
    ((wxRIRefData*)m_refData)->CreateRects(region);
    Reset();
}

bool wxRegionIterator::HaveRects() const
{
    return m_current < ((wxRIRefData*)m_refData)->m_numRects;
}

wxRegionIterator& wxRegionIterator::operator ++ ()
{
    if (HaveRects())
        ++m_current;

    return *this;
}

wxRegionIterator wxRegionIterator::operator ++ (int)
{
    wxRegionIterator tmp = *this;
    if (HaveRects())
        ++m_current;

    return tmp;
}

wxCoord wxRegionIterator::GetX() const
{
    wxCHECK_MSG( HaveRects(), 0, wxT("invalid wxRegionIterator") );

    return ((wxRIRefData*)m_refData)->m_rects[m_current].x;
}

wxCoord wxRegionIterator::GetY() const
{
    wxCHECK_MSG( HaveRects(), 0, wxT("invalid wxRegionIterator") );

    return ((wxRIRefData*)m_refData)->m_rects[m_current].y;
}

wxCoord wxRegionIterator::GetW() const
{
    wxCHECK_MSG( HaveRects(), 0, wxT("invalid wxRegionIterator") );

    return ((wxRIRefData*)m_refData)->m_rects[m_current].width;
}

wxCoord wxRegionIterator::GetH() const
{
    wxCHECK_MSG( HaveRects(), 0, wxT("invalid wxRegionIterator") );

    return ((wxRIRefData*)m_refData)->m_rects[m_current].height;
}

wxRect wxRegionIterator::GetRect() const
{
    wxRect r;
    if( HaveRects() )
        r = ((wxRIRefData*)m_refData)->m_rects[m_current];

    return r;
}
