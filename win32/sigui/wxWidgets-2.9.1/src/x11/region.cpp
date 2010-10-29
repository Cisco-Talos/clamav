/////////////////////////////////////////////////////////////////////////////
// File:      src/x11/region.cpp
// Purpose:   Region class
// Author:    Julian Smart, Robert Roebling
// Created:   Fri Oct 24 10:46:34 MET 1997
// RCS-ID:    $Id$
// Copyright: (c) 1997 Julian Smart, Robert Roebling
// Licence:   wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/region.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/gdicmn.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include "wx/x11/private.h"
#include "X11/Xutil.h"
#ifdef __VMS__
#pragma message enable nosimpint
#endif

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
    {
        m_region = XCreateRegion();
        XUnionRegion( refData.m_region, m_region, m_region );
    }

    virtual ~wxRegionRefData()
    {
        if (m_region)
            XDestroyRegion( m_region );
    }

    Region m_region;
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
    XRectangle rect;
    rect.x = (short)x;
    rect.y = (short)y;
    rect.width = (unsigned short)w;
    rect.height = (unsigned short)h;

    m_refData = new wxRegionRefData();

    M_REGIONDATA->m_region = XCreateRegion();
    XUnionRectWithRegion( &rect, M_REGIONDATA->m_region, M_REGIONDATA->m_region );
}

wxRegion::wxRegion( size_t WXUNUSED(n), const wxPoint *WXUNUSED(points), wxPolygonFillMode WXUNUSED(fillStyle) )
{
#if 0
    XPoint *xpoints = new XPoint[n];
    for ( size_t i = 0 ; i < n ; i++ )
    {
        xpoints[i].x = points[i].x;
        xpoints[i].y = points[i].y;
    }

    m_refData = new wxRegionRefData();

    Region* reg = gdk_region_polygon
                     (
                        gdkpoints,
                        n,
                        fillStyle == wxWINDING_RULE ? GDK_WINDING_RULE
                                                    : GDK_EVEN_ODD_RULE
                     );

    M_REGIONDATA->m_region = reg;

    delete [] xpoints;
#endif
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
    return XEqualRegion( M_REGIONDATA->m_region,
                         M_REGIONDATA_OF(region)->m_region ) == True;
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
    // work around for XUnionRectWithRegion() bug: taking a union with an empty
    // rect results in an empty region (at least XFree 3.3.6 and 4.0 have this
    // problem)
    if ( r.IsEmpty() )
        return true;

    XRectangle rect;
    rect.x = (short)r.x;
    rect.y = (short)r.y;
    rect.width = (unsigned short)r.width;
    rect.height = (unsigned short)r.height;

    if (!m_refData)
    {
        m_refData = new wxRegionRefData();
        M_REGIONDATA->m_region = XCreateRegion();
    }
    else
    {
        AllocExclusive();
    }

    XUnionRectWithRegion( &rect, M_REGIONDATA->m_region, M_REGIONDATA->m_region );

    return true;
}

bool wxRegion::DoUnionWithRegion( const wxRegion& region )
{
    wxCHECK_MSG( region.Ok(), false, wxT("invalid region") );

    if (!m_refData)
    {
        m_refData = new wxRegionRefData();
        M_REGIONDATA->m_region = XCreateRegion();
    }
    else
    {
        AllocExclusive();
    }

    XUnionRegion( M_REGIONDATA->m_region,
                  M_REGIONDATA_OF(region)->m_region,
                  M_REGIONDATA->m_region );

    return true;
}

bool wxRegion::DoIntersect( const wxRegion& region )
{
    wxCHECK_MSG( region.Ok(), false, wxT("invalid region") );

    if (!m_refData)
    {
        m_refData = new wxRegionRefData();
        M_REGIONDATA->m_region = XCreateRegion();

        // leave here
        return true;
    }
    else
    {
        AllocExclusive();
    }

    XIntersectRegion( M_REGIONDATA->m_region,
                      M_REGIONDATA_OF(region)->m_region,
                      M_REGIONDATA->m_region );

    return true;
}

bool wxRegion::DoSubtract( const wxRegion& region )
{
    wxCHECK_MSG( region.Ok(), false, wxT("invalid region") );

    if (!m_refData)
    {
        m_refData = new wxRegionRefData();
        M_REGIONDATA->m_region = XCreateRegion();
    }
    else
    {
        AllocExclusive();
    }

    XSubtractRegion( M_REGIONDATA->m_region,
                     M_REGIONDATA_OF(region)->m_region,
                     M_REGIONDATA->m_region );

    return true;
}

bool wxRegion::DoXor( const wxRegion& region )
{
    wxCHECK_MSG( region.Ok(), false, wxT("invalid region") );

    if (!m_refData)
    {
        m_refData = new wxRegionRefData();
        M_REGIONDATA->m_region = XCreateRegion();
    }
    else
    {
        AllocExclusive();
    }

    XXorRegion( M_REGIONDATA->m_region,
                M_REGIONDATA_OF(region)->m_region,
                M_REGIONDATA->m_region );

    return true;
}

// ----------------------------------------------------------------------------
// wxRegion tests
// ----------------------------------------------------------------------------

bool wxRegion::DoGetBox( wxCoord &x, wxCoord &y, wxCoord &w, wxCoord &h ) const
{
    if (m_refData)
    {
        XRectangle rect;
        XClipBox( M_REGIONDATA->m_region, &rect );
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

bool wxRegion::DoOffset( wxCoord x, wxCoord y )
{
    if (!m_refData)
        return false;

    AllocExclusive();

    XOffsetRegion( M_REGIONDATA->m_region, x, y );

    return true;
}

bool wxRegion::IsEmpty() const
{
    if (!m_refData)
        return true;

    return XEmptyRegion( M_REGIONDATA->m_region ) == True;
}

wxRegionContain wxRegion::DoContainsPoint( wxCoord x, wxCoord y ) const
{
    if (!m_refData)
        return wxOutRegion;

    if (XPointInRegion( M_REGIONDATA->m_region, x, y ))
        return wxInRegion;
    else
        return wxOutRegion;
}

wxRegionContain wxRegion::DoContainsRect(const wxRect& r) const
{
    if (!m_refData)
        return wxOutRegion;

    int res = XRectInRegion(M_REGIONDATA->m_region, r.x, r.y, r.width, r.height);
    switch (res)
    {
        case RectangleIn:   return wxInRegion;
        case RectangleOut:  return wxOutRegion;
        case RectanglePart: return wxPartRegion;
    }
    return wxOutRegion;
}

WXRegion *wxRegion::GetX11Region() const
{
    if (!m_refData)
        return NULL;

    return (WXRegion*) M_REGIONDATA->m_region;
}

// ----------------------------------------------------------------------------
// wxRegionIterator
// ----------------------------------------------------------------------------

// the following structures must match the private structures
// in X11 region code ( xc/lib/X11/region.h )

// this makes the Region type transparent
// and we have access to the region rectangles

struct _XBox {
    short x1, x2, y1, y2;
};

struct _XRegion {
    long   size , numRects;
    _XBox *rects, extents;
};

class wxRIRefData: public wxGDIRefData
{
public:

    wxRIRefData() : m_rects(0), m_numRects(0){}
   virtual ~wxRIRefData();

    wxRect *m_rects;
    size_t  m_numRects;

    void CreateRects( const wxRegion& r );
};

wxRIRefData::~wxRIRefData()
{
    delete [] m_rects;
}

void wxRIRefData::CreateRects( const wxRegion& region )
{
    if (m_rects)
      delete [] m_rects;

    m_rects = 0;
    m_numRects = 0;

    if (region.IsEmpty()) return;

    Region r = (Region) region.GetX11Region();
    if (r)
    {
#if wxUSE_NANOX
        GR_RECT rect;
        GrGetRegionBox(r, & rect);
        m_numRects = 1;
        m_rects = new wxRect[1];
        m_rects[0].x = rect.x;
        m_rects[0].y = rect.y;
        m_rects[0].width = rect.width;
        m_rects[0].height = rect.height;
#else
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
#endif
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

wxRegionIterator::operator bool () const
{
    return HaveRects();
}

void wxRegionIterator::operator ++ ()
{
    if (HaveRects()) ++m_current;
}

void wxRegionIterator::operator ++ (int)
{
    if (HaveRects()) ++m_current;
}

wxCoord wxRegionIterator::GetX() const
{
    if( !HaveRects() ) return 0;
    return ((wxRIRefData*)m_refData)->m_rects[m_current].x;
}

wxCoord wxRegionIterator::GetY() const
{
    if( !HaveRects() ) return 0;
    return ((wxRIRefData*)m_refData)->m_rects[m_current].y;
}

wxCoord wxRegionIterator::GetW() const
{
    if( !HaveRects() ) return -1;
    return ((wxRIRefData*)m_refData)->m_rects[m_current].width;
}

wxCoord wxRegionIterator::GetH() const
{
    if( !HaveRects() ) return -1;
    return ((wxRIRefData*)m_refData)->m_rects[m_current].height;
}

wxRect wxRegionIterator::GetRect() const
{
    wxRect r;
    if( HaveRects() )
        r = ((wxRIRefData*)m_refData)->m_rects[m_current];

    return r;
}
