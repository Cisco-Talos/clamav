/////////////////////////////////////////////////////////////////////////////
// Name:      src/mgl/region.cpp
// Purpose:   Region handling for wxWidgets/MGL
// Author:    Vaclav Slavik
// RCS-ID:    $Id$
// Copyright: (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:   wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#include "wx/region.h"

#ifndef WX_PRECOMP
    #include "wx/gdicmn.h"
    #include "wx/module.h"
#endif

#include "wx/thread.h"

#include <mgraph.hpp>

#include "wx/listimpl.cpp"
WX_DEFINE_LIST(wxRegionRectList)

IMPLEMENT_DYNAMIC_CLASS(wxRegion, wxGDIObject)
IMPLEMENT_DYNAMIC_CLASS(wxRegionIterator, wxObject)

//-----------------------------------------------------------------------------
// wxRegionRefData implementation
//-----------------------------------------------------------------------------

class WXDLLEXPORT wxRegionRefData : public wxGDIRefData
{
public:
    wxRegionRefData() {}

    wxRegionRefData(const wxRegionRefData& data)
    {
        m_region = data.m_region;
    }

    virtual ~wxRegionRefData() {}

    MGLRegion m_region;
};

#define M_REGION       (((wxRegionRefData*)m_refData)->m_region)
#define M_REGION_OF(r) (((wxRegionRefData*)(r.m_refData))->m_region)

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

/*
 * Create an empty region.
 */
wxRegion::wxRegion()
{
    m_refData = NULL;
}

wxRegion::wxRegion(wxCoord x, wxCoord y, wxCoord w, wxCoord h)
{
    m_refData = new wxRegionRefData;
    MGLRect rect(x, y, x + w, y + h);
    M_REGION = rect;
}

wxRegion::wxRegion(const wxPoint& topLeft, const wxPoint& bottomRight)
{
    m_refData = new wxRegionRefData;
    MGLRect rect(topLeft.x, topLeft.y, bottomRight.x+1, bottomRight.y+1);
    M_REGION = rect;
}

wxRegion::wxRegion(const wxRect& r)
{
    m_refData = new wxRegionRefData;
    MGLRect rect(r.GetLeft(), r.GetTop(), r.GetRight()+1, r.GetBottom()+1);
    M_REGION = rect;
}

wxRegion::wxRegion(const MGLRegion& region)
{
    m_refData = new wxRegionRefData;
    M_REGION = region;
}

wxRegion::wxRegion(size_t n, const wxPoint *points, int WXUNUSED(fillStyle))
{
    m_refData = new wxRegionRefData;
    point_t *pts = new point_t[n];

    for (size_t i = 0; i < n; i++)
    {
        pts[i].x = points[i].x;
        pts[i].y = points[i].y;
    }

    region_t* rgn = MGL_rgnPolygon(n, pts, 1, 0, 0);

    M_REGION = rgn;

    delete [] pts;
}

wxRegion::~wxRegion()
{
    // m_refData unrefed in ~wxObject
}

const MGLRegion& wxRegion::GetMGLRegion() const
{
    return M_REGION;
}

//-----------------------------------------------------------------------------
// Modify region
//-----------------------------------------------------------------------------

// Clear current region
void wxRegion::Clear()
{
    UnRef();
}


//-----------------------------------------------------------------------------
// Information on region
//-----------------------------------------------------------------------------

bool wxRegion::DoIsEqual(const wxRegion& WXUNUSED(region)) const
{
    wxFAIL_MSG( wxT("not implemented") );

    return false;
}

// Outer bounds of region
bool wxRegion::DoGetBox(wxCoord& x, wxCoord& y, wxCoord&w, wxCoord &h) const
{
    if (m_refData)
    {
        rect_t rect;
        rect = M_REGION.getBounds();
        x = rect.left;
        y = rect.top;
        w = rect.right - rect.left;
        h = rect.bottom - rect.top;

        return true;
    }
    else
    {
        x = y = w = h = 0;
        return false;
    }
}

// Is region empty?
bool wxRegion::IsEmpty() const
{
    if (!m_refData)
        return true;

    return (bool)(M_REGION.isEmpty());
}

//-----------------------------------------------------------------------------
// Modifications
//-----------------------------------------------------------------------------

bool wxRegion::DoOffset(wxCoord x, wxCoord y)
{
    AllocExclusive();
    M_REGION.offset(x, y);
    return true;
}

// Union rectangle or region with this.
bool wxRegion::DoUnionWithRect(const wxRect& r)
{
    AllocExclusive();
    M_REGION += MGLRect(r.x, r.y, r.GetRight() + 1, r.GetHeight() + 1);
    return true;
}

bool wxRegion::DoUnionWithRegion(const wxRegion& region)
{
    AllocExclusive();
    M_REGION += M_REGION_OF(region);
    return true;
}

bool wxRegion::DoIntersect(const wxRegion& region)
{
    AllocExclusive();
    M_REGION &= M_REGION_OF(region);
    return true;
}

bool wxRegion::DoSubtract(const wxRegion& region)
{
    AllocExclusive();
    M_REGION -= M_REGION_OF(region);
    return true;
}

bool wxRegion::DoXor(const wxRegion& region)
{
    AllocExclusive();
    MGLRegion rg1 = M_REGION + M_REGION_OF(region),
              rg2 = M_REGION & M_REGION_OF(region);
    M_REGION = rg1 - rg2;
    return true;
}


//-----------------------------------------------------------------------------
// Tests
//-----------------------------------------------------------------------------

// Does the region contain the point (x,y)?
wxRegionContain wxRegion::DoContainsPoint(wxCoord x, wxCoord y) const
{
    if (!m_refData)
        return wxOutRegion;

    if (M_REGION.includes((int)x, (int)y))
        return wxInRegion;
    else
        return wxOutRegion;
}

// Does the region contain the rectangle (x, y, w, h)?
wxRegionContain wxRegion::DoContainsRect(const wxRect& r) const
{
    if (!m_refData)
        return wxOutRegion;

    MGLRect rect(r.x, r.y, r.GetRight() + 1, r.GetBottom() + 1);
    MGLRegion rg;

    // 1) is the rectangle entirely covered by the region?
    rg = MGLRegion(rect) - M_REGION;
    if (rg.isEmpty())
        return wxInRegion;

    // 2) is the rectangle completely outside the region?
    rg = M_REGION & rect; // intersection
    if (rg.isEmpty())
        return wxOutRegion;

    // 3) neither case happened => it is partially covered:
    return wxPartRegion;
}

///////////////////////////////////////////////////////////////////////////////
//                               wxRegionIterator                                 //
///////////////////////////////////////////////////////////////////////////////

#if wxUSE_THREADS
static wxMutex *gs_mutexIterator;

class wxMglRegionModule : public wxModule
{
public:
    virtual bool OnInit()
    {
        gs_mutexIterator = new wxMutex();
        return true;
    }
    virtual void OnExit()
    {
        wxDELETE(gs_mutexIterator);
    }

    DECLARE_DYNAMIC_CLASS(wxMglRegionModule)
};
IMPLEMENT_DYNAMIC_CLASS(wxMglRegionModule, wxModule)
#endif

/*
 * Initialize empty iterator
 */
wxRegionIterator::wxRegionIterator() : m_currentNode(NULL)
{
    m_rects.DeleteContents(true);
}

wxRegionIterator::~wxRegionIterator()
{
}

/*
 * Initialize iterator for region
 */
wxRegionIterator::wxRegionIterator(const wxRegion& region)
{
    m_rects.DeleteContents(true);
    Reset(region);
}

/*
 * Reset iterator for a new /e region.
 */


static wxRegionRectList *gs_rectList;

static void MGLAPI wxMGL_region_callback(const rect_t *r)
{
    gs_rectList->Append(new wxRect(r->left, r->top,
                                   r->right - r->left, r->bottom - r->top));
}

void wxRegionIterator::Reset(const wxRegion& region)
{
    m_currentNode = NULL;
    m_rects.Clear();

    if (!region.Empty())
    {
#if wxUSE_THREADS
        wxMutexLocker lock(*gs_mutexIterator);
#endif
        gs_rectList = &m_rects;
        M_REGION_OF(region).traverse(wxMGL_region_callback);
        m_currentNode = m_rects.GetFirst();
    }
}

/*
 * Increment iterator. The rectangle returned is the one after the
 * incrementation.
 */
void wxRegionIterator::operator ++ ()
{
    if (m_currentNode)
        m_currentNode = m_currentNode->GetNext();
}

/*
 * Increment iterator. The rectangle returned is the one before the
 * incrementation.
 */
void wxRegionIterator::operator ++ (int)
{
    if (m_currentNode)
        m_currentNode = m_currentNode->GetNext();
}

wxCoord wxRegionIterator::GetX() const
{
    if (m_currentNode)
        return m_currentNode->GetData()->x;
    else
        return 0;
}

wxCoord wxRegionIterator::GetY() const
{
    if (m_currentNode)
        return m_currentNode->GetData()->y;
    else
        return 0;
}

wxCoord wxRegionIterator::GetW() const
{
    if (m_currentNode)
        return m_currentNode->GetData()->width;
    else
        return 0;
}

wxCoord wxRegionIterator::GetH() const
{
    if (m_currentNode)
        return m_currentNode->GetData()->height;
    else
        return 0;
}
