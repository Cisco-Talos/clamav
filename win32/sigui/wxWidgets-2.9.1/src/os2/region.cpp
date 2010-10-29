/////////////////////////////////////////////////////////////////////////////
// File:      src/os2/region.cpp
// Purpose:   Region class
// Author:    David Webster
// Modified by:
// Created:   10/15/99
// RCS-ID:    $Id$
// Copyright: (c) David Webster
// Licence:   wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/window.h"
    #include "wx/gdicmn.h"
#endif

#include "wx/os2/region.h"

#include "wx/os2/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxRegion, wxGDIObject)
IMPLEMENT_DYNAMIC_CLASS(wxRegionIterator, wxObject)

//-----------------------------------------------------------------------------
// wxRegionRefData implementation
//-----------------------------------------------------------------------------

class WXDLLEXPORT wxRegionRefData : public wxGDIRefData {
public:
    wxRegionRefData()
    {
        m_hRegion = 0;
        m_hPS     = 0;
    }

    wxRegionRefData(const wxRegionRefData& rData)
    {
        RGNRECT                     vRgnData;
        PRECTL                      pRect = NULL;

        vRgnData.ulDirection = RECTDIR_LFRT_TOPBOT;
        if (::GpiQueryRegionRects( rData.m_hPS      // Pres space
                                  ,rData.m_hRegion  // Handle of region to query
                                  ,NULL             // Return all RECTs
                                  ,&vRgnData        // Will contain number or RECTs in region
                                  ,NULL             // NULL to return number of RECTs
                                 ))
        {
            pRect = new RECTL[vRgnData.crcReturned];
            vRgnData.crc = vRgnData.crcReturned;
            vRgnData.ircStart = 1;
            if (::GpiQueryRegionRects( rData.m_hPS     // Pres space of source
                                      ,rData.m_hRegion // Handle of source region
                                      ,NULL            // Return all RECTs
                                      ,&vRgnData       // Operations set to return rects
                                      ,pRect           // Will contain the actual RECTS
                                     ))
            {
                m_hRegion = ::GpiCreateRegion( rData.m_hPS
                                              ,vRgnData.crcReturned
                                              ,pRect
                                             );
                m_hPS = rData.m_hPS;
            }
            delete [] pRect;
        }
    }

    virtual ~wxRegionRefData()
    {
        ::GpiDestroyRegion(m_hPS, m_hRegion);
    }

    HRGN                            m_hRegion;
    HPS                             m_hPS;
};

#define M_REGION (((wxRegionRefData*)m_refData)->m_hRegion)
#define M_REGION_OF(rgn) (((wxRegionRefData*)(rgn.m_refData))->m_hRegion)

//-----------------------------------------------------------------------------
// wxRegion
//-----------------------------------------------------------------------------

// General remark:
// wxRegion is always basically stored in wx coordinates. However, since
// OS/2's internal functions rely on "top > bottom", the values of top and
// bottom values of a region need to be interchanged, as compared to wx.
// This needs to be taken into account when feeding any rectangle to wx _or_
// when accessing the region data via GetBox, wxRegionIterator or otherwise.

/*!
 * Create an empty region.
 */
wxRegion::wxRegion()
{
    m_refData = new wxRegionRefData;
} // end of wxRegion::wxRegion

wxRegion::wxRegion(
  WXHRGN                            hRegion,
  WXHDC                             hPS
)
{
    m_refData = new wxRegionRefData;
    M_REGION = (HRGN) hRegion;
    (((wxRegionRefData*)m_refData)->m_hPS) = hPS;
} // end of wxRegion::wxRegion

wxRegion::wxRegion(
  wxCoord                           x
, wxCoord                           y
, wxCoord                           vWidth
, wxCoord                           vHeight
)
{
    RECTL                           vRect;
    SIZEL                           vSize = {0, 0};
    DEVOPENSTRUC                    vDop = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
    HDC                             hDC = ::DevOpenDC( vHabmain
                                                      ,OD_MEMORY
                                                      ,"*"
                                                      ,5L
                                                      ,(PDEVOPENDATA)&vDop
                                                      ,NULLHANDLE
                                                     );


    vRect.xLeft   = x;
    vRect.xRight  = x + vWidth;
    vRect.yBottom = y;
    vRect.yTop    = y + vHeight;

    m_refData     = new wxRegionRefData;

    //
    // Need a PS to create a Region
    //
    ((wxRegionRefData*)m_refData)->m_hPS = ::GpiCreatePS( vHabmain
                                                         ,hDC
                                                         ,&vSize
                                                         ,PU_PELS | GPIT_MICRO | GPIA_ASSOC
                                                        );
    M_REGION      = ::GpiCreateRegion( ((wxRegionRefData*)m_refData)->m_hPS
                                      ,1
                                      ,&vRect
                                     );
} // end of wxRegion::wxRegion

wxRegion::wxRegion(const wxPoint& rTopLeft,
                   const wxPoint& rBottomRight)
{
    RECTL                           vRect;
    SIZEL                           vSize = {0, 0};
    DEVOPENSTRUC                    vDop = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
    HDC                             hDC = ::DevOpenDC( vHabmain
                                                      ,OD_MEMORY
                                                      ,"*"
                                                      ,5L
                                                      ,(PDEVOPENDATA)&vDop
                                                      ,NULLHANDLE
                                                     );

    vRect.xLeft   = rTopLeft.x;
    vRect.xRight  = rBottomRight.x;
    vRect.yBottom = rTopLeft.y;
    vRect.yTop    = rBottomRight.y;

    m_refData     = new wxRegionRefData;

    //
    // Need a PS to create a Region
    //
    ((wxRegionRefData*)m_refData)->m_hPS = ::GpiCreatePS( vHabmain
                                                         ,hDC
                                                         ,&vSize
                                                         ,PU_PELS | GPIT_MICRO | GPIA_ASSOC
                                                        );
    M_REGION      = ::GpiCreateRegion( ((wxRegionRefData*)m_refData)->m_hPS
                                      ,1
                                      ,&vRect
                                     );
} // end of wxRegion::wxRegion

wxRegion::wxRegion(const wxRect& rRect)
{
    RECTL                           vRect;
    SIZEL                           vSize = {0, 0};
    DEVOPENSTRUC                    vDop = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
    HDC                             hDC = ::DevOpenDC( vHabmain
                                                      ,OD_MEMORY
                                                      ,"*"
                                                      ,5L
                                                      ,(PDEVOPENDATA)&vDop
                                                      ,NULLHANDLE
                                                     );


    vRect.xLeft   = rRect.x;
    vRect.xRight  = rRect.x + rRect.width;
    vRect.yBottom = rRect.y;
    vRect.yTop    = rRect.y + rRect.height;

    m_refData     = new wxRegionRefData;

    //
    // Need a PS to create a Region
    //
    ((wxRegionRefData*)m_refData)->m_hPS = ::GpiCreatePS( vHabmain
                                                         ,hDC
                                                         ,&vSize
                                                         ,PU_PELS | GPIT_MICRO | GPIA_ASSOC
                                                        );
    M_REGION      = ::GpiCreateRegion( ((wxRegionRefData*)m_refData)->m_hPS
                                      ,1
                                      ,&vRect
                                     );
} // end of wxRegion::wxRegion

wxRegion::wxRegion(size_t n, const wxPoint *points, wxPolygonFillMode WXUNUSED(fillStyle))
{
    // TO DO
}

//
// Destroy the region.
//
wxRegion::~wxRegion()
{
} // end of wxRegion::~wxRegion

wxGDIRefData *wxRegion::CreateGDIRefData() const
{
    return new wxRegionRefData;
}

wxGDIRefData *wxRegion::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxRegionRefData(*(wxRegionRefData *)data);
}

//-----------------------------------------------------------------------------
//# Modify region
//-----------------------------------------------------------------------------

bool wxRegion::DoOffset( wxCoord x, wxCoord y )
{
    if ( !x && !y )
    {
        // nothing to do
        return true;
    }

    AllocExclusive();

#if 0
    if ( ::OffsetRgn(GetHrgn(), x, y) == ERROR )
    {
        wxLogLastError(wxT("OffsetRgn"));

        return false;
    }
#endif
    return true;
}

//
// Clear current region
//
void wxRegion::Clear()
{
    UnRef();
} // end of wxRegion::Clear

//
// Union region with this.
//
bool wxRegion::DoCombine( const wxRegion& rRegion, wxRegionOp eOp )
{
    //
    // We can't use the API functions if we don't have a valid region handle
    //
    if (!m_refData)
    {
        // combining with an empty/invalid region works differently depending
        // on the operation
        switch (eOp)
        {
            case wxRGN_COPY:
            case wxRGN_OR:
            case wxRGN_XOR:
                *this = rRegion;
                break;

            default:
                wxFAIL_MSG( wxT("unknown region operation") );
                // fall through

            case wxRGN_AND:
            case wxRGN_DIFF:
                // leave empty/invalid
                return false;
        }
    }
    else // we have a valid region
    {

        LONG                        lMode = 0;

        switch (eOp)
        {
            case wxRGN_AND:
                lMode = CRGN_AND;
                break;

            case wxRGN_OR:
                lMode = CRGN_OR;
                break;

            case wxRGN_XOR:
                lMode = CRGN_XOR;
                break;

            case wxRGN_DIFF:
                lMode = CRGN_DIFF;
                break;

            case wxRGN_COPY:
            default:
                lMode = CRGN_COPY;
                break;
        }
        return (::GpiCombineRegion( ((wxRegionRefData*)rRegion.m_refData)->m_hPS
                                   ,M_REGION
                                   ,M_REGION
                                   ,((wxRegionRefData*)rRegion.m_refData)->m_hRegion
                                   ,lMode
                                  ) != RGN_ERROR);
    }
    return true;
} // end of wxRegion::Combine

//-----------------------------------------------------------------------------
//# Information on region
//-----------------------------------------------------------------------------

bool wxRegion::DoIsEqual(const wxRegion& WXUNUSED(region)) const
{
    return false;
}

//
// Outer bounds of region
//
bool wxRegion::DoGetBox(
  wxCoord&                          x
, wxCoord&                          y
, wxCoord&                          vWidth
, wxCoord&                          vHeight
) const
{
    if (m_refData)
    {
        RECTL                       vRect;
        APIRET                      rc;

        rc = ::GpiQueryRegionBox( ((wxRegionRefData*)m_refData)->m_hPS
                            ,M_REGION
                            ,&vRect
                           );
        x       = vRect.xLeft;
        y       = vRect.yBottom;
        vWidth  = vRect.xRight - vRect.xLeft;
        vHeight = vRect.yTop - vRect.yBottom;
        return true;
    }
    else
    {
        x = y = vWidth = vHeight = 0L;
        return false;
    }
} // end of wxRegion::GetBox

//
// Is region empty?
//
bool wxRegion::IsEmpty() const
{
    wxCoord x;
    wxCoord y;
    wxCoord vWidth;
    wxCoord vHeight;

    if (M_REGION == 0)
        return true;

    GetBox( x
           ,y
           ,vWidth
           ,vHeight
          );
    return ((vWidth == 0) && (vHeight == 0));
} // end of wxRegion::IsEmpty

//-----------------------------------------------------------------------------
// Tests
//-----------------------------------------------------------------------------
//
// Does the region contain the point pt?
//
wxRegionContain wxRegion::DoContainsPoint( wxCoord x, wxCoord y ) const
{
    POINTL vPoint = { x, y };

    if (!m_refData)
        return wxOutRegion;

    LONG lInside = ::GpiPtInRegion( ((wxRegionRefData*)m_refData)->m_hPS,
                                    M_REGION,
                                    &vPoint
                                  );
    if (lInside == PRGN_INSIDE)
        return wxInRegion;
    else
        return wxOutRegion;
} // end of wxRegion::Contains

//
// Does the region contain the rectangle (x, y, w, h)?
//
wxRegionContain wxRegion::DoContainsRect(const wxRect& rect) const
{
    if (!m_refData)
        return wxOutRegion;

    RECTL   vRect;
    vRect.xLeft   = rect.x;
    vRect.xRight  = rect.x + rect.width;
    vRect.yTop    = rect.y + rect.height;
    vRect.yBottom = rect.y;

    LONG lInside = ::GpiRectInRegion( ((wxRegionRefData*)m_refData)->m_hPS,
                                      M_REGION,
                                      &vRect
                                    );
    switch (lInside)
    {
        case RRGN_INSIDE    :   return wxInRegion;
        case RRGN_PARTIAL   :   return wxPartRegion;
        case RRGN_ERROR     :
        default             :   return wxOutRegion;
    }

} // end of wxRegion::Contains

//
// Get internal region handle
//
WXHRGN wxRegion::GetHRGN() const
{
    if (!m_refData)
        return (WXHRGN) 0;
    return (WXHRGN) M_REGION;
}

//
// Set a new PS, this means we have to recreate the old region in the new
// PS
//
void wxRegion::SetPS(
  HPS                               hPS
)
{
    RGNRECT                     vRgnData;
    PRECTL                      pRect = NULL;

    vRgnData.ulDirection = RECTDIR_LFRT_TOPBOT;
    if (::GpiQueryRegionRects( ((wxRegionRefData*)m_refData)->m_hPS
                              ,((wxRegionRefData*)m_refData)->m_hRegion
                              ,NULL
                              ,&vRgnData
                              ,NULL
                             ))
    {
        pRect = new RECTL[vRgnData.crcReturned];
        vRgnData.crc = vRgnData.crcReturned;
        vRgnData.ircStart = 1;
        if (::GpiQueryRegionRects( ((wxRegionRefData*)m_refData)->m_hPS
                                  ,((wxRegionRefData*)m_refData)->m_hRegion
                                  ,NULL
                                  ,&vRgnData
                                  ,pRect
                                 ))
        {
            //
            // First destroy the region out of the old PS
            // and then create it in the new and set the new to current
            //
            ::GpiDestroyRegion( ((wxRegionRefData*)m_refData)->m_hPS
                               ,M_REGION
                              );
            ((wxRegionRefData*)m_refData)->m_hRegion = ::GpiCreateRegion( hPS
                                                                         ,vRgnData.crcReturned
                                                                         ,pRect
                                                                        );
            ((wxRegionRefData*)m_refData)->m_hPS = hPS;
        }
        delete [] pRect;
    }
} // end of wxRegion::SetPS

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
//                             wxRegionIterator                              //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////

//
// Initialize empty iterator
//
wxRegionIterator::wxRegionIterator()
: m_lCurrent(0)
, m_lNumRects(0)
, m_pRects(NULL)
{
} // end of wxRegionIterator::wxRegionIterator

wxRegionIterator::~wxRegionIterator()
{
    if (m_pRects)
        delete[] m_pRects;
} // end of wxRegionIterator::~wxRegionIterator

//
// Initialize iterator for region
//
wxRegionIterator::wxRegionIterator(
  const wxRegion&                   rRegion
)
{
    m_pRects = NULL;
    Reset(rRegion);
} // end of wxRegionIterator::wxRegionIterator

//
// Reset iterator for a new /e region.
//
void wxRegionIterator::Reset(
  const wxRegion&                   rRegion
)
{
    m_lCurrent = 0;
    m_lNumRects = 0;
    m_vRegion  = rRegion;

    if (m_pRects)
        delete[] m_pRects;

    m_pRects = NULL;

    if (m_vRegion.Empty())
        m_lNumRects = 0;
    else
    {
        RGNRECT                     vRgnData;
        PRECTL                      pRect;

        vRgnData.ulDirection = RECTDIR_LFRT_TOPBOT;
        if (::GpiQueryRegionRects( ((wxRegionRefData*)rRegion.m_refData)->m_hPS     // Pres space
                                  ,((wxRegionRefData*)rRegion.m_refData)->m_hRegion // Handle of region to query
                                  ,NULL                                             // Return all RECTs
                                  ,&vRgnData                                        // Will contain number or RECTs in region
                                  ,NULL                                             // NULL to return number of RECTs
                                 ))
        {
            pRect = new RECTL[vRgnData.crcReturned];
            m_pRects = new wxRect[vRgnData.crcReturned];
            vRgnData.crc = vRgnData.crcReturned;
            m_lNumRects = vRgnData.crcReturned;
            vRgnData.ircStart = 1;
            if (::GpiQueryRegionRects( ((wxRegionRefData*)rRegion.m_refData)->m_hPS     // Pres space of source
                                      ,((wxRegionRefData*)rRegion.m_refData)->m_hRegion // Handle of source region
                                      ,NULL                                             // Return all RECTs
                                      ,&vRgnData                                        // Operations set to return rects
                                      ,pRect                                            // Will contain the actual RECTS
                                     ))
            {
#if 0
                M_REGION = ::GpiCreateRegion( ((wxRegionRefData*)rRegion.m_refData)->m_hPS
                                             ,vRgnData.crcReturned
                                             ,pRect
                                            );
#endif
                for( LONG i = 0; i < m_lNumRects; i++)
                {
                    m_pRects[i].x      = pRect[i].xLeft;
                    m_pRects[i].width  = pRect[i].xRight - pRect[i].xLeft;
                    m_pRects[i].y      = pRect[i].yBottom;
                    m_pRects[i].height = pRect[i].yTop - pRect[i].yBottom;
                }
#if 0
                ((wxRegionRefData*)m_refData)->m_hPS = ((wxRegionRefData*)rRegion.m_refData)->m_hPS;
#endif
            }
        }
    }
} // end of wxRegionIterator::Reset

//
// Increment iterator. The rectangle returned is the one after the
// incrementation.
//
void wxRegionIterator::operator++ ()
{
    if (m_lCurrent < m_lNumRects)
        ++m_lCurrent;
} // end of wxRegionIterator::operator ++

//
// Increment iterator. The rectangle returned is the one before the
// incrementation.
//
void wxRegionIterator::operator++ (int)
{
    if (m_lCurrent < m_lNumRects)
        ++m_lCurrent;
} // end of wxRegionIterator::operator++

wxCoord wxRegionIterator::GetX() const
{
    if (m_lCurrent < m_lNumRects)
        return m_pRects[m_lCurrent].x;
    return 0L;
} // end of wxRegionIterator::GetX

wxCoord wxRegionIterator::GetY() const
{
    if (m_lCurrent < m_lNumRects)
        return m_pRects[m_lCurrent].y;
    return 0L;
} // end of wxRegionIterator::GetY

wxCoord wxRegionIterator::GetW() const
{
    if (m_lCurrent < m_lNumRects)
        return m_pRects[m_lCurrent].width ;
    return 0L;
} // end of wxRegionIterator::GetW

wxCoord wxRegionIterator::GetH() const
{
    if (m_lCurrent < m_lNumRects)
        return m_pRects[m_lCurrent].height;
    return 0L;
} // end of wxRegionIterator::GetH
