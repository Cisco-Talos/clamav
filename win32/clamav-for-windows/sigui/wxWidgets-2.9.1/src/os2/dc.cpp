/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/dc.cpp
// Purpose:     wxDC class
// Author:      David Webster
// Modified by:
// Created:     10/14/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/window.h"
    #include "wx/dc.h"
    #include "wx/utils.h"
    #include "wx/dialog.h"
    #include "wx/app.h"
    #include "wx/bitmap.h"
    #include "wx/dcmemory.h"
    #include "wx/log.h"
    #include "wx/icon.h"
    #include "wx/msgdlg.h"
    #include "wx/dcprint.h"
    #include "wx/statusbr.h"
    #include "wx/module.h"
#endif

#include <string.h>

#include "wx/os2/dc.h"
#include "wx/os2/dcclient.h"
#include "wx/os2/private.h"

IMPLEMENT_ABSTRACT_CLASS(wxPMDCImpl, wxDCImpl)

//
// wxWidgets uses the Microsoft convention that the origin is the UPPER left.
// Native OS/2 however in the GPI and PM define the origin as the LOWER left.
// In order to map OS/2 GPI/PM y coordinates to wxWidgets coordinates we must
// perform the following transformation:
//
// Parent object height:     POBJHEIGHT
// Desried origin:           WXORIGINY
// Object to place's height: OBJHEIGHT
//
// To get the OS2 position from the wxWidgets one:
//
// OS2Y = POBJHEIGHT - (WXORIGINY + OBJHEIGHT)
//
// For OS/2 wxDC's we will always determine m_vRclPaint as the size of the
// OS/2 Presentation Space associated with the device context.  y is the
// desired application's y coordinate of the origin in wxWidgets space.
// objy is the height of the object we are going to draw.
//
#define OS2Y(y, objy) ((m_vRclPaint.yTop - m_vRclPaint.yBottom) - (y + objy))

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

static const int VIEWPORT_EXTENT = 1000;

static const int MM_POINTS = 9;
static const int MM_METRIC = 10;

// ---------------------------------------------------------------------------
// private functions
// ---------------------------------------------------------------------------

// convert degrees to radians
static inline double DegToRad(double deg) { return (deg * M_PI) / 180.0; }

int SetTextColor(
  HPS                               hPS
, int                               nForegroundColour
)
{
    CHARBUNDLE                      vCbnd;

    vCbnd.lColor =  nForegroundColour;
    ::GpiSetAttrs( hPS       // presentation-space handle
                  ,PRIM_CHAR // Char primitive.
                  ,CBB_COLOR // sets color.
                  ,0         //
                  ,&vCbnd    // buffer for attributes.
                 );
    return 0;
}

int QueryTextBkColor(
  HPS                               hPS
)
{
    CHARBUNDLE                      vCbnd;

    ::GpiQueryAttrs( hPS            // presentation-space handle
                    ,PRIM_CHAR      // Char primitive.
                    ,CBB_BACK_COLOR // Background color.
                    ,&vCbnd         // buffer for attributes.
                   );
    return vCbnd.lBackColor;
}


int SetTextBkColor(
  HPS                               hPS
, int                               nBackgroundColour
)
{
    CHARBUNDLE                      vCbnd;
    int                             rc;

    rc =  QueryTextBkColor(hPS);

    vCbnd.lBackColor = nBackgroundColour;
    ::GpiSetAttrs(hPS,            // presentation-space handle
                  PRIM_CHAR,      // Char primitive.
                  CBB_BACK_COLOR, // sets color.
                  0,
                  &vCbnd          // buffer for attributes.
                 );
    return rc;
}

int SetBkMode(
  HPS                               hPS
, int                               nBackgroundMode
)
{
    if(nBackgroundMode == wxTRANSPARENT)
        ::GpiSetBackMix( hPS
                        ,BM_LEAVEALONE
                       );
    else
        // the background of the primitive takes  over whatever is underneath.
        ::GpiSetBackMix( hPS
                        ,BM_OVERPAINT
                        );
    return 0;
}

// ===========================================================================
// implementation
// ===========================================================================

#if wxUSE_DC_CACHEING

/*
 * This implementation is a bit ugly and uses the old-fashioned wxList class, so I will
 * improve it in due course, either using arrays, or simply storing pointers to one
 * entry for the bitmap, and two for the DCs. -- JACS
 */

// ---------------------------------------------------------------------------
// wxDCCacheEntry
// ---------------------------------------------------------------------------

wxList wxPMDCImpl::m_svBitmapCache;
wxList wxPMDCImpl::m_svDCCache;

wxDCCacheEntry::wxDCCacheEntry(
  WXHBITMAP                         hBitmap
, int                               nWidth
, int                               nHeight
, int                               nDepth
)
{
    m_hBitmap = hBitmap;
    m_hPS     = NULLHANDLE;
    m_nWidth  = nWidth;
    m_nHeight = nHeight;
    m_nDepth  = nDepth;
} // end of wxDCCacheEntry::wxDCCacheEntry

wxDCCacheEntry::wxDCCacheEntry(
  HPS                               hPS
, int                               nDepth
)
{
    m_hBitmap = NULLHANDLE;
    m_hPS     = hPS;
    m_nWidth  = 0;
    m_nHeight = 0;
    m_nDepth  = nDepth;
} // end of wxDCCacheEntry::wxDCCacheEntry

wxDCCacheEntry::~wxDCCacheEntry()
{
    if (m_hBitmap)
        ::GpiDeleteBitmap(m_hBitmap);
    if (m_hPS)
        ::GpiDestroyPS(m_hPS);
} // end of wxDCCacheEntry::~wxDCCacheEntry

wxDCCacheEntry* wxPMDCImpl::FindBitmapInCache(
  HPS                               hPS
, int                               nWidth
, int                               nHeight
)
{
    int                             nDepth = 24; // we'll fix this later ::GetDeviceCaps((HDC) dc, PLANES) * ::GetDeviceCaps((HDC) dc, BITSPIXEL);
    wxNode*                         pNode = m_svBitmapCache.First();
    BITMAPINFOHEADER2               vBmpHdr;

    while(pNode)
    {
        wxDCCacheEntry*             pEntry = (wxDCCacheEntry*)pNode->Data();

        if (pEntry->m_nDepth == nDepth)
        {
            memset(&vBmpHdr, 0, sizeof(BITMAPINFOHEADER2));

            if (pEntry->m_nWidth < nWidth || pEntry->m_nHeight < nHeight)
            {
                ::GpiDeleteBitmap((HBITMAP)pEntry->m_hBitmap);
                vBmpHdr.cbFix     = sizeof(BITMAPINFOHEADER2);
                vBmpHdr.cx        = nWidth;
                vBmpHdr.cy        = nHeight;
                vBmpHdr.cPlanes   = 1;
                vBmpHdr.cBitCount = (USHORT)nDepth;

                pEntry->m_hBitmap = (WXHBITMAP) ::GpiCreateBitmap( hPS
                                                                  ,&vBmpHdr
                                                                  ,0L, NULL, NULL
                                                                 );
                if (!pEntry->m_hBitmap)
                {
                    wxLogLastError(wxT("CreateCompatibleBitmap"));
                }
                pEntry->m_nWidth  = nWidth;
                pEntry->m_nHeight = nHeight;
                return pEntry;
            }
            return pEntry;
        }
        pNode = pNode->Next();
    }
    memset(&vBmpHdr, 0, sizeof(BITMAPINFOHEADER2));
    vBmpHdr.cbFix     = sizeof(BITMAPINFOHEADER2);
    vBmpHdr.cx        = nWidth;
    vBmpHdr.cy        = nHeight;
    vBmpHdr.cPlanes   = 1;
    vBmpHdr.cBitCount = (USHORT)nDepth;

    WXHBITMAP                       hBitmap = (WXHBITMAP) ::GpiCreateBitmap( hPS
                                                                            ,&vBmpHdr
                                                                            ,0L, NULL, NULL
                                                                           );
    if (!hBitmap)
    {
        wxLogLastError(wxT("CreateCompatibleBitmap"));
    }
    wxDCCacheEntry*                 pEntry = new wxDCCacheEntry( hBitmap
                                                                ,nWidth
                                                                ,nHeight
                                                                ,nDepth
                                                               );
    AddToBitmapCache(pEntry);
    return pEntry;
} // end of FindBitmapInCache

wxDCCacheEntry* wxPMDCImpl::FindDCInCache(
  wxDCCacheEntry*                   pNotThis
, HPS                               hPS
)
{
    int                             nDepth = 24; // we'll fix this up later ::GetDeviceCaps((HDC) dc, PLANES) * ::GetDeviceCaps((HDC) dc, BITSPIXEL);
    wxNode*                         pNode = m_svDCCache.First();

    while(pNode)
    {
        wxDCCacheEntry*             pEntry = (wxDCCacheEntry*)pNode->Data();

        //
        // Don't return the same one as we already have
        //
        if (!pNotThis || (pNotThis != pEntry))
        {
            if (pEntry->m_nDepth == nDepth)
            {
                return pEntry;
            }
        }
        pNode = pNode->Next();
    }
    wxDCCacheEntry*                 pEntry = new wxDCCacheEntry( hPS
                                                                ,nDepth
                                                               );
    AddToDCCache(pEntry);
    return pEntry;
} // end of wxPMDCImpl::FindDCInCache

void wxPMDCImpl::AddToBitmapCache(
  wxDCCacheEntry*                   pEntry
)
{
    m_svBitmapCache.Append(pEntry);
} // end of wxPMDCImpl::AddToBitmapCache

void wxPMDCImpl::AddToDCCache(
  wxDCCacheEntry*                   pEntry
)
{
    m_svDCCache.Append(pEntry);
} // end of wxPMDCImpl::AddToDCCache

void wxPMDCImpl::ClearCache()
{
    m_svBitmapCache.DeleteContents(true);
    m_svBitmapCache.Clear();
    m_svBitmapCache.DeleteContents(false);
    m_svDCCache.DeleteContents(true);
    m_svDCCache.Clear();
    m_svDCCache.DeleteContents(false);
} // end of wxPMDCImpl::ClearCache

// Clean up cache at app exit
class wxDCModule : public wxModule
{
public:
    virtual bool OnInit() { return true; }
    virtual void OnExit() { wxPMDCImpl::ClearCache(); }

private:
    DECLARE_DYNAMIC_CLASS(wxDCModule)
}; // end of CLASS wxDCModule

IMPLEMENT_DYNAMIC_CLASS(wxDCModule, wxModule)

#endif // ndef for wxUSE_DC_CACHEING

// ---------------------------------------------------------------------------
// wxDC
// ---------------------------------------------------------------------------

wxPMDCImpl::wxPMDCImpl( wxDC *owner, WXHDC hDC ) :
    wxDCImpl( owner )
{
    Init();
    m_hDC          = hDC;
} // end of wxPMDCImpl::wxPMDCImpl

wxPMDCImpl::~wxPMDCImpl(void)
{
    if ( m_hDC != 0 )
    {
        SelectOldObjects(m_hDC);

        // if we own the HDC, we delete it, otherwise we just release it

        if (m_bOwnsDC)
        {
            if(m_hPS)
            {
                ::GpiAssociate(m_hPS, NULLHANDLE);
                ::GpiDestroyPS(m_hPS);
            }
            m_hPS = NULLHANDLE;
            ::DevCloseDC((HDC)m_hDC);
        }
        else
        {
            //
            // Just Dissacociate, not destroy if we don't own the DC
            //
            if(m_hPS)
            {
                ::GpiAssociate(m_hPS, NULLHANDLE);
            }
        }
    }
} // end of wxPMDCImpl::~wxDC

// This will select current objects out of the DC,
// which is what you have to do before deleting the
// DC.
void wxPMDCImpl::SelectOldObjects(
  WXHDC                             hPS
)
{
    if (hPS)
    {
        if (m_hOldBitmap)
        {
            ::GpiSetBitmap(hPS, (HBITMAP) m_hOldBitmap);
            if (m_vSelectedBitmap.Ok())
            {
                m_vSelectedBitmap.SetSelectedInto(NULL);
            }
        }
        m_hOldBitmap = 0;
        //
        // OS/2 has no other native GDI objects to set in a PS/DC like windows
        //
        m_hOldPen = 0;
        m_hOldBrush = 0;
        m_hOldFont = 0;
        m_hOldPalette = 0;
    }

    m_brush           = wxNullBrush;
    m_pen             = wxNullPen;
    m_palette         = wxNullPalette;
    m_font            = wxNullFont;
    m_backgroundBrush = wxNullBrush;
    m_vSelectedBitmap = wxNullBitmap;
} // end of wxPMDCImpl::SelectOldObjects

// ---------------------------------------------------------------------------
// clipping
// ---------------------------------------------------------------------------

#define DO_SET_CLIPPING_BOX()                    \
{                                                \
    RECTL rect;                                  \
                                                 \
    ::GpiQueryClipBox(m_hPS, &rect);             \
                                                 \
    m_clipX1 = (wxCoord) XDEV2LOG(rect.xLeft);   \
    m_clipY1 = (wxCoord) YDEV2LOG(rect.yTop);    \
    m_clipX2 = (wxCoord) XDEV2LOG(rect.xRight);  \
    m_clipY2 = (wxCoord) YDEV2LOG(rect.yBottom); \
}

void wxPMDCImpl::DoSetClippingRegion(
  wxCoord                           vX
, wxCoord                           vY
, wxCoord                           vWidth
, wxCoord                           vHeight
)
{
    RECTL                           vRect;

    vY = OS2Y(vY,vHeight);
    m_clipping    = true;
    vRect.xLeft   = vX;
    vRect.yTop    = vY + vHeight;
    vRect.xRight  = vX + vWidth;
    vRect.yBottom = vY;
    ::GpiIntersectClipRectangle(m_hPS, &vRect);
    DO_SET_CLIPPING_BOX()
} // end of wxPMDCImpl::DoSetClippingRegion

void wxPMDCImpl::DoSetDeviceClippingRegion(
  const wxRegion&                   rRegion
)
{
     wxCHECK_RET(rRegion.GetHRGN(), wxT("invalid clipping region"));
     HRGN                           hRgnOld;

     m_clipping = true;
     ::GpiSetClipRegion( m_hPS
                        ,(HRGN)rRegion.GetHRGN()
                        ,&hRgnOld
                       );
    DO_SET_CLIPPING_BOX()
} // end of wxPMDCImpl::DoSetDeviceClippingRegion

void wxPMDCImpl::DestroyClippingRegion(void)
{
    if (m_clipping && m_hPS)
    {
         HRGN                       hRgnOld;
         RECTL                      vRect;

         // TODO: this should restore the previous clipped region
         //       so that OnPaint processing works correctly, and
         //       the update doesn't get destroyed after the first
         //       DestroyClippingRegion
         vRect.xLeft   = XLOG2DEV(0);
         vRect.yTop    = YLOG2DEV(32000);
         vRect.xRight  = XLOG2DEV(32000);
         vRect.yBottom = YLOG2DEV(0);

         HRGN                       hRgn = ::GpiCreateRegion(m_hPS, 1, &vRect);

         ::GpiSetClipRegion(m_hPS, hRgn, &hRgnOld);
     }
    ResetClipping();
} // end of wxPMDCImpl::DestroyClippingRegion

// ---------------------------------------------------------------------------
// query capabilities
// ---------------------------------------------------------------------------

bool wxPMDCImpl::CanDrawBitmap() const
{
    return true;
}

bool wxPMDCImpl::CanGetTextExtent() const
{
    LONG                            lTechnology = 0L;

    ::DevQueryCaps(GetHDC(), CAPS_TECHNOLOGY, 1L, &lTechnology);
    return (lTechnology == CAPS_TECH_RASTER_DISPLAY) || (lTechnology == CAPS_TECH_RASTER_PRINTER);
} // end of wxPMDCImpl::CanGetTextExtent

int wxPMDCImpl::GetDepth() const
{
    LONG                            lCapsColorBitcount;
    int                             nBitsPerPixel = 0;

    if(::DevQueryCaps( GetHDC()
                      ,CAPS_COLOR_BITCOUNT
                      ,1L
                      ,&lCapsColorBitcount
                     ))
    {
        nBitsPerPixel = (int)lCapsColorBitcount;
    }
    return nBitsPerPixel;
} // end of wxPMDCImpl::GetDepth

// ---------------------------------------------------------------------------
// drawing
// ---------------------------------------------------------------------------

void wxPMDCImpl::Clear()
{
    //
    // If this is a canvas DC then just fill with the background color
    // Otherwise purge the whole thing
    //
    if (m_pCanvas)
    {
        RECTL                       vRect;

        ::GpiQueryClipBox(m_hPS, &vRect);
        ::WinFillRect(m_hPS, &vRect, ::GpiQueryBackColor(m_hPS));
    }
    else
    ::GpiErase(m_hPS);
} // end of wxPMDCImpl::Clear

bool wxPMDCImpl::DoFloodFill(
  wxCoord                           vX
, wxCoord                           vY
, const wxColour&                   rCol
, wxFloodFillStyle                  nStyle
)
{
    POINTL                          vPtlPos;
    LONG                            lColor;
    LONG                            lOptions;
    LONG                            lHits;
    bool                            bSuccess = false;

    vPtlPos.x = vX;             // Loads x-coordinate
    vPtlPos.y = OS2Y(vY,0);     // Loads y-coordinate
    ::GpiMove(m_hPS, &vPtlPos); // Sets current position
    lColor = rCol.GetPixel();
    lOptions = FF_BOUNDARY;
    if(wxFLOOD_SURFACE == nStyle)
        lOptions = FF_SURFACE;

    if ((lHits = ::GpiFloodFill(m_hPS, lOptions, lColor)) != GPI_ERROR)
        bSuccess = true;

    return bSuccess;
} // end of wxPMDCImpl::DoFloodFill

bool wxPMDCImpl::DoGetPixel(
  wxCoord                           vX
, wxCoord                           vY
, wxColour*                         pCol
) const
{
    POINTL                          vPoint;
    LONG                            lColor;

    vPoint.x = vX;
    vPoint.y = OS2Y(vY,0);
    lColor = ::GpiQueryPel(m_hPS, &vPoint);

    //
    // return the color of the pixel
    //
    if(pCol)
        pCol->Set( GetRValue(lColor)
                  ,GetGValue(lColor)
                  ,GetBValue(lColor)
                 );
    return true;
} // end of wxPMDCImpl::DoGetPixel

void wxPMDCImpl::DoCrossHair(
  wxCoord                           vX
, wxCoord                           vY
)
{
    vY = OS2Y(vY,0);

    wxCoord                         vX1 = vX - VIEWPORT_EXTENT;
    wxCoord                         vY1 = vY - VIEWPORT_EXTENT;
    wxCoord                         vX2 = vX + VIEWPORT_EXTENT;
    wxCoord                         vY2 = vY + VIEWPORT_EXTENT;
    POINTL                          vPoint[4];

    vPoint[0].x = vX1;
    vPoint[0].y = vY;

    vPoint[1].x = vX2;
    vPoint[1].y = vY;

    ::GpiMove(m_hPS, &vPoint[0]);
    ::GpiLine(m_hPS, &vPoint[1]);

    vPoint[2].x = vX;
    vPoint[2].y = vY1;

    vPoint[3].x = vX;
    vPoint[3].y = vY2;

    ::GpiMove(m_hPS, &vPoint[2]);
    ::GpiLine(m_hPS, &vPoint[3]);
    CalcBoundingBox(vX1, vY1);
    CalcBoundingBox(vX2, vY2);
} // end of wxPMDCImpl::DoCrossHair

void wxPMDCImpl::DoDrawLine(
  wxCoord                           vX1
, wxCoord                           vY1
, wxCoord                           vX2
, wxCoord                           vY2
)
{
    POINTL                          vPoint[2];
    COLORREF                        vColor = 0x00ffffff;

    //
    // Might be a memory DC with no Paint rect.
    //
    if (!(m_vRclPaint.yTop == 0 &&
          m_vRclPaint.yBottom == 0 &&
          m_vRclPaint.xRight == 0 &&
          m_vRclPaint.xLeft == 0))
    {
        vY1 = OS2Y(vY1,0);
        vY2 = OS2Y(vY2,0);
    }
    else
    {
        if (m_vSelectedBitmap.Ok())
        {
            m_vRclPaint.yTop = m_vSelectedBitmap.GetHeight();
            m_vRclPaint.xRight = m_vSelectedBitmap.GetWidth();
            vY1 = OS2Y(vY1,0);
            vY2 = OS2Y(vY2,0);
        }
    }
    vPoint[0].x = vX1;
    vPoint[0].y = vY1;
    vPoint[1].x = vX2;
    vPoint[1].y = vY2;
    if (m_pen.Ok())
    {
        vColor = m_pen.GetColour().GetPixel();
    }
    ::GpiSetColor(m_hPS, vColor);
    ::GpiMove(m_hPS, &vPoint[0]);
    ::GpiLine(m_hPS, &vPoint[1]);
    CalcBoundingBox(vX1, vY1);
    CalcBoundingBox(vX2, vY2);
} // end of wxPMDCImpl::DoDrawLine

//////////////////////////////////////////////////////////////////////////////
// Draws an arc of a circle, centred on (xc, yc), with starting point (x1, y1)
// and ending at (x2, y2). The current pen is used for the outline and the
// current brush for filling the shape. The arc is drawn in an anticlockwise
// direction from the start point to the end point.
//////////////////////////////////////////////////////////////////////////////
void wxPMDCImpl::DoDrawArc(
  wxCoord                           vX1
, wxCoord                           vY1
, wxCoord                           vX2
, wxCoord                           vY2
, wxCoord                           vXc
, wxCoord                           vYc
)
{
     POINTL                         vPtlPos;
     POINTL                         vPtlArc[2]; // Structure for current position
     double                         dRadius;
     double                         dAngl1;
     double                         dAngl2;
     double                         dAnglmid;
     wxCoord                        vXm;
     wxCoord                        vYm;
     ARCPARAMS                      vArcp; // Structure for arc parameters

    if((vX1 == vXc && vY1 == vXc) || (vX2 == vXc && vY2 == vXc))
        return; // Draw point ??
    dRadius = 0.5 * ( hypot( (double)(vY1 - vYc)
                            ,(double)(vX1 - vXc)
                           ) +
                      hypot( (double)(vY2 - vYc)
                            ,(double)(vX2 - vXc)
                           )
                     );

    dAngl1 = atan2( (double)(vY1 - vYc)
                   ,(double)(vX1 - vXc)
                  );
    dAngl2 = atan2( (double)(vY2 - vYc)
                   ,(double)(vX2 - vXc)
                  );
    if(dAngl2 < dAngl1)
        dAngl2 += M_PI * 2;

    //
    // GpiPointArc can't draw full arc
    //
     if(dAngl2 == dAngl1 || (vX1 == vX2 && vY1 == vY2) )
     {
        //
        // Medium point
        //
        dAnglmid = (dAngl1 + dAngl2)/2. + M_PI;
        vXm      = (wxCoord)(vXc + dRadius * cos(dAnglmid));
        vYm      = (wxCoord)(vYc + dRadius * sin(dAnglmid));
        DoDrawArc( vX1, vY1
                  ,vXm, vYm
                  ,vXc, vYc
                 );
        DoDrawArc( vXm, vYm
                  ,vX2, vY2
                  ,vXc, vYc
                 );
        return;
    }

    //
    // Medium point
    //
    dAnglmid = (dAngl1 + dAngl2)/2.;
    vXm      = (wxCoord)(vXc + dRadius * cos(dAnglmid));
    vYm      = (wxCoord)(vYc + dRadius * sin(dAnglmid));

    //
    // Ellipse main axis (r,q), (p,s) with center at (0,0) */
    //
    vArcp.lR = 0;
    vArcp.lQ = 1;
    vArcp.lP = 1;
    vArcp.lS = 0;
    ::GpiSetArcParams(m_hPS, &vArcp); // Sets parameters to default

    vPtlPos.x = vX1; // Loads x-coordinate
    vPtlPos.y = vY1; // Loads y-coordinate
    ::GpiMove(m_hPS, &vPtlPos); // Sets current position
    vPtlArc[0].x = vXm;
    vPtlArc[0].y = vYm;
    vPtlArc[1].x = vX2;
    vPtlArc[1].y = vY2;
    ::GpiPointArc(m_hPS, vPtlArc); // Draws the arc
    CalcBoundingBox( (wxCoord)(vXc - dRadius)
                    ,(wxCoord)(vYc - dRadius)
                   );
    CalcBoundingBox( (wxCoord)(vXc + dRadius)
                    ,(wxCoord)(vYc + dRadius)
                   );
} // end of wxPMDCImpl::DoDrawArc

void wxPMDCImpl::DoDrawCheckMark(
  wxCoord                           vX1
, wxCoord                           vY1
, wxCoord                           vWidth
, wxCoord                           vHeight
)
{
    POINTL                          vPoint[2];

    vY1 = OS2Y(vY1,vHeight);

    vPoint[0].x = vX1;
    vPoint[0].y = vY1;
    vPoint[1].x = vX1 + vWidth;
    vPoint[1].y = vY1 + vHeight;

    ::GpiMove(m_hPS, &vPoint[0]);
    ::GpiBox( m_hPS       // handle to a presentation space
             ,DRO_OUTLINE // draw the box outline ? or ?
             ,&vPoint[1]  // address of the corner
             ,0L          // horizontal corner radius
             ,0L          // vertical corner radius
            );
    if(vWidth > 4 && vHeight > 4)
    {
        int                         nTmp;

        vPoint[0].x += 2; vPoint[0].y += 2;
        vPoint[1].x -= 2; vPoint[1].y -= 2;
        ::GpiMove(m_hPS, &vPoint[0]);
        ::GpiLine(m_hPS, &vPoint[1]);
        nTmp = vPoint[0].x;
        vPoint[0].x = vPoint[1].x;
        vPoint[1].x = nTmp;
        ::GpiMove(m_hPS, &vPoint[0]);
        ::GpiLine(m_hPS, &vPoint[1]);
    }
    CalcBoundingBox( vX1
                    ,vY1
                   );

    wxCoord                         vX2 = vX1 + vWidth;
    wxCoord                         vY2 = vY1 + vHeight;

    CalcBoundingBox( vX2
                    ,vY2
                   );
} // end of wxPMDCImpl::DoDrawCheckMark

void wxPMDCImpl::DoDrawPoint(
  wxCoord                           vX
, wxCoord                           vY
)
{
    POINTL                          vPoint;
    COLORREF                        vColor = 0x00ffffff;

    if (m_pen.Ok())
    {
        vColor = m_pen.GetColour().GetPixel();
    }
    ::GpiSetColor(m_hPS, vColor);
    vPoint.x = vX;
    vPoint.y = OS2Y(vY,0);
    ::GpiSetPel(m_hPS, &vPoint);
    CalcBoundingBox( vX
                    ,vY
                   );
} // end of wxPMDCImpl::DoDrawPoint

void wxPMDCImpl::DoDrawPolygon( int n,
                          wxPoint vPoints[],
                          wxCoord vXoffset,
                          wxCoord vYoffset,
                          wxPolygonFillMode nFillStyle )
{
    ULONG     ulCount = 1;    // Number of polygons.
    POLYGON   vPlgn;          // polygon.
    ULONG     flOptions = 0L; // Drawing options.

    //////////////////////////////////////////////////////////////////////////////
    // This contains fields of option bits... to draw boundary lines as well as
    // the area interior.
    //
    // Drawing boundary lines:
    //   POLYGON_NOBOUNDARY              Does not draw boundary lines.
    //   POLYGON_BOUNDARY                Draws boundary lines (the default).
    //
    // Construction of the area interior:
    //   POLYGON_ALTERNATE               Constructs interior in alternate mode
    //                                   (the default).
    //   POLYGON_WINDING                 Constructs interior in winding mode.
    //////////////////////////////////////////////////////////////////////////////

    ULONG     flModel = POLYGON_INCL; // Drawing model.

    //////////////////////////////////////////////////////////////////////////////
    // Drawing model.
    //   POLYGON_INCL  Fill is inclusive of bottom right (the default).
    //   POLYGON_EXCL  Fill is exclusive of bottom right.
    //       This is provided to aid migration from other graphics models.
    //////////////////////////////////////////////////////////////////////////////

    LONG      lHits = 0L; // Correlation/error indicator.
    int       i;
    int       nIsTRANSPARENT = 0;
    LONG      lBorderColor = 0L;
    LONG      lColor = 0L;

    lBorderColor = m_pen.GetColour().GetPixel();
    lColor       = m_brush.GetColour().GetPixel();
    if(m_brush.GetStyle() == wxTRANSPARENT)
        nIsTRANSPARENT = 1;

    vPlgn.ulPoints = n;
    vPlgn.aPointl = (POINTL*) calloc( n + 1
                                     ,sizeof(POINTL)
                                    ); // well, new will call malloc

    for(i = 0; i < n; i++)
    {
        vPlgn.aPointl[i].x = vPoints[i].x+vXoffset;
        vPlgn.aPointl[i].y = OS2Y(vPoints[i].y+vYoffset,0);
    }
    flOptions = POLYGON_BOUNDARY;
    if(nFillStyle == wxWINDING_RULE)
        flOptions |= POLYGON_WINDING;
    else
        flOptions |= POLYGON_ALTERNATE;

    ::GpiSetColor(m_hPS, lBorderColor);
    ::GpiMove(m_hPS, &vPlgn.aPointl[0]);
    lHits = ::GpiPolygons(m_hPS, ulCount, &vPlgn, flOptions, flModel);
    free(vPlgn.aPointl);
} // end of wxPMDCImpl::DoDrawPolygon

void wxPMDCImpl::DoDrawLines(
  int                               n
, wxPoint                           vPoints[]
, wxCoord                           vXoffset
, wxCoord                           vYoffset
)
{
    POINTL                          vPoint;

    if (vXoffset != 0L || vXoffset != 0L)
    {
        int                             i;

        vPoint.x = vPoints[0].x + vXoffset;
        vPoint.y = OS2Y(vPoints[0].y + vYoffset,0);
        ::GpiMove(m_hPS, &vPoint);

        LONG                            lBorderColor = m_pen.GetColour().GetPixel();

        ::GpiSetColor(m_hPS, lBorderColor);
        for(i = 1; i < n; i++)
        {
            vPoint.x = vPoints[i].x + vXoffset;
            vPoint.y = OS2Y(vPoints[i].y + vYoffset,0);
            ::GpiLine(m_hPS, &vPoint);
        }
    }
    else
    {
        int                         i;

        CalcBoundingBox( vPoints[0].x
                        ,vPoints[0].y
                       );
        vPoint.x = vPoints[0].x;
        vPoint.y = OS2Y(vPoints[0].y,0);
        ::GpiMove(m_hPS, &vPoint);

        for (i = 0; i < n; i++)
        {
            CalcBoundingBox( vPoints[i].x
                            ,vPoints[i].y
                           );
            vPoint.x = vPoints[i].x;
            vPoint.y = OS2Y(vPoints[i].y,0);
            ::GpiLine(m_hPS, &vPoint);
        }
    }
} // end of wxPMDCImpl::DoDrawLines

void wxPMDCImpl::DoDrawRectangle(
  wxCoord                           vX
, wxCoord                           vY
, wxCoord                           vWidth
, wxCoord                           vHeight
)
{
    POINTL                          vPoint[2];
    LONG                            lControl;
    LONG                            lColor;
    LONG                            lBorderColor;
    int                             nIsTRANSPARENT = 0;

    //
    // Might be a memory DC with no Paint rect.
    //
    if (!(m_vRclPaint.yTop == 0 &&
          m_vRclPaint.yBottom == 0 &&
          m_vRclPaint.xRight == 0 &&
          m_vRclPaint.xLeft == 0))
        vY = OS2Y(vY,vHeight);
    else
    {
        if (m_vSelectedBitmap.Ok())
        {
            m_vRclPaint.yTop = m_vSelectedBitmap.GetHeight();
            m_vRclPaint.xRight = m_vSelectedBitmap.GetWidth();
            vY = OS2Y(vY,vHeight);
        }
    }

    wxCoord                         vX2 = vX + vWidth;
    wxCoord                         vY2 = vY + vHeight;

    vPoint[0].x = vX;
    vPoint[0].y = vY;
    vPoint[1].x = vX + vWidth - 1;
    vPoint[1].y = vY + vHeight - 1;
    ::GpiMove(m_hPS, &vPoint[0]);
    lColor       = m_brush.GetColour().GetPixel();
    lBorderColor = m_pen.GetColour().GetPixel();
    if (m_brush.GetStyle() == wxTRANSPARENT)
        nIsTRANSPARENT = 1;
    if(lColor == lBorderColor || nIsTRANSPARENT)
    {
        lControl = DRO_OUTLINEFILL; //DRO_FILL;
        if(m_brush.GetStyle() == wxTRANSPARENT)
            lControl = DRO_OUTLINE;

        ::GpiSetColor(m_hPS, lBorderColor);
        ::GpiBox( m_hPS       // handle to a presentation space
                 ,lControl   // draw the box outline ? or ?
                 ,&vPoint[1]  // address of the corner
                 ,0L          // horizontal corner radius
                 ,0L          // vertical corner radius
                );
    }
    else
    {
        lControl = DRO_OUTLINE;
        ::GpiSetColor( m_hPS
                      ,lBorderColor
                     );
        ::GpiBox( m_hPS
                 ,lControl
                 ,&vPoint[1]
                 ,0L
                 ,0L
                );
        lControl = DRO_FILL;
        ::GpiSetColor( m_hPS
                      ,lColor
                     );
        vPoint[0].x = vX + 1;
        vPoint[0].y = vY + 1;
        vPoint[1].x = vX + vWidth - 2;
        vPoint[1].y = vY + vHeight - 2;
        ::GpiMove(m_hPS, &vPoint[0]);
        ::GpiBox( m_hPS
                 ,lControl
                 ,&vPoint[1]
                 ,0L
                 ,0L
                );
    }
    CalcBoundingBox(vX, vY);
    CalcBoundingBox(vX2, vY2);
} // end of wxPMDCImpl::DoDrawRectangle

void wxPMDCImpl::DoDrawRoundedRectangle(
  wxCoord                           vX
, wxCoord                           vY
, wxCoord                           vWidth
, wxCoord                           vHeight
, double                            dRadius
)
{
    POINTL                          vPoint[2];
    LONG                            lControl;
    LONG                            lColor;
    LONG                            lBorderColor;
    int                             nIsTRANSPARENT = 0;

    //
    // Might be a memory DC with no Paint rect.
    //
    if (!(m_vRclPaint.yTop == 0 &&
          m_vRclPaint.yBottom == 0 &&
          m_vRclPaint.xRight == 0 &&
          m_vRclPaint.xLeft == 0))
        vY = OS2Y(vY,vHeight);
    else
    {
        if (m_vSelectedBitmap.Ok())
        {
            m_vRclPaint.yTop = m_vSelectedBitmap.GetHeight();
            m_vRclPaint.xRight = m_vSelectedBitmap.GetWidth();
            vY = OS2Y(vY,vHeight);
        }
    }

    wxCoord                         vX2 = (vX + vWidth);
    wxCoord                         vY2 = (vY + vHeight);

    vPoint[0].x = vX;
    vPoint[0].y = vY;
    vPoint[1].x = vX + vWidth - 1;
    vPoint[1].y = vY + vHeight - 1;
    ::GpiMove(m_hPS, &vPoint[0]);

    lColor       = m_brush.GetColour().GetPixel();
    lBorderColor = m_pen.GetColour().GetPixel();
    lControl = DRO_OUTLINEFILL; //DRO_FILL;
    if (m_brush.GetStyle() == wxTRANSPARENT)
        nIsTRANSPARENT = 1;
    if(lColor == lBorderColor || nIsTRANSPARENT)
    {
        lControl = DRO_OUTLINEFILL; //DRO_FILL;
        if(m_brush.GetStyle() == wxTRANSPARENT)
            lControl = DRO_OUTLINE;

        ::GpiSetColor(m_hPS, lColor);
        ::GpiBox( m_hPS         // handle to a presentation space
                 ,lControl      // draw the box outline ? or ?
                 ,&vPoint[1]    // address of the corner
                 ,(LONG)dRadius // horizontal corner radius
                 ,(LONG)dRadius // vertical corner radius
                );
    }
    else
    {
        lControl = DRO_OUTLINE;
        ::GpiSetColor( m_hPS
                      ,lBorderColor
                     );
        ::GpiBox( m_hPS
                 ,lControl
                 ,&vPoint[1]
                 ,(LONG)dRadius
                 ,(LONG)dRadius
                );
        lControl = DRO_FILL;
        ::GpiSetColor( m_hPS
                      ,lColor
                     );
        vPoint[0].x = vX + 1;
        vPoint[0].y = vY + 1;
        vPoint[1].x = vX + vWidth - 2;
        vPoint[1].y = vY + vHeight - 2;
        ::GpiMove(m_hPS, &vPoint[0]);
        ::GpiBox( m_hPS
                 ,lControl
                 ,&vPoint[1]
                 ,(LONG)dRadius
                 ,(LONG)dRadius
                );
    }

    CalcBoundingBox(vX, vY);
    CalcBoundingBox(vX2, vY2);
} // end of wxPMDCImpl::DoDrawRoundedRectangle

// Draw Ellipse within box (x,y) - (x+width, y+height)
void wxPMDCImpl::DoDrawEllipse(
  wxCoord                           vX
, wxCoord                           vY
, wxCoord                           vWidth
, wxCoord                           vHeight
)
{
    POINTL                          vPtlPos; // Structure for current position
    FIXED                           vFxMult; // Multiplier for ellipse
    ARCPARAMS                       vArcp;   // Structure for arc parameters

    vY = OS2Y(vY,vHeight);

    vArcp.lR = 0;
    vArcp.lQ = vHeight/2;
    vArcp.lP = vWidth/2;
    vArcp.lS = 0;
    ::GpiSetArcParams( m_hPS
                      ,&vArcp
                     ); // Sets parameters to default
    vPtlPos.x = vX + vWidth/2;  // Loads x-coordinate
    vPtlPos.y = vY + vHeight/2; // Loads y-coordinate
    ::GpiMove( m_hPS
              ,&vPtlPos
             ); // Sets current position
    vFxMult = MAKEFIXED(1, 0);             /* Sets multiplier            */

    //
    // DRO_FILL, DRO_OTLINEFILL - where to get
    //
    ::GpiFullArc( m_hPS
                 ,DRO_OUTLINE
                 ,vFxMult
                ); // Draws full arc with center at current position

    wxCoord                         vX2 = (vX + vWidth);
    wxCoord                         vY2 = (vY + vHeight);

    CalcBoundingBox(vX, vY);
    CalcBoundingBox(vX2, vY2);
} // end of wxPMDCImpl::DoDrawEllipse

void wxPMDCImpl::DoDrawEllipticArc(
  wxCoord                           vX
, wxCoord                           vY
, wxCoord                           vWidth
, wxCoord                           vHeight
, double                            dSa
, double                            dEa
)
{
    POINTL                          vPtlPos; // Structure for current position
    FIXED                           vFxMult; // Multiplier for ellipse
    ARCPARAMS                       vArcp;   // Structure for arc parameters
    FIXED                           vFSa;
    FIXED                           vFSweepa; // Start angle, sweep angle
    double                          dIntPart;
    double                          dFractPart;

    vY = OS2Y(vY,vHeight);

    dFractPart = modf(dSa,&dIntPart);
    vFSa = MAKEFIXED((int)dIntPart, (int)(dFractPart * 0xffff) );
    dFractPart = modf(dEa - dSa, &dIntPart);
    vFSweepa = MAKEFIXED((int)dIntPart, (int)(dFractPart * 0xffff) );

    //
    // Ellipse main axis (r,q), (p,s) with center at (0,0)
    //
    vArcp.lR = 0;
    vArcp.lQ = vHeight/2;
    vArcp.lP = vWidth/2;
    vArcp.lS = 0;
    ::GpiSetArcParams(m_hPS, &vArcp); // Sets parameters to default
    vPtlPos.x = (wxCoord)(vX + vWidth/2  * (1. + cos(DegToRad(dSa)))); // Loads x-coordinate
    vPtlPos.y = (wxCoord)(vY + vHeight/2 * (1. + sin(DegToRad(dSa)))); // Loads y-coordinate
    ::GpiMove(m_hPS, &vPtlPos); // Sets current position

    //
    // May be not to the center ?
    //
    vPtlPos.x = vX + vWidth/2 ; // Loads x-coordinate
    vPtlPos.y = vY + vHeight/2; // Loads y-coordinate
    vFxMult = MAKEFIXED(1, 0);  // Sets multiplier

    //
    // DRO_FILL, DRO_OTLINEFILL - where to get
    //
    ::GpiPartialArc( m_hPS
                    ,&vPtlPos
                    ,vFxMult
                    ,vFSa
                    ,vFSweepa
                   );
    wxCoord                         vX2 = (vX + vWidth);
    wxCoord                         vY2 = (vY + vHeight);

    CalcBoundingBox(vX, vY);
    CalcBoundingBox(vX2, vY2);
} // end of wxPMDCImpl::DoDrawEllipticArc

void wxPMDCImpl::DoDrawIcon(
  const wxIcon&                     rIcon
, wxCoord                           vX
, wxCoord                           vY
)
{
    //
    // Need to copy back into a bitmap.  ::WinDrawPointer uses device coords
    // and I don't feel like figuring those out for scrollable windows so
    // just convert to a bitmap then let the DoDrawBitmap routine display it
    //
    if (rIcon.IsXpm())
    {
        DoDrawBitmap(rIcon.GetXpmSrc(), vX, vY, true);
    }
    else
    {
        wxBitmap                        vBitmap(rIcon);

        DoDrawBitmap(vBitmap, vX, vY, false);
    }
    CalcBoundingBox(vX, vY);
    CalcBoundingBox(vX + rIcon.GetWidth(), vY + rIcon.GetHeight());
} // end of wxPMDCImpl::DoDrawIcon

void wxPMDCImpl::DoDrawBitmap(
  const wxBitmap&                   rBmp
, wxCoord                           vX
, wxCoord                           vY
, bool                              bUseMask
)
{
#if wxUSE_PRINTING_ARCHITECTURE
    if (!IsKindOf(CLASSINFO(wxPrinterDC)))
#endif
    {
        HBITMAP                         hBitmap =  (HBITMAP)rBmp.GetHBITMAP();
        HBITMAP                         hBitmapOld = NULLHANDLE;
        POINTL                          vPoint[4];

        vY = OS2Y(vY,rBmp.GetHeight());

        vPoint[0].x = vX;
        vPoint[0].y = vY + rBmp.GetHeight();
        vPoint[1].x = vX + rBmp.GetWidth();
        vPoint[1].y = vY;
        vPoint[2].x = 0;
        vPoint[2].y = 0;
        vPoint[3].x = rBmp.GetWidth();
        vPoint[3].y = rBmp.GetHeight();
        if (bUseMask)
        {
            wxMask*                     pMask = rBmp.GetMask();

            if (pMask)
            {
                //
                // Need to imitate ::MaskBlt in windows.
                // 1) Extract the bits from from the bitmap.
                // 2) Extract the bits from the mask
                // 3) Using the mask bits do the following:
                //   A) If the mask byte is 00 leave the bitmap byte alone
                //   B) If the mask byte is FF copy the screen color into
                //      bitmap byte
                // 4) Create a new bitmap and set its bits to the above result
                // 5) Blit this to the screen PS
                //
                HBITMAP                 hMask = (HBITMAP)pMask->GetMaskBitmap();
                HBITMAP                 hOldMask   = NULLHANDLE;
                HBITMAP                 hOldBitmap = NULLHANDLE;
                HBITMAP                 hNewBitmap = NULLHANDLE;
                unsigned char*          pucBits;     // buffer that will contain the bitmap data
                unsigned char*          pucBitsMask; // buffer that will contain the mask data
                unsigned char*          pucData;     // pointer to use to traverse bitmap data
                unsigned char*          pucDataMask; // pointer to use to traverse mask data
                LONG                    lHits;
                ERRORID                 vError;
                wxString                sError;

                //
                // The usual Memory context creation stuff
                //
                DEVOPENSTRUC                    vDop  = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
                SIZEL                           vSize = {0, 0};
                HDC                             hDC   = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
                HPS                             hPS   = ::GpiCreatePS(vHabmain, hDC, &vSize, PU_PELS | GPIA_ASSOC);

                //
                // The usual bitmap header stuff
                //
                BITMAPINFOHEADER2               vHeader;
                BITMAPINFO2                     vInfo;

                memset(&vHeader, '\0', 16);
                vHeader.cbFix           = 16;

                memset(&vInfo, '\0', 16);
                vInfo.cbFix           = 16;
                vInfo.cx              = (ULONG)rBmp.GetWidth();
                vInfo.cy              = (ULONG)rBmp.GetHeight();
                vInfo.cPlanes         = 1;
                vInfo.cBitCount       = 24; // Set to desired count going in

                //
                // Create the buffers for data....all wxBitmaps are 24 bit internally
                //
                int                     nBytesPerLine = rBmp.GetWidth() * 3;
                int                     nSizeDWORD    = sizeof(DWORD);
                int                     nLineBoundary = nBytesPerLine % nSizeDWORD;
                int                     nPadding = 0;
                int                     i;
                int                     j;
                LONG                    lScans = 0L;
                LONG                    lColor = 0L;

                //
                // Need to get a background color for mask blitting
                //
                if (IsKindOf(CLASSINFO(wxWindowDCImpl)))
                {
                    wxWindowDCImpl*  pWindowDC = wxDynamicCast(this, wxWindowDCImpl);

                    lColor = pWindowDC->m_pCanvas->GetBackgroundColour().GetPixel();
                }
                else if (GetBrush().Ok())
                    lColor = GetBrush().GetColour().GetPixel();
                else
                    lColor = m_textBackgroundColour.GetPixel();

                //
                // Bitmap must be in a double-word aligned address so we may
                // have some padding to worry about
                //
                if (nLineBoundary > 0)
                {
                    nPadding     = nSizeDWORD - nLineBoundary;
                    nBytesPerLine += nPadding;
                }
                pucBits = (unsigned char *)malloc(nBytesPerLine * rBmp.GetHeight());
                pucBitsMask = (unsigned char *)malloc(nBytesPerLine * rBmp.GetHeight());
                memset(pucBits, '\0', (nBytesPerLine * rBmp.GetHeight()));
                memset(pucBitsMask, '\0', (nBytesPerLine * rBmp.GetHeight()));

                //
                // Extract the bitmap and mask data
                //
                if ((hOldBitmap = ::GpiSetBitmap(hPS, hBitmap)) == HBM_ERROR)
                {
                    vError = ::WinGetLastError(vHabmain);
                    sError = wxPMErrorToStr(vError);
                }
                ::GpiQueryBitmapInfoHeader(hBitmap, &vHeader);
                vInfo.cBitCount = 24;
                if ((lScans = ::GpiQueryBitmapBits( hPS
                                                   ,0L
                                                   ,(LONG)rBmp.GetHeight()
                                                   ,(PBYTE)pucBits
                                                   ,&vInfo
                                                  )) == GPI_ALTERROR)
                {
                    vError = ::WinGetLastError(vHabmain);
                    sError = wxPMErrorToStr(vError);
                }
                if ((hOldMask = ::GpiSetBitmap(hPS, hMask)) == HBM_ERROR)
                {
                    vError = ::WinGetLastError(vHabmain);
                    sError = wxPMErrorToStr(vError);
                }
                ::GpiQueryBitmapInfoHeader(hMask, &vHeader);
                vInfo.cBitCount = 24;
                if ((lScans = ::GpiQueryBitmapBits( hPS
                                                   ,0L
                                                   ,(LONG)rBmp.GetHeight()
                                                   ,(PBYTE)pucBitsMask
                                                   ,&vInfo
                                                  )) == GPI_ALTERROR)
                {
                    vError = ::WinGetLastError(vHabmain);
                    sError = wxPMErrorToStr(vError);
                }
                if (( hMask = ::GpiSetBitmap(hPS, hOldMask)) == HBM_ERROR)
                {
                    vError = ::WinGetLastError(vHabmain);
                    sError = wxPMErrorToStr(vError);
                }

                //
                // Now set the bytes(bits) according to the mask values
                // 3 bytes per pel...must handle one at a time
                //
                pucData     = pucBits;
                pucDataMask = pucBitsMask;

                //
                // 16 bit kludge really only kinda works.  The mask gets applied
                // where needed but the original bitmap bits are dorked sometimes
                //
                bool                    bpp16 = (wxDisplayDepth() == 16);

                for (i = 0; i < rBmp.GetHeight(); i++)
                {
                    for (j = 0; j < rBmp.GetWidth(); j++)
                    {
                        // Byte 1
                        if (bpp16 && *pucDataMask == 0xF8) // 16 bit display gobblygook
                            pucData++;
                        else if (*pucDataMask == 0xFF) // leave bitmap byte alone
                            pucData++;
                        else
                        {
                            *pucData = ((unsigned char)(lColor >> 16));
                            pucData++;
                        }
                        // Byte 2
                        if (bpp16 && *(pucDataMask + 1) == 0xFC) // 16 bit display gobblygook
                            pucData++;
                        else if (*(pucDataMask + 1) == 0xFF) // leave bitmap byte alone
                            pucData++;
                        else
                        {
                            *pucData = ((unsigned char)(lColor >> 8));
                            pucData++;
                        }

                        // Byte 3
                        if (bpp16 && *(pucDataMask + 2) == 0xF8) // 16 bit display gobblygook
                            pucData++;
                        else if (*(pucDataMask + 2) == 0xFF) // leave bitmap byte alone
                            pucData++;
                        else
                        {
                            *pucData = ((unsigned char)lColor);
                            pucData++;
                        }
                        pucDataMask += 3;
                    }
                    for (j = 0; j < nPadding; j++)
                    {
                        pucData++;
                        pucDataMask++;
                    }
                }
                //
                // Create a new bitmap
                //
                vHeader.cx              = (ULONG)rBmp.GetWidth();
                vHeader.cy              = (ULONG)rBmp.GetHeight();
                vHeader.cPlanes         = 1L;
                vHeader.cBitCount       = 24;
                if ((hNewBitmap = ::GpiCreateBitmap( hPS
                                                    ,&vHeader
                                                    ,CBM_INIT
                                                    ,(PBYTE)pucBits
                                                    ,&vInfo
                                                   )) == GPI_ERROR)
                {
                    vError = ::WinGetLastError(vHabmain);
                    sError = wxPMErrorToStr(vError);
                }

                //
                // Now blit it to the screen PS
                //
                if ((lHits = ::GpiWCBitBlt( (HPS)GetHPS()
                                           ,hNewBitmap
                                           ,4
                                           ,vPoint
                                           ,ROP_SRCCOPY
                                           ,BBO_IGNORE
                                          )) == GPI_ERROR)
                {
                    vError = ::WinGetLastError(vHabmain);
                    sError = wxPMErrorToStr(vError);
                }

                //
                // Clean up
                //
                free(pucBits);
                free(pucBitsMask);
                ::GpiSetBitmap(hPS, NULLHANDLE);
                ::GpiDeleteBitmap(hNewBitmap);
                ::GpiDestroyPS(hPS);
                ::DevCloseDC(hDC);
            }
        }
        else
        {
            ULONG                       lOldForeGround = ::GpiQueryColor((HPS)GetHPS());
            ULONG                       lOldBackGround = ::GpiQueryBackColor((HPS)GetHPS());

            if (m_textForegroundColour.Ok())
            {
                ::GpiSetColor( (HPS)GetHPS()
                               ,m_textForegroundColour.GetPixel()
                              );
            }
            if (m_textBackgroundColour.Ok())
            {
                ::GpiSetBackColor( (HPS)GetHPS()
                                  ,m_textBackgroundColour.GetPixel()
                                 );
            }
            //
            // Need to alter bits in a mono bitmap to match the new
            // background-foreground if it is different.
            //
            if (rBmp.IsMono() &&
               ((m_textForegroundColour.GetPixel() != lOldForeGround) ||
                (m_textBackgroundColour.GetPixel() != lOldBackGround)))
            {
                DEVOPENSTRUC        vDop  = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
                SIZEL               vSize = {0, 0};
                HDC                 hDC   = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDop, NULLHANDLE);
                HPS                 hPS   = ::GpiCreatePS(vHabmain, hDC, &vSize, PU_PELS | GPIA_ASSOC);

                int                 nBytesPerLine = rBmp.GetWidth() * 3;
                int                 i, j;
                LONG                lForeGround = m_textForegroundColour.GetPixel();
                LONG                lBackGround = m_textBackgroundColour.GetPixel();
                LONG                lScans;
                HBITMAP             hOldBitmap = NULLHANDLE;
                BITMAPINFO2         vInfo;
                ERRORID             vError;
                wxString            sError;


                memset(&vInfo, '\0', 16);
                vInfo.cbFix           = 16;
                vInfo.cx              = (ULONG)rBmp.GetWidth();
                vInfo.cy              = (ULONG)rBmp.GetHeight();
                vInfo.cPlanes         = 1;
                vInfo.cBitCount       = 24;

                unsigned char*          pucBits;     // buffer that will contain the bitmap data
                unsigned char*          pucData;     // pointer to use to traverse bitmap data

                pucBits = new unsigned char[nBytesPerLine * rBmp.GetHeight()];
                memset(pucBits, '\0', (nBytesPerLine * rBmp.GetHeight()));

                if ((hOldBitmap = ::GpiSetBitmap(hPS, hBitmap)) == HBM_ERROR)
                {
                    vError = ::WinGetLastError(vHabmain);
                    sError = wxPMErrorToStr(vError);
                    return;
                }
                if ((lScans = ::GpiQueryBitmapBits( hPS
                                                   ,0L
                                                   ,(LONG)rBmp.GetHeight()
                                                   ,(PBYTE)pucBits
                                                   ,&vInfo
                                                  )) == GPI_ALTERROR)
                {
                    vError = ::WinGetLastError(vHabmain);
                    sError = wxPMErrorToStr(vError);
                    return;
                }
                unsigned char           cOldRedFore   = (unsigned char)(lOldForeGround >> 16);
                unsigned char           cOldGreenFore = (unsigned char)(lOldForeGround >> 8);
                unsigned char           cOldBlueFore  = (unsigned char)lOldForeGround;

                unsigned char           cRedFore   = (unsigned char)(lForeGround >> 16);
                unsigned char           cGreenFore = (unsigned char)(lForeGround >> 8);
                unsigned char           cBlueFore  = (unsigned char)lForeGround;

                unsigned char           cRedBack   = (unsigned char)(lBackGround >> 16);
                unsigned char           cGreenBack = (unsigned char)(lBackGround >> 8);
                unsigned char           cBlueBack  = (unsigned char)lBackGround;

                pucData = pucBits;
                for (i = 0; i < rBmp.GetHeight(); i++)
                {
                    for (j = 0; j < rBmp.GetWidth(); j++)
                    {
                        unsigned char    cBmpRed   = *pucData;
                        unsigned char    cBmpGreen = *(pucData + 1);
                        unsigned char    cBmpBlue  = *(pucData + 2);

                        if ((cBmpRed == cOldRedFore) &&
                            (cBmpGreen == cOldGreenFore) &&
                            (cBmpBlue == cOldBlueFore))
                        {
                            *pucData = cBlueFore;
                            pucData++;
                            *pucData = cGreenFore;
                            pucData++;
                            *pucData = cRedFore;
                            pucData++;
                        }
                        else
                        {
                            *pucData = cBlueBack;
                            pucData++;
                            *pucData = cGreenBack;
                            pucData++;
                            *pucData = cRedBack;
                            pucData++;
                        }
                    }
                }
                if ((lScans = ::GpiSetBitmapBits( hPS
                                                 ,0L
                                                 ,(LONG)rBmp.GetHeight()
                                                 ,(PBYTE)pucBits
                                                 ,&vInfo
                                                )) == GPI_ALTERROR)
                {
                    vError = ::WinGetLastError(vHabmain);
                    sError = wxPMErrorToStr(vError);
                    return;
                }
                delete [] pucBits;
                ::GpiSetBitmap(hPS, NULLHANDLE);
                ::GpiDestroyPS(hPS);
                ::DevCloseDC(hDC);
            }
            ::GpiWCBitBlt( (HPS)GetHPS()
                          ,hBitmap
                          ,4
                          ,vPoint
                          ,ROP_SRCCOPY
                          ,BBO_IGNORE
                         );
            ::GpiSetBitmap((HPS)GetHPS(), hBitmapOld);
            ::GpiSetColor((HPS)GetHPS(), lOldForeGround);
            ::GpiSetBackColor((HPS)GetHPS(), lOldBackGround);
        }
    }
} // end of wxPMDCImpl::DoDrawBitmap

void wxPMDCImpl::DoDrawText(
  const wxString&                   rsText
, wxCoord                           vX
, wxCoord                           vY
)
{
    wxCoord                         vWidth;
    wxCoord                         vHeight;

    DrawAnyText( rsText
                ,vX
                ,vY
               );

    CalcBoundingBox(vX, vY);
    GetOwner()->GetTextExtent(rsText, &vWidth, &vHeight);
    CalcBoundingBox((vX + vWidth), (vY + vHeight));
} // end of wxPMDCImpl::DoDrawText

void wxPMDCImpl::DrawAnyText( const wxString& rsText,
                        wxCoord vX,
                        wxCoord vY )
{
    int                             nOldBackground = 0;
    POINTL                          vPtlStart;
    LONG                            lHits;
    wxCoord                         vTextX = 0;
    wxCoord                         vTextY = 0;

    //
    // prepare for drawing the text
    //

    //
    // Set text color attributes
    //
    if (m_textForegroundColour.Ok())
    {
        SetTextColor( m_hPS
                     ,(int)m_textForegroundColour.GetPixel()
                    );
    }

    if (m_textBackgroundColour.Ok())
    {
        nOldBackground = SetTextBkColor( m_hPS
                                        ,(int)m_textBackgroundColour.GetPixel()
                                       );
    }
    SetBkMode( m_hPS
              ,m_backgroundMode
             );
    GetOwner()->GetTextExtent( rsText
                              ,&vTextX
                              ,&vTextY
                             );
    vPtlStart.x = vX;
    if (!(m_vRclPaint.yTop == 0 &&
          m_vRclPaint.yBottom == 0 &&
          m_vRclPaint.xRight == 0 &&
          m_vRclPaint.xLeft == 0))
    {
        vPtlStart.y = OS2Y(vY,vTextY);
    }
    else
    {
        if (m_vSelectedBitmap.Ok())
        {
            m_vRclPaint.yTop = m_vSelectedBitmap.GetHeight();
            m_vRclPaint.xRight = m_vSelectedBitmap.GetWidth();
            vPtlStart.y = OS2Y(vY,vTextY);
        }
        else
            vPtlStart.y = vY;
    }

    ::GpiMove(m_hPS, &vPtlStart);
    lHits = ::GpiCharString( m_hPS
                            ,rsText.length()
                            ,rsText.char_str()
                           );
    if (lHits != GPI_OK)
    {
        wxLogLastError(wxT("TextOut"));
    }

    //
    // Restore the old parameters (text foreground colour may be left because
    // it never is set to anything else, but background should remain
    // transparent even if we just drew an opaque string)
    //
    if (m_textBackgroundColour.Ok())
            SetTextBkColor( m_hPS
                           ,nOldBackground
                          );
    SetBkMode( m_hPS
              ,wxTRANSPARENT
             );
}

void wxPMDCImpl::DoDrawRotatedText(
  const wxString&                   rsText
, wxCoord                           vX
, wxCoord                           vY
, double                            dAngle
)
{
    if (dAngle == 0.0)
    {
        DoDrawText( rsText
                   ,vX
                   ,vY
                  );
    }

   // TODO:
   /*
    if ( angle == 0.0 )
    {
        DoDrawText(text, x, y);
    }
    else
    {
        LOGFONT lf;
        wxFillLogFont(&lf, &m_font);

        // GDI wants the angle in tenth of degree
        long angle10 = (long)(angle * 10);
        lf.lfEscapement = angle10;
        lf. lfOrientation = angle10;

        HFONT hfont = ::CreateFontIndirect(&lf);
        if ( !hfont )
        {
            wxLogLastError("CreateFont");
        }
        else
        {
            HFONT hfontOld = ::SelectObject(GetHdc(), hfont);

            DrawAnyText(text, x, y);

            (void)::SelectObject(GetHdc(), hfontOld);
        }

        // call the bounding box by adding all four vertices of the rectangle
        // containing the text to it (simpler and probably not slower than
        // determining which of them is really topmost/leftmost/...)
        wxCoord w, h;
        GetTextExtent(text, &w, &h);

        double rad = DegToRad(angle);

        // "upper left" and "upper right"
        CalcBoundingBox(x, y);
        CalcBoundingBox(x + w*cos(rad), y - h*sin(rad));
        CalcBoundingBox(x + h*sin(rad), y + h*cos(rad));

        // "bottom left" and "bottom right"
        x += (wxCoord)(h*sin(rad));
        y += (wxCoord)(h*cos(rad));
        CalcBoundingBox(x, y);
        CalcBoundingBox(x + h*sin(rad), y + h*cos(rad));
    }
*/
}

// ---------------------------------------------------------------------------
// set GDI objects
// ---------------------------------------------------------------------------

void wxPMDCImpl::DoSelectPalette( bool WXUNUSED(bRealize) )
{
    //
    // Set the old object temporarily, in case the assignment deletes an object
    // that's not yet selected out.
    //
    if (m_hOldPalette)
    {
        m_hOldPalette = 0;
    }

    if (m_palette.Ok())
    {
        HPALETTE                    hOldPal;

        hOldPal = ::GpiSelectPalette((HDC) m_hPS, (HPALETTE) m_palette.GetHPALETTE());
        if (!m_hOldPalette)
            m_hOldPalette = (WXHPALETTE)hOldPal;
    }
} // end of wxPMDCImpl::DoSelectPalette

void wxPMDCImpl::InitializePalette()
{
    if (wxDisplayDepth() <= 8 )
    {
        //
        // Look for any window or parent that has a custom palette. If any has
        // one then we need to use it in drawing operations
        //
        wxWindow*                   pWin = m_pCanvas->GetAncestorWithCustomPalette();

        m_hasCustomPalette = pWin && pWin->HasCustomPalette();
        if (m_hasCustomPalette)
        {
            m_palette = pWin->GetPalette();

            //
            // turn on PM translation for this palette
            //
            DoSelectPalette();
        }
    }
} // end of wxPMDCImpl::InitializePalette

void wxPMDCImpl::SetPalette(
  const wxPalette&                  rPalette
)
{
    if (m_hOldFont)
    {
        m_hOldFont = 0;
    }
    m_palette = rPalette;
    if (!rPalette.Ok())
    {
        if (m_hOldFont)
        {
            m_hOldFont = 0;
        }
    }
    HPALETTE                    hOldPal = ::GpiSelectPalette((HDC) m_hPS, (HPALETTE) m_palette.GetHPALETTE());
    if (!m_hOldPalette)
        m_hOldPalette = (WXHPALETTE)hOldPal;
} // end of wxPMDCImpl::SetPalette

void wxPMDCImpl::SetFont(
  const wxFont&                     rFont
)
{
    //
    // Set the old object temporarily, in case the assignment deletes an object
    // that's not yet selected out.
    //
    if (m_hOldFont)
    {
        m_hOldFont = 0;
    }
    m_font = rFont;
    if (!rFont.Ok())
    {
        m_hOldFont = 0;
    }

    m_font.SetPS(m_hPS); // this will realize the font

    if (m_font.Ok())
    {
        HFONT                       hFont = m_font.GetResourceHandle();
        if (hFont == (HFONT) NULL)
        {
            wxLogDebug(wxT("::SelectObject failed in wxPMDCImpl::SetFont."));
        }
        if (!m_hOldFont)
            m_hOldFont = (WXHFONT) hFont;
    }
} // end of wxPMDCImpl::SetFont

void wxPMDCImpl::SetPen(
  const wxPen&                      rPen
)
{
    if (m_pen == rPen)
        return;
    m_pen = rPen;
    if (!m_pen.Ok())
        return;

    if (m_hOldPen)
        m_hOldPen = 0L;
    m_pen = rPen;

    if (!m_pen.Ok())
    {
        if (m_hOldPen)
        {
            m_pen.SetPS((HPS)m_hOldPen);
        }
        m_hOldPen = 0L;
    }

    if (m_pen.Ok())
    {
        if (m_pen.GetResourceHandle())
        {
            m_pen.SetPS(m_hPS);
            if (!m_hOldPen)
                m_hOldPen = m_pen.GetPS();
        }
        ::GpiSetColor(m_hPS, m_pen.GetColour().GetPixel());
    }
}

void wxPMDCImpl::SetBrush(
  const wxBrush&                    rBrush
)
{
    if (m_hOldBrush)
        m_hOldBrush = 0L;
    m_brush = rBrush;
    if (!m_brush.Ok())
    if (m_brush == rBrush)
        return;
    if (!m_brush.Ok())
        if (m_hOldBrush)
            m_hOldBrush = 0L;

    if (!m_brush.Ok())
    {
        if (m_hOldBrush)
        {
            m_brush.SetPS((HPS)m_hOldBrush);
        }
        m_hOldBrush = 0L;
    }

    if (m_brush.Ok())
    {
        if (m_brush.GetResourceHandle())
        {
            m_brush.SetPS(m_hPS);
            if (!m_hOldBrush)
                m_hOldBrush = (WXHWND)m_brush.GetPS();
        }
    }
} // end of wxPMDCImpl::SetBrush

void wxPMDCImpl::SetBackground(const wxBrush& rBrush)
{
    m_backgroundBrush = rBrush;

    if (m_backgroundBrush.Ok())
    {
        (void)::GpiSetBackColor((HPS)m_hPS, m_backgroundBrush.GetColour().GetPixel());
    }
} // end of wxPMDCImpl::SetBackground

void wxPMDCImpl::SetBackgroundMode(int nMode)
{
    m_backgroundMode = nMode;
} // end of wxPMDCImpl::SetBackgroundMode

void wxPMDCImpl::SetLogicalFunction(wxRasterOperationMode nFunction)
{
    m_logicalFunction = nFunction;
    SetRop((WXHDC)m_hDC);
} // wxPMDCImpl::SetLogicalFunction

void wxPMDCImpl::SetRop(WXHDC hDC)
{
    if (!hDC || m_logicalFunction < 0)
        return;

    LONG lCRop;
    switch (m_logicalFunction)
    {
        case wxXOR:
            lCRop = FM_XOR;
            break;

        case wxINVERT:
            lCRop = FM_INVERT;
            break;

        case wxOR_REVERSE:
            lCRop = FM_MERGESRCNOT;
            break;

        case wxAND_REVERSE:
            lCRop = FM_NOTMASKSRC;
            break;

        case wxCLEAR:
            lCRop = FM_ONE;
            break;

        case wxSET:
            lCRop = FM_ZERO;
            break;

        case wxSRC_INVERT:
            lCRop = FM_MERGENOTSRC;
            break;

        case wxOR_INVERT:
            lCRop = FM_MERGESRCNOT;
            break;

        case wxAND:
            lCRop = FM_AND;
            break;

        case wxOR:
            lCRop = FM_OR;
            break;

        case wxAND_INVERT:
            lCRop = FM_SUBTRACT;
            break;

        case wxEQUIV:
        case wxNAND:
        case wxCOPY:
        default:
            lCRop = FM_OVERPAINT;
            break;
    }
    ::GpiSetMix((HPS)hDC, lCRop);
} // end of wxPMDCImpl::SetRop

bool wxPMDCImpl::StartDoc( const wxString& WXUNUSED(rsMessage) )
{
    // We might be previewing, so return true to let it continue.
    return true;
} // end of wxPMDCImpl::StartDoc

void wxPMDCImpl::EndDoc()
{
} // end of wxPMDCImpl::EndDoc

void wxPMDCImpl::StartPage()
{
} // end of wxPMDCImpl::StartPage

void wxPMDCImpl::EndPage()
{
} // end of wxPMDCImpl::EndPage

// ---------------------------------------------------------------------------
// text metrics
// ---------------------------------------------------------------------------

wxCoord wxPMDCImpl::GetCharHeight() const
{
    FONTMETRICS                     vFM; // metrics structure

    ::GpiQueryFontMetrics( m_hPS
                          ,sizeof(FONTMETRICS)
                          ,&vFM
                         );
    return YDEV2LOGREL(vFM.lXHeight);
}

wxCoord wxPMDCImpl::GetCharWidth() const
{
    FONTMETRICS                     vFM; // metrics structure

    ::GpiQueryFontMetrics( m_hPS
                          ,sizeof(FONTMETRICS)
                          ,&vFM
                         );
    return XDEV2LOGREL(vFM.lAveCharWidth);
}

void wxPMDCImpl::DoGetTextExtent(
  const wxString&                   rsString
, wxCoord*                          pvX
, wxCoord*                          pvY
, wxCoord*                          pvDescent
, wxCoord*                          pvExternalLeading
, const wxFont*                     pTheFont
) const
{
    POINTL                          avPoint[TXTBOX_COUNT];
    POINTL                          vPtMin;
    POINTL                          vPtMax;
    int                             i;
    int                             l;
    FONTMETRICS                     vFM; // metrics structure
    BOOL                            bRc;
    ERRORID                         vErrorCode; // last error id code
    wxFont*                         pFontToUse = (wxFont*)pTheFont;

    wxChar                          zMsg[128]; // DEBUG
    wxString                        sError;

    if (!pFontToUse)
        pFontToUse = (wxFont*)&m_font;
    l = rsString.length();

    //
    // In world coordinates.
    //
    if (!m_hPS)
    {
    (void)wxMessageBox( wxT("wxWidgets core library")
                ,"Using uninitialized DC for measuring text!\n"
                ,wxICON_INFORMATION
                );
    }

    bRc = ::GpiQueryTextBox( m_hPS
                            ,l
                            ,rsString.char_str()
                            ,TXTBOX_COUNT // return maximum information
                            ,avPoint      // array of coordinates points
                           );
    if(!bRc)
    {
       vErrorCode = ::WinGetLastError(wxGetInstance());
       sError = wxPMErrorToStr(vErrorCode);
       // DEBUG
       wxSprintf(zMsg, wxT("GpiQueryTextBox for %s: failed with Error: %lx - %s"), rsString.c_str(), vErrorCode, sError.c_str());
       (void)wxMessageBox( wxT("wxWidgets core library")
                          ,zMsg
                          ,wxICON_INFORMATION
                         );
    }

    vPtMin.x = avPoint[0].x;
    vPtMax.x = avPoint[0].x;
    vPtMin.y = avPoint[0].y;
    vPtMax.y = avPoint[0].y;
    for (i = 1; i < 4; i++)
    {
        if(vPtMin.x > avPoint[i].x) vPtMin.x = avPoint[i].x;
        if(vPtMin.y > avPoint[i].y) vPtMin.y = avPoint[i].y;
        if(vPtMax.x < avPoint[i].x) vPtMax.x = avPoint[i].x;
        if(vPtMax.y < avPoint[i].y) vPtMax.y = avPoint[i].y;
    }
    ::GpiQueryFontMetrics( m_hPS
                          ,sizeof(FONTMETRICS)
                          ,&vFM
                         );

    if (pvX)
        *pvX = (wxCoord)(vPtMax.x - vPtMin.x + 1);
    if (pvY)
        *pvY = (wxCoord)(vPtMax.y - vPtMin.y + 1);
    if (pvDescent)
        *pvDescent = vFM.lMaxDescender;
    if (pvExternalLeading)
        *pvExternalLeading = vFM.lExternalLeading;
}

void wxPMDCImpl::SetMapMode(
  wxMappingMode                     nMode
)
{
    int                             nPixelWidth = 0;
    int                             nPixelHeight = 0;
    int                             nMmWidth = 1;
    int                             nMmHeight = 1;
    LONG                            lArray[CAPS_VERTICAL_RESOLUTION+1];

    m_mappingMode = nMode;

    if(::DevQueryCaps( m_hDC
                      ,CAPS_FAMILY                  // id of first item
                      ,CAPS_VERTICAL_RESOLUTION+1   // number of items wanted
                      ,lArray
                     ))
    {
        LONG                        lHorzRes;
        LONG                        lVertRes;

        nPixelWidth    = lArray[CAPS_WIDTH];
        nPixelHeight   = lArray[CAPS_HEIGHT];
        lHorzRes  = lArray[CAPS_HORIZONTAL_RESOLUTION]; // returns pel/meter
        lVertRes  = lArray[CAPS_VERTICAL_RESOLUTION];   // returns pel/meter
        nMmWidth  = (lHorzRes/1000) * nPixelWidth;
        nMmHeight = (lVertRes/1000) * nPixelHeight;
    }
    if ((nPixelWidth == 0) || (nPixelHeight == 0) || (nMmWidth == 0) || (nMmHeight == 0))
    {
        return;
    }

    double dMm2pixelsX = nPixelWidth/(double)nMmWidth;
    double dMm2pixelsY = nPixelHeight/(double)nMmHeight;

    switch (nMode)
    {
        case wxMM_TWIPS:
            m_logicalScaleX = (twips2mm * dMm2pixelsX);
            m_logicalScaleY = (twips2mm * dMm2pixelsY);
            break;

        case wxMM_POINTS:
            m_logicalScaleX = (pt2mm * dMm2pixelsX);
            m_logicalScaleY = (pt2mm * dMm2pixelsY);
            break;

        case wxMM_METRIC:
            m_logicalScaleX = dMm2pixelsX;
            m_logicalScaleY = dMm2pixelsY;
            break;

        case wxMM_LOMETRIC:
            m_logicalScaleX = (dMm2pixelsX/10.0);
            m_logicalScaleY = (dMm2pixelsY/10.0);
            break;

        case wxMM_TEXT:
        default:
            m_logicalScaleX = 1.0;
            m_logicalScaleY = 1.0;
            break;
    }

    SIZEL                           vSize;
    ULONG                           ulOptions;

    ulOptions = ::GpiQueryPS(m_hPS, &vSize);
    if (!ulOptions & PU_ARBITRARY)
    {
        ulOptions = PU_ARBITRARY | GPIF_DEFAULT;
        ::GpiSetPS(m_hPS, &vSize, ulOptions);
    }
    ComputeScaleAndOrigin();

}; // end of wxPMDCImpl::SetMapMode

void wxPMDCImpl::SetUserScale( double dX,
                         double dY )
{
    m_userScaleX = dX;
    m_userScaleY = dY;

    SetMapMode(m_mappingMode);
} // end of wxPMDCImpl::SetUserScale

void wxPMDCImpl::SetAxisOrientation( bool bXLeftRight,
                               bool bYBottomUp )
{
    m_signX = bXLeftRight ? 1 : -1;
    m_signY = bYBottomUp ? -1 : 1;

    SetMapMode(m_mappingMode);
} // end of wxPMDCImpl::SetAxisOrientation

void wxPMDCImpl::SetLogicalOrigin(
  wxCoord                           vX
, wxCoord                           vY
)
{
    RECTL                           vRect;

    ::GpiQueryPageViewport( m_hPS
                           ,&vRect
                          );
    vRect.xRight -= vX;
    vRect.yTop += vY;
    vRect.xLeft = vX;
    vRect.yBottom = vY;
    ::GpiSetPageViewport( m_hPS
                         ,&vRect
                        );
}; // end of wxPMDCImpl::SetLogicalOrigin

void wxPMDCImpl::SetDeviceOrigin(
  wxCoord                           vX
, wxCoord                           vY
)
{
    RECTL                           vRect;

    m_deviceOriginX = vX;
    m_deviceOriginY = vY;
    ::GpiQueryPageViewport( m_hPS
                           ,&vRect
                          );
    vRect.xLeft += vX;
    vRect.xRight += vX;
    vRect.yBottom -= vY;
    vRect.yTop -= vY;
    ::GpiSetPageViewport( m_hPS
                         ,&vRect
                        );
}; // end of wxPMDCImpl::SetDeviceOrigin

// ---------------------------------------------------------------------------
// bit blit
// ---------------------------------------------------------------------------

bool wxPMDCImpl::DoBlit( wxCoord vXdest,
                   wxCoord vYdest,
                   wxCoord vWidth,
                   wxCoord vHeight,
                   wxDC*   pSource,
                   wxCoord vXsrc,
                   wxCoord vYsrc,
                   wxRasterOperationMode     nRop,
                   bool    bUseMask,
                   wxCoord WXUNUSED(vXsrcMask),
                   wxCoord WXUNUSED(vYsrcMask) )
{
    wxMask*                         pMask = NULL;
    CHARBUNDLE                      vCbnd;
    COLORREF                        vOldTextColor;
    COLORREF                        vOldBackground = ::GpiQueryBackColor(m_hPS);

    wxDCImpl *impl = pSource->GetImpl();
    wxPMDCImpl *pm_impl = wxDynamicCast( impl, wxPMDCImpl );
    if (!pm_impl)
    {
        // TODO: Do we want to be able to blit
        //       from other DCs too?
        return false;
    }

    if (bUseMask)
    {
        const wxBitmap&             rBmp = pm_impl->GetSelectedBitmap();

        pMask = rBmp.GetMask();
        if (!(rBmp.Ok() && pMask && pMask->GetMaskBitmap()))
        {
            bUseMask = false;
        }
    }

    ::GpiQueryAttrs( m_hPS
                    ,PRIM_CHAR
                    ,CBB_COLOR
                    ,&vCbnd
                   );
    vOldTextColor = (COLORREF)vCbnd.lColor;

    if (m_textForegroundColour.Ok())
    {
        vCbnd.lColor = (LONG)m_textForegroundColour.GetPixel();
        ::GpiSetAttrs( m_hPS           // presentation-space handle
                      ,PRIM_CHAR       // Char primitive.
                      ,CBB_COLOR       // sets color.
                      ,0
                      ,&vCbnd          // buffer for attributes.
                     );
    }
    if (m_textBackgroundColour.Ok())
    {
        ::GpiSetBackColor(m_hPS, (LONG)m_textBackgroundColour.GetPixel());
    }

    LONG                            lRop = ROP_SRCCOPY;

    switch (nRop)
    {
        case wxXOR:          lRop = ROP_SRCINVERT;        break;
        case wxINVERT:       lRop = ROP_DSTINVERT;        break;
        case wxOR_REVERSE:   lRop = 0x00DD0228;           break;
        case wxAND_REVERSE:  lRop = ROP_SRCERASE;         break;
        case wxCLEAR:        lRop = ROP_ZERO;             break;
        case wxSET:          lRop = ROP_ONE;              break;
        case wxOR_INVERT:    lRop = ROP_MERGEPAINT;       break;
        case wxAND:          lRop = ROP_SRCAND;           break;
        case wxOR:           lRop = ROP_SRCPAINT;         break;
        case wxEQUIV:        lRop = 0x00990066;           break;
        case wxNAND:         lRop = 0x007700E6;           break;
        case wxAND_INVERT:   lRop = 0x00220326;           break;
        case wxCOPY:         lRop = ROP_SRCCOPY;          break;
        case wxNO_OP:        lRop = ROP_NOTSRCERASE;      break;
        case wxSRC_INVERT:   lRop = ROP_SRCINVERT;        break;
        case wxNOR:          lRop = ROP_NOTSRCCOPY;       break;
        default:
           wxFAIL_MSG( wxT("unsupported logical function") );
           return false;
    }

    bool                            bSuccess;

    if (bUseMask)
    {
        //
        // Blit bitmap with mask
        //

        //
        // Create a temp buffer bitmap and DCs/PSs to access it and the mask
        //
        HDC                             hDCMask;
        HDC                             hDCBuffer;
        HPS                             hPSMask;
        HPS                             hPSBuffer;
        DEVOPENSTRUC                    vDOP = {0L, "DISPLAY", NULL, 0L, 0L, 0L, 0L, 0L, 0L};
        BITMAPINFOHEADER2               vBmpHdr;
        HBITMAP                         hBufBitmap;
        SIZEL                           vSize = {0, 0};
        LONG                            rc;

        memset(&vBmpHdr, 0, sizeof(BITMAPINFOHEADER2));
        vBmpHdr.cbFix     = sizeof(BITMAPINFOHEADER2);
        vBmpHdr.cx        = vWidth;
        vBmpHdr.cy        = vHeight;
        vBmpHdr.cPlanes   = 1;
        vBmpHdr.cBitCount = 24;

#if wxUSE_DC_CACHEING
        {
            //
            // create a temp buffer bitmap and DCs to access it and the mask
            //
            wxDCCacheEntry*         pDCCacheEntry1    = FindDCInCache( NULL
                                                                      ,pm_impl->GetHPS()
                                                                     );
            wxDCCacheEntry*         pDCCacheEntry2    = FindDCInCache( pDCCacheEntry1
                                                                      ,GetHPS()
                                                                     );
            wxDCCacheEntry*         pBitmapCacheEntry = FindBitmapInCache( GetHPS()
                                                                          ,vWidth
                                                                          ,vHeight
                                                                         );

            hPSMask = pDCCacheEntry1->m_hPS;
            hDCBuffer = (HDC)pDCCacheEntry2->m_hPS;
            hBufBitmap = (HBITMAP)pBitmapCacheEntry->m_hBitmap;
            wxUnusedVar(hDCMask);
        }
#else
        {
            hDCMask = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDOP, NULLHANDLE);
            hDCBuffer = ::DevOpenDC(vHabmain, OD_MEMORY, "*", 5L, (PDEVOPENDATA)&vDOP, NULLHANDLE);
            hPSMask = ::GpiCreatePS(vHabmain, hDCMask, &vSize, PU_PELS | GPIT_MICRO | GPIA_ASSOC);
            hPSBuffer = ::GpiCreatePS(vHabmain, hDCBuffer, &vSize, PU_PELS | GPIT_MICRO | GPIA_ASSOC);
            hBufBitmap = ::GpiCreateBitmap(GetHPS(), &vBmpHdr, 0L, NULL, NULL);
        }
#endif

        POINTL                          aPoint1[4] = { {0, 0}
                              ,{vWidth, vHeight}
                              ,{vXdest, vYdest}
                              ,{vXdest + vWidth, vYdest + vHeight}
                                                     };
        POINTL                          aPoint2[4] = { {0, 0}
                              ,{vWidth, vHeight}
                              ,{vXsrc, vYsrc}
                              ,{vXsrc + vWidth, vYsrc + vHeight}
                                                     };
        POINTL                          aPoint3[4] = { {vXdest, vYdest}
                              ,{vXdest + vWidth, vYdest + vHeight}
                              ,{vXsrc, vYsrc}
                              ,{vXsrc + vWidth, vYsrc + vHeight}
                                                     };
        POINTL                          aPoint4[4] = { {vXdest, vYdest}
                              ,{vXdest + vWidth, vYdest + vHeight}
                              ,{0, 0}
                              ,{vWidth, vHeight}
                                                     };
        ::GpiSetBitmap(hPSMask, (HBITMAP) pMask->GetMaskBitmap());
        ::GpiSetBitmap(hPSBuffer, (HBITMAP) hBufBitmap);

        //
        // Copy dest to buffer
        //
        rc = ::GpiBitBlt( hPSBuffer
                         ,GetHPS()
                         ,4L
                         ,aPoint1
                         ,ROP_SRCCOPY
                         ,BBO_IGNORE
                        );
        if (rc == GPI_ERROR)
        {
            wxLogLastError(wxT("BitBlt"));
        }

        //
        // Copy src to buffer using selected raster op
        //
        rc = ::GpiBitBlt( hPSBuffer
                         ,GetHPS()
                         ,4L
                         ,aPoint2
                         ,lRop
                         ,BBO_IGNORE
                        );
        if (rc == GPI_ERROR)
        {
            wxLogLastError(wxT("BitBlt"));
        }

        //
        // Set masked area in buffer to BLACK (pixel value 0)
        //
        COLORREF                        vPrevBkCol = ::GpiQueryBackColor(GetHPS());
        COLORREF                        vPrevCol = ::GpiQueryColor(GetHPS());

        ::GpiSetBackColor(GetHPS(), OS2RGB(255, 255, 255));
        ::GpiSetColor(GetHPS(), OS2RGB(0, 0, 0));

        rc = ::GpiBitBlt( hPSBuffer
                         ,hPSMask
                         ,4L
                         ,aPoint2
                         ,ROP_SRCAND
                         ,BBO_IGNORE
                        );
        if (rc == GPI_ERROR)
        {
            wxLogLastError(wxT("BitBlt"));
        }

        //
        // Set unmasked area in dest to BLACK
        //
        ::GpiSetBackColor(GetHPS(), OS2RGB(0, 0, 0));
        ::GpiSetColor(GetHPS(), OS2RGB(255, 255, 255));
        rc = ::GpiBitBlt( GetHPS()
                         ,hPSMask
                         ,4L
                         ,aPoint3
                         ,ROP_SRCAND
                         ,BBO_IGNORE
                        );
        if (rc == GPI_ERROR)
        {
            wxLogLastError(wxT("BitBlt"));
        }

        //
        // Restore colours to original values
        //
        ::GpiSetBackColor(GetHPS(), vPrevBkCol);
        ::GpiSetColor(GetHPS(), vPrevCol);

        //
        // OR buffer to dest
        //
        rc = ::GpiBitBlt( GetHPS()
                         ,hPSMask
                         ,4L
                         ,aPoint4
                         ,ROP_SRCPAINT
                         ,BBO_IGNORE
                        );
        if (rc == GPI_ERROR)
        {
            bSuccess = false;
            wxLogLastError(wxT("BitBlt"));
        }

        //
        // Tidy up temporary DCs and bitmap
        //
        ::GpiSetBitmap(hPSMask, NULLHANDLE);
        ::GpiSetBitmap(hPSBuffer, NULLHANDLE);
#if !wxUSE_DC_CACHEING
        ::GpiDestroyPS(hPSMask);
        ::GpiDestroyPS(hPSBuffer);
        ::DevCloseDC(hDCMask);
        ::DevCloseDC(hDCBuffer);
        ::GpiDeleteBitmap(hBufBitmap);
#endif
        bSuccess = true;
    }
    else // no mask, just BitBlt() it
    {
      POINTL                          aPoint[4] = { {vXdest, vYdest}
                           ,{vXdest + vWidth, vYdest + vHeight}
                           ,{vXsrc, vYsrc}
                           ,{vXsrc + vWidth, vYsrc + vHeight}
                                                    };

        bSuccess = (::GpiBitBlt( m_hPS
                                ,pm_impl->GetHPS()
                                ,4L
                                ,aPoint
                                ,lRop
                                ,BBO_IGNORE
                               ) != GPI_ERROR);
        if (!bSuccess )
        {
            wxLogLastError(wxT("BitBlt"));
        }
    }
    vCbnd.lColor = (LONG)vOldTextColor;
    ::GpiSetAttrs( m_hPS           // presentation-space handle
                  ,PRIM_CHAR       // Char primitive.
                  ,CBB_COLOR       // sets color.
                  ,0
                  ,&vCbnd          // buffer for attributes.
                 );
    ::GpiSetBackColor(m_hPS, (LONG)vOldBackground);
    return bSuccess;
}

void wxPMDCImpl::DoGetSize( int* pnWidth,
                            int* pnHeight ) const
{
    LONG lArray[CAPS_HEIGHT+1];

    if(::DevQueryCaps( m_hDC
                      ,CAPS_FAMILY
                      ,CAPS_HEIGHT+1
                      ,lArray
                     ))
    {
        if (pnWidth)
            *pnWidth  = lArray[CAPS_WIDTH];
        if (pnHeight)
            *pnHeight = lArray[CAPS_HEIGHT];
    }
}; // end of wxPMDCImpl::DoGetSize(

void wxPMDCImpl::DoGetSizeMM( int* pnWidth,
                        int* pnHeight ) const
{
    LONG                            lArray[CAPS_VERTICAL_RESOLUTION+1];

    if(::DevQueryCaps( m_hDC
                      ,CAPS_FAMILY
                      ,CAPS_VERTICAL_RESOLUTION+1
                      ,lArray
                     ))
    {
        if(pnWidth)
        {
            int nWidth   = lArray[CAPS_WIDTH];
            int nHorzRes = lArray[CAPS_HORIZONTAL_RESOLUTION]; // returns pel/meter
            // use fp to avoid returning 0 if nHorzRes < 1000
            *pnWidth  = (int)((nHorzRes/1000.0) * nWidth);
        }

        if(pnHeight)
        {
            int nHeight  = lArray[CAPS_HEIGHT];
            int nVertRes = lArray[CAPS_VERTICAL_RESOLUTION];   // returns pel/meter
            // use fp to avoid returning 0 if nVertRes < 1000
            *pnHeight = (int)((nVertRes/1000.0) * nHeight);
        }
    }
}; // end of wxPMDCImpl::DoGetSizeMM

wxSize wxPMDCImpl::GetPPI() const
{
    LONG                            lArray[CAPS_VERTICAL_RESOLUTION+1];
    int                             nWidth = 0;
    int                             nHeight = 0;

    if(::DevQueryCaps( m_hDC
                      ,CAPS_FAMILY
                      ,CAPS_VERTICAL_RESOLUTION+1
                      ,lArray
                     ))
    {
        int                         nPelWidth;
        int                         nPelHeight;
        int                         nHorzRes;
        int                         nVertRes;

        nPelWidth  = lArray[CAPS_WIDTH];
        nPelHeight = lArray[CAPS_HEIGHT];
        nHorzRes   = lArray[CAPS_HORIZONTAL_RESOLUTION]; // returns pel/meter
        nVertRes   = lArray[CAPS_VERTICAL_RESOLUTION];   // returns pel/meter
        nWidth   = (int)((nHorzRes/39.3) * nPelWidth);
        nHeight  = (int)((nVertRes/39.3) * nPelHeight);
    }
    wxSize ppisize(nWidth, nHeight);
    return ppisize;
} // end of wxPMDCImpl::GetPPI

void wxPMDCImpl::SetLogicalScale( double dX, double dY )
{
    m_logicalScaleX = dX;
    m_logicalScaleY = dY;
}; // end of wxPMDCImpl::SetLogicalScale
