/////////////////////////////////////////////////////////////////////////////
// Name:        src/mgl/dc.cpp
// Purpose:     wxDC class
// Author:      Vaclav Slavik
// Created:     2001/03/09
// RCS-ID:      $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ===========================================================================
// declarations
// ===========================================================================

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/dc.h"
    #include "wx/dcmemory.h"
    #include "wx/log.h"
#endif

#include "wx/fontutil.h"
#include "wx/encinfo.h"
#include "wx/fontmap.h"
#include "wx/mgl/private.h"

#include <string.h>
#include <mgraph.hpp>



//-----------------------------------------------------------------------------
// constants
//-----------------------------------------------------------------------------

const double RAD2DEG        = 180.0 / M_PI;


//-----------------------------------------------------------------------------
// pens data:
//-----------------------------------------------------------------------------

const ushort STIPPLE_wxDOT        = 0x5555/* - - - - - - - -*/;
const ushort STIPPLE_wxLONG_DASH  = 0xF0F0/*    ----    ----*/;
const ushort STIPPLE_wxSHORT_DASH = 0xCCCC/*--  --  --  --  */;
const ushort STIPPLE_wxDOT_DASH   = 0x3939/*  ---  -  ---  -*/;
const ushort STIPPLE_wxSOLID      = 0xFFFF/*----------------*/;

#define PATTERN_ROW(b7,b6,b5,b4,b3,b2,b1,b0) \
            ((b7 << 7) | (b6 << 6) | (b5 << 5) | (b4 << 4) | \
             (b3 << 3) | (b2 << 2) | (b1 << 1) | b0)

static pattern_t PATTERN_wxFDIAGONAL_HATCH = {{
       PATTERN_ROW(1,0,0,0,0,0,0,0),
       PATTERN_ROW(0,1,0,0,0,0,0,0),
       PATTERN_ROW(0,0,1,0,0,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,0,0,1,0,0,0),
       PATTERN_ROW(0,0,0,0,0,1,0,0),
       PATTERN_ROW(0,0,0,0,0,0,1,0),
       PATTERN_ROW(0,0,0,0,0,0,0,1),
       }};

static pattern_t PATTERN_wxCROSSDIAG_HATCH = {{
       PATTERN_ROW(1,0,0,0,0,0,0,1),
       PATTERN_ROW(0,1,0,0,0,0,1,0),
       PATTERN_ROW(0,0,1,0,0,1,0,0),
       PATTERN_ROW(0,0,0,1,1,0,0,0),
       PATTERN_ROW(0,0,0,1,1,0,0,0),
       PATTERN_ROW(0,0,1,0,0,1,0,0),
       PATTERN_ROW(0,1,0,0,0,0,1,0),
       PATTERN_ROW(1,0,0,0,0,0,0,1),
       }};

static pattern_t PATTERN_wxBDIAGONAL_HATCH = {{
       PATTERN_ROW(0,0,0,0,0,0,0,1),
       PATTERN_ROW(0,0,0,0,0,0,1,0),
       PATTERN_ROW(0,0,0,0,0,1,0,0),
       PATTERN_ROW(0,0,0,0,1,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,1,0,0,0,0,0),
       PATTERN_ROW(0,1,0,0,0,0,0,0),
       PATTERN_ROW(1,0,0,0,0,0,0,0),
       }};

static pattern_t PATTERN_wxCROSS_HATCH = {{
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(1,1,1,1,1,1,1,1),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       }};

static pattern_t PATTERN_wxHORIZONTAL_HATCH = {{
       PATTERN_ROW(0,0,0,0,0,0,0,0),
       PATTERN_ROW(0,0,0,0,0,0,0,0),
       PATTERN_ROW(0,0,0,0,0,0,0,0),
       PATTERN_ROW(1,1,1,1,1,1,1,1),
       PATTERN_ROW(0,0,0,0,0,0,0,0),
       PATTERN_ROW(0,0,0,0,0,0,0,0),
       PATTERN_ROW(0,0,0,0,0,0,0,0),
       PATTERN_ROW(0,0,0,0,0,0,0,0),
       }};

static pattern_t PATTERN_wxVERTICAL_HATCH = {{
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       PATTERN_ROW(0,0,0,1,0,0,0,0),
       }};

#undef PATTERN_ROW

//-----------------------------------------------------------------------------
// wxDC
//-----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxDC, wxDCBase)

// Default constructor
wxDC::wxDC()
{
    m_isMemDC = false;
    m_MGLDC = NULL;
    m_OwnsMGLDC = false;
    m_ok = false; // must call SetMGLDevCtx() before using it

    m_mm_to_pix_x = (double)wxGetDisplaySize().GetWidth() /
                    (double)wxGetDisplaySizeMM().GetWidth();
    m_mm_to_pix_y = (double)wxGetDisplaySize().GetHeight() /
                    (double)wxGetDisplaySizeMM().GetHeight();

    m_pen = *wxBLACK_PEN;
    m_font = *wxNORMAL_FONT;
    m_brush = *wxWHITE_BRUSH;
    m_penOfsX = m_penOfsY = 0;

    m_penSelected = m_brushSelected = false;
    m_downloadedPatterns[0] = m_downloadedPatterns[1] = false;

    m_mglFont = NULL;
}


wxDC::~wxDC()
{
    if (m_OwnsMGLDC)
        delete m_MGLDC;
}

void wxDC::SetMGLDC(MGLDevCtx *mgldc, bool OwnsMGLDC)
{
    if ( m_OwnsMGLDC && m_MGLDC )
        delete m_MGLDC;
    m_MGLDC = mgldc;
    m_OwnsMGLDC = OwnsMGLDC;
    m_ok = true;

    if ( !m_globalClippingRegion.IsNull() )
        SetClippingRegion(m_globalClippingRegion);

    InitializeMGLDC();
}

void wxDC::InitializeMGLDC()
{
    if ( GetDepth() > 8 )
    {
        wxCurrentDCSwitcher switcher(m_MGLDC); // will go away with MGL6
        m_MGLDC->setFontBlendMode(MGL_AA_RGBBLEND);
    }
}


// ---------------------------------------------------------------------------
// clipping
// ---------------------------------------------------------------------------


#define DO_SET_CLIPPING_BOX(rg)                      \
{                                                    \
    wxRect rect = rg.GetBox();                       \
    m_clipX1 = (wxCoord) XDEV2LOG(rect.GetLeft());   \
    m_clipY1 = (wxCoord) YDEV2LOG(rect.GetTop());    \
    m_clipX2 = (wxCoord) XDEV2LOG(rect.GetRight());  \
    m_clipY2 = (wxCoord) YDEV2LOG(rect.GetBottom()); \
}

void wxDC::DoSetClippingRegion(wxCoord cx, wxCoord cy, wxCoord cw, wxCoord ch)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    wxRect rect(XLOG2DEV(cx), YLOG2DEV(cy), XLOG2DEVREL(cw), YLOG2DEVREL(ch));

    if ( !m_currentClippingRegion.IsNull() )
        m_currentClippingRegion.Intersect(rect);
    else
        m_currentClippingRegion.Union(rect);

    m_MGLDC->setClipRegion(m_currentClippingRegion.GetMGLRegion());

    m_clipping = true;
    DO_SET_CLIPPING_BOX(m_currentClippingRegion)
}

void wxDC::DoSetDeviceClippingRegion(const wxRegion& region)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    if ( region.IsEmpty() )
    {
        DestroyClippingRegion();
        return;
    }

    wxRegion rg(region);

    // check if the DC is scaled or moved, and if yes, then
    // convert rg to device coordinates:
    if ( m_deviceOriginX != 0 || m_deviceOriginY != 0 ||
         m_logicalOriginX != 0 || m_logicalOriginY != 0 ||
         XLOG2DEVREL(500) != 500 || YLOG2DEVREL(500) != 500 )
    {
        region_t *mrg = rg.GetMGLRegion().rgnPointer();
        span_t *s;
        segment_t *p;
        for (s = mrg->spans; s; s = s->next)
        {
            s->y = YLOG2DEV(s->y);
            for (p = s->seg; p; p = p->next)
                p->x = XLOG2DEV(p->x);
        }
    }

    if ( !m_currentClippingRegion.IsNull() )
        m_currentClippingRegion.Intersect(rg);
    else
        m_currentClippingRegion.Union(rg);

    m_MGLDC->setClipRegion(m_currentClippingRegion.GetMGLRegion());

    m_clipping = true;
    DO_SET_CLIPPING_BOX(m_currentClippingRegion)
}

void wxDC::DestroyClippingRegion()
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    if ( !m_globalClippingRegion.IsNull() )
    {
        m_MGLDC->setClipRegion(m_globalClippingRegion.GetMGLRegion());
        m_currentClippingRegion = m_globalClippingRegion;
        m_clipping = true;
    }
    else
    {
        m_MGLDC->setClipRect(MGLRect(0, 0, m_MGLDC->sizex()+1, m_MGLDC->sizey()+1));
        ResetClipping();
        m_currentClippingRegion.Clear();
    }
}

// ---------------------------------------------------------------------------
// query capabilities
// ---------------------------------------------------------------------------

bool wxDC::CanDrawBitmap() const
{
    return true;
}

bool wxDC::CanGetTextExtent() const
{
    return true;
}

int wxDC::GetDepth() const
{
    return m_MGLDC->getBitsPerPixel();
}

// ---------------------------------------------------------------------------
// drawing
// ---------------------------------------------------------------------------

void wxDC::Clear()
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    m_MGLDC->makeCurrent(); // will go away with MGL6.0
    if ( m_backgroundBrush.GetStyle() != wxTRANSPARENT )
    {
        int w, h;
        wxBrush oldb = m_brush;
        SetBrush(m_backgroundBrush);
        SelectBrush();
        GetSize(&w, &h);
        m_MGLDC->fillRect(0, 0, w, h);
        SetBrush(oldb);
    }
}

extern bool wxDoFloodFill(wxDC *dc, wxCoord x, wxCoord y,
                          const wxColour & col, wxFloodFillStyle style);

bool wxDC::DoFloodFill(wxCoord x, wxCoord y,
                       const wxColour& col, wxFloodFillStyle style)
{
    return wxDoFloodFill(this, x, y, col, style);
}

bool wxDC::DoGetPixel(wxCoord x, wxCoord y, wxColour *col) const
{
    wxCHECK_MSG( col, false, wxT("NULL colour parameter in wxDC::GetPixel"));

    uchar r, g, b;
    m_MGLDC->unpackColorFast(m_MGLDC->getPixel(XLOG2DEV(x), YLOG2DEV(y)),
                             r, g, b);
    col->Set(r, g, b);
    return true;
}

void wxDC::DoCrossHair(wxCoord x, wxCoord y)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    if ( m_pen.GetStyle() != wxTRANSPARENT )
    {
        int w = 0;
        int h = 0;
        GetSize(&w, &h);
        m_MGLDC->makeCurrent(); // will go away with MGL6.0
        if ( !m_penSelected )
            SelectPen();
        wxCoord xx = XLOG2DEV(x);
        wxCoord yy = YLOG2DEV(y);
        m_MGLDC->line(m_penOfsX, yy + m_penOfsY, w-1 + m_penOfsX, yy + m_penOfsY);
        m_MGLDC->line(xx + m_penOfsX, m_penOfsY, x + m_penOfsX, h-1 + m_penOfsY);
        CalcBoundingBox(0, 0);
        CalcBoundingBox(w, h);
    }
}

void wxDC::DoDrawLine(wxCoord x1, wxCoord y1, wxCoord x2, wxCoord y2)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    if ( m_pen.GetStyle() != wxTRANSPARENT )
    {
        m_MGLDC->makeCurrent(); // will go away with MGL6.0
        if ( !m_penSelected )
            SelectPen();
        m_MGLDC->lineExt(XLOG2DEV(x1) + m_penOfsX, YLOG2DEV(y1) + m_penOfsY,
                      XLOG2DEV(x2) + m_penOfsX, YLOG2DEV(y2) + m_penOfsY,FALSE);
        CalcBoundingBox(x1, y1);
        CalcBoundingBox(x2, y2);
    }
}

// Draws an arc of a circle, centred on (xc, yc), with starting point (x1, y1)
// and ending at (x2, y2)
void wxDC::DoDrawArc(wxCoord x1, wxCoord y1,
                     wxCoord x2, wxCoord y2,
                     wxCoord xc, wxCoord yc)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    wxCoord xx1 = XLOG2DEV(x1);
    wxCoord yy1 = YLOG2DEV(y1);
    wxCoord xx2 = XLOG2DEV(x2);
    wxCoord yy2 = YLOG2DEV(y2);
    wxCoord xxc = XLOG2DEV(xc);
    wxCoord yyc = YLOG2DEV(yc);
    double dx = xx1 - xxc;
    double dy = yy1 - yyc;
    double radius = sqrt((double)(dx*dx+dy*dy));
    wxCoord r = (wxCoord)radius;
    double radius1, radius2;


    if (xx1 == xx2 && yy1 == yy2)
    {
        radius1 = 0.0;
        radius2 = 360.0;
    }
    else if (radius == 0.0)
    {
        radius1 = radius2 = 0.0;
    }
    else
    {
        radius1 = (xx1 - xxc == 0) ?
            (yy1 - yyc < 0) ? 90.0 : -90.0 :
            -atan2(double(yy1-yyc), double(xx1-xxc)) * RAD2DEG;
        radius2 = (xx2 - xxc == 0) ?
            (yy2 - yyc < 0) ? 90.0 : -90.0 :
            -atan2(double(yy2-yyc), double(xx2-xxc)) * RAD2DEG;
    }
    wxCoord alpha1 = wxCoord(radius1);
    wxCoord alpha2 = alpha1 + wxCoord(radius2 - radius1);
    while (alpha2 <= 0) alpha2 += 360;
    while (alpha1 > 360) alpha1 -= 360;

    m_MGLDC->makeCurrent(); // will go away with MGL6.0
    if ( m_brush.GetStyle() != wxTRANSPARENT )
    {
        if ( !m_brushSelected )
            SelectBrush();
        m_MGLDC->fillEllipseArc(xxc, yyc, r, r, alpha1, alpha2);
    }

    if ( m_pen.GetStyle() != wxTRANSPARENT )
    {
        if ( !m_penSelected )
         SelectPen();
        m_MGLDC->ellipseArc(xxc + m_penOfsX, yyc + m_penOfsY, r, r, alpha1, alpha2);
    }

    CalcBoundingBox(xc - r, yc - r);
    CalcBoundingBox(xc + r, yc + r);
}

void wxDC::DoDrawPoint(wxCoord x, wxCoord y)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    if ( m_pen.GetStyle() != wxTRANSPARENT )
    {
        m_MGLDC->makeCurrent(); // will go away with MGL6.0
        if ( !m_penSelected )
            SelectPen();
        m_MGLDC->pixel(XLOG2DEV(x), YLOG2DEV(y));
        CalcBoundingBox(x, y);
    }
}

void wxDC::DoDrawPolygon(int n, wxPoint points[], wxCoord xoffset, wxCoord yoffset,wxPolygonFillMode WXUNUSED(fillStyle))
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    wxCoord xxoffset = XLOG2DEVREL(xoffset),
            yyoffset = YLOG2DEVREL(yoffset);
    MGLPoint *cpoints = new MGLPoint[n+1];
    for (int i = 0; i < n; i++)
    {
        CalcBoundingBox(points[i].x + xoffset, points[i].y + yoffset);
        cpoints[i].x = (int)(XLOG2DEV(points[i].x));
        cpoints[i].y = (int)(YLOG2DEV(points[i].y));
    }
    cpoints[n] = cpoints[0];

    m_MGLDC->makeCurrent(); // will go away with MGL6.0
    if ( m_brush.GetStyle() != wxTRANSPARENT )
    {
        if ( !m_brushSelected )
            SelectBrush();
        m_MGLDC->fillPolygon(n, cpoints, xxoffset, yyoffset);
    }

    if ( m_pen.GetStyle() != wxTRANSPARENT )
    {
        if ( !m_penSelected )
            SelectPen();
        if (m_penOfsX != 0 || m_penOfsY != 0)
        {
            for (int i = 0; i <= n; i++)
            {
                cpoints[i].x += m_penOfsX;
                cpoints[i].y += m_penOfsY;
            }
        }
        m_MGLDC->polyLine(n+1, cpoints);
    }

    delete[] cpoints;
}

void wxDC::DoDrawLines(int n, wxPoint points[], wxCoord xoffset, wxCoord yoffset)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    if ( m_pen.GetStyle() != wxTRANSPARENT )
    {
        MGLPoint *cpoints = new MGLPoint[n];
        m_MGLDC->makeCurrent(); // will go away with MGL6.0
        if ( !m_penSelected )
            SelectPen();
        for (int i = 0; i < n; i++)
        {
            CalcBoundingBox(points[i].x + xoffset, points[i].y + yoffset);
            cpoints[i].x = (int)(XLOG2DEV(points[i].x + xoffset) /*+ m_penOfsX*/);
            cpoints[i].y = (int)(YLOG2DEV(points[i].y + yoffset) /*+ m_penOfsY*/);
        }
        m_MGLDC->polyLine(n, cpoints);
        delete[] cpoints;
    }
}

void wxDC::DoDrawRectangle(wxCoord x, wxCoord y, wxCoord width, wxCoord height)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    wxCoord xx = XLOG2DEV(x);
    wxCoord yy = YLOG2DEV(y);
    wxCoord ww = m_signX * XLOG2DEVREL(width);
    wxCoord hh = m_signY * YLOG2DEVREL(height);

    if ( ww == 0 || hh == 0 ) return;

    if ( ww < 0 )
    {
        ww = -ww;
        xx = xx - ww;
    }
    if ( hh < 0 )
    {
        hh = -hh;
        yy = yy - hh;
    }

    m_MGLDC->makeCurrent(); // will go away with MGL6.0
    if ( m_brush.GetStyle() != wxTRANSPARENT )
    {
        if ( !m_brushSelected )
            SelectBrush();
        m_MGLDC->fillRect(xx, yy, xx + ww, yy + hh);
    }

    if ( m_pen.GetStyle() != wxTRANSPARENT )
    {
        if ( !m_penSelected )
            SelectPen();

        m_MGLDC->rect(xx + m_penOfsX, yy + m_penOfsY,
                      xx + ww + m_penOfsX, yy + hh + m_penOfsY);
    }

    CalcBoundingBox(x, y);
    CalcBoundingBox(x + width, y + height);
}

void wxDC::DoDrawRoundedRectangle(wxCoord x, wxCoord y, wxCoord width, wxCoord height, double radius)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    if ( radius < 0.0 )
        radius = -radius * ((width < height) ? width : height);

    wxCoord xx = XLOG2DEV(x);
    wxCoord yy = YLOG2DEV(y);
    wxCoord ww = m_signX * XLOG2DEVREL(width);
    wxCoord hh = m_signY * YLOG2DEVREL(height);
    wxCoord rr = XLOG2DEVREL((wxCoord)radius);

    // CMB: handle -ve width and/or height
    if ( ww < 0 )
    {
        ww = -ww;
        xx = xx - ww;
    }
    if ( hh < 0 )
    {
        hh = -hh;
        yy = yy - hh;
    }

    // CMB: if radius is zero use DrawRectangle() instead to avoid
    // X drawing errors with small radii
    if ( rr == 0 )
    {
        DrawRectangle(x, y, width, height);
        return;
    }

    // CMB: draw nothing if transformed w or h is 0
    if ( ww == 0 || hh == 0 ) return;

    // CMB: ensure dd is not larger than rectangle otherwise we
    // get an hour glass shape
    wxCoord dd = 2 * rr;
    if ( dd > ww ) dd = ww;
    if ( dd > hh ) dd = hh;
    rr = dd / 2;

    m_MGLDC->makeCurrent(); // will go away with MGL6.0
    if ( m_brush.GetStyle() != wxTRANSPARENT )
    {
        if (!m_brushSelected)
            SelectBrush();
        m_MGLDC->fillRect(xx+rr, yy, xx+ww-rr, yy+hh);
        m_MGLDC->fillRect(xx, yy+rr, xx+ww, yy+hh-rr);
        m_MGLDC->fillEllipseArc(xx+rr, yy+rr, rr, rr, 90, 180);
        m_MGLDC->fillEllipseArc(xx+ww-rr, yy+rr, rr, rr, 0, 90);
        m_MGLDC->fillEllipseArc(xx+rr, yy+hh-rr, rr, rr, 180, 270);
        m_MGLDC->fillEllipseArc(xx+ww-rr, yy+hh-rr, rr, rr, 270, 0);
    }

    if ( m_pen.GetStyle() != wxTRANSPARENT )
    {
        if ( !m_penSelected )
            SelectPen();
        xx += m_penOfsX;
        yy += m_penOfsY;
        m_MGLDC->line(xx+rr+1, yy, xx+ww-rr, yy);
        m_MGLDC->ellipseArc(xx+ww-rr, yy+rr, rr, rr, 0, 90);
        m_MGLDC->line(xx+ww, yy+rr+1, xx+ww, yy+hh-rr);
        m_MGLDC->ellipseArc(xx+ww-rr, yy+hh-rr, rr, rr, 270, 0);
        m_MGLDC->line(xx+ww-rr, yy+hh, xx+rr+1, yy+hh);
        m_MGLDC->ellipseArc(xx+rr, yy+hh-rr, rr, rr, 180, 270);
        m_MGLDC->line(xx, yy+hh-rr, xx, yy+rr+1);
        m_MGLDC->ellipseArc(xx+rr, yy+rr, rr, rr, 90, 180);
    }

    CalcBoundingBox(x, y);
    CalcBoundingBox(x + width, y + height);
}

void wxDC::DoDrawEllipse(wxCoord x, wxCoord y, wxCoord width, wxCoord height)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    wxCoord x2 = (x+width);
    wxCoord y2 = (y+height);

    m_MGLDC->makeCurrent(); // will go away with MGL6.0
    if ( m_brush.GetStyle() != wxTRANSPARENT )
    {
        if ( !m_brushSelected )
            SelectBrush();
        MGLRect rect(XLOG2DEV(x), YLOG2DEV(y), XLOG2DEV(x2), YLOG2DEV(y2));
        m_MGLDC->fillEllipse(rect);
    }

    if ( m_pen.GetStyle() != wxTRANSPARENT )
    {
        if ( !m_penSelected )
            SelectPen();
        MGLRect rect(XLOG2DEV(x) + m_penOfsX, YLOG2DEV(y) + m_penOfsY,
                     XLOG2DEV(x2) + m_penOfsX, YLOG2DEV(y2) + m_penOfsY);
        m_MGLDC->ellipse(rect);
    }

    CalcBoundingBox(x, y);
    CalcBoundingBox(x2, y2);
}

void wxDC::DoDrawEllipticArc(wxCoord x,wxCoord y,wxCoord w,wxCoord h,double sa,double ea)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    wxCoord x2 = (x+w);
    wxCoord y2 = (y+h);

    m_MGLDC->makeCurrent(); // will go away with MGL6.0
    if ( m_brush.GetStyle() != wxTRANSPARENT )
    {
        if (!m_brushSelected) SelectBrush();
        MGLRect rect(XLOG2DEV(x), YLOG2DEV(y), XLOG2DEV(x2), YLOG2DEV(y2));
        m_MGLDC->fillEllipseArc(rect, (int)sa, (int)ea);
    }

    if ( m_pen.GetStyle() != wxTRANSPARENT )
    {
        if ( !m_penSelected )
            SelectPen();
        MGLRect rect(XLOG2DEV(x) + m_penOfsX, YLOG2DEV(y) + m_penOfsY,
                     XLOG2DEV(x2) + m_penOfsX, YLOG2DEV(y2) + m_penOfsY);
        m_MGLDC->ellipseArc(rect, (int)sa, (int)ea);
    }

    CalcBoundingBox(x, y);
    CalcBoundingBox(x2, y2);
}

void wxDC::DoDrawText(const wxString& text, wxCoord x, wxCoord y)
{
    m_MGLDC->makeCurrent(); // will go away with MGL6.0
    DrawAnyText(text, x, y);

    // update the bounding box
    wxCoord w, h;
    CalcBoundingBox(x, y);
    GetTextExtent(text, &w, &h);
    CalcBoundingBox(x + w, y + h);
}

bool wxDC::SelectMGLFont()
{
    if ( m_mglFont == NULL )
    {
        float scale = m_scaleY;
        bool antialiased = (GetDepth() > 8);

        m_mglFont = m_font.GetMGLfont_t(scale, antialiased);
        wxCHECK_MSG( m_mglFont, false, wxT("invalid font") );

        m_MGLDC->useFont(m_mglFont);
        wxLogTrace("mgl_font", "useFont(%p)", m_mglFont);

#if !wxUSE_UNICODE
        wxNativeEncodingInfo nativeEnc;
        wxFontEncoding encoding = m_font.GetEncoding();
        if ( !wxGetNativeFontEncoding(encoding, &nativeEnc) ||
             !wxTestFontEncoding(nativeEnc) )
        {
#if wxUSE_FONTMAP
            if ( !wxFontMapper::Get()->GetAltForEncoding(encoding, &nativeEnc) )
#endif
            {
                nativeEnc.mglEncoding = MGL_ENCODING_ASCII;
            }
        }
        m_MGLDC->setTextEncoding(nativeEnc.mglEncoding);
#endif
    }
    return true;
}

void wxDC::DrawAnyText(const wxString& text, wxCoord x, wxCoord y)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    SelectMGLFont();

    // Render the text:
    wxCoord xx = XLOG2DEV(x);
    wxCoord yy = YLOG2DEV(y);

    m_MGLDC->setLineStyle(MGL_LINE_STIPPLE);
    m_MGLDC->setLineStipple(0xFFFF);
    m_MGLDC->setPenSize(1, 1);
    m_MGLDC->setPenStyle(MGL_BITMAP_SOLID);

#if wxUSE_UNICODE
    const wchar_t *c_text = text.c_str();
#else
    const char *c_text = text.c_str();
#endif

#if 1
    // FIXME_MGL - this is a temporary hack in absence of proper
    //             implementation of solid text background in MGL. Once
    //             the bug in MGL is fixed, this code should be nuked
    //             immediately. Note that the code is not 100% correct;
    //             it only works with wxCOPY logical function
    if ( m_backgroundMode == wxSOLID )
    {
        int w = m_MGLDC->textWidth(c_text);
        int h = m_MGLDC->textHeight();
        m_MGLDC->setColor(m_MGLDC->packColorFast(m_textBackgroundColour.Red(),
                m_textBackgroundColour.Green(), m_textBackgroundColour.Blue()));
        m_MGLDC->fillRect(xx, yy, xx+w, yy+h);
    }
#endif

    m_MGLDC->setColor(m_MGLDC->packColorFast(m_textForegroundColour.Red(),
            m_textForegroundColour.Green(), m_textForegroundColour.Blue()));
    m_MGLDC->setBackColor(m_MGLDC->packColorFast(m_textBackgroundColour.Red(),
            m_textBackgroundColour.Green(), m_textBackgroundColour.Blue()));

    m_MGLDC->drawStr(xx, yy, c_text);

    // Render underline:
    if ( m_font.GetUnderlined() )
    {
        int x1 = xx, y1 = yy;
        int x2 = 0 , y2 = 0;
        int w = m_MGLDC->textWidth(c_text);
        m_MGLDC->underScoreLocation(x1, y1, c_text);
        switch (m_MGLDC->getTextDirection())
        {
            case MGL_RIGHT_DIR: x2 = x1 + w, y2 = y1; break;
            case MGL_LEFT_DIR:  x2 = x1 - w, y2 = y1; break;
            case MGL_UP_DIR:    x2 = x1, y2 = y1 - w; break;
            case MGL_DOWN_DIR:  x2 = x1, y2 = y1 + w; break;
        }
        m_MGLDC->line(x1, y1, x2, y2);
    }

    m_penSelected = m_brushSelected = false;
}

void wxDC::DoDrawRotatedText(const wxString& text,
                             wxCoord x, wxCoord y,
                             double angle)
{
    m_MGLDC->makeCurrent(); // will go away with MGL6.0

    if ( angle == 0 )
    {
        DoDrawText(text, x, y);
        return;
    }
    else if ( angle == 90.0 )
        m_MGLDC->setTextDirection(MGL_UP_DIR);
    else if ( angle == 180.0 )
        m_MGLDC->setTextDirection(MGL_LEFT_DIR);
    else if ( angle == 270.0 )
        m_MGLDC->setTextDirection(MGL_DOWN_DIR);
    else
    {
        // FIXME_MGL -- implement once MGL supports it
        wxFAIL_MSG(wxT("wxMGL only supports rotated text with angle 0,90,180 or 270"));
        return;
    }

    DrawAnyText(text, x, y);

    // Restore default:
    m_MGLDC->setTextDirection(MGL_RIGHT_DIR);
}

// ---------------------------------------------------------------------------
// set GDI objects
// ---------------------------------------------------------------------------

void wxDC::SelectMGLStipplePen(int style)
{
    ushort stipple;

    switch (style)
    {
        case wxDOT:        stipple = STIPPLE_wxDOT;        break;
        case wxLONG_DASH:  stipple = STIPPLE_wxLONG_DASH;  break;
        case wxSHORT_DASH: stipple = STIPPLE_wxSHORT_DASH; break;
        case wxDOT_DASH:   stipple = STIPPLE_wxDOT_DASH;   break;
        default:           stipple = STIPPLE_wxSOLID;      break;
    }

    m_MGLDC->setLineStyle(MGL_LINE_STIPPLE);
    m_MGLDC->setLineStipple(stipple);
    m_MGLDC->setPenSize(1, 1);
    m_MGLDC->setPenStyle(MGL_BITMAP_SOLID);
    m_penOfsY = m_penOfsX = 0;
}

// Accepted valus of SelectMGLFatPen's 2nd argument
enum {
    wxMGL_SELECT_FROM_PEN,
    wxMGL_SELECT_FROM_BRUSH
};

void wxDC::SelectMGLFatPen(int style, int flag)
{
    MGL_penStyleType penstyle;
    const pattern_t *pattern = NULL;
    pixpattern24_t *pixPattern = NULL;
    int wx, wy;
    int slot;

    // Since MGL pens may be created from wxBrush or wxPen and we often
    // switch between pens and brushes, we take advantage of MGL's ability
    // to have multiple (pix)pattern_t's loaded. We always download pen
    // to 0th slot and brush to 1st slot.
    if ( flag == wxMGL_SELECT_FROM_PEN )
        slot = 0;
    else
        slot = 1;

    // compute pen's width:
    if ( m_pen.GetWidth() <= 1 )
    {
        wx = wy = 1;
        m_penOfsX = m_penOfsY = 0;
    }
    else
    {
        wx = (int)(0.5 + fabs((double) XLOG2DEVREL(m_pen.GetWidth())));
        wy = (int)(0.5 + fabs((double) YLOG2DEVREL(m_pen.GetWidth())));
        m_penOfsX = -wx/2;
        m_penOfsY = -wy/2;
    }

    // find pen's type:
    penstyle = MGL_BITMAP_TRANSPARENT;
    switch (style)
    {
        case wxBDIAGONAL_HATCH:  pattern = &PATTERN_wxBDIAGONAL_HATCH;
                                 penstyle = MGL_BITMAP_TRANSPARENT;
                                 break;
        case wxCROSSDIAG_HATCH:  pattern = &PATTERN_wxCROSSDIAG_HATCH;
                                 penstyle = MGL_BITMAP_TRANSPARENT;
                                 break;
        case wxFDIAGONAL_HATCH:  pattern = &PATTERN_wxFDIAGONAL_HATCH;
                                 penstyle = MGL_BITMAP_TRANSPARENT;
                                 break;
        case wxCROSS_HATCH:      pattern = &PATTERN_wxCROSS_HATCH;
                                 penstyle = MGL_BITMAP_TRANSPARENT;
                                 break;
        case wxHORIZONTAL_HATCH: pattern = &PATTERN_wxHORIZONTAL_HATCH;
                                 penstyle = MGL_BITMAP_TRANSPARENT;
                                 break;
        case wxVERTICAL_HATCH:   pattern = &PATTERN_wxVERTICAL_HATCH;
                                 penstyle = MGL_BITMAP_TRANSPARENT;
                                 break;

        case wxSTIPPLE:
            if ( flag == wxMGL_SELECT_FROM_PEN )
                pixPattern = (pixpattern24_t*) m_pen.GetPixPattern();
            else
                pixPattern = (pixpattern24_t*) m_brush.GetPixPattern();
            penstyle = MGL_PIXMAP;
            break;

        case wxSTIPPLE_MASK_OPAQUE:
            pattern = (pattern_t*) m_brush.GetMaskPattern();
            penstyle = MGL_BITMAP_OPAQUE;
            break;

        case wxSOLID:
        default:
            penstyle = MGL_BITMAP_SOLID; break;
    }

    // ...and finally, pass the pen to MGL:

    if ( pattern )
    {
        if ( !m_downloadedPatterns[slot] )
        {
            m_MGLDC->setPenBitmapPattern(slot, pattern);
            m_downloadedPatterns[slot] = true;
        }
        m_MGLDC->usePenBitmapPattern(slot);
    }

    if ( pixPattern )
    {
        if ( !m_downloadedPatterns[slot] )
        {
            pixpattern_t pix;
            int x, y, c;

            switch (GetDepth())
            {
                case 8:
                    for (y = 0; y < 8; y++)
                        for (x = 0; x < 8; x++)
                            pix.b8.p[x][y] = (uchar)m_MGLDC->packColorFast(
                                                        pixPattern->p[x][y][0],
                                                        pixPattern->p[x][y][1],
                                                        pixPattern->p[x][y][2]);
                    break;
                case 15:
                case 16:
                    for (y = 0; y < 8; y++)
                        for (x = 0; x < 8; x++)
                            pix.b16.p[x][y] = (M_uint16)m_MGLDC->packColorFast(
                                                        pixPattern->p[x][y][0],
                                                        pixPattern->p[x][y][1],
                                                        pixPattern->p[x][y][2]);
                    break;
                case 24:
                    for (y = 0; y < 8; y++)
                        for (x = 0; x < 8; x++)
                            for (c = 0; c < 3; c++)
                                pix.b24.p[x][y][c] = pixPattern->p[x][y][c];
                    break;
                case 32:
                    for (y = 0; y < 8; y++)
                        for (x = 0; x < 8; x++)
                            pix.b32.p[x][y] = m_MGLDC->packColorFast(
                                                        pixPattern->p[x][y][0],
                                                        pixPattern->p[x][y][1],
                                                        pixPattern->p[x][y][2]);
                    break;
                default:
                    wxFAIL_MSG(wxT("invalid DC depth"));
                    break;
            }
            m_MGLDC->setPenPixmapPattern(slot, &pix);
            m_downloadedPatterns[slot] = true;
        }
        m_MGLDC->usePenPixmapPattern(slot);
    }

    m_MGLDC->setLineStyle(MGL_LINE_PENSTYLE);
    m_MGLDC->setPenStyle(penstyle);
    m_MGLDC->setPenSize(wy, wx);
}

void wxDC::SelectPen()
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    wxColour& clr = m_pen.GetColour();
    m_MGLDC->makeCurrent(); // will go away with MGL6.0
    m_MGLDC->setColorRGB(clr.Red(), clr.Green(), clr.Blue());

    switch (m_pen.GetStyle())
    {
        case wxTRANSPARENT:
            break;

        case wxDOT:
        case wxLONG_DASH:
        case wxSHORT_DASH:
        case wxDOT_DASH:
            SelectMGLStipplePen(m_pen.GetStyle());
            break;

        case wxBDIAGONAL_HATCH:
        case wxCROSSDIAG_HATCH:
        case wxFDIAGONAL_HATCH:
        case wxCROSS_HATCH:
        case wxHORIZONTAL_HATCH:
        case wxVERTICAL_HATCH:
            SelectMGLFatPen(m_pen.GetStyle(), wxMGL_SELECT_FROM_PEN);
            break;

        case wxSTIPPLE:
            SelectMGLFatPen(m_pen.GetStyle(), wxMGL_SELECT_FROM_PEN);
            break;

        case wxSOLID:
        case wxUSER_DASH:
        default:
            if ( m_pen.GetWidth() <= 1 )
                SelectMGLStipplePen(wxSOLID);
            else
                SelectMGLFatPen(wxSOLID, wxMGL_SELECT_FROM_PEN);
            break;
    }
    m_penSelected = true;
    m_brushSelected = false;
}

void wxDC::SelectBrush()
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    wxColour fg, bg;
    m_MGLDC->makeCurrent(); // will go away with MGL6.0

    if ( m_brush.GetStyle() == wxSTIPPLE_MASK_OPAQUE )
    {
        fg = m_textForegroundColour;
        bg = m_textBackgroundColour;
    }
    else
    {
        fg = m_brush.GetColour();
        bg = m_backgroundBrush.GetColour();
    }

    m_MGLDC->setColorRGB(fg.Red(), fg.Green(), fg.Blue());
    m_MGLDC->setBackColor(m_MGLDC->packColorFast(bg.Red(), bg.Green(), bg.Blue()));
    m_penSelected = false;
    m_brushSelected = true;

    SelectMGLFatPen(m_brush.GetStyle(), wxMGL_SELECT_FROM_BRUSH);
}

void wxDC::SetPen(const wxPen& pen)
{
    if ( !pen.Ok() ) return;
    if ( m_pen == pen ) return;
    m_pen = pen;
    m_penSelected = false;
    m_downloadedPatterns[0] = false;
}

void wxDC::SetBrush(const wxBrush& brush)
{
    if ( !brush.Ok() ) return;
    if ( m_brush == brush ) return;
    m_brush = brush;
    m_brushSelected = false;
    m_downloadedPatterns[1] = false;
}

void wxDC::SetPalette(const wxPalette& palette)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    if ( !palette.Ok() )
    {
        if ( m_oldPalette.Ok() )
            SetPalette(m_oldPalette);
        return;
    }

    if ( palette.IsSameAs(m_palette) )
        return;

    m_oldPalette = m_palette;
    m_palette = palette;

    int cnt = m_palette.GetColoursCount();
    palette_t *pal = m_palette.GetMGLpalette_t();
    m_MGLDC->setPalette(pal, cnt, 0);
    m_MGLDC->realizePalette(cnt, 0, TRUE);
}

void wxDC::SetFont(const wxFont& font)
{
    if ( font.Ok() )
    {
        m_font = font;
        m_mglFont = NULL;
    }
}

void wxDC::SetBackground(const wxBrush& brush)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    if (!brush.Ok()) return;

    m_backgroundBrush = brush;
    wxColour &clr = m_backgroundBrush.GetColour();
    m_MGLDC->makeCurrent(); // will go away with MGL6.0
    m_MGLDC->setBackColor(
             m_MGLDC->packColorFast(clr.Red(), clr.Green(), clr.Blue()));
}

void wxDC::SetBackgroundMode(int mode)
{
    m_backgroundMode = mode;
    if ( mode == wxSOLID )
        m_MGLDC->setBackMode(MGL_OPAQUE_BACKGROUND);
    else
        m_MGLDC->setBackMode(MGL_TRANSPARENT_BACKGROUND);
}

void wxDC::SetLogicalFunction(wxRasterOperationMode function)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );

    m_logicalFunction = function;

    m_MGLDC->makeCurrent(); // will go away with MGL6.0
    m_MGLDC->setWriteMode(LogicalFunctionToMGLRop(m_logicalFunction));
}

int wxDC::LogicalFunctionToMGLRop(int logFunc) const
{
    MGL_writeModeType rop;

    switch (logFunc)
    {
        case wxCLEAR:        rop = MGL_R2_BLACK;         break;
        case wxXOR:          rop = MGL_R2_XORSRC;        break;
        case wxINVERT:       rop = MGL_R2_NOT;           break;
        case wxOR_REVERSE:   rop = MGL_R2_MERGESRCNOT;   break;
        case wxAND_REVERSE:  rop = MGL_R2_MASKSRCNOT;    break;
        case wxCOPY:         rop = MGL_R2_COPYSRC;       break;
        case wxAND:          rop = MGL_R2_MASKSRC;       break;
        case wxAND_INVERT:   rop = MGL_R2_MASKNOTSRC;    break;
        case wxNO_OP:        rop = MGL_R2_NOP;           break;
        case wxNOR:          rop = MGL_R2_NOTMERGESRC;   break;
        case wxEQUIV:        rop = MGL_R2_NOTXORSRC;     break;
        case wxSRC_INVERT:   rop = MGL_R2_NOTCOPYSRC;    break;
        case wxOR_INVERT:    rop = MGL_R2_MERGENOTSRC;   break;
        case wxNAND:         rop = MGL_R2_NOTMASKSRC;    break;
        case wxOR:           rop = MGL_R2_MERGESRC;      break;
        case wxSET:          rop = MGL_R2_WHITE;         break;
        default:
           wxFAIL_MSG( wxT("unsupported logical function") );
           return MGL_REPLACE_MODE;
    }
    return (int)rop;
}

bool wxDC::StartDoc(const wxString& WXUNUSED(message))
{
    // We might be previewing, so return true to let it continue.
    return true;
}

void wxDC::EndDoc()
{
}

void wxDC::StartPage()
{
}

void wxDC::EndPage()
{
}

// ---------------------------------------------------------------------------
// text metrics
// ---------------------------------------------------------------------------

wxCoord wxDC::GetCharHeight() const
{
    wxCurrentDCSwitcher switcher(m_MGLDC);
    if ( !wxConstCast(this, wxDC)->SelectMGLFont() ) return -1;
    return YDEV2LOGREL(m_mglFont->fontHeight);
}

wxCoord wxDC::GetCharWidth() const
{
    wxCurrentDCSwitcher switcher(m_MGLDC);
    if ( !wxConstCast(this, wxDC)->SelectMGLFont() ) return -1;
    // VS: wxT() is intentional, charWidth() has both char and wchar_t version
    // VS: YDEV is corrent, it should *not* be XDEV, because font's are only
    //     scaled according to m_scaleY
    return YDEV2LOGREL(m_mglFont->fontWidth);
}

void wxDC::DoGetTextExtent(const wxString& string, wxCoord *x, wxCoord *y,
                           wxCoord *descent, wxCoord *externalLeading,
                           const wxFont *theFont) const
{
    wxFont oldFont;

    if ( theFont != NULL )
    {
        oldFont = m_font;
        wxConstCast(this, wxDC)->SetFont(*theFont);
    }

    wxCurrentDCSwitcher switcher(m_MGLDC);
    if ( !wxConstCast(this, wxDC)->SelectMGLFont() ) return;

    if ( x )
        // VS: YDEV is corrent, it should *not* be XDEV, because font's are
        //     only scaled according to m_scaleY
        *x = YDEV2LOGREL(m_MGLDC->textWidth(string.wc_str()));
    if ( y )
        *y = YDEV2LOGREL(m_MGLDC->textHeight());
    if ( descent )
        *descent = YDEV2LOGREL(m_mglFont->descent);
    if ( externalLeading )
        *externalLeading = YDEV2LOGREL(m_mglFont->leading);

    if ( theFont != NULL )
        wxConstCast(this, wxDC)->SetFont(oldFont);
}


// ---------------------------------------------------------------------------
// mapping modes
// ---------------------------------------------------------------------------

void wxDC::ComputeScaleAndOrigin()
{
    double newX = m_logicalScaleX * m_userScaleX;
    double newY = m_logicalScaleY * m_userScaleY;

    // make sure font will be reloaded before drawing:
    if ( newY != m_scaleY )
        m_mglFont = NULL;
    // make sure m_penOfs{X,Y} will be reevaluated before drawing:
    if ( newY != m_scaleY || newX != m_scaleX )
        m_penSelected = false;

    m_scaleX = newX, m_scaleY = newY;
}

void wxDC::DoGetSize(int *w, int *h) const
{
    if (w) *w = m_MGLDC->sizex()+1;
    if (h) *h = m_MGLDC->sizey()+1;
}

void wxDC::DoGetSizeMM(int *width, int *height) const
{
    int w = 0;
    int h = 0;
    GetSize(&w, &h);
    if ( width ) *width = int(double(w) / (m_userScaleX*m_mm_to_pix_x));
    if ( height ) *height = int(double(h) / (m_userScaleY*m_mm_to_pix_y));
}

wxSize wxDC::GetPPI() const
{
    return wxSize(int(double(m_mm_to_pix_x) * inches2mm),
                  int(double(m_mm_to_pix_y) * inches2mm));
}


// ---------------------------------------------------------------------------
// Blitting
// ---------------------------------------------------------------------------

bool wxDC::DoBlit(wxCoord xdest, wxCoord ydest,
                  wxCoord width, wxCoord height,
                  wxDC *source, wxCoord xsrc, wxCoord ysrc,
                  wxRasterOperationMode rop, bool useMask,
                  wxCoord xsrcMask, wxCoord ysrcMask)
{
    wxCHECK_MSG( Ok(), false, wxT("invalid dc") );
    wxCHECK_MSG( source, false, wxT("invalid source dc") );

    // transform the source DC coords to the device ones
    xsrc = source->LogicalToDeviceX(xsrc);
    ysrc = source->LogicalToDeviceY(ysrc);

    /* FIXME_MGL: use the mask origin when drawing transparently */
    if (xsrcMask == -1 && ysrcMask == -1)
    {
        xsrcMask = xsrc; ysrcMask = ysrc;
    }
    else
    {
        xsrcMask = source->LogicalToDeviceX(xsrcMask);
        ysrcMask = source->LogicalToDeviceY(ysrcMask);
    }

    CalcBoundingBox(xdest, ydest);
    CalcBoundingBox(xdest + width, ydest + height);

    /* scale/translate size and position */
    wxCoord xx = XLOG2DEV(xdest);
    wxCoord yy = YLOG2DEV(ydest);

    if ( source->m_isMemDC )
    {
        wxMemoryDC *memDC = (wxMemoryDC*) source;
        DoDrawSubBitmap(memDC->GetSelectedObject(),
                        xsrc, ysrc, width, height,
                        xdest, ydest, rop, useMask);
    }
    else
    {
        wxCoord ww = XLOG2DEVREL(width);
        wxCoord hh = YLOG2DEVREL(height);

        m_MGLDC->makeCurrent(); // will go away with MGL6.0
        m_MGLDC->bitBlt(*source->GetMGLDC(),
                        xsrc, ysrc, xsrc + ww, ysrc + hh,
                        xx, yy, LogicalFunctionToMGLRop(rop));
    }

    return true;
}

void wxDC::DoDrawBitmap(const wxBitmap &bmp, wxCoord x, wxCoord y, bool useMask)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );
    wxCHECK_RET( bmp.Ok(), wxT("invalid bitmap") );

    wxCoord w = bmp.GetWidth();
    wxCoord h = bmp.GetHeight();

    DoDrawSubBitmap(bmp, 0, 0, w, h, x, y, m_logicalFunction, useMask);
}

void wxDC::DoDrawIcon(const wxIcon& icon, wxCoord x, wxCoord y)
{
    // VZ: egcs 1.0.3 refuses to compile this without cast, no idea why
    DoDrawBitmap((const wxBitmap&)icon, x, y, true);
}


static inline void DoBitBlt(const wxBitmap& src, MGLDevCtx *dst,
                            int sx, int sy, int sw, int sh,
                            int dx, int dy, int dw, int dh,
                            int rop, bool useStretching, bool putSection)
{
    bitmap_t *bmp = src.GetMGLbitmap_t();
    if (!useStretching)
    {
        if (!putSection)
            dst->putBitmap(dx, dy, bmp, rop);
        else
            dst->putBitmapSection(sx, sy, sx + sw, sy + sh, dx, dy, bmp, rop);
    }
    else
    {
        if (!putSection)
            dst->stretchBitmap(dx, dy, dx + dw, dy + dh, bmp, rop);
        else
            dst->stretchBitmapSection(sx, sy, sx + sw, sy + sh,
                                      dx, dy, dx + dw, dy + dh, bmp, rop);
    }
}

void wxDC::DoDrawSubBitmap(const wxBitmap &bmp,
                           wxCoord x, wxCoord y, wxCoord w, wxCoord h,
                           wxCoord destx, wxCoord desty, int rop, bool useMask)
{
    wxCHECK_RET( Ok(), wxT("invalid dc") );
    wxCHECK_RET( bmp.Ok(), wxT("invalid bitmap") );

    CalcBoundingBox(x, y);
    CalcBoundingBox(x + w, y + h);

    wxCoord dx = XLOG2DEV(destx);
    wxCoord dy = YLOG2DEV(desty);
    wxCoord dw = XLOG2DEVREL(w);
    wxCoord dh = YLOG2DEVREL(h);

    m_MGLDC->makeCurrent(); // will go away with MGL6.0

    bool useStretching = ((w != dw) || (h != dh));
    bool putSection = (w != bmp.GetWidth() || h != bmp.GetHeight());
    MGL_writeModeType mglRop = (MGL_writeModeType)LogicalFunctionToMGLRop(rop);

    if ( bmp.GetDepth() == 1 )
    {
        // Mono bitmaps are handled in special way -- all 1s are drawn in
        // foreground colours, all 0s in background colour.

        ((wxBitmap&)bmp).SetMonoPalette(m_textForegroundColour, m_textBackgroundColour);
    }

    if ( useMask && bmp.GetMask() )
    {
        // Since MGL does not support masks directly (in MGL, mask is handled
        // in same way as in wxImage, i.e. there is one "key" color), we
        // simulate masked bitblt in 6 steps (same as in MSW):
        //
        // 1. Create a temporary bitmap and copy the destination area into it.
        // 2. Copy the source area into the temporary bitmap using the
        //    specified logical function.
        // 3. Set the masked area in the temporary bitmap to BLACK by ANDing
        //    the mask bitmap with the temp bitmap with the foreground colour
        //    set to WHITE and the bg colour set to BLACK.
        // 4. Set the unmasked area in the destination area to BLACK by
        //    ANDing the mask bitmap with the destination area with the
        //    foreground colour set to BLACK and the background colour set
        //    to WHITE.
        // 5. OR the temporary bitmap with the destination area.
        // 6. Delete the temporary bitmap.
        //
        // This sequence of operations ensures that the source's transparent
        // area need not be black, and logical functions are supported.

        wxBitmap mask = bmp.GetMask()->GetBitmap();

        MGLMemoryDC *temp;

        if ( GetDepth() <= 8 )
        {
            temp = new MGLMemoryDC(dw, dh, GetDepth(), NULL);
            wxDC tempdc;
            tempdc.SetMGLDC(temp, false);
            tempdc.SetPalette(m_palette);
        }
        else
        {
            pixel_format_t pf;
            m_MGLDC->getPixelFormat(pf);
            temp = new MGLMemoryDC(dw, dh, GetDepth(), &pf);
        }

        wxCHECK_RET( temp->isValid(), wxT("cannot create temporary dc") );

        temp->bitBlt(*m_MGLDC, dx, dy, dx + dw, dy + dh, 0, 0, MGL_REPLACE_MODE);

        DoBitBlt(bmp, temp, x, y, w, h, 0, 0, dw, dh, mglRop,
                 useStretching, putSection);

        mask.SetMonoPalette(wxColour(0,0,0), wxColour(255,255,255));
        DoBitBlt(mask, temp, x, y, w, h, 0, 0, dw, dh, MGL_R2_MASKSRC,
                 useStretching, putSection);
        DoBitBlt(mask, m_MGLDC, x, y, w, h, dx, dy, dw, dh, MGL_R2_MASKNOTSRC,
                 useStretching, putSection);

        m_MGLDC->bitBlt(*temp, 0, 0, dw, dh, dx, dy, MGL_OR_MODE);

        delete temp;
    }

    else
    {
        DoBitBlt(bmp, m_MGLDC, x, y, w, h, dx, dy, dw, dh, mglRop,
                 useStretching, putSection);
    }
}
