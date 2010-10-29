/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/dcclient.cpp
// Purpose:     wxClientDCImpl class
// Author:      Julian Smart
// Modified by:
// Created:     01/02/97
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/*
  About pens, brushes, and the m_autoSetting flag:

  Under X, pens and brushes control some of the same X drawing
  parameters.  Therefore, it is impossible to independently maintain
  the current pen and the current brush. Also, some settings depend on
  the current logical function. The m_currentFill, etc. instance
  variables remember state across the brush and pen.

  Since pens are used more than brushes, the m_autoSetting flag is used to
  indicate that a brush was recently used, and SetPen must be called to
  reinstall the current pen's parameters. If m_autoSetting includes 0x2, then the
  pens color may need to be set based on XOR.

  There is, unfortunately, some confusion between setting the current pen/brush
  and actually installing the brush/pen parameters. Both functionalies are
  perform by SetPen and SetBrush. C'est la vie.
*/

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/window.h"
    #include "wx/dcmemory.h"
    #include "wx/math.h"
    #include "wx/image.h"
    #include "wx/dcclient.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"
#include "wx/motif/dcclient.h"

#ifdef __EMX__
    #include <float.h>          // for M_PI
#endif // __EMX__

#include "bdiag.xbm"
#include "fdiag.xbm"
#include "cdiag.xbm"
#include "horiz.xbm"
#include "verti.xbm"
#include "cross.xbm"

static Pixmap bdiag, cdiag, fdiag, cross, horiz, verti;

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------

// Fudge factor (VZ: what??)
#define WX_GC_CF 1

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

IMPLEMENT_ABSTRACT_CLASS(wxClientDCImpl, wxWindowDCImpl)
IMPLEMENT_ABSTRACT_CLASS(wxPaintDCImpl, wxWindowDCImpl)
IMPLEMENT_ABSTRACT_CLASS(wxWindowDCImpl, wxMotifDCImpl)

#define IS_HATCH(s)    ((s)>=wxFIRST_HATCH && (s)<=wxLAST_HATCH)

// FIXME: left over after removal of wxDC::GetOptimization()
#define GET_OPTIMIZATION false

// ----------------------------------------------------------------------------
// prototypes
// ----------------------------------------------------------------------------

static void XCopyRemote(Display *src_display, Display *dest_display,
                        Drawable src, Drawable dest,
                        GC destgc,
                        int srcx, int srcy,
                        unsigned int w, unsigned int h,
                        int destx, int desty,
                        bool more, XImage **cache);

// ============================================================================
// implementation
// ============================================================================

/*
 * compare two doubles and return the larger rounded
 * to the nearest int
 */
static int roundmax(double a, double b)
{
    return (int)((a > b ? a : b) + 0.5);
}

/*
 * compare two doubles and return the smaller rounded
 * to the nearest int
 */
static int roundmin(double a, double b)
{
    return (int)((a < b ? a : b) - 0.5);
}


// ----------------------------------------------------------------------------
// wxWindowDCImpl
// ----------------------------------------------------------------------------

void wxWindowDCImpl::Init()
{
    m_gc = (WXGC) 0;
    m_gcBacking = (WXGC) 0;
    m_window = NULL;
    m_backgroundPixel = -1;
    m_currentPenWidth = 1;
    m_currentPenJoin = -1;
    m_currentPenDashCount = -1;
    m_currentPenDash = NULL;
    m_currentStyle = -1;
    m_currentFill = -1;
    m_colour = wxColourDisplay();
    m_display = NULL;
    m_pixmap = (WXPixmap) 0;
    m_autoSetting = 0;
    m_ok = false;
    m_clipRegion = (WXRegion) 0;
}

wxWindowDCImpl::wxWindowDCImpl(wxDC *owner)
              : wxMotifDCImpl(owner)
{
    Init();
}

wxWindowDCImpl::wxWindowDCImpl(wxDC *owner, wxWindow *window)
              : wxMotifDCImpl(owner)
{
    wxASSERT_MSG( (window != NULL), "You must pass a valid wxWindow to wxWindowDCImpl/wxClientDCImpl/wxPaintDCImpl constructor." );

    Init();

    m_window = window;
    m_font = window->GetFont();
    m_ok = true;

    m_display = window->GetXDisplay();
    m_pixmap = window->GetXWindow();
    Display* display = (Display*) m_display;

    XSetWindowColormap (display, (Pixmap) m_pixmap, (Colormap) wxTheApp->GetMainColormap(m_display));

    XGCValues gcvalues;
    gcvalues.foreground = BlackPixel (display, DefaultScreen (display));
    gcvalues.background = WhitePixel (display, DefaultScreen (display));
    gcvalues.graphics_exposures = False;
    gcvalues.subwindow_mode = IncludeInferiors;
    gcvalues.line_width = 1;
#if !wxMOTIF_NEW_FONT_HANDLING
    WXFontStructPtr pFontStruct = m_font.GetFontStruct(m_userScaleY*m_logicalScaleY, m_display);
    gcvalues.font = ((XFontStruct*)pFontStruct)->fid;
#endif
    m_gc = (WXGC) XCreateGC (display, RootWindow (display, DefaultScreen (display)),
        GCForeground | GCBackground | GCGraphicsExposures | GCLineWidth | GCSubwindowMode
#if !wxMOTIF_NEW_FONT_HANDLING
        | GCFont
#endif
                             ,
        &gcvalues);

    if (m_window->GetBackingPixmap())
    {
        m_gcBacking = (WXGC) XCreateGC (display, RootWindow (display,
            DefaultScreen (display)),
            GCForeground | GCBackground | GCGraphicsExposures | GCLineWidth | GCSubwindowMode,
            &gcvalues);
    }

    m_backgroundPixel = gcvalues.background;

    SetBackground(wxBrush(m_window->GetBackgroundColour(), wxSOLID));
}

wxWindowDCImpl::~wxWindowDCImpl()
{
    if (m_gc)
        XFreeGC ((Display*) m_display, (GC) m_gc);
    m_gc = (WXGC) 0;

    if (m_gcBacking)
        XFreeGC ((Display*) m_display, (GC) m_gcBacking);
    m_gcBacking = (WXGC) 0;

    if (m_clipRegion)
        XDestroyRegion ((Region) m_clipRegion);
    m_clipRegion = (WXRegion) 0;
}

extern bool wxDoFloodFill(wxDC *dc, wxCoord x, wxCoord y,
                          const wxColour & col, wxFloodFillStyle style);

bool wxWindowDCImpl::DoFloodFill(wxCoord x, wxCoord y,
                             const wxColour& col, wxFloodFillStyle style)
{
    return wxDoFloodFill(GetOwner(), x, y, col, style);
}

bool wxWindowDCImpl::DoGetPixel( wxCoord x1, wxCoord y1, wxColour *col ) const
{
    // Generic (and therefore rather inefficient) method.
    // Could be improved.
    wxMemoryDC memdc;
    wxBitmap bitmap(1, 1);
    memdc.SelectObject(bitmap);
    memdc.Blit(0, 0, 1, 1, GetOwner(), x1, y1);
    memdc.SelectObject(wxNullBitmap);
    wxImage image = bitmap.ConvertToImage();
    col->Set(image.GetRed(0, 0), image.GetGreen(0, 0), image.GetBlue(0, 0));
    return true;
}

void wxWindowDCImpl::DoDrawLine( wxCoord x1, wxCoord y1, wxCoord x2, wxCoord y2 )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    int x1d, y1d, x2d, y2d;

    x1d = XLOG2DEV(x1);
    y1d = YLOG2DEV(y1);
    x2d = XLOG2DEV(x2);
    y2d = YLOG2DEV(y2);

    if (m_autoSetting)
        SetPen (m_pen);

    XDrawLine ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, x1d, y1d, x2d, y2d);

    if (m_window && m_window->GetBackingPixmap())
        XDrawLine ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(), (GC) m_gcBacking,
        XLOG2DEV_2(x1), YLOG2DEV_2(y1),
        XLOG2DEV_2(x2), YLOG2DEV_2(y2));

    CalcBoundingBox(x1, y1);
    CalcBoundingBox(x2, y2);
}

void wxWindowDCImpl::DoCrossHair( wxCoord x, wxCoord y )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    if (m_autoSetting)
        SetPen (m_pen);

    int xx = XLOG2DEV (x);
    int yy = YLOG2DEV (y);
    int ww, hh;
    wxDisplaySize (&ww, &hh);
    XDrawLine ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, 0, yy,
        ww, yy);
    XDrawLine ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xx, 0,
        xx, hh);

    if (m_window && m_window->GetBackingPixmap())
    {
        xx = XLOG2DEV_2 (x);
        yy = YLOG2DEV_2 (y);
        XDrawLine ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(), (GC) m_gcBacking,
            0, yy,
            ww, yy);
        XDrawLine ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(), (GC) m_gcBacking,
            xx, 0,
            xx, hh);
    }
}

void wxWindowDCImpl::DoDrawArc( wxCoord x1, wxCoord y1, wxCoord x2, wxCoord y2, wxCoord xc, wxCoord yc )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    int xx1 = XLOG2DEV (x1);
    int yy1 = YLOG2DEV (y1);
    int xx2 = XLOG2DEV (x2);
    int yy2 = YLOG2DEV (y2);
    int xxc = XLOG2DEV (xc);
    int yyc = YLOG2DEV (yc);
    int xxc_2 = XLOG2DEV_2 (xc);
    int yyc_2 = YLOG2DEV_2 (yc);

    wxCoord dx = xx1 - xxc;
    wxCoord dy = yy1 - yyc;
    double radius = sqrt ((double)(dx * dx + dy * dy));
    wxCoord r = (wxCoord) radius;

    double radius1, radius2;

    if (xx1 == xx2 && yy1 == yy2)
    {
        radius1 = 0.0;
        radius2 = 360.0;
    }
    else if (radius == 0.0)
        radius1 = radius2 = 0.0;
    else
    {
        if (xx1 - xxc == 0)
            if (yy1 - yyc < 0)
                radius1 = 90.0;
            else
                radius1 = -90.0;
            else
                radius1 = -atan2 ((double) (yy1 - yyc), (double) (xx1 - xxc)) * 360.0 / (2 * M_PI);

            if (xx2 - xxc == 0)
                if (yy2 - yyc < 0)
                    radius2 = 90.0;
                else
                    radius2 = -90.0;
                else
                    radius2 = -atan2 ((double) (yy2 - yyc), (double) (xx2 - xxc)) * 360.0 / (2 * M_PI);
    }
    radius1 *= 64.0;
    radius2 *= 64.0;
    int alpha1 = (int) radius1;
    int alpha2 = (int) (radius2 - radius1);
    while (alpha2 <= 0)
        alpha2 += 360 * 64;
    while (alpha2 > 360 * 64)
        alpha2 -= 360 * 64;

    if (m_brush.IsOk() && m_brush.GetStyle () != wxTRANSPARENT)
    {
        SetBrush (m_brush);
        XFillArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) (GC) m_gc,
            xxc - r, yyc - r, 2 * r, 2 * r, alpha1, alpha2);

        if (m_window && m_window->GetBackingPixmap())
            XFillArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(), (GC) m_gcBacking,
            xxc_2 - r, yyc_2 - r, 2 * r, 2 * r, alpha1, alpha2);

    }

    if (m_pen.IsOk() && m_pen.GetStyle () != wxTRANSPARENT)
    {
        if (m_autoSetting)
            SetPen (m_pen);
        XDrawArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc,
            xxc - r, yyc - r, 2 * r, 2 * r, alpha1, alpha2);

        if (m_window && m_window->GetBackingPixmap())
            XDrawArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(), (GC) m_gcBacking,
            xxc_2 - r, yyc_2 - r, 2 * r, 2 * r, alpha1, alpha2);
    }
    CalcBoundingBox (x1, y1);
    CalcBoundingBox (x2, y2);
}

void wxWindowDCImpl::DoDrawEllipticArc( wxCoord x, wxCoord y, wxCoord width, wxCoord height, double sa, double ea )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    int xd, yd, wd, hd;

    xd = XLOG2DEV(x);
    yd = YLOG2DEV(y);
    wd = XLOG2DEVREL(width);
    hd = YLOG2DEVREL(height);

    if (sa>=360 || sa<=-360) sa=sa-int(sa/360)*360;
    if (ea>=360 || ea<=-360) ea=ea-int(ea/360)*360;
    int start = int(sa*64);
    int end   = int(ea*64);
    if (start<0) start+=360*64;
    if (end  <0) end  +=360*64;
    if (end>start) end-=start;
    else end+=360*64-start;

    if (m_brush.IsOk() && m_brush.GetStyle () != wxTRANSPARENT)
    {
        m_autoSetting = true;    // must be reset

        SetBrush (m_brush);
        XFillArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd, yd, wd, hd, start, end);

        if (m_window && m_window->GetBackingPixmap())
            XFillArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(), (GC) m_gcBacking,
            XLOG2DEV_2 (x), YLOG2DEV_2 (y),wd,hd,start,end);
    }

    if (m_pen.IsOk() && m_pen.GetStyle () != wxTRANSPARENT)
    {
        if (m_autoSetting)
            SetPen (m_pen);
        XDrawArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd, yd, wd, hd, start,end);
        if (m_window && m_window->GetBackingPixmap())
            XDrawArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(), (GC) m_gcBacking,
            XLOG2DEV_2 (x), YLOG2DEV_2 (y),wd,hd,start,end);
    }
    CalcBoundingBox (x, y);
    CalcBoundingBox (x + width, y + height);
}

void wxWindowDCImpl::DoDrawPoint( wxCoord x, wxCoord y )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    if (m_pen.IsOk() && m_autoSetting)
        SetPen (m_pen);

    XDrawPoint ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, XLOG2DEV (x), YLOG2DEV (y));
    if (m_window && m_window->GetBackingPixmap())
        XDrawPoint ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking, XLOG2DEV_2 (x), YLOG2DEV_2 (y));

    CalcBoundingBox (x, y);
}

void wxWindowDCImpl::DoDrawLines( int n, wxPoint points[], wxCoord xoffset, wxCoord yoffset )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    if (m_pen.IsOk() && m_pen.GetStyle () != wxTRANSPARENT)
    {
        if (m_autoSetting)
            SetPen (m_pen);

        XPoint *xpoints = new XPoint[n];
        int i;

        for (i = 0; i < n; i++)
        {
            xpoints[i].x = (short)XLOG2DEV (points[i].x + xoffset);
            xpoints[i].y = (short)YLOG2DEV (points[i].y + yoffset);
        }
        XDrawLines ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xpoints, n, 0);

        if (m_window && m_window->GetBackingPixmap())
        {
            for (i = 0; i < n; i++)
            {
                xpoints[i].x = (short)XLOG2DEV_2 (points[i].x + xoffset);
                xpoints[i].y = (short)YLOG2DEV_2 (points[i].y + yoffset);
            }
            XDrawLines ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking, xpoints, n, 0);
        }
        delete[]xpoints;
    }
}

void wxWindowDCImpl::DoDrawPolygon( int n, wxPoint points[],
                                wxCoord xoffset, wxCoord yoffset, wxPolygonFillMode fillStyle )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    XPoint *xpoints1 = new XPoint[n + 1];
    XPoint *xpoints2 = new XPoint[n + 1];
    int i;
    for (i = 0; i < n; i++)
    {
        xpoints1[i].x = (short)XLOG2DEV (points[i].x + xoffset);
        xpoints1[i].y = (short)YLOG2DEV (points[i].y + yoffset);
        xpoints2[i].x = (short)XLOG2DEV_2 (points[i].x + xoffset);
        xpoints2[i].y = (short)YLOG2DEV_2 (points[i].y + yoffset);
        CalcBoundingBox (points[i].x + xoffset, points[i].y + yoffset);
    }

    // Close figure for XDrawLines (not needed for XFillPolygon)
    xpoints1[i].x = xpoints1[0].x;
    xpoints1[i].y = xpoints1[0].y;
    xpoints2[i].x = xpoints2[0].x;
    xpoints2[i].y = xpoints2[0].y;

    if (m_brush.IsOk() && m_brush.GetStyle () != wxTRANSPARENT)
    {
        SetBrush (m_brush);
        XSetFillRule ((Display*) m_display, (GC) m_gc, fillStyle == wxODDEVEN_RULE ? EvenOddRule : WindingRule);
        XFillPolygon ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xpoints1, n, Complex, 0);
        XSetFillRule ((Display*) m_display, (GC) m_gc, EvenOddRule);    // default mode
        if (m_window && m_window->GetBackingPixmap())
        {
            XSetFillRule ((Display*) m_display,(GC) m_gcBacking,
                fillStyle == wxODDEVEN_RULE ? EvenOddRule : WindingRule);
            XFillPolygon ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking, xpoints2, n, Complex, 0);
            XSetFillRule ((Display*) m_display,(GC) m_gcBacking, EvenOddRule);    // default mode
        }
    }

    if (m_pen.IsOk() && m_pen.GetStyle () != wxTRANSPARENT)
    {
        if (m_autoSetting)
            SetPen (m_pen);
        XDrawLines ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xpoints1, n + 1, 0);

        if (m_window && m_window->GetBackingPixmap())
            XDrawLines ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking, xpoints2, n + 1, 0);
    }

    delete[]xpoints1;
    delete[]xpoints2;
}

void wxWindowDCImpl::DoDrawRectangle( wxCoord x, wxCoord y, wxCoord width, wxCoord height )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    int xd, yd, wfd, hfd, wd, hd;

    xd = XLOG2DEV(x);
    yd = YLOG2DEV(y);
    wfd = XLOG2DEVREL(width);
    wd = wfd - WX_GC_CF;
    hfd = YLOG2DEVREL(height);
    hd = hfd - WX_GC_CF;

    if (wfd == 0 || hfd == 0) return;
    if (wd < 0) { wd = - wd; xd = xd - wd; }
    if (hd < 0) { hd = - hd; yd = yd - hd; }

    if (m_brush.IsOk() && m_brush.GetStyle () != wxTRANSPARENT)
    {
        SetBrush (m_brush);
        XFillRectangle ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd, yd, wfd, hfd);

        if (m_window && m_window->GetBackingPixmap())
            XFillRectangle ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
            XLOG2DEV_2 (x), YLOG2DEV_2 (y),
            wfd, hfd);
    }

    if (m_pen.IsOk() && m_pen.GetStyle () != wxTRANSPARENT)
    {
        if (m_autoSetting)
            SetPen (m_pen);
        XDrawRectangle ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd, yd, wd, hd);

        if (m_window && m_window->GetBackingPixmap())
            XDrawRectangle ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
            XLOG2DEV_2 (x), YLOG2DEV_2 (y),
            wd, hd);
    }
    CalcBoundingBox (x, y);
    CalcBoundingBox (x + width, y + height);
}

void wxWindowDCImpl::DoDrawRoundedRectangle( wxCoord x, wxCoord y, wxCoord width, wxCoord height, double radius )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    // If radius is negative, it's a proportion of the smaller dimension.

    if (radius < 0.0) radius = - radius * ((width < height) ? width : height);

    int xd = XLOG2DEV (x);
    int yd = YLOG2DEV (y);
    int rd = XLOG2DEVREL ((long) radius);
    int wd = XLOG2DEVREL (width) - WX_GC_CF;
    int hd = YLOG2DEVREL (height) - WX_GC_CF;

    int rw_d = rd * 2;
    int rh_d = rw_d;

    // If radius is zero use DrawRectangle() instead to avoid
    // X drawing errors with small radii
    if (rd == 0)
    {
        DoDrawRectangle( x, y, width, height );
        return;
    }

    // Draw nothing if transformed w or h is 0
    if (wd == 0 || hd == 0) return;

    // CMB: adjust size if outline is drawn otherwise the result is
    // 1 pixel too wide and high
    if (m_pen.GetStyle() != wxTRANSPARENT)
    {
        wd--;
        hd--;
    }

    // CMB: ensure dd is not larger than rectangle otherwise we
    // get an hour glass shape
    if (rw_d > wd) rw_d = wd;
    if (rw_d > hd) rw_d = hd;
    rd = rw_d / 2;

    // For backing pixmap
    int xd2 = XLOG2DEV_2 (x);
    int yd2 = YLOG2DEV_2 (y);
    int rd2 = XLOG2DEVREL ((long) radius);
    int wd2 = XLOG2DEVREL (width) ;
    int hd2 = YLOG2DEVREL (height) ;

    int rw_d2 = rd2 * 2;
    int rh_d2 = rw_d2;

    if (m_brush.IsOk() && m_brush.GetStyle () != wxTRANSPARENT)
    {
        SetBrush (m_brush);

        XFillRectangle ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd + rd, yd,
            wd - rw_d, hd);
        XFillRectangle ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd, yd + rd,
            wd, hd - rh_d);

        // Arcs start from 3 o'clock, positive angles anticlockwise
        // Top-left
        XFillArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd, yd,
            rw_d, rh_d, 90 * 64, 90 * 64);
        // Top-right
        XFillArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd + wd - rw_d, yd,
            //        rw_d, rh_d, 0, 90 * 64);
            rw_d, rh_d, 0, 91 * 64);
        // Bottom-right
        XFillArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd + wd - rw_d,
            yd + hd - rh_d,
            //        rw_d, rh_d, 270 * 64, 90 * 64);
            rw_d, rh_d, 269 * 64, 92 * 64);
        // Bottom-left
        XFillArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd, yd + hd - rh_d,
            rw_d, rh_d, 180 * 64, 90 * 64);

        if (m_window && m_window->GetBackingPixmap())
        {
            XFillRectangle ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2 + rd2, yd2, wd2 - rw_d2, hd2);
            XFillRectangle ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2, yd2 + rd2, wd2, hd2 - rh_d2);

            XFillArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2, yd2, rw_d2, rh_d2, 90 * 64, 90 * 64);
            XFillArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2 + wd2 - rw_d2, yd2,
                //            rw_d2, rh_d2, 0, 90 * 64);
                rw_d2, rh_d2, 0, 91 * 64);
            XFillArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2 + wd2 - rw_d2,
                yd2 + hd2 - rh_d2,
                //            rw_d2, rh_d2, 270 * 64, 90 * 64);
                rw_d2, rh_d2, 269 * 64, 92 * 64);
            XFillArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2, yd2 + hd2 - rh_d2,
                rw_d2, rh_d2, 180 * 64, 90 * 64);
        }
    }

    if (m_pen.IsOk() && m_pen.GetStyle () != wxTRANSPARENT)
    {
        SetPen (m_pen);
        XDrawLine ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd + rd, yd,
            xd + wd - rd + 1, yd);
        XDrawLine ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd + rd, yd + hd,
            xd + wd - rd, yd + hd);

        XDrawLine ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd, yd + rd,
            xd, yd + hd - rd);
        XDrawLine ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd + wd, yd + rd,
            xd + wd, yd + hd - rd + 1);
        XDrawArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd, yd,
            rw_d, rh_d, 90 * 64, 90 * 64);
        XDrawArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd + wd - rw_d, yd,
            //        rw_d, rh_d, 0, 90 * 64);
            rw_d, rh_d, 0, 91 * 64);
        XDrawArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd + wd - rw_d,
            yd + hd - rh_d,
            rw_d, rh_d, 269 * 64, 92 * 64);
        XDrawArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd, yd + hd - rh_d,
            rw_d, rh_d, 180 * 64, 90 * 64);

        if (m_window && m_window->GetBackingPixmap())
        {
            XDrawLine ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2 + rd2, yd2,
                xd2 + wd2 - rd2 + 1, yd2);
            XDrawLine ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2 + rd2, yd2 + hd2,
                xd2 + wd2 - rd2, yd2 + hd2);

            XDrawLine ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2, yd2 + rd2,
                xd2, yd2 + hd2 - rd2);
            XDrawLine ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2 + wd2, yd2 + rd2,
                xd2 + wd2, yd2 + hd2 - rd2 + 1);
            XDrawArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2, yd2,
                rw_d2, rh_d2, 90 * 64, 90 * 64);
            XDrawArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2 + wd2 - rw_d2, yd2,
                //            rw_d2, rh_d2, 0, 90 * 64);
                rw_d2, rh_d2, 0, 91 * 64);
            XDrawArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2 + wd2 - rw_d2,
                yd2 + hd2 - rh_d2,
                rw_d2, rh_d2, 269 * 64, 92 * 64);
            XDrawArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                xd2, yd2 + hd2 - rh_d2,
                rw_d2, rh_d2, 180 * 64, 90 * 64);
        }
    }
    CalcBoundingBox (x, y);
    CalcBoundingBox (x + width, y + height);
}

void wxWindowDCImpl::DoDrawEllipse( wxCoord x, wxCoord y, wxCoord width, wxCoord height )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    // Check for negative width and height
    if (height < 0)
    {
        y = y + height;
        height = - height ;
    }

    if (width < 0)
    {
        x = x + width;
        width = - width ;
    }

    static const int angle = 23040;

    int xd, yd, wd, hd;

    xd = XLOG2DEV(x);
    yd = YLOG2DEV(y);
    wd = XLOG2DEVREL(width) ;
    hd = YLOG2DEVREL(height) ;

    if (m_brush.IsOk() && m_brush.GetStyle () != wxTRANSPARENT)
    {
        SetBrush (m_brush);
        XFillArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd, yd, wd, hd, 0, angle);
        if (m_window && m_window->GetBackingPixmap())
            XFillArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
            XLOG2DEV_2 (x), YLOG2DEV_2 (y),
            XLOG2DEVREL (width) - WX_GC_CF,
            YLOG2DEVREL (height) - WX_GC_CF, 0, angle);
    }

    if (m_pen.IsOk() && m_pen.GetStyle () != wxTRANSPARENT)
    {
        if (m_autoSetting)
            SetPen (m_pen);
        XDrawArc ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, xd, yd, wd, hd, 0, angle);
        if (m_window && m_window->GetBackingPixmap())
            XDrawArc ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
            XLOG2DEV_2 (x), YLOG2DEV_2 (y),
            XLOG2DEVREL (width) - WX_GC_CF,
            YLOG2DEVREL (height) - WX_GC_CF, 0, angle);
    }
    CalcBoundingBox (x, y);
    CalcBoundingBox (x + width, y + height);

}

bool wxWindowDCImpl::CanDrawBitmap() const
{
    wxCHECK_MSG( IsOk(), false, "invalid dc" );

    return true;
}

// TODO: use scaled Blit e.g. as per John Price's implementation
// in Contrib/Utilities
bool wxWindowDCImpl::DoBlit( wxCoord xdest, wxCoord ydest,
                         wxCoord width, wxCoord height,
                         wxDC *source, wxCoord xsrc, wxCoord ysrc,
                         wxRasterOperationMode rop, bool useMask,
                         wxCoord xsrcMask, wxCoord ysrcMask )
{
    wxCHECK_MSG( IsOk(), false, "invalid dc" );

    wxWindowDC const * sourceDC = wxDynamicCast(source, wxWindowDC);
    wxCHECK_MSG( sourceDC, false, "Blit source DC must be wxWindowDCImpl or derived class." );

    // cast is safe in virtue of the above wxCHECK_MSG()
    const wxWindowDCImpl * const
        srcImpl = static_cast<const wxWindowDCImpl *>(sourceDC->GetImpl());
    WXDisplay * const srcDpy = srcImpl->m_display;


    // Be sure that foreground pixels (1) of the Icon will be painted with
    // foreground colour. [m_textForegroundColour] Background pixels (0)
    // will be painted with backgound colour (m_textBackgroundColour)
    // Using ::SetPen is horribly slow, so avoid doing it
    WXPixel oldBackgroundPixel = -1;
    WXPixel oldForegroundPixel = -1;

    if (m_textBackgroundColour.IsOk())
    {
        oldBackgroundPixel = m_backgroundPixel;
        WXPixel pixel = m_textBackgroundColour.AllocColour(m_display);

        XSetBackground ((Display*) m_display, (GC) m_gc, pixel);
        if (m_window && m_window->GetBackingPixmap())
            XSetBackground ((Display*) m_display,(GC) m_gcBacking,
                            pixel);
    }
    if (m_textForegroundColour.IsOk())
    {
        oldForegroundPixel = m_currentColour.GetPixel();

        if( m_textForegroundColour.GetPixel() <= -1 )
            CalculatePixel( m_textForegroundColour,
                            m_textForegroundColour, true);

        WXPixel pixel = m_textForegroundColour.GetPixel();
        if (pixel > -1)
            SetForegroundPixelWithLogicalFunction(pixel);
    }

    // Do bitmap scaling if necessary

    wxBitmap *scaledBitmap = NULL;
    Pixmap sourcePixmap = (Pixmap) NULL;
    double scaleX, scaleY;
    GetUserScale(& scaleX, & scaleY);
    bool retVal = false;

    /* TODO: use the mask origin when drawing transparently */
    if (xsrcMask == -1 && ysrcMask == -1)
    {
        xsrcMask = xsrc; ysrcMask = ysrc;
    }

    // Sorry, can't scale masks just yet
    if (!useMask && (scaleX != 1.0 || scaleY != 1.0) && sourceDC->IsKindOf(CLASSINFO(wxMemoryDC)))
    {
        wxMemoryDC* memDC = (wxMemoryDC*) sourceDC;
        wxBitmap& bitmap = memDC->GetSelectedBitmap();

        wxASSERT_MSG( (bitmap.IsOk()), "Bad source bitmap in wxWindowDCImpl::Blit");

        wxImage image = bitmap.ConvertToImage();
        if (!image.IsOk())
        {
            sourcePixmap = (Pixmap) bitmap.GetDrawable();
        }
        else
        {
            int scaledW = (int) (bitmap.GetWidth() * scaleX);
            int scaledH = (int) (bitmap.GetHeight() * scaleY);

            image = image.Scale(scaledW, scaledH);
            scaledBitmap = new wxBitmap(image);
            sourcePixmap = (Pixmap) scaledBitmap->GetDrawable();
        }
    }
    else
    {
        sourcePixmap = (Pixmap) srcImpl->m_pixmap;
    }

    if (m_pixmap && sourcePixmap)
    {
        /* MATTHEW: [9] */
        wxRasterOperationMode orig = m_logicalFunction;

        SetLogicalFunction (rop);

        if (m_display != srcDpy)
        {
            XImage *cache = NULL;

            if (m_window && m_window->GetBackingPixmap())
                XCopyRemote((Display*) srcDpy, (Display*) m_display,
                (Pixmap) sourcePixmap, (Pixmap) m_window->GetBackingPixmap(),
                (GC) m_gcBacking,
                source->LogicalToDeviceX (xsrc),
                source->LogicalToDeviceY (ysrc),
                source->LogicalToDeviceXRel(width),
                source->LogicalToDeviceYRel(height),
                XLOG2DEV_2 (xdest), YLOG2DEV_2 (ydest),
                True, &cache);

            if ( useMask && source->IsKindOf(CLASSINFO(wxMemoryDC)) )
            {
                wxMemoryDC *memDC = (wxMemoryDC *)source;
                wxBitmap& sel = memDC->GetSelectedBitmap();
                if ( sel.IsOk() && sel.GetMask() && sel.GetMask()->GetBitmap() )
                {
                    XSetClipMask   ((Display*) m_display, (GC) m_gc, (Pixmap) sel.GetMask()->GetBitmap());
                    XSetClipOrigin ((Display*) m_display, (GC) m_gc, XLOG2DEV (xdest), YLOG2DEV (ydest));
                }
            }

            XCopyRemote((Display*) srcDpy, (Display*) m_display, (Pixmap) sourcePixmap, (Pixmap) m_pixmap, (GC) m_gc,
                source->LogicalToDeviceX (xsrc),
                source->LogicalToDeviceY (ysrc),
                source->LogicalToDeviceXRel(width),
                source->LogicalToDeviceYRel(height),
                XLOG2DEV (xdest), YLOG2DEV (ydest),
                False, &cache);

            if ( useMask )
            {
                if ( m_clipRegion )
                    XSetRegion ((Display*) m_display, (GC) m_gc,
                                (Region) m_clipRegion);
                else
                    XSetClipMask   ((Display*) m_display, (GC) m_gc, None);

                XSetClipOrigin ((Display*) m_display, (GC) m_gc, 0, 0);
            }

        } else
        {        //XGCValues values;
        //XGetGCValues((Display*)m_display, (GC)m_gc, GCForeground, &values);

            if (m_window && m_window->GetBackingPixmap())
            {
                // +++ MARKUS (mho@comnets.rwth-aachen): error on blitting bitmaps with depth 1
                if (source->IsKindOf(CLASSINFO(wxMemoryDC)) && ((wxMemoryDC*) source)->GetSelectedBitmap().GetDepth() == 1)
                {
                    XCopyPlane ((Display*) m_display, (Pixmap) sourcePixmap, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                        source->LogicalToDeviceX (xsrc),
                        source->LogicalToDeviceY (ysrc),
                        source->LogicalToDeviceXRel(width),
                        source->LogicalToDeviceYRel(height),
                        XLOG2DEV_2 (xdest), YLOG2DEV_2 (ydest), 1);
                }
                else
                {
                    XCopyArea ((Display*) m_display, (Pixmap) sourcePixmap, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                        source->LogicalToDeviceX (xsrc),
                        source->LogicalToDeviceY (ysrc),
                        source->LogicalToDeviceXRel(width),
                        source->LogicalToDeviceYRel(height),
                        XLOG2DEV_2 (xdest), YLOG2DEV_2 (ydest));
                }
            }
            if ( useMask && source->IsKindOf(CLASSINFO(wxMemoryDC)) )
            {
                wxMemoryDC *memDC = (wxMemoryDC *)source;
                wxBitmap& sel = memDC->GetSelectedBitmap();
                if ( sel.IsOk() && sel.GetMask() && sel.GetMask()->GetBitmap() )
                {
                    XSetClipMask   ((Display*) m_display, (GC) m_gc, (Pixmap) sel.GetMask()->GetBitmap());
                    XSetClipOrigin ((Display*) m_display, (GC) m_gc, XLOG2DEV (xdest), YLOG2DEV (ydest));
                }
            }

            // Check if we're copying from a mono bitmap
            if (source->IsKindOf(CLASSINFO(wxMemoryDC)) &&
                ((wxMemoryDC*)source)->GetSelectedBitmap().IsOk() &&
                (((wxMemoryDC*)source)->GetSelectedBitmap().GetDepth () == 1))
            {
                XCopyPlane ((Display*) m_display, (Pixmap) sourcePixmap, (Pixmap) m_pixmap, (GC) m_gc,
                    source->LogicalToDeviceX (xsrc),
                    source->LogicalToDeviceY (ysrc),
                    source->LogicalToDeviceXRel(width),
                    source->LogicalToDeviceYRel(height),
                    XLOG2DEV (xdest), YLOG2DEV (ydest), 1);
            }
            else
            {
                XCopyArea ((Display*) m_display, (Pixmap) sourcePixmap, (Pixmap) m_pixmap, (GC) m_gc,
                    source->LogicalToDeviceX (xsrc),
                    source->LogicalToDeviceY (ysrc),
                    source->LogicalToDeviceXRel(width),
                    source->LogicalToDeviceYRel(height),
                    XLOG2DEV (xdest), YLOG2DEV (ydest));

            }
            if ( useMask )
            {
                if ( m_clipRegion )
                    XSetRegion ((Display*) m_display, (GC) m_gc,
                                (Region) m_clipRegion);
                else
                    XSetClipMask   ((Display*) m_display, (GC) m_gc, None);

                XSetClipOrigin ((Display*) m_display, (GC) m_gc, 0, 0);
            }

        } /* Remote/local (Display*) m_display */
        CalcBoundingBox (xdest, ydest);
        CalcBoundingBox (xdest + width, ydest + height);

        SetLogicalFunction(orig);

        retVal = true;
  }
  if (scaledBitmap) delete scaledBitmap;

  if (oldBackgroundPixel > -1)
  {
      XSetBackground ((Display*) m_display, (GC) m_gc, oldBackgroundPixel);
      if (m_window && m_window->GetBackingPixmap())
          XSetBackground ((Display*) m_display,(GC) m_gcBacking,
                          oldBackgroundPixel);
  }
  if (oldForegroundPixel > -1)
  {
      XSetForeground ((Display*) m_display, (GC) m_gc, oldForegroundPixel);
      if (m_window && m_window->GetBackingPixmap())
          XSetForeground ((Display*) m_display,(GC) m_gcBacking,
                          oldForegroundPixel);
  }

  return retVal;
}

void wxWindowDCImpl::DoDrawText( const wxString &text, wxCoord x, wxCoord y )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    // Since X draws from the baseline of the text, must add the text height
    int cx = 0;
    int cy = 0;
    int ascent = 0;
    int slen = text.length();

    // Set FillStyle, otherwise X will use current stipple!
    XGCValues gcV, gcBackingV;

    XGetGCValues ((Display*) m_display, (GC)m_gc, GCFillStyle, &gcV);
    XSetFillStyle ((Display*) m_display, (GC) m_gc, FillSolid);
    if (m_window && m_window->GetBackingPixmap())
    {
        XGetGCValues ((Display*) m_display, (GC)m_gcBacking, GCFillStyle,
                      &gcBackingV );
        XSetFillStyle ((Display*) m_display, (GC) m_gcBacking, FillSolid);
    }

    if (m_font.IsOk())
        wxGetTextExtent (m_display, m_font, m_userScaleY * m_logicalScaleY,
                         text, &cx, &cy, &ascent, NULL);

    // First draw a rectangle representing the text background, if a text
    // background is specified
    if (m_textBackgroundColour.IsOk () && (m_backgroundMode != wxTRANSPARENT))
    {
        wxColour oldPenColour = m_currentColour;
        m_currentColour = m_textBackgroundColour;
        bool sameColour = (oldPenColour.IsOk () && m_textBackgroundColour.IsOk () &&
            (oldPenColour.Red () == m_textBackgroundColour.Red ()) &&
            (oldPenColour.Blue () == m_textBackgroundColour.Blue ()) &&
            (oldPenColour.Green () == m_textBackgroundColour.Green ()));

        // This separation of the big && test required for gcc2.7/HP UX 9.02
        // or pixel value can be corrupted!
        sameColour = (sameColour &&
            (oldPenColour.GetPixel() == m_textBackgroundColour.GetPixel()));

        if (!sameColour || !GET_OPTIMIZATION)
        {
            WXPixel pixel = m_textBackgroundColour.AllocColour(m_display);
            m_currentColour = m_textBackgroundColour;

            // Set the GC to the required colour
            if (pixel > -1)
            {
                XSetForeground ((Display*) m_display, (GC) m_gc, pixel);
                if (m_window && m_window->GetBackingPixmap())
                    XSetForeground ((Display*) m_display,(GC) m_gcBacking, pixel);
            }
        }
        else
            m_textBackgroundColour = oldPenColour ;

        XFillRectangle ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, XLOG2DEV (x), YLOG2DEV (y), cx, cy);
        if (m_window && m_window->GetBackingPixmap())
            XFillRectangle ((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
            XLOG2DEV_2 (x), YLOG2DEV_2 (y), cx, cy);
    }

    // Now set the text foreground and draw the text
    if (m_textForegroundColour.IsOk ())
    {
        wxColour oldPenColour = m_currentColour;
        m_currentColour = m_textForegroundColour;
        bool sameColour = (oldPenColour.IsOk () && m_currentColour.IsOk () &&
            (oldPenColour.Red () == m_currentColour.Red ()) &&
            (oldPenColour.Blue () == m_currentColour.Blue ()) &&
            (oldPenColour.Green () == m_currentColour.Green ()) &&
            (oldPenColour.GetPixel() == m_currentColour.GetPixel()));

        if (!sameColour || !GET_OPTIMIZATION)
        {
            WXPixel pixel = CalculatePixel(m_textForegroundColour,
                                           m_currentColour, false);

            // Set the GC to the required colour
            if (pixel > -1)
            {
                XSetForeground ((Display*) m_display, (GC) m_gc, pixel);
                if (m_window && m_window->GetBackingPixmap())
                    XSetForeground ((Display*) m_display,(GC) m_gcBacking, pixel);
            }
        }
        else
            m_textForegroundColour = oldPenColour;
    }

    // We need to add the ascent, not the whole height, since X draws at the
    // point above the descender.
#if 0
    if (use16)
        XDrawString16((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, XLOG2DEV (x), YLOG2DEV (y) + ascent,
        (XChar2b *)(char*) (const char*) text, slen);
    else
#endif // 0
#if wxMOTIF_NEW_FONT_HANDLING
        XFontSet fset = (XFontSet) m_font.GetFontSet (m_userScaleY * m_logicalScaleY, m_display);
        XmbDrawString((Display*) m_display, (Pixmap) m_pixmap, fset, (GC) m_gc, XLOG2DEV (x), YLOG2DEV (y) + ascent, text, slen);
#else
        XDrawString((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc, XLOG2DEV (x), YLOG2DEV (y) + ascent, text, slen);
#endif

    if (m_window && m_window->GetBackingPixmap()) {
#if 0
        if (use16)
            XDrawString16((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(), (GC) m_gcBacking,
            XLOG2DEV_2 (x), YLOG2DEV_2 (y) + ascent,
            (XChar2b *)(char*) (const char*) text, slen);
        else
#endif // 0
#if wxMOTIF_NEW_FONT_HANDLING
            XmbDrawString((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(), fset, (GC) m_gcBacking,
            XLOG2DEV_2 (x), YLOG2DEV_2 (y) + ascent,
                        text.mb_str(), slen);
#else
            XDrawString((Display*) m_display, (Pixmap) m_window->GetBackingPixmap(), (GC) m_gcBacking,
            XLOG2DEV_2 (x), YLOG2DEV_2 (y) + ascent,
                        text.mb_str(), slen);
#endif
    }

    // restore fill style
    XSetFillStyle ((Display*) m_display, (GC) m_gc, gcV.fill_style);
    if (m_window && m_window->GetBackingPixmap())
        XSetFillStyle ((Display*) m_display, (GC) m_gcBacking,
                       gcBackingV.fill_style);

    wxCoord w, h;
    DoGetTextExtent (text, &w, &h);
    CalcBoundingBox (x + w, y + h);
    CalcBoundingBox (x, y);
}

void wxWindowDCImpl::DoDrawRotatedText( const wxString &text, wxCoord x, wxCoord y,
                                    double angle )
{
    if (angle == 0.0)
    {
        DoDrawText(text, x, y);
        return;
    }

    wxCHECK_RET( IsOk(), "invalid dc" );

    WXPixel oldBackgroundPixel = -1;
    WXPixel oldForegroundPixel = -1;
    WXPixel foregroundPixel = -1;
    WXPixel backgroundPixel = -1;

    if (m_textBackgroundColour.IsOk())
    {
        oldBackgroundPixel = m_backgroundPixel;
        backgroundPixel = m_textBackgroundColour.AllocColour(m_display);
    }
    if (m_textForegroundColour.IsOk())
    {
        oldForegroundPixel = m_currentColour.GetPixel();

        if( m_textForegroundColour.GetPixel() <= -1 )
            CalculatePixel( m_textForegroundColour,
                            m_textForegroundColour, true);

        foregroundPixel = m_textForegroundColour.GetPixel();
    }

    // Since X draws from the baseline of the text, must add the text height
    int cx = 0;
    int cy = 0;
    int ascent = 0;

    if (m_font.IsOk())
        wxGetTextExtent (m_display, m_font, m_userScaleY * m_logicalScaleY,
                         text, &cx, &cy, &ascent, NULL);

    wxBitmap src(cx, cy);
    wxMemoryDC dc;
    dc.SelectObject(src);
    dc.SetFont(GetFont());
    dc.SetBackground(*wxWHITE_BRUSH);
    dc.SetBrush(*wxBLACK_BRUSH);
    dc.Clear();
    dc.DrawText(text, 0, 0);
    dc.SetFont(wxNullFont);

    // Calculate the size of the rotated bounding box.
    double dx = cos(angle / 180.0 * M_PI);
    double dy = sin(angle / 180.0 * M_PI);
    double x4 = cy * dy;
    double y4 = cy * dx;
    double x3 = cx * dx;
    double y3 = -cx * dy;
    double x2 = x3 + x4;
    double y2 = y3 + y4;
    double x1 = x;
    double y1 = y;

    // Create image from the source bitmap after writing the text into it.
    wxImage  image = src.ConvertToImage();

    int minx = roundmin(0, roundmin(x4, roundmin(x2, x3)));
    int miny = roundmin(0, roundmin(y4, roundmin(y2, y3)));
    int maxx = roundmax(0, roundmax(x4, roundmax(x2, x3)));
    int maxy = roundmax(0, roundmax(y4, roundmax(y2, y3)));

    bool lastFore = false, lastBack = false;

    // This rotates counterclockwise around the top left corner.
    for (int rx = minx; rx < maxx; rx++)
    {
        for (int ry = miny; ry < maxy; ry++)
        {
            // transform dest coords to source coords
            int sx = (int) (rx * dx - ry * dy + 0.5);
            int sy = - (int) (-ry * dx - rx * dy + 0.5);
            if (sx >= 0 && sx < cx && sy >= 0 && sy < cy)
            {
                bool textPixel = image.GetRed(sx, sy) == 0;

                if (!textPixel && m_backgroundMode != wxSOLID)
                    continue;

                wxCoord ox = (wxCoord) (x1 + rx),
                        oy = (wxCoord) (y1 + ry);
                // draw black pixels, ignore white ones (i.e. transparent b/g)
                if (textPixel && !lastFore)
                {
                    XSetForeground ((Display*) m_display, (GC) m_gc,
                                    foregroundPixel);
                    lastFore = true;
                    lastBack = false;
                }
                else if (!textPixel && !lastBack)
                {
                    XSetForeground ((Display*) m_display, (GC) m_gc,
                                    backgroundPixel);
                    lastFore = false;
                    lastBack = true;
                }

                XDrawPoint ((Display*) m_display, (Pixmap) m_pixmap,
                            (GC) m_gc, XLOG2DEV (ox), YLOG2DEV (oy));
                if (m_window && m_window->GetBackingPixmap())
                    XDrawPoint ((Display*) m_display,
                                (Pixmap) m_window->GetBackingPixmap(),
                                (GC) m_gcBacking,
                                XLOG2DEV_2 (ox), YLOG2DEV_2 (oy));
            }
        }
    }

    if (oldBackgroundPixel > -1)
    {
        XSetBackground ((Display*) m_display, (GC) m_gc, oldBackgroundPixel);
        if (m_window && m_window->GetBackingPixmap())
            XSetBackground ((Display*) m_display,(GC) m_gcBacking,
                            oldBackgroundPixel);
    }
    if (oldForegroundPixel > -1)
    {
        XSetForeground ((Display*) m_display, (GC) m_gc, oldForegroundPixel);
        if (m_window && m_window->GetBackingPixmap())
            XSetForeground ((Display*) m_display,(GC) m_gcBacking,
                            oldForegroundPixel);
    }

    CalcBoundingBox (minx, miny);
    CalcBoundingBox (maxx, maxy);
}

bool wxWindowDCImpl::CanGetTextExtent() const
{
    return true;
}

void wxWindowDCImpl::DoGetTextExtent( const wxString &string, wxCoord *width, wxCoord *height,
                                wxCoord *descent, wxCoord *externalLeading,
                                const wxFont *font ) const
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    const wxFont* theFont = font ? font : &m_font;

    if (!theFont->IsOk())
    {
        // TODO: this should be an error log function
        wxFAIL_MSG("set a valid font before calling GetTextExtent!");

        if (width) *width = -1;
        if (height) *height = -1;
        return;
    }

    wxGetTextExtent(m_display, *theFont, m_userScaleY * m_logicalScaleY,
                    string, width, height, NULL, descent);

    if (width) *width = XDEV2LOGREL (*width);
    if (height) *height = YDEV2LOGREL (*height);
    if (externalLeading)
        *externalLeading = 0;
}

wxCoord wxWindowDCImpl::GetCharWidth() const
{
    wxCHECK_MSG( IsOk(), 0, "invalid dc" );
    wxCHECK_MSG( m_font.IsOk(), 0, "invalid font" );

    int width;

    wxGetTextExtent (m_display, m_font, m_userScaleY * m_logicalScaleY,
                     "x", &width, NULL, NULL, NULL);

    return XDEV2LOGREL(width);
}

wxCoord wxWindowDCImpl::GetCharHeight() const
{
    wxCHECK_MSG( IsOk(), 0, "invalid dc" );
    wxCHECK_MSG( m_font.IsOk(), 0, "invalid font" );

    int height;

    wxGetTextExtent (m_display, m_font, m_userScaleY * m_logicalScaleY,
                     "x", NULL, &height, NULL, NULL);

    return XDEV2LOGREL(height);
}

void wxWindowDCImpl::DoGetSize( int *width, int *height ) const
{
    int w = 0, h = 0;

    if( m_window )
    {
        if( m_window->GetBackingPixmap() )
        {
            w = m_window->GetPixmapWidth();
            h = m_window->GetPixmapHeight();
        }
        else
            m_window->GetSize( &w, &h );
    }

    if( width ) *width = w;
    if( height ) *height = h;
}

void wxWindowDCImpl::Clear()
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    wxRect rect( GetSize() );
    Clear( rect );
}

void wxWindowDCImpl::Clear(const wxRect& rect)
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    int x = rect.x; int y = rect.y;
    int w = rect.width; int h = rect.height;

    wxBrush saveBrush = m_brush;
    SetBrush (m_backgroundBrush);

    XFillRectangle ((Display*) m_display, (Pixmap) m_pixmap, (GC) m_gc,
                    x, y, w, h);

    if (m_window && m_window->GetBackingPixmap())
        XFillRectangle ((Display*) m_display,
                        (Pixmap) m_window->GetBackingPixmap(),(GC) m_gcBacking,
                        x, y, w, h);

    m_brush = saveBrush;
}

void wxWindowDCImpl::SetFont( const wxFont &font )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    m_font = font;

    if (!m_font.IsOk())
    {
        return;
    }

#if !wxMOTIF_NEW_FONT_HANDLING
    WXFontStructPtr pFontStruct = m_font.GetFontStruct(m_userScaleY*m_logicalScaleY, m_display);

    Font fontId = ((XFontStruct*)pFontStruct)->fid;
    XSetFont ((Display*) m_display, (GC) m_gc, fontId);

    if (m_window && m_window->GetBackingPixmap())
        XSetFont ((Display*) m_display,(GC) m_gcBacking, fontId);
#endif
}

void wxWindowDCImpl::SetForegroundPixelWithLogicalFunction(WXPixel pixel)
{
    if (m_logicalFunction == wxXOR)
    {
        XGCValues values;
        XGetGCValues ((Display*) m_display, (GC) m_gc, GCBackground, &values);
        XSetForeground ((Display*) m_display, (GC) m_gc,
                        pixel ^ values.background);
        if (m_window && m_window->GetBackingPixmap())
            XSetForeground ((Display*) m_display,(GC) m_gcBacking,
                            pixel ^ values.background);
    }
    else
    {
        XSetForeground ((Display*) m_display, (GC) m_gc, pixel);
        if (m_window && m_window->GetBackingPixmap())
            XSetForeground ((Display*) m_display,(GC) m_gcBacking, pixel);
    }
}

WXPixel wxWindowDCImpl::CalculatePixel(wxColour& colour, wxColour& curCol,
                               bool roundToWhite) const
{
    const unsigned char wp = (unsigned char)255;

    WXPixel pixel = -1;
    if(!m_colour) // Mono display
    {
        unsigned char red = colour.Red ();
        unsigned char blue = colour.Blue ();
        unsigned char green = colour.Green ();
        // white
        if((red == wp && blue == wp && green == wp) ||
           // not black and roundToWhite was specified
           ((red != 0 || blue != 0 || green != 0) && roundToWhite))
        {
            curCol = *wxWHITE;
            pixel = WhitePixel((Display*) m_display,
                               DefaultScreen((Display*) m_display));
            curCol.SetPixel(pixel);
            colour.SetPixel(pixel);
        }
        else
        {
            curCol = *wxBLACK;
            pixel = BlackPixel((Display*) m_display,
                               DefaultScreen((Display*) m_display));
            curCol.SetPixel(pixel);
            colour.SetPixel(pixel);
        }
    }
    else
    {
        curCol = colour;
        pixel = colour.AllocColour((Display*) m_display);
        curCol.SetPixel(pixel);
    }

    return pixel;
}

void wxWindowDCImpl::SetPen( const wxPen &pen )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    m_pen = pen;
    if (!m_pen.IsOk())
        return;

    wxBitmap oldStipple = m_currentStipple;
    int oldStyle = m_currentStyle;
    int oldFill = m_currentFill;
    int old_pen_width = m_currentPenWidth;
    int old_pen_join = m_currentPenJoin;
    int old_pen_cap = m_currentPenCap;
    int old_pen_nb_dash = m_currentPenDashCount;
    wxX11Dash *old_pen_dash = m_currentPenDash;

    wxColour oldPenColour = m_currentColour;
    m_currentColour = m_pen.GetColour ();
    m_currentStyle = m_pen.GetStyle ();
    m_currentFill = m_pen.GetStyle (); // TODO?
    m_currentPenWidth = m_pen.GetWidth ();
    m_currentPenJoin = m_pen.GetJoin ();
    m_currentPenCap = m_pen.GetCap ();
    m_currentPenDashCount = m_pen.GetDashCount();
    m_currentPenDash = (wxX11Dash*)m_pen.GetDash();

    if (m_currentStyle == wxSTIPPLE)
        m_currentStipple = * m_pen.GetStipple ();

    bool sameStyle = (oldStyle == m_currentStyle &&
        oldFill == m_currentFill &&
        old_pen_join == m_currentPenJoin &&
        old_pen_cap == m_currentPenCap &&
        old_pen_nb_dash == m_currentPenDashCount &&
        old_pen_dash == m_currentPenDash &&
        old_pen_width == m_currentPenWidth);

    bool sameColour = (oldPenColour.IsOk () &&
        (oldPenColour.Red () == m_currentColour.Red ()) &&
        (oldPenColour.Blue () == m_currentColour.Blue ()) &&
        (oldPenColour.Green () == m_currentColour.Green ()) &&
        (oldPenColour.GetPixel() == m_currentColour.GetPixel()));

    if (!sameStyle || !GET_OPTIMIZATION)
    {
        int scaled_width = (int) XLOG2DEVREL (m_pen.GetWidth ());
        if (scaled_width < 0)
            scaled_width = 0;

        int style;
        int join;
        int cap;
        static const wxX11Dash dotted[] = {2, 5};
        static const wxX11Dash short_dashed[] = {4, 4};
        static const wxX11Dash long_dashed[] = {4, 8};
        static const wxX11Dash dotted_dashed[] = {6, 6, 2, 6};

        // We express dash pattern in pen width unit, so we are
        // independent of zoom factor and so on...
        int req_nb_dash;
        const wxX11Dash *req_dash;

        switch (m_pen.GetStyle ())
        {
        case wxUSER_DASH:
            req_nb_dash = m_currentPenDashCount;
            req_dash = m_currentPenDash;
            style = LineOnOffDash;
            break;
        case wxDOT:
            req_nb_dash = 2;
            req_dash = dotted;
            style = LineOnOffDash;
            break;
        case wxSHORT_DASH:
            req_nb_dash = 2;
            req_dash = short_dashed;
            style = LineOnOffDash;
            break;
        case wxLONG_DASH:
            req_nb_dash = 2;
            req_dash = long_dashed;
            style = LineOnOffDash;
            break;
        case wxDOT_DASH:
            req_nb_dash = 4;
            req_dash = dotted_dashed;
            style = LineOnOffDash;
            break;
        case wxSTIPPLE:
        case wxSOLID:
        case wxTRANSPARENT:
        default:
            style = LineSolid;
            req_dash = NULL;
            req_nb_dash = 0;
        }

        if (req_dash && req_nb_dash)
        {
            wxX11Dash *real_req_dash = new wxX11Dash[req_nb_dash];
            if (real_req_dash)
            {
                int factor = scaled_width == 0 ? 1 : scaled_width;
                for (int i = 0; i < req_nb_dash; i++)
                    real_req_dash[i] = (wxX11Dash)(req_dash[i] * factor);
                XSetDashes ((Display*) m_display, (GC) m_gc, 0, real_req_dash, req_nb_dash);

                if (m_window && m_window->GetBackingPixmap())
                    XSetDashes ((Display*) m_display,(GC) m_gcBacking, 0, real_req_dash, req_nb_dash);
                delete[]real_req_dash;
            }
            else
            {
                // No Memory. We use non-scaled dash pattern...
                XSetDashes ((Display*) m_display, (GC) m_gc, 0, req_dash, req_nb_dash);

                if (m_window && m_window->GetBackingPixmap())
                    XSetDashes ((Display*) m_display,(GC) m_gcBacking, 0, req_dash, req_nb_dash);
            }
        }

        switch (m_pen.GetCap ())
        {
        case wxCAP_PROJECTING:
            cap = CapProjecting;
            break;
        case wxCAP_BUTT:
            cap = CapButt;
            break;
        case wxCAP_ROUND:
        default:
            cap = (scaled_width <= 1) ? CapNotLast : CapRound;
            break;
        }

        switch (m_pen.GetJoin ())
        {
        case wxJOIN_BEVEL:
            join = JoinBevel;
            break;
        case wxJOIN_MITER:
            join = JoinMiter;
            break;
        case wxJOIN_ROUND:
        default:
            join = JoinRound;
            break;
        }

        XSetLineAttributes ((Display*) m_display, (GC) m_gc, scaled_width, style, cap, join);

        if (m_window && m_window->GetBackingPixmap())
            XSetLineAttributes ((Display*) m_display,(GC) m_gcBacking, scaled_width, style, cap, join);
    }

    if (IS_HATCH(m_currentFill) && ((m_currentFill != oldFill) || !GET_OPTIMIZATION))
    {
        Pixmap myStipple;

        oldStipple = wxNullBitmap;    // For later reset!!

        switch (m_currentFill)
        {
        case wxBDIAGONAL_HATCH:
            if (bdiag == (Pixmap) 0)
                bdiag = XCreateBitmapFromData ((Display*) m_display,
                RootWindow ((Display*) m_display, DefaultScreen ((Display*) m_display)),
                bdiag_bits, bdiag_width, bdiag_height);
            myStipple = bdiag;
            break;
        case wxFDIAGONAL_HATCH:
            if (fdiag == (Pixmap) 0)
                fdiag = XCreateBitmapFromData ((Display*) m_display,
                RootWindow ((Display*) m_display, DefaultScreen ((Display*) m_display)),
                fdiag_bits, fdiag_width, fdiag_height);
            myStipple = fdiag;
            break;
        case wxCROSS_HATCH:
            if (cross == (Pixmap) 0)
                cross = XCreateBitmapFromData ((Display*) m_display,
                RootWindow ((Display*) m_display, DefaultScreen ((Display*) m_display)),
                cross_bits, cross_width, cross_height);
            myStipple = cross;
            break;
        case wxHORIZONTAL_HATCH:
            if (horiz == (Pixmap) 0)
                horiz = XCreateBitmapFromData ((Display*) m_display,
                RootWindow ((Display*) m_display, DefaultScreen ((Display*) m_display)),
                horiz_bits, horiz_width, horiz_height);
            myStipple = horiz;
            break;
        case wxVERTICAL_HATCH:
            if (verti == (Pixmap) 0)
                verti = XCreateBitmapFromData ((Display*) m_display,
                RootWindow ((Display*) m_display, DefaultScreen ((Display*) m_display)),
                verti_bits, verti_width, verti_height);
            myStipple = verti;
            break;
        case wxCROSSDIAG_HATCH:
        default:
            if (cdiag == (Pixmap) 0)
                cdiag = XCreateBitmapFromData ((Display*) m_display,
                RootWindow ((Display*) m_display, DefaultScreen ((Display*) m_display)),
                cdiag_bits, cdiag_width, cdiag_height);
            myStipple = cdiag;
            break;
        }
        XSetStipple ((Display*) m_display, (GC) m_gc, myStipple);

        if (m_window && m_window->GetBackingPixmap())
            XSetStipple ((Display*) m_display,(GC) m_gcBacking, myStipple);
    }
    else if (m_currentStyle == wxSTIPPLE && m_currentStipple.IsOk()
        && ((!m_currentStipple.IsSameAs(oldStipple)) || !GET_OPTIMIZATION))
    {
        XSetStipple ((Display*) m_display, (GC) m_gc, (Pixmap) m_currentStipple.GetDrawable());

        if (m_window && m_window->GetBackingPixmap())
            XSetStipple ((Display*) m_display,(GC) m_gcBacking, (Pixmap) m_currentStipple.GetDrawable());
    }

    if ((m_currentFill != oldFill) || !GET_OPTIMIZATION)
    {
        int fill_style;

        if (m_currentFill == wxSTIPPLE)
            fill_style = FillStippled;
        else if (IS_HATCH (m_currentFill))
            fill_style = FillStippled;
        else
            fill_style = FillSolid;
        XSetFillStyle ((Display*) m_display, (GC) m_gc, fill_style);
        if (m_window && m_window->GetBackingPixmap())
            XSetFillStyle ((Display*) m_display,(GC) m_gcBacking, fill_style);
    }

    // must test m_logicalFunction, because it involves background!
    if (!sameColour || !GET_OPTIMIZATION
        || ((m_logicalFunction == wxXOR) || (m_autoSetting & 0x2)))
    {
        WXPixel pixel = -1;
        if (m_pen.GetStyle () == wxTRANSPARENT)
            pixel = m_backgroundPixel;
        else
        {
            wxColour penClr = m_pen.GetColour();
            pixel = CalculatePixel( penClr, m_currentColour, false);
            m_pen.SetColour(penClr);
        }

        // Finally, set the GC to the required colour
        if (pixel > -1)
            SetForegroundPixelWithLogicalFunction(pixel);
    }
    else
        m_pen.GetColour().SetPixel(oldPenColour.GetPixel());

    m_autoSetting = 0;
}

void wxWindowDCImpl::SetBrush( const wxBrush &brush )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    m_brush = brush;

    if (!m_brush.IsOk() || m_brush.GetStyle () == wxTRANSPARENT)
        return;

    int oldFill = m_currentFill;
    wxBitmap oldStipple = m_currentStipple;

    m_autoSetting |= 0x1;

    m_currentFill = m_brush.GetStyle ();
    if (m_currentFill == wxSTIPPLE)
        m_currentStipple = * m_brush.GetStipple ();

    wxColour oldBrushColour(m_currentColour);
    m_currentColour = m_brush.GetColour ();

    bool sameColour = (oldBrushColour.IsOk () &&
        (oldBrushColour.Red () == m_currentColour.Red ()) &&
        (oldBrushColour.Blue () == m_currentColour.Blue ()) &&
        (oldBrushColour.Green () == m_currentColour.Green ()) &&
        (oldBrushColour.GetPixel() == m_currentColour.GetPixel()));

    int stippleDepth = -1;

    if ((oldFill != m_brush.GetStyle ()) || !GET_OPTIMIZATION)
    {
        switch (brush.GetStyle ())
        {
        case wxTRANSPARENT:
            break;
        case wxSTIPPLE:
            stippleDepth = m_currentStipple.GetDepth();
            // fall through!
        case wxBDIAGONAL_HATCH:
        case wxCROSSDIAG_HATCH:
        case wxFDIAGONAL_HATCH:
        case wxCROSS_HATCH:
        case wxHORIZONTAL_HATCH:
        case wxVERTICAL_HATCH:
            {
                if (stippleDepth == -1) stippleDepth = 1;

                // Chris Breeze 23/07/97: use background mode to
                // determine whether fill style should be solid or
                // transparent
                int style = stippleDepth == 1 ?
                    (m_backgroundMode == wxSOLID ?
                     FillOpaqueStippled : FillStippled) :
                    FillTiled;
                XSetFillStyle ((Display*) m_display, (GC) m_gc, style);
                if (m_window && m_window->GetBackingPixmap())
                    XSetFillStyle ((Display*) m_display,(GC) m_gcBacking, style);
            }
            break;
        case wxSOLID:
        default:
            XSetFillStyle ((Display*) m_display, (GC) m_gc, FillSolid);
            if (m_window && m_window->GetBackingPixmap())
                XSetFillStyle ((Display*) m_display,(GC) m_gcBacking,
                               FillSolid);
        }
    }

    if (IS_HATCH(m_currentFill) && ((m_currentFill != oldFill) || !GET_OPTIMIZATION))
    {
        Pixmap myStipple;

        switch (m_currentFill)
        {
        case wxBDIAGONAL_HATCH:
            if (bdiag == (Pixmap) 0)
                bdiag = XCreateBitmapFromData ((Display*) m_display,
                RootWindow ((Display*) m_display, DefaultScreen ((Display*) m_display)),
                bdiag_bits, bdiag_width, bdiag_height);
            myStipple = bdiag;
            break;
        case wxFDIAGONAL_HATCH:
            if (fdiag == (Pixmap) 0)
                fdiag = XCreateBitmapFromData ((Display*) m_display,
                RootWindow ((Display*) m_display, DefaultScreen ((Display*) m_display)),
                fdiag_bits, fdiag_width, fdiag_height);
            myStipple = fdiag;
            break;
        case wxCROSS_HATCH:
            if (cross == (Pixmap) 0)
                cross = XCreateBitmapFromData ((Display*) m_display,
                RootWindow ((Display*) m_display, DefaultScreen ((Display*) m_display)),
                cross_bits, cross_width, cross_height);
            myStipple = cross;
            break;
        case wxHORIZONTAL_HATCH:
            if (horiz == (Pixmap) 0)
                horiz = XCreateBitmapFromData ((Display*) m_display,
                RootWindow ((Display*) m_display, DefaultScreen ((Display*) m_display)),
                horiz_bits, horiz_width, horiz_height);
            myStipple = horiz;
            break;
        case wxVERTICAL_HATCH:
            if (verti == (Pixmap) 0)
                verti = XCreateBitmapFromData ((Display*) m_display,
                RootWindow ((Display*) m_display, DefaultScreen ((Display*) m_display)),
                verti_bits, verti_width, verti_height);
            myStipple = verti;
            break;
        case wxCROSSDIAG_HATCH:
        default:
            if (cdiag == (Pixmap) 0)
                cdiag = XCreateBitmapFromData ((Display*) m_display,
                RootWindow ((Display*) m_display, DefaultScreen ((Display*) m_display)),
                cdiag_bits, cdiag_width, cdiag_height);
            myStipple = cdiag;
            break;
        }
        XSetStipple ((Display*) m_display, (GC) m_gc, myStipple);

        if (m_window && m_window->GetBackingPixmap())
            XSetStipple ((Display*) m_display,(GC) m_gcBacking, myStipple);
    }
    // X can forget the stipple value when resizing a window (apparently)
    // so always set the stipple.
    else if (m_currentFill != wxSOLID && m_currentFill != wxTRANSPARENT &&
             m_currentStipple.IsOk()) // && m_currentStipple != oldStipple)
    {
        if (m_currentStipple.GetDepth() == 1)
        {
            XSetStipple ((Display*) m_display, (GC) m_gc,
                         (Pixmap) m_currentStipple.GetDrawable());
        if (m_window && m_window->GetBackingPixmap())
                XSetStipple ((Display*) m_display,(GC) m_gcBacking,
                             (Pixmap) m_currentStipple.GetDrawable());
        }
        else
        {
            XSetTile ((Display*) m_display, (GC) m_gc,
                      (Pixmap) m_currentStipple.GetDrawable());
            if (m_window && m_window->GetBackingPixmap())
                XSetTile ((Display*) m_display,(GC) m_gcBacking,
                          (Pixmap) m_currentStipple.GetDrawable());
        }
    }

    // must test m_logicalFunction, because it involves background!
    if (!sameColour || !GET_OPTIMIZATION || m_logicalFunction == wxXOR)
    {
        wxColour brushClr = m_brush.GetColour();
        WXPixel pixel = CalculatePixel( brushClr, m_currentColour, true);
        m_brush.SetColour(brushClr);

        if (pixel > -1)
            SetForegroundPixelWithLogicalFunction(pixel);
    }
    else
        m_brush.GetColour().SetPixel(oldBrushColour.GetPixel());
}

void wxWindowDCImpl::SetBackground( const wxBrush &brush )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    m_backgroundBrush = brush;

    if (!m_backgroundBrush.IsOk())
        return;

    m_backgroundPixel = m_backgroundBrush.GetColour().AllocColour(m_display);

    // Necessary for ::DrawIcon, which use fg/bg pixel or the GC.
    // And Blit,... (Any fct that use XCopyPlane, in fact.)
    XSetBackground ((Display*) m_display, (GC) m_gc, m_backgroundPixel);
    if (m_window && m_window->GetBackingPixmap())
        XSetBackground ((Display*) m_display,(GC) m_gcBacking,
                        m_backgroundPixel);
}

void wxWindowDCImpl::SetLogicalFunction( wxRasterOperationMode function )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    int x_function;

    /* MATTHEW: [9] */
    if (m_logicalFunction == function)
        return;

    switch (function)
    {
    case wxCLEAR:
        x_function = GXclear;
        break;
    case wxXOR:
        x_function = GXxor;
        break;
    case wxINVERT:
        x_function = GXinvert;
        break;
    case wxOR_REVERSE:
        x_function = GXorReverse;
        break;
    case wxAND_REVERSE:
        x_function = GXandReverse;
        break;
    case wxAND:
        x_function = GXand;
        break;
    case wxOR:
        x_function = GXor;
        break;
    case wxAND_INVERT:
        x_function = GXandInverted;
        break;
    case wxNO_OP:
        x_function = GXnoop;
        break;
    case wxNOR:
        x_function = GXnor;
        break;
    case wxEQUIV:
        x_function = GXequiv;
        break;
    case wxSRC_INVERT:
        x_function = GXcopyInverted;
        break;
    case wxOR_INVERT:
        x_function = GXorInverted;
        break;
    case wxNAND:
        x_function = GXnand;
        break;
    case wxSET:
        x_function = GXset;
        break;
    case wxCOPY:
    default:
        x_function = GXcopy;
        break;
    }

    XSetFunction((Display*) m_display, (GC) m_gc, x_function);
    if (m_window && m_window->GetBackingPixmap())
        XSetFunction((Display*) m_display, (GC) m_gcBacking, x_function);

    if ((m_logicalFunction == wxXOR) != (function == wxXOR))
        /* MATTHEW: [9] Need to redo pen simply */
        m_autoSetting |= 0x2;

    m_logicalFunction = function;

}

void wxWindowDCImpl::SetTextForeground( const wxColour &col )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    m_textForegroundColour = col;
}

void wxWindowDCImpl::SetTextBackground( const wxColour &col )
{
    wxCHECK_RET( IsOk(), "invalid dc" );

    m_textBackgroundColour = col;
}

void wxWindowDCImpl::SetBackgroundMode( int mode )
{
    m_backgroundMode = mode;
}

void wxWindowDCImpl::SetPalette( const wxPalette& palette )
{
    if (m_window)
    {
        if (palette.IsOk())
            /* Use GetXColormap */
            XSetWindowColormap ((Display*) m_display, (Window) m_window->GetXWindow(),
            (Colormap) palette.GetXColormap());
        else
            /* Use wxGetMainColormap */
            XSetWindowColormap ((Display*) m_display, (Window) m_window->GetXWindow(),
            (Colormap) wxTheApp->GetMainColormap(m_display));
    }
}

static void wxCopyRegion( WXRegion src, WXRegion& dst )
{
    if( !dst )
        dst = XCreateRegion();
    XUnionRegion( (Region)src, (Region)src, (Region)dst );
}

// Helper function; userRegion is the region set by calling SetClippingRegion
void wxWindowDCImpl::SetDCClipping( WXRegion userRegion )
{
    bool hasUpdateRegion = m_window && m_window->GetUpdateRegion().IsOk();
    // this means that we should start the clip region from scratch,
    // or from the update region, if any
    if( !userRegion )
    {
        if( m_clipRegion )
            XDestroyRegion( (Region)m_clipRegion );
        m_clipRegion = (WXRegion)NULL;

        if( hasUpdateRegion )
            wxCopyRegion( m_window->GetUpdateRegion().GetX11Region(),
                          m_clipRegion );
    }
    // intersect the user region, if any, with the
    // exisiting clip region
    else // if( userRegion )
    {
        if( !m_clipRegion )
            wxCopyRegion( userRegion, m_clipRegion );
        else
            XIntersectRegion( (Region)m_clipRegion,
                              (Region)userRegion, (Region)m_clipRegion );
    }

    if( m_clipRegion )
        XSetRegion( (Display*)m_display, (GC)m_gc, (Region)m_clipRegion );
    else
        XSetClipMask( (Display*)m_display, (GC)m_gc, None );
}

void wxWindowDCImpl::DoSetClippingRegion( wxCoord x, wxCoord y,
                                      wxCoord width, wxCoord height )
{
    wxMotifDCImpl::DoSetClippingRegion( x, y, width, height );

    wxRegion temp(XLOG2DEV(x), YLOG2DEV(y),
                  XLOG2DEVREL(width), YLOG2DEVREL(height));

    SetDCClipping(temp.GetX11Region());

    // Needs to work differently for Pixmap: without this,
    // there's a nasty (Display*) m_display bug. 8/12/94
    if (m_window && m_window->GetBackingPixmap())
    {
        XRectangle rects[1];
        rects[0].x = (short)XLOG2DEV_2(x);
        rects[0].y = (short)YLOG2DEV_2(y);
        rects[0].width = (unsigned short)XLOG2DEVREL(width);
        rects[0].height = (unsigned short)YLOG2DEVREL(height);
        XSetClipRectangles((Display*) m_display, (GC) m_gcBacking,
                           0, 0, rects, 1, Unsorted);
    }
}

void wxWindowDCImpl::DoSetDeviceClippingRegion( const wxRegion& region )
{
    SetDCClipping(region.GetX11Region());

    // Needs to work differently for Pixmap: without this,
    // there's a nasty (Display*) m_display bug. 8/12/94
    if (m_window && m_window->GetBackingPixmap())
    {
        wxRect box = region.GetBox();

        XRectangle rects[1];
        rects[0].x = (short)box.x;
        rects[0].y = (short)box.y;
        rects[0].width = (unsigned short)box.width;
        rects[0].height = (unsigned short)box.height;
        XSetClipRectangles((Display*) m_display, (GC) m_gcBacking,
                           0, 0, rects, 1, Unsorted);
    }
}


void wxWindowDCImpl::DestroyClippingRegion()
{
    wxMotifDCImpl::DestroyClippingRegion();

    SetDCClipping(NULL);

    if (m_window && m_window->GetBackingPixmap())
        XSetClipMask ((Display*) m_display, (GC) m_gcBacking, None);
}

// Resolution in pixels per logical inch
wxSize wxWindowDCImpl::GetPPI() const
{
    // TODO
    return wxSize(100, 100);
}

int wxWindowDCImpl::GetDepth() const
{
    // TODO
    return 24;
}




// ----------------------------------------------------------------------------
// wxPaintDCImpl
// ----------------------------------------------------------------------------

wxPaintDCImpl::wxPaintDCImpl(wxDC *owner, wxWindow* win)
             : wxWindowDCImpl(owner, win)
{
    // Set the clipping region.to the update region
    SetDCClipping((WXRegion)NULL);
}

wxPaintDCImpl::~wxPaintDCImpl()
{
    if (m_window)
        m_window->ClearUpdateRegion();
    SetDCClipping((WXRegion)NULL);
}

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

/*
   Used when copying between drawables on different (Display*) m_displays. Not
   very fast, but better than giving up.
*/

static void XCopyRemote(Display *src_display, Display *dest_display,
                        Drawable src, Drawable dest,
                        GC destgc,
                        int srcx, int srcy,
                        unsigned int w, unsigned int h,
                        int destx, int desty,
                        bool more, XImage **cache)
{
    XImage *image, *destimage;
    Colormap destcm, srccm;
    static const int CACHE_SIZE = 256;

    unsigned int i, j;
    Pixel cachesrc[CACHE_SIZE], cachedest[CACHE_SIZE];
    int k, cache_pos, all_cache;

    if (!cache || !*cache)
        image = XGetImage(src_display, src, srcx, srcy, w, h, AllPlanes, ZPixmap);
    else
        image = *cache;

    destimage = XGetImage(dest_display, dest, destx, desty, w, h, AllPlanes, ZPixmap);

    srccm = (Colormap) wxTheApp->GetMainColormap((WXDisplay*) src_display);
    destcm = (Colormap) wxTheApp->GetMainColormap((WXDisplay*) dest_display);

    cache_pos = 0;
    all_cache = False;

    for (i = 0; i < w; i++)
        for (j = 0; j < h; j++) {
            Pixel pixel;
            XColor xcol;

            pixel = XGetPixel(image, i, j);
            for (k = cache_pos; k--; )
                if (cachesrc[k] == pixel) {
                    pixel = cachedest[k];
                    goto install;
                }
                if (all_cache)
                    for (k = CACHE_SIZE; k-- > cache_pos; )
                        if (cachesrc[k] == pixel) {
                            pixel = cachedest[k];
                            goto install;
                        }

                        cachesrc[cache_pos] = xcol.pixel = pixel;
                        XQueryColor(src_display, srccm, &xcol);
                        if (!XAllocColor(dest_display, destcm, &xcol))
                            xcol.pixel = 0;
                        cachedest[cache_pos] = pixel = xcol.pixel;

                        if (++cache_pos >= CACHE_SIZE) {
                            cache_pos = 0;
                            all_cache = true;
                        }

install:
                        XPutPixel(destimage, i, j, pixel);
        }

        XPutImage(dest_display, dest, destgc, destimage, 0, 0, destx, desty, w, h);
        XDestroyImage(destimage);

        if (more && cache)
            *cache = image;
        else
            XDestroyImage(image);
}

