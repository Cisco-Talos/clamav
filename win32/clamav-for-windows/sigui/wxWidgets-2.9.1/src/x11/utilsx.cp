/////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/utilsx.cpp
// Purpose:     Private functions common to X11 and Motif ports
// Author:      Mattia Barbon
// Modified by:
// Created:     05/04/03
// RCS-ID:      $Id$
// Copyright:   (c) Mattia Barbon
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __VMS
#define XShapeQueryExtension XSHAPEQUERYEXTENSION
#endif

#include "wx/x11/privx.h"

#ifdef HAVE_XSHAPE

    #ifndef WX_PRECOMP
        #include "wx/bitmap.h"
        #include "wx/region.h"
    #endif

    #ifdef __VMS
        #include "wx/vms_x_fix.h"
        #include <X11/shape.h>
    #else
        #include <X11/extensions/shape.h>
    #endif

    #include "wx/dcmemory.h"
#endif

#ifdef HAVE_X11_XKBLIB_H
    /* under HP-UX and Solaris 2.6, at least, XKBlib.h defines structures with
     * field named "explicit" - which is, of course, an error for a C++
     * compiler. To be on the safe side, just redefine it everywhere. */
    #define explicit __wx_explicit

    #include "X11/XKBlib.h"

    #undef explicit
#endif // HAVE_X11_XKBLIB_H


// ----------------------------------------------------------------------------
// XShape code
// ----------------------------------------------------------------------------

#ifdef HAVE_XSHAPE

bool wxDoSetShape( Display* xdisplay,
                   Window xwindow,
                   const wxRegion& region )
{
    int dummy1, dummy2;

    if( !XShapeQueryExtension( xdisplay, &dummy1, &dummy2 ) )
        return false;

    if( region.IsEmpty() )
    {
        XShapeCombineMask( xdisplay, xwindow, ShapeBounding, 0, 0,
                           None, ShapeSet );
    }
    else
    {
        // wxRegion::ConvertToBitmap gives us the wrong Pixmap:
        // polychrome and with black and white reversed
        wxRect box = region.GetBox();
        wxBitmap bmp(box.GetRight(), box.GetBottom(), 1);
        wxMemoryDC dc;
        dc.SelectObject(bmp);
        dc.SetBackground(*wxBLACK_BRUSH);
        dc.Clear();
        dc.SetDeviceClippingRegion(region);
        dc.SetBackground(*wxWHITE_BRUSH);
        dc.Clear();
        dc.SelectObject(wxNullBitmap);

        XShapeCombineMask( xdisplay, xwindow, ShapeBounding, 0, 0,
                           (Pixmap)bmp.GetDrawable(), ShapeSet );
    }

    return true;
}

#else

bool wxDoSetShape( Display* WXUNUSED(xdisplay),
                   Window WXUNUSED(xwindow),
                   const wxRegion& WXUNUSED(region) )
{
    return false;
}

#endif

// ----------------------------------------------------------------------------
// wxXVisualInfo
// ----------------------------------------------------------------------------

#if !wxUSE_NANOX

bool wxFillXVisualInfo( wxXVisualInfo* vi, Display* dpy )
{
    int xscreen = DefaultScreen( dpy );
    Visual* vis = DefaultVisual( dpy, xscreen );
    int bpp = DefaultDepth( dpy, xscreen );

    XVisualInfo vinfo_template;
    XVisualInfo *vinfo;

    vinfo_template.visual = vis;
    vinfo_template.visualid = XVisualIDFromVisual( vis );
    vinfo_template.depth = bpp;
    int nitem = 0;

    vinfo = XGetVisualInfo( dpy, VisualIDMask|VisualDepthMask,
                            &vinfo_template, &nitem );

    wxCHECK_MSG( vinfo, false, wxT("no visual") );

    vi->Init( dpy, vinfo );

    XFree(vinfo);

    return true;
}

inline int ABS(int x) { return x < 0 ? -x : x; }

static void wxCalcPrecAndShift( unsigned long mask, int *shift, int *prec )
{
    *shift = 0;
    *prec = 0;

    while (!(mask & 0x1))
    {
        (*shift)++;
        mask >>= 1;
    }

    while (mask & 0x1)
    {
        (*prec)++;
        mask >>= 1;
    }
}

wxXVisualInfo::wxXVisualInfo()
{
    m_visualColormap = NULL;
    m_colorCube = NULL;
}

wxXVisualInfo::~wxXVisualInfo()
{
    if (m_colorCube)
        free( m_colorCube );

    if (m_visualColormap)
        delete [] (XColor*)m_visualColormap;
}

void wxXVisualInfo::Init( Display* dpy, XVisualInfo* vi )
{
    m_visualType = vi->visual->c_class;
    m_visualScreen = vi->screen;

    m_visualRedMask = vi->red_mask;
    m_visualGreenMask = vi->green_mask;
    m_visualBlueMask = vi->blue_mask;

    if (m_visualType != GrayScale && m_visualType != PseudoColor)
    {
        wxCalcPrecAndShift( m_visualRedMask, &m_visualRedShift,
                            &m_visualRedPrec );
        wxCalcPrecAndShift( m_visualGreenMask, &m_visualGreenShift,
                            &m_visualGreenPrec );
        wxCalcPrecAndShift( m_visualBlueMask, &m_visualBlueShift,
                            &m_visualBluePrec );
    }

    m_visualDepth = vi->depth;
    if (vi->depth == 16)
        vi->depth = m_visualRedPrec + m_visualGreenPrec + m_visualBluePrec;

    m_visualColormapSize = vi->colormap_size;

    if (m_visualDepth > 8)
        return;

    m_visualColormap = new XColor[m_visualColormapSize];
    XColor* colors = (XColor*) m_visualColormap;

    for (int i = 0; i < m_visualColormapSize; i++)
        colors[i].pixel = i;

    XQueryColors( dpy, DefaultColormap(dpy, vi->screen),
                  colors, m_visualColormapSize );

    m_colorCube = (unsigned char*)malloc(32 * 32 * 32);

    for (int r = 0; r < 32; r++)
    {
        for (int g = 0; g < 32; g++)
        {
            for (int b = 0; b < 32; b++)
            {
                int rr = (r << 3) | (r >> 2);
                int gg = (g << 3) | (g >> 2);
                int bb = (b << 3) | (b >> 2);

                int index = -1;

                if (colors)
                {
                    int max = 3 * 65536;

                    for (int i = 0; i < m_visualColormapSize; i++)
                    {
                        int rdiff = ((rr << 8) - colors[i].red);
                        int gdiff = ((gg << 8) - colors[i].green);
                        int bdiff = ((bb << 8) - colors[i].blue);
                        int sum = ABS (rdiff) + ABS (gdiff) + ABS (bdiff);
                        if (sum < max)
                        {
                            index = i; max = sum;
                        }
                    }
                }
                else
                {
                    // assume 8-bit true or static colors. this really exists
                    index = (r >> (5 - m_visualRedPrec)) << m_visualRedShift;
                    index |= (g >> (5 - m_visualGreenPrec)) << m_visualGreenShift;
                    index |= (b >> (5 - m_visualBluePrec)) << m_visualBlueShift;
                }
                m_colorCube[ (r*1024) + (g*32) + b ] = (unsigned char)index;
            }
        }
    }
}

#endif // !wxUSE_NANOX

/* Don't synthesize KeyUp events holding down a key and producing
   KeyDown events with autorepeat. */
bool wxSetDetectableAutoRepeat( bool flag )
{
#ifdef HAVE_X11_XKBLIB_H
    Bool result;
    XkbSetDetectableAutoRepeat( (Display *)wxGetDisplay(), flag, &result );
    return result;       /* true if keyboard hardware supports this mode */
#else
    wxUnusedVar(flag);
    return false;
#endif
}

