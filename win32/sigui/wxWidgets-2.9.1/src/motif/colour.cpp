/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/colour.cpp
// Purpose:     wxColour class
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

//// TODO: make wxColour a ref-counted object,
//// so pixel values get shared.

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/colour.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/gdicmn.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxColour, wxObject)

wxCOMPILE_TIME_ASSERT( sizeof(WXPixel) == sizeof(Pixel), PixelSizeIsOk );

// Colour

void wxColour::Init()
{
    m_isInit = false;
    m_red = m_blue = m_green = 0;
    m_pixel = -1;
}

wxColour::wxColour(const wxColour& col)
{
    *this = col;
}

wxColour& wxColour::operator =(const wxColour& col)
{
    m_red = col.m_red;
    m_green = col.m_green;
    m_blue = col.m_blue;
    m_isInit = col.m_isInit;
    m_pixel = col.m_pixel;
    return *this;
}

wxColour::~wxColour()
{
}

void wxColour::InitRGBA(unsigned char r, unsigned char g, unsigned char b,
                        unsigned char WXUNUSED(a))
{
    m_red = r;
    m_green = g;
    m_blue = b;
    m_isInit = true;
    m_pixel = -1;
}

// Allocate a colour, or nearest colour, using the given display.
// If realloc is true, ignore the existing pixel, otherwise just return
// the existing one.
// Returns the old or allocated pixel.

// TODO: can this handle mono displays? If not, we should have an extra
// flag to specify whether this should be black or white by default.

WXPixel wxColour::AllocColour(WXDisplay* display, bool realloc)
{
    if ((m_pixel != -1) && !realloc)
        return m_pixel;

    XColor color;
    color.red = (unsigned short) Red ();
    color.red |= (unsigned short)(color.red << 8);
    color.green = (unsigned short) Green ();
    color.green |= (unsigned short)(color.green << 8);
    color.blue = (unsigned short) Blue ();
    color.blue |= (unsigned short)(color.blue << 8);

    color.flags = DoRed | DoGreen | DoBlue;

    WXColormap cmap = wxTheApp->GetMainColormap(display);

    if (!XAllocColor ((Display*) display, (Colormap) cmap, &color))
    {
        m_pixel = wxGetBestMatchingPixel((Display*) display, &color,(Colormap) cmap);
        return m_pixel;
    }
    else
    {
        m_pixel = (WXPixel) color.pixel;
        return m_pixel;
    }
}

/*-------------------------------------------
Markus Emmenegger <mege@iqe.ethz.ch>
Find the pixel value with an assigned color closest to the desired color
Used if color cell allocation fails
As the returned pixel value may be in use by another application,
the color might change anytime.
But in many cases, that is still better than always using black.
--
Chris Breeze <chris@hel.co.uk>
Improvements:
1) More efficient calculation of RGB distance of colour cell from
the desired colour. There is no need to take the sqrt of 'dist', and
since we are only interested in the top 8-bits of R, G and B we
can perform integer arithmetic.
2) Attempt to allocate a read-only colour when a close match is found.
A read-only colour will not change.
3) Fall back to the closest match if no read-only colours are available.

  Possible further improvements:
  1) Scan the lookup table and sort the colour cells in order of
  increasing
  distance from the desired colour. Then attempt to allocate a
  read-only
  colour starting from the nearest match.
  2) Linear RGB distance is not a particularly good method of colour
  matching
  (though it is quick). Converting the colour to HLS and then comparing
  may give better matching.
-------------------------------------------*/

WXPixel wxGetBestMatchingPixel(Display *display, XColor *desiredColor, Colormap cmap)
{
    if (cmap == (Colormap) NULL)
        cmap = (Colormap) wxTheApp->GetMainColormap(display);

    int numPixVals = XDisplayCells(display, DefaultScreen (display));
    int mindist = 256 * 256 * 3;
    Pixel bestpixel = BlackPixel (display, DefaultScreen (display));
    int red = desiredColor->red >> 8;
    int green = desiredColor->green >> 8;
    int blue = desiredColor->blue >> 8;
    const int threshold = 2 * 2 * 3;    // allow an error of up to 2 in R,G & B

    for (int pixelcount = 0; pixelcount < numPixVals; pixelcount++)
    {
        XColor matching_color;
        matching_color.pixel = pixelcount;
        XQueryColor(display,cmap,&matching_color);

        int delta_red = red - (matching_color.red >> 8);
        int delta_green = green - (matching_color.green >> 8);
        int delta_blue = blue - (matching_color.blue >> 8);

        int dist = delta_red * delta_red +
            delta_green * delta_green +
            delta_blue * delta_blue;

        if (dist <= threshold)
        {
            // try to allocate a read-only colour...
            if (XAllocColor (display, cmap, &matching_color))
            {
                return matching_color.pixel;
            }
        }
        if (dist < mindist)
        {
            bestpixel = pixelcount;
            mindist = dist;
        }
    }
    return bestpixel;
}
