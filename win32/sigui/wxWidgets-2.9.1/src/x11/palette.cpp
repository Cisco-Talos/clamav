/////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/palette.cpp
// Purpose:     wxPalette
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/*
 * Colour map
 *
 * When constructed with the default constructor, we start from
 * the wxApp::GetMainColormap, allocating additional read-only cells
 * in Create().  The cells are freed on the next call to Create()
 * or when the destructor is called.
 */

/* Wolfram Gloger <u7y22ab@sunmail.lrz-muenchen.de>
I have implemented basic colormap support for the X11 versions of
wxWidgets, notably wxPalette::Create().  The way I did it is to
allocate additional read-only color cells in the default colormap.  In
general you will get arbitrary pixel values assigned to these new
cells and therefore I added a method wxPalette::TransferBitmap()
which maps the pixel values 0..n to the real ones obtained with
Create().  This is only implemented for the popular case of 8-bit
depth.

Allocating read-write color cells would involve installing a private
X11 colormap for a particular window, and AFAIK this is not
recommended; only the window manager should do this...  Also, it is
not the functionality that wxPalette::Create() aims to provide.
 */

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/palette.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/utils.h"
    #include "wx/window.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif

#ifdef __VMS__
#pragma message enable nosimpint
#endif
#include "wx/x11/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxPalette, wxGDIObject)
IMPLEMENT_DYNAMIC_CLASS(wxXPalette, wxObject)

/*
* Palette
*
*/

wxXPalette::wxXPalette()
{
    m_cmap = (WXColormap) 0;
    m_pix_array_n = 0;
    m_pix_array = (unsigned long*) 0;
    m_display = (WXDisplay*) 0;
    m_destroyable = false;
}

wxPaletteRefData::wxPaletteRefData()
{
}

wxPaletteRefData::~wxPaletteRefData()
{
    Display *display = NULL;

    wxList::compatibility_iterator node, next;

    for (node = m_palettes.GetFirst(); node; node = next) {
        wxXPalette *c = (wxXPalette *)node->GetData();
        unsigned long *pix_array = c->m_pix_array;
        Colormap cmap = (Colormap) c->m_cmap;
        bool destroyable = c->m_destroyable;
        int pix_array_n = c->m_pix_array_n;
        display = (Display*) c->m_display;

        if (pix_array_n > 0)
        {
#if !wxUSE_NANOX
            //      XFreeColors(display, cmap, pix_array, pix_array_n, 0);
            // Be careful not to free '0' pixels...
            int i, j;
            for(i=j=0; i<pix_array_n; i=j) {
                while(j<pix_array_n && pix_array[j]!=0) j++;
                if(j > i) XFreeColors(display, cmap, &pix_array[i], j-i, 0);
                while(j<pix_array_n && pix_array[j]==0) j++;
            }
#endif
            delete [] pix_array;
        }

        if (destroyable)
            XFreeColormap(display, cmap);

        next = node->GetNext();
        m_palettes.Erase(node);
        delete c;
    }
}

wxPalette::wxPalette()
{
}

wxPalette::wxPalette(int n, const unsigned char *red, const unsigned char *green, const unsigned char *blue)
{
    Create(n, red, green, blue);
}

wxPalette::~wxPalette()
{
}

bool wxPalette::Create(int n, const unsigned char *red, const unsigned char *green, const unsigned char *blue)
{
    UnRef();

    if (!n) {
        return false;
    }

    m_refData = new wxPaletteRefData;

    XColor xcol;
    Display* display = (Display*) wxGetDisplay();

    unsigned long *pix_array;
    Colormap cmap;
    int pix_array_n;

    cmap = (Colormap) wxTheApp->GetMainColormap(display);

    pix_array = new unsigned long[n];
    if (!pix_array)
        return false;

    pix_array_n = n;
    xcol.flags = DoRed | DoGreen | DoBlue;
    for(int i = 0; i < n; i++) {
        xcol.red = (unsigned short)red[i] << 8;
        xcol.green = (unsigned short)green[i] << 8;
        xcol.blue = (unsigned short)blue[i] << 8;
        pix_array[i] = (XAllocColor(display, cmap, &xcol) == 0) ? 0 : xcol.pixel;
    }

    wxXPalette *c = new wxXPalette;

    c->m_pix_array_n = pix_array_n;
    c->m_pix_array = pix_array;
    c->m_cmap = (WXColormap) cmap;
    c->m_display = (WXDisplay*) display;
    c->m_destroyable = false;
    M_PALETTEDATA->m_palettes.Append(c);

    return true;
}

wxGDIRefData *wxPalette::CreateGDIRefData() const
{
    return new wxPaletteRefData;
}

wxGDIRefData *wxPalette::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxPaletteRefData(*static_cast<const wxPaletteRefData *>(data));
}

int wxPalette::GetPixel(unsigned char WXUNUSED(red),
                        unsigned char WXUNUSED(green),
                        unsigned char WXUNUSED(blue)) const
{
    if ( !m_refData )
        return wxNOT_FOUND;

    // TODO
    return wxNOT_FOUND;
}

bool wxPalette::GetRGB(int index, unsigned char *WXUNUSED(red), unsigned char *WXUNUSED(green), unsigned char *WXUNUSED(blue)) const
{
    if ( !m_refData )
        return false;

    if (index < 0 || index > 255)
        return false;

    // TODO
    return false;
}

WXColormap wxPalette::GetXColormap(WXDisplay* display) const
{
    if (!M_PALETTEDATA || (M_PALETTEDATA->m_palettes.GetCount() == 0))
        return wxTheApp->GetMainColormap(display);

    wxList::compatibility_iterator node = M_PALETTEDATA->m_palettes.GetFirst();
    if (!display && node)
    {
        wxXPalette* p = (wxXPalette*) node->GetData();
        return p->m_cmap;
    }
    while (node)
    {
        wxXPalette* p = (wxXPalette*) node->GetData();
        if (p->m_display == display)
            return p->m_cmap;

        node = node->GetNext();
    }

    /* Make a new one: */
    wxXPalette *c = new wxXPalette;
    wxXPalette *first = (wxXPalette *)M_PALETTEDATA->m_palettes.GetFirst()->GetData();
    XColor xcol;
    int pix_array_n = first->m_pix_array_n;

    c->m_pix_array_n = pix_array_n;
    c->m_pix_array = new unsigned long[pix_array_n];
    c->m_display = display;
    c->m_cmap = wxTheApp->GetMainColormap(display);
    c->m_destroyable = false;

    xcol.flags = DoRed | DoGreen | DoBlue;
    int i;
    for (i = 0; i < pix_array_n; i++)
    {
        xcol.pixel = first->m_pix_array[i];
        XQueryColor((Display*) first->m_display, (Colormap) first->m_cmap, &xcol);
        c->m_pix_array[i] =
            (XAllocColor((Display*) display, (Colormap) c->m_cmap, &xcol) == 0) ? 0 : xcol.pixel;
    }

    //    wxPalette* nonConstThis = (wxPalette*) this;

    M_PALETTEDATA->m_palettes.Append(c);

    return c->m_cmap;
}

bool wxPalette::TransferBitmap(void *data, int depth, int size)
{
    switch(depth) {
    case 8:
        {
            unsigned char *uptr = (unsigned char *)data;
            int pix_array_n;
            unsigned long *pix_array = GetXPixArray((Display*) wxGetDisplay(), &pix_array_n);
            while(size-- > 0)
            {
                if((int)*uptr < pix_array_n)
                    *uptr = (unsigned char)pix_array[*uptr];
                uptr++;
            }

            return true;
        }
    default:
        return false;
    }
}

bool wxPalette::TransferBitmap8(unsigned char *data, unsigned long sz,
                                void *dest, unsigned int bpp)
{
    int pix_array_n;
    unsigned long *pix_array = GetXPixArray((Display*) wxGetDisplay(), &pix_array_n);
    switch(bpp) {
    case 8: {
        unsigned char *dptr = (unsigned char *)dest;
        while(sz-- > 0) {
            if((int)*data < pix_array_n)
                *dptr = (unsigned char)pix_array[*data];
            data++;
            dptr++;
        }
        break;
            }
    case 16: {
        unsigned short *dptr = (unsigned short *)dest;
        while(sz-- > 0) {
            if((int)*data < pix_array_n)
                *dptr = (unsigned short)pix_array[*data];
            data++;
            dptr++;
        }
        break;
             }
    case 24: {
        struct rgb24 { unsigned char r, g, b; } *dptr = (struct rgb24 *)dest;
        while(sz-- > 0) {
            if((int)*data < pix_array_n) {
                dptr->r = pix_array[*data] & 0xFF;
                dptr->g = (pix_array[*data] >> 8) & 0xFF;
                dptr->b = (pix_array[*data] >> 16) & 0xFF;
            }
            data++;
            dptr++;
        }
        break;
             }
    case 32: {
        unsigned long *dptr = (unsigned long *)dest;
        while(sz-- > 0) {
            if((int)*data < pix_array_n)
                *dptr = pix_array[*data];
            data++;
            dptr++;
        }
        break;
             }
    default:
        return false;
    }
    return true;
}

unsigned long *wxPalette::GetXPixArray(WXDisplay *display, int *n)
{
    if (!M_PALETTEDATA)
        return (unsigned long*) 0;
    wxList::compatibility_iterator node;

    for (node = M_PALETTEDATA->m_palettes.GetFirst(); node; node = node->GetNext())
    {
        wxXPalette *c = (wxXPalette *)node->GetData();
        if (c->m_display == display)
        {
            if (n)
                *n = c->m_pix_array_n;
            return c->m_pix_array;
        }
    }

    /* Not found; call GetXColormap, which will create it, then this again */
    if (GetXColormap(display))
        return GetXPixArray(display, n);
    else
        return (unsigned long*) 0;
}

void wxPalette::PutXColormap(WXDisplay* display, WXColormap cm, bool dp)
{
    UnRef();

    m_refData = new wxPaletteRefData;

    wxXPalette *c = new wxXPalette;

    c->m_pix_array_n = 0;
    c->m_pix_array = (unsigned long*) NULL;
    c->m_display = display;
    c->m_cmap = cm;
    c->m_destroyable = dp;

    M_PALETTEDATA->m_palettes.Append(c);
}
