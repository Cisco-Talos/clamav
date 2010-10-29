/////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/bitmap.cpp
// Purpose:     wxBitmap
// Author:      Julian Smart, Robert Roebling
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart, Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/bitmap.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/dcmemory.h"
    #include "wx/icon.h"
    #include "wx/math.h"
    #include "wx/image.h"
#endif

#include "wx/x11/private.h"

/* No point in using libXPM for NanoX */
#if wxUSE_NANOX
#undef wxHAVE_LIB_XPM
#define wxHAVE_LIB_XPM 0

// Copy from the drawable to the wxImage
bool wxGetImageFromDrawable(GR_DRAW_ID drawable, int srcX, int srcY, int width, int height, wxImage& image);
#endif

#if wxUSE_XPM
#if wxHAVE_LIB_XPM
#include <X11/xpm.h>
#else
#include "wx/xpmdecod.h"
#include "wx/wfstream.h"
#endif
#endif

//-----------------------------------------------------------------------------
// wxMask
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxMask,wxObject)

wxMask::wxMask()
{
    m_bitmap = NULL;
    m_display = NULL;
}

wxMask::wxMask( const wxBitmap& bitmap, const wxColour& colour )
{
    m_bitmap = NULL;
    Create( bitmap, colour );
}

wxMask::wxMask( const wxBitmap& bitmap, int paletteIndex )
{
    m_bitmap = NULL;
    Create( bitmap, paletteIndex );
}

wxMask::wxMask( const wxBitmap& bitmap )
{
    m_bitmap = NULL;
    Create( bitmap );
}

wxMask::~wxMask()
{
    if (m_bitmap)
        XFreePixmap( (Display*) m_display, (Pixmap) m_bitmap );
}

bool wxMask::Create( const wxBitmap& bitmap,
                     const wxColour& colour )
{
#if !wxUSE_NANOX
    if (m_bitmap)
    {
        XFreePixmap( (Display*) m_display, (Pixmap) m_bitmap );
        m_bitmap = NULL;
    }

    m_display = bitmap.GetDisplay();

    wxImage image = bitmap.ConvertToImage();
    if (!image.Ok()) return false;

    m_display = bitmap.GetDisplay();

    Display *xdisplay = (Display*) m_display;
    int xscreen = DefaultScreen( xdisplay );
    Window xroot = RootWindow( xdisplay, xscreen );

    m_bitmap = (WXPixmap) XCreatePixmap( xdisplay, xroot, image.GetWidth(), image.GetHeight(), 1 );
    GC gc = XCreateGC( xdisplay, (Pixmap) m_bitmap, 0, NULL );

    XSetForeground( xdisplay, gc, WhitePixel(xdisplay,xscreen) );
    XSetFillStyle( xdisplay, gc, FillSolid );
    XFillRectangle( xdisplay, (Pixmap) m_bitmap, gc, 0, 0, image.GetWidth(), image.GetHeight() );

    unsigned char *data = image.GetData();
    int index = 0;

    unsigned char red = colour.Red();
    unsigned char green = colour.Green();
    unsigned char blue = colour.Blue();

    int bpp = wxTheApp->GetVisualInfo(m_display)->m_visualDepth;

    if (bpp == 15)
    {
        red &= 0xf8;
        green &= 0xf8;
        blue &= 0xf8;
    } else
    if (bpp == 16)
    {
        red &= 0xf8;
        green &= 0xfc;
        blue &= 0xf8;
    } else
    if (bpp == 12)
    {
        red &= 0xf0;
        green &= 0xf0;
        blue &= 0xf0;
    }

    XSetForeground( xdisplay, gc, BlackPixel(xdisplay,xscreen) );

    int width = image.GetWidth();
    int height = image.GetHeight();
    for (int j = 0; j < height; j++)
    {
        int start_x = -1;
        int i;
        for (i = 0; i < width; i++)
        {
            if ((data[index] == red) &&
                (data[index+1] == green) &&
                (data[index+2] == blue))
            {
                if (start_x == -1)
                start_x = i;
            }
            else
            {
                if (start_x != -1)
                {
                    XDrawLine( xdisplay, (Pixmap) m_bitmap, gc, start_x, j, i-1, j );
                    start_x = -1;
                }
            }
            index += 3;
        }
        if (start_x != -1)
            XDrawLine( xdisplay, (Pixmap) m_bitmap, gc, start_x, j, i, j );
    }

    XFreeGC( xdisplay, gc );

    return true;
#else
    return false;
#endif
    // wxUSE_NANOX
}

bool wxMask::Create( const wxBitmap& bitmap, int paletteIndex )
{
    unsigned char r,g,b;
    wxPalette *pal = bitmap.GetPalette();

    wxCHECK_MSG( pal, false, wxT("Cannot create mask from bitmap without palette") );

    pal->GetRGB(paletteIndex, &r, &g, &b);

    return Create(bitmap, wxColour(r, g, b));
}

bool wxMask::Create( const wxBitmap& bitmap )
{
#if !wxUSE_NANOX
    if (m_bitmap)
    {
        XFreePixmap( (Display*) m_display, (Pixmap) m_bitmap );
        m_bitmap = NULL;
    }

    if (!bitmap.Ok()) return false;

    wxCHECK_MSG( bitmap.GetBitmap(), false, wxT("Cannot create mask from colour bitmap") );

    m_display = bitmap.GetDisplay();

    int xscreen = DefaultScreen( (Display*) m_display );
    Window xroot = RootWindow( (Display*) m_display, xscreen );

    m_bitmap = (WXPixmap) XCreatePixmap( (Display*) m_display, xroot, bitmap.GetWidth(), bitmap.GetHeight(), 1 );

    if (!m_bitmap) return false;

    GC gc = XCreateGC( (Display*) m_display, (Pixmap) m_bitmap, 0, NULL );

    XCopyPlane( (Display*) m_display, (Pixmap) bitmap.GetBitmap(), (Pixmap) m_bitmap,
       gc, 0, 0, bitmap.GetWidth(), bitmap.GetHeight(), 0, 0, 1 );

    XFreeGC( (Display*) m_display, gc );

    return true;
#else
    return false;
#endif
    // wxUSE_NANOX
}

//-----------------------------------------------------------------------------
// wxBitmapRefData
//-----------------------------------------------------------------------------

class wxBitmapRefData : public wxGDIRefData
{
public:
    wxBitmapRefData();
    wxBitmapRefData(const wxBitmapRefData& data);
    virtual ~wxBitmapRefData();

    // shouldn't be called more than once as it doesn't free the existing data
    bool Create(int width, int height, int depth);

    virtual bool IsOk() const { return m_pixmap || m_bitmap; }

    Pixmap          m_pixmap;
    Pixmap          m_bitmap;
    Display        *m_display;
    wxMask         *m_mask;
    int             m_width;
    int             m_height;
    int             m_bpp;
    wxPalette      *m_palette;
};

wxBitmapRefData::wxBitmapRefData()
{
    m_pixmap = 0;
    m_bitmap = 0;
    m_display = NULL;
    m_mask = NULL;
    m_width = 0;
    m_height = 0;
    m_bpp = 0;
    m_palette = NULL;
}

wxBitmapRefData::wxBitmapRefData(const wxBitmapRefData& data)
{
    m_pixmap = 0;
    m_bitmap = 0;
    m_display = data.m_display;
    m_mask = NULL; // FIXME: should copy
    m_palette = NULL; // FIXME: should copy

    Create(data.m_width, data.m_height, data.m_bpp);
}

bool wxBitmapRefData::Create(int width, int height, int depth)
{
    m_width = width;
    m_height = height;
    m_bpp = depth;

    m_display = wxGlobalDisplay();

    wxCHECK_MSG( m_display, false, wxT("No display") );

    int xscreen = DefaultScreen(m_display);
    int bpp = DefaultDepth(m_display, xscreen);
    if ( depth == -1 )
        depth = bpp;

    wxCHECK_MSG( (depth == bpp) || (depth == 1), false,
                 wxT("invalid bitmap depth") );

#if wxUSE_NANOX
    m_pixmap = (WXPixmap) GrNewPixmap(width, height, NULL);
#else // !wxUSE_NANOX
    Window xroot = RootWindow(m_display, xscreen);

    *(depth == 1 ? &m_bitmap : &m_pixmap) =
        XCreatePixmap(m_display, xroot, width, height, depth);
#endif // wxUSE_NANOX/!wxUSE_NANOX

    wxCHECK_MSG( m_pixmap || m_bitmap, false, wxT("Bitmap creation failed") );

    return true;
}

wxBitmapRefData::~wxBitmapRefData()
{
    if (m_pixmap)
       XFreePixmap(m_display, m_pixmap);
    if (m_bitmap)
       XFreePixmap(m_display, m_bitmap);
    delete m_mask;
    delete m_palette;
}

//-----------------------------------------------------------------------------

// helper function

static WXPixmap wxGetSubPixmap( WXDisplay* xdisplay, WXPixmap xpixmap,
                                int x, int y, int width, int height,
                                int depth )
{
    Display * const dpy = (Display *)xdisplay;

    int xscreen = DefaultScreen( dpy );
    Window xroot = RootWindow( dpy, xscreen );
    Visual* xvisual = DefaultVisual( dpy, xscreen );

    XImage* ximage = XCreateImage( dpy, xvisual, depth,
                                   ZPixmap, 0, 0, width, height, 32, 0 );
    ximage->data = (char*)malloc( ximage->bytes_per_line * ximage->height );
    ximage = XGetSubImage( dpy, (Pixmap)xpixmap,
                           x, y, width, height,
                           AllPlanes, ZPixmap, ximage, 0, 0 );

    GC gc = XCreateGC( dpy, (Pixmap)xpixmap, 0, NULL );
    Pixmap ret = XCreatePixmap( dpy, xroot,
                                width, height, depth );

    XPutImage( dpy, ret, gc, ximage,
               0, 0, 0, 0, width, height );
    XDestroyImage( ximage );
    XFreeGC( dpy, gc );

    return (WXPixmap)ret;
}


//-----------------------------------------------------------------------------
// wxBitmap
//-----------------------------------------------------------------------------

#define M_BMPDATA ((wxBitmapRefData *)m_refData)

IMPLEMENT_DYNAMIC_CLASS(wxBitmap,wxGDIObject)

bool wxBitmap::Create( int width, int height, int depth )
{
    UnRef();

    wxCHECK_MSG( (width > 0) && (height > 0), false, wxT("invalid bitmap size") );

    m_refData = new wxBitmapRefData();

    return M_BMPDATA->Create(width, height, depth);
}

bool wxBitmap::Create(const void* data, wxBitmapType type,
                      int width, int height, int depth)
{
    UnRef();

    wxBitmapHandler *handler = FindHandler(type);

    if ( handler == NULL ) {
        wxLogWarning(wxT("no data bitmap handler for type %ld defined."),
                     (long)type);

        return false;
    }

    return handler->Create(this, data, type, width, height, depth);
}

bool wxBitmap::Create(WXPixmap pixmap)
{
    UnRef();
    Pixmap xpixmap = (Pixmap)pixmap;
    Display* xdisplay = wxGlobalDisplay();
    int xscreen = DefaultScreen( xdisplay );
    Window xroot = RootWindow( xdisplay, xscreen );

    // make a copy of the Pixmap
    Window root;
    int x, y;
    unsigned width, height, border, depth;

    XGetGeometry( xdisplay, (Drawable)xpixmap, &root, &x, &y,
                  &width, &height, &border, &depth );
    Pixmap copy = XCreatePixmap( xdisplay, xroot, width, height, depth );

    GC gc = XCreateGC( xdisplay, copy, 0, NULL );
    XCopyArea( xdisplay, xpixmap, copy, gc, 0, 0, width, height, 0, 0 );
    XFreeGC( xdisplay, gc );

    // fill in ref data
    wxBitmapRefData* ref = new wxBitmapRefData();

    if( depth == 1 )
        ref->m_bitmap = copy;
    else
        ref->m_pixmap = copy;

    ref->m_display = xdisplay;
    ref->m_width = width;
    ref->m_height = height;
    ref->m_bpp = depth;

    m_refData = ref;

    return true;
}

wxBitmap::wxBitmap(const char* const* bits)
{
    Create(bits, wxBITMAP_TYPE_XPM_DATA, 0, 0, 0);
}

wxGDIRefData *wxBitmap::CreateGDIRefData() const
{
    return new wxBitmapRefData;
}

wxGDIRefData *wxBitmap::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxBitmapRefData(*static_cast<const wxBitmapRefData *>(data));
}

bool wxBitmap::CreateFromImage( const wxImage& image, int depth )
{
#if wxUSE_NANOX
    if (!image.Ok())
    {
        wxASSERT_MSG(image.Ok(), wxT("Invalid wxImage passed to wxBitmap::CreateFromImage."));
        return false;
    }

    int w = image.GetWidth();
    int h = image.GetHeight();

    if (!Create(w, h, depth))
        return false;

    // Unfortunately the mask has to be screen-depth since
    // 1-bpp bitmaps don't seem to be supported
    // TODO: implement transparent drawing, presumably
    // by doing several blits as per the Windows
    // implementation because Nano-X doesn't support
    // XSetClipMask.
    // TODO: could perhaps speed this function up
    // by making a buffer of pixel values,
    // and then calling GrArea to write that to the
    // pixmap. See demos/nxroach.c.

    bool hasMask = image.HasMask();

    GC pixmapGC = GrNewGC();
    Pixmap pixmap = (Pixmap) GetPixmap();

    GC maskGC = 0;
    Pixmap maskPixmap = 0;

    unsigned char maskR = 0;
    unsigned char maskG = 0;
    unsigned char maskB = 0;

    if (hasMask)
    {
        maskR = image.GetMaskRed();
        maskG = image.GetMaskGreen();
        maskB = image.GetMaskBlue();

        maskGC = GrNewGC();
        maskPixmap = GrNewPixmap(w, h, 0);
        if (!maskPixmap)
            hasMask = false;
        else
        {
            wxMask* mask = new wxMask;
            mask->SetBitmap((WXPixmap) maskPixmap);
            SetMask(mask);
        }
    }

    GR_COLOR lastPixmapColour = 0;
    GR_COLOR lastMaskColour = 0;

    int i, j;
    for (i = 0; i < w; i++)
    {
        for (j = 0; j < h; j++)
        {
            unsigned char red = image.GetRed(i, j);
            unsigned char green = image.GetGreen(i, j);
            unsigned char blue = image.GetBlue(i, j);

            GR_COLOR colour = GR_RGB(red, green, blue);

            // Efficiency measure
            if (colour != lastPixmapColour || (i == 0 && j == 0))
            {
                GrSetGCForeground(pixmapGC, colour);
                lastPixmapColour = colour;
            }

            GrPoint(pixmap, pixmapGC, i, j);

            if (hasMask)
            {
                // scan the bitmap for the transparent colour and set the corresponding
                // pixels in the mask to BLACK and the rest to WHITE
                if (maskR == red && maskG == green && maskB == blue)
                {
                    colour = GR_RGB(0, 0, 0);
                }
                else
                {
                    colour = GR_RGB(255, 255, 255);
                }
                if (colour != lastMaskColour || (i == 0 && j == 0))
                {
                    GrSetGCForeground(maskGC, colour);
                    lastMaskColour = colour;
                }
                GrPoint(maskPixmap, maskGC, i, j);
            }
        }
    }

    GrDestroyGC(pixmapGC);
    if (hasMask)
        GrDestroyGC(maskGC);

    return true;
#else
    // !wxUSE_NANOX

    UnRef();

    wxCHECK_MSG( image.Ok(), false, wxT("invalid image") );
    wxCHECK_MSG( depth == -1, false, wxT("invalid bitmap depth") );

    m_refData = new wxBitmapRefData();

    M_BMPDATA->m_display = wxGlobalDisplay();

    Display *xdisplay = (Display*) M_BMPDATA->m_display;

    int xscreen = DefaultScreen( xdisplay );
    Window xroot = RootWindow( xdisplay, xscreen );
    Visual* xvisual = DefaultVisual( xdisplay, xscreen );

    int bpp = wxTheApp->GetVisualInfo(M_BMPDATA->m_display)->m_visualDepth;

    int width = image.GetWidth();
    int height = image.GetHeight();
    M_BMPDATA->m_width = width;
    M_BMPDATA->m_height = height;

    if (depth != 1) depth = bpp;
    M_BMPDATA->m_bpp = depth;

    if (depth == 1)
    {
        wxFAIL_MSG( wxT("mono images later") );
    }
    else
    {
        // Create image

        XImage *data_image = XCreateImage( xdisplay, xvisual, bpp, ZPixmap, 0, 0, width, height, 32, 0 );
        data_image->data = (char*) malloc( data_image->bytes_per_line * data_image->height );

        if (data_image->data == NULL)
        {
            wxLogError( wxT("Out of memory.") );  // TODO clean
            return false;
        }

        M_BMPDATA->m_pixmap = XCreatePixmap( xdisplay, xroot, width, height, depth );

        // Create mask if necessary
        const bool hasMask = image.HasMask();

        XImage *mask_image = NULL;
        if ( hasMask )
        {
            mask_image = XCreateImage( xdisplay, xvisual, 1, ZPixmap, 0, 0, width, height, 32, 0 );
            mask_image->data = (char*) malloc( mask_image->bytes_per_line * mask_image->height );

            if (mask_image->data == NULL)
            {
                wxLogError( wxT("Out of memory.") ); // TODO clean
                return false;
            }

            wxMask *mask = new wxMask();
            mask->SetDisplay( xdisplay );
            mask->SetBitmap( (WXPixmap) XCreatePixmap( xdisplay, xroot, width, height, 1 ) );

            SetMask( mask );
        }

        if (bpp < 8) bpp = 8;

        // Render

        enum byte_order { RGB, RBG, BRG, BGR, GRB, GBR };
        byte_order b_o = RGB;

        wxXVisualInfo* vi = wxTheApp->GetVisualInfo(M_BMPDATA->m_display);
        unsigned long greenMask = vi->m_visualGreenMask,
                      redMask   = vi->m_visualRedMask,
                      blueMask  = vi->m_visualBlueMask;

        if (bpp > 8)
        {
            if ((redMask > greenMask) && (greenMask > blueMask))     b_o = RGB;
            else if ((redMask > blueMask) && (blueMask > greenMask)) b_o = RBG;
            else if ((blueMask > redMask) && (redMask > greenMask))  b_o = BRG;
            else if ((blueMask > greenMask) && (greenMask > redMask))b_o = BGR;
            else if ((greenMask > redMask) && (redMask > blueMask))  b_o = GRB;
            else if ((greenMask > blueMask) && (blueMask > redMask)) b_o = GBR;
        }

        int r_mask = image.GetMaskRed();
        int g_mask = image.GetMaskGreen();
        int b_mask = image.GetMaskBlue();

        unsigned char* data = image.GetData();
        wxASSERT_MSG( data, wxT("No image data") );

        unsigned char *colorCube =
            wxTheApp->GetVisualInfo(M_BMPDATA->m_display)->m_colorCube;

        int index = 0;
        for (int y = 0; y < height; y++)
        {
            for (int x = 0; x < width; x++)
            {
                int r = data[index];
                index++;
                int g = data[index];
                index++;
                int b = data[index];
                index++;

                if (hasMask)
                {
                    if ((r == r_mask) && (b == b_mask) && (g == g_mask))
                        XPutPixel( mask_image, x, y, 0 );
                    else
                        XPutPixel( mask_image, x, y, 1 );
                }

                switch (bpp)
                {
                    case 8:
                    {
                        int pixel = 0;
                        pixel = colorCube[ ((r & 0xf8) << 7) + ((g & 0xf8) << 2) + ((b & 0xf8) >> 3) ];
                        XPutPixel( data_image, x, y, pixel );
                        break;
                    }
                    case 12:  // SGI only
                    {
                        int pixel = 0;
                        switch (b_o)
                        {
                            case RGB: pixel = ((r & 0xf0) << 4) | (g & 0xf0) | ((b & 0xf0) >> 4); break;
                            case RBG: pixel = ((r & 0xf0) << 4) | (b & 0xf0) | ((g & 0xf0) >> 4); break;
                            case GRB: pixel = ((g & 0xf0) << 4) | (r & 0xf0) | ((b & 0xf0) >> 4); break;
                            case GBR: pixel = ((g & 0xf0) << 4) | (b & 0xf0) | ((r & 0xf0) >> 4); break;
                            case BRG: pixel = ((b & 0xf0) << 4) | (r & 0xf0) | ((g & 0xf0) >> 4); break;
                            case BGR: pixel = ((b & 0xf0) << 4) | (g & 0xf0) | ((r & 0xf0) >> 4); break;
                        }
                        XPutPixel( data_image, x, y, pixel );
                        break;
                    }
                    case 15:
                    {
                        int pixel = 0;
                        switch (b_o)
                        {
                            case RGB: pixel = ((r & 0xf8) << 7) | ((g & 0xf8) << 2) | ((b & 0xf8) >> 3); break;
                            case RBG: pixel = ((r & 0xf8) << 7) | ((b & 0xf8) << 2) | ((g & 0xf8) >> 3); break;
                            case GRB: pixel = ((g & 0xf8) << 7) | ((r & 0xf8) << 2) | ((b & 0xf8) >> 3); break;
                            case GBR: pixel = ((g & 0xf8) << 7) | ((b & 0xf8) << 2) | ((r & 0xf8) >> 3); break;
                            case BRG: pixel = ((b & 0xf8) << 7) | ((r & 0xf8) << 2) | ((g & 0xf8) >> 3); break;
                            case BGR: pixel = ((b & 0xf8) << 7) | ((g & 0xf8) << 2) | ((r & 0xf8) >> 3); break;
                        }
                        XPutPixel( data_image, x, y, pixel );
                        break;
                    }
                    case 16:
                    {
                        // I actually don't know if for 16-bit displays, it is alway the green
                        // component or the second component which has 6 bits.
                        int pixel = 0;
                        switch (b_o)
                        {
                            case RGB: pixel = ((r & 0xf8) << 8) | ((g & 0xfc) << 3) | ((b & 0xf8) >> 3); break;
                            case RBG: pixel = ((r & 0xf8) << 8) | ((b & 0xfc) << 3) | ((g & 0xf8) >> 3); break;
                            case GRB: pixel = ((g & 0xf8) << 8) | ((r & 0xfc) << 3) | ((b & 0xf8) >> 3); break;
                            case GBR: pixel = ((g & 0xf8) << 8) | ((b & 0xfc) << 3) | ((r & 0xf8) >> 3); break;
                            case BRG: pixel = ((b & 0xf8) << 8) | ((r & 0xfc) << 3) | ((g & 0xf8) >> 3); break;
                            case BGR: pixel = ((b & 0xf8) << 8) | ((g & 0xfc) << 3) | ((r & 0xf8) >> 3); break;
                        }
                        XPutPixel( data_image, x, y, pixel );
                        break;
                    }
                    case 32:
                    case 24:
                    {
                        int pixel = 0;
                        switch (b_o)
                        {
                            case RGB: pixel = (r << 16) | (g << 8) | b; break;
                            case RBG: pixel = (r << 16) | (b << 8) | g; break;
                            case BRG: pixel = (b << 16) | (r << 8) | g; break;
                            case BGR: pixel = (b << 16) | (g << 8) | r; break;
                            case GRB: pixel = (g << 16) | (r << 8) | b; break;
                            case GBR: pixel = (g << 16) | (b << 8) | r; break;
                        }
                        XPutPixel( data_image, x, y, pixel );
                    }
                    default: break;
                }
            } // for
        }  // for

        // Blit picture

        GC gc = XCreateGC( xdisplay, (Pixmap) M_BMPDATA->m_pixmap, 0, NULL );
        XPutImage( xdisplay, (Pixmap) M_BMPDATA->m_pixmap, gc, data_image, 0, 0, 0, 0, width, height );
        XDestroyImage( data_image );
        XFreeGC( xdisplay, gc );

        // Blit mask

        if (image.HasMask())
        {
            GC gc = XCreateGC( xdisplay, (Pixmap) GetMask()->GetBitmap(), 0, NULL );
            XPutImage( xdisplay, (Pixmap) GetMask()->GetBitmap(), gc, mask_image, 0, 0, 0, 0, width, height );

            XDestroyImage( mask_image );
            XFreeGC( xdisplay, gc );
        }
    }

    return true;
#endif
    // wxUSE_NANOX
}

wxImage wxBitmap::ConvertToImage() const
{
    wxImage image;

    wxCHECK_MSG( Ok(), wxNullImage, wxT("invalid bitmap") );

    Display *xdisplay = (Display*) M_BMPDATA->m_display;
    wxASSERT_MSG( xdisplay, wxT("No display") );

#if wxUSE_NANOX
    //int bpp = DefaultDepth(xdisplay, xscreen);
    wxGetImageFromDrawable((Pixmap) GetPixmap(), 0, 0, GetWidth(), GetHeight(), image);
    return image;
#else
    // !wxUSE_NANOX
    int bpp = wxTheApp->GetVisualInfo(M_BMPDATA->m_display)->m_visualDepth;
    XImage *x_image = NULL;
    if (GetPixmap())
    {
        x_image = XGetImage( xdisplay, (Pixmap) GetPixmap(),
            0, 0,
            GetWidth(), GetHeight(),
            AllPlanes, ZPixmap );
    } else
    if (GetBitmap())
    {
        x_image = XGetImage( xdisplay, (Pixmap) GetBitmap(),
            0, 0,
            GetWidth(), GetHeight(),
            AllPlanes, ZPixmap );
    } else
    {
        wxFAIL_MSG( wxT("Ill-formed bitmap") );
    }

    wxCHECK_MSG( x_image, wxNullImage, wxT("couldn't create image") );

    image.Create( GetWidth(), GetHeight() );
    char unsigned *data = image.GetData();

    if (!data)
    {
        XDestroyImage( x_image );
        wxFAIL_MSG( wxT("couldn't create image") );
        return wxNullImage;
    }

    XImage *x_image_mask = NULL;
    if (GetMask())
    {
        x_image_mask = XGetImage( xdisplay, (Pixmap) GetMask()->GetBitmap(),
            0, 0,
            GetWidth(), GetHeight(),
            AllPlanes, ZPixmap );

        image.SetMaskColour( 16, 16, 16 );  // anything unlikely and dividable
    }

    int red_shift_right = 0;
    int green_shift_right = 0;
    int blue_shift_right = 0;
    int red_shift_left = 0;
    int green_shift_left = 0;
    int blue_shift_left = 0;
    bool use_shift = false;

    if (GetPixmap())
    {
        wxXVisualInfo* vi = wxTheApp->GetVisualInfo(M_BMPDATA->m_display);

        red_shift_right = vi->m_visualRedShift;
        red_shift_left = 8 - vi->m_visualRedPrec;
        green_shift_right = vi->m_visualGreenShift;
        green_shift_left = 8 - vi->m_visualGreenPrec;
        blue_shift_right = vi->m_visualBlueShift;
        blue_shift_left = 8 - vi->m_visualBluePrec;

        use_shift = (vi->m_visualType == GrayScale) ||
                    (vi->m_visualType != PseudoColor);
    }

    if (GetBitmap())
    {
        bpp = 1;
    }

    XColor *colors = (XColor*)wxTheApp->
        GetVisualInfo(M_BMPDATA->m_display)->m_visualColormap;

    int width = GetWidth();
    int height = GetHeight();
    long pos = 0;
    for (int j = 0; j < height; j++)
    {
        for (int i = 0; i < width; i++)
        {
            unsigned long pixel = XGetPixel( x_image, i, j );
            if (bpp == 1)
            {
                if (pixel == 0)
                {
                    data[pos]   = 0;
                    data[pos+1] = 0;
                    data[pos+2] = 0;
                }
                else
                {
                    data[pos]   = 255;
                    data[pos+1] = 255;
                    data[pos+2] = 255;
                }
            }
            else if (use_shift)
            {
                data[pos] =   (unsigned char)((pixel >> red_shift_right)   << red_shift_left);
                data[pos+1] = (unsigned char)((pixel >> green_shift_right) << green_shift_left);
                data[pos+2] = (unsigned char)((pixel >> blue_shift_right)  << blue_shift_left);
            }
            else if (colors)
            {
                data[pos] =   (unsigned char)(colors[pixel].red   >> 8);
                data[pos+1] = (unsigned char)(colors[pixel].green >> 8);
                data[pos+2] = (unsigned char)(colors[pixel].blue  >> 8);
            }
            else
            {
                wxFAIL_MSG( wxT("Image conversion failed. Unknown visual type.") );
            }

            if (x_image_mask)
            {
                int mask_pixel = XGetPixel( x_image_mask, i, j );
                if (mask_pixel == 0)
                {
                    data[pos] = 16;
                    data[pos+1] = 16;
                    data[pos+2] = 16;
                }
            }

            pos += 3;
        }
    }

    XDestroyImage( x_image );
    if (x_image_mask) XDestroyImage( x_image_mask );
    return image;
#endif
    // wxUSE_NANOX
}

wxBitmap::wxBitmap( const wxString &filename, wxBitmapType type )
{
    LoadFile( filename, type );
}

wxBitmap::wxBitmap( const char bits[], int width, int height, int depth )
{
    m_refData = new wxBitmapRefData;

    (void) Create(bits, wxBITMAP_TYPE_XBM_DATA, width, height, depth);
}

wxBitmap::~wxBitmap()
{
}

int wxBitmap::GetHeight() const
{
    wxCHECK_MSG( Ok(), -1, wxT("invalid bitmap") );

    return M_BMPDATA->m_height;
}

int wxBitmap::GetWidth() const
{
    wxCHECK_MSG( Ok(), -1, wxT("invalid bitmap") );

    return M_BMPDATA->m_width;
}

int wxBitmap::GetDepth() const
{
    wxCHECK_MSG( Ok(), -1, wxT("invalid bitmap") );

    return M_BMPDATA->m_bpp;
}

wxMask *wxBitmap::GetMask() const
{
    wxCHECK_MSG( Ok(), NULL, wxT("invalid bitmap") );

    return M_BMPDATA->m_mask;
}

void wxBitmap::SetMask( wxMask *mask )
{
    wxCHECK_RET( Ok(), wxT("invalid bitmap") );

    AllocExclusive();
    if (M_BMPDATA->m_mask) delete M_BMPDATA->m_mask;

    M_BMPDATA->m_mask = mask;
}

bool wxBitmap::CopyFromIcon(const wxIcon& icon)
{
    *this = icon;
    return true;
}

wxBitmap wxBitmap::GetSubBitmap( const wxRect& rect) const
{
    wxCHECK_MSG( Ok() &&
                 (rect.x >= 0) && (rect.y >= 0) &&
                 (rect.x+rect.width  <= M_BMPDATA->m_width ) &&
                 (rect.y+rect.height <= M_BMPDATA->m_height),
                 wxNullBitmap, wxT("invalid bitmap or bitmap region") );

    wxBitmap ret( rect.width, rect.height, M_BMPDATA->m_bpp );
    wxASSERT_MSG( ret.Ok(), wxT("GetSubBitmap error") );

    if( GetMask() )
    {
        wxMask* mask = new wxMask();
        mask->SetDisplay( GetMask()->GetDisplay() );
        mask->SetBitmap( wxGetSubPixmap( GetMask()->GetDisplay(),
                                         GetMask()->GetBitmap(),
                                         rect.x, rect.y,
                                         rect.width, rect.height,
                                         1 ) );

        ret.SetMask( mask );
    }

    if( GetPixmap() )
    {
        ret.SetPixmap( wxGetSubPixmap( GetDisplay(),
                                       GetPixmap(),
                                       rect.x, rect.y,
                                       rect.width, rect.height,
                                       M_BMPDATA->m_bpp ) );
    }

    if( GetBitmap() )
    {
        ret.SetBitmap( wxGetSubPixmap( GetDisplay(),
                                       GetBitmap(),
                                       rect.x, rect.y,
                                       rect.width, rect.height,
                                       1 ) );
    }

    return ret;
}

bool wxBitmap::SaveFile( const wxString &name, wxBitmapType type,
                         const wxPalette *palette ) const
{
    wxCHECK_MSG( Ok(), false, wxT("invalid bitmap") );

    wxBitmapHandler *handler = FindHandler(type);

    // Try to save the bitmap via wxImage handlers:
    if (handler == NULL)
    {
        wxImage image(this->ConvertToImage());
        if (image.Ok()) return image.SaveFile( name, type );

        return false;
    }

    return handler->SaveFile(this, name, type, palette);
}

bool wxBitmap::LoadFile( const wxString &name, wxBitmapType type )
{
    UnRef();

    if (!wxFileExists(name)) return false;

    wxBitmapHandler *handler = FindHandler(type);

    if (handler == NULL)
    {
        wxImage image;
        if (!image.LoadFile( name, type ))
            return false;

        if (image.Ok())
        {
            *this = wxBitmap(image);
            return true;
        }
        else return false;
    }

    return handler->LoadFile(this, name, type, -1, -1);
}

void wxBitmap::SetPalette(const wxPalette& palette)
{
    wxCHECK_RET(Ok(), wxT("invalid bitmap"));
    wxCHECK_RET(GetDepth() > 1 && GetDepth() <= 8,
                wxT("cannot set palette for bitmap of this depth"));

    AllocExclusive();
    wxDELETE(M_BMPDATA->m_palette);

    if (!palette.Ok()) return;

    M_BMPDATA->m_palette = new wxPalette(palette);
}

wxPalette *wxBitmap::GetPalette() const
{
    if (!Ok()) return NULL;

    return M_BMPDATA->m_palette;
}

void wxBitmap::SetHeight( int height )
{
    AllocExclusive();

    M_BMPDATA->m_height = height;
}

void wxBitmap::SetWidth( int width )
{
    AllocExclusive();

    M_BMPDATA->m_width = width;
}

void wxBitmap::SetDepth( int depth )
{
    AllocExclusive();

    M_BMPDATA->m_bpp = depth;
}

void wxBitmap::SetPixmap( WXPixmap pixmap )
{
    if (!m_refData) m_refData = new wxBitmapRefData();

    M_BMPDATA->m_pixmap = (Pixmap)pixmap;
}

void wxBitmap::SetBitmap( WXPixmap bitmap )
{
    if (!m_refData) m_refData = new wxBitmapRefData();

    M_BMPDATA->m_bitmap = (Pixmap)bitmap;
}

WXPixmap wxBitmap::GetPixmap() const
{
    wxCHECK_MSG( Ok(), (WXPixmap) NULL, wxT("invalid bitmap") );

    return (WXPixmap)M_BMPDATA->m_pixmap;
}

WXPixmap wxBitmap::GetBitmap() const
{
    wxCHECK_MSG( Ok(), (WXPixmap) NULL, wxT("invalid bitmap") );

    return (WXPixmap)M_BMPDATA->m_bitmap;
}

WXPixmap wxBitmap::GetDrawable() const
{
    wxCHECK_MSG( Ok(), (WXPixmap) NULL, wxT("invalid bitmap") );

    return (WXPixmap)(M_BMPDATA->m_bpp == 1 ? M_BMPDATA->m_bitmap
                                            : M_BMPDATA->m_pixmap);
}

WXDisplay *wxBitmap::GetDisplay() const
{
    wxCHECK_MSG( Ok(), NULL, wxT("invalid bitmap") );

    return M_BMPDATA->m_display;
}

#if wxUSE_NANOX
// Copy from the drawable to the wxImage
bool wxGetImageFromDrawable(GR_DRAW_ID drawable, int srcX, int srcY, int width, int height, wxImage& image)
{
    GR_SCREEN_INFO sinfo;
    int x, y;
    GR_PIXELVAL *pixels;
    GR_PALETTE* palette = NULL;
    unsigned char rgb[3], *pp;

    GrGetScreenInfo(&sinfo);

    if (sinfo.pixtype == MWPF_PALETTE) {
        if(!(palette = (GR_PALETTE*) malloc(sizeof(GR_PALETTE)))) {
            return false;
        }
        GrGetSystemPalette(palette);
    }

    if(!(pixels = (GR_PIXELVAL*) malloc(sizeof(GR_PIXELVAL) * width * height)))
    {
        return false;
    }

    image.Create(width, height);

    GrReadArea(drawable, srcX, srcY, width, height,
            pixels);


    for(x = 0; x < sinfo.cols; x++) {

        pp = (unsigned char *)pixels +
            ((x + (y * sinfo.cols)) *
             sizeof(GR_PIXELVAL));

        switch(sinfo.pixtype) {
            /* FIXME: These may need modifying on big endian. */
            case MWPF_TRUECOLOR0888:
            case MWPF_TRUECOLOR888:
                rgb[0] = pp[2];
                rgb[1] = pp[1];
                rgb[2] = pp[0];
                break;
            case MWPF_PALETTE:
                rgb[0] = palette->palette[pp[0]].r;
                rgb[1] = palette->palette[pp[0]].g;
                rgb[2] = palette->palette[pp[0]].b;
                break;
            case MWPF_TRUECOLOR565:
                rgb[0] = pp[1] & 0xf8;
                rgb[1] = ((pp[1] & 0x07) << 5) |
                    ((pp[0] & 0xe0) >> 3);
                rgb[2] = (pp[0] & 0x1f) << 3;
                break;
            case MWPF_TRUECOLOR555:
                rgb[0] = (pp[1] & 0x7c) << 1;
                rgb[1] = ((pp[1] & 0x03) << 6) |
                    ((pp[0] & 0xe0) >> 2);
                rgb[2] = (pp[0] & 0x1f) << 3;
                break;
            case MWPF_TRUECOLOR332:
                rgb[0] = pp[0] & 0xe0;
                rgb[1] = (pp[0] & 0x1c) << 3;
                rgb[2] = (pp[0] & 0x03) << 6;
                break;
            default:
                fprintf(stderr, "Unsupported pixel "
                        "format\n");
                return 1;
        }

        image.SetRGB(x, y, rgb[0], rgb[1], rgb[2]);

    }

    free(pixels);
    if(palette) free(palette);

    return true;
}

#if 0
int GrGetPixelColor(GR_SCREEN_INFO* sinfo, GR_PALETTE* palette, GR_PIXELVAL pixel,
    unsigned char* red, unsigned char* green, unsigned char* blue)
{
    unsigned char rgb[3], *pp;

    pp = (unsigned char*) & pixel ;

    switch (sinfo.pixtype)
    {
        /* FIXME: These may need modifying on big endian. */
        case MWPF_TRUECOLOR0888:
        case MWPF_TRUECOLOR888:
            rgb[0] = pp[2];
            rgb[1] = pp[1];
            rgb[2] = pp[0];
            break;
        case MWPF_PALETTE:
            rgb[0] = palette->palette[pp[0]].r;
            rgb[1] = palette->palette[pp[0]].g;
            rgb[2] = palette->palette[pp[0]].b;
            break;
        case MWPF_TRUECOLOR565:
            rgb[0] = pp[1] & 0xf8;
            rgb[1] = ((pp[1] & 0x07) << 5) |
                ((pp[0] & 0xe0) >> 3);
            rgb[2] = (pp[0] & 0x1f) << 3;
            break;
        case MWPF_TRUECOLOR555:
            rgb[0] = (pp[1] & 0x7c) << 1;
            rgb[1] = ((pp[1] & 0x03) << 6) |
                ((pp[0] & 0xe0) >> 2);
            rgb[2] = (pp[0] & 0x1f) << 3;
            break;
        case MWPF_TRUECOLOR332:
            rgb[0] = pp[0] & 0xe0;
            rgb[1] = (pp[0] & 0x1c) << 3;
            rgb[2] = (pp[0] & 0x03) << 6;
            break;
        default:
            fprintf(stderr, "Unsupported pixel format\n");
            return 0;
    }


    *(red) = rgb[0];
    *(green) = rgb[1];
    *(blue) = rgb[2];
    return 1;
}
#endif

#endif
  // wxUSE_NANOX

// ============================================================================
// Bitmap handlers
// ============================================================================

#define M_BMPHANDLERDATA ((wxBitmapRefData *)bitmap->GetRefData())

#if wxUSE_XPM

#if wxHAVE_LIB_XPM || wxUSE_STREAMS

// ----------------------------------------------------------------------------
// wxXPMFileHandler
// ----------------------------------------------------------------------------

class wxXPMFileHandler : public wxBitmapHandler
{
public:
    wxXPMFileHandler()
    {
        SetName( wxT("XPM file") );
        SetExtension( wxT("xpm") );
        SetType( wxBITMAP_TYPE_XPM );
    };

    virtual bool LoadFile(wxBitmap *bitmap, const wxString& name,
                          wxBitmapType flags,
                          int desiredWidth, int desiredHeight);

    virtual bool SaveFile(const wxBitmap *bitmap, const wxString& name,
                          wxBitmapType type,
                          const wxPalette *palette = NULL) const;

    virtual bool Create(wxBitmap *WXUNUSED(bitmap),
                        const void* WXUNUSED(data),
                        wxBitmapType WXUNUSED(flags),
                        int WXUNUSED(width),
                        int WXUNUSED(height),
                        int WXUNUSED(depth) = 1)
        { return false; }

    DECLARE_DYNAMIC_CLASS(wxXPMFileHandler)
};

IMPLEMENT_DYNAMIC_CLASS(wxXPMFileHandler, wxBitmapHandler)

bool wxXPMFileHandler::LoadFile(wxBitmap *bitmap,
                                const wxString& name,
                                wxBitmapType WXUNUSED(flags),
                                int WXUNUSED(desiredWidth),
                                int WXUNUSED(desiredHeight))
{
#if wxHAVE_LIB_XPM
    if (!bitmap->GetRefData())
        bitmap->SetRefData( new wxBitmapRefData() );

    M_BMPHANDLERDATA->m_display = wxGlobalDisplay();

    Display *xdisplay = (Display*) M_BMPHANDLERDATA->m_display;

    int xscreen = DefaultScreen( xdisplay );
    Window xroot = RootWindow( xdisplay, xscreen );

    int bpp = DefaultDepth( xdisplay, xscreen );

    XpmAttributes xpmAttr;
    xpmAttr.valuemask = XpmReturnInfos;    // nothing yet, but get infos back

    Pixmap pixmap;
    Pixmap mask = 0;

    int ErrorStatus = XpmReadFileToPixmap( xdisplay, xroot,
                                           (char*) ((const char*) name.c_str()),
                                           &pixmap, &mask, &xpmAttr);

    if (ErrorStatus == XpmSuccess)
    {
        M_BMPHANDLERDATA->m_width = xpmAttr.width;
        M_BMPHANDLERDATA->m_height = xpmAttr.height;

        M_BMPHANDLERDATA->m_bpp = bpp;  // mono as well?

        XpmFreeAttributes(&xpmAttr);

        M_BMPHANDLERDATA->m_bitmap = (Pixmap) pixmap;

        if (mask)
        {
            M_BMPHANDLERDATA->m_mask = new wxMask;
            M_BMPHANDLERDATA->m_mask->SetBitmap( (WXPixmap) mask );
            M_BMPHANDLERDATA->m_mask->SetDisplay( xdisplay );
        }
    }
    else
    {
        UnRef();

        return false;
    }

    return true;
#elif wxUSE_STREAMS
    wxXPMDecoder decoder;
    wxFileInputStream stream(name);
    if (stream.IsOk())
    {
        wxImage image(decoder.ReadFile(stream));
        return image.IsOk() && bitmap->CreateFromImage(image);
    }

    return false;
#else // !wxHAVE_LIB_XPM && !wxUSE_STREAMS
    return false;
#endif // wxHAVE_LIB_XPM / wxUSE_STREAMS
}

bool wxXPMFileHandler::SaveFile(const wxBitmap *bitmap,
                                const wxString& name,
                                wxBitmapType type,
                                const wxPalette *WXUNUSED(palette)) const
{
    wxImage image(bitmap->ConvertToImage());
    if (image.Ok())
        return image.SaveFile( name, type );

    return false;
}

#endif // wxHAVE_LIB_XPM || wxUSE_STREAMS

// ----------------------------------------------------------------------------
// wxXPMDataHandler
// ----------------------------------------------------------------------------

class wxXPMDataHandler : public wxBitmapHandler
{
    DECLARE_DYNAMIC_CLASS(wxXPMDataHandler)
public:
    wxXPMDataHandler()
    {
        SetName( wxT("XPM data") );
        SetExtension( wxT("xpm") );
        SetType( wxBITMAP_TYPE_XPM_DATA );
    };

    virtual bool LoadFile(wxBitmap *WXUNUSED(bitmap),
                          const wxString& WXUNUSED(name),
                          wxBitmapType WXUNUSED(flags),
                          int WXUNUSED(desiredWidth),
                          int WXUNUSED(desiredHeight))
        { return false; }

    virtual bool SaveFile(const wxBitmap *WXUNUSED(bitmap),
                          const wxString& WXUNUSED(name),
                          wxBitmapType WXUNUSED(type),
                          const wxPalette *WXUNUSED(palette) = NULL) const
        { return false; }

    virtual bool Create(wxBitmap *bitmap, const void* data, wxBitmapType flags,
                        int width, int height, int depth = 1);
};

IMPLEMENT_DYNAMIC_CLASS(wxXPMDataHandler, wxBitmapHandler)

bool wxXPMDataHandler::Create(wxBitmap *bitmap, const void* bits,
                              wxBitmapType WXUNUSED(flags),
                              int WXUNUSED(width), int WXUNUSED(height), int WXUNUSED(depth))
{
#if wxHAVE_LIB_XPM
    wxCHECK_MSG( bits != NULL, false, wxT("invalid bitmap data") );

    if (!bitmap->GetRefData())
        bitmap->SetRefData( new wxBitmapRefData() );

    M_BMPHANDLERDATA->m_display = wxGlobalDisplay();

    Display *xdisplay = (Display*) M_BMPHANDLERDATA->m_display;

    int xscreen = DefaultScreen( xdisplay );
    Window xroot = RootWindow( xdisplay, xscreen );

    int bpp = DefaultDepth( xdisplay, xscreen );

    XpmAttributes xpmAttr;
    xpmAttr.valuemask = XpmReturnInfos;    // nothing yet, but get infos back

    Pixmap pixmap = 0;
    Pixmap mask = 0;

    int ErrorStatus = XpmCreatePixmapFromData( xdisplay, xroot, (char**) bits,
                                               &pixmap, &mask, &xpmAttr );

    if (ErrorStatus == XpmSuccess)
    {
        M_BMPHANDLERDATA->m_width = xpmAttr.width;
        M_BMPHANDLERDATA->m_height = xpmAttr.height;

        M_BMPHANDLERDATA->m_bpp = bpp;  // mono as well?

#if wxDEBUG_LEVEL
        unsigned int depthRet;
        int xRet, yRet;
        unsigned int widthRet, heightRet, borderWidthRet;
        XGetGeometry( xdisplay, pixmap, &xroot, &xRet, &yRet,
            &widthRet, &heightRet, &borderWidthRet, &depthRet);

        wxASSERT_MSG( bpp == (int)depthRet, wxT("colour depth mismatch") );
#endif // wxDEBUG_LEVEL

        XpmFreeAttributes(&xpmAttr);

        M_BMPHANDLERDATA->m_pixmap = (Pixmap) pixmap;

        if (mask)
        {
            M_BMPHANDLERDATA->m_mask = new wxMask;
            M_BMPHANDLERDATA->m_mask->SetBitmap( (WXPixmap) mask );
            M_BMPHANDLERDATA->m_mask->SetDisplay( xdisplay );
        }
        return true;
    }
    else
    {
        bitmap->UnRef();

        return false;
    }
#else // !wxHAVE_LIB_XPM
    wxXPMDecoder decoder;
    wxImage image(decoder.ReadData((const char **)bits));
    return image.Ok() && bitmap->CreateFromImage(image);
#endif // wxHAVE_LIB_XPM/!wxHAVE_LIB_XPM
}

#endif // wxUSE_XPM

// ----------------------------------------------------------------------------
// wxXBMDataHandler
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxXBMDataHandler: public wxBitmapHandler
{
    DECLARE_DYNAMIC_CLASS(wxXBMDataHandler)
public:
    inline wxXBMDataHandler()
    {
        SetName( wxT("XBM data") );
        SetExtension( wxT("xbm") );
        SetType( wxBITMAP_TYPE_XBM_DATA );
    };

    virtual bool LoadFile(wxBitmap *WXUNUSED(bitmap),
                          const wxString& WXUNUSED(name),
                          wxBitmapType WXUNUSED(flags),
                          int WXUNUSED(desiredWidth),
                          int WXUNUSED(desiredHeight))
        { return false; }

    virtual bool SaveFile(const wxBitmap *WXUNUSED(bitmap),
                          const wxString& WXUNUSED(name),
                          wxBitmapType WXUNUSED(type),
                          const wxPalette *WXUNUSED(palette) = NULL) const
        { return false; }

    virtual bool Create(wxBitmap *bitmap, const void* data, wxBitmapType type,
                        int width, int height, int depth = 1);
};

IMPLEMENT_DYNAMIC_CLASS(wxXBMDataHandler, wxBitmapHandler)

bool wxXBMDataHandler::Create( wxBitmap *bitmap, const void* bits,
                               wxBitmapType WXUNUSED(type),
                               int width, int height, int WXUNUSED(depth))
{
#if !wxUSE_NANOX
    if (!bitmap->GetRefData())
        bitmap->SetRefData( new wxBitmapRefData() );

    M_BMPHANDLERDATA->m_display = wxGlobalDisplay();

    Display *xdisplay = (Display*) M_BMPHANDLERDATA->m_display;

    int xscreen = DefaultScreen( xdisplay );
    Window xroot = RootWindow( xdisplay, xscreen );

    M_BMPHANDLERDATA->m_mask = NULL;
    M_BMPHANDLERDATA->m_bitmap =
        XCreateBitmapFromData(xdisplay, xroot,
                              (char *) bits, width, height );
    M_BMPHANDLERDATA->m_width = width;
    M_BMPHANDLERDATA->m_height = height;
    M_BMPHANDLERDATA->m_bpp = 1;

    return true;
#else
   wxCHECK_MSG( M_BMPHANDLERDATA->m_bitmap, false,
                 wxT("couldn't create bitmap") );
#endif
}

void wxBitmap::InitStandardHandlers()
{
    AddHandler(new wxXBMDataHandler);
#if wxUSE_XPM
#if wxHAVE_LIB_XPM || wxUSE_STREAMS
    AddHandler(new wxXPMFileHandler);
#endif
    AddHandler(new wxXPMDataHandler);
#endif
}
