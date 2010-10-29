/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/bitmap.cpp
// Purpose:
// Author:      Robert Roebling
// RCS-ID:      $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/bitmap.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/dcmemory.h"
    #include "wx/palette.h"
    #include "wx/icon.h"
    #include "wx/math.h"
    #include "wx/image.h"
#endif // WX_PRECOMP

#include "wx/filefn.h"

#include <gdk/gdk.h>
#include <gtk/gtk.h>
#include <gdk/gdkx.h>

#include <gdk/gdkrgb.h>

extern
void gdk_wx_draw_bitmap (GdkDrawable  *drawable,
                         GdkGC        *gc,
                         GdkDrawable  *src,
                         gint          xsrc,
                         gint          ysrc,
                         gint          xdest,
                         gint          ydest,
                         gint          width,
                         gint          height);

//-----------------------------------------------------------------------------
// data
//-----------------------------------------------------------------------------

extern GtkWidget *wxGetRootWindow();

//-----------------------------------------------------------------------------
// wxMask
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxMask,wxObject)

wxMask::wxMask()
{
    m_bitmap = NULL;
}

wxMask::wxMask( const wxBitmap& bitmap, const wxColour& colour )
{
    m_bitmap = NULL;
    Create( bitmap, colour );
}

#if wxUSE_PALETTE
wxMask::wxMask( const wxBitmap& bitmap, int paletteIndex )
{
    m_bitmap = NULL;
    Create( bitmap, paletteIndex );
}
#endif // wxUSE_PALETTE

wxMask::wxMask( const wxBitmap& bitmap )
{
    m_bitmap = NULL;
    Create( bitmap );
}

wxMask::~wxMask()
{
    if (m_bitmap)
        gdk_bitmap_unref( m_bitmap );
}

bool wxMask::Create( const wxBitmap& bitmap,
                     const wxColour& colour )
{
    if (m_bitmap)
    {
        gdk_bitmap_unref( m_bitmap );
        m_bitmap = NULL;
    }

    wxImage image = bitmap.ConvertToImage();
    if (!image.Ok()) return false;

    m_bitmap = gdk_pixmap_new( wxGetRootWindow()->window, image.GetWidth(), image.GetHeight(), 1 );
    GdkGC *gc = gdk_gc_new( m_bitmap );

    GdkColor color;
    color.red = 65000;
    color.green = 65000;
    color.blue = 65000;
    color.pixel = 1;
    gdk_gc_set_foreground( gc, &color );
    gdk_gc_set_fill( gc, GDK_SOLID );
    gdk_draw_rectangle( m_bitmap, gc, TRUE, 0, 0, image.GetWidth(), image.GetHeight() );

    unsigned char *data = image.GetData();
    int index = 0;

    unsigned char red = colour.Red();
    unsigned char green = colour.Green();
    unsigned char blue = colour.Blue();

    GdkVisual *visual = wxTheApp->GetGdkVisual();

    int bpp = visual->depth;
    if ((bpp == 16) && (visual->red_mask != 0xf800))
        bpp = 15;
    if (bpp == 15)
    {
        red = red & 0xf8;
        green = green & 0xf8;
        blue = blue & 0xf8;
    }
    else if (bpp == 16)
    {
        red = red & 0xf8;
        green = green & 0xfc;
        blue = blue & 0xf8;
    }
    else if (bpp == 12)
    {
        red = red & 0xf0;
        green = green & 0xf0;
        blue = blue & 0xf0;
    }

    color.red = 0;
    color.green = 0;
    color.blue = 0;
    color.pixel = 0;
    gdk_gc_set_foreground( gc, &color );

    for (int j = 0; j < image.GetHeight(); j++)
    {
        int start_x = -1;
        int i;
        for (i = 0; i < image.GetWidth(); i++)
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
                    gdk_draw_line( m_bitmap, gc, start_x, j, i-1, j );
                    start_x = -1;
                }
            }
            index += 3;
        }
        if (start_x != -1)
            gdk_draw_line( m_bitmap, gc, start_x, j, i, j );
    }

    gdk_gc_unref( gc );

    return true;
}

#if wxUSE_PALETTE
bool wxMask::Create( const wxBitmap& bitmap, int paletteIndex )
{
    unsigned char r,g,b;
    wxPalette *pal = bitmap.GetPalette();

    wxCHECK_MSG( pal, false, wxT("Cannot create mask from bitmap without palette") );

    pal->GetRGB(paletteIndex, &r, &g, &b);

    return Create(bitmap, wxColour(r, g, b));
}
#endif // wxUSE_PALETTE

bool wxMask::Create( const wxBitmap& bitmap )
{
    if (m_bitmap)
    {
        gdk_bitmap_unref( m_bitmap );
        m_bitmap = NULL;
    }

    if (!bitmap.Ok()) return false;

    wxCHECK_MSG( bitmap.GetBitmap(), false, wxT("Cannot create mask from colour bitmap") );

    m_bitmap = gdk_pixmap_new( wxGetRootWindow()->window, bitmap.GetWidth(), bitmap.GetHeight(), 1 );

    if (!m_bitmap) return false;

    GdkGC *gc = gdk_gc_new( m_bitmap );

    gdk_wx_draw_bitmap( m_bitmap, gc, bitmap.GetBitmap(), 0, 0, 0, 0, bitmap.GetWidth(), bitmap.GetHeight() );

    gdk_gc_unref( gc );

    return true;
}

GdkBitmap *wxMask::GetBitmap() const
{
    return m_bitmap;
}


//-----------------------------------------------------------------------------
// wxBitmapRefData
//-----------------------------------------------------------------------------

class wxBitmapRefData : public wxGDIRefData
{
public:
    wxBitmapRefData();
    wxBitmapRefData(const wxBitmapRefData& data);
    bool Create(int width, int height, int bpp);
    virtual ~wxBitmapRefData();

    virtual bool IsOk() const { return m_pixmap || m_bitmap; }

    GdkPixmap      *m_pixmap;
    GdkBitmap      *m_bitmap;
    wxMask         *m_mask;
    int             m_width;
    int             m_height;
    int             m_bpp;
#if wxUSE_PALETTE
    wxPalette      *m_palette;
#endif // wxUSE_PALETTE
};

wxBitmapRefData::wxBitmapRefData()
{
    m_pixmap = NULL;
    m_bitmap = NULL;
    m_mask = NULL;
    m_width = 0;
    m_height = 0;
    m_bpp = 0;
#if wxUSE_PALETTE
    m_palette = NULL;
#endif // wxUSE_PALETTE
}

wxBitmapRefData::wxBitmapRefData(const wxBitmapRefData& data)
{
    Create(data.m_width, data.m_height, data.m_bpp);

    m_mask = data.m_mask ? new wxMask(*data.m_mask) : NULL;

#if wxUSE_PALETTE
    wxASSERT_MSG( !data.m_palette,
                  wxT("copying bitmaps palette not implemented") );
#endif // wxUSE_PALETTE


    // copy the bitmap data by simply drawing the source bitmap on this one
    GdkPixmap **dst;
    if ( data.m_pixmap )
    {
        dst = &m_pixmap;
    }
    else if ( data.m_bitmap )
    {
        dst = &m_bitmap;
    }
    else // invalid bitmap?
    {
        return;
    }

    GdkGC *gc = gdk_gc_new(*dst);
    if ( m_bpp == 1 )
    {
        gdk_wx_draw_bitmap(m_bitmap, gc, data.m_bitmap, 0, 0, 0, 0, -1, -1);
    }
    else // colour pixmap
    {
        gdk_draw_pixmap(m_pixmap, gc, data.m_pixmap, 0, 0, 0, 0, -1, -1);
    }

    gdk_gc_unref(gc);
}

bool wxBitmapRefData::Create(int width, int height, int bpp)
{
    m_width = width;
    m_height = height;
    m_bpp = bpp;

    m_mask = NULL;
#if wxUSE_PALETTE
    m_palette = NULL;
#endif

    // to understand how this compiles you should know that GdkPixmap and
    // GdkBitmap are one and the same type in GTK+ 1
    GdkPixmap **ppix;
    if ( m_bpp != 1 )
    {
        const GdkVisual * const visual = wxTheApp->GetGdkVisual();

        wxCHECK_MSG( (bpp == -1) || (bpp == visual->depth) || (bpp == 32), false,
                        wxT("invalid bitmap depth") );

        m_bpp = visual->depth;

        ppix = &m_pixmap;
        m_bitmap = NULL;
    }
    else // mono bitmap
    {
        ppix = &m_bitmap;
        m_pixmap = NULL;
    }

    *ppix = gdk_pixmap_new( wxGetRootWindow()->window, width, height, m_bpp );

    return *ppix != NULL;
}

wxBitmapRefData::~wxBitmapRefData()
{
    if (m_pixmap)
        gdk_pixmap_unref( m_pixmap );
    if (m_bitmap)
        gdk_bitmap_unref( m_bitmap );
    delete m_mask;
#if wxUSE_PALETTE
    delete m_palette;
#endif // wxUSE_PALETTE
}


//-----------------------------------------------------------------------------
// wxBitmap
//-----------------------------------------------------------------------------

#define M_BMPDATA ((wxBitmapRefData *)m_refData)

IMPLEMENT_DYNAMIC_CLASS(wxBitmap,wxGDIObject)

wxGDIRefData *wxBitmap::CreateGDIRefData() const
{
    return new wxBitmapRefData;
}

wxGDIRefData *wxBitmap::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxBitmapRefData(*static_cast<const wxBitmapRefData *>(data));
}

bool wxBitmap::Create( int width, int height, int depth )
{
    UnRef();

    if ( width <= 0 || height <= 0 )
    {
        return false;
    }

    m_refData = new wxBitmapRefData();
    return M_BMPDATA->Create(width, height, depth);
}

wxBitmap::wxBitmap(const char* const* bits)
{
    wxCHECK2_MSG(bits != NULL, return, wxT("invalid bitmap data"));

    GdkVisual *visual = wxTheApp->GetGdkVisual();

    m_refData = new wxBitmapRefData();

    GdkBitmap *mask = NULL;

    M_BMPDATA->m_pixmap = gdk_pixmap_create_from_xpm_d( wxGetRootWindow()->window, &mask, NULL, (gchar **) bits );

    wxCHECK2_MSG(M_BMPDATA->m_pixmap, return, wxT("couldn't create pixmap"));

    if (mask)
    {
        M_BMPDATA->m_mask = new wxMask();
        M_BMPDATA->m_mask->m_bitmap = mask;
    }

    gdk_window_get_size( M_BMPDATA->m_pixmap, &(M_BMPDATA->m_width), &(M_BMPDATA->m_height) );

    M_BMPDATA->m_bpp = visual->depth;  // Can we get a different depth from create_from_xpm_d() ?
}

wxBitmap wxBitmap::Rescale( int clipx, int clipy, int clipwidth, int clipheight, int newx, int newy )
{
    wxCHECK_MSG( Ok(), wxNullBitmap, wxT("invalid bitmap") );

    if (newy==M_BMPDATA->m_width && newy==M_BMPDATA->m_height)
        return *this;

    int width = wxMax(newx, 1);
    int height = wxMax(newy, 1);
    width = wxMin(width, clipwidth);
    height = wxMin(height, clipheight);

    wxBitmap bmp;

    GdkImage *img = NULL;
    if (GetPixmap())
        img = gdk_image_get( GetPixmap(), 0, 0, GetWidth(), GetHeight() );
    else if (GetBitmap())
        img = gdk_image_get( GetBitmap(), 0, 0, GetWidth(), GetHeight() );
    else
        wxFAIL_MSG( wxT("Ill-formed bitmap") );

    wxCHECK_MSG( img, wxNullBitmap, wxT("couldn't create image") );

    int bpp = -1;


    GdkGC *gc = NULL;
    GdkPixmap *dstpix = NULL;
    if (GetPixmap())
    {
        GdkVisual *visual = gdk_window_get_visual( GetPixmap() );
        if (visual == NULL)
            visual = wxTheApp->GetGdkVisual();

        bpp = visual->depth;
        bmp = wxBitmap(width,height,bpp);
        dstpix = bmp.GetPixmap();
        gc = gdk_gc_new( dstpix );
    }

    char *dst = NULL;
    long dstbyteperline = 0;

    if (GetBitmap())
    {
        bpp = 1;
        dstbyteperline = width/8*M_BMPDATA->m_bpp;
        if (width*M_BMPDATA->m_bpp % 8 != 0)
            dstbyteperline++;
        dst = (char*) malloc(dstbyteperline*height);
    }

    // be careful to use the right scaling factor
    float scx = (float)M_BMPDATA->m_width/(float)newx;
    float scy = (float)M_BMPDATA->m_height/(float)newy;
    // prepare accel-tables
    int *tablex = (int *)calloc(width,sizeof(int));
    int *tabley = (int *)calloc(height,sizeof(int));

    // accel table filled with clipped values
    for (int x = 0; x < width; x++)
        tablex[x] = (int) (scx * (x+clipx));
    for (int y = 0; y < height; y++)
        tabley[y] = (int) (scy * (y+clipy));

    // Main rescaling routine starts here
    for (int h = 0; h < height; h++)
    {
        char outbyte = 0;
        int old_x = -1;
        guint32 old_pixval = 0;

        for (int w = 0; w < width; w++)
        {
            guint32 pixval;
            int x = tablex[w];
            if (x == old_x)
                pixval = old_pixval;
            else
            {
                pixval = gdk_image_get_pixel( img, x, tabley[h] );
                old_pixval = pixval;
                old_x = x;
            }

            if (bpp == 1)
            {
                if (!pixval)
                {
                    char bit=1;
                    char shift = bit << (w % 8);
                    outbyte |= shift;
                }

                if ((w+1)%8==0)
                {
                    dst[h*dstbyteperline+w/8] = outbyte;
                    outbyte = 0;
                }
            }
            else
            {
                GdkColor col;
                col.pixel = pixval;
                gdk_gc_set_foreground( gc, &col );
                gdk_draw_point( dstpix, gc, w, h);
            }
        }

        // do not forget the last byte
        if ((bpp == 1) && (width % 8 != 0))
            dst[h*dstbyteperline+width/8] = outbyte;
    }

    gdk_image_destroy( img );
    if (gc) gdk_gc_unref( gc );

    if (bpp == 1)
    {
        bmp = wxBitmap( (const char *)dst, width, height, 1 );
        free( dst );
    }

    if (GetMask())
    {
        dstbyteperline = width/8;
        if (width % 8 != 0)
            dstbyteperline++;
        dst = (char*) malloc(dstbyteperline*height);
        img = gdk_image_get( GetMask()->GetBitmap(), 0, 0, GetWidth(), GetHeight() );

        for (int h = 0; h < height; h++)
        {
            char outbyte = 0;
            int old_x = -1;
            guint32 old_pixval = 0;

            for (int w = 0; w < width; w++)
            {
                guint32 pixval;
                int x = tablex[w];
                if (x == old_x)
                    pixval = old_pixval;
                else
                {
                    pixval = gdk_image_get_pixel( img, x, tabley[h] );
                    old_pixval = pixval;
                    old_x = x;
                }

                if (pixval)
                {
                    char bit=1;
                    char shift = bit << (w % 8);
                    outbyte |= shift;
                }

                if ((w+1)%8 == 0)
                {
                    dst[h*dstbyteperline+w/8] = outbyte;
                    outbyte = 0;
                }
            }

            // do not forget the last byte
            if (width % 8 != 0)
                dst[h*dstbyteperline+width/8] = outbyte;
        }
        wxMask* mask = new wxMask;
        mask->m_bitmap = gdk_bitmap_create_from_data( wxGetRootWindow()->window, (gchar *) dst, width, height );
        bmp.SetMask(mask);

        free( dst );
        gdk_image_destroy( img );
    }

    free( tablex );
    free( tabley );

    return bmp;
}

bool wxBitmap::CreateFromImage(const wxImage& image, int depth)
{
    UnRef();

    wxCHECK_MSG( image.Ok(), false, wxT("invalid image") );
    wxCHECK_MSG( depth == -1 || depth == 1, false, wxT("invalid bitmap depth") );

    if (image.GetWidth() <= 0 || image.GetHeight() <= 0)
        return false;

    m_refData = new wxBitmapRefData();

    if (depth == 1)
    {
        return CreateFromImageAsBitmap(image);
    }
    else
    {
        return CreateFromImageAsPixmap(image);
    }
}

// conversion to mono bitmap:
bool wxBitmap::CreateFromImageAsBitmap(const wxImage& img)
{
    // convert alpha channel to mask, if it is present:
    wxImage image(img);
    image.ConvertAlphaToMask();

    int width = image.GetWidth();
    int height = image.GetHeight();

    SetHeight( height );
    SetWidth( width );

    SetBitmap( gdk_pixmap_new( wxGetRootWindow()->window, width, height, 1 ) );

    SetDepth( 1 );

    GdkVisual *visual = wxTheApp->GetGdkVisual();

    // Create picture image

    unsigned char *data_data = (unsigned char*)malloc( ((width >> 3)+8) * height );

    GdkImage *data_image =
        gdk_image_new_bitmap( visual, data_data, width, height );

    // Create mask image

    GdkImage *mask_image = NULL;

    if (image.HasMask())
    {
        unsigned char *mask_data = (unsigned char*)malloc( ((width >> 3)+8) * height );

        mask_image =  gdk_image_new_bitmap( visual, mask_data, width, height );

        wxMask *mask = new wxMask();
        mask->m_bitmap = gdk_pixmap_new( wxGetRootWindow()->window, width, height, 1 );

        SetMask( mask );
    }

    int r_mask = image.GetMaskRed();
    int g_mask = image.GetMaskGreen();
    int b_mask = image.GetMaskBlue();

    unsigned char* data = image.GetData();

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

            if (image.HasMask())
            {
                if ((r == r_mask) && (b == b_mask) && (g == g_mask))
                    gdk_image_put_pixel( mask_image, x, y, 1 );
                else
                    gdk_image_put_pixel( mask_image, x, y, 0 );
            }

            if ((r == 255) && (b == 255) && (g == 255))
                gdk_image_put_pixel( data_image, x, y, 1 );
            else
                gdk_image_put_pixel( data_image, x, y, 0 );

        } // for
    }  // for

    // Blit picture

    GdkGC *data_gc = gdk_gc_new( GetBitmap() );

    gdk_draw_image( GetBitmap(), data_gc, data_image, 0, 0, 0, 0, width, height );

    gdk_image_destroy( data_image );
    gdk_gc_unref( data_gc );

    // Blit mask

    if (image.HasMask())
    {
        GdkGC *mask_gc = gdk_gc_new( GetMask()->GetBitmap() );

        gdk_draw_image( GetMask()->GetBitmap(), mask_gc, mask_image, 0, 0, 0, 0, width, height );

        gdk_image_destroy( mask_image );
        gdk_gc_unref( mask_gc );
    }

    return true;
}

// conversion to colour bitmap:
bool wxBitmap::CreateFromImageAsPixmap(const wxImage& img)
{
    // convert alpha channel to mask, if it is present:
    wxImage image(img);
    image.ConvertAlphaToMask();

    int width = image.GetWidth();
    int height = image.GetHeight();

    SetHeight( height );
    SetWidth( width );

    SetPixmap( gdk_pixmap_new( wxGetRootWindow()->window, width, height, -1 ) );

    GdkVisual *visual = wxTheApp->GetGdkVisual();

    int bpp = visual->depth;

    SetDepth( bpp );

    if ((bpp == 16) && (visual->red_mask != 0xf800))
        bpp = 15;
    else if (bpp < 8)
        bpp = 8;

    // We handle 8-bit bitmaps ourselves using the colour cube, 12-bit
    // visuals are not supported by GDK so we do these ourselves, too.
    // 15-bit and 16-bit should actually work and 24-bit certainly does.
#ifdef __sgi
    if (!image.HasMask() && (bpp > 16))
#else
    if (!image.HasMask() && (bpp > 12))
#endif
    {
        static bool s_hasInitialized = false;

        if (!s_hasInitialized)
        {
            gdk_rgb_init();
            s_hasInitialized = true;
        }

        GdkGC *gc = gdk_gc_new( GetPixmap() );

        gdk_draw_rgb_image( GetPixmap(),
                            gc,
                            0, 0,
                            width, height,
                            GDK_RGB_DITHER_NONE,
                            image.GetData(),
                            width*3 );

        gdk_gc_unref( gc );
        return true;
    }

    // Create picture image

    GdkImage *data_image =
        gdk_image_new( GDK_IMAGE_FASTEST, visual, width, height );

    // Create mask image

    GdkImage *mask_image = NULL;

    if (image.HasMask())
    {
        unsigned char *mask_data = (unsigned char*)malloc( ((width >> 3)+8) * height );

        mask_image =  gdk_image_new_bitmap( visual, mask_data, width, height );

        wxMask *mask = new wxMask();
        mask->m_bitmap = gdk_pixmap_new( wxGetRootWindow()->window, width, height, 1 );

        SetMask( mask );
    }

    // Render

    enum byte_order { RGB, RBG, BRG, BGR, GRB, GBR };
    byte_order b_o = RGB;

    if (bpp > 8)
    {
        if ((visual->red_mask > visual->green_mask) && (visual->green_mask > visual->blue_mask))      b_o = RGB;
        else if ((visual->red_mask > visual->blue_mask) && (visual->blue_mask > visual->green_mask))  b_o = RBG;
        else if ((visual->blue_mask > visual->red_mask) && (visual->red_mask > visual->green_mask))   b_o = BRG;
        else if ((visual->blue_mask > visual->green_mask) && (visual->green_mask > visual->red_mask)) b_o = BGR;
        else if ((visual->green_mask > visual->red_mask) && (visual->red_mask > visual->blue_mask))   b_o = GRB;
        else if ((visual->green_mask > visual->blue_mask) && (visual->blue_mask > visual->red_mask))  b_o = GBR;
    }

    int r_mask = image.GetMaskRed();
    int g_mask = image.GetMaskGreen();
    int b_mask = image.GetMaskBlue();

    unsigned char* data = image.GetData();

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

            if (image.HasMask())
            {
                if ((r == r_mask) && (b == b_mask) && (g == g_mask))
                    gdk_image_put_pixel( mask_image, x, y, 1 );
                else
                    gdk_image_put_pixel( mask_image, x, y, 0 );
            }

            switch (bpp)
            {
                case 8:
                {
                    int pixel = -1;
                    if (wxTheApp->m_colorCube)
                    {
                        pixel = wxTheApp->m_colorCube[ ((r & 0xf8) << 7) + ((g & 0xf8) << 2) + ((b & 0xf8) >> 3) ];
                    }
                    else
                    {
                        GdkColormap *cmap = gtk_widget_get_default_colormap();
                        GdkColor *colors = cmap->colors;
                        int max = 3 * (65536);

                        for (int i = 0; i < cmap->size; i++)
                        {
                            int rdiff = (r << 8) - colors[i].red;
                            int gdiff = (g << 8) - colors[i].green;
                            int bdiff = (b << 8) - colors[i].blue;
                            int sum = ABS (rdiff) + ABS (gdiff) + ABS (bdiff);
                            if (sum < max) { pixel = i; max = sum; }
                        }
                    }

                    gdk_image_put_pixel( data_image, x, y, pixel );

                    break;
                }
                case 12:  // SGI only
                {
                    guint32 pixel = 0;
                    switch (b_o)
                    {
                        case RGB: pixel = ((r & 0xf0) << 4) | (g & 0xf0) | ((b & 0xf0) >> 4); break;
                        case RBG: pixel = ((r & 0xf0) << 4) | (b & 0xf0) | ((g & 0xf0) >> 4); break;
                        case GRB: pixel = ((g & 0xf0) << 4) | (r & 0xf0) | ((b & 0xf0) >> 4); break;
                        case GBR: pixel = ((g & 0xf0) << 4) | (b & 0xf0) | ((r & 0xf0) >> 4); break;
                        case BRG: pixel = ((b & 0xf0) << 4) | (r & 0xf0) | ((g & 0xf0) >> 4); break;
                        case BGR: pixel = ((b & 0xf0) << 4) | (g & 0xf0) | ((r & 0xf0) >> 4); break;
                    }
                    gdk_image_put_pixel( data_image, x, y, pixel );
                    break;
                }
                case 15:
                {
                    guint32 pixel = 0;
                    switch (b_o)
                    {
                        case RGB: pixel = ((r & 0xf8) << 7) | ((g & 0xf8) << 2) | ((b & 0xf8) >> 3); break;
                        case RBG: pixel = ((r & 0xf8) << 7) | ((b & 0xf8) << 2) | ((g & 0xf8) >> 3); break;
                        case GRB: pixel = ((g & 0xf8) << 7) | ((r & 0xf8) << 2) | ((b & 0xf8) >> 3); break;
                        case GBR: pixel = ((g & 0xf8) << 7) | ((b & 0xf8) << 2) | ((r & 0xf8) >> 3); break;
                        case BRG: pixel = ((b & 0xf8) << 7) | ((r & 0xf8) << 2) | ((g & 0xf8) >> 3); break;
                        case BGR: pixel = ((b & 0xf8) << 7) | ((g & 0xf8) << 2) | ((r & 0xf8) >> 3); break;
                    }
                    gdk_image_put_pixel( data_image, x, y, pixel );
                    break;
                }
                case 16:
                {
                    // I actually don't know if for 16-bit displays, it is alway the green
                    // component or the second component which has 6 bits.
                    guint32 pixel = 0;
                    switch (b_o)
                    {
                        case RGB: pixel = ((r & 0xf8) << 8) | ((g & 0xfc) << 3) | ((b & 0xf8) >> 3); break;
                        case RBG: pixel = ((r & 0xf8) << 8) | ((b & 0xfc) << 3) | ((g & 0xf8) >> 3); break;
                        case GRB: pixel = ((g & 0xf8) << 8) | ((r & 0xfc) << 3) | ((b & 0xf8) >> 3); break;
                        case GBR: pixel = ((g & 0xf8) << 8) | ((b & 0xfc) << 3) | ((r & 0xf8) >> 3); break;
                        case BRG: pixel = ((b & 0xf8) << 8) | ((r & 0xfc) << 3) | ((g & 0xf8) >> 3); break;
                        case BGR: pixel = ((b & 0xf8) << 8) | ((g & 0xfc) << 3) | ((r & 0xf8) >> 3); break;
                    }
                    gdk_image_put_pixel( data_image, x, y, pixel );
                    break;
                }
                case 32:
                case 24:
                {
                    guint32 pixel = 0;
                    switch (b_o)
                    {
                        case RGB: pixel = (r << 16) | (g << 8) | b; break;
                        case RBG: pixel = (r << 16) | (b << 8) | g; break;
                        case BRG: pixel = (b << 16) | (r << 8) | g; break;
                        case BGR: pixel = (b << 16) | (g << 8) | r; break;
                        case GRB: pixel = (g << 16) | (r << 8) | b; break;
                        case GBR: pixel = (g << 16) | (b << 8) | r; break;
                    }
                    gdk_image_put_pixel( data_image, x, y, pixel );
                    break;
                }
                default: break;
            }
        } // for
    }  // for

    // Blit picture

    GdkGC *data_gc = gdk_gc_new( GetPixmap() );

    gdk_draw_image( GetPixmap(), data_gc, data_image, 0, 0, 0, 0, width, height );

    gdk_image_destroy( data_image );
    gdk_gc_unref( data_gc );

    // Blit mask

    if (image.HasMask())
    {
        GdkGC *mask_gc = gdk_gc_new( GetMask()->GetBitmap() );

        gdk_draw_image( GetMask()->GetBitmap(), mask_gc, mask_image, 0, 0, 0, 0, width, height );

        gdk_image_destroy( mask_image );
        gdk_gc_unref( mask_gc );
    }

    return true;
}

wxImage wxBitmap::ConvertToImage() const
{
    wxImage image;

    wxCHECK_MSG( Ok(), wxNullImage, wxT("invalid bitmap") );

    image.Create(GetWidth(), GetHeight());
    unsigned char *data = image.GetData();

    if (!data)
    {
        wxFAIL_MSG( wxT("couldn't create image") );
        return wxNullImage;
    }

    // the colour used as transparent one in wxImage and the one it is
    // replaced with when it really occurs in the bitmap
    static const int MASK_RED = 1;
    static const int MASK_GREEN = 2;
    static const int MASK_BLUE = 3;
    static const int MASK_BLUE_REPLACEMENT = 2;

    GdkImage *gdk_image = NULL;

    if (HasPixmap())
    {
        gdk_image = gdk_image_get( GetPixmap(),
                                    0, 0,
                                    GetWidth(), GetHeight() );
    }
    else if (GetBitmap())
    {
        gdk_image = gdk_image_get( GetBitmap(),
                                    0, 0,
                                    GetWidth(), GetHeight() );
    }
    else
    {
        wxFAIL_MSG( wxT("Ill-formed bitmap") );
    }

    wxCHECK_MSG( gdk_image, wxNullImage, wxT("couldn't create image") );

    GdkImage *gdk_image_mask = NULL;
    if (GetMask())
    {
        gdk_image_mask = gdk_image_get( GetMask()->GetBitmap(),
                                        0, 0,
                                        GetWidth(), GetHeight() );

        image.SetMaskColour( MASK_RED, MASK_GREEN, MASK_BLUE );
    }

    int bpp = -1;
    int red_shift_right = 0;
    int green_shift_right = 0;
    int blue_shift_right = 0;
    int red_shift_left = 0;
    int green_shift_left = 0;
    int blue_shift_left = 0;
    bool use_shift = false;

    if (GetPixmap())
    {
        GdkVisual *visual = gdk_window_get_visual( GetPixmap() );
        if (visual == NULL)
            visual = wxTheApp->GetGdkVisual();

        bpp = visual->depth;
        if (bpp == 16)
            bpp = visual->red_prec + visual->green_prec + visual->blue_prec;
        red_shift_right = visual->red_shift;
        red_shift_left = 8-visual->red_prec;
        green_shift_right = visual->green_shift;
        green_shift_left = 8-visual->green_prec;
        blue_shift_right = visual->blue_shift;
        blue_shift_left = 8-visual->blue_prec;

        use_shift = (visual->type == GDK_VISUAL_TRUE_COLOR) || (visual->type == GDK_VISUAL_DIRECT_COLOR);
    }
    if (GetBitmap())
    {
        bpp = 1;
    }


    GdkColormap *cmap = gtk_widget_get_default_colormap();

    long pos = 0;
    for (int j = 0; j < GetHeight(); j++)
    {
        for (int i = 0; i < GetWidth(); i++)
        {
            wxUint32 pixel = gdk_image_get_pixel( gdk_image, i, j );
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
                data[pos] =   (pixel >> red_shift_right)   << red_shift_left;
                data[pos+1] = (pixel >> green_shift_right) << green_shift_left;
                data[pos+2] = (pixel >> blue_shift_right)  << blue_shift_left;
            }
            else if (cmap->colors)
            {
                data[pos] =   cmap->colors[pixel].red   >> 8;
                data[pos+1] = cmap->colors[pixel].green >> 8;
                data[pos+2] = cmap->colors[pixel].blue  >> 8;
            }
            else
            {
                wxFAIL_MSG( wxT("Image conversion failed. Unknown visual type.") );
            }

            if (gdk_image_mask)
            {
                int mask_pixel = gdk_image_get_pixel( gdk_image_mask, i, j );
                if (mask_pixel == 0)
                {
                    data[pos] = MASK_RED;
                    data[pos+1] = MASK_GREEN;
                    data[pos+2] = MASK_BLUE;
                }
                else if ( data[pos] == MASK_RED &&
                            data[pos+1] == MASK_GREEN &&
                                data[pos+2] == MASK_BLUE )
                {
                    data[pos+2] = MASK_BLUE_REPLACEMENT;
                }
            }

            pos += 3;
        }
    }

    gdk_image_destroy( gdk_image );
    if (gdk_image_mask) gdk_image_destroy( gdk_image_mask );

    return image;
}

wxBitmap::wxBitmap( const wxString &filename, wxBitmapType type )
{
    LoadFile( filename, type );
}

wxBitmap::wxBitmap( const char bits[], int width, int height, int WXUNUSED(depth))
{
    if ( width > 0 && height > 0 )
    {
        m_refData = new wxBitmapRefData();

        M_BMPDATA->m_mask = NULL;
        M_BMPDATA->m_bitmap = gdk_bitmap_create_from_data
                              (
                                wxGetRootWindow()->window,
                                (gchar *) bits,
                                width,
                                height
                              );
        M_BMPDATA->m_width = width;
        M_BMPDATA->m_height = height;
        M_BMPDATA->m_bpp = 1;

        wxASSERT_MSG( M_BMPDATA->m_bitmap, wxT("couldn't create bitmap") );
    }
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
                 (rect.x+rect.width <= M_BMPDATA->m_width) && (rect.y+rect.height <= M_BMPDATA->m_height),
                 wxNullBitmap, wxT("invalid bitmap or bitmap region") );

    wxBitmap ret( rect.width, rect.height, M_BMPDATA->m_bpp );
    wxASSERT_MSG( ret.Ok(), wxT("GetSubBitmap error") );

    if (ret.GetPixmap())
    {
        GdkGC *gc = gdk_gc_new( ret.GetPixmap() );
        gdk_draw_pixmap( ret.GetPixmap(), gc, GetPixmap(), rect.x, rect.y, 0, 0, rect.width, rect.height );
        gdk_gc_destroy( gc );
    }
    else
    {
        GdkGC *gc = gdk_gc_new( ret.GetBitmap() );
        GdkColor col;
        col.pixel = 0xFFFFFF;
        gdk_gc_set_foreground( gc, &col );
        col.pixel = 0;
        gdk_gc_set_background( gc, &col );
        gdk_wx_draw_bitmap( ret.GetBitmap(), gc, GetBitmap(), rect.x, rect.y, 0, 0, rect.width, rect.height );
        gdk_gc_destroy( gc );
    }

    if (GetMask())
    {
        wxMask *mask = new wxMask;
        mask->m_bitmap = gdk_pixmap_new( wxGetRootWindow()->window, rect.width, rect.height, 1 );

        GdkGC *gc = gdk_gc_new( mask->m_bitmap );
        GdkColor col;
        col.pixel = 0xFFFFFF;
        gdk_gc_set_foreground( gc, &col );
        col.pixel = 0;
        gdk_gc_set_background( gc, &col );
        gdk_wx_draw_bitmap( mask->m_bitmap, gc, M_BMPDATA->m_mask->m_bitmap, rect.x, rect.y, 0, 0, rect.width, rect.height );
        gdk_gc_destroy( gc );

        ret.SetMask( mask );
    }

    return ret;
}

bool wxBitmap::SaveFile( const wxString &name, wxBitmapType type, const wxPalette *WXUNUSED(palette) ) const
{
    wxCHECK_MSG( Ok(), false, wxT("invalid bitmap") );

    // Try to save the bitmap via wxImage handlers:
    {
        wxImage image = ConvertToImage();
        if (image.Ok()) return image.SaveFile( name, type );
    }

    return false;
}

bool wxBitmap::LoadFile( const wxString &name, wxBitmapType type )
{
    UnRef();

    if (!wxFileExists(name))
        return false;

    GdkVisual *visual = wxTheApp->GetGdkVisual();

    if (type == wxBITMAP_TYPE_XPM)
    {
        m_refData = new wxBitmapRefData();

        GdkBitmap *mask = NULL;

        M_BMPDATA->m_pixmap = gdk_pixmap_create_from_xpm
                              (
                                wxGetRootWindow()->window,
                                &mask,
                                NULL,
                                name.fn_str()
                              );

        if (mask)
        {
           M_BMPDATA->m_mask = new wxMask();
           M_BMPDATA->m_mask->m_bitmap = mask;
        }

        gdk_window_get_size( M_BMPDATA->m_pixmap, &(M_BMPDATA->m_width), &(M_BMPDATA->m_height) );

        M_BMPDATA->m_bpp = visual->depth;
    }
    else // try if wxImage can load it
    {
        wxImage image;
        if ( !image.LoadFile( name, type ) || !image.Ok() )
            return false;

        *this = wxBitmap(image);
    }

    return true;
}

#if wxUSE_PALETTE
wxPalette *wxBitmap::GetPalette() const
{
    if (!Ok())
        return NULL;

    return M_BMPDATA->m_palette;
}

void wxBitmap::SetPalette(const wxPalette& WXUNUSED(palette))
{
    // TODO
}
#endif // wxUSE_PALETTE

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

void wxBitmap::SetPixmap( GdkPixmap *pixmap )
{
    if (!m_refData)
        m_refData = new wxBitmapRefData();

    M_BMPDATA->m_pixmap = pixmap;
}

void wxBitmap::SetBitmap( GdkPixmap *bitmap )
{
    if (!m_refData)
        m_refData = new wxBitmapRefData();

    M_BMPDATA->m_bitmap = bitmap;
}

GdkPixmap *wxBitmap::GetPixmap() const
{
    wxCHECK_MSG( Ok(), NULL, wxT("invalid bitmap") );

    return M_BMPDATA->m_pixmap;
}

bool wxBitmap::HasPixmap() const
{
    wxCHECK_MSG( Ok(), false, wxT("invalid bitmap") );

    return M_BMPDATA->m_pixmap != NULL;
}

GdkBitmap *wxBitmap::GetBitmap() const
{
    wxCHECK_MSG( Ok(), NULL, wxT("invalid bitmap") );

    return M_BMPDATA->m_bitmap;
}

void *wxBitmap::GetRawData(wxPixelDataBase& WXUNUSED(data), int WXUNUSED(bpp))
{
    return NULL;
}

void wxBitmap::UngetRawData(wxPixelDataBase& WXUNUSED(data))
{
}

bool wxBitmap::HasAlpha() const
{
    return false;
}

/* static */ void wxBitmap::InitStandardHandlers()
{
    // TODO: Insert handler based on GdkPixbufs handler later
}
