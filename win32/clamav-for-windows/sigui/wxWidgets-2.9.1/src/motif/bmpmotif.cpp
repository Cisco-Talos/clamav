/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/bmpmotif.cpp
// Purpose:     wxBitmap
// Author:      Julian Smart, originally in bitmap.cpp
// Modified by:
// Created:     25/03/2003
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/motif/bmpmotif.h"

#ifndef WX_PRECOMP
    #include "wx/math.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

#if wxHAVE_LIB_XPM
    #include <X11/xpm.h>
#endif

Pixmap XCreateInsensitivePixmap( Display *display, Pixmap pixmap );

static inline wxCharBuffer GetCacheImageName(WXImage image)
{
    return wxString::Format(wxT("wxBitmap_%p"), image).ToAscii();
}

wxBitmapCache::~wxBitmapCache()
{
    if( m_display )
    {
        Screen* screen = DefaultScreenOfDisplay( (Display*)m_display );

        if( m_labelPixmap )
            XmDestroyPixmap( screen, (Pixmap)m_labelPixmap );

        if( m_armPixmap )
            XmDestroyPixmap( screen, (Pixmap)m_armPixmap );

        if( m_insensPixmap )
            XmDestroyPixmap( screen, (Pixmap)m_insensPixmap );

    }

    if( m_image )
    {
        XmUninstallImage( (XImage*)m_image );
        XtFree( (char*)(XImage*)m_image );
    }
}

void wxBitmapCache::SetBitmap( const wxBitmap& bitmap )
{
    if ( !m_bitmap.IsSameAs(bitmap) )
    {
        InvalidateCache();
        m_bitmap = bitmap;

        if( m_image )
        {
            XmUninstallImage( (XImage*)m_image );
            XtFree( (char*)(XImage*)m_image );
            m_image = NULL;
        }
    }
}

void wxBitmapCache::InvalidateCache()
{
    m_recalcPixmaps.label  = true;
    m_recalcPixmaps.arm    = true;
    m_recalcPixmaps.insens = true;
}

void wxBitmapCache::SetColoursChanged()
{
    InvalidateCache();
}

void wxBitmapCache::CreateImageIfNeeded( WXWidget w )
{
    if( m_image )
        return;

    m_display = w ?
                (WXDisplay*)XtDisplay( (Widget)w ) :
                (WXDisplay*)wxGetDisplay();

    XImage *ximage = XGetImage( (Display*)m_display,
                                (Drawable)m_bitmap.GetDrawable(),
                                0, 0,
                                m_bitmap.GetWidth(), m_bitmap.GetHeight(),
                                AllPlanes, ZPixmap );

    m_image = (WXImage*)ximage;

    if( m_image )
    {
        XmInstallImage( ximage, GetCacheImageName(m_image).data() );
    }
}

WXPixmap wxBitmapCache::GetPixmapFromCache(WXWidget w)
{
    Widget widget = (Widget)w;
    while( XmIsGadget( widget ) )
        widget = XtParent( widget );

    WXPixel fg, bg;
    XtVaGetValues( widget,
                   XmNbackground, &bg,
                   XmNforeground, &fg,
                   NULL );

    Screen* screen = DefaultScreenOfDisplay( (Display*)m_display );
    return (WXPixmap)XmGetPixmap(screen, GetCacheImageName(m_image).data(), fg, bg);
}

WXPixmap wxBitmapCache::GetLabelPixmap( WXWidget w )
{
    if( m_labelPixmap && !m_recalcPixmaps.label )
        return m_labelPixmap;

    CreateImageIfNeeded( w );

    Screen* screen = DefaultScreenOfDisplay( (Display*)m_display );

    if( m_labelPixmap )
        XmDestroyPixmap( screen, (Pixmap)m_labelPixmap );

    if( !m_image )
        return (WXPixmap)NULL;

    m_labelPixmap = GetPixmapFromCache(w);
    m_recalcPixmaps.label = !m_labelPixmap;
    return m_labelPixmap;
}

WXPixmap wxBitmapCache::GetArmPixmap( WXWidget w )
{
    if( m_armPixmap && !m_recalcPixmaps.arm )
        return m_armPixmap;

    CreateImageIfNeeded( w );

    Screen* screen = DefaultScreenOfDisplay( (Display*)m_display );

    if( m_armPixmap )
        XmDestroyPixmap( screen, (Pixmap)m_armPixmap );

    if( !m_image )
        return (WXPixmap)NULL;

    m_armPixmap = GetPixmapFromCache(w);
    m_recalcPixmaps.arm = !m_armPixmap;
    return m_armPixmap;
}

WXPixmap wxBitmapCache::GetInsensPixmap( WXWidget w )
{
    if( m_insensPixmap && !m_recalcPixmaps.insens )
        return m_insensPixmap;

    CreateImageIfNeeded( w );

    Screen* screen = DefaultScreenOfDisplay( (Display*)m_display );

    if( m_insensPixmap )
        XmDestroyPixmap( screen, (Pixmap)m_insensPixmap );

    if( !m_image )
        return (WXPixmap)NULL;

    m_insensPixmap =
        (WXPixmap)XCreateInsensitivePixmap( (Display*)m_display,
                                            (Pixmap)m_bitmap.GetDrawable() );

    m_recalcPixmaps.insens = !m_insensPixmap;
    return m_insensPixmap;
}

//////////////////////////////////////////////////////////////////////////////
// Utility function
//////////////////////////////////////////////////////////////////////////////

/****************************************************************************

  NAME
  XCreateInsensitivePixmap - create a grayed-out copy of a pixmap

  SYNOPSIS
  Pixmap XCreateInsensitivePixmap( Display *display, Pixmap pixmap )

  DESCRIPTION
  This function creates a grayed-out copy of the argument pixmap, suitable
  for use as a XmLabel's XmNlabelInsensitivePixmap resource.

  RETURN VALUES
  The return value is the new Pixmap id or zero on error.  Errors include
  a NULL display argument or an invalid Pixmap argument.

  ERRORS
  If one of the XLib functions fail, it will produce a X error.  The
  default X error handler prints a diagnostic and calls exit().

  SEE ALSO
  XCopyArea(3), XCreateBitmapFromData(3), XCreateGC(3), XCreatePixmap(3),
  XFillRectangle(3), exit(2)

  AUTHOR
  John R Veregge - john@puente.jpl.nasa.gov
  Advanced Engineering and Prototyping Group (AEG)
  Information Systems Technology Section (395)
  Jet Propulsion Lab - Calif Institute of Technology

*****************************************************************************/

Pixmap
XCreateInsensitivePixmap( Display *display, Pixmap pixmap )

{
    static char stipple_data[] =
        {
            0x55, 0x55, 0xAA, 0xAA, 0x55, 0x55, 0xAA, 0xAA,
            0x55, 0x55, 0xAA, 0xAA, 0x55, 0x55, 0xAA, 0xAA,
            0x55, 0x55, 0xAA, 0xAA, 0x55, 0x55, 0xAA, 0xAA,
            0x55, 0x55, 0xAA, 0xAA, 0x55, 0x55, 0xAA, 0xAA
        };
    GC        gc;
    Pixmap    ipixmap, stipple;
    unsigned    width, height, depth;

    Window    window;    /* These return values */
    unsigned    border;    /* from XGetGeometry() */
    int        x, y;    /* are not needed.     */

    ipixmap = 0;

    if ( NULL == display || 0 == pixmap )
        return ipixmap;

    if ( 0 == XGetGeometry( display, pixmap, &window, &x, &y,
                &width, &height, &border, &depth )
       )
        return ipixmap; /* BadDrawable: probably an invalid pixmap */

    /* Get the stipple pixmap to be used to 'gray-out' the argument pixmap.
     */
    stipple = XCreateBitmapFromData( display, pixmap, stipple_data, 16, 16 );
    if ( 0 != stipple )
    {
        gc = XCreateGC( display, pixmap, (XtGCMask)0, NULL );
        if ( NULL != gc )
        {
            /* Create an identical copy of the argument pixmap.
             */
            ipixmap = XCreatePixmap( display, pixmap, width, height, depth );
            if ( 0 != ipixmap )
            {
                /* Copy the argument pixmap into the new pixmap.
                 */
                XCopyArea( display, pixmap, ipixmap,
                        gc, 0, 0, width, height, 0, 0 );

                /* Refill the new pixmap using the stipple algorithm/pixmap.
                 */
                XSetStipple( display, gc, stipple );
                XSetFillStyle( display, gc, FillStippled );
                XFillRectangle( display, ipixmap, gc, 0, 0, width, height );
            }
            XFreeGC( display, gc );
        }
        XFreePixmap( display, stipple );
    }
    return ipixmap;
}
