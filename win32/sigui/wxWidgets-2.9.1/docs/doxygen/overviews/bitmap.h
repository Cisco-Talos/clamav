/////////////////////////////////////////////////////////////////////////////
// Name:        bitmap.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_bitmap Bitmaps and Icons

Classes:
@li wxBitmap
@li wxBitmapHandler
@li wxIcon
@li wxCursor

The wxBitmap class encapsulates the concept of a platform-dependent bitmap,
either monochrome or colour. Platform-specific methods for creating a wxBitmap
object from an existing file are catered for, and this is an occasion where
conditional compilation will sometimes be required.

A bitmap created dynamically or loaded from a file can be selected into a
memory device context (instance of wxMemoryDC). This enables the bitmap to be
copied to a window or memory device context using wxDC::Blit(), or to be used
as a drawing surface.

See wxMemoryDC for an example of drawing onto a bitmap.

All wxWidgets platforms support XPMs for small bitmaps and icons. You may
include the XPM inline as below, since it's C code, or you can load it at
run-time.

@code
#include "sample.xpm"
@endcode

Sometimes you wish to use a .ico resource on Windows, and XPMs on other
platforms (for example to take advantage of Windows' support for multiple icon
resolutions).

A macro, wxICON(), is available which creates an icon using an XPM on the
appropriate platform, or an icon resource on Windows:

@code
wxIcon icon(wxICON(sample));

// The above line is equivalent to this:

#if defined(__WXGTK__) || defined(__WXMOTIF__)
    wxIcon icon(sample_xpm);
#endif

#if defined(__WXMSW__)
    wxIcon icon("sample");
#endif
@endcode

There is also a corresponding wxBITMAP() macro which allows to create the
bitmaps in much the same way as wxICON() creates icons. It assumes that bitmaps
live in resources under Windows or OS2 and XPM files under all other platforms
(for XPMs, the corresponding file must be included before this macro is used,
of course, and the name of the bitmap should be the same as the resource name
under Windows with @c _xpm suffix). For example:

@code
// an easy and portable way to create a bitmap
wxBitmap bmp(wxBITMAP(bmpname));

// which is roughly equivalent to the following
#if defined(__WXMSW__) || defined(__WXPM__)
    wxBitmap bmp("bmpname", wxBITMAP_TYPE_RESOURCE);
#else // Unix
    wxBitmap bmp(bmpname_xpm, wxBITMAP_TYPE_XPM);
#endif
@endcode

You should always use wxICON() and wxBITMAP() macros because they work for any
platform (unlike the code above which doesn't deal with wxMac, wxX11, ...) and
are shorter and more clear than versions with many @ifdef_ blocks. Even better,
use the same XPMs on all platforms.

@li @ref overview_bitmap_supportedformats
@li @ref overview_bitmap_handlers


<hr>


@section overview_bitmap_supportedformats Supported Bitmap File Formats

The following lists the formats handled on different platforms. Note that
missing or partially-implemented formats are automatically supplemented by
using wxImage to load the data, and then converting it to wxBitmap form. Note
that using wxImage is the preferred way to load images in wxWidgets, with the
exception of resources (XPM-files or native Windows resources).

Writing an image format handler for wxImage is also far easier than writing one
for wxBitmap, because wxImage has exactly one format on all platforms whereas
wxBitmap can store pixel data very differently, depending on colour depths and
platform.

@subsection overview_bitmap_supportedformats_bmp wxBitmap

Under Windows, wxBitmap may load the following formats:

    @li Windows bitmap resource (wxBITMAP_TYPE_BMP_RESOURCE)
    @li Windows bitmap file (wxBITMAP_TYPE_BMP)
    @li XPM data and file (wxBITMAP_TYPE_XPM)
    @li All formats that are supported by the wxImage class.

Under wxGTK, wxBitmap may load the following formats:

    @li XPM data and file (wxBITMAP_TYPE_XPM)
    @li All formats that are supported by the wxImage class.

Under wxMotif and wxX11, wxBitmap may load the following formats:

    @li XBM data and file (wxBITMAP_TYPE_XBM)
    @li XPM data and file (wxBITMAP_TYPE_XPM)
    @li All formats that are supported by the wxImage class.

@subsection overview_bitmap_supportedformats_icon wxIcon

Under Windows, wxIcon may load the following formats:

    @li Windows icon resource (wxBITMAP_TYPE_ICO_RESOURCE)
    @li Windows icon file (wxBITMAP_TYPE_ICO)
    @li XPM data and file (wxBITMAP_TYPE_XPM)

Under wxGTK, wxIcon may load the following formats:

    @li XPM data and file (wxBITMAP_TYPE_XPM)
    @li All formats that are supported by the wxImage class.

Under wxMotif and wxX11, wxIcon may load the following formats:

    @li XBM data and file (wxBITMAP_TYPE_XBM)
    @li XPM data and file (wxBITMAP_TYPE_XPM)
    @li All formats that are supported by the wxImage class.

@subsection overview_bitmap_supportedformats_cursor wxCursor

Under Windows, wxCursor may load the following formats:

    @li Windows cursor resource (wxBITMAP_TYPE_CUR_RESOURCE)
    @li Windows cursor file (wxBITMAP_TYPE_CUR)
    @li Windows icon file (wxBITMAP_TYPE_ICO)
    @li Windows bitmap file (wxBITMAP_TYPE_BMP)

Under wxGTK, wxCursor may load the following formats (in addition to stock
cursors):

    @li None (stock cursors only).

Under wxMotif and wxX11, wxCursor may load the following formats:

    @li XBM data and file (wxBITMAP_TYPE_XBM)


@section overview_bitmap_handlers Bitmap Format Handlers

To provide extensibility, the functionality for loading and saving bitmap
formats is not implemented in the wxBitmap class, but in a number of handler
classes, derived from wxBitmapHandler. There is a static list of handlers which
wxBitmap examines when a file load/save operation is requested.

Some handlers are provided as standard, but if you have special requirements,
you may wish to initialise the wxBitmap class with some extra handlers which
you write yourself or receive from a third party.

To add a handler object to wxBitmap, your application needs to include the
header which implements it, and then call the static function
wxBitmap::AddHandler().

@note Bitmap handlers are not implemented on all platforms, and new ones rarely
need to be implemented since wxImage can be used for loading most formats, as
noted earlier.

*/

