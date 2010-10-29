///////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/dib.cpp
// Purpose:     implements wxDIB class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10.13.04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_WXDIB

#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/log.h"
    #include "wx/intl.h"
    #include "wx/bitmap.h"
    #include "wx/image.h"
#endif //WX_PRECOMP

#include "wx/file.h"

#include "wx/palmos/dib.h"

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

// calculate the number of palette entries needed for the bitmap with this
// number of bits per pixel
static inline WORD GetNumberOfColours(WORD bitsPerPixel)
{
    // only 1, 4 and 8bpp bitmaps use palettes (well, they could be used with
    // 24bpp ones too but we don't support this as I think it's quite uncommon)
    return bitsPerPixel <= 8 ? 1 << bitsPerPixel : 0;
}

// wrapper around ::GetObject() for DIB sections
static inline bool GetDIBSection(HBITMAP hbmp, DIBSECTION *ds)
{
    // note that at least under Win9x (this doesn't seem to happen under Win2K
    // but this doesn't mean anything, of course), GetObject() may return
    // sizeof(DIBSECTION) for a bitmap which is *not* a DIB section and the way
    // to check for it is by looking at the bits pointer
    return ::GetObject(hbmp, sizeof(DIBSECTION), ds) == sizeof(DIBSECTION) &&
                ds->dsBm.bmBits;
}

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxDIB creation
// ----------------------------------------------------------------------------

bool wxDIB::Create(int width, int height, int depth)
{
    return false;
}

bool wxDIB::Create(const wxBitmap& bmp)
{
    return false;
}

bool wxDIB::CopyFromDDB(HBITMAP hbmp)
{
    return false;
}


// ----------------------------------------------------------------------------
// Loading/saving the DIBs
// ----------------------------------------------------------------------------

bool wxDIB::Load(const wxString& filename)
{
    return false;
}

bool wxDIB::Save(const wxString& filename)
{
    return false;
}

// ----------------------------------------------------------------------------
// wxDIB accessors
// ----------------------------------------------------------------------------

void wxDIB::DoGetObject() const
{
}

// ----------------------------------------------------------------------------
// DDB <-> DIB conversions
// ----------------------------------------------------------------------------

HBITMAP wxDIB::CreateDDB(HDC hdc) const
{
    return 0;
}

/* static */
HBITMAP wxDIB::ConvertToBitmap(const BITMAPINFO *pbmi, HDC hdc, void *bits)
{
    return 0;
}

/* static */
size_t wxDIB::ConvertFromBitmap(BITMAPINFO *pbi, HBITMAP hbmp)
{
    return 0;
}

/* static */
HGLOBAL wxDIB::ConvertFromBitmap(HBITMAP hbmp)
{
    return NULL;
}

// ----------------------------------------------------------------------------
// palette support
// ----------------------------------------------------------------------------

#if wxUSE_PALETTE

wxPalette *wxDIB::CreatePalette() const
{
    return NULL;
}

#endif // wxUSE_PALETTE

// ----------------------------------------------------------------------------
// wxImage support
// ----------------------------------------------------------------------------

#if wxUSE_IMAGE

bool wxDIB::Create(const wxImage& image)
{
    return false;
}

wxImage wxDIB::ConvertToImage() const
{
    return wxNullImage;
}

#endif // wxUSE_IMAGE

#endif // wxUSE_WXDIB
