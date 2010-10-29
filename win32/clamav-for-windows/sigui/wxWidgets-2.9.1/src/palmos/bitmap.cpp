////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/bitmap.cpp
// Purpose:     wxBitmap
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/08/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

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

#include "wx/bitmap.h"

#ifndef WX_PRECOMP
    #include <stdio.h>

    #include "wx/list.h"
    #include "wx/utils.h"
    #include "wx/app.h"
    #include "wx/palette.h"
    #include "wx/dcmemory.h"
    #include "wx/icon.h"
    #include "wx/log.h"
    #include "wx/image.h"
#endif

#if wxUSE_WXDIB
#include "wx/palmos/dib.h"
#endif

#include "wx/xpmdecod.h"

// missing from mingw32 header
#ifndef CLR_INVALID
    #define CLR_INVALID ((COLORREF)-1)
#endif // no CLR_INVALID

// ----------------------------------------------------------------------------
// Bitmap data
// ----------------------------------------------------------------------------

class WXDLLEXPORT wxBitmapRefData : public wxGDIImageRefData
{
public:
    wxBitmapRefData();
    virtual ~wxBitmapRefData() { Free(); }

    virtual void Free();

    // set the mask object to use as the mask, we take ownership of it
    void SetMask(wxMask *mask)
    {
        delete m_bitmapMask;
        m_bitmapMask = mask;
    }

    // return the mask
    wxMask *GetMask() const { return m_bitmapMask; }

public:
#if wxUSE_PALETTE
    wxPalette     m_bitmapPalette;
#endif // wxUSE_PALETTE

#if wxUSE_WXDIB
    wxDIB *m_dib;
#endif

    bool m_hasAlpha;

    bool m_isDIB;

private:
    wxMask       *m_bitmapMask;

    wxDECLARE_NO_COPY_CLASS(wxBitmapRefData);
};

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxBitmap, wxGDIObject)
IMPLEMENT_DYNAMIC_CLASS(wxMask, wxObject)

IMPLEMENT_DYNAMIC_CLASS(wxBitmapHandler, wxObject)

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// helper functions
// ----------------------------------------------------------------------------

#if !wxUSE_WXDIB
    #define NEVER_USE_DIB
#else
    static inline bool wxShouldCreateDIB(int w, int h, int d, WXHDC hdc)
    {
        // here is the logic:
        //
        //  (a) if hdc is specified, the caller explicitly wants DDB
        //  (b) otherwise, create a DIB if depth >= 24 (we don't support 16bpp
        //      or less DIBs anyhow)
        //  (c) finally, create DIBs under Win9x even if the depth hasn't been
        //      explicitly specified but the current display depth is 24 or
        //      more and the image is "big", i.e. > 16Mb which is the
        //      theoretical limit for DDBs under Win9x
        //
        // consequences (all of which seem to make sense):
        //
        //  (i)     by default, DDBs are created (depth == -1 usually)
        //  (ii)    DIBs can be created by explicitly specifying the depth
        //  (iii)   using a DC always forces creating a DDB
        return !hdc &&
                (d >= 24 ||
                    (d == -1 &&
                        wxDIB::GetLineSize(w, wxDisplayDepth())*h > 16*1024*1024));
    }

    #define SOMETIMES_USE_DIB
#endif // different DIB usage scenarious

// ----------------------------------------------------------------------------
// wxBitmapRefData
// ----------------------------------------------------------------------------

wxBitmapRefData::wxBitmapRefData()
{
    m_bitmapMask = NULL;

    m_hBitmap = (WXHBITMAP) NULL;
#if wxUSE_WXDIB
    m_dib = NULL;
#endif

    m_isDIB =
    m_hasAlpha = false;
}

void wxBitmapRefData::Free()
{
}

// ----------------------------------------------------------------------------
// wxBitmap creation
// ----------------------------------------------------------------------------

// this function should be called from all wxBitmap ctors
void wxBitmap::Init()
{
}

wxGDIImageRefData *wxBitmap::CreateData() const
{
    return NULL;
}

bool wxBitmap::CopyFromCursor(const wxCursor& cursor)
{
    return false;
}

bool wxBitmap::CopyFromIcon(const wxIcon& icon)
{
    return false;
}

#ifndef NEVER_USE_DIB

bool wxBitmap::CopyFromDIB(const wxDIB& dib)
{
    return false:
}

#endif // NEVER_USE_DIB

wxBitmap::wxBitmap(const char bits[], int width, int height, int depth)
{
    Init();
}

wxBitmap::wxBitmap(int w, int h, const wxDC& dc)
{
}

wxBitmap::wxBitmap(const void* data, long type, int width, int height, int depth)
{
}

wxBitmap::wxBitmap(const wxString& filename, wxBitmapType type)
{
}

bool wxBitmap::Create(int width, int height, int depth)
{
    return false;
}

bool wxBitmap::Create(int width, int height, const wxDC& dc)
{
    return false;
}

bool wxBitmap::DoCreate(int w, int h, int d, WXHDC hdc)
{
    return false;
}

#if wxUSE_IMAGE

// ----------------------------------------------------------------------------
// wxImage to/from conversions
// ----------------------------------------------------------------------------

#if wxUSE_WXDIB

bool wxBitmap::CreateFromImage(const wxImage& image, int depth)
{
    return false;
}

bool wxBitmap::CreateFromImage(const wxImage& image, const wxDC& dc)
{
    return false;
}

bool wxBitmap::CreateFromImage(const wxImage& image, int depth, WXHDC hdc)
{
    return false;
}

wxImage wxBitmap::ConvertToImage() const
{
    wxImage image;
    return image;
}

#endif // wxUSE_WXDIB

#endif // wxUSE_IMAGE

// ----------------------------------------------------------------------------
// loading and saving bitmaps
// ----------------------------------------------------------------------------

bool wxBitmap::LoadFile(const wxString& filename, long type)
{
    return false;
}

bool wxBitmap::Create(const void* data, long type, int width, int height, int depth)
{
    return false;
}

bool wxBitmap::SaveFile(const wxString& filename,
                        int type,
                        const wxPalette *palette)
{
    return false;
}

// ----------------------------------------------------------------------------
// sub bitmap extraction
// ----------------------------------------------------------------------------

wxBitmap wxBitmap::GetSubBitmap( const wxRect& rect) const
{
    wxBitmap ret( 0, 0 );
    return ret;
}

// ----------------------------------------------------------------------------
// wxBitmap accessors
// ----------------------------------------------------------------------------

#if wxUSE_PALETTE
wxPalette* wxBitmap::GetPalette() const
{
    return NULL;
}
#endif

wxMask *wxBitmap::GetMask() const
{
    return NULL;
}

bool wxBitmap::HasAlpha() const
{
    return false;
}

// ----------------------------------------------------------------------------
// wxBitmap setters
// ----------------------------------------------------------------------------

#if wxUSE_PALETTE

void wxBitmap::SetPalette(const wxPalette& palette)
{
}

#endif // wxUSE_PALETTE

void wxBitmap::SetMask(wxMask *mask)
{
}

// ----------------------------------------------------------------------------
// raw bitmap access support
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// wxMask
// ----------------------------------------------------------------------------

wxMask::wxMask()
{
    m_maskBitmap = 0;
}

// Construct a mask from a bitmap and a colour indicating
// the transparent area
wxMask::wxMask(const wxBitmap& bitmap, const wxColour& colour)
{
}

// Construct a mask from a bitmap and a palette index indicating
// the transparent area
wxMask::wxMask(const wxBitmap& bitmap, int paletteIndex)
{
}

// Construct a mask from a mono bitmap (copies the bitmap).
wxMask::wxMask(const wxBitmap& bitmap)
{
}

wxMask::~wxMask()
{
}

// Create a mask from a mono bitmap (copies the bitmap).
bool wxMask::Create(const wxBitmap& bitmap)
{
    return false;
}

// Create a mask from a bitmap and a palette index indicating
// the transparent area
bool wxMask::Create(const wxBitmap& bitmap, int paletteIndex)
{
    return false;
}

// Create a mask from a bitmap and a colour indicating
// the transparent area
bool wxMask::Create(const wxBitmap& bitmap, const wxColour& colour)
{
    return false;
}

// ----------------------------------------------------------------------------
// wxBitmapHandler
// ----------------------------------------------------------------------------

bool wxBitmapHandler::Create(wxGDIImage *image,
                             const void* data,
                             long flags,
                             int width, int height, int depth)
{
    return false;
}

bool wxBitmapHandler::Load(wxGDIImage *image,
                           const wxString& name,
                           long flags,
                           int width, int height)
{
    return false;
}

bool wxBitmapHandler::Save(wxGDIImage *image,
                           const wxString& name,
                           int type)
{
    return false;
}

bool wxBitmapHandler::Create(wxBitmap *WXUNUSED(bitmap),
                             const void* WXUNUSED(data),
                             long WXUNUSED(type),
                             int WXUNUSED(width),
                             int WXUNUSED(height),
                             int WXUNUSED(depth))
{
    return false;
}

bool wxBitmapHandler::LoadFile(wxBitmap *WXUNUSED(bitmap),
                               const wxString& WXUNUSED(name),
                               long WXUNUSED(type),
                               int WXUNUSED(desiredWidth),
                               int WXUNUSED(desiredHeight))
{
    return false;
}

bool wxBitmapHandler::SaveFile(wxBitmap *WXUNUSED(bitmap),
                               const wxString& WXUNUSED(name),
                               int WXUNUSED(type),
                               const wxPalette *WXUNUSED(palette))
{
    return false;
}
