/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/dc.cpp
// Purpose:     wxDC class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ===========================================================================
// declarations
// ===========================================================================

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

#include <string.h>

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/image.h"
    #include "wx/window.h"
    #include "wx/dc.h"
    #include "wx/utils.h"
    #include "wx/dialog.h"
    #include "wx/app.h"
    #include "wx/bitmap.h"
    #include "wx/dcmemory.h"
    #include "wx/log.h"
    #include "wx/icon.h"
    #include "wx/dcprint.h"
    #include "wx/module.h"
#endif

#include "wx/sysopt.h"
#include "wx/dynlib.h"

#include "wx/palmos/dc.h"

#ifndef AC_SRC_ALPHA
    #define AC_SRC_ALPHA 1
#endif

#ifndef LAYOUT_RTL
    #define LAYOUT_RTL 1
#endif

/* Quaternary raster codes */
#ifndef MAKEROP4
#define MAKEROP4(fore,back) (DWORD)((((back) << 8) & 0xFF000000) | (fore))
#endif

// apparently with MicroWindows it is possible that HDC is 0 so we have to
// check for this ourselves
#ifdef __WXMICROWIN__
    #define WXMICROWIN_CHECK_HDC if ( !GetHDC() ) return;
    #define WXMICROWIN_CHECK_HDC_RET(x) if ( !GetHDC() ) return x;
#else
    #define WXMICROWIN_CHECK_HDC
    #define WXMICROWIN_CHECK_HDC_RET(x)
#endif

IMPLEMENT_ABSTRACT_CLASS(wxPalmDCImpl, wxDCImpl)

// ---------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------

// ROPs which don't have standard names (see "Ternary Raster Operations" in the
// MSDN docs for how this and other numbers in wxDC::Blit() are obtained)
#define DSTCOPY 0x00AA0029      // a.k.a. NOP operation

// ----------------------------------------------------------------------------
// macros for logical <-> device coords conversion
// ----------------------------------------------------------------------------

/*
   We currently let Windows do all the translations itself so these macros are
   not really needed (any more) but keep them to enhance readability of the
   code by allowing to see where are the logical and where are the device
   coordinates used.
 */

#ifdef __WXWINCE__
    #define XLOG2DEV(x) ((x-m_logicalOriginX)*m_signX)
    #define YLOG2DEV(y) ((y-m_logicalOriginY)*m_signY)
    #define XDEV2LOG(x) ((x)*m_signX+m_logicalOriginX)
    #define YDEV2LOG(y) ((y)*m_signY+m_logicalOriginY)
#else
    #define XLOG2DEV(x) (x)
    #define YLOG2DEV(y) (y)
    #define XDEV2LOG(x) (x)
    #define YDEV2LOG(y) (y)
#endif

// ---------------------------------------------------------------------------
// private functions
// ---------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------

#if wxUSE_DYNLIB_CLASS

// helper class to cache dynamically loaded libraries and not attempt reloading
// them if it fails
class wxOnceOnlyDLLLoader
{
public:
    // ctor argument must be a literal string as we don't make a copy of it!
    wxOnceOnlyDLLLoader(const wxChar *dllName)
        : m_dllName(dllName)
    {
    }


    // return the symbol with the given name or NULL if the DLL not loaded
    // or symbol not present
    void *GetSymbol(const wxChar *name)
    {
        // we're prepared to handle errors here
        wxLogNull noLog;

        if ( m_dllName )
        {
            m_dll.Load(m_dllName);

            // reset the name whether we succeeded or failed so that we don't
            // try again the next time
            m_dllName = NULL;
        }

        return m_dll.IsLoaded() ? m_dll.GetSymbol(name) : NULL;
    }

    void Unload()
    {
        if ( m_dll.IsLoaded() )
        {
            m_dll.Unload();
        }
    }

private:
    wxDynamicLibrary m_dll;
    const wxChar *m_dllName;
};

#endif // wxUSE_DYNLIB_CLASS

// ===========================================================================
// implementation
// ===========================================================================

// ---------------------------------------------------------------------------
// wxPalmDCImpl
// ---------------------------------------------------------------------------

wxPalmDCImpl::wxPalmDCImpl( wxDC *owner, WXHDC hDC ) :
    wxDCImpl( owner )
{
    Init();
    m_hDC = hDC;
}

wxPalmDCImpl::~wxPalmDCImpl()
{
}

// This will select current objects out of the DC,
// which is what you have to do before deleting the
// DC.
void wxPalmDCImpl::SelectOldObjects(WXHDC dc)
{
}

// ---------------------------------------------------------------------------
// clipping
// ---------------------------------------------------------------------------

void wxPalmDCImpl::UpdateClipBox()
{
}

void
wxPalmDCImpl::DoGetClippingBox(wxCoord *x, wxCoord *y, wxCoord *w, wxCoord *h) const
{
}

void wxPalmDCImpl::DoSetClippingRegion(wxCoord x, wxCoord y, wxCoord w, wxCoord h)
{
}

void wxPalmDCImpl::DoSetDeviceClippingRegion(const wxRegion& region)
{
}

void wxPalmDCImpl::DestroyClippingRegion()
{
}

// ---------------------------------------------------------------------------
// query capabilities
// ---------------------------------------------------------------------------

bool wxPalmDCImpl::CanDrawBitmap() const
{
    return false;
}

bool wxPalmDCImpl::CanGetTextExtent() const
{
    return false;
}

int wxPalmDCImpl::GetDepth() const
{
    return 0;
}

// ---------------------------------------------------------------------------
// drawing
// ---------------------------------------------------------------------------

void wxPalmDCImpl::Clear()
{
}

bool wxPalmDCImpl::DoFloodFill(wxCoord WXUNUSED_IN_WINCE(x),
                       wxCoord WXUNUSED_IN_WINCE(y),
                       const wxColour& WXUNUSED_IN_WINCE(col),
                       wxFloodFillStyle WXUNUSED_IN_WINCE(style))
{
    return false;
}

bool wxPalmDCImpl::DoGetPixel(wxCoord x, wxCoord y, wxColour *col) const
{
    return false;
}

void wxPalmDCImpl::DoCrossHair(wxCoord x, wxCoord y)
{
}

void wxPalmDCImpl::DoDrawLine(wxCoord x1, wxCoord y1, wxCoord x2, wxCoord y2)
{
}

// Draws an arc of a circle, centred on (xc, yc), with starting point (x1, y1)
// and ending at (x2, y2)
void wxPalmDCImpl::DoDrawArc(wxCoord x1, wxCoord y1,
                     wxCoord x2, wxCoord y2,
                     wxCoord xc, wxCoord yc)
{
}

void wxPalmDCImpl::DoDrawCheckMark(wxCoord x1, wxCoord y1,
                           wxCoord width, wxCoord height)
{
}

void wxPalmDCImpl::DoDrawPoint(wxCoord x, wxCoord y)
{
}

void wxPalmDCImpl::DoDrawPolygon(int n,
                         wxPoint points[],
                         wxCoord xoffset,
                         wxCoord yoffset,
                         wxPolygonFillMode WXUNUSED_IN_WINCE(fillStyle))
{
}

void
wxPalmDCImpl::DoDrawPolyPolygon(int n,
                        int count[],
                        wxPoint points[],
                        wxCoord xoffset,
                        wxCoord yoffset,
                        wxPolygonFillMode fillStyle)
{
}

void wxPalmDCImpl::DoDrawLines(int n, wxPoint points[], wxCoord xoffset, wxCoord yoffset)
{
}

void wxPalmDCImpl::DoDrawRectangle(wxCoord x, wxCoord y, wxCoord width, wxCoord height)
{
}

void wxPalmDCImpl::DoDrawRoundedRectangle(wxCoord x, wxCoord y, wxCoord width, wxCoord height, double radius)
{
}

void wxPalmDCImpl::DoDrawEllipse(wxCoord x, wxCoord y, wxCoord width, wxCoord height)
{
}

#if wxUSE_SPLINES
void wxPalmDCImpl::DoDrawSpline(const wxPointList *points)
{
}
#endif

// Chris Breeze 20/5/98: first implementation of DrawEllipticArc on Windows
void wxPalmDCImpl::DoDrawEllipticArc(wxCoord x,wxCoord y,wxCoord w,wxCoord h,double sa,double ea)
{
}

void wxPalmDCImpl::DoDrawIcon(const wxIcon& icon, wxCoord x, wxCoord y)
{
}

void wxPalmDCImpl::DoDrawBitmap( const wxBitmap &bmp, wxCoord x, wxCoord y, bool useMask )
{
}

void wxPalmDCImpl::DoDrawText(const wxString& text, wxCoord x, wxCoord y)
{
}

void wxPalmDCImpl::DrawAnyText(const wxString& text, wxCoord x, wxCoord y)
{
}

void wxPalmDCImpl::DoDrawRotatedText(const wxString& text,
                             wxCoord x, wxCoord y,
                             double angle)
{
}

// ---------------------------------------------------------------------------
// set GDI objects
// ---------------------------------------------------------------------------

#if wxUSE_PALETTE

void wxPalmDCImpl::DoSelectPalette(bool realize)
{
}

void wxPalmDCImpl::SetPalette(const wxPalette& palette)
{
}

void wxPalmDCImpl::InitializePalette()
{
}

#endif // wxUSE_PALETTE

// SetFont/Pen/Brush() really ask to be implemented as a single template
// function... but doing it is not worth breaking OpenWatcom build <sigh>

void wxPalmDCImpl::SetFont(const wxFont& font)
{
}

void wxPalmDCImpl::SetPen(const wxPen& pen)
{
}

void wxPalmDCImpl::SetBrush(const wxBrush& brush)
{
}

void wxPalmDCImpl::SetBackground(const wxBrush& brush)
{
}

void wxPalmDCImpl::SetBackgroundMode(int mode)
{
}

void wxPalmDCImpl::SetLogicalFunction(wxRasterOperationMode function)
{
}

void wxPalmDCImpl::SetRop(WXHDC dc)
{
}

bool wxPalmDCImpl::StartDoc(const wxString& WXUNUSED(message))
{
    // We might be previewing, so return true to let it continue.
    return true;
}

void wxPalmDCImpl::EndDoc()
{
}

void wxPalmDCImpl::StartPage()
{
}

void wxPalmDCImpl::EndPage()
{
}

// ---------------------------------------------------------------------------
// text metrics
// ---------------------------------------------------------------------------

wxCoord wxPalmDCImpl::GetCharHeight() const
{
    return 0;
}

wxCoord wxPalmDCImpl::GetCharWidth() const
{
    return 0;
}

void wxPalmDCImpl::DoGetTextExtent(const wxString& string, wxCoord *x, wxCoord *y,
                           wxCoord *descent, wxCoord *externalLeading,
                           const wxFont *font) const
{
}


// Each element of the array will be the width of the string up to and
// including the coresoponding character in text.

bool wxPalmDCImpl::DoGetPartialTextExtents(const wxString& text, wxArrayInt& widths) const
{
    return false;
}

void wxPalmDCImpl::RealizeScaleAndOrigin()
{
}

void wxPalmDCImpl::SetMapMode(wxMappingMode mode)
{
}

void wxPalmDCImpl::SetUserScale(double x, double y)
{
}

void wxPalmDCImpl::SetAxisOrientation(bool xLeftRight,
                              bool yBottomUp)
{
}

void wxPalmDCImpl::SetLogicalOrigin(wxCoord x, wxCoord y)
{
}

void wxPalmDCImpl::SetDeviceOrigin(wxCoord x, wxCoord y)
{
}

// ---------------------------------------------------------------------------
// bit blit
// ---------------------------------------------------------------------------

bool wxPalmDCImpl::DoBlit(wxCoord dstX, wxCoord dstY,
                  wxCoord dstWidth, wxCoord dstHeight,
                  wxDC *source,
                  wxCoord srcX, wxCoord srcY,
                  wxRasterOperationMode rop, bool useMask,
                  wxCoord srcMaskX, wxCoord srcMaskY)
{
    return false;
}

bool wxPalmDCImpl::DoStretchBlit(wxCoord xdest, wxCoord ydest,
                         wxCoord dstWidth, wxCoord dstHeight,
                         wxDC *source,
                         wxCoord xsrc, wxCoord ysrc,
                         wxCoord srcWidth, wxCoord srcHeight,
                         wxRasterOperationMode rop, bool useMask,
                         wxCoord xsrcMask, wxCoord ysrcMask)
{
    return false;
}

void wxPalmDCImpl::GetDeviceSize(int *width, int *height) const
{
}

void wxPalmDCImpl::DoGetSizeMM(int *w, int *h) const
{
}

wxSize wxPalmDCImpl::GetPPI() const
{
    return wxSize(0, 0);
}

// For use by wxWidgets only, unless custom units are required.
void wxPalmDCImpl::SetLogicalScale(double x, double y)
{
}

// ----------------------------------------------------------------------------
// DC caching
// ----------------------------------------------------------------------------

#if wxUSE_DC_CACHEING

/*
 * This implementation is a bit ugly and uses the old-fashioned wxList class, so I will
 * improve it in due course, either using arrays, or simply storing pointers to one
 * entry for the bitmap, and two for the DCs. -- JACS
 */

wxObjectList wxPalmDCImpl::sm_bitmapCache;
wxObjectList wxPalmDCImpl::sm_dcCache;

wxDCCacheEntry::wxDCCacheEntry(WXHBITMAP hBitmap, int w, int h, int depth)
{
    m_bitmap = hBitmap;
    m_dc = 0;
    m_width = w;
    m_height = h;
    m_depth = depth;
}

wxDCCacheEntry::wxDCCacheEntry(WXHDC hDC, int depth)
{
}

wxDCCacheEntry::~wxDCCacheEntry()
{
}

wxDCCacheEntry* wxPalmDCImpl::FindBitmapInCache(WXHDC dc, int w, int h)
{
    return NULL;
}

wxDCCacheEntry* wxPalmDCImpl::FindDCInCache(wxDCCacheEntry* notThis, WXHDC dc)
{
    return NULL;
}

void wxPalmDCImpl::AddToBitmapCache(wxDCCacheEntry* entry)
{
}

void wxPalmDCImpl::AddToDCCache(wxDCCacheEntry* entry)
{
}

void wxPalmDCImpl::ClearCache()
{
}

// Clean up cache at app exit
class wxDCModule : public wxModule
{
public:
    virtual bool OnInit() { return true; }
    virtual void OnExit() { wxPalmDCImpl::ClearCache(); }

private:
    DECLARE_DYNAMIC_CLASS(wxDCModule)
};

IMPLEMENT_DYNAMIC_CLASS(wxDCModule, wxModule)

#endif // wxUSE_DC_CACHEING

void wxPalmDCImpl::DoGradientFillLinear (const wxRect& rect,
                                 const wxColour& initialColour,
                                 const wxColour& destColour,
                                 wxDirection nDirection)
{
}

#if wxUSE_DYNLIB_CLASS

wxLayoutDirection wxPalmDCImpl::GetLayoutDirection() const
{
    DWORD layout = wxGetDCLayout(GetHdc());

    if ( layout == (DWORD)-1 )
        return wxLayout_Default;

    return layout & LAYOUT_RTL ? wxLayout_RightToLeft : wxLayout_LeftToRight;
}

void wxPalmDCImpl::SetLayoutDirection(wxLayoutDirection dir)
{
}

#else // !wxUSE_DYNLIB_CLASS

// we can't provide RTL support without dynamic loading, so stub it out
wxLayoutDirection wxPalmDCImpl::GetLayoutDirection() const
{
    return wxLayout_Default;
}

void wxPalmDCImpl::SetLayoutDirection(wxLayoutDirection WXUNUSED(dir))
{
}

#endif // wxUSE_DYNLIB_CLASS/!wxUSE_DYNLIB_CLASS
