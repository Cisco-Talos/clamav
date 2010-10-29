/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/bitmap.h
// Purpose:     wxBitmap class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_BITMAP_H_
#define _WX_BITMAP_H_

#include "wx/palmos/gdiimage.h"
#include "wx/gdicmn.h"
#include "wx/palette.h"

class WXDLLIMPEXP_FWD_CORE wxBitmap;
class WXDLLIMPEXP_FWD_CORE wxBitmapHandler;
class WXDLLIMPEXP_FWD_CORE wxBitmapRefData;
class WXDLLIMPEXP_FWD_CORE wxControl;
class WXDLLIMPEXP_FWD_CORE wxCursor;
class WXDLLIMPEXP_FWD_CORE wxDC;
#if wxUSE_WXDIB
class WXDLLIMPEXP_FWD_CORE wxDIB;
#endif
class WXDLLIMPEXP_FWD_CORE wxIcon;
class WXDLLIMPEXP_FWD_CORE wxImage;
class WXDLLIMPEXP_FWD_CORE wxMask;
class WXDLLIMPEXP_FWD_CORE wxPalette;
class WXDLLIMPEXP_FWD_CORE wxPixelDataBase;

// ----------------------------------------------------------------------------
// wxBitmap: a mono or colour bitmap
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxBitmap : public wxGDIImage
{
public:
    // default ctor creates an invalid bitmap, you must Create() it later
    wxBitmap() { Init(); }

    // Initialize with raw data
    wxBitmap(const char bits[], int width, int height, int depth = 1);

    // Initialize with XPM data
    wxBitmap(const char* const* data);

    // Load a file or resource
    wxBitmap(const wxString& name, wxBitmapType type = wxBITMAP_DEFAULT_TYPE);

    // New constructor for generalised creation from data
    wxBitmap(const void* data, long type, int width, int height, int depth = 1);

    // Create a new, uninitialized bitmap of the given size and depth (if it
    // is omitted, will create a bitmap compatible with the display)
    //
    // NB: this ctor will create a DIB for 24 and 32bpp bitmaps, use ctor
    //     taking a DC argument if you want to force using DDB in this case
    wxBitmap(int width, int height, int depth = -1) { /*TODO*/ }
    wxBitmap(const wxSize& sz, int depth = -1) { /*TODO*/ }

    // Create a bitmap compatible with the given DC
    wxBitmap(int width, int height, const wxDC& dc);

#if wxUSE_IMAGE && wxUSE_WXDIB
    // Convert from wxImage
    wxBitmap(const wxImage& image, int depth = -1)
        { (void)CreateFromImage(image, depth); }

    // Create a DDB compatible with the given DC from wxImage
    wxBitmap(const wxImage& image, const wxDC& dc)
        { (void)CreateFromImage(image, dc); }
#endif // wxUSE_IMAGE

    // we must have this, otherwise icons are silently copied into bitmaps using
    // the copy ctor but the resulting bitmap is invalid!
    wxBitmap(const wxIcon& icon) { Init(); CopyFromIcon(icon); }

    wxBitmap& operator=(const wxIcon& icon)
    {
        (void)CopyFromIcon(icon);

        return *this;
    }

    wxBitmap& operator=(const wxCursor& cursor)
    {
        (void)CopyFromCursor(cursor);

        return *this;
    }

    virtual ~wxBitmap() {}

#if wxUSE_IMAGE && wxUSE_WXDIB
    wxImage ConvertToImage() const;
#endif // wxUSE_IMAGE

    // get the given part of bitmap
    wxBitmap GetSubBitmap( const wxRect& rect ) const;

    // copies the contents and mask of the given (colour) icon to the bitmap
    bool CopyFromIcon(const wxIcon& icon);

    // copies the contents and mask of the given cursor to the bitmap
    bool CopyFromCursor(const wxCursor& cursor);

#if wxUSE_WXDIB
    // copies from a device independent bitmap
    bool CopyFromDIB(const wxDIB& dib);
#endif

    virtual bool Create(int width, int height, int depth = wxBITMAP_SCREEN_DEPTH);
    virtual bool Create(const wxSize& sz, int depth = wxBITMAP_SCREEN_DEPTH)
        { return Create(sz.GetWidth(), sz.GetHeight(), depth); }

    virtual bool Create(int width, int height, const wxDC& dc);
    virtual bool Create(const void* data, long type, int width, int height, int depth = 1);
    virtual bool LoadFile(const wxString& name, long type = wxBITMAP_DEFAULT_TYPE);
    virtual bool SaveFile(const wxString& name, int type, const wxPalette *cmap = NULL);

    wxBitmapRefData *GetBitmapData() const
        { return (wxBitmapRefData *)m_refData; }

    // raw bitmap access support functions
    void *GetRawData(wxPixelDataBase& data, int bpp);
    void UngetRawData(wxPixelDataBase& data);

#if wxUSE_PALETTE
    wxPalette* GetPalette() const;
    void SetPalette(const wxPalette& palette);
#endif // wxUSE_PALETTE

    wxMask *GetMask() const;
    void SetMask(wxMask *mask);

    // these functions are internal and shouldn't be used, they risk to
    // disappear in the future
    bool HasAlpha() const;

    // implementation only from now on
    // -------------------------------

public:
    void SetHBITMAP(WXHBITMAP bmp) { SetHandle((WXHANDLE)bmp); }
    WXHBITMAP GetHBITMAP() const { return (WXHBITMAP)GetHandle(); }

protected:
    // common part of all ctors
    void Init();

    virtual wxGDIImageRefData *CreateData() const;

    // creates an uninitialized bitmap, called from Create()s above
    bool DoCreate(int w, int h, int depth, WXHDC hdc);

#if wxUSE_IMAGE && wxUSE_WXDIB
    // creates the bitmap from wxImage, supposed to be called from ctor
    bool CreateFromImage(const wxImage& image, int depth);

    // creates a DDB from wxImage, supposed to be called from ctor
    bool CreateFromImage(const wxImage& image, const wxDC& dc);

    // common part of the 2 methods above (hdc may be 0)
    bool CreateFromImage(const wxImage& image, int depth, WXHDC hdc);
#endif // wxUSE_IMAGE

private:
    DECLARE_DYNAMIC_CLASS(wxBitmap)
};

// ----------------------------------------------------------------------------
// wxMask: a mono bitmap used for drawing bitmaps transparently.
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxMask : public wxObject
{
public:
    wxMask();

    // Construct a mask from a bitmap and a colour indicating the transparent
    // area
    wxMask(const wxBitmap& bitmap, const wxColour& colour);

    // Construct a mask from a bitmap and a palette index indicating the
    // transparent area
    wxMask(const wxBitmap& bitmap, int paletteIndex);

    // Construct a mask from a mono bitmap (copies the bitmap).
    wxMask(const wxBitmap& bitmap);

    // construct a mask from the givne bitmap handle
    wxMask(WXHBITMAP hbmp) { m_maskBitmap = hbmp; }

    virtual ~wxMask();

    bool Create(const wxBitmap& bitmap, const wxColour& colour);
    bool Create(const wxBitmap& bitmap, int paletteIndex);
    bool Create(const wxBitmap& bitmap);

    // Implementation
    WXHBITMAP GetMaskBitmap() const { return m_maskBitmap; }
    void SetMaskBitmap(WXHBITMAP bmp) { m_maskBitmap = bmp; }

protected:
    WXHBITMAP m_maskBitmap;

    DECLARE_DYNAMIC_CLASS(wxMask)
};

// ----------------------------------------------------------------------------
// wxBitmapHandler is a class which knows how to load/save bitmaps to/from file
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxBitmapHandler : public wxGDIImageHandler
{
public:
    wxBitmapHandler() { m_type = wxBITMAP_TYPE_INVALID; }
    wxBitmapHandler(const wxString& name, const wxString& ext, long type)
        : wxGDIImageHandler(name, ext, type)
    {
    }

    // keep wxBitmapHandler derived from wxGDIImageHandler compatible with the
    // old class which worked only with bitmaps
    virtual bool Create(wxBitmap *bitmap,
                        const void* data,
                        long flags,
                        int width, int height, int depth = 1);
    virtual bool LoadFile(wxBitmap *bitmap,
                          const wxString& name,
                          long flags,
                          int desiredWidth, int desiredHeight);
    virtual bool SaveFile(wxBitmap *bitmap,
                          const wxString& name,
                          int type,
                          const wxPalette *palette = NULL);

    virtual bool Create(wxGDIImage *image,
                        const void* data,
                        long flags,
                        int width, int height, int depth = 1);
    virtual bool Load(wxGDIImage *image,
                      const wxString& name,
                      long flags,
                      int desiredWidth, int desiredHeight);
    virtual bool Save(wxGDIImage *image,
                      const wxString& name,
                      int type);

private:
    DECLARE_DYNAMIC_CLASS(wxBitmapHandler)
};

#endif
  // _WX_BITMAP_H_
