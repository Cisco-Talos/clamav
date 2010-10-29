/////////////////////////////////////////////////////////////////////////////
// Name:        bitmap.h
// Author:      Vaclav Slavik
// RCS-ID:      $Id$
// Copyright:   (c) 2001-2002 SciTech Software, Inc. (www.scitechsoft.com)
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef __WX_BITMAP_H__
#define __WX_BITMAP_H__

//-----------------------------------------------------------------------------
// classes
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_FWD_CORE wxDC;
class WXDLLIMPEXP_FWD_CORE wxMemoryDC;

class MGLDevCtx;
struct bitmap_t;

//-----------------------------------------------------------------------------
// wxBitmap
//-----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxBitmap: public wxBitmapBase
{
public:
    wxBitmap() {}
    wxBitmap(int width, int height, int depth = -1)
        { Create(width, height, depth); }
    wxBitmap(const wxSize& sz, int depth = -1)
        { Create(sz, depth); }
    wxBitmap(const char bits[], int width, int height, int depth = 1);
    wxBitmap(const char* const* bits);
    wxBitmap(const wxString &filename, wxBitmapType type = wxBITMAP_DEFAULT_TYPE);
    wxBitmap(const wxImage& image, int depth = -1);
    virtual ~wxBitmap() {}

    bool Create(int width, int height, int depth = wxBITMAP_SCREEN_DEPTH);
    bool Create(const wxSize& sz, int depth = wxBITMAP_SCREEN_DEPTH)
        { return Create(sz.GetWidth(), sz.GetHeight(), depth); }

    virtual int GetHeight() const;
    virtual int GetWidth() const;
    virtual int GetDepth() const;

    virtual wxImage ConvertToImage() const;

    virtual wxMask *GetMask() const;
    virtual void SetMask(wxMask *mask);

    virtual wxBitmap GetSubBitmap(const wxRect& rect) const;

    virtual bool SaveFile(const wxString &name, wxBitmapType type, const wxPalette *palette = NULL) const;
    virtual bool LoadFile(const wxString &name, wxBitmapType type = wxBITMAP_DEFAULT_TYPE);

    virtual wxPalette *GetPalette() const;
    virtual void SetPalette(const wxPalette& palette);

    // copies the contents and mask of the given (colour) icon to the bitmap
    virtual bool CopyFromIcon(const wxIcon& icon);

    static void InitStandardHandlers();

    // implementation:
    virtual void SetHeight(int height);
    virtual void SetWidth(int width);
    virtual void SetDepth(int depth);

    virtual wxColour QuantizeColour(const wxColour& colour) const;

    // get underlying native representation:
    bitmap_t *GetMGLbitmap_t() const;

protected:
    virtual wxGDIRefData *CreateGDIRefData() const;
    virtual wxGDIRefData *CloneGDIRefData(const wxGDIRefData *data) const;

    // creates temporary DC for access to bitmap's data:
    MGLDevCtx *CreateTmpDC() const;
    // sets fg & bg colours for 1bit bitmaps:
    void SetMonoPalette(const wxColour& fg, const wxColour& bg);

private:
    DECLARE_DYNAMIC_CLASS(wxBitmap)

    friend class wxDC;
    friend class wxMemoryDC;
};

#endif // __WX_BITMAP_H__
