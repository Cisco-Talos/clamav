/////////////////////////////////////////////////////////////////////////////
// Name:        dcsvg.h
// Purpose:     interface of wxSVGFileDC
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxSVGFileDC

    A wxSVGFileDC is a device context onto which graphics and text can be
    drawn, and the output produced as a vector file, in SVG format (see the W3C
    SVG Specifications <http://www.w3.org/TR/2001/REC-SVG-20010904/>). This
    format can be read by a range of programs, including a Netscape plugin
    (Adobe), full details are given in the SVG Implementation and Resource
    Directory <http://www.svgi.org/>. Vector formats may often be smaller than
    raster formats.

    The intention behind wxSVGFileDC is that it can be used to produce a file
    corresponding to the screen display context, wxSVGFileDC, by passing the
    wxSVGFileDC as a parameter instead of a wxSVGFileDC. Thus the wxSVGFileDC
    is a write-only class.

    As the wxSVGFileDC is a vector format, raster operations like GetPixel()
    are unlikely to be supported. However, the SVG specification allows for PNG
    format raster files to be embedded in the SVG, and so bitmaps, icons and
    blit operations in wxSVGFileDC are supported.

    A more substantial SVG library (for reading and writing) is available at
    the wxArt2D website <http://wxart2d.sourceforge.net/>.

    @library{wxcore}
    @category{dc}
*/
class wxSVGFileDC : public wxDC
{
public:
    /**
        Initializes a wxSVGFileDC with the given @a f filename with the given
        @a Width and @a Height at @a dpi resolution.
    */
    wxSVGFileDC(const wxString& filename, int width = 320, int height = 240, double dpi = 72);

    /**
        Destructor.
    */
    virtual ~wxSVGFileDC();

    /**
        Does nothing.
    */
    void EndDoc();

    /**
        Does nothing.
    */
    void EndPage();

    /**
        This makes no sense in wxSVGFileDC and does nothing.
    */
    void Clear();

    /**
        Does the same as wxDC::SetLogicalFunction(), except that only wxCOPY is
        available. Trying to set one of the other values will fail.
    */
    void SetLogicalFunction(wxRasterOperationMode function);

    //@{
    /**
        Functions not implemented in this DC class.
    */
    void CrossHair(wxCoord x, wxCoord y);
    void DestroyClippingRegion();
    bool FloodFill(wxCoord x, wxCoord y, const wxColour& colour,
                   wxFloodFillStyle style = wxFLOOD_SURFACE);
    void GetClippingBox(wxCoord *x, wxCoord *y, wxCoord *width, wxCoord *height) const;
    bool GetPixel(wxCoord x, wxCoord y, wxColour* colour) const;
    void SetClippingRegion(wxCoord x, wxCoord y, wxCoord width,
                           wxCoord height);
    void SetClippingRegion(const wxPoint& pt, const wxSize& sz);
    void SetClippingRegion(const wxRect& rect);
    void SetClippingRegion(const wxRegion& region);
    void SetPalette(const wxPalette& palette);
    bool StartDoc(const wxString& message);
    //@}
};

