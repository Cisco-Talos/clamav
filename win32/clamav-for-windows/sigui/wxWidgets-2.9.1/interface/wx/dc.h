/////////////////////////////////////////////////////////////////////////////
// Name:        dc.h
// Purpose:     interface of wxDC
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


/**
    Logical raster operations which can be used with wxDC::SetLogicalFunction
    and some other wxDC functions (e.g. wxDC::Blit and wxDC::StretchBlit).

    The description of the values below refer to how a generic @e src source pixel
    and the corresponding @e dst destination pixel gets combined together to produce
    the final pixel. E.g. @c wxCLEAR and @c wxSET completely ignore the source
    and the destination pixel and always put zeroes or ones in the final surface.
*/
enum wxRasterOperationMode
{
    wxCLEAR,       //!< 0
    wxXOR,         //!< @e src XOR @e dst
    wxINVERT,      //!< NOT @e dst
    wxOR_REVERSE,  //!< @e src OR (NOT @e dst)
    wxAND_REVERSE, //!< @e src AND (NOT @e dst)
    wxCOPY,        //!< @e src
    wxAND,         //!< @e src AND @e dst
    wxAND_INVERT,  //!< (NOT @e src) AND @e dst
    wxNO_OP,       //!< @e dst
    wxNOR,         //!< (NOT @e src) AND (NOT @e dst)
    wxEQUIV,       //!< (NOT @e src) XOR @e dst
    wxSRC_INVERT,  //!< (NOT @e src)
    wxOR_INVERT,   //!< (NOT @e src) OR @e dst
    wxNAND,        //!< (NOT @e src) OR (NOT @e dst)
    wxOR,          //!< @e src OR @e dst
    wxSET          //!< 1
};

/**
    Flood styles used by wxDC::FloodFill.
*/
enum wxFloodFillStyle
{
    /** The flooding occurs until a colour other than the given colour is encountered. */
    wxFLOOD_SURFACE = 1,

    /** The area to be flooded is bounded by the given colour. */
    wxFLOOD_BORDER
};

/**
    The mapping used to transform @e logical units to @e device units.
    See wxDC::SetMapMode.
*/
enum wxMappingMode
{
    /**
        Each logical unit is 1 device pixel.
        This is the default mapping mode for all wxDC-derived classes.
    */
    wxMM_TEXT = 1,

    /** Each logical unit is 1 millimeter. */
    wxMM_METRIC,

    /** Each logical unit is 1/10 of a millimeter. */
    wxMM_LOMETRIC,

    /**
        Each logical unit is 1/20 of a @e "printer point", or 1/1440 of an inch
        (also known as "twip"). Equivalent to about 17.64 micrometers.
    */
    wxMM_TWIPS,

    /**
        Each logical unit is a @e "printer point" i.e. 1/72 of an inch.
        Equivalent to about 353 micrometers.
    */
    wxMM_POINTS
};



/**
    @class wxDC

    A wxDC is a @e "device context" onto which graphics and text can be drawn.
    It is intended to represent different output devices and offers a common
    abstract API for drawing on any of them.

    wxWidgets offers an alternative drawing API based on the modern drawing
    backends GDI+, CoreGraphics and Cairo. See wxGraphicsContext, wxGraphicsRenderer
    and related classes. There is also a wxGCDC linking the APIs by offering
    the wxDC API ontop of a wxGraphicsContext.

    wxDC is an abstract base class and cannot be created directly.
    Use wxPaintDC, wxClientDC, wxWindowDC, wxScreenDC, wxMemoryDC or
    wxPrinterDC. Notice that device contexts which are associated with windows
    (i.e. wxClientDC, wxWindowDC and wxPaintDC) use the window font and colours
    by default (starting with wxWidgets 2.9.0) but the other device context
    classes use system-default values so you always must set the appropriate
    fonts and colours before using them.

    In addition to the versions of the methods documented below, there
    are also versions which accept single wxPoint parameter instead
    of the two wxCoord ones or wxPoint and wxSize instead of the four
    wxCoord parameters.

    Beginning with wxWidgets 2.9.0 the entire wxDC code has been
    reorganized. All platform dependent code (actually all drawing code)
    has been moved into backend classes which derive from a common
    wxDCImpl class. The user-visible classes such as wxClientDC and
    wxPaintDC merely forward all calls to the backend implementation.


    @section dc_units Device and logical units

    In the wxDC context there is a distinction between @e logical units and @e device units.

    @b Device units are the units native to the particular device; e.g. for a screen,
    a device unit is a @e pixel. For a printer, the device unit is defined by the
    resolution of the printer (usually given in @c DPI: dot-per-inch).

    All wxDC functions use instead @b logical units, unless where explicitely
    stated. Logical units are arbitrary units mapped to device units using
    the current mapping mode (see wxDC::SetMapMode).

    This mechanism allows to reuse the same code which prints on e.g. a window
    on the screen to print on e.g. a paper.


    @section dc_alpha_support Support for Transparency / Alpha Channel

    On Mac OS X colours with alpha channel are supported. Instances of wxPen
    or wxBrush that are built from wxColour use the colour's alpha values
    when stroking or filling.


    @library{wxcore}
    @category{dc,gdi}

    @see @ref overview_dc, wxGraphicsContext, wxDCFontChanger, wxDCTextColourChanger,
         wxDCPenChanger, wxDCBrushChanger, wxDCClipper

    @todo Precise definition of default/initial state.
    @todo Pixelwise definition of operations (e.g. last point of a line not
          drawn).
*/
class wxDC : public wxObject
{
public:
    /**
        @name Coordinate conversion functions
    */
    //@{

    /**
        Convert @e device X coordinate to logical coordinate, using the current
        mapping mode, user scale factor, device origin and axis orientation.
    */
    wxCoord DeviceToLogicalX(wxCoord x) const;

    /**
        Convert @e device X coordinate to relative logical coordinate, using the
        current mapping mode and user scale factor but ignoring the
        axis orientation. Use this for converting a width, for example.
    */
    wxCoord DeviceToLogicalXRel(wxCoord x) const;

    /**
        Converts @e device Y coordinate to logical coordinate, using the current
        mapping mode, user scale factor, device origin and axis orientation.
    */
    wxCoord DeviceToLogicalY(wxCoord y) const;

    /**
        Convert @e device Y coordinate to relative logical coordinate, using the
        current mapping mode and user scale factor but ignoring the
        axis orientation. Use this for converting a height, for example.
    */
    wxCoord DeviceToLogicalYRel(wxCoord y) const;

    /**
        Converts logical X coordinate to device coordinate, using the current
        mapping mode, user scale factor, device origin and axis orientation.
    */
    wxCoord LogicalToDeviceX(wxCoord x) const;

    /**
        Converts logical X coordinate to relative device coordinate, using the
        current mapping mode and user scale factor but ignoring the
        axis orientation. Use this for converting a width, for example.
    */
    wxCoord LogicalToDeviceXRel(wxCoord x) const;

    /**
        Converts logical Y coordinate to device coordinate, using the current
        mapping mode, user scale factor, device origin and axis orientation.
    */
    wxCoord LogicalToDeviceY(wxCoord y) const;

    /**
        Converts logical Y coordinate to relative device coordinate, using the
        current mapping mode and user scale factor but ignoring the
        axis orientation. Use this for converting a height, for example.
    */
    wxCoord LogicalToDeviceYRel(wxCoord y) const;

    //@}



    /**
        @name Drawing functions
    */
    //@{

    /**
        Clears the device context using the current background brush.
    */
    void Clear();

    /**
        Draws an arc of a circle, centred on (@a xc, @a yc), with starting
        point (@a xStart, @a yStart) and ending at (@a xEnd, @a yEnd). 
        The current pen is used for the outline and the current brush for 
        filling the shape.

        The arc is drawn in a counter-clockwise direction from the start point
        to the end point.
    */
    void DrawArc(wxCoord xStart, wxCoord yStart, wxCoord xEnd, wxCoord yEnd,
                 wxCoord xc, wxCoord yc);

    /**
        @overload
    */
    void DrawArc(const wxPoint& ptStart, const wxPoint& ptEnd, const wxPoint& centre);

    /**
        Draw a bitmap on the device context at the specified point. If
        @a transparent is @true and the bitmap has a transparency mask, the
        bitmap will be drawn transparently.

        When drawing a mono-bitmap, the current text foreground colour will be
        used to draw the foreground of the bitmap (all bits set to 1), and the
        current text background colour to draw the background (all bits set to
        0).

        @see SetTextForeground(), SetTextBackground(), wxMemoryDC
    */
    void DrawBitmap(const wxBitmap& bitmap, wxCoord x, wxCoord y,
                    bool useMask = false);

    /**
        @overload
    */
    void DrawBitmap(const wxBitmap &bmp, const wxPoint& pt,
                    bool useMask = false);

    /**
        Draws a check mark inside the given rectangle.
    */
    void DrawCheckMark(wxCoord x, wxCoord y, wxCoord width, wxCoord height);

    /**
        @overload
    */
    void DrawCheckMark(const wxRect& rect);

    /**
        Draws a circle with the given centre and radius.

        @see DrawEllipse()
    */
    void DrawCircle(wxCoord x, wxCoord y, wxCoord radius);

    /**
        @overload
    */
    void DrawCircle(const wxPoint& pt, wxCoord radius);

    /**
        Draws an ellipse contained in the rectangle specified either with the
        given top left corner and the given size or directly. The current pen
        is used for the outline and the current brush for filling the shape.

        @see DrawCircle()
    */
    void DrawEllipse(wxCoord x, wxCoord y, wxCoord width, wxCoord height);

    /**
        @overload
    */
    void DrawEllipse(const wxPoint& pt, const wxSize& size);

    /**
        @overload
    */
    void DrawEllipse(const wxRect& rect);

    /**
        Draws an arc of an ellipse. The current pen is used for drawing the arc
        and the current brush is used for drawing the pie.

        @a x and @a y specify the x and y coordinates of the upper-left corner
        of the rectangle that contains the ellipse.

        @a width and @a height specify the width and height of the rectangle
        that contains the ellipse.

        @a start and @a end specify the start and end of the arc relative to
        the three-o'clock position from the center of the rectangle. Angles are
        specified in degrees (360 is a complete circle). Positive values mean
        counter-clockwise motion. If @a start is equal to @e end, a complete
        ellipse will be drawn.
    */
    void DrawEllipticArc(wxCoord x, wxCoord y, wxCoord width, wxCoord height,
                          double start, double end);

    /**
        @overload
    */
    void DrawEllipticArc(const wxPoint& pt, const wxSize& sz,
                         double sa, double ea);

    /**
        Draw an icon on the display (does nothing if the device context is
        PostScript). This can be the simplest way of drawing bitmaps on a
        window.
    */
    void DrawIcon(const wxIcon& icon, wxCoord x, wxCoord y);

    /**
        @overload
    */
    void DrawIcon(const wxIcon& icon, const wxPoint& pt);

    /**
        Draw optional bitmap and the text into the given rectangle and aligns
        it as specified by alignment parameter; it also will emphasize the
        character with the given index if it is != -1 and return the bounding
        rectangle if required.
    */
    void DrawLabel(const wxString& text, const wxBitmap& image,
                   const wxRect& rect,
                   int alignment = wxALIGN_LEFT | wxALIGN_TOP,
                   int indexAccel = -1, wxRect* rectBounding = NULL);

    /**
        @overload
    */
    void DrawLabel(const wxString& text, const wxRect& rect,
                   int alignment = wxALIGN_LEFT | wxALIGN_TOP,
                   int indexAccel = -1);

    /**
        Draws a line from the first point to the second. The current pen is
        used for drawing the line. Note that the point (@a x2, @a y2) is not
        part of the line and is not drawn by this function (this is consistent
        with the behaviour of many other toolkits).
    */
    void DrawLine(wxCoord x1, wxCoord y1, wxCoord x2, wxCoord y2);

    /**
        @overload
    */
    void DrawLine(const wxPoint& pt1, const wxPoint& pt2);

    /**
        Draws lines using an array of points of size @a n adding the optional
        offset coordinate. The current pen is used for drawing the lines.

        @beginWxPythonOnly
        The wxPython version of this method accepts a Python list of wxPoint
        objects.
        @endWxPythonOnly

        @beginWxPerlOnly
        Not supported by wxPerl.
        @endWxPerlOnly
    */
    void DrawLines(int n, wxPoint points[], wxCoord xoffset = 0,
                   wxCoord yoffset = 0);
    /**
        This method uses a list of wxPoints, adding the optional offset
        coordinate. The programmer is responsible for deleting the list of
        points.

        @beginWxPythonOnly
        The wxPython version of this method accepts a Python list of wxPoint
        objects.
        @endWxPythonOnly

        @beginWxPerlOnly
        The wxPerl version of this method accepts
        as its first parameter a reference to an array
        of wxPoint objects.
        @endWxPerlOnly
    */
    void DrawLines(const wxPointList* points,
                   wxCoord xoffset = 0, wxCoord yoffset = 0);

    /**
        Draws a point using the color of the current pen. Note that the other
        properties of the pen are not used, such as width.
    */
    void DrawPoint(wxCoord x, wxCoord y);

    /**
        @overload
    */
    void DrawPoint(const wxPoint& pt);

    /**
        Draws a filled polygon using an array of points of size @a n, adding
        the optional offset coordinate. The first and last points are
        automatically closed.

        The last argument specifies the fill rule: @b wxODDEVEN_RULE (the
        default) or @b wxWINDING_RULE.

        The current pen is used for drawing the outline, and the current brush
        for filling the shape. Using a transparent brush suppresses filling.

        @beginWxPerlOnly
        Not supported by wxPerl.
        @endWxPerlOnly
    */
    void DrawPolygon(int n, wxPoint points[], wxCoord xoffset = 0,
                     wxCoord yoffset = 0,
                     wxPolygonFillMode fill_style = wxODDEVEN_RULE);
    /**
        This method draws a filled polygon using a list of wxPoints, adding the
        optional offset coordinate. The first and last points are automatically
        closed.

        The last argument specifies the fill rule: @b wxODDEVEN_RULE (the
        default) or @b wxWINDING_RULE.

        The current pen is used for drawing the outline, and the current brush
        for filling the shape. Using a transparent brush suppresses filling.

        The programmer is responsible for deleting the list of points.

        @beginWxPythonOnly
        The wxPython version of this method accepts a Python list of wxPoint
        objects.
        @endWxPythonOnly

        @beginWxPerlOnly
        The wxPerl version of this method accepts
        as its first parameter a reference to an array
        of wxPoint objects.
        @endWxPerlOnly
    */
    void DrawPolygon(const wxPointList* points,
                     wxCoord xoffset = 0, wxCoord yoffset = 0,
                     wxPolygonFillMode fill_style = wxODDEVEN_RULE);

    /**
        Draws two or more filled polygons using an array of @a points, adding
        the optional offset coordinates.

        Notice that for the platforms providing a native implementation of this
        function (Windows and PostScript-based wxDC currently), this is more
        efficient than using DrawPolygon() in a loop.

        @a n specifies the number of polygons to draw, the array @e count of
        size @a n specifies the number of points in each of the polygons in the
        @a points array.

        The last argument specifies the fill rule: @b wxODDEVEN_RULE (the
        default) or @b wxWINDING_RULE.

        The current pen is used for drawing the outline, and the current brush
        for filling the shape. Using a transparent brush suppresses filling.

        The polygons maybe disjoint or overlapping. Each polygon specified in a
        call to DrawPolyPolygon() must be closed. Unlike polygons created by
        the DrawPolygon() member function, the polygons created by this
        method are not closed automatically.

        @beginWxPythonOnly
        Not implemented yet.
        @endWxPythonOnly
    */
    void DrawPolyPolygon(int n, int count[], wxPoint points[],
                         wxCoord xoffset = 0, wxCoord yoffset = 0,
                         wxPolygonFillMode fill_style = wxODDEVEN_RULE);

    /**
        Draws a rectangle with the given top left corner, and with the given
        size.  The current pen is used for the outline and the current brush
        for filling the shape.
    */
    void DrawRectangle(wxCoord x, wxCoord y, wxCoord width, wxCoord height);

    /**
        @overload
    */
    void DrawRectangle(const wxPoint& pt, const wxSize& sz);

    /**
        @overload
    */
    void DrawRectangle(const wxRect& rect);

    /**
        Draws the text rotated by @a angle degrees 
        (positive angles are counterclockwise; the full angle is 360 degrees).

        @note Under Win9x only TrueType fonts can be drawn by this function. In
              particular, a font different from @c wxNORMAL_FONT should be used
              as the latter is not a TrueType font. @c wxSWISS_FONT is an
              example of a font which is.

        @see DrawText()
    */
    void DrawRotatedText(const wxString& text, wxCoord x, wxCoord y,
                         double angle);

    /**
        @overload
    */
    void DrawRotatedText(const wxString& text, const wxPoint&,
                         double angle);

    /**
        Draws a rectangle with the given top left corner, and with the given
        size. The corners are quarter-circles using the given radius. The
        current pen is used for the outline and the current brush for filling
        the shape.

        If @a radius is positive, the value is assumed to be the radius of the
        rounded corner. If @a radius is negative, the absolute value is assumed
        to be the @e proportion of the smallest dimension of the rectangle.
        This means that the corner can be a sensible size relative to the size
        of the rectangle, and also avoids the strange effects X produces when
        the corners are too big for the rectangle.
    */
    void DrawRoundedRectangle(wxCoord x, wxCoord y, wxCoord width,
                              wxCoord height, double radius);

    /**
        @overload
    */
    void DrawRoundedRectangle(const wxPoint& pt, const wxSize& sz,
                              double radius);

    /**
        @overload
    */
    void DrawRoundedRectangle(const wxRect& rect, double radius);

    /**
        Draws a spline between all given points using the current pen.

        @beginWxPythonOnly
        The wxPython version of this method accepts a Python list of wxPoint
        objects.
        @endWxPythonOnly

        @beginWxPerlOnly
        Not supported by wxPerl.
        @endWxPerlOnly
    */
    void DrawSpline(int n, wxPoint points[]);

    /**
        @overload


        @beginWxPerlOnly
        The wxPerl version of this method accepts
        as its first parameter a reference to an array
        of wxPoint objects.
        @endWxPerlOnly
    */
    void DrawSpline(const wxPointList* points);

    /**
        @overload


        @beginWxPerlOnly
        Not supported by wxPerl.
        @endWxPerlOnly
    */
    void DrawSpline(wxCoord x1, wxCoord y1, wxCoord x2, wxCoord y2,
                    wxCoord x3, wxCoord y3);

    /**
        Draws a text string at the specified point, using the current text
        font, and the current text foreground and background colours.

        The coordinates refer to the top-left corner of the rectangle bounding
        the string. See GetTextExtent() for how to get the dimensions of a text
        string, which can be used to position the text more precisely.

        @note The current @ref GetLogicalFunction() "logical function" is
              ignored by this function.
    */
    void DrawText(const wxString& text, wxCoord x, wxCoord y);

    /**
        @overload
    */
    void DrawText(const wxString& text, const wxPoint& pt);

    /**
        Fill the area specified by rect with a radial gradient, starting from
        @a initialColour at the centre of the circle and fading to
        @a destColour on the circle outside.

        The circle is placed at the centre of @a rect.

        @note Currently this function is very slow, don't use it for real-time
              drawing.
    */
    void GradientFillConcentric(const wxRect& rect,
                                const wxColour& initialColour,
                                const wxColour& destColour);

    /**
        Fill the area specified by rect with a radial gradient, starting from
        @a initialColour at the centre of the circle and fading to
        @a destColour on the circle outside.

        @a circleCenter are the relative coordinates of centre of the circle in
        the specified @a rect.

        @note Currently this function is very slow, don't use it for real-time
              drawing.
    */
    void GradientFillConcentric(const wxRect& rect,
                                const wxColour& initialColour,
                                const wxColour& destColour,
                                const wxPoint& circleCenter);

    /**
        Fill the area specified by @a rect with a linear gradient, starting
        from @a initialColour and eventually fading to @e destColour.

        The @a nDirection specifies the direction of the colour change, default is
        to use @a initialColour on the left part of the rectangle and
        @a destColour on the right one.
    */
    void GradientFillLinear(const wxRect& rect, const wxColour& initialColour,
                            const wxColour& destColour,
                            wxDirection nDirection = wxRIGHT);

    /**
        Flood fills the device context starting from the given point, using
        the current brush colour, and using a style:

        - wxFLOOD_SURFACE: The flooding occurs until a colour other than the
          given colour is encountered.
        - wxFLOOD_BORDER: The area to be flooded is bounded by the given
          colour.

        @return @false if the operation failed.

        @note The present implementation for non-Windows platforms may fail to
              find colour borders if the pixels do not match the colour
              exactly. However the function will still return @true.
    */
    bool FloodFill(wxCoord x, wxCoord y, const wxColour& colour,
                   wxFloodFillStyle style = wxFLOOD_SURFACE);

    /**
        @overload
    */
    bool FloodFill(const wxPoint& pt, const wxColour& col,
                   int style = wxFLOOD_SURFACE);

    /**
        Displays a cross hair using the current pen. This is a vertical and
        horizontal line the height and width of the window, centred on the
        given point.
    */
    void CrossHair(wxCoord x, wxCoord y);

    /**
        @overload
    */
    void CrossHair(const wxPoint& pt);

    //@}


    /**
        @name Clipping region functions
    */
    //@{

    /**
        Destroys the current clipping region so that none of the DC is clipped.

        @see SetClippingRegion()
    */
    void DestroyClippingRegion();

    /**
        Gets the rectangle surrounding the current clipping region.

        @beginWxPythonOnly
        No arguments are required and the four values defining the rectangle
        are returned as a tuple.
        @endWxPythonOnly
    */
    void GetClippingBox(wxCoord *x, wxCoord *y, wxCoord *width, wxCoord *height) const;

    /**
        Sets the clipping region for this device context to the intersection of
        the given region described by the parameters of this method and the
        previously set clipping region.

        The clipping region is an area to which drawing is restricted. Possible
        uses for the clipping region are for clipping text or for speeding up
        window redraws when only a known area of the screen is damaged.

        Notice that you need to call DestroyClippingRegion() if you want to set
        the clipping region exactly to the region specified.

        Also note that if the clipping region is empty, any previously set
        clipping region is destroyed, i.e. it is equivalent to calling
        DestroyClippingRegion(), and not to clipping out all drawing on the DC
        as might be expected.

        @see DestroyClippingRegion(), wxRegion
    */
    void SetClippingRegion(wxCoord x, wxCoord y, wxCoord width, wxCoord height);

    /**
        @overload
    */
    void SetClippingRegion(const wxPoint& pt, const wxSize& sz);

    /**
        @overload
    */
    void SetClippingRegion(const wxRect& rect);

    /**
        Sets the clipping region for this device context.

        Unlike SetClippingRegion(), this function works with physical
        coordinates and not with the logical ones.
     */
    void SetDeviceClippingRegion(const wxRegion& region);

    //@}


    /**
        @name Text/character extent functions
    */
    //@{

    /**
        Gets the character height of the currently set font.
    */
    wxCoord GetCharHeight() const;

    /**
        Gets the average character width of the currently set font.
    */
    wxCoord GetCharWidth() const;

    /**
        Gets the dimensions of the string using the currently selected font.
        @a string is the text string to measure, @e heightLine, if non @NULL,
        is where to store the height of a single line.

        The text extent is set in the given @a w and @a h pointers.

        If the optional parameter @a font is specified and valid, then it is
        used for the text extent calculation, otherwise the currently selected
        font is used.

        @note This function works with both single-line and multi-line strings.

        @beginWxPerlOnly
        In wxPerl this method is implemented as
        GetMultiLineTextExtent(string, font = undef) returning a
        3-element list (width, height, line_height)
        @endWxPerlOnly

        @see wxFont, SetFont(), GetPartialTextExtents(), GetTextExtent()
    */
    void GetMultiLineTextExtent(const wxString& string, wxCoord* w,
                                wxCoord* h,
                                wxCoord* heightLine = NULL,
                                const wxFont* font = NULL) const;
    /**
        Gets the dimensions of the string using the currently selected font.
        @a string is the text string to measure, @e heightLine, if non @NULL,
        is where to store the height of a single line.

        @return The text extent as a wxSize object.

        @note This function works with both single-line and multi-line strings.

        @beginWxPerlOnly
        Not supported by wxPerl.
        @endWxPerlOnly

        @see wxFont, SetFont(), GetPartialTextExtents(), GetTextExtent()
    */
    wxSize GetMultiLineTextExtent(const wxString& string) const;

    /**
        Fills the @a widths array with the widths from the beginning of @a text
        to the corresponding character of @a text. The generic version simply
        builds a running total of the widths of each character using
        GetTextExtent(), however if the various platforms have a native API
        function that is faster or more accurate than the generic
        implementation then it should be used instead.

        @beginWxPythonOnly
        This method only takes the @a text parameter and returns a Python list
        of integers.
        @endWxPythonOnly

        @beginWxPerlOnly
        In wxPerl this method only takes the @a text parameter and
        returns the widths as a list of integers.
        @endWxPerlOnly

        @see GetMultiLineTextExtent(), GetTextExtent()
    */
    bool GetPartialTextExtents(const wxString& text,
                               wxArrayInt& widths) const;

    /**
        Gets the dimensions of the string using the currently selected font.
        @a string is the text string to measure, @a descent is the dimension
        from the baseline of the font to the bottom of the descender, and
        @a externalLeading is any extra vertical space added to the font by the
        font designer (usually is zero).

        The text extent is returned in @a w and @a h pointers or as a wxSize
        object depending on which version of this function is used.

        If the optional parameter @a font is specified and valid, then it is
        used for the text extent calculation. Otherwise the currently selected
        font is.

        @note This function only works with single-line strings.

        @beginWxPythonOnly
        The following methods are implemented in wxPython:
        - GetTextExtent(string) - Returns a 2-tuple, (width, height).
        - GetFullTextExtent(string, font=NULL) -
            Returns a 4-tuple, (width, height, descent, externalLeading).
        @endWxPythonOnly

        @beginWxPerlOnly
        In wxPerl this method is implemented as GetTextExtent(string,
        font = undef) returning a 4-element list (width, height,
        descent, externalLeading)
        @endWxPerlOnly

        @see wxFont, SetFont(), GetPartialTextExtents(),
             GetMultiLineTextExtent()
    */
    void GetTextExtent(const wxString& string, wxCoord* w, wxCoord* h,
                       wxCoord* descent = NULL,
                       wxCoord* externalLeading = NULL,
                       const wxFont* font = NULL) const;

    /**
        @overload


        @beginWxPerlOnly
        Not supported by wxPerl.
        @endWxPerlOnly
    */
    wxSize GetTextExtent(const wxString& string) const;

    //@}


    /**
        @name Text properties functions
    */
    //@{

    /**
        Returns the current background mode: @c wxSOLID or @c wxTRANSPARENT.

        @see SetBackgroundMode()
    */
    int GetBackgroundMode() const;

    /**
        Gets the current font. 
        
        Notice that even although each device context object has some default font 
        after creation, this method would return a ::wxNullFont initially and only 
        after calling SetFont() a valid font is returned.
    */
    const wxFont& GetFont() const;

    /**
        Gets the current layout direction of the device context. On platforms
        where RTL layout is supported, the return value will either be
        @c wxLayout_LeftToRight or @c wxLayout_RightToLeft. If RTL layout is
        not supported, the return value will be @c wxLayout_Default.

        @see SetLayoutDirection()
    */
    wxLayoutDirection GetLayoutDirection() const;

    /**
        Gets the current text background colour.

        @see SetTextBackground()
    */
    const wxColour& GetTextBackground() const;

    /**
        Gets the current text foreground colour.

        @see SetTextForeground()
    */
    const wxColour& GetTextForeground() const;

    /**
        @a mode may be one of @c wxSOLID and @c wxTRANSPARENT. 
        
        This setting determines whether text will be drawn with a background 
        colour or not.
    */
    void SetBackgroundMode(int mode);

    /**
        Sets the current font for the DC. 

        If the argument is ::wxNullFont (or another invalid font; see wxFont::IsOk), 
        the current font is selected out of the device context (leaving wxDC without 
        any valid font), allowing the current font to be destroyed safely.

        @see wxFont
    */
    void SetFont(const wxFont& font);

    /**
        Sets the current text background colour for the DC.
    */
    void SetTextBackground(const wxColour& colour);

    /**
        Sets the current text foreground colour for the DC.

        @see wxMemoryDC for the interpretation of colours when drawing into a
             monochrome bitmap.
    */
    void SetTextForeground(const wxColour& colour);

    /**
        Sets the current layout direction for the device context. 
        
        @param dir 
           May be either @c wxLayout_Default, @c wxLayout_LeftToRight or
           @c wxLayout_RightToLeft.

        @see GetLayoutDirection()
    */
    void SetLayoutDirection(wxLayoutDirection dir);

    //@}


    /**
        @name Bounding box functions
    */
    //@{

    /**
        Adds the specified point to the bounding box which can be retrieved
        with MinX(), MaxX() and MinY(), MaxY() functions.

        @see ResetBoundingBox()
    */
    void CalcBoundingBox(wxCoord x, wxCoord y);

    /**
        Gets the maximum horizontal extent used in drawing commands so far.
    */
    wxCoord MaxX() const;

    /**
        Gets the maximum vertical extent used in drawing commands so far.
    */
    wxCoord MaxY() const;

    /**
        Gets the minimum horizontal extent used in drawing commands so far.
    */
    wxCoord MinX() const;

    /**
        Gets the minimum vertical extent used in drawing commands so far.
    */
    wxCoord MinY() const;

    /**
        Resets the bounding box: after a call to this function, the bounding
        box doesn't contain anything.

        @see CalcBoundingBox()
    */
    void ResetBoundingBox();

    //@}


    /**
        @name Page and document start/end functions
    */
    //@{

    /**
        Starts a document (only relevant when outputting to a printer).
        @a message is a message to show while printing.
    */
    bool StartDoc(const wxString& message);

    /**
        Starts a document page (only relevant when outputting to a printer).
    */
    void StartPage();

    /**
        Ends a document (only relevant when outputting to a printer).
    */
    void EndDoc();

    /**
        Ends a document page (only relevant when outputting to a printer).
    */
    void EndPage();

    //@}


    /**
        @name Bit-Block Transfer operations (blit)
    */
    //@{

    /**
        Copy from a source DC to this DC, specifying the destination
        coordinates, size of area to copy, source DC, source coordinates,
        logical function, whether to use a bitmap mask, and mask source
        position.

        @param xdest
            Destination device context x position.
        @param ydest
            Destination device context y position.
        @param width
            Width of source area to be copied.
        @param height
            Height of source area to be copied.
        @param source
            Source device context.
        @param xsrc
            Source device context x position.
        @param ysrc
            Source device context y position.
        @param logicalFunc
            Logical function to use, see SetLogicalFunction().
        @param useMask
            If @true, Blit does a transparent blit using the mask that is
            associated with the bitmap selected into the source device context.
            The Windows implementation does the following if MaskBlt cannot be
            used:
            <ol>
            <li>Creates a temporary bitmap and copies the destination area into
                it.</li>
            <li>Copies the source area into the temporary bitmap using the
                specified logical function.</li>
            <li>Sets the masked area in the temporary bitmap to BLACK by ANDing
                the mask bitmap with the temp bitmap with the foreground colour
                set to WHITE and the bg colour set to BLACK.</li>
            <li>Sets the unmasked area in the destination area to BLACK by
                ANDing the mask bitmap with the destination area with the
                foreground colour set to BLACK and the background colour set to
                WHITE.</li>
            <li>ORs the temporary bitmap with the destination area.</li>
            <li>Deletes the temporary bitmap.</li>
            </ol>
            This sequence of operations ensures that the source's transparent
            area need not be black, and logical functions are supported.
            @n @b Note: on Windows, blitting with masks can be speeded up
            considerably by compiling wxWidgets with the wxUSE_DC_CACHE option
            enabled. You can also influence whether MaskBlt or the explicit
            mask blitting code above is used, by using wxSystemOptions and
            setting the @c no-maskblt option to 1.
        @param xsrcMask
            Source x position on the mask. If both xsrcMask and ysrcMask are
            @c -1, xsrc and ysrc will be assumed for the mask source position.
            Currently only implemented on Windows.
        @param ysrcMask
            Source y position on the mask. If both xsrcMask and ysrcMask are
            @c -1, xsrc and ysrc will be assumed for the mask source position.
            Currently only implemented on Windows.

        @remarks There is partial support for Blit() in wxPostScriptDC, under X.

        @see StretchBlit(), wxMemoryDC, wxBitmap, wxMask
    */
    bool Blit(wxCoord xdest, wxCoord ydest, wxCoord width,
              wxCoord height, wxDC* source, wxCoord xsrc, wxCoord ysrc,
              wxRasterOperationMode logicalFunc = wxCOPY, bool useMask = false,
              wxCoord xsrcMask = wxDefaultCoord, wxCoord ysrcMask = wxDefaultCoord);

    /**
        Copy from a source DC to this DC, specifying the destination
        coordinates, destination size, source DC, source coordinates, size of
        source area to copy, logical function, whether to use a bitmap mask,
        and mask source position.

        @param xdest
            Destination device context x position.
        @param ydest
            Destination device context y position.
        @param dstWidth
            Width of destination area.
        @param dstHeight
            Height of destination area.
        @param source
            Source device context.
        @param xsrc
            Source device context x position.
        @param ysrc
            Source device context y position.
        @param srcWidth
            Width of source area to be copied.
        @param srcHeight
            Height of source area to be copied.
        @param logicalFunc
            Logical function to use, see SetLogicalFunction().
        @param useMask
            If @true, Blit does a transparent blit using the mask that is
            associated with the bitmap selected into the source device context.
            The Windows implementation does the following if MaskBlt cannot be
            used:
            <ol>
            <li>Creates a temporary bitmap and copies the destination area into
                it.</li>
            <li>Copies the source area into the temporary bitmap using the
                specified logical function.</li>
            <li>Sets the masked area in the temporary bitmap to BLACK by ANDing
                the mask bitmap with the temp bitmap with the foreground colour
                set to WHITE and the bg colour set to BLACK.</li>
            <li>Sets the unmasked area in the destination area to BLACK by
                ANDing the mask bitmap with the destination area with the
                foreground colour set to BLACK and the background colour set to
                WHITE.</li>
            <li>ORs the temporary bitmap with the destination area.</li>
            <li>Deletes the temporary bitmap.</li>
            </ol>
            This sequence of operations ensures that the source's transparent
            area need not be black, and logical functions are supported.
            @n @b Note: on Windows, blitting with masks can be speeded up
            considerably by compiling wxWidgets with the wxUSE_DC_CACHE option
            enabled. You can also influence whether MaskBlt or the explicit
            mask blitting code above is used, by using wxSystemOptions and
            setting the @c no-maskblt option to 1.
        @param xsrcMask
            Source x position on the mask. If both xsrcMask and ysrcMask are
            wxDefaultCoord, @a xsrc and @a ysrc will be assumed for the mask
            source position. Currently only implemented on Windows.
        @param ysrcMask
            Source y position on the mask. If both xsrcMask and ysrcMask are
            wxDefaultCoord, @a xsrc and @a ysrc will be assumed for the mask
            source position. Currently only implemented on Windows.

        There is partial support for Blit() in wxPostScriptDC, under X.

        StretchBlit() is only implemented under wxMAC and wxMSW.

        See wxMemoryDC for typical usage.

        @since 2.9.0

        @see Blit(), wxMemoryDC, wxBitmap, wxMask
    */
    bool StretchBlit(wxCoord xdest, wxCoord ydest,
                     wxCoord dstWidth, wxCoord dstHeight,
                     wxDC* source, wxCoord xsrc, wxCoord ysrc,
                     wxCoord srcWidth, wxCoord srcHeight,
                     wxRasterOperationMode logicalFunc = wxCOPY,
                     bool useMask = false,
                     wxCoord xsrcMask = wxDefaultCoord,
                     wxCoord ysrcMask = wxDefaultCoord);
    //@}


    /**
        @name Background/foreground brush and pen
    */
    //@{

    /**
        Gets the brush used for painting the background.

        @see wxDC::SetBackground()
    */
    const wxBrush& GetBackground() const;

    /**
        Gets the current brush.

        @see wxDC::SetBrush()
    */
    const wxBrush& GetBrush() const;

    /**
        Gets the current pen.

        @see SetPen()
    */
    const wxPen& GetPen() const;

    /**
        Sets the current background brush for the DC.
    */
    void SetBackground(const wxBrush& brush);

    /**
        Sets the current brush for the DC.

        If the argument is ::wxNullBrush (or another invalid brush; see wxBrush::IsOk), 
        the current brush is selected out of the device context (leaving wxDC without 
        any valid brush), allowing the current brush to be destroyed safely.

        @see wxBrush, wxMemoryDC (for the interpretation of colours when
             drawing into a monochrome bitmap)
    */
    void SetBrush(const wxBrush& brush);

    /**
        Sets the current pen for the DC. 

        If the argument is ::wxNullPen (or another invalid pen; see wxPen::IsOk), 
        the current pen is selected out of the device context (leaving wxDC without any 
        valid pen), allowing the current pen to be destroyed safely.

        @see wxMemoryDC for the interpretation of colours when drawing into a
             monochrome bitmap.
    */
    void SetPen(const wxPen& pen);

    //@}


    /**
        Copy attributes from another DC.

        The copied attributes currently are:
            - Font
            - Text foreground and background colours
            - Background brush
            - Layout direction

        @param dc
            A valid (i.e. its IsOk() must return @true) source device context.
     */
    void CopyAttributes(const wxDC& dc);

    /**
        Returns the depth (number of bits/pixel) of this DC.

        @see wxDisplayDepth()
    */
    int GetDepth() const;

    /**
        Returns the current device origin.

        @see SetDeviceOrigin()
    */
    wxPoint GetDeviceOrigin() const;

    /**
        Gets the current logical function.

        @see SetLogicalFunction()
    */
    wxRasterOperationMode GetLogicalFunction() const;

    /**
        Gets the current mapping mode for the device context.

        @see SetMapMode()
    */
    wxMappingMode GetMapMode() const;

    /**
        Gets in @a colour the colour at the specified location. Not available
        for wxPostScriptDC or wxMetafileDC.

        @note Setting a pixel can be done using DrawPoint().

        @beginWxPythonOnly
        The wxColour value is returned and is not required as a parameter.
        @endWxPythonOnly
    */
    bool GetPixel(wxCoord x, wxCoord y, wxColour* colour) const;

    /**
        Returns the resolution of the device in pixels per inch.
    */
    wxSize GetPPI() const;

    /**
        Gets the horizontal and vertical extent of this device context in @e device units.
        It can be used to scale graphics to fit the page.

        For example, if @e maxX and @e maxY represent the maximum horizontal
        and vertical 'pixel' values used in your application, the following
        code will scale the graphic to fit on the printer page:

        @code
        wxCoord w, h;
        dc.GetSize(&w, &h);
        double scaleX = (double)(maxX / w);
        double scaleY = (double)(maxY / h);
        dc.SetUserScale(min(scaleX, scaleY),min(scaleX, scaleY));
        @endcode

        @beginWxPythonOnly
        In place of a single overloaded method name, wxPython implements the
        following methods:
        - GetSize() - Returns a wxSize.
        - GetSizeWH() - Returns a 2-tuple (width, height).
        @endWxPythonOnly

        @beginWxPerlOnly
        In wxPerl there are two methods instead of a single overloaded
        method:
        - GetSize(): returns a Wx::Size object.
        - GetSizeWH(): returns a 2-element list (width, height).
        @endWxPerlOnly
    */
    void GetSize(wxCoord* width, wxCoord* height) const;

    /**
        @overload
    */
    wxSize GetSize() const;

    /**
        Returns the horizontal and vertical resolution in millimetres.
    */
    void GetSizeMM(wxCoord* width, wxCoord* height) const;

    /**
        @overload
    */
    wxSize GetSizeMM() const;

    /**
        Gets the current user scale factor.

        @beginWxPerlOnly
        In wxPerl this method takes no arguments and return a two
        element array (x, y).
        @endWxPerlOnly

        @see SetUserScale()
    */
    void GetUserScale(double* x, double* y) const;

    /**
        Returns @true if the DC is ok to use.
    */
    bool IsOk() const;

    /**
        Sets the x and y axis orientation (i.e., the direction from lowest to
        highest values on the axis). The default orientation is x axis from
        left to right and y axis from top down.

        @param xLeftRight
            True to set the x axis orientation to the natural left to right
            orientation, @false to invert it.
        @param yBottomUp
            True to set the y axis orientation to the natural bottom up
            orientation, @false to invert it.
    */
    void SetAxisOrientation(bool xLeftRight, bool yBottomUp);

    /**
        Sets the device origin (i.e., the origin in pixels after scaling has
        been applied). This function may be useful in Windows printing
        operations for placing a graphic on a page.
    */
    void SetDeviceOrigin(wxCoord x, wxCoord y);

    /**
        Sets the current logical function for the device context.
        It determines how a @e source pixel (from a pen or brush colour, or source
        device context if using Blit()) combines with a @e destination pixel in
        the current device context.
        Text drawing is not affected by this function.

        See ::wxRasterOperationMode enumeration values for more info.

        The default is @c wxCOPY, which simply draws with the current colour.
        The others combine the current colour and the background using a logical
        operation. @c wxINVERT is commonly used for drawing rubber bands or moving
        outlines, since drawing twice reverts to the original colour.
    */
    void SetLogicalFunction(wxRasterOperationMode function);

    /**
        The mapping mode of the device context defines the unit of measurement
        used to convert @e logical units to @e device units.

        Note that in X, text drawing isn't handled consistently with the mapping mode;
        a font is always specified in point size. However, setting the user scale (see
        SetUserScale()) scales the text appropriately. In Windows, scalable
        TrueType fonts are always used; in X, results depend on availability of
        fonts, but usually a reasonable match is found.

        The coordinate origin is always at the top left of the screen/printer.

        Drawing to a Windows printer device context uses the current mapping
        mode, but mapping mode is currently ignored for PostScript output.
    */
    void SetMapMode(wxMappingMode mode);

    /**
        If this is a window DC or memory DC, assigns the given palette to the
        window or bitmap associated with the DC. If the argument is
        ::wxNullPalette, the current palette is selected out of the device
        context, and the original palette restored.

        @see wxPalette
    */
    void SetPalette(const wxPalette& palette);

    /**
        Sets the user scaling factor, useful for applications which require
        'zooming'.
    */
    void SetUserScale(double xScale, double yScale);
};



/**
    @class wxDCClipper

    wxDCClipper is a small helper class for setting a clipping region on a wxDC
    and unsetting it automatically. An object of wxDCClipper class is typically
    created on the stack so that it is automatically destroyed when the object
    goes out of scope. A typical usage example:

    @code
    void MyFunction(wxDC& dc)
    {
        wxDCClipper clip(dc, rect);
        // ... drawing functions here are affected by clipping rect ...
    }

    void OtherFunction()
    {
        wxDC dc;
        MyFunction(dc);
        // ... drawing functions here are not affected by clipping rect ...
    }
    @endcode

    @library{wxcore}
    @category{gdi}

    @see wxDC::SetClippingRegion(), wxDCFontChanger, wxDCTextColourChanger, wxDCPenChanger,
         wxDCBrushChanger
*/
class wxDCClipper
{
public:
    //@{
    /**
        Sets the clipping region to the specified region/coordinates.

        The clipping region is automatically unset when this object is destroyed.
    */
    wxDCClipper(wxDC& dc, const wxRegion& r);
    wxDCClipper(wxDC& dc, const wxRect& rect);
    wxDCClipper(wxDC& dc, wxCoord x, wxCoord y, wxCoord w, wxCoord h);
    //@}

    /**
        Destroys the clipping region associated with the DC passed to the ctor.
    */
    ~wxDCClipper();
};


/**
    @class wxDCBrushChanger

    wxDCBrushChanger is a small helper class for setting a brush on a wxDC
    and unsetting it automatically in the destructor, restoring the previous one.

    @library{wxcore}
    @category{gdi}

    @see wxDC::SetBrush(), wxDCFontChanger, wxDCTextColourChanger, wxDCPenChanger,
         wxDCClipper
*/
class wxDCBrushChanger
{
public:
    /**
        Sets @a brush on the given @a dc, storing the old one.

        @param dc
            The DC where the brush must be temporary set.
        @param brush
            The brush to set.
    */
    wxDCBrushChanger(wxDC& dc, const wxBrush& brush);

    /**
        Restores the brush originally selected in the DC passed to the ctor.
    */
    ~wxDCBrushChanger();
};


/**
    @class wxDCPenChanger

    wxDCPenChanger is a small helper class for setting a pen on a wxDC
    and unsetting it automatically in the destructor, restoring the previous one.

    @library{wxcore}
    @category{gdi}

    @see wxDC::SetPen(), wxDCFontChanger, wxDCTextColourChanger, wxDCBrushChanger,
         wxDCClipper
*/
class wxDCPenChanger
{
public:
    /**
        Sets @a pen on the given @a dc, storing the old one.

        @param dc
            The DC where the pen must be temporary set.
        @param pen
            The pen to set.
    */
    wxDCPenChanger(wxDC& dc, const wxPen& pen);

    /**
        Restores the pen originally selected in the DC passed to the ctor.
    */
    ~wxDCPenChanger();
};



/**
    @class wxDCTextColourChanger

    wxDCTextColourChanger is a small helper class for setting a foreground
    text colour on a wxDC and unsetting it automatically in the destructor,
    restoring the previous one.

    @library{wxcore}
    @category{gdi}

    @see wxDC::SetTextForeground(), wxDCFontChanger, wxDCPenChanger, wxDCBrushChanger,
         wxDCClipper
*/
class wxDCTextColourChanger
{
public:
    /**
        Trivial constructor not changing anything.

        This constructor is useful if you don't know beforehand if the colour
        needs to be changed or not. It simply creates the object which won't do
        anything in its destructor unless Set() is called -- in which case it
        would reset the previous colour.
     */
    wxDCTextColourChanger(wxDC& dc);

    /**
        Sets @a col on the given @a dc, storing the old one.

        @param dc
            The DC where the colour must be temporary set.
        @param col
            The colour to set.
    */
    wxDCTextColourChanger(wxDC& dc, const wxColour& col);

    /**
        Set the colour to use.

        This method is meant to be called once only and only on the objects
        created with the constructor overload not taking wxColour argument and
        has the same effect as the other constructor, i.e. sets the colour to
        the given @a col and ensures that the old value is restored when this
        object is destroyed.
     */
    void Set(const wxColour& col);

    /**
        Restores the colour originally selected in the DC passed to the ctor.
    */
    ~wxDCTextColourChanger();
};



/**
    @class wxDCFontChanger

    wxDCFontChanger is a small helper class for setting a font on a wxDC and
    unsetting it automatically in the destructor, restoring the previous one.

    @since 2.9.0

    @library{wxcore}
    @category{gdi}

    @see wxDC::SetFont(), wxDCTextColourChanger, wxDCPenChanger, wxDCBrushChanger,
         wxDCClipper
*/
class wxDCFontChanger
{
public:
    /**
        Trivial constructor not changing anything.

        This constructor is useful if you don't know beforehand if the font
        needs to be changed or not. It simply creates the object which won't do
        anything in its destructor unless Set() is called -- in which case it
        would reset the previous font.

        @since 2.9.1
     */
    wxDCFontChanger(wxDC& dc);

    /**
        Sets @a font on the given @a dc, storing the old one.

        @param dc
            The DC where the font must be temporary set.
        @param font
            The font to set.
    */
    wxDCFontChanger(wxDC& dc, const wxFont& font);

    /**
        Set the font to use.

        This method is meant to be called once only and only on the objects
        created with the constructor overload not taking wxColour argument and
        has the same effect as the other constructor, i.e. sets the font to
        the given @a font and ensures that the old value is restored when this
        object is destroyed.
     */
    void Set(const wxFont& font);

    /**
        Restores the font originally selected in the DC passed to the ctor.
    */
    ~wxDCFontChanger();
};

