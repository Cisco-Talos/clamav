/////////////////////////////////////////////////////////////////////////////
// Name:        graphics.h
// Purpose:     interface of various wxGraphics* classes
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxGraphicsPath

    A wxGraphicsPath is a native representation of a geometric path. The
    contents are specific an private to the respective renderer. Instances are
    reference counted and can therefore be assigned as usual. The only way to
    get a valid instance is by using wxGraphicsContext::CreatePath() or
    wxGraphicsRenderer::CreatePath().

    @library{wxcore}
    @category{gdi}
*/
class wxGraphicsPath : public wxGraphicsObject
{
public:
    /**
        Adds an arc of a circle.

        The circle is defined by the coordinates of its centre (@a x, @a y) or
        @a c and its radius @a r. The arc goes from the starting angle @a
        startAngle to @a endAngle either clockwise or counter-clockwise
        depending on the value of @a clockwise argument.

        The angles are measured in radians but, contrary to the usual
        mathematical convention, are always @e clockwise from the horizontal
        axis.
    */
    //@{
    virtual void AddArc(wxDouble x, wxDouble y, wxDouble r,
                        wxDouble startAngle, wxDouble endAngle,
                        bool clockwise);
    void AddArc(const wxPoint2DDouble& c, wxDouble r,
                wxDouble startAngle, wxDouble endAngle, bool clockwise);
    //@}

    /**
        Appends a an arc to two tangents connecting (current) to (@a x1,@a y1)
        and (@a x1,@a y1) to (@a x2,@a y2), also a straight line from (current)
        to (@a x1,@a y1).
    */
    virtual void AddArcToPoint(wxDouble x1, wxDouble y1, wxDouble x2,
                               wxDouble y2, wxDouble r);

    /**
        Appends a circle around (@a x,@a y) with radius @a r as a new closed
        subpath.
    */
    virtual void AddCircle(wxDouble x, wxDouble y, wxDouble r);

    /**
        Adds a cubic bezier curve from the current point, using two control
        points and an end point.
    */
    virtual void AddCurveToPoint(wxDouble cx1, wxDouble cy1,
                                 wxDouble cx2, wxDouble cy2,
                                 wxDouble x, wxDouble y);
    /**
        Adds a cubic bezier curve from the current point, using two control
        points and an end point.
    */
    void AddCurveToPoint(const wxPoint2DDouble& c1,
                         const wxPoint2DDouble& c2,
                         const wxPoint2DDouble& e);

    /**
        Appends an ellipse fitting into the passed in rectangle.
    */
    virtual void AddEllipse(wxDouble x, wxDouble y, wxDouble w, wxDouble h);

    /**
        Adds a straight line from the current point to (@a x,@a y).
    */
    virtual void AddLineToPoint(wxDouble x, wxDouble y);
    /**
        Adds a straight line from the current point to @a p.
    */
    void AddLineToPoint(const wxPoint2DDouble& p);

    /**
        Adds another path.
    */
    virtual void AddPath(const wxGraphicsPath& path);

    /**
        Adds a quadratic bezier curve from the current point, using a control
        point and an end point.
    */
    virtual void AddQuadCurveToPoint(wxDouble cx, wxDouble cy,
                                     wxDouble x, wxDouble y);

    /**
        Appends a rectangle as a new closed subpath.
    */
    virtual void AddRectangle(wxDouble x, wxDouble y, wxDouble w, wxDouble h);

    /**
        Appends a rounded rectangle as a new closed subpath.
    */
    virtual void AddRoundedRectangle(wxDouble x, wxDouble y, wxDouble w,
                                     wxDouble h, wxDouble radius);

    /**
        Closes the current sub-path.
    */
    virtual void CloseSubpath();

    /**
        @return @true if the point is within the path.
    */
    bool Contains(const wxPoint2DDouble& c,
                  int fillStyle = wxODDEVEN_RULE) const;
    /**
        @return @true if the point is within the path.
    */
    virtual bool Contains(wxDouble x, wxDouble y,
                          int fillStyle = wxODDEVEN_RULE) const;

    /**
        Gets the bounding box enclosing all points (possibly including control
        points).
    */
    wxRect2DDouble GetBox() const;
    /**
        Gets the bounding box enclosing all points (possibly including control
        points).
    */
    virtual void GetBox(wxDouble* x, wxDouble* y,
                        wxDouble* w, wxDouble* h) const;

    /**
        Gets the last point of the current path, (0,0) if not yet set.
    */
    virtual void GetCurrentPoint(wxDouble* x, wxDouble* y) const;
    /**
        Gets the last point of the current path, (0,0) if not yet set.
    */
    wxPoint2DDouble GetCurrentPoint() const;

    /**
        Returns the native path (CGPathRef for Core Graphics, Path pointer for
        GDIPlus and a cairo_path_t pointer for cairo).
    */
    virtual void* GetNativePath() const;

    /**
        Begins a new subpath at (@a x,@a y).
    */
    virtual void MoveToPoint(wxDouble x, wxDouble y);
    /**
        Begins a new subpath at @a p.
    */
    void MoveToPoint(const wxPoint2DDouble& p);

    /**
        Transforms each point of this path by the matrix.
    */
    virtual void Transform(const wxGraphicsMatrix& matrix);

    /**
        Gives back the native path returned by GetNativePath() because there
        might be some deallocations necessary (e.g. on cairo the native path
        returned by GetNativePath() is newly allocated each time).
    */
    virtual void UnGetNativePath(void* p) const;
};



/**
    @class wxGraphicsObject

    This class is the superclass of native graphics objects like pens etc. It
    allows reference counting. Not instantiated by user code.

    @library{wxcore}
    @category{gdi}

    @see wxGraphicsBrush, wxGraphicsPen, wxGraphicsMatrix, wxGraphicsPath
*/
class wxGraphicsObject : public wxObject
{
public:
    /**
        Returns the renderer that was used to create this instance, or @NULL
        if it has not been initialized yet.
    */
    wxGraphicsRenderer* GetRenderer() const;

    /**
        @return @false if this object is valid, otherwise returns @true.
    */
    bool IsNull() const;
};

/**
    Anti-aliasing modes used by wxGraphicsContext::SetAntialiasMode().
*/
enum wxAntialiasMode
{
    /** No anti-aliasing */
    wxANTIALIAS_NONE,

    /** The default anti-aliasing */
    wxANTIALIAS_DEFAULT,
};

/**
    Compositing is done using Porter-Duff compositions
    (see http://keithp.com/~keithp/porterduff/p253-porter.pdf) with
    wxGraphicsContext::SetCompositionMode().

    The description give a short equation on how the values of a resulting
    pixel are calculated.
    @e R = Result, @e S = Source, @e D = Destination, colors premultiplied with alpha
    @e Ra, @e Sa, @e Da their alpha components
*/
enum wxCompositionMode
{
    wxCOMPOSITION_CLEAR, /**< @e R = 0 */
    wxCOMPOSITION_SOURCE, /**< @e R = S */
    wxCOMPOSITION_OVER, /**< @e R = @e S + @e D*(1 - @e Sa) */
    wxCOMPOSITION_IN, /**< @e R = @e S*@e Da */
    wxCOMPOSITION_OUT, /**< @e R = @e S*(1 - @e Da) */
    wxCOMPOSITION_ATOP, /**< @e R = @e S*@e Da + @e D*(1 - @e Sa) */

    wxCOMPOSITION_DEST, /**< @e R = @e D, essentially a noop */
    wxCOMPOSITION_DEST_OVER, /**< @e R = @e S*(1 - @e Da) + @e D */
    wxCOMPOSITION_DEST_IN, /**< @e R = @e D*@e Sa */
    wxCOMPOSITION_DEST_OUT, /**< @e R = @e D*(1 - @e Sa) */
    wxCOMPOSITION_DEST_ATOP, /**< @e R = @e S*(1 - @e Da) + @e D*@e Sa */
    wxCOMPOSITION_XOR, /**< @e R = @e S*(1 - @e Da) + @e D*(1 - @e Sa) */
    wxCOMPOSITION_ADD, /**< @e R = @e S + @e D */
};


/**
    @class wxGraphicsContext

    A wxGraphicsContext instance is the object that is drawn upon. It is
    created by a renderer using wxGraphicsRenderer::CreateContext(). This can
    be either directly using a renderer instance, or indirectly using the
    static convenience Create() functions of wxGraphicsContext that always
    delegate the task to the default renderer.

    @code
    void MyCanvas::OnPaint(wxPaintEvent &event)
    {
        // Create paint DC
        wxPaintDC dc(this);

        // Create graphics context from it
        wxGraphicsContext *gc = wxGraphicsContext::Create( dc );

        if (gc)
        {
            // make a path that contains a circle and some lines
            gc->SetPen( *wxRED_PEN );
            wxGraphicsPath path = gc->CreatePath();
            path.AddCircle( 50.0, 50.0, 50.0 );
            path.MoveToPoint(0.0, 50.0);
            path.AddLineToPoint(100.0, 50.0);
            path.MoveToPoint(50.0, 0.0);
            path.AddLineToPoint(50.0, 100.0 );
            path.CloseSubpath();
            path.AddRectangle(25.0, 25.0, 50.0, 50.0);

            gc->StrokePath(path);

            delete gc;
        }
    }
    @endcode

    @library{wxcore}
    @category{gdi,dc}

    @see wxGraphicsRenderer::CreateContext(), wxGCDC, wxDC
*/
class wxGraphicsContext : public wxGraphicsObject
{
public:
    /**
        Creates a wxGraphicsContext from a wxWindow.

        @see wxGraphicsRenderer::CreateContext()
    */
    static wxGraphicsContext* Create(wxWindow* window);

    /**
        Creates a wxGraphicsContext from a wxWindowDC

        @see wxGraphicsRenderer::CreateContext()
    */
    static wxGraphicsContext* Create(const wxWindowDC& dc);

    /**
        Creates a wxGraphicsContext from a wxMemoryDC

        @see wxGraphicsRenderer::CreateContext()
    */
    static wxGraphicsContext* Create(const wxMemoryDC& dc);

    /**
        Creates a wxGraphicsContext from a wxPrinterDC. Under GTK+, this will
        only work when using the GtkPrint printing backend which is available
        since GTK+ 2.10.

        @see wxGraphicsRenderer::CreateContext(), @ref overview_unixprinting
    */
    static wxGraphicsContext* Create(const wxPrinterDC& dc);

    /**
        Clips drawings to the specified region.
    */
    virtual void Clip(const wxRegion& region) = 0;

    /**
        Clips drawings to the specified rectangle.
    */
    virtual void Clip(wxDouble x, wxDouble y, wxDouble w, wxDouble h) = 0;

    /**
        Concatenates the passed in transform with the current transform of this
        context.
    */
    virtual void ConcatTransform(const wxGraphicsMatrix& matrix) = 0;

    /**
        Creates a native brush from a wxBrush.
    */
    virtual wxGraphicsBrush CreateBrush(const wxBrush& brush) const;

    /**
        Creates a native graphics font from a wxFont and a text colour.
    */
    virtual wxGraphicsFont CreateFont(const wxFont& font,
                                      const wxColour& col = *wxBLACK) const;

    /**
        Creates a wxGraphicsContext from a native context. This native context
        must be a CGContextRef for Core Graphics, a Graphics pointer for
        GDIPlus, or a cairo_t pointer for cairo.

        @see wxGraphicsRenderer::CreateContextFromNativeContext()
    */
    static wxGraphicsContext* CreateFromNative(void* context);

    /**
        Creates a wxGraphicsContext from a native window.

        @see wxGraphicsRenderer::CreateContextFromNativeWindow()
    */
    static wxGraphicsContext* CreateFromNativeWindow(void* window);

    /**
        Creates a native brush with a linear gradient.

        The brush starts at (@a x1, @a y1) and ends at (@a x2, @a y2). Either
        just the start and end gradient colours (@a c1 and @a c2) or full set
        of gradient @a stops can be specified.

        The version taking wxGraphicsGradientStops is new in wxWidgets 2.9.1.
    */
    //@{
    wxGraphicsBrush
    CreateLinearGradientBrush(wxDouble x1, wxDouble y1,
                              wxDouble x2, wxDouble y2,
                              const wxColour& c1, const wxColour& c2) const;

    wxGraphicsBrush
    CreateLinearGradientBrush(wxDouble x1, wxDouble y1,
                              wxDouble x2, wxDouble y2,
                              const wxGraphicsGradientStops& stops) const;
    //@}

    /**
        Creates a native affine transformation matrix from the passed in
        values. The default parameters result in an identity matrix.
    */
    virtual wxGraphicsMatrix CreateMatrix(wxDouble a = 1.0, wxDouble b = 0.0,
                                          wxDouble c = 0.0, wxDouble d = 1.0,
                                          wxDouble tx = 0.0,
                                          wxDouble ty = 0.0) const;

    /**
        Creates a native graphics path which is initially empty.
    */
    wxGraphicsPath CreatePath() const;

    /**
        Creates a native pen from a wxPen.
    */
    virtual wxGraphicsPen CreatePen(const wxPen& pen) const;

    /**
        Creates a native brush with a radial gradient.

        The brush originats at (@a xo, @a yc) and ends on a circle around
        (@a xc, @a yc) with the given @a radius.

        The gradient may be specified either by its start and end colours @a
        oColor and @a cColor or by a full set of gradient @a stops.

        The version taking wxGraphicsGradientStops is new in wxWidgets 2.9.1.
    */
    //@{
    virtual wxGraphicsBrush
    CreateRadialGradientBrush(wxDouble xo, wxDouble yo,
                              wxDouble xc, wxDouble yc,
                              wxDouble radius,
                              const wxColour& oColor,
                              const wxColour& cColor) const;

    virtual wxGraphicsBrush
    CreateRadialGradientBrush(wxDouble xo, wxDouble yo,
                              wxDouble xc, wxDouble yc,
                              wxDouble radius,
                              const wxGraphicsGradientStops& stops) = 0;
    //@}

    /**
        Draws the bitmap. In case of a mono bitmap, this is treated as a mask
        and the current brushed is used for filling.
    */
    virtual void DrawBitmap(const wxBitmap& bmp, wxDouble x, wxDouble y,
                            wxDouble w, wxDouble h) = 0;

    /**
        Draws an ellipse.
    */
    virtual void DrawEllipse(wxDouble x, wxDouble y, wxDouble w, wxDouble h);

    /**
        Draws the icon.
    */
    virtual void DrawIcon(const wxIcon& icon, wxDouble x, wxDouble y,
                          wxDouble w, wxDouble h) = 0;

    /**
        Draws a polygon.
    */
    virtual void DrawLines(size_t n, const wxPoint2DDouble* points,
                           wxPolygonFillMode fillStyle = wxODDEVEN_RULE);

    /**
        Draws the path by first filling and then stroking.
    */
    virtual void DrawPath(const wxGraphicsPath& path,
                          wxPolygonFillMode fillStyle = wxODDEVEN_RULE);

    /**
        Draws a rectangle.
    */
    virtual void DrawRectangle(wxDouble x, wxDouble y, wxDouble w, wxDouble h);

    /**
        Draws a rounded rectangle.
    */
    virtual void DrawRoundedRectangle(wxDouble x, wxDouble y, wxDouble w,
                                      wxDouble h, wxDouble radius);

    /**
        Draws text at the defined position.
    */
    void DrawText(const wxString& str, wxDouble x, wxDouble y);
    /**
        Draws text at the defined position.

        @param str
            The text to draw.
        @param x
            The x coordinate position to draw the text at.
        @param y
            The y coordinate position to draw the text at.
        @param angle
            The angle relative to the (default) horizontal direction to draw
            the string.
    */
    void DrawText(const wxString& str, wxDouble x, wxDouble y, wxDouble angle);
    /**
        Draws text at the defined position.

        @param str
            The text to draw.
        @param x
            The x coordinate position to draw the text at.
        @param y
            The y coordinate position to draw the text at.
        @param backgroundBrush
            Brush to fill the text with.
    */
    void DrawText(const wxString& str, wxDouble x, wxDouble y,
                  const wxGraphicsBrush& backgroundBrush);
    /**
        Draws text at the defined position.

        @param str
            The text to draw.
        @param x
            The x coordinate position to draw the text at.
        @param y
            The y coordinate position to draw the text at.
        @param angle
            The angle relative to the (default) horizontal direction to draw
            the string.
        @param backgroundBrush
            Brush to fill the text with.
    */
    void DrawText(const wxString& str, wxDouble x, wxDouble y,
                  wxDouble angle, const wxGraphicsBrush& backgroundBrush);

    /**
        Fills the path with the current brush.
    */
    virtual void FillPath(const wxGraphicsPath& path,
                          wxPolygonFillMode fillStyle = wxODDEVEN_RULE) = 0;

    /**
        Returns the native context (CGContextRef for Core Graphics, Graphics
        pointer for GDIPlus and cairo_t pointer for cairo).
    */
    virtual void* GetNativeContext() = 0;

    /**
        Fills the @a widths array with the widths from the beginning of
        @a text to the corresponding character of @a text.
    */
    virtual void GetPartialTextExtents(const wxString& text,
                                       wxArrayDouble& widths) const = 0;

    /**
        Gets the dimensions of the string using the currently selected font.

        @param text
            The text string to measure.
        @param width
            Variable to store the total calculated width of the text.
        @param height
            Variable to store the total calculated height of the text.
        @param descent
            Variable to store the dimension from the baseline of the font to
            the bottom of the descender.
        @param externalLeading
            Any extra vertical space added to the font by the font designer
            (usually is zero).
    */
    virtual void GetTextExtent(const wxString& text, wxDouble* width,
                               wxDouble* height, wxDouble* descent,
                               wxDouble* externalLeading) const = 0;

    /**
        Gets the current transformation matrix of this context.
    */
    virtual wxGraphicsMatrix GetTransform() const = 0;

    /**
        Resets the clipping to original shape.
    */
    virtual void ResetClip() = 0;

    /**
        Rotates the current transformation matrix (in radians).
    */
    virtual void Rotate(wxDouble angle) = 0;

    /**
        Scales the current transformation matrix.
    */
    virtual void Scale(wxDouble xScale, wxDouble yScale) = 0;

    /**
        Sets the brush for filling paths.
    */
    void SetBrush(const wxBrush& brush);
    /**
        Sets the brush for filling paths.
    */
    virtual void SetBrush(const wxGraphicsBrush& brush);

    /**
        Sets the font for drawing text.
    */
    void SetFont(const wxFont& font, const wxColour& colour);
    /**
        Sets the font for drawing text.
    */
    virtual void SetFont(const wxGraphicsFont& font);

    /**
        Sets the pen used for stroking.
    */
    void SetPen(const wxPen& pen);
    /**
        Sets the pen used for stroking.
    */
    virtual void SetPen(const wxGraphicsPen& pen);

    /**
        Sets the current transformation matrix of this context
    */
    virtual void SetTransform(const wxGraphicsMatrix& matrix) = 0;

    /**
        Strokes a single line.
    */
    virtual void StrokeLine(wxDouble x1, wxDouble y1, wxDouble x2, wxDouble y2);

    /**
        Stroke disconnected lines from begin to end points, fastest method
        available for this purpose.
    */
    virtual void StrokeLines(size_t n, const wxPoint2DDouble* beginPoints,
                             const wxPoint2DDouble* endPoints);
    /**
        Stroke disconnected lines from begin to end points, fastest method
        available for this purpose.
    */
    virtual void StrokeLines(size_t n, const wxPoint2DDouble* points);

    /**
        Strokes along a path with the current pen.
    */
    virtual void StrokePath(const wxGraphicsPath& path) = 0;

    /**
        Translates the current transformation matrix.
    */
    virtual void Translate(wxDouble dx, wxDouble dy) = 0;

    /**
        Redirects all rendering is done into a fully transparent temporary context
    */
    virtual void BeginLayer(wxDouble opacity) = 0;

    /**
        Composites back the drawings into the context with the opacity given at
        the BeginLayer call
    */
    virtual void EndLayer() = 0;

    /**
        Sets the antialiasing mode, returns true if it supported
    */
    virtual bool SetAntialiasMode(wxAntialiasMode antialias) = 0;

    /**
        Returns the current shape antialiasing mode
    */
    virtual wxAntialiasMode GetAntialiasMode() const ;

    /**
        Sets the compositing operator, returns true if it supported
    */
    virtual bool SetCompositionMode(wxCompositionMode op) = 0;

    /**
        Returns the current compositing operator
    */
    virtual wxCompositionMode GetCompositionMode() const;

};

/**
    Represents a single gradient stop in a collection of gradient stops as
    represented by wxGraphicsGradientStops.

    @library{wxcore}
    @category{gdi}

    @since 2.9.1
*/
class wxGraphicsGradientStop
{
public:
    /**
        Creates a stop with the given colour and position.

        @param col The colour of this stop. Note that the alpha component of
            the colour is honoured thus allowing the background colours to
            partially show through the gradient.
        @param pos The stop position, must be in [0, 1] range with 0 being the
            beginning and 1 the end of the gradient.
    */
    wxGraphicsGradientStop(wxColour col = wxTransparentColour, float pos = 0.);

    /// Return the stop colour.
    const wxColour& GetColour() const;

    /**
        Change the stop colour.

        @param col The new colour.
    */
    void SetColour(const wxColour& col);

    /// Return the stop position.
    float GetPosition() const;

    /**
        Change the stop position.

        @param pos The new position, must always be in [0, 1] range.
    */
    void SetPosition(float pos);
};

/**
    Represents a collection of wxGraphicGradientStop values for use with
    CreateLinearGradientBrush and CreateRadialGradientBrush.

    The stops are maintained in order of position.  If two or more stops are
    added with the same position then the one(s) added later come later.
    This can be useful for producing discontinuities in the colour gradient.

    Notice that this class is write-once, you can't modify the stops once they
    had been added.

    @library{wxcore}
    @category{gdi}

    @since 2.9.1
*/
class wxGraphicsGradientStops
{
public:
    /**
        Initializes the gradient stops with the given boundary colours.

        Creates a wxGraphicsGradientStops instance with start colour given
        by @a startCol and end colour given by @a endCol.
    */
    wxGraphicsGradientStops(wxColour startCol = wxTransparentColour,
                            wxColour endCol = wxTransparentColour);

    /**
        Add a new stop.
    */
    //@{
    void Add(const wxGraphicsGradientStop& stop);
    void Add(wxColour col, float pos);
    //@}

    /**
        Returns the stop at the given index.

        @param n The index, must be in [0, GetCount()) range.
    */
    wxGraphicsGradientStop Item(unsigned n) const;

    /**
        Returns the number of stops.
    */
    unsigned GetCount() const;

    /**
        Set the start colour to @a col
    */
    void SetStartColour(wxColour col);

    /**
        Returns the start colour.
    */
    wxColour GetStartColour() const;

    /**
        Set the end colour to @a col
    */
    void SetEndColour(wxColour col);

    /**
        Returns the end colour.
    */
    wxColour GetEndColour() const;
};

/**
    @class wxGraphicsRenderer

    A wxGraphicsRenderer is the instance corresponding to the rendering engine
    used. There may be multiple instances on a system, if there are different
    rendering engines present, but there is always only one instance per
    engine. This instance is pointed back to by all objects created by it
    (wxGraphicsContext, wxGraphicsPath etc) and can be retrieved through their
    wxGraphicsObject::GetRenderer() method. Therefore you can create an
    additional instance of a path etc. by calling
    wxGraphicsObject::GetRenderer() and then using the appropriate CreateXXX()
    function of that renderer.

    @code
    wxGraphicsPath *path = // from somewhere
    wxGraphicsBrush *brush = path->GetRenderer()->CreateBrush( *wxBLACK_BRUSH );
    @endcode

    @library{wxcore}
    @category{gdi}
*/
class wxGraphicsRenderer : public wxObject
{
public:
    /**
        Creates a wxGraphicsContext from a wxWindow.
    */
    virtual wxGraphicsContext* CreateContext(wxWindow* window) = 0;

    /**
        Creates a wxGraphicsContext from a wxWindowDC
    */
    virtual wxGraphicsContext* CreateContext(const wxWindowDC& dc) = 0 ;

    /**
        Creates a wxGraphicsContext from a wxMemoryDC
    */
    virtual wxGraphicsContext* CreateContext(const wxMemoryDC& dc) = 0 ;

    /**
        Creates a wxGraphicsContext from a wxPrinterDC
    */
    virtual wxGraphicsContext* CreateContext(const wxPrinterDC& dc) = 0 ;

    /**
        Creates a native brush from a wxBrush.
    */
    virtual wxGraphicsBrush CreateBrush(const wxBrush& brush) = 0;

    /**
        Creates a wxGraphicsContext from a native context. This native context
        must be a CGContextRef for Core Graphics, a Graphics pointer for
        GDIPlus, or a cairo_t pointer for cairo.
    */
    virtual wxGraphicsContext* CreateContextFromNativeContext(void* context) = 0;

    /**
        Creates a wxGraphicsContext from a native window.
    */
    virtual wxGraphicsContext* CreateContextFromNativeWindow(void* window) = 0;

    /**
        Creates a wxGraphicsContext that can be used for measuring texts only.
        No drawing commands are allowed.
    */
    virtual wxGraphicsContext * CreateMeasuringContext() = 0;

    /**
        Creates a native graphics font from a wxFont and a text colour.
    */
    virtual wxGraphicsFont CreateFont(const wxFont& font,
                                      const wxColour& col = *wxBLACK) = 0;


    /**
        Creates a native brush with a linear gradient.

        Stops support is new since wxWidgets 2.9.1, previously only the start
        and end colours could be specified.
    */
    virtual wxGraphicsBrush CreateLinearGradientBrush(wxDouble x1,
                                                      wxDouble y1,
                                                      wxDouble x2,
                                                      wxDouble y2,
                                                      const wxGraphicsGradientStops& stops) = 0;

    /**
        Creates a native affine transformation matrix from the passed in
        values. The defaults result in an identity matrix.
    */
    virtual wxGraphicsMatrix CreateMatrix(wxDouble a = 1.0, wxDouble b = 0.0,
                                          wxDouble c = 0.0, wxDouble d = 1.0,
                                          wxDouble tx = 0.0,
                                          wxDouble ty = 0.0) = 0;

    /**
        Creates a native graphics path which is initially empty.
    */
    virtual wxGraphicsPath CreatePath() = 0;

    /**
        Creates a native pen from a wxPen.
    */
    virtual wxGraphicsPen CreatePen(const wxPen& pen) = 0;

    /**
        Creates a native brush with a radial gradient.

        Stops support is new since wxWidgets 2.9.1, previously only the start
        and end colours could be specified.
    */
    virtual wxGraphicsBrush CreateRadialGradientBrush(wxDouble xo, wxDouble yo,
                                                      wxDouble xc, wxDouble yc,
                                                      wxDouble radius,
                                                      const wxGraphicsGradientStops& stops) = 0;

    /**
        Returns the default renderer on this platform. On OS X this is the Core
        Graphics (a.k.a. Quartz 2D) renderer, on MSW the GDIPlus renderer, and
        on GTK we currently default to the cairo renderer.
    */
    static wxGraphicsRenderer* GetDefaultRenderer();
};



/**
    @class wxGraphicsBrush

    A wxGraphicsBrush is a native representation of a brush. The contents are
    specific and private to the respective renderer. Instances are ref counted
    and can therefore be assigned as usual. The only way to get a valid
    instance is via wxGraphicsContext::CreateBrush() or
    wxGraphicsRenderer::CreateBrush().

    @library{wxcore}
    @category{gdi}
*/
class wxGraphicsBrush : public wxGraphicsObject
{
public:

};



/**
    @class wxGraphicsFont

    A wxGraphicsFont is a native representation of a font. The contents are
    specific and private to the respective renderer. Instances are ref counted
    and can therefore be assigned as usual. The only way to get a valid
    instance is via wxGraphicsContext::CreateFont() or
    wxGraphicsRenderer::CreateFont().

    @library{wxcore}
    @category{gdi}
*/
class wxGraphicsFont : public wxGraphicsObject
{
public:

};



/**
    @class wxGraphicsPen

    A wxGraphicsPen is a native representation of a pen. The contents are
    specific and private to the respective renderer. Instances are ref counted
    and can therefore be assigned as usual. The only way to get a valid
    instance is via wxGraphicsContext::CreatePen() or
    wxGraphicsRenderer::CreatePen().

    @library{wxcore}
    @category{gdi}
*/
class wxGraphicsPen : public wxGraphicsObject
{
public:

};



/**
    @class wxGraphicsMatrix

    A wxGraphicsMatrix is a native representation of an affine matrix. The
    contents are specific and private to the respective renderer. Instances are
    ref counted and can therefore be assigned as usual. The only way to get a
    valid instance is via wxGraphicsContext::CreateMatrix() or
    wxGraphicsRenderer::CreateMatrix().

    @library{wxcore}
    @category{gdi}
*/
class wxGraphicsMatrix : public wxGraphicsObject
{
public:
    /**
        Concatenates the matrix passed with the current matrix.
    */
    virtual void Concat(const wxGraphicsMatrix* t);
    /**
        Concatenates the matrix passed with the current matrix.
    */
    void Concat(const wxGraphicsMatrix& t);

    /**
        Returns the component values of the matrix via the argument pointers.
    */
    virtual void Get(wxDouble* a = NULL, wxDouble* b = NULL,
                     wxDouble* c = NULL, wxDouble* d = NULL,
                     wxDouble* tx = NULL, wxDouble* ty = NULL) const;

    /**
        Returns the native representation of the matrix. For CoreGraphics this
        is a CFAffineMatrix pointer, for GDIPlus a Matrix Pointer, and for
        Cairo a cairo_matrix_t pointer.
    */
    virtual void* GetNativeMatrix() const;

    /**
        Inverts the matrix.
    */
    virtual void Invert();

    /**
        Returns @true if the elements of the transformation matrix are equal.
    */
    virtual bool IsEqual(const wxGraphicsMatrix* t) const;
    /**
        Returns @true if the elements of the transformation matrix are equal.
    */
    bool IsEqual(const wxGraphicsMatrix& t) const;

    /**
        Return @true if this is the identity matrix.
    */
    virtual bool IsIdentity() const;

    /**
        Rotates this matrix (in radians).
    */
    virtual void Rotate(wxDouble angle);

    /**
        Scales this matrix.
    */
    virtual void Scale(wxDouble xScale, wxDouble yScale);

    /**
        Sets the matrix to the respective values (default values are the
        identity matrix).
    */
    virtual void Set(wxDouble a = 1.0, wxDouble b = 0.0, wxDouble c = 0.0,
                     wxDouble d = 1.0, wxDouble tx = 0.0, wxDouble ty = 0.0);

    /**
        Applies this matrix to a distance (ie. performs all transforms except
        translations).
    */
    virtual void TransformDistance(wxDouble* dx, wxDouble* dy) const;

    /**
        Applies this matrix to a point.
    */
    virtual void TransformPoint(wxDouble* x, wxDouble* y) const;

    /**
        Translates this matrix.
    */
    virtual void Translate(wxDouble dx, wxDouble dy);
};

