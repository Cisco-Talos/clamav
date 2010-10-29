/////////////////////////////////////////////////////////////////////////////
// Name:        gdicmn.h
// Purpose:     interface of wxRealPoint
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


/**
    Bitmap type flags. See wxBitmap and wxImage classes.
*/
enum wxBitmapType
{
    wxBITMAP_TYPE_INVALID,
    wxBITMAP_TYPE_BMP,
    wxBITMAP_TYPE_BMP_RESOURCE,
    wxBITMAP_TYPE_RESOURCE = wxBITMAP_TYPE_BMP_RESOURCE,
    wxBITMAP_TYPE_ICO,
    wxBITMAP_TYPE_ICO_RESOURCE,
    wxBITMAP_TYPE_CUR,
    wxBITMAP_TYPE_CUR_RESOURCE,
    wxBITMAP_TYPE_XBM,
    wxBITMAP_TYPE_XBM_DATA,
    wxBITMAP_TYPE_XPM,
    wxBITMAP_TYPE_XPM_DATA,
    wxBITMAP_TYPE_TIF,
    wxBITMAP_TYPE_TIF_RESOURCE,
    wxBITMAP_TYPE_GIF,
    wxBITMAP_TYPE_GIF_RESOURCE,
    wxBITMAP_TYPE_PNG,
    wxBITMAP_TYPE_PNG_RESOURCE,
    wxBITMAP_TYPE_JPEG,
    wxBITMAP_TYPE_JPEG_RESOURCE,
    wxBITMAP_TYPE_PNM,
    wxBITMAP_TYPE_PNM_RESOURCE,
    wxBITMAP_TYPE_PCX,
    wxBITMAP_TYPE_PCX_RESOURCE,
    wxBITMAP_TYPE_PICT,
    wxBITMAP_TYPE_PICT_RESOURCE,
    wxBITMAP_TYPE_ICON,
    wxBITMAP_TYPE_ICON_RESOURCE,
    wxBITMAP_TYPE_ANI,
    wxBITMAP_TYPE_IFF,
    wxBITMAP_TYPE_TGA,
    wxBITMAP_TYPE_MACCURSOR,
    wxBITMAP_TYPE_MACCURSOR_RESOURCE,
    wxBITMAP_TYPE_ANY = 50
};

/**
    Polygon filling mode. See wxDC::DrawPolygon.
*/
enum wxPolygonFillMode
{
    wxODDEVEN_RULE = 1,
    wxWINDING_RULE
};

/**
    Standard cursors.

    Notice that under wxMSW some of these cursors are defined in @c wx.rc file
    and not by the system itself so you should include this file from your own
    resource file (possibly creating a trivial resource file just containing a
    single include line if you don't need it otherwise) to be able to use them.

    See wxCursor.
*/
enum wxStockCursor
{
    wxCURSOR_NONE,
    wxCURSOR_ARROW,             ///< A standard arrow cursor.
    wxCURSOR_RIGHT_ARROW,       ///< A standard arrow cursor pointing to the right.
    wxCURSOR_BULLSEYE,          ///< Bullseye cursor.
    wxCURSOR_CHAR,              ///< Rectangular character cursor.
    wxCURSOR_CROSS,             ///< A cross cursor.
    wxCURSOR_HAND,              ///< A hand cursor.
    wxCURSOR_IBEAM,             ///< An I-beam cursor (vertical line).
    wxCURSOR_LEFT_BUTTON,       ///< Represents a mouse with the left button depressed.
    wxCURSOR_MAGNIFIER,         ///< A magnifier icon.
    wxCURSOR_MIDDLE_BUTTON,     ///< Represents a mouse with the middle button depressed.
    wxCURSOR_NO_ENTRY,          ///< A no-entry sign cursor.
    wxCURSOR_PAINT_BRUSH,       ///< A paintbrush cursor.
    wxCURSOR_PENCIL,            ///< A pencil cursor.
    wxCURSOR_POINT_LEFT,        ///< A cursor that points left.
    wxCURSOR_POINT_RIGHT,       ///< A cursor that points right.
    wxCURSOR_QUESTION_ARROW,    ///< An arrow and question mark.
    wxCURSOR_RIGHT_BUTTON,      ///< Represents a mouse with the right button depressed.
    wxCURSOR_SIZENESW,          ///< A sizing cursor pointing NE-SW.
    wxCURSOR_SIZENS,            ///< A sizing cursor pointing N-S.
    wxCURSOR_SIZENWSE,          ///< A sizing cursor pointing NW-SE.
    wxCURSOR_SIZEWE,            ///< A sizing cursor pointing W-E.
    wxCURSOR_SIZING,            ///< A general sizing cursor.
    wxCURSOR_SPRAYCAN,          ///< A spraycan cursor.
    wxCURSOR_WAIT,              ///< A wait cursor.
    wxCURSOR_WATCH,             ///< A watch cursor.
    wxCURSOR_BLANK,             ///< Transparent cursor.
    wxCURSOR_DEFAULT,           ///< Standard X11 cursor (only in wxGTK).
    wxCURSOR_COPY_ARROW ,       ///< MacOS Theme Plus arrow (only in wxMac).
    wxCURSOR_CROSS_REVERSE,     ///< Only available on wxX11.
    wxCURSOR_DOUBLE_ARROW,      ///< Only available on wxX11.
    wxCURSOR_BASED_ARROW_UP,    ///< Only available on wxX11.
    wxCURSOR_BASED_ARROW_DOWN,  ///< Only available on wxX11.
    wxCURSOR_ARROWWAIT,         ///< A wait cursor with a standard arrow.
    wxCURSOR_MAX
};



/**
    @class wxRealPoint

    A wxRealPoint is a useful data structure for graphics operations.

    It contains floating point @e x and @e y members.
    See wxPoint for an integer version.

    Note that the coordinates stored inside a wxRealPoint object may be negative
    and that wxRealPoint functions do not perform any check against negative values.

    @library{wxcore}
    @category{data}

    @see wxPoint
*/
class wxRealPoint
{
public:
    /**
        Initializes to zero the x and y members.
    */
    wxRealPoint();

    /**
        Initializes the point with the given coordinates.
    */
    wxRealPoint(double x, double y);

    /**
        Converts the given wxPoint (with integer coordinates) to a wxRealPoint.
    */
    wxRealPoint(const wxPoint& pt);

    /**
        @name Miscellaneous operators

        Note that these operators are documented as class members
        (to make them easier to find) but, as their prototype shows,
        they are implemented as global operators; note that this is
        transparent to the user but it helps to understand why the
        following functions are documented to take the wxPoint they
        operate on as an explicit argument.
    */
    //@{
    wxRealPoint& operator=(const wxRealPoint& pt);

    bool operator ==(const wxRealPoint& p1, const wxRealPoint& p2);
    bool operator !=(const wxRealPoint& p1, const wxRealPoint& p2);

    wxRealPoint operator +(const wxRealPoint& p1, const wxRealPoint& p2);
    wxRealPoint operator -(const wxRealPoint& p1, const wxRealPoint& p2);

    wxRealPoint& operator +=(const wxRealPoint& pt);
    wxRealPoint& operator -=(const wxRealPoint& pt);

    wxRealPoint operator +(const wxRealPoint& pt, const wxSize& sz);
    wxRealPoint operator -(const wxRealPoint& pt, const wxSize& sz);
    wxRealPoint operator +(const wxSize& sz, const wxRealPoint& pt);
    wxRealPoint operator -(const wxSize& sz, const wxRealPoint& pt);

    wxRealPoint& operator +=(const wxSize& sz);
    wxRealPoint& operator -=(const wxSize& sz);

    wxSize operator /(const wxRealPoint& sz, int factor);
    wxSize operator *(const wxRealPoint& sz, int factor);
    wxSize operator *(int factor, const wxSize& sz);
    wxSize& operator /=(int factor);
    wxSize& operator *=(int factor);
    //@}

    /**
        X coordinate of this point.
    */
    double x;

    /**
        Y coordinate of this point.
    */
    double y;
};



/**
    @class wxRect

    A class for manipulating rectangles.

    Note that the x, y coordinates and the width and height stored inside a wxRect
    object may be negative and that wxRect functions do not perform any check against
    negative values.

    @library{wxcore}
    @category{data}

    @see wxPoint, wxSize
*/
class wxRect
{
public:
    /**
        Default constructor.
        Initializes to zero the internal @a x, @a y, @a width and @a height members.
    */
    wxRect();
    /**
        Creates a wxRect object from @a x, @a y, @a width and @a height values.
    */
    wxRect(int x, int y, int width, int height);
    /**
        Creates a wxRect object from top-left and bottom-right points.
    */
    wxRect(const wxPoint& topLeft, const wxPoint& bottomRight);
    /**
        Creates a wxRect object from position @a pos and @a size values.
    */
    wxRect(const wxPoint& pos, const wxSize& size);
    /**
        Creates a wxRect object from @a size values at the origin.
    */
    wxRect(const wxSize& size);

    //@{
    /**
        Returns the rectangle having the same size as this one but centered
        relatively to the given rectangle @a r. By default, rectangle is
        centred in both directions but if @a dir includes only @c wxVERTICAL or
        only @c wxHORIZONTAL, then it is only centered in this direction while
        the other component of its position remains unchanged.
    */
    wxRect CentreIn(const wxRect& r, int dir = wxBOTH) const;
    wxRect CenterIn(const wxRect& r, int dir = wxBOTH) const;
    //@}

    /**
        Returns @true if the given point is inside the rectangle (or on its
        boundary) and @false otherwise.
    */
    bool Contains(int x, int y) const;
    /**
        Returns @true if the given point is inside the rectangle (or on its
        boundary) and @false otherwise.
    */
    bool Contains(const wxPoint& pt) const;
    /**
        Returns @true if the given rectangle is completely inside this
        rectangle (or touches its boundary) and @false otherwise.
    */
    bool Contains(const wxRect& rect) const;

    //@{
    /**
        Decrease the rectangle size.

        This method is the opposite from Inflate(): Deflate(a, b) is equivalent
        to Inflate(-a, -b). Please refer to Inflate() for full description.
    */
    void Deflate(wxCoord dx, wxCoord dy);
    void Deflate(const wxSize& diff);
    void Deflate(wxCoord diff);
    wxRect Deflate(wxCoord dx, wxCoord dy) const;
    //@}

    /**
        Gets the bottom point of the rectangle.
    */
    int GetBottom() const;

    /**
        Gets the position of the bottom left corner.
    */
    wxPoint GetBottomLeft() const;

    /**
        Gets the position of the bottom right corner.
    */
    wxPoint GetBottomRight() const;

    /**
        Gets the height member.
    */
    int GetHeight() const;

    /**
        Gets the left point of the rectangle (the same as GetX()).
    */
    int GetLeft() const;

    /**
        Gets the position.
    */
    wxPoint GetPosition() const;

    /**
        Gets the right point of the rectangle.
    */
    int GetRight() const;

    /**
        Gets the size.

        @see SetSize()
    */
    wxSize GetSize() const;

    /**
        Gets the top point of the rectangle (the same as GetY()).
    */
    int GetTop() const;

    /**
        Gets the position of the top left corner of the rectangle, same as
        GetPosition().
    */
    wxPoint GetTopLeft() const;

    /**
        Gets the position of the top right corner.
    */
    wxPoint GetTopRight() const;

    /**
        Gets the width member.
    */
    int GetWidth() const;

    /**
        Gets the x member.
    */
    int GetX() const;

    /**
        Gets the y member.
    */
    int GetY() const;

    //@{
    /**
        Increases the size of the rectangle.

        The left border is moved farther left and the right border is moved
        farther right by @a dx. The upper border is moved farther up and the
        bottom border is moved farther down by @a dy. (Note the the width and
        height of the rectangle thus change by 2*dx and 2*dy, respectively.) If
        one or both of @a dx and @a dy are negative, the opposite happens: the
        rectangle size decreases in the respective direction.

        Inflating and deflating behaves "naturally". Defined more precisely,
        that means:
        -# "Real" inflates (that is, @a dx and/or @a dy = 0) are not
           constrained. Thus inflating a rectangle can cause its upper left
           corner to move into the negative numbers. (2.5.4 and older forced
           the top left coordinate to not fall below (0, 0), which implied a
           forced move of the rectangle.)
        -# Deflates are clamped to not reduce the width or height of the
           rectangle below zero. In such cases, the top-left corner is
           nonetheless handled properly. For example, a rectangle at (10, 10)
           with size (20, 40) that is inflated by (-15, -15) will become
           located at (20, 25) at size (0, 10). Finally, observe that the width
           and height are treated independently. In the above example, the
           width is reduced by 20, whereas the height is reduced by the full 30
           (rather than also stopping at 20, when the width reached zero).

        @see Deflate()
    */
    void Inflate(wxCoord dx, wxCoord dy);
    void Inflate(const wxSize& diff);
    void Inflate(wxCoord diff);
    wxRect Inflate(wxCoord dx, wxCoord dy) const;
    //@}

    /**
        Modifies this rectangle to contain the overlapping portion of this rectangle
        and the one passed in as parameter.

        @return This rectangle, modified.
    */
    wxRect& Intersect(const wxRect& rect);

    /**
        Returns the overlapping portion of this rectangle and the one passed in as
        parameter.
    */
    wxRect Intersect(const wxRect& rect) const;

    /**
        Returns @true if this rectangle has a non-empty intersection with the
        rectangle @a rect and @false otherwise.
    */
    bool Intersects(const wxRect& rect) const;

    /**
        Returns @true if this rectangle has a width or height less than or
        equal to 0 and @false otherwise.
    */
    bool IsEmpty() const;

    //@{
    /**
        Moves the rectangle by the specified offset. If @a dx is positive, the
        rectangle is moved to the right, if @a dy is positive, it is moved to the
        bottom, otherwise it is moved to the left or top respectively.
    */
    void Offset(wxCoord dx, wxCoord dy);
    void Offset(const wxPoint& pt);
    //@}

    /**
        Sets the height.
    */
    void SetHeight(int height);

    /**
        Sets the size.

        @see GetSize()
    */
    void SetSize(const wxSize& s);

    /**
        Sets the width.
    */
    void SetWidth(int width);

    /**
        Sets the x position.
    */
    void SetX(int x);

    /**
        Sets the y position.
    */
    void SetY(int y);

    //@{
    /**
        Modifies the rectangle to contain the bounding box of this rectangle
        and the one passed in as parameter.
    */
    wxRect Union(const wxRect& rect) const;
    wxRect& Union(const wxRect& rect);
    //@}

    /**
        Inequality operator.
    */
    bool operator !=(const wxRect& r1, const wxRect& r2);

    //@{
    /**
        Like Union(), but doesn't treat empty rectangles specially.
    */
    wxRect operator +(const wxRect& r1, const wxRect& r2);
    wxRect& operator +=(const wxRect& r);
    //@}

    //@{
    /**
        Returns the intersection of two rectangles (which may be empty).
    */
    wxRect operator *(const wxRect& r1, const wxRect& r2);
    wxRect& operator *=(const wxRect& r);
    //@}

    /**
        Assignment operator.
    */
    wxRect& operator=(const wxRect& rect);

    /**
        Equality operator.
    */
    bool operator ==(const wxRect& r1, const wxRect& r2);

    /**
        Height member.
    */
    int height;

    /**
        Width member.
    */
    int width;

    /**
        x coordinate of the top-level corner of the rectangle.
    */
    int x;

    /**
        y coordinate of the top-level corner of the rectangle.
    */
    int y;
};



/**
    @class wxPoint

    A wxPoint is a useful data structure for graphics operations.

    It contains integer @e x and @e y members.
    See wxRealPoint for a floating point version.

    Note that the width and height stored inside a wxPoint object may be negative
    and that wxPoint functions do not perform any check against negative values
    (this is used to e.g. store the special -1 value in ::wxDefaultPosition instance).

    @library{wxcore}
    @category{data}

    @stdobjects
    ::wxDefaultPosition

    @see wxRealPoint
*/
class wxPoint
{
public:
    /**
        Constructs a point.
        Initializes the internal x and y coordinates to zero.
    */
    wxPoint();

    /**
        Initializes the point object with the given @a x and @a y coordinates.
    */
    wxPoint(int x, int y);

    /**
        Converts the given wxRealPoint (with floating point coordinates) to a
        wxPoint instance.
    */
    wxPoint(const wxRealPoint& pt);

    /**
        @name Miscellaneous operators

        Note that these operators are documented as class members
        (to make them easier to find) but, as their prototype shows,
        they are implemented as global operators; note that this is
        transparent to the user but it helps to understand why the
        following functions are documented to take the wxPoint they
        operate on as an explicit argument.
    */
    //@{
    wxPoint& operator=(const wxPoint& pt);

    bool operator ==(const wxPoint& p1, const wxPoint& p2);
    bool operator !=(const wxPoint& p1, const wxPoint& p2);

    wxPoint operator +(const wxPoint& p1, const wxPoint& p2);
    wxPoint operator -(const wxPoint& p1, const wxPoint& p2);

    wxPoint& operator +=(const wxPoint& pt);
    wxPoint& operator -=(const wxPoint& pt);

    wxPoint operator +(const wxPoint& pt, const wxSize& sz);
    wxPoint operator -(const wxPoint& pt, const wxSize& sz);
    wxPoint operator +(const wxSize& sz, const wxPoint& pt);
    wxPoint operator -(const wxSize& sz, const wxPoint& pt);

    wxPoint& operator +=(const wxSize& sz);
    wxPoint& operator -=(const wxSize& sz);

    wxSize operator /(const wxPoint& sz, int factor);
    wxSize operator *(const wxPoint& sz, int factor);
    wxSize operator *(int factor, const wxSize& sz);
    wxSize& operator /=(int factor);
    wxSize& operator *=(int factor);
    //@}

    /**
        x member.
    */
    int x;

    /**
        y member.
    */
    int  y;
};

/**
    Global istance of a wxPoint initialized with values (-1,-1).
*/
wxPoint wxDefaultPosition;


/**
    @class wxColourDatabase

    wxWidgets maintains a database of standard RGB colours for a predefined
    set of named colours. The application may add to this set if desired by
    using AddColour() and may use it to look up colours by names using Find()
    or find the names for the standard colour using FindName().

    There is one predefined, global instance of this class called
    ::wxTheColourDatabase.

    The standard database contains at least the following colours:

    @beginTable
    <tr><td>
       AQUAMARINE
    @n BLACK
    @n BLUE
    @n BLUE VIOLET
    @n BROWN
    @n CADET BLUE
    @n CORAL
    @n CORNFLOWER BLUE
    @n CYAN
    @n DARK GREY
    @n DARK GREEN
    @n DARK OLIVE GREEN
    @n DARK ORCHID
    @n DARK SLATE BLUE
    @n DARK SLATE GREY
    @n DARK TURQUOISE
    @n DIM GREY
    </td><td>
       FIREBRICK
    @n FOREST GREEN
    @n GOLD
    @n GOLDENROD
    @n GREY
    @n GREEN
    @n GREEN YELLOW
    @n INDIAN RED
    @n KHAKI
    @n LIGHT BLUE
    @n LIGHT GREY
    @n LIGHT STEEL BLUE
    @n LIME GREEN
    @n MAGENTA
    @n MAROON
    @n MEDIUM AQUAMARINE
    @n MEDIUM BLUE
    </td><td>
       MEDIUM FOREST GREEN
    @n MEDIUM GOLDENROD
    @n MEDIUM ORCHID
    @n MEDIUM SEA GREEN
    @n MEDIUM SLATE BLUE
    @n MEDIUM SPRING GREEN
    @n MEDIUM TURQUOISE
    @n MEDIUM VIOLET RED
    @n MIDNIGHT BLUE
    @n NAVY
    @n ORANGE
    @n ORANGE RED
    @n ORCHID
    @n PALE GREEN
    @n PINK
    @n PLUM
    @n PURPLE
    </td><td>
       RED
    @n SALMON
    @n SEA GREEN
    @n SIENNA
    @n SKY BLUE
    @n SLATE BLUE
    @n SPRING GREEN
    @n STEEL BLUE
    @n TAN
    @n THISTLE
    @n TURQUOISE
    @n VIOLET
    @n VIOLET RED
    @n WHEAT
    @n WHITE
    @n YELLOW
    @n YELLOW GREEN
    </td></tr>
    @endTable

    @library{wxcore}
    @category{gdi}

    @see wxColour
*/
class wxColourDatabase
{
public:
    /**
        Constructs the colour database. It will be initialized at the first
        use.
    */
    wxColourDatabase();

    /**
        Adds a colour to the database. If a colour with the same name already
        exists, it is replaced.
    */
    void AddColour(const wxString& colourName, const wxColour& colour);

    /**
        Finds a colour given the name. Returns an invalid colour object (that
        is, wxColour::IsOk() will return @false) if the colour wasn't found in
        the database.
    */
    wxColour Find(const wxString& colourName) const;

    /**
        Finds a colour name given the colour. Returns an empty string if the
        colour is not found in the database.
    */
    wxString FindName(const wxColour& colour) const;
};


/**
    @class wxSize

    A wxSize is a useful data structure for graphics operations.
    It simply contains integer @e width and @e height members.

    Note that the width and height stored inside a wxSize object may be negative
    and that wxSize functions do not perform any check against negative values
    (this is used to e.g. store the special -1 value in ::wxDefaultSize instance).
    See also IsFullySpecified() and SetDefaults() for utility functions regarding
    the special -1 value.

    wxSize is used throughout wxWidgets as well as wxPoint which, although
    almost equivalent to wxSize, has a different meaning: wxPoint represents a
    position while wxSize represents the size.

    @beginWxPythonOnly
    wxPython defines aliases for the @e x and @e y members named @e width and
    @e height since it makes much more sense for sizes.
    @endWxPythonOnly

    @library{wxcore}
    @category{data}

    @stdobjects
    ::wxDefaultSize

    @see wxPoint, wxRealPoint
*/
class wxSize
{
public:
    /**
        Initializes this size object with zero width and height.
    */
    wxSize();

    /**
        Initializes this size object with the given @a width and @a height.
    */
    wxSize(int width, int height);

    //@{
    /**
        Decreases the size in both x and y directions.

        @see IncBy()
    */
    void DecBy(const wxPoint& pt);
    void DecBy(const wxSize& size);
    void DecBy(int dx, int dy);
    void DecBy(int d);
    //@}

    /**
        Decrements this object so that both of its dimensions are not greater
        than the corresponding dimensions of the @a size.

        @see IncTo()
    */
    void DecTo(const wxSize& size);

    /**
        Gets the height member.
    */
    int GetHeight() const;

    /**
        Gets the width member.
    */
    int GetWidth() const;

    //@{
    /**
        Increases the size in both x and y directions.

        @see DecBy()
    */
    void IncBy(const wxPoint& pt);
    void IncBy(const wxSize& size);
    void IncBy(int dx, int dy);
    void IncBy(int d);
    //@}

    /**
        Increments this object so that both of its dimensions are not less than
        the corresponding dimensions of the @a size.

        @see DecTo()
    */
    void IncTo(const wxSize& size);

    /**
        Returns @true if neither of the size object components is equal to -1,
        which is used as default for the size values in wxWidgets (hence the
        predefined ::wxDefaultSize has both of its components equal to -1).

        This method is typically used before calling SetDefaults().
    */
    bool IsFullySpecified() const;

    /**
        Scales the dimensions of this object by the given factors. If you want
        to scale both dimensions by the same factor you can also use
        operator*=().

        @return A reference to this object (so that you can concatenate other
                 operations in the same line).
    */
    wxSize& Scale(float xscale, float yscale);

    /**
        Sets the width and height members.
    */
    void Set(int width, int height);

    /**
        Combine this size object with another one replacing the default (i.e.
        equal to -1) components of this object with those of the other. It is
        typically used like this:

        @code
        if ( !size.IsFullySpecified() )
        {
            size.SetDefaults(GetDefaultSize());
        }
        @endcode

        @see IsFullySpecified()
    */
    void SetDefaults(const wxSize& sizeDefault);

    /**
        Sets the height.
    */
    void SetHeight(int height);

    /**
        Sets the width.
    */
    void SetWidth(int width);


    /**
        @name Miscellaneous operators

        Note that these operators are documented as class members
        (to make them easier to find) but, as their prototype shows,
        they are implemented as global operators; note that this is
        transparent to the user but it helps to understand why the
        following functions are documented to take the wxSize they
        operate on as an explicit argument.
    */
    //@{
    wxSize& operator=(const wxSize& sz);

    bool operator ==(const wxSize& s1, const wxSize& s2);
    bool operator !=(const wxSize& s1, const wxSize& s2);

    wxSize operator +(const wxSize& s1, const wxSize& s2);
    wxSize operator -(const wxSize& s1, const wxSize& s2);
    wxSize& operator +=(const wxSize& sz);
    wxSize& operator -=(const wxSize& sz);

    wxSize operator /(const wxSize& sz, int factor);
    wxSize operator *(const wxSize& sz, int factor);
    wxSize operator *(int factor, const wxSize& sz);
    wxSize& operator /=(int factor);
    wxSize& operator *=(int factor);
    //@}
};

/**
    Global instance of a wxSize object initialized to (-1,-1).
*/
wxSize wxDefaultSize;




// ============================================================================
// Global functions/macros
// ============================================================================

/** @addtogroup group_funcmacro_gdi */
//@{

/**
    This macro loads a bitmap from either application resources (on the
    platforms for which they exist, i.e. Windows and OS2) or from an XPM file.
    This can help to avoid using @ifdef_ when creating bitmaps.

    @see @ref overview_bitmap, wxICON()

    @header{wx/gdicmn.h}
*/
#define wxBITMAP(bitmapName)

/**
    This macro loads an icon from either application resources (on the
    platforms for which they exist, i.e. Windows and OS2) or from an XPM file.
    This can help to avoid using @ifdef_ when creating icons.

    @see @ref overview_bitmap, wxBITMAP()

    @header{wx/gdicmn.h}
*/
#define wxICON(iconName)

/**
    Returns @true if the display is colour, @false otherwise.

    @header{wx/gdicmn.h}
*/
bool wxColourDisplay();

/**
    Returns the depth of the display (a value of 1 denotes a monochrome
    display).

    @header{wx/gdicmn.h}
*/
int wxDisplayDepth();

/**
    Globally sets the cursor; only has an effect on Windows, Mac and GTK+. You
    should call this function with wxNullCursor to restore the system cursor.

    @see wxCursor, wxWindow::SetCursor()

    @header{wx/gdicmn.h}
*/
void wxSetCursor(const wxCursor& cursor);

//@}

/** @addtogroup group_funcmacro_gdi */
//@{
/**
    Returns the dimensions of the work area on the display. On Windows this
    means the area not covered by the taskbar, etc. Other platforms are
    currently defaulting to the whole display until a way is found to provide
    this info for all window managers, etc.

    @header{wx/gdicmn.h}
*/
void wxClientDisplayRect(int* x, int* y, int* width, int* height);
wxRect wxGetClientDisplayRect();
//@}

/** @addtogroup group_funcmacro_gdi */
//@{
/**
    Returns the display resolution in pixels per inch.

    The @c x component of the returned wxSize object contains the horizontal
    resolution and the @c y one -- the vertical resolution.

    @header{wx/gdicmn.h}

    @since 2.9.0
*/
wxSize wxGetDisplayPPI();
//@}

/** @addtogroup group_funcmacro_gdi */
//@{
/**
    Returns the display size in pixels.

    For the version taking @a width and @a header arguments, either of them
    can be @NULL if the caller is not interested in the returned value.

    @header{wx/gdicmn.h}
*/
void wxDisplaySize(int* width, int* height);
wxSize wxGetDisplaySize();
//@}

/** @addtogroup group_funcmacro_gdi */
//@{
/**
    Returns the display size in millimeters.

    For the version taking @a width and @a header arguments, either of them
    can be @NULL if the caller is not interested in the returned value.

    @see wxGetDisplayPPI()

    @header{wx/gdicmn.h}
*/
void wxDisplaySizeMM(int* width, int* height);
wxSize wxGetDisplaySizeMM();
//@}

