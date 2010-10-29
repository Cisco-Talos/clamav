/////////////////////////////////////////////////////////////////////////////
// Name:        region.h
// Purpose:     interface of wxRegionIterator
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    Types of results returned from a call to wxRegion::Contains().
*/
enum wxRegionContain
{
    /** The specified value is not contained within this region. */
    wxOutRegion = 0,

    /**
        The specified value is partially contained within this region.

        On Windows, this result is not supported. ::wxInRegion will be returned
        instead.
    */
    wxPartRegion = 1,

    /**
        The specified value is fully contained within this region.

        On Windows, this result will be returned even if only part of the specified
        value is contained in this region.
    */
    wxInRegion = 2
};

/**
    @class wxRegionIterator

    This class is used to iterate through the rectangles in a region,
    typically when examining the damaged regions of a window within an OnPaint call.

    To use it, construct an iterator object on the stack and loop through the
    regions, testing the object and incrementing the iterator at the end of the
    loop.

    See wxPaintEvent for an example of use.

    @library{wxcore}
    @category{gdi}

    @stdobjects
    ::wxNullRegion

    @see wxPaintEvent
*/
class wxRegionIterator : public wxObject
{
public:
    /**
        Default constructor.
    */
    wxRegionIterator();
    /**
        Creates an iterator object given a region.
    */
    wxRegionIterator(const wxRegion& region);

    /**
        An alias for GetHeight().
    */
    wxCoord GetH() const;

    /**
        Returns the height value for the current region.
    */
    wxCoord GetHeight() const;

    /**
        Returns the current rectangle.
    */
    wxRect GetRect() const;

    /**
        An alias for GetWidth().
    */
    wxCoord GetW() const;

    /**
        Returns the width value for the current region.
    */
    wxCoord GetWidth() const;

    /**
        Returns the x value for the current region.
    */
    wxCoord GetX() const;

    /**
        Returns the y value for the current region.
    */
    wxCoord GetY() const;

    /**
        Returns @true if there are still some rectangles; otherwise returns @false.
    */
    bool HaveRects() const;

    /**
        Resets the iterator to the beginning of the rectangles.
    */
    void Reset();

    /**
        Resets the iterator to the given region.
    */
    void Reset(const wxRegion& region);

    /**
        Increment operator. Increments the iterator to the next region.

        @beginWxPythonOnly
        A wxPython alias for this operator is called Next.
        @endWxPythonOnly
    */
    wxRegionIterator& operator ++();

    /**
        Returns @true if there are still some rectangles; otherwise returns @false.

        You can use this to test the iterator object as if it were of type @c bool.
    */
    operator bool() const;
};



/**
    @class wxRegion

    A wxRegion represents a simple or complex region on a device context or window.

    This class uses @ref overview_refcount "reference counting and copy-on-write"
    internally so that assignments between two instances of this class are very
    cheap. You can therefore use actual objects instead of pointers without
    efficiency problems. If an instance of this class is changed it will create
    its own data internally so that other instances, which previously shared the
    data using the reference counting, are not affected.

    @stdobjects
    - ::wxNullRegion

    @library{wxcore}
    @category{data,gdi}

    @see wxRegionIterator
*/
class wxRegion : public wxGDIObject
{
public:
    /**
        Default constructor.
    */
    wxRegion();
    /**
        Constructs a rectangular region with the given position and size.
    */
    wxRegion(wxCoord x, wxCoord y, wxCoord width, wxCoord height);
    /**
        Constructs a rectangular region from the top left point and the bottom right
        point.
    */
    wxRegion(const wxPoint& topLeft, const wxPoint& bottomRight);
    /**
        Constructs a rectangular region a wxRect object.
    */
    wxRegion(const wxRect& rect);
    /**
        Copy constructor, uses @ref overview_refcount.
    */
    wxRegion(const wxRegion& region);
    /**
        Constructs a region corresponding to the polygon made of @a n points
        in the provided array.
        @a fillStyle parameter may have values @c wxWINDING_RULE or @c wxODDEVEN_RULE.
    */
    wxRegion(size_t n, const wxPoint* points, wxPolygonFillMode fillStyle = wxODDEVEN_RULE);
    /**
        Constructs a region using a bitmap. See Union() for more details.
    */
    wxRegion(const wxBitmap& bmp);
    /**
        Constructs a region using the non-transparent pixels of a bitmap.  See
        Union() for more details.
    */
    wxRegion(const wxBitmap& bmp, const wxColour& transColour,
             int tolerance = 0);

    /**
        Destructor.
        See @ref overview_refcount_destruct "reference-counted object destruction" for
        more info.
    */
    virtual ~wxRegion();

    /**
        Clears the current region.
    */
    virtual void Clear();

    /**
        Returns a value indicating whether the given point is contained within the region.

        @return The return value is one of @c wxOutRegion and @c wxInRegion.
    */
    wxRegionContain Contains(wxCoord x, wxCoord y) const;
    /**
        Returns a value indicating whether the given point is contained within the region.

        @return The return value is one of @c wxOutRegion and @c wxInRegion.
    */
    wxRegionContain Contains(const wxPoint& pt) const;
    /**
        Returns a value indicating whether the given rectangle is contained within the
        region.

        @return One of ::wxOutRegion, ::wxPartRegion or ::wxInRegion.

        @note On Windows, only ::wxOutRegion and ::wxInRegion are returned; a value
              ::wxInRegion then indicates that all or some part of the region is
              contained in this region.
    */
    wxRegionContain Contains(wxCoord x, wxCoord y, wxCoord width, wxCoord height) const;
    /**
        Returns a value indicating whether the given rectangle is contained within the
        region.

        @return One of ::wxOutRegion, ::wxPartRegion or ::wxInRegion.

        @note On Windows, only ::wxOutRegion and ::wxInRegion are returned; a value
              ::wxInRegion then indicates that all or some part of the region is
              contained in this region.
    */
    wxRegionContain Contains(const wxRect& rect) const;

    /**
        Convert the region to a black and white bitmap with the white pixels
        being inside the region.
    */
    wxBitmap ConvertToBitmap() const;

    //@{
    /**
        Returns the outer bounds of the region.
    */
    void GetBox(wxCoord& x, wxCoord& y, wxCoord& width,
                wxCoord& height) const;
    wxRect GetBox() const;
    //@}

    /**
        Finds the intersection of this region and another, rectangular region,
        specified using position and size.

        @return @true if successful, @false otherwise.

        @remarks Creates the intersection of the two regions, that is, the parts
                 which are in both regions. The result is stored in this
                 region.
    */
    bool Intersect(wxCoord x, wxCoord y, wxCoord width,
                   wxCoord height);
    /**
        Finds the intersection of this region and another, rectangular region.

        @return @true if successful, @false otherwise.

        @remarks Creates the intersection of the two regions, that is, the parts
                 which are in both regions. The result is stored in this
                 region.
    */
    bool Intersect(const wxRect& rect);
    /**
        Finds the intersection of this region and another region.

        @return @true if successful, @false otherwise.

        @remarks Creates the intersection of the two regions, that is, the parts
                 which are in both regions. The result is stored in this
                 region.
    */
    bool Intersect(const wxRegion& region);

    /**
        Returns @true if the region is empty, @false otherwise.
    */
    virtual bool IsEmpty() const;

    /**
        Returns @true if the region is equal to, i.e. covers the same area as,
        another one.

        @note If both this region and @a region are invalid, they are
              considered to be equal.
    */
    bool IsEqual(const wxRegion& region) const;

    //@{
    /**
        Moves the region by the specified offsets in horizontal and vertical
        directions.

        @return @true if successful, @false otherwise (the region is unchanged
                 then).
    */
    bool Offset(wxCoord x, wxCoord y);
    bool Offset(const wxPoint& pt);
    //@}

    /**
        Subtracts a rectangular region from this region.

        @return @true if successful, @false otherwise.

        @remarks This operation combines the parts of 'this' region that are not
                 part of the second region. The result is stored in this
                 region.
    */
    bool Subtract(const wxRect& rect);
    /**
        Subtracts a region from this region.

        @return @true if successful, @false otherwise.

        @remarks This operation combines the parts of 'this' region that are not
                 part of the second region. The result is stored in this
                 region.
    */
    bool Subtract(const wxRegion& region);

    /**
        Finds the union of this region and another, rectangular region, specified using
        position and size.

        @return @true if successful, @false otherwise.

        @remarks This operation creates a region that combines all of this region
                 and the second region. The result is stored in this
                 region.
    */
    bool Union(wxCoord x, wxCoord y, wxCoord width, wxCoord height);
    /**
        Finds the union of this region and another, rectangular region.

        @return @true if successful, @false otherwise.

        @remarks This operation creates a region that combines all of this region
                 and the second region. The result is stored in this
                 region.
    */
    bool Union(const wxRect& rect);
    /**
        Finds the union of this region and another region.

        @return @true if successful, @false otherwise.

        @remarks This operation creates a region that combines all of this region
                 and the second region. The result is stored in this
                 region.
    */
    bool Union(const wxRegion& region);
    /**
        Finds the union of this region and the non-transparent pixels of a
        bitmap. The bitmap's mask is used to determine transparency. If the
        bitmap doesn't have a mask, the bitmap's full dimensions are used.

        @return @true if successful, @false otherwise.

        @remarks This operation creates a region that combines all of this region
                 and the second region. The result is stored in this
                 region.
    */
    bool Union(const wxBitmap& bmp);
    /**
        Finds the union of this region and the non-transparent pixels of a
        bitmap. Colour to be treated as transparent is specified in the
        @a transColour argument, along with an optional colour tolerance value.

        @return @true if successful, @false otherwise.

        @remarks This operation creates a region that combines all of this region
                 and the second region. The result is stored in this
                 region.
    */
    bool Union(const wxBitmap& bmp, const wxColour& transColour,
               int tolerance = 0);

    /**
        Finds the Xor of this region and another, rectangular region, specified using
        position and size.

        @return @true if successful, @false otherwise.

        @remarks This operation creates a region that combines all of this region
                 and the second region, except for any overlapping
                 areas. The result is stored in this region.
    */
    bool Xor(wxCoord x, wxCoord y, wxCoord width, wxCoord height);
    /**
        Finds the Xor of this region and another, rectangular region.

        @return @true if successful, @false otherwise.

        @remarks This operation creates a region that combines all of this region
                 and the second region, except for any overlapping
                 areas. The result is stored in this region.
    */
    bool Xor(const wxRect& rect);
    /**
        Finds the Xor of this region and another region.

        @return @true if successful, @false otherwise.

        @remarks This operation creates a region that combines all of this region
                 and the second region, except for any overlapping
                 areas. The result is stored in this region.
    */
    bool Xor(const wxRegion& region);

    /**
        Assignment operator, using @ref overview_refcount.
    */
    wxRegion& operator=(const wxRegion& region);
};

/**
    An empty region.
*/
wxRegion wxNullRegion;
