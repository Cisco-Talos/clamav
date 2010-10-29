/////////////////////////////////////////////////////////////////////////////
// Name:        colour.h
// Purpose:     interface of wxColour
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////



/**
    Flags for wxColour -> wxString conversion (see wxColour::GetAsString).

    @{
*/
#define wxC2S_NAME              1   //!< Return colour name, when possible.
#define wxC2S_CSS_SYNTAX        2   //!< Return colour in "rgb(r,g,b)" syntax.
#define wxC2S_HTML_SYNTAX       4   //!< Return colour in "#rrggbb" syntax.

//@}


/**
    @class wxColour

    A colour is an object representing a combination of Red, Green, and Blue
    (RGB) intensity values, and is used to determine drawing colours. See the
    entry for wxColourDatabase for how a pointer to a predefined, named colour
    may be returned instead of creating a new colour.

    Valid RGB values are in the range 0 to 255.

    You can retrieve the current system colour settings with wxSystemSettings.

    @library{wxcore}
    @category{gdi}

    @stdobjects
    - ::wxNullColour - An empty, invalid colour.
    - ::wxTransparentColour - Valid but fully transparent colour (new in 2.9.1).
    - ::wxBLACK
    - ::wxBLUE
    - ::wxCYAN
    - ::wxGREEN
    - ::wxYELLOW
    - ::wxLIGHT_GREY
    - ::wxRED
    - ::wxWHITE

    @see wxColourDatabase, wxPen, wxBrush, wxColourDialog, wxSystemSettings
*/
class wxColour : public wxObject
{
public:

    /**
        Default constructor.
    */
    wxColour();

    /**
        @param red
            The red value.
        @param green
            The green value.
        @param blue
            The blue value.
        @param alpha
            The alpha value. Alpha values range from 0 (wxALPHA_TRANSPARENT) to
            255 (wxALPHA_OPAQUE).
    */
    wxColour(unsigned char red, unsigned char green, unsigned char blue,
             unsigned char alpha = wxALPHA_OPAQUE);

    /**
        @param colourName
            The colour name.
    */
    wxColour(const wxString& colourName);

    /**
        Copy constructor.
    */
    wxColour(const wxColour& colour);

    /**
        Returns the alpha value, on platforms where alpha is not yet supported, this
        always returns wxALPHA_OPAQUE.
    */
    virtual unsigned char Alpha() const;

    /**
        Returns the blue intensity.
    */
    virtual unsigned char Blue() const;

    /**
        Converts this colour to a wxString using the given flags.

        The supported flags are @c wxC2S_NAME, to obtain the colour name
        (e.g. wxColour(255,0,0) == "red"), @c wxC2S_CSS_SYNTAX, to obtain
        the colour in the "rgb(r,g,b)" or "rgba(r,g,b,a)" syntax
        (e.g. wxColour(255,0,0,85) == "rgba(255,0,0,0.333)"), and
        @c wxC2S_HTML_SYNTAX, to obtain the colour as "#" followed by 6
        hexadecimal digits (e.g. wxColour(255,0,0) == "#FF0000").

        This function never fails and always returns a non-empty string but
        asserts if the colour has alpha channel (i.e. is non opaque) but
        @c wxC2S_CSS_SYNTAX (which is the only one supporting alpha) is not
        specified in flags.

        @since 2.7.0
    */
    virtual wxString GetAsString(long flags = wxC2S_NAME | wxC2S_CSS_SYNTAX) const;

    //@{
    /**
        Sets the RGB or RGBA colour values from a single 32 bit value.

        The arguments @a colRGB and @a colRGBA should be of the form 0x00BBGGRR
        and 0xAABBGGRR respectively where @c 0xRR, @c 0xGG, @c 0xBB and @c 0xAA
        are the values of the red, blue, green and alpha components.

        Notice the right-to-left order of components!

        @see GetRGB(), GetRGBA()

        @since 2.9.1
    */
    void SetRGB(wxUint32 colRGB);
    void SetRGBA(wxUint32 colRGBA);
    //@}

    //@{
    /**
        Gets the RGB or RGBA colour values as a single 32 bit value.

        The returned value is of the same form as expected by SetRGB() and
        SetRGBA().

        Notice that GetRGB() returns the value with 0 as its highest byte
        independently of the value actually returned by Alpha(). So for a fully
        opaque colour, the return value of GetRGBA() is @c 0xFFBBGGRR while
        that of GetRGB() is @c 0x00BBGGRR.

        @since 2.9.1
    */
    wxUint32 GetRGB() const;
    wxUint32 GetRGBA() const;
    //@}

    /**
        Returns a pixel value which is platform-dependent.
        On Windows, a COLORREF is returned.
        On X, an allocated pixel value is returned.
        If the pixel is invalid (on X, unallocated), @c -1 is returned.
    */
    int GetPixel() const;

    /**
        Returns the green intensity.
    */
    virtual unsigned char Green() const;

    /**
        Returns @true if the colour object is valid (the colour has been initialised
        with RGB values).
    */
    virtual bool IsOk() const;

    /**
        Returns the red intensity.
    */
    virtual unsigned char Red() const;

    //@{
    /**
        Sets the RGB intensity values using the given values (first overload),
        extracting them from the packed long (second overload), using the given
        string (third overloard).

        When using third form, Set() accepts: colour names (those listed in
        wxTheColourDatabase()), the CSS-like @c "rgb(r,g,b)" or
        @c "rgba(r,g,b,a)" syntax (case insensitive) and the HTML-like syntax
        (i.e. @c "#" followed by 6 hexadecimal digits for red, green, blue
        components).

        Returns @true if the conversion was successful, @false otherwise.

        @since 2.7.0
    */
    void Set(unsigned char red, unsigned char green,
             unsigned char blue,
             unsigned char alpha = wxALPHA_OPAQUE);
    void Set(unsigned long RGB);
    bool Set(const wxString& str);
    //@}

    /**
        Tests the inequality of two colours by comparing individual red, green, blue
        colours and alpha values.
    */
    bool operator !=(const wxColour& colour) const;

    /**
        Assignment operator, using a colour name to be found in the colour database.

        @see wxColourDatabase
    */
    wxColour& operator=(const wxColour& colour);

    /**
        Tests the equality of two colours by comparing individual red, green, blue
        colours and alpha values.
    */
    bool operator ==(const wxColour& colour) const;

    /**
        Assign 0 or 255 to rgb out parameters.
        @since 2.9.0
    */
    static void MakeMono(unsigned char* r, unsigned char* g, unsigned char* b, bool on);
    
    /**
        Create a disabled (dimmed) colour from (in/out) rgb parameters.
        @since 2.9.0
    */
    static void MakeDisabled(unsigned char* r, unsigned char* g, unsigned char* b, unsigned char brightness = 255);
    
    /**
        Create a grey colour from (in/out) rgb parameters using integer arithmetic.
        @since 2.9.0
    */
    static void MakeGrey(unsigned char* r, unsigned char* g, unsigned char* b);
    
    /**
        Create a grey colour from (in/out) rgb parameters using floating point arithmetic.
        Defaults to using the standard ITU-T BT.601 when converting to YUV, where every pixel equals
        (R * @a weight_r) + (G * @a weight_g) + (B * @a weight_b).
        @since 2.9.0
    */
    static void MakeGrey(unsigned char* r, unsigned char* g, unsigned char* b,
                         double weight_r, double weight_g, double weight_b);

    /**
        Blend colour, taking alpha into account.
        @since 2.9.0
    */
    static unsigned char AlphaBlend(unsigned char fg, unsigned char bg, double alpha);
    
    /**
        ChangeLightness() is a utility function that simply darkens
        or lightens a color, based on the specified percentage
        ialpha of 0 would be completely black, 200 completely white
        an ialpha of 100 returns the same colour
        @since 2.9.0
    */
    static void ChangeLightness(unsigned char* r, unsigned char* g, unsigned char* b, int ialpha);

    /**
        wxColour wrapper for ChangeLightness(r,g,b,ialpha).
        @since 2.9.0
    */
    wxColour ChangeLightness(int ialpha) const;
};


/** @name Predefined colors. */
//@{
wxColour wxNullColour;
wxColour wxTransparentColour;
wxColour* wxBLACK;
wxColour* wxBLUE;
wxColour* wxCYAN;
wxColour* wxGREEN;
wxColour* wxYELLOW;
wxColour* wxLIGHT_GREY;
wxColour* wxRED;
wxColour* wxWHITE;
//@}



// ============================================================================
// Global functions/macros
// ============================================================================

/** @addtogroup group_funcmacro_misc */
//@{

/**
    Converts string to a wxColour best represented by the given string. Returns
    @true on success.

    @see wxToString(const wxColour&)

    @header{wx/colour.h}
*/
bool wxFromString(const wxString& string, wxColour* colour);

/**
    Converts the given wxColour into a string.

    @see wxFromString(const wxString&, wxColour*)

    @header{wx/colour.h}
*/
wxString wxToString(const wxColour& colour);

//@}

