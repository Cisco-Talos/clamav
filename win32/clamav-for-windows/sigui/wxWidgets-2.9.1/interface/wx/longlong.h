/////////////////////////////////////////////////////////////////////////////
// Name:        longlong.h
// Purpose:     interface of wxLongLong
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxLongLong

    This class represents a signed 64 bit long number. It is implemented using the
    native 64 bit type where available (machines with 64 bit longs or compilers
    which have (an analog of) @e long long type) and uses the emulation code in
    the other cases which ensures that it is the most efficient solution for
    working with 64 bit integers independently of the architecture.

    wxLongLong defines all usual arithmetic operations such as addition,
    subtraction, bitwise shifts and logical operations as well as multiplication
    and division (not yet for the machines without native @e long long).
    It also has operators for implicit construction from and conversion to the native
    @e long long type if it exists and @e long.

    You would usually use this type in exactly the same manner as any other
    (built-in) arithmetic type. Note that wxLongLong is a signed type, if you
    want unsigned values use wxULongLong which has exactly the same API as
    wxLongLong except when explicitly mentioned otherwise.

    If a native (i.e. supported directly by the compiler) 64 bit integer type was
    found to exist, @e wxLongLong_t macro will be defined to correspond to it.
    Also, in this case only, two additional macros will be defined:
    - wxLongLongFmtSpec() for printing 64 bit integers using the standard @c printf()
      function (but see also wxLongLong::ToString for a more portable solution);
    - wxLL() for defining 64 bit integer compile-time constants.

    @library{wxbase}
    @category{data}
*/
class wxLongLong
{
public:
    /**
        Default constructor initializes the object to 0.
    */
    wxLongLong();

    /**
        Constructor from native long long (only for compilers supporting it).
    */
    wxLongLong(wxLongLong_t ll);

    /**
        Constructor from 2 longs: the high and low part are combined into one
        wxLongLong.
    */
    wxLongLong(long hi, unsigned long lo);

    //@{
    /**
        Returns an absolute value of wxLongLong - either making a copy (const version)
        or modifying it in place (the second one). Not in wxULongLong.
    */
    wxLongLong Abs() const;
    wxLongLong& Abs();
    //@}

    /**
        This allows to convert a double value to wxLongLong type.

        Such conversion is not always possible in which case the result will be
        silently truncated in a platform-dependent way. Not in wxULongLong.
    */
    wxLongLong Assign(double d);

    /**
        Returns the high 32 bits of 64 bit integer.
    */
    long GetHi() const;

    /**
        Returns the low 32 bits of 64 bit integer.
    */
    unsigned long GetLo() const;

    /**
        Convert to native long long (only for compilers supporting it).
    */
    wxLongLong_t GetValue() const;

    /**
        Returns the value as @c double.
    */
    double ToDouble() const;

    /**
        Truncate wxLongLong to long. If the conversion loses data (i.e. the wxLongLong
        value is outside the range of built-in long type), an assert will be triggered
        in debug mode.
    */
    long ToLong() const;

    /**
        Returns the string representation of a wxLongLong.
    */
    wxString ToString() const;


    /**
        Adds 2 wxLongLongs together and returns the result.
    */
    wxLongLong operator+(const wxLongLong& ll) const;

    /**
        Add another wxLongLong to this one.
    */
    wxLongLong& operator+(const wxLongLong& ll);


    /**
        Subtracts 2 wxLongLongs and returns the result.
    */
    wxLongLong operator-(const wxLongLong& ll) const;

    /**
        Subtracts another wxLongLong from this one.
    */
    wxLongLong& operator-(const wxLongLong& ll);


    //@{
    /**
        Pre/post increment operator.
    */
    wxLongLong operator++();
    wxLongLong operator++(int);
    //@}

    //@{
    /**
        Pre/post decrement operator.
    */
    wxLongLong operator--();
    wxLongLong operator--(int);
    //@}

    /**
        Returns the value of this wxLongLong with opposite sign. Not in wxULongLong.
    */
    wxLongLong operator-() const;

    /**
        Assignment operator from unsigned long long. The sign bit will be copied too.

        @since 2.7.0
    */
    wxLongLong& operator=(const wxULongLong& ll);

    /**
        Assignment operator from native long long (only for compilers supporting it).
    */
    wxLongLong& operator=(wxLongLong_t ll);

    /**
        Assignment operator from native unsigned long long (only for compilers supporting it).

        @since 2.7.0
    */
    wxLongLong& operator=(wxULongLong_t ll);

    /**
        Assignment operator from long.

        @since 2.7.0
    */
    wxLongLong& operator=(long l);

    /**
        Assignment operator from unsigned long.

        @since 2.7.0
    */
    wxLongLong& operator=(unsigned long l);

};


/**
    @class wxULongLong

    This class represents an unsigned 64 bit long number.

    Since wxULongLong has exactly the same API as wxLongLong, please refer
    to wxLongLong documentation (this page exists only as redirection).

    @library{wxbase}
    @category{data}
*/
class wxULongLong
{
};


// ============================================================================
// Global functions/macros
// ============================================================================

/** @addtogroup group_funcmacro_misc */
//@{

/**
    This macro is defined to contain the @c printf() format specifier using
    which 64 bit integer numbers (i.e. those of type @c wxLongLong_t) can be
    printed. Example of using it:

    @code
    #ifdef wxLongLong_t
        wxLongLong_t ll = wxLL(0x1234567890abcdef);
        printf("Long long = %" wxLongLongFmtSpec "x\n", ll);
    #endif
    @endcode

    @see wxLL()

    @header{wx/longlong.h}
*/
#define wxLongLongFmtSpec

/**
    This macro is defined for the platforms with a native 64 bit integer type
    and allow the use of 64 bit compile time constants:

    @code
    #ifdef wxLongLong_t
        wxLongLong_t ll = wxLL(0x1234567890abcdef);
    #endif
    @endcode

    @see wxULL(), wxLongLong

    @header{wx/longlong.h}
*/
wxLongLong_t wxLL(number);

/**
    This macro is defined for the platforms with a native 64 bit integer type
    and allow the use of 64 bit compile time constants:

    @code
    #ifdef wxLongLong_t
        unsigned wxLongLong_t ll = wxULL(0x1234567890abcdef);
    #endif
    @endcode

    @see wxLL(), wxLongLong

    @header{wx/longlong.h}
*/
wxLongLong_t wxULL(number);

//@}

