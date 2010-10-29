/////////////////////////////////////////////////////////////////////////////
// Name:        unichar.h
// Purpose:     interface of wxUniChar
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxUniChar

    This class represents a single Unicode character. It can be converted to
    and from @c char or @c wchar_t and implements commonly used character operations.

    @library{wxbase}
    @category{data}
*/
class wxUniChar
{
public:
    /**
        A type capable of holding any Unicode code point.
        We do not use wchar_t as it cannot do the job on Win32,
        where wchar_t is a 16-bit type (wchar_t* is encoded using UTF-16 on Win32).
    */
    typedef wxUint32 value_type;

    /**
        Default ctor.
    */
    wxUniChar();

    //@{
    /**
        Create a character from the 8-bit character value @a c using the
        current locale encoding.
    */
    wxUniChar(char c);
    wxUniChar(unsigned char c);
    //@}

    wxUniChar(int c);
    wxUniChar(unsigned int c);
    wxUniChar(long int c);
    wxUniChar(unsigned long int c);
    wxUniChar(short int c);
    wxUniChar(unsigned short int c);

    wxUniChar(const wxUniCharRef& c);

    /**
        Returns Unicode code point value of the character.
    */
    value_type GetValue() const;

    /**
        Returns true if the character is an ASCII character (i.e. if its value is less than 128).
    */
    bool IsAscii() const;

    /**
        Returns true if the character is representable as a single byte in the
        current locale encoding.

        This function only returns true if the character can be converted in
        exactly one byte, e.g. it only returns true for 7 bit ASCII characters
        when the encoding used is UTF-8.

        It is mostly useful to test if the character can be passed to functions
        taking a char and is used by wxWidgets itself for this purpose.

        @param c
            An output pointer to the value of this Unicode character as a @c
            char. Must be non-@NULL.
        @return
            @true if the object is an 8 bit char and @a c was filled with its
            value as char or @false otherwise (@a c won't be modified then).

        @see IsAscii()

        @since 2.9.1
     */
    bool GetAsChar(char *c) const;

    //@{
    /**
        Conversions to char and wchar_t types: all of those are needed to be
        able to pass wxUniChars to various standard narrow and wide character
        functions.
    */
    operator char() const;
    operator unsigned char() const;
    operator wchar_t() const;
    operator int() const;
    operator unsigned int() const;
    operator long int() const;
    operator unsigned long int() const;
    operator short int() const;
    operator unsigned short int() const;
    //@}

    //@{
    /**
        Assignment operators
    */
    wxUniChar& operator=(const wxUniChar& c);
    wxUniChar& operator=(const wxUniCharRef& c);
    wxUniChar& operator=(char c);
    wxUniChar& operator=(unsigned char c);
    wxUniChar& operator=(wchar_t c);
    wxUniChar& operator=(int c);
    wxUniChar& operator=(unsigned int c);
    wxUniChar& operator=(long int c);
    wxUniChar& operator=(unsigned long int c);
    wxUniChar& operator=(short int c);
    wxUniChar& operator=(unsigned short int c);
    //@}
};


/**
    @class wxUniCharRef

    Writeable reference to a character in wxString.

    This class can be used in the same way wxChar is used, except that changing
    its value updates the underlying string object.

    @library{wxbase}
    @category{data}
*/
class wxUniCharRef
{
public:
};

