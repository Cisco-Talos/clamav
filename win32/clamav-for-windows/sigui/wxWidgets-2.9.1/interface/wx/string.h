/////////////////////////////////////////////////////////////////////////////
// Name:        string.h
// Purpose:     interface of wxStringBuffer, wxString
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


/**
    @class wxString

    The wxString class has been completely rewritten for wxWidgets 3.0
    and this change was actually the main reason for the calling that
    version wxWidgets 3.0.

    wxString is a class representing a Unicode character string.
    wxString uses @c std::basic_string internally (even if @c wxUSE_STL is not defined)
    to store its content (unless this is not supported by the compiler or disabled
    specifically when building wxWidgets) and it therefore inherits
    many features from @c std::basic_string. (Note that most implementations of
    @c std::basic_string are thread-safe and don't use reference counting.)

    These @c std::basic_string standard functions are only listed here, but
    they are not fully documented in this manual; see the STL documentation
    (http://www.cppreference.com/wiki/string/start) for more info.
    The behaviour of all these functions is identical to the behaviour
    described there.

    You may notice that wxString sometimes has several functions which do
    the same thing like Length(), Len() and length() which all return the
    string length. In all cases of such duplication the @c std::string
    compatible methods should be used.

    For informations about the internal encoding used by wxString and
    for important warnings and advices for using it, please read
    the @ref overview_string.

    Since wxWidgets 3.0 wxString always stores Unicode strings, so you should
    be sure to read also @ref overview_unicode.


    @section string_index Index of the member groups

    Links for quick access to the various categories of wxString functions:
    - @ref_member_group{ctor, Constructors and assignment operators}
    - @ref_member_group{length, Length functions}
    - @ref_member_group{ch_access, Character access functions}
    - @ref_member_group{conv, Conversions functions}
    - @ref_member_group{concat, Concatenation functions}
    - @ref_member_group{cmp, Comparison functions}
    - @ref_member_group{substring, Substring extraction functions}
    - @ref_member_group{caseconv, Case conversion functions}
    - @ref_member_group{search, Searching and replacing functions}
    - @ref_member_group{numconv, Conversion to numbers functions}
    - @ref_member_group{fmt, Formatting and printing functions}
    - @ref_member_group{mem, Memory management functions}
    - @ref_member_group{misc, Miscellaneous functions}
    - @ref_member_group{iter, Iterator interface functions}
    - @ref_member_group{stl, STL interface functions}


    @library{wxbase}
    @category{data}

    @stdobjects
    ::wxEmptyString

    @see @ref overview_string, @ref overview_unicode,
         @ref group_funcmacro_string "String-related functions", wxUString,
         wxCharBuffer, wxUniChar, wxStringTokenizer, wxStringBuffer, wxStringBufferLength
*/
class wxString
{
public:
    /**
        @name Standard types

        Types used with wxString.
    */
    //@{
    typedef wxUniChar value_type;
    typedef wxUniChar char_type;
    typedef wxUniCharRef reference;
    typedef wxChar* pointer;
    typedef const wxChar* const_pointer;
    typedef size_t size_type;
    typedef wxUniChar const_reference;
    //@}


    /**
        @member_group_name{ctor, Constructors and assignment operators}

        A string may be constructed either from a C string, (some number of copies of)
        a single character or a wide (Unicode) string. For all constructors (except the
        default which creates an empty string) there is also a corresponding assignment
        operator.

        See also the assign() STL-like function.
    */
    //@{

    /**
       Default constructor
    */
    wxString();

    /**
       Creates a string from another string.
       Just increases the ref count by 1.
    */
    wxString(const wxString& stringSrc);

    /**
       Construct a string consisting of @a nRepeat copies of ch.
    */
    wxString(wxUniChar ch, size_t nRepeat = 1);

    /**
       Construct a string consisting of @a nRepeat copies of ch.
    */
    wxString(wxUniCharRef ch, size_t nRepeat = 1);

    /**
       Construct a string consisting of @a nRepeat copies of ch
       converted to Unicode using the current locale encoding.
    */
    wxString(char ch, size_t nRepeat = 1);

    /**
       Construct a string consisting of @a nRepeat copies of ch.
    */
    wxString(wchar_t ch, size_t nRepeat = 1);

    /**
       Constructs a string from the string literal @a psz using
       the current locale encoding to convert it to Unicode (wxConvLibc).
    */
    wxString(const char *psz);

    /**
       Constructs a string from the string literal @a psz using
       @a conv to convert it Unicode.
    */
    wxString(const char *psz, const wxMBConv& conv);

    /**
       Constructs a string from the first @a nLength character of the string literal @a psz using
       the current locale encoding to convert it to Unicode (wxConvLibc).
    */
    wxString(const char *psz, size_t nLength);

    /**
       Constructs a string from the first @a nLength character of the string literal @a psz using
       @a conv to convert it Unicode.
    */
    wxString(const char *psz, const wxMBConv& conv, size_t nLength);

    /**
       Constructs a string from the string literal @a pwz.
    */
    wxString(const wchar_t *pwz);

    /**
       Constructs a string from the first @a nLength characters of the string literal @a pwz.
    */
    wxString(const wchar_t *pwz, size_t nLength);

    /**
       Constructs a string from @a buf using the using the current locale
        encoding to convert it to Unicode.
    */
    wxString(const wxCharBuffer& buf);

    /**
       Constructs a string from @a buf.
    */
    wxString(const wxWCharBuffer& buf);

    /**
       Constructs a string from @a str using the using the current locale encoding
       to convert it to Unicode (wxConvLibc).

       @see ToStdString()
    */
    wxString(const std::string& str);

    /**
       Constructs a string from @a str.

       @see ToStdWstring()
    */
    wxString(const std::wstring& str);

    /**
        String destructor.

        Note that this is not virtual, so wxString must not be inherited from.
    */
    ~wxString();

    /**
        Assignment: see the relative wxString constructor.
    */
    wxString operator =(const wxString& str);

    /**
        Assignment: see the relative wxString constructor.
    */
    wxString operator =(wxUniChar c);

    //@}



    /**
        @member_group_name{length, String length}

        These functions return the string length and/or check whether the string
        is empty.

        See also the length(), size() or empty() STL-like functions.
    */
    //@{


    /**
        Returns the length of the string.
    */
    size_t Len() const;

    /**
        Returns the length of the string (same as Len).
        This is a wxWidgets 1.xx compatibility function; you should not use it in new
        code.
    */
    size_t Length() const;

    /**
        Returns @true if the string is empty.
    */
    bool IsEmpty() const;

    /**
        Returns @true if the string is empty (same as wxString::IsEmpty).
        This is a wxWidgets 1.xx compatibility function; you should not use it in new
        code.
    */
    bool IsNull() const;

    /**
        Empty string is @false, so !string will only return @true if the
        string is empty.

        @see IsEmpty().
    */
    bool operator!() const;

    //@}



    /**
        @member_group_name{ch_access, Character access}

        Many functions below take a character index in the string.
        As with C strings and arrays, the indices start from 0, so the first character
        of a string is string[0]. An attempt to access a character beyond the end of the
        string (which may even be 0 if the string is empty) will provoke an assert
        failure in @ref overview_debugging "debug builds", but no checks are
        done in release builds.
    */
    //@{

    /**
        Returns the character at position @a n (read-only).
    */
    wxUniChar GetChar(size_t n) const;

    /**
        wxWidgets compatibility conversion. Same as c_str().
    */
    const wxCStrData GetData() const;

    /**
        Returns a reference to the character at position @a n.
    */
    wxUniCharRef GetWritableChar(size_t n);

    /**
        Returns a writable buffer of at least @a len bytes.

        It returns a pointer to a new memory block, and the existing data will not be copied.
        Call UngetWriteBuf() as soon as possible to put the string back into a reasonable state.

        This method is deprecated, please use wxStringBuffer or wxStringBufferLength instead.
    */
    wxStringCharType* GetWriteBuf(size_t len);

    /**
        Puts the string back into a reasonable state (in which it can be used
        normally), after GetWriteBuf() was called.

        The version of the function without the @a len parameter will calculate the
        new string length itself assuming that the string is terminated by the first
        @c NUL character in it while the second one will use the specified length
        and thus is the only version which should be used with the strings with
        embedded @c NULs (it is also slightly more efficient as @c strlen()
        doesn't have to be called).

        This method is deprecated, please use wxStringBuffer or wxStringBufferLength instead.
    */
    void UngetWriteBuf();

    /**
        @overload
    */
    void UngetWriteBuf(size_t len);

    /**
        Sets the character at position @e n.
    */
    void SetChar(size_t n, wxUniChar ch);

    /**
        Returns a the last character.

        This is a wxWidgets 1.xx compatibility function;
        you should not use it in new code.
    */
    wxUniChar Last() const;

    /**
        Returns a reference to the last character (writable).

        This is a wxWidgets 1.xx compatibility function;
        you should not use it in new code.
    */
    wxUniCharRef Last();

    /**
        Returns the @a i-th character of the string.
    */
    wxUniChar operator [](size_t i) const;

    /**
        Returns a writable reference to the @a i-th character of the string.
    */
    wxUniCharRef operator [](size_t i);

    //@}


    /**
        @member_group_name{conv, Conversions}

        This section contains both implicit and explicit conversions to C style
        strings. Although implicit conversion is quite convenient, you are advised
        to use wc_str() for the sake of clarity.
    */
    //@{

    /**
        Returns a lightweight intermediate class which is in turn implicitly
        convertible to both @c const @c char* and to @c const @c wchar_t*.
        Given this ambiguity it is mostly better to use wc_str(), mb_str() or
        utf8_str() instead.

        Please see the @ref overview_unicode for more information about it.

        Note that the returned value is not convertible to @c char* or
        @c wchar_t*, use char_str() or wchar_str() if you need to pass
        string value to a function expecting non-const pointer.

        @see wc_str(), utf8_str(), c_str(), mb_str(), fn_str()
    */
    wxCStrData c_str() const;

    /**
        Returns an object with string data that is implicitly convertible to
        @c char* pointer. Note that any change to the returned buffer is lost and so
        this function is only usable for passing strings to legacy libraries that
        don't have const-correct API. Use wxStringBuffer if you want to modify
        the string.

        @see c_str()
    */
    wxWritableCharBuffer char_str(const wxMBConv& conv = wxConvLibc) const;

    /**
        Returns buffer of the specified type containing the string data.

        This method is only useful in template code, otherwise you should
        directly call mb_str() or wc_str() if you need to retrieve a narrow or
        wide string from this wxString. The template parameter @a t should be
        either @c char or @c wchar_t.

        Notice that retrieving a char buffer in UTF-8 build will return the
        internal string representation in UTF-8 while in wchar_t build the char
        buffer will contain the conversion of the string to the encoding of the
        current locale (and so can fail).

        @param len
            If non-@NULL, filled with the length of the returned buffer.

        @return
            buffer containing the string contents in the specified type,
            notice that it may be @NULL if the conversion failed (e.g. Unicode
            string couldn't be converted to the current encoding when @a T is
            @c char).
     */
    template <typename T>
    wxCharTypeBuffer<T> tchar_str(size_t *len = NULL) const;

    /**
        Returns a string representation suitable for passing to OS' functions
        for file handling.
    */
    const wchar_t* fn_str() const;

    /**
        @overload
    */
    const char* fn_str() const;

    /**
        @overload
    */
    const wxCharBuffer fn_str() const;

    /**
        Returns the multibyte (C string) representation of the string
        using @e conv's wxMBConv::cWC2MB method and returns wxCharBuffer.

        @see wc_str(), utf8_str(), c_str(), wxMBConv
    */
    const wxCharBuffer mb_str(const wxMBConv& conv = wxConvLibc) const;

    /**
        Converts the strings contents to UTF-8 and returns it either as a
        temporary wxCharBuffer object or as a pointer to the internal
        string contents in UTF-8 build.

        @see wc_str(), c_str(), mb_str()
    */
    const wxScopedCharBuffer utf8_str() const;

    /**
        Converts the strings contents to the wide character represention
        and returns it as a temporary wxWCharBuffer object (Unix and OS X)
        or returns a pointer to the internal string contents in wide character
        mode (Windows).

        The macro wxWX2WCbuf is defined as the correct return type (without const).

        @see utf8_str(), c_str(), mb_str(), fn_str(), wchar_str()
    */
    const wchar_t* wc_str() const;

    /**
        @overload
    */
    const wxWCharBuffer wc_str() const;

    /**
        Returns an object with string data that is implicitly convertible to
        @c char* pointer. Note that changes to the returned buffer may or may
        not be lost (depending on the build) and so this function is only usable for
        passing strings to legacy libraries that don't have const-correct API. Use
        wxStringBuffer if you want to modify the string.

        @see mb_str(), wc_str(), fn_str(), c_str(), char_str()
    */
    wxWritableWCharBuffer wchar_str() const;

    /**
       Explicit conversion to C string in the internal representation (either
       wchar_t* or UTF-8-encoded char*, depending on the build).
    */
    const wxStringCharType *wx_str() const;

    /**
        Converts the string to an 8-bit string in ISO-8859-1 encoding in the
        form of a wxCharBuffer (Unicode builds only).

        This is a convenience method useful when storing binary data in
        wxString. It should be used @em only for this purpose. It is only valid
        to call this method on strings created using From8BitData().

        @since 2.8.4

        @see wxString::From8BitData()
    */
    const wxScopedCharBuffer To8BitData() const;

    /**
        Converts the string to an ASCII, 7-bit string in the form of
        a wxCharBuffer (Unicode builds only) or a C string (ANSI builds).
        Note that this conversion only works if the string contains only ASCII
        characters. The @ref mb_str() "mb_str" method provides more
        powerful means of converting wxString to C string.
    */
    const char* ToAscii() const;

    /**
        @overload
    */
    const wxCharBuffer ToAscii() const;

    /**
        Return the string as an std::string in current locale encoding.

        Note that if the conversion of (Unicode) string contents to the current
        locale fails, the return string will be empty. Be sure to check for
        this to avoid silent data loss.

        Instead of using this function it's also possible to write
        @code
        std::string s;
        wxString wxs;
        ...
        s = std::string(wxs);
        @endcode
        but using ToStdString() may make the code more clear.

        @since 2.9.1
    */
    std::string ToStdString() const;

    /**
        Return the string as an std::wstring.

        Unlike ToStdString(), there is no danger of data loss when using this
        function.

        @since 2.9.1
    */
    std::wstring ToStdWstring() const;

    /**
        Same as utf8_str().
    */
    const wxScopedCharBuffer ToUTF8() const;

    //@}


    /**
        @member_group_name{concat, Concatenation}

        Almost anything may be concatenated (appended to) with a string!

        Note that the various operator<<() overloads work as C++ stream insertion
        operators. They insert the given value into the string.
        Precision and format cannot be set using them. Use Printf() instead.

        See also the insert() and append() STL-like functions.
    */
    //@{

    /**
       Appends the string literal @a psz.
    */
    wxString& Append(const char* psz);

    /**
       Appends the wide string literal @a pwz.
    */
    wxString& Append(const wchar_t* pwz);

    /**
       Appends the string literal @a psz with max length @a nLen.
    */
    wxString& Append(const char* psz, size_t nLen);

    /**
       Appends the wide string literal @a psz with max length @a nLen.
    */
    wxString& Append(const wchar_t* pwz, size_t nLen);

    /**
       Appends the string @a s.
    */
    wxString& Append(const wxString& s);

    /**
       Appends the character @a ch @a count times.
    */
    wxString &Append(wxUniChar ch, size_t count = 1u);

    /**
        Prepends @a str to this string, returning a reference to this string.
    */
    wxString& Prepend(const wxString& str);

    /**
        Concatenation: returns a new string equal to the concatenation of the operands.
    */
    wxString operator +(const wxString& x, const wxString& y);

    /**
        @overload
    */
    wxString operator +(const wxString& x, wxUniChar y);

    wxString& operator<<(const wxString& s);
    wxString& operator<<(const char* psz);
    wxString& operator<<(const wchar_t* pwz);
    wxString& operator<<(const wxCStrData& psz);
    wxString& operator<<(char ch);
    wxString& operator<<(unsigned char ch);
    wxString& operator<<(wchar_t ch);
    wxString& operator<<(const wxCharBuffer& s);
    wxString& operator<<(const wxWCharBuffer& s);
    wxString& operator<<(wxUniChar ch);
    wxString& operator<<(wxUniCharRef ch);
    wxString& operator<<(unsigned int ui);
    wxString& operator<<(long l);
    wxString& operator<<(unsigned long ul);
    wxString& operator<<(wxLongLong_t ll);
    wxString& operator<<(wxULongLong_t ul);
    wxString& operator<<(float f);
    wxString& operator<<(double d);

    /**
        Concatenation in place: the argument is appended to the string.
    */
    void operator +=(const wxString& str);

    /**
        @overload
    */
    void operator +=(wxUniChar c);

    //@}


    /**
        @member_group_name{cmp, Comparison}

        The default comparison function Cmp() is case-sensitive and so is the default
        version of IsSameAs(). For case insensitive comparisons you should use CmpNoCase()
        or give a second parameter to IsSameAs(). This last function is maybe more
        convenient if only equality of the strings matters because it returns a boolean
        @true value if the strings are the same and not 0 (which is usually @false
        in C) as Cmp() does.

        Matches() is a poor man's regular expression matcher: it only understands
        '*' and '?' metacharacters in the sense of DOS command line interpreter.

        StartsWith() is helpful when parsing a line of text which should start
        with some predefined prefix and is more efficient than doing direct string
        comparison as you would also have to precalculate the length of the prefix.

        See also the compare() STL-like function.
    */
    //@{

    /**
        Case-sensitive comparison.
        Returns a positive value if the string is greater than the argument,
        zero if it is equal to it or a negative value if it is less than the
        argument (same semantics as the standard @c strcmp() function).

        @see CmpNoCase(), IsSameAs().
    */
    int Cmp(const wxString& s) const;

    /**
        Case-insensitive comparison.
        Returns a positive value if the string is greater than the argument,
        zero if it is equal to it or a negative value if it is less than the
        argument (same semantics as the standard @c strcmp() function).

        @see Cmp(), IsSameAs().
    */
    int CmpNoCase(const wxString& s) const;

    /**
        Test whether the string is equal to another string @a s.

        The test is case-sensitive if @a caseSensitive is @true (default) or not if it is
        @false.

        @return @true if the string is equal to the other one, @false otherwise.

        @see Cmp(), CmpNoCase()
    */
    bool IsSameAs(const wxString& s, bool caseSensitive = true) const;

    /**
        Test whether the string is equal to the single character @a ch.

        The test is case-sensitive if @a caseSensitive is @true (default) or not if it is
        @false.

        @return @true if the string is equal to this character, @false otherwise.

        @see Cmp(), CmpNoCase()
    */
    bool IsSameAs(wxUniChar ch, bool caseSensitive = true) const;

    /**
        Returns @true if the string contents matches a mask containing '*' and '?'.
    */
    bool Matches(const wxString& mask) const;

    /**
        This function can be used to test if the string starts with the specified
        @a prefix.

        If it does, the function will return @true and put the rest of the string
        (i.e. after the prefix) into @a rest string if it is not @NULL.
        Otherwise, the function returns @false and doesn't modify the @a rest.
    */
    bool StartsWith(const wxString& prefix, wxString *rest = NULL) const;

    /**
        This function can be used to test if the string ends with the specified
        @e suffix. If it does, the function will return @true and put the
        beginning of the string before the suffix into @e rest string if it is not
        @NULL. Otherwise, the function returns @false and doesn't
        modify the @e rest.
    */
    bool EndsWith(const wxString& suffix, wxString *rest = NULL) const;

    //@}


    /**
        @member_group_name{substring, Substring extraction}

        These functions allow you to extract a substring from the string. The
        original string is not modified and the function returns the extracted
        substring.

        See also the at() and the substr() STL-like functions.
    */

    /**
        Returns a substring starting at @e first, with length @e count, or the rest of
        the string if @a count is the default value.
    */
    wxString Mid(size_t first, size_t nCount = wxString::npos) const;

    /**
        Returns the part of the string between the indices @a from and @a to
        inclusive.

        This is a wxWidgets 1.xx compatibility function, use Mid()
        instead (but note that parameters have different meaning).
    */
    wxString SubString(size_t from, size_t to) const;

    /**
        Same as Mid() (substring extraction).
    */
    wxString operator()(size_t start, size_t len) const;

    /**
        Returns the first @a count characters of the string.
    */
    wxString Left(size_t count) const;

    /**
        Returns the last @a count characters.
    */
    wxString Right(size_t count) const;

    /**
        Gets all the characters after the first occurrence of @e ch.
        Returns the empty string if @e ch is not found.
    */
    wxString AfterFirst(wxUniChar ch) const;

    /**
        Gets all the characters after the last occurrence of @e ch.
        Returns the whole string if @e ch is not found.
    */
    wxString AfterLast(wxUniChar ch) const;

    /**
        Gets all characters before the first occurrence of @e ch.
        Returns the whole string if @a ch is not found.
    */
    wxString BeforeFirst(wxUniChar ch) const;

    /**
        Gets all characters before the last occurrence of @e ch.
        Returns the empty string if @a ch is not found.
    */
    wxString BeforeLast(wxUniChar ch) const;

    //@}


    /**
        @member_group_name{caseconv, Case conversion}

        The MakeXXX() variants modify the string in place, while the other functions
        return a new string which contains the original text converted to the upper or
        lower case and leave the original string unchanged.
    */
    //@{

    /**
        Return the copy of the string with the first string character in the
        upper case and the subsequent ones in the lower case.

        @since 2.9.0

        @see MakeCapitalized()
     */
    wxString Capitalize() const;

    /**
        Returns this string converted to the lower case.

        @see MakeLower()
    */
    wxString Lower() const;

    /**
        Same as MakeLower.
        This is a wxWidgets 1.xx compatibility function; you should not use it in new
        code.
    */
    void LowerCase();

    /**
        Converts the first characters of the string to the upper case and all
        the subsequent ones to the lower case and returns the result.

        @since 2.9.0

        @see Capitalize()
    */
    wxString& MakeCapitalized();

    /**
        Converts all characters to lower case and returns the reference to the
        modified string.

        @see Lower()
    */
    wxString& MakeLower();

    /**
        Converts all characters to upper case and returns the reference to the
        modified string.

        @see Upper()
    */
    wxString& MakeUpper();

    /**
        Returns this string converted to upper case.

        @see MakeUpper()
    */
    wxString Upper() const;

    /**
        The same as MakeUpper().

        This is a wxWidgets 1.xx compatibility function; you should not use it in new
        code.
    */
    void UpperCase();

    //@}


    /**
        @member_group_name{search, Searching and replacing}

        These functions replace the standard @c strchr() and @c strstr()
        functions.

        See also the find(), rfind(), replace() STL-like functions.
    */
    //@{

    /**
        Searches for the given character @a ch.
        Returns the position or @c wxNOT_FOUND if not found.
    */
    int Find(wxUniChar ch, bool fromEnd = false) const;

    /**
        Searches for the given string @a sub.
        Returns the starting position or @c wxNOT_FOUND if not found.
    */
    int Find(const wxString& sub) const;

    /**
        Same as Find().

        This is a wxWidgets 1.xx compatibility function;
        you should not use it in new code.
    */
    int First(wxUniChar ch) const;

    /**
        Same as Find().

        This is a wxWidgets 1.xx compatibility function;
        you should not use it in new code.
    */
    int First(const wxString& str) const;

    /**
        Replace first (or all) occurrences of substring with another one.

        @param strOld
            The string to search for replacing.
        @param strNew
            The substitution string.
        @param replaceAll
            If @true a global replace will be done (default), otherwise only the
            first occurrence will be replaced.

        Returns the number of replacements made.
    */
    size_t Replace(const wxString& strOld, const wxString& strNew,
                   bool replaceAll = true);

    //@}



    /**
        @member_group_name{numconv, Conversion to numbers}

        The string provides functions for conversion to signed and unsigned integer and
        floating point numbers.

        All functions take a pointer to the variable to put the numeric value
        in and return @true if the @b entire string could be converted to a
        number. Notice if there is a valid number in the beginning of the
        string, it is returned in the output parameter even if the function
        returns @false because there is more text following it.
     */
    //@{

    /**
        Attempts to convert the string to a floating point number.

        Returns @true on success (the number is stored in the location pointed to by
        @a val) or @false if the string does not represent such number (the value of
        @a val may still be modified in this case).

        Note that unlike ToCDouble() this function uses a localized version of
        @c wxStrtod() and thus needs as decimal point (and thousands separator) the
        locale-specific decimal point. Thus you should use this function only when
        you are sure that this string contains a floating point number formatted with
        the rules of the locale currently in use (see wxLocale).

        Refer to the docs of the standard function @c strtod() for more details about
        the supported syntax.

        @see ToCDouble(), ToLong(), ToULong()
    */
    bool ToDouble(double* val) const;

    /**
        Variant of ToDouble() always working in "C" locale.

        Works like ToDouble() but unlike it this function expects the floating point
        number to be formatted always with the rules dictated by the "C" locale
        (in particular, the decimal point must be a dot), independently from the
        current application-wide locale (see wxLocale).

        @see ToDouble(), ToLong(), ToULong()
    */
    bool ToCDouble(double* val) const;

    /**
        Attempts to convert the string to a signed integer in base @a base.

        Returns @true on success in which case the number is stored in the location
        pointed to by @a val or @false if the string does not represent a
        valid number in the given base (the value of @a val may still be
        modified in this case).

        The value of @a base must be comprised between 2 and 36, inclusive, or
        be a special value 0 which means that the usual rules of @c C numbers are
        applied: if the number starts with @c 0x it is considered to be in base
        16, if it starts with @c 0 - in base 8 and in base 10 otherwise. Note
        that you may not want to specify the base 0 if you are parsing the numbers
        which may have leading zeroes as they can yield unexpected (to the user not
        familiar with C) results.

        Note that unlike ToCLong() this function uses a localized version of
        @c wxStrtol(). Thus you should use this function only when you are sure
        that this string contains an integer number formatted with
        the rules of the locale currently in use (see wxLocale).

        Refer to the docs of the standard function @c strtol() for more details about
        the supported syntax.

        @see ToCDouble(), ToDouble(), ToULong()
    */
    bool ToLong(long* val, int base = 10) const;

    /**
        Variant of ToLong() always working in "C" locale.

        Works like ToLong() but unlike it this function expects the integer
        number to be formatted always with the rules dictated by the "C" locale,
        independently from the current application-wide locale (see wxLocale).

        @see ToDouble(), ToLong(), ToULong()
    */
    bool ToCLong(long* val, int base = 10) const;

    /**
        This is exactly the same as ToLong() but works with 64 bit integer numbers.

        Notice that currently it doesn't work (always returns @false) if parsing of 64
        bit numbers is not supported by the underlying C run-time library. Compilers
        with C99 support and Microsoft Visual C++ version 7 and higher do support this.

        @see ToLong(), ToULongLong()
    */
    bool ToLongLong(wxLongLong_t* val, int base = 10) const;

    /**
        Attempts to convert the string to an unsigned integer in base @a base.

        Returns @true on success in which case the number is stored in the
        location pointed to by @a val or @false if the string does not
        represent a valid number in the given base (the value of @a val may
        still be modified in this case).

        Please notice that this function  behaves in the same way as the standard
        @c strtoul() and so it simply converts negative numbers to unsigned
        representation instead of rejecting them (e.g. -1 is returned as @c ULONG_MAX).

        See ToLong() for the more detailed description of the @a base parameter
        (and of the locale-specific behaviour of this function).

        @see ToCULong(), ToDouble(), ToLong()
    */
    bool ToULong(unsigned long* val, int base = 10) const;

    /**
        Variant of ToULong() always working in "C" locale.

        Works like ToULong() but unlike it this function expects the integer
        number to be formatted always with the rules dictated by the "C" locale,
        independently from the current application-wide locale (see wxLocale).

        @see ToDouble(), ToLong(), ToULong()
    */
    bool ToCULong(unsigned long* val, int base = 10) const;

    /**
        This is exactly the same as ToULong() but works with 64 bit integer
        numbers.

        Please see ToLongLong() for additional remarks.
    */
    bool ToULongLong(wxULongLong_t* val, int base = 10) const;

    //@}


    /**
        @member_group_name{fmt, Formatting and printing}

        Both formatted versions (Printf/() and stream-like insertion operators
        exist (for basic types only).

        See also the static Format() and FormatV() functions.
    */
    //@{

    /**
        Similar to the standard function @e sprintf(). Returns the number of
        characters written, or an integer less than zero on error.
        Note that if @c wxUSE_PRINTF_POS_PARAMS is set to 1, then this function supports
        Unix98-style positional parameters:

        @code
        wxString str;

        str.Printf(wxT("%d %d %d"), 1, 2, 3);
        // str now contains "1 2 3"

        str.Printf(wxT("%2$d %3$d %1$d"), 1, 2, 3);
        // str now contains "2 3 1"
        @endcode

        @note This function will use a safe version of @e vsprintf() (usually called
        @e vsnprintf()) whenever available to always allocate the buffer of correct
        size. Unfortunately, this function is not available on all platforms and the
        dangerous @e vsprintf() will be used then which may lead to buffer overflows.
    */
    int Printf(const wxString& pszFormat, ...);

    /**
        Similar to vprintf. Returns the number of characters written, or an integer
        less than zero
        on error.
    */
    int PrintfV(const wxString& pszFormat, va_list argPtr);

    //@}


    /**
        @member_group_name{mem, Memory management}

        The following are "advanced" functions and they will be needed rarely.
        Alloc() and Shrink() are only interesting for optimization purposes.
        wxStringBuffer and wxStringBufferLength classes may be very useful when working
        with some external API which requires the caller to provide a writable buffer.

        See also the reserve() and resize() STL-like functions.
    */
    //@{

    /**
        Preallocate enough space for wxString to store @a nLen characters.

        Please note that this method does the same thing as the standard
        reserve() one and shouldn't be used in new code.

        This function may be used to increase speed when the string is
        constructed by repeated concatenation as in

        @code
            // delete all vowels from the string
            wxString DeleteAllVowels(const wxString& original)
            {
                wxString result;

                size_t len = original.length();

                result.Alloc(len);

                for ( size_t n = 0; n < len; n++ )
                {
                    if ( strchr("aeuio", tolower(original[n])) == NULL )
                        result += original[n];
                }

                return result;
            }
        @endcode

        because it will avoid the need to reallocate string memory many times
        (in case of long strings). Note that it does not set the maximal length
        of a string -- it will still expand if more than @a nLen characters are
        stored in it. Also, it does not truncate the existing string (use
        Truncate() for this) even if its current length is greater than @a nLen.

        @return @true if memory was successfully allocated, @false otherwise.
    */
    bool Alloc(size_t nLen);

    /**
        Minimizes the string's memory. This can be useful after a call to
        Alloc() if too much memory were preallocated.
    */
    bool Shrink();

    /**
        Returns a deep copy of the string.

        That is, the returned string is guaranteed to not share data with this
        string when using reference-counted wxString implementation.

        This method is primarily useful for passing strings between threads
        (because wxString is not thread-safe). Unlike creating a copy using
        @c wxString(c_str()), Clone() handles embedded NULs correctly.

        @since 2.9.0
     */
    wxString Clone() const;

    /**
        Empties the string and frees memory occupied by it.

        @see Empty()
    */
    void Clear();

    //@}



    /**
        @member_group_name{misc, Miscellaneous}

        Miscellaneous other string functions.
    */
    //@{

    /**
        Returns @true if target appears anywhere in wxString; else @false.

        This is a wxWidgets 1.xx compatibility function; you should not use it in new code.
    */
    bool Contains(const wxString& str) const;

    /**
        Makes the string empty, but doesn't free memory occupied by the string.

        @see Clear().
    */
    void Empty();

    /**
        Returns the number of occurrences of @e ch in the string.

        This is a wxWidgets 1.xx compatibility function; you should not use it in new code.
    */
    int Freq(wxUniChar ch) const;

    /**
        Returns @true if the string contains only ASCII characters.
        See wxUniChar::IsAscii for more details.

        This is a wxWidgets 1.xx compatibility function; you should not use it in new
        code.
    */
    bool IsAscii() const;

    /**
        Returns @true if the string is an integer (with possible sign).

        This is a wxWidgets 1.xx compatibility function; you should not use it in new code.
    */
    bool IsNumber() const;

    /**
        Returns @true if the string is a word.

        This is a wxWidgets 1.xx compatibility function; you should not use it in new code.
    */
    bool IsWord() const;

    /**
        Adds @a count copies of @a chPad to the beginning, or to the end of the
        string (the default).

        Removes spaces from the left or from the right (default).
    */
    wxString& Pad(size_t count, wxUniChar chPad = ' ', bool fromRight = true);

    /**
        Removes all characters from the string starting at @a pos.
        Use Truncate() as a more readable alternative.

        This is a wxWidgets 1.xx compatibility function; you should not use it in new code.
    */
    wxString& Remove(size_t pos);

    /**
        Removes @a len characters from the string, starting at @a pos.

        This is a wxWidgets 1.xx compatibility function; you should not use it in new code.
    */
    wxString& Remove(size_t pos, size_t len);

    /**
        Removes the last character.
    */
    wxString& RemoveLast(size_t n = 1);

    /**
        Strip characters at the front and/or end.

        This is the same as Trim() except that it doesn't change this string.

        This is a wxWidgets 1.xx compatibility function; you should not use it in new code.
    */
    wxString Strip(stripType s = trailing) const;

    /**
        Removes white-space (space, tabs, form feed, newline and carriage return) from
        the left or from the right end of the string (right is default).
    */
    wxString& Trim(bool fromRight = true);

    /**
        Truncate the string to the given length.
    */
    wxString& Truncate(size_t len);

    //@}




    /**
        @member_group_name{iter, Iterator interface}

        These methods return iterators to the beginnnig or end of the string.

        Please see any STL reference (e.g. http://www.cppreference.com/wiki/string/start)
        for their documentation.
    */
    //@{

    const_iterator begin() const;
    iterator begin();
    const_iterator end() const;
    iterator end();

    const_reverse_iterator rbegin() const;
    reverse_iterator rbegin();
    const_reverse_iterator rend() const;
    reverse_iterator rend();

    //@}



    /**
        @member_group_name{stl, STL interface}

        The supported STL functions are listed here.

        Please see any STL reference (e.g. http://www.cppreference.com/wiki/string/start)
        for their documentation.
    */
    //@{

    wxString& append(const wxString& str, size_t pos, size_t n);
    wxString& append(const wxString& str);
    wxString& append(const char *sz, size_t n);
    wxString& append(const wchar_t *sz, size_t n);
    wxString& append(size_t n, wxUniChar ch);
    wxString& append(const_iterator first, const_iterator last);

    wxString& assign(const wxString& str, size_t pos, size_t n);
    wxString& assign(const wxString& str);
    wxString& assign(const char *sz, size_t n);
    wxString& assign(const wchar_t *sz, size_t n);
    wxString& assign(size_t n, wxUniChar ch);
    wxString& assign(const_iterator first, const_iterator last);

    wxUniChar at(size_t n) const;
    wxUniCharRef at(size_t n);

    void clear();

    size_type capacity() const;

    int compare(const wxString& str) const;
    int compare(size_t nStart, size_t nLen, const wxString& str) const;
    int compare(size_t nStart, size_t nLen,
            const wxString& str, size_t nStart2, size_t nLen2) const;
    int compare(size_t nStart, size_t nLen,
            const char* sz, size_t nCount = npos) const;
    int compare(size_t nStart, size_t nLen,
            const wchar_t* sz, size_t nCount = npos) const;

    wxCStrData data() const;

    bool empty() const;

    wxString& erase(size_type pos = 0, size_type n = npos);
    iterator erase(iterator first, iterator last);
    iterator erase(iterator first);

    size_t find(const wxString& str, size_t nStart = 0) const;
    size_t find(const char* sz, size_t nStart = 0, size_t n = npos) const;
    size_t find(const wchar_t* sz, size_t nStart = 0, size_t n = npos) const;
    size_t find(wxUniChar ch, size_t nStart = 0) const;
    size_t find_first_of(const char* sz, size_t nStart = 0) const;
    size_t find_first_of(const wchar_t* sz, size_t nStart = 0) const;
    size_t find_first_of(const char* sz, size_t nStart, size_t n) const;
    size_t find_first_of(const wchar_t* sz, size_t nStart, size_t n) const;
    size_t find_first_of(wxUniChar c, size_t nStart = 0) const;
    size_t find_last_of (const wxString& str, size_t nStart = npos) const;
    size_t find_last_of (const char* sz, size_t nStart = npos) const;
    size_t find_last_of (const wchar_t* sz, size_t nStart = npos) const;
    size_t find_last_of(const char* sz, size_t nStart, size_t n) const;
    size_t find_last_of(const wchar_t* sz, size_t nStart, size_t n) const;
    size_t find_last_of(wxUniChar c, size_t nStart = npos) const;
    size_t find_first_not_of(const wxString& str, size_t nStart = 0) const;
    size_t find_first_not_of(const char* sz, size_t nStart = 0) const;
    size_t find_first_not_of(const wchar_t* sz, size_t nStart = 0) const;
    size_t find_first_not_of(const char* sz, size_t nStart, size_t n) const;
    size_t find_first_not_of(const wchar_t* sz, size_t nStart, size_t n) const;
    size_t find_first_not_of(wxUniChar ch, size_t nStart = 0) const;
    size_t find_last_not_of(const wxString& str, size_t nStart = npos) const;
    size_t find_last_not_of(const char* sz, size_t nStart = npos) const;
    size_t find_last_not_of(const wchar_t* sz, size_t nStart = npos) const;
    size_t find_last_not_of(const char* sz, size_t nStart, size_t n) const;
    size_t find_last_not_of(const wchar_t* sz, size_t nStart, size_t n) const;

    wxString& insert(size_t nPos, const wxString& str);
    wxString& insert(size_t nPos, const wxString& str, size_t nStart, size_t n);
    wxString& insert(size_t nPos, const char *sz, size_t n);
    wxString& insert(size_t nPos, const wchar_t *sz, size_t n);
    wxString& insert(size_t nPos, size_t n, wxUniChar ch);
    iterator insert(iterator it, wxUniChar ch);
    void insert(iterator it, const_iterator first, const_iterator last);
    void insert(iterator it, size_type n, wxUniChar ch);

    size_t length() const;

    size_type max_size() const;

    void reserve(size_t sz);
    void resize(size_t nSize, wxUniChar ch = '\0');

    wxString& replace(size_t nStart, size_t nLen, const wxString& str);
    wxString& replace(size_t nStart, size_t nLen, size_t nCount, wxUniChar ch);
    wxString& replace(size_t nStart, size_t nLen,
                        const wxString& str, size_t nStart2, size_t nLen2);
    wxString& replace(size_t nStart, size_t nLen,
                        const char* sz, size_t nCount);
    wxString& replace(size_t nStart, size_t nLen,
                        const wchar_t* sz, size_t nCount);
    wxString& replace(size_t nStart, size_t nLen,
                        const wxString& s, size_t nCount);
    wxString& replace(iterator first, iterator last, const wxString& s);
    wxString& replace(iterator first, iterator last, const char* s, size_type n);
    wxString& replace(iterator first, iterator last, const wchar_t* s, size_type n);
    wxString& replace(iterator first, iterator last, size_type n, wxUniChar ch);
    wxString& replace(iterator first, iterator last,
                        const_iterator first1, const_iterator last1);
    wxString& replace(iterator first, iterator last,
                        const char *first1, const char *last1);
    wxString& replace(iterator first, iterator last,
                        const wchar_t *first1, const wchar_t *last1);

    size_t rfind(const wxString& str, size_t nStart = npos) const;
    size_t rfind(const char* sz, size_t nStart = npos, size_t n = npos) const;
    size_t rfind(const wchar_t* sz, size_t nStart = npos, size_t n = npos) const;
    size_t rfind(wxUniChar ch, size_t nStart = npos) const;

    size_type size() const;
    wxString substr(size_t nStart = 0, size_t nLen = npos) const;
    void swap(wxString& str);

    //@}



    // STATIC FUNCTIONS
    // Keep these functions separed from the other groups or Doxygen gets confused
    // -----------------------------------------------------------------------------

    /**
        An 'invalid' value for string index
    */
    static const size_t npos;

    /**
        This static function returns the string containing the result of calling
        Printf() with the passed parameters on it.

        @see FormatV(), Printf()
    */
    static wxString Format(const wxString& format, ...);

    /**
        This static function returns the string containing the result of calling
        PrintfV() with the passed parameters on it.

        @see Format(), PrintfV()
    */
    static wxString FormatV(const wxString& format, va_list argptr);

    //@{
    /**
        Converts given buffer of binary data from 8-bit string to wxString. In
        Unicode build, the string is interpreted as being in ISO-8859-1
        encoding. The version without @e len parameter takes NUL-terminated
        data.

        This is a convenience method useful when storing binary data in
        wxString. It should be used @em only for that purpose and only in
        conjunction with To8BitData(). Use mb_str() for conversion of character
        data to known encoding.

        @since 2.8.4

        @see wxString::To8BitData()
    */
    static wxString From8BitData(const char* buf, size_t len);
    static wxString From8BitData(const char* buf);
    //@}

    //@{
    /**
        Converts the string or character from an ASCII, 7-bit form
        to the native wxString representation.
    */
    static wxString FromAscii(const char* s);
    static wxString FromAscii(const unsigned char* s);
    static wxString FromAscii(const char* s, size_t len);
    static wxString FromAscii(const unsigned char* s, size_t len);
    static wxString FromAscii(char c);
    //@}

    /**
        Returns a string with the textual representation of the number in C
        locale.

        Unlike FromDouble() the string returned by this function always uses
        the period character as decimal separator, independently of the current
        locale.

        @since 2.9.1

        @see ToCDouble()
     */
    static wxString FromCDouble(double val);

    /**
        Returns a string with the textual representation of the number.

        This is a simple wrapper for @code wxString::Format("%g", val)
        @endcode.

        Notice that the string returned by this function uses the decimal
        separator appropriate for the current locale, e.g. @c "," and not a
        period in French locale. Use FromCDouble() if this is unwanted.

        @since 2.9.1

        @see ToDouble()
     */
    static wxString FromDouble(double val);

    //@{
    /**
        Converts C string encoded in UTF-8 to wxString.

        If @a s is not a valid UTF-8 string, an empty string is returned.

        Notice that when using UTF-8 wxWidgets build there is a more efficient
        alternative to this function called FromUTF8Unchecked() which, unlike
        this one, doesn't check that the input string is valid.

        @since 2.8.4
    */
    static wxString FromUTF8(const char* s);
    static wxString FromUTF8(const char* s, size_t len);
    //@}

    //@{
    /**
        Converts C string encoded in UTF-8 to wxString without checking its
        validity.

        This method assumes that @a s is a valid UTF-8 sequence and doesn't do
        any validation (although an assert failure is triggered in debug builds
        if the string is invalid). Only use it if you are absolutely sure that
        @a s is a correct UTF-8 string (e.g. because it comes from another
        library using UTF-8) and if the performance matters, otherwise use
        slower (in UTF-8 build) but safer FromUTF8(). Passing a bad UTF-8
        string to this function will result in creating a corrupted wxString
        and all the subsequent operations on it will be undefined.

        @since 2.8.9
    */
    static wxString FromUTF8Unchecked(const char* s);
    static wxString FromUTF8Unchecked(const char* s, size_t len);
    //@}
};



//@{
/**
    Comparison operator for string types.
*/
inline bool operator==(const wxString& s1, const wxString& s2);
inline bool operator!=(const wxString& s1, const wxString& s2);
inline bool operator< (const wxString& s1, const wxString& s2);
inline bool operator> (const wxString& s1, const wxString& s2);
inline bool operator<=(const wxString& s1, const wxString& s2);
inline bool operator>=(const wxString& s1, const wxString& s2);
inline bool operator==(const wxString& s1, const wxCStrData& s2);
inline bool operator==(const wxCStrData& s1, const wxString& s2);
inline bool operator!=(const wxString& s1, const wxCStrData& s2);
inline bool operator!=(const wxCStrData& s1, const wxString& s2);
inline bool operator==(const wxString& s1, const wxWCharBuffer& s2);
inline bool operator==(const wxWCharBuffer& s1, const wxString& s2);
inline bool operator!=(const wxString& s1, const wxWCharBuffer& s2);
inline bool operator!=(const wxWCharBuffer& s1, const wxString& s2);
inline bool operator==(const wxString& s1, const wxCharBuffer& s2);
inline bool operator==(const wxCharBuffer& s1, const wxString& s2);
inline bool operator!=(const wxString& s1, const wxCharBuffer& s2);
inline bool operator!=(const wxCharBuffer& s1, const wxString& s2);
//@}

//@{
/**
    Comparison operators char types.
*/
inline bool operator==(const wxUniChar& c, const wxString& s);
inline bool operator==(const wxUniCharRef& c, const wxString& s);
inline bool operator==(char c, const wxString& s);
inline bool operator==(wchar_t c, const wxString& s);
inline bool operator==(int c, const wxString& s);
inline bool operator==(const wxString& s, const wxUniChar& c);
inline bool operator==(const wxString& s, const wxUniCharRef& c);
inline bool operator==(const wxString& s, char c);
inline bool operator==(const wxString& s, wchar_t c);
inline bool operator!=(const wxUniChar& c, const wxString& s);
inline bool operator!=(const wxUniCharRef& c, const wxString& s);
inline bool operator!=(char c, const wxString& s);
inline bool operator!=(wchar_t c, const wxString& s);
inline bool operator!=(int c, const wxString& s);
inline bool operator!=(const wxString& s, const wxUniChar& c);
inline bool operator!=(const wxString& s, const wxUniCharRef& c);
inline bool operator!=(const wxString& s, char c);
inline bool operator!=(const wxString& s, wchar_t c);
//@}

/**
    The global wxString instance of an empty string.
    Used extensively in the entire wxWidgets API.
*/
wxString wxEmptyString;



/**
    @class wxStringBufferLength

    This tiny class allows you to conveniently access the wxString internal buffer
    as a writable pointer without any risk of forgetting to restore the string to
    the usable state later, and allows the user to set the internal length of the string.

    For example, assuming you have a low-level OS function called
    @c "int GetMeaningOfLifeAsString(char *)" copying the value in the provided
    buffer (which must be writable, of course), and returning the actual length
    of the string, you might call it like this:

    @code
        wxString theAnswer;
        wxStringBufferLength theAnswerBuffer(theAnswer, 1024);
        int nLength = GetMeaningOfLifeAsString(theAnswerBuffer);
        theAnswerBuffer.SetLength(nLength);
        if ( theAnswer != "42" )
            wxLogError("Something is very wrong!");
    @endcode

    Note that the exact usage of this depends on whether or not wxUSE_STL is
    enabled. If wxUSE_STL is enabled, wxStringBuffer creates a separate empty
    character buffer, and if wxUSE_STL is disabled, it uses GetWriteBuf() from
    wxString, keeping the same buffer wxString uses intact. In other words,
    relying on wxStringBuffer containing the old wxString data is not a good
    idea if you want to build your program both with and without wxUSE_STL.

    Note that wxStringBuffer::SetLength @b must be called before
    wxStringBufferLength destructs.

    @library{wxbase}
    @category{data}
*/
class wxStringBufferLength
{
public:
    /**
        Constructs a writable string buffer object associated with the given string
        and containing enough space for at least @a len characters.

        Basically, this is equivalent to calling wxString::GetWriteBuf and
        saving the result.
    */
    wxStringBufferLength(const wxString& str, size_t len);

    /**
        Restores the string passed to the constructor to the usable state by calling
        wxString::UngetWriteBuf on it.
    */
    ~wxStringBufferLength();

    /**
        Sets the internal length of the string referred to by wxStringBufferLength to
        @a nLength characters.

        Must be called before wxStringBufferLength destructs.
    */
    void SetLength(size_t nLength);

    /**
        Returns the writable pointer to a buffer of the size at least equal to the
        length specified in the constructor.
    */
    wxChar* operator wxChar *();
};


/**
    @class wxStringBuffer

    This tiny class allows you to conveniently access the wxString internal buffer
    as a writable pointer without any risk of forgetting to restore the string
    to the usable state later.

    For example, assuming you have a low-level OS function called
    @c "GetMeaningOfLifeAsString(char *)" returning the value in the provided
    buffer (which must be writable, of course) you might call it like this:

    @code
        wxString theAnswer;
        GetMeaningOfLifeAsString(wxStringBuffer(theAnswer, 1024));
        if ( theAnswer != "42" )
            wxLogError("Something is very wrong!");
    @endcode

    Note that the exact usage of this depends on whether or not @c wxUSE_STL is
    enabled. If @c wxUSE_STL is enabled, wxStringBuffer creates a separate empty
    character buffer, and if @c wxUSE_STL is disabled, it uses GetWriteBuf() from
    wxString, keeping the same buffer wxString uses intact. In other words,
    relying on wxStringBuffer containing the old wxString data is not a good
    idea if you want to build your program both with and without @c wxUSE_STL.

    @library{wxbase}
    @category{data}
*/
class wxStringBuffer
{
public:
    /**
        Constructs a writable string buffer object associated with the given string
        and containing enough space for at least @a len characters.
        Basically, this is equivalent to calling wxString::GetWriteBuf() and
        saving the result.
    */
    wxStringBuffer(const wxString& str, size_t len);

    /**
        Restores the string passed to the constructor to the usable state by calling
        wxString::UngetWriteBuf() on it.
    */
    ~wxStringBuffer();

    /**
        Returns the writable pointer to a buffer of the size at least equal to the
        length specified in the constructor.
    */
    wxStringCharType* operator wxStringCharType *();
};


/** @addtogroup group_funcmacro_string */
//@{

/**
    Allows to extend a function with the signature:
    @code bool SomeFunc(const wxUniChar& c) @endcode
    which operates on a single character, to an entire wxString.

    E.g. if you want to check if an entire string contains only digits,
    you can do:
    @code
        if (wxStringCheck<wxIsdigit>(myString))
            ... // the entire string contains oly digits!
        else
            ... // at least one character of myString is not a digit
    @endcode

    @return @true if the given function returns a non-zero value for all
            characters of the @a val string.
*/
template<bool (T)(const wxUniChar& c)>
    inline bool wxStringCheck(const wxString& val);

//@}
