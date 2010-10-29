/////////////////////////////////////////////////////////////////////////////
// Name:        regex.h
// Purpose:     interface of wxRegEx
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @anchor wxRE_FLAGS

    Flags for regex compilation to be used with wxRegEx::Compile().
*/
enum
{
    /** Use extended regex syntax. */
    wxRE_EXTENDED = 0,

    /** Use advanced RE syntax (built-in regex only). */
    wxRE_ADVANCED = 1,

    /** Use basic RE syntax. */
    wxRE_BASIC    = 2,

    /** Ignore case in match. */
    wxRE_ICASE    = 4,

    /** Only check match, don't set back references. */
    wxRE_NOSUB    = 8,

    /**
        If not set, treat '\n' as an ordinary character, otherwise it is
        special: it is not matched by '.' and '^' and '$' always match
        after/before it regardless of the setting of wxRE_NOT[BE]OL.
    */
    wxRE_NEWLINE  = 16,

    /** Default flags.*/
    wxRE_DEFAULT  = wxRE_EXTENDED
};

/**
    @anchor wxRE_NOT_FLAGS

    Flags for regex matching to be used with wxRegEx::Matches().
    These flags are mainly useful when doing several matches in a long string
    to prevent erroneous matches for '^' and '$':
*/
enum
{
    /** '^' doesn't match at the start of line. */
    wxRE_NOTBOL = 32,

    /** '$' doesn't match at the end of line. */
    wxRE_NOTEOL = 64
};

/**
    @class wxRegEx

    wxRegEx represents a regular expression.  This class provides support
    for regular expressions matching and also replacement.

    It is built on top of either the system library (if it has support
    for POSIX regular expressions - which is the case of the most modern
    Unices) or uses the built in Henry Spencer's library.  Henry Spencer
    would appreciate being given credit in the documentation of software
    which uses his library, but that is not a requirement.

    Regular expressions, as defined by POSIX, come in two flavours: @e extended
    and @e basic.  The builtin library also adds a third flavour
    of expression @ref overview_resyntax "advanced", which is not available
    when using the system library.

    Unicode is fully supported only when using the builtin library.
    When using the system library in Unicode mode, the expressions and data
    are translated to the default 8-bit encoding before being passed to
    the library.

    On platforms where a system library is available, the default is to use
    the builtin library for Unicode builds, and the system library otherwise.
    It is possible to use the other if preferred by selecting it when building
    the wxWidgets.

    @library{wxbase}
    @category{data}

    Examples:

    A bad example of processing some text containing email addresses (the example
    is bad because the real email addresses can have more complicated form than
    @c user@host.net):

    @code
    wxString text;
    ...
    wxRegEx reEmail = "([^@]+)@([[:alnum:].-_].)+([[:alnum:]]+)";
    if ( reEmail.Matches(text) )
    {
        wxString text = reEmail.GetMatch(email);
        wxString username = reEmail.GetMatch(email, 1);
        if ( reEmail.GetMatch(email, 3) == "com" ) // .com TLD?
        {
            ...
        }
    }

    // or we could do this to hide the email address
    size_t count = reEmail.ReplaceAll(text, "HIDDEN@\\2\\3");
    printf("text now contains %u hidden addresses", count);
    @endcode
*/
class wxRegEx
{
public:

    /**
        Default constructor: use Compile() later.
    */
    wxRegEx();

    /**
        Create and compile the regular expression, use
        IsValid() to test for compilation errors.

        As for the flags, please see @ref wxRE_FLAGS.
    */
    wxRegEx(const wxString& expr, int flags = wxRE_DEFAULT);


    /**
        Destructor. It's not virtual, don't derive from this class.
    */
    ~wxRegEx();

    /**
        Compile the string into regular expression, return @true if ok or @false
        if string has a syntax error.

        As for the flags, please see @ref wxRE_FLAGS.
    */
    bool Compile(const wxString& pattern, int flags = wxRE_DEFAULT);

    /**
        Get the start index and the length of the match of the expression
        (if @a index is 0) or a bracketed subexpression (@a index different from 0).

        May only be called after successful call to Matches() and only if @c wxRE_NOSUB
        was @b not used in Compile().

        Returns @false if no match or if an error occurred.

    */
    bool GetMatch(size_t* start, size_t* len, size_t index = 0) const;

    /**
        Returns the part of string corresponding to the match where index is interpreted
        as above. Empty string is returned if match failed.

        May only be called after successful call to Matches() and only if @c wxRE_NOSUB
        was @b not used in Compile().
    */
    wxString  GetMatch(const wxString& text, size_t index = 0) const;

    /**
        Returns the size of the array of matches, i.e. the number of bracketed
        subexpressions plus one for the expression itself, or 0 on error.

        May only be called after successful call to Compile().
        and only if @c wxRE_NOSUB was @b not used.
    */
    size_t GetMatchCount() const;

    /**
        Return @true if this is a valid compiled regular expression, @false
        otherwise.
    */
    bool IsValid() const;

    //@{
    /**
        Matches the precompiled regular expression against the string @a text,
        returns @true if matches and @false otherwise.

        @e Flags may be combination of @c wxRE_NOTBOL and @c wxRE_NOTEOL, see
        @ref wxRE_NOT_FLAGS.

        Some regex libraries assume that the text given is null terminated, while
        others require the length be given as a separate parameter. Therefore for
        maximum portability assume that @a text cannot contain embedded nulls.

        When the <b>Matches(const wxChar *text, int flags = 0)</b> form is used,
        a wxStrlen() will be done internally if the regex library requires the
        length. When using Matches() in a loop the <b>Matches(text, flags, len)</b>
        form can be used instead, making it possible to avoid a wxStrlen() inside
        the loop.

        May only be called after successful call to Compile().
    */
    bool Matches(const wxChar* text, int flags = 0) const;
    bool Matches(const wxChar* text, int flags, size_t len) const;
    //@}

    /**
        Matches the precompiled regular expression against the string @a text,
        returns @true if matches and @false otherwise.

        @e Flags may be combination of @c wxRE_NOTBOL and @c wxRE_NOTEOL, see
        @ref wxRE_NOT_FLAGS.

        May only be called after successful call to Compile().
    */
    bool Matches(const wxString& text, int flags = 0) const;

    /**
        Replaces the current regular expression in the string pointed to by
        @a text, with the text in @a replacement and return number of matches
        replaced (maybe 0 if none found) or -1 on error.

        The replacement text may contain back references @c \\number which will be
        replaced with the value of the corresponding subexpression in the
        pattern match. @c \\0 corresponds to the entire match and @c \& is a
        synonym for it. Backslash may be used to quote itself or @c \& character.

        @a maxMatches may be used to limit the number of replacements made, setting
        it to 1, for example, will only replace first occurrence (if any) of the
        pattern in the text while default value of 0 means replace all.
    */
    int Replace(wxString* text, const wxString& replacement,
                size_t maxMatches = 0) const;

    /**
        Replace all occurrences: this is actually a synonym for
        Replace().

        @see ReplaceFirst()
    */
    int ReplaceAll(wxString* text, const wxString& replacement) const;

    /**
        Replace the first occurrence.
    */
    int ReplaceFirst(wxString* text, const wxString& replacement) const;
};

