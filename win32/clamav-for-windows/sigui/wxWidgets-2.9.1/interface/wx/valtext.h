/////////////////////////////////////////////////////////////////////////////
// Name:        valtext.h
// Purpose:     interface of wxTextValidator
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


/**
    Styles used by wxTextValidator.

    Note that when you specify more styles in wxTextValidator the validation checks
    are performed in the order in which the styles of this enumeration are defined.
*/
enum wxTextValidatorStyle
{
    /// No filtering takes place.
    wxFILTER_NONE,

    /// Empty strings are filtered out.
    /// If this style is not specified then empty strings are accepted
    /// only if they pass the other checks (if you use more than one wxTextValidatorStyle).
    wxFILTER_EMPTY,

    /// Non-ASCII characters are filtered out. See wxString::IsAscii.
    wxFILTER_ASCII,

    /// Non-alpha characters are filtered out.
    /// Uses the wxWidgets wrapper for the standard CRT function @c isalpha
    /// (which is locale-dependent) on all characters of the string.
    wxFILTER_ALPHA,

    /// Non-alphanumeric characters are filtered out.
    /// Uses the wxWidgets wrapper for the standard CRT function @c isalnum
    /// (which is locale-dependent) on all characters of the string.
    wxFILTER_ALPHANUMERIC,

    /// Non-numeric characters are filtered out.
    /// Uses the wxWidgets wrapper for the standard CRT function @c isdigit
    /// (which is locale-dependent) on all characters of the string.
    wxFILTER_DIGITS,

    /// Non-numeric characters are filtered out.
    /// Works like @c wxFILTER_SIMPLE_NUMBER but allows also decimal points,
    /// minus/plus signs and the 'e' or 'E' character to input exponents.
    /// Note that this is not the same behaviour of wxString::IsNumber().
    wxFILTER_NUMERIC,

    /// Use an include list. The validator checks if the user input is on
    /// the list, complaining if not. See wxTextValidator::SetIncludes().
    wxFILTER_INCLUDE_LIST,

    /// Use an include list. The validator checks if each input character is
    /// in the list (one character per list element), complaining if not.
    /// See wxTextValidator::SetCharIncludes().
    wxFILTER_INCLUDE_CHAR_LIST,

    /// Use an exclude list. The validator checks if the user input is on
    /// the list, complaining if it is. See wxTextValidator::SetExcludes().
    wxFILTER_EXCLUDE_LIST,

    /// Use an exclude list. The validator checks if each input character is
    /// in the list (one character per list element), complaining if it is.
    /// See wxTextValidator::SetCharExcludes().
    wxFILTER_EXCLUDE_CHAR_LIST
};

/**
    @class wxTextValidator

    wxTextValidator validates text controls, providing a variety of filtering
    behaviours.

    For more information, please see @ref overview_validator.

    @library{wxcore}
    @category{validator}

    @see @ref overview_validator, wxValidator, wxGenericValidator
*/
class wxTextValidator : public wxValidator
{
public:
    /**
        Default constructor.
    */
    wxTextValidator(const wxTextValidator& validator);

    /**
        Constructor taking a style and optional pointer to a wxString variable.

        @param style
            One or more of the ::wxTextValidatorStyle styles. See SetStyle().
        @param valPtr
            A pointer to a wxString variable that contains the value. This
            variable should have a lifetime equal to or longer than the
            validator lifetime (which is usually determined by the lifetime of
            the window).
    */
    wxTextValidator(long style = wxFILTER_NONE, wxString* valPtr = NULL);

    /**
        Clones the text validator using the copy constructor.
    */
    virtual wxObject* Clone() const;

    /**
        Returns a reference to the exclude list (the list of invalid values).
    */
    wxArrayString& GetExcludes();

    /**
        Returns a reference to the include list (the list of valid values).
    */
    wxArrayString& GetIncludes();

    /**
        Returns the validator style.

        @see HasFlag()
    */
    long GetStyle() const;

    /**
        Returns @true if the given @a style bit is set in the current style.
    */
    bool HasFlag(wxTextValidatorStyle style) const;

    /**
        Receives character input from the window and filters it according to
        the current validator style.
    */
    void OnChar(wxKeyEvent& event);

    /**
        Sets the exclude list (invalid values for the user input).
    */
    void SetExcludes(const wxArrayString& stringList);

    /**
        Breaks the given @a chars strings in single characters and sets the
        internal wxArrayString used to store the "excluded" characters
        (see SetExcludes()).

        This function is mostly useful when @c wxFILTER_EXCLUDE_CHAR_LIST was used.
    */
    void SetCharExcludes(const wxString& chars);

    /**
        Sets the include list (valid values for the user input).
    */
    void SetIncludes(const wxArrayString& stringList);

    /**
        Breaks the given @a chars strings in single characters and sets the
        internal wxArrayString used to store the "included" characters
        (see SetIncludes()).

        This function is mostly useful when @c wxFILTER_INCLUDE_CHAR_LIST was used.
    */
    void SetCharIncludes(const wxString& chars);

    /**
        Sets the validator style which must be a combination of one or more
        of the ::wxTextValidatorStyle values.

        Note that not all possible combinations make sense!
        Also note that the order in which the checks are performed is important,
        in case you specify more than a single style.
        wxTextValidator will perform the checks in the same definition order
        used in the ::wxTextValidatorStyle enumeration.
    */
    void SetStyle(long style);

    /**
        Transfers the value in the text control to the string.
    */
    virtual bool TransferFromWindow();

    /**
        Transfers the string value to the text control.
    */
    virtual bool TransferToWindow();

    /**
        Validates the window contents against the include or exclude lists,
        depending on the validator style.
    */
    virtual bool Validate(wxWindow* parent);

protected:

    /**
        Returns @true if all the characters of the given @a val string
        are present in the include list (set by SetIncludes() or SetCharIncludes()).
    */
    bool ContainsOnlyIncludedCharacters(const wxString& val) const;

    /**
        Returns true if at least one character of the given @a val string
        is present in the exclude list (set by SetExcludes() or SetCharExcludes()).
    */
    bool ContainsExcludedCharacters(const wxString& val) const;

    /**
        Returns the error message if the contents of @a val are invalid
        or the empty string if @a val is valid.
    */
    virtual wxString IsValid(const wxString& val) const;
};

