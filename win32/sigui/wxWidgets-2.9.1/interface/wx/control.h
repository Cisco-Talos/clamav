/////////////////////////////////////////////////////////////////////////////
// Name:        control.h
// Purpose:     interface of wxControl
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    Flags used by wxControl::Ellipsize function.
*/
enum wxEllipsizeFlags
{
    /// No special flags.
    wxELLIPSIZE_FLAGS_NONE = 0,

    /**
        Take mnemonics into account when calculating the text width.

        With this flag when calculating the size of the passed string,
        mnemonics characters (see wxControl::SetLabel) will be automatically
        reduced to a single character. This leads to correct calculations only
        if the string passed to Ellipsize() will be used with
        wxControl::SetLabel. If you don't want ampersand to be interpreted as
        mnemonics (e.g. because you use wxControl::SetLabelText) then don't use
        this flag.
     */
    wxELLIPSIZE_FLAGS_PROCESS_MNEMONICS = 1,

    /**
        Expand tabs in spaces when calculating the text width.

        This flag tells wxControl::Ellipsize() to calculate the width of tab
        characters @c '\\t' as 6 spaces.
     */
    wxELLIPSIZE_FLAGS_EXPAND_TABS = 2,

    /// The default flags for wxControl::Ellipsize.
    wxELLIPSIZE_FLAGS_DEFAULT = wxELLIPSIZE_FLAGS_PROCESS_MNEMONICS|
                                wxELLIPSIZE_FLAGS_EXPAND_TABS
};


/**
    The different ellipsization modes supported by the
    wxControl::Ellipsize function.
*/
enum wxEllipsizeMode
{
    /// Don't ellipsize the text at all. @since 2.9.1
    wxELLIPSIZE_NONE,

    /// Put the ellipsis at the start of the string, if the string needs ellipsization.
    wxELLIPSIZE_START,

    /// Put the ellipsis in the middle of the string, if the string needs ellipsization.
    wxELLIPSIZE_MIDDLE,

    /// Put the ellipsis at the end of the string, if the string needs ellipsization.
    wxELLIPSIZE_END
};

/**
    @class wxControl

    This is the base class for a control or "widget".

    A control is generally a small window which processes user input and/or
    displays one or more item of data.

    @beginEventEmissionTable{wxClipboardTextEvent}
    @event{EVT_TEXT_COPY(id, func)}
           Some or all of the controls content was copied to the clipboard.
    @event{EVT_TEXT_CUT(id, func)}
           Some or all of the controls content was cut (i.e. copied and
           deleted).
    @event{EVT_TEXT_PASTE(id, func)}
           Clipboard content was pasted into the control.
    @endEventTable

    @library{wxcore}
    @category{ctrl}

    @see wxValidator
*/
class wxControl : public wxWindow
{
public:
    /**
        Simulates the effect of the user issuing a command to the item.

        @see wxCommandEvent
    */
    virtual void Command(wxCommandEvent& event);

    /**
        Returns the control's label, as it was passed to SetLabel().

        Note that the returned string may contains mnemonics ("&" characters) if they were
        passed to the SetLabel() function; use GetLabelText() if they are undesired.

        Also note that the returned string is always the string which was passed to
        SetLabel() but may be different from the string passed to SetLabelText()
        (since this last one escapes mnemonic characters).
    */
    wxString GetLabel() const;

    /**
        Returns the control's label without mnemonics.

        Note that because of the stripping of the mnemonics the returned string may differ
        from the string which was passed to SetLabel() but should always be the same which
        was passed to SetLabelText().
    */
    wxString GetLabelText() const;

    /**
        Sets the control's label.

        All "&" characters in the @a label are special and indicate that the
        following character is a @e mnemonic for this control and can be used to
        activate it from the keyboard (typically by using @e Alt key in
        combination with it). To insert a literal ampersand character, you need
        to double it, i.e. use use "&&". If this behaviour is undesirable, use
        SetLabelText() instead.
    */
    void SetLabel(const wxString& label);

    /**
        Sets the control's label to exactly the given string.

        Unlike SetLabel(), this function shows exactly the @a text passed to it
        in the control, without interpreting ampersands in it in any way.
        Notice that it means that the control can't have any mnemonic defined
        for it using this function.

        @see EscapeMnemonics()
     */
    void SetLabelText(const wxString& text);


public:     // static functions
    
    /**
        Returns the given @a label string without mnemonics ("&" characters).
    */
    static wxString GetLabelText(const wxString& label);

    /**
        Returns the given @a str string without mnemonics ("&" characters).
        
        @note This function is identic to GetLabelText() and is provided both for symmetry
              with the wxStaticText::RemoveMarkup() function and to allow to write more
              readable code (since this function has a more descriptive name respect GetLabelText()).
    */
    static wxString RemoveMnemonics(const wxString& str);

    /**
        Escapes the special mnemonics characters ("&") in the given string.

        This function can be helpful if you need to set the controls label to a
        user-provided string. If the string contains ampersands, they wouldn't
        appear on the display but be used instead to indicate that the
        character following the first of them can be used as a control mnemonic.
        While this can sometimes be desirable (e.g. to allow the user to
        configure mnemonics of the controls), more often you will want to use
        this function before passing a user-defined string to SetLabel().
        Alternatively, if the label is entirely user-defined, you can just call
        SetLabelText() directly -- but this function must be used if the label
        is a combination of a part defined by program containing the control
        mnemonics and a user-defined part.

        @param text
            The string such as it should appear on the display.
        @return
            The same string with the ampersands in it doubled.
     */
    static wxString EscapeMnemonics(const wxString& text);

    /**
        Replaces parts of the @a label string with ellipsis, if needed, so
        that it doesn't exceed @a maxWidth.
        
        Note that this functions is guaranteed to always returns a string
        whose rendering on the given DC takes less than @a maxWidth pixels
        in horizontal.

        @param label
            The string to ellipsize
        @param dc
            The DC used to retrieve the character widths through the
            wxDC::GetPartialTextExtents() function.
        @param mode
            The ellipsization mode. This is the setting which determines
            which part of the string should be replaced by the ellipsis.
            See ::wxEllipsizeMode enumeration values for more info.
        @param maxWidth
            The maximum width of the returned string in pixels.
            This argument determines how much characters of the string need to
            be removed (and replaced by ellipsis).
        @param flags
            One or more of the ::wxEllipsizeFlags enumeration values combined.
    */
    static wxString Ellipsize(const wxString& label, const wxDC& dc,
                              wxEllipsizeMode mode, int maxWidth,
                              int flags = wxELLIPSIZE_FLAGS_DEFAULT);
};

