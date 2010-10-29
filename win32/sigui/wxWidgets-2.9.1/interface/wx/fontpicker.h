/////////////////////////////////////////////////////////////////////////////
// Name:        fontpicker.h
// Purpose:     interface of wxFontPickerCtrl
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxFontPickerCtrl

    This control allows the user to select a font. The generic implementation is
    a button which brings up a wxFontDialog when clicked. Native implementation
    may differ but this is usually a (small) widget which give access to the
    font-chooser dialog.
    It is only available if @c wxUSE_FONTPICKERCTRL is set to 1 (the default).

    @beginStyleTable
    @style{wxFNTP_DEFAULT_STYLE}
           The default style: wxFNTP_FONTDESC_AS_LABEL | wxFNTP_USEFONT_FOR_LABEL.
    @style{wxFNTP_USE_TEXTCTRL}
           Creates a text control to the left of the picker button which is
           completely managed by the wxFontPickerCtrl and which can be used by
           the user to specify a font (see SetSelectedFont). The text control
           is automatically synchronized with button's value. Use functions
           defined in wxPickerBase to modify the text control.
    @style{wxFNTP_FONTDESC_AS_LABEL}
           Keeps the label of the button updated with the fontface name and
           the font size. E.g. choosing "Times New Roman bold, italic with
           size 10" from the fontdialog, will update the label (overwriting
           any previous label) with the "Times New Roman, 10" text.
    @style{wxFNTP_USEFONT_FOR_LABEL}
           Uses the currently selected font to draw the label of the button.
    @endStyleTable

    @beginEventEmissionTable{wxFontPickerEvent}
    @event{EVT_FONTPICKER_CHANGED(id, func)}
        The user changed the font selected in the control either using the button
        or using text control (see wxFNTP_USE_TEXTCTRL; note that in this case the
        event is fired only if the user's input is valid, i.e. recognizable).
    @endEventTable

    @library{wxcore}
    @category{pickers}
    @appearance{fontpickerctrl.png}

    @see wxFontDialog, wxFontPickerEvent
*/
class wxFontPickerCtrl : public wxPickerBase
{
public:
    /**
        Initializes the object and calls Create() with
        all the parameters.
    */
    wxFontPickerCtrl(wxWindow* parent, wxWindowID id,
                     const wxFont& font = wxNullFont,
                     const wxPoint& pos = wxDefaultPosition,
                     const wxSize& size = wxDefaultSize,
                     long style = wxFNTP_DEFAULT_STYLE,
                     const wxValidator& validator = wxDefaultValidator,
                     const wxString& name = wxFontPickerCtrlNameStr);

    /**
        Creates this widget with given parameters.

        @param parent
            Parent window, must not be non-@NULL.
        @param id
            The identifier for the control.
        @param font
            The initial font shown in the control.
            If ::wxNullFont is given, the default font is used.
        @param pos
            Initial position.
        @param size
            Initial size.
        @param style
            The window style, see wxFNTP_* flags.
        @param validator
            Validator which can be used for additional date checks.
        @param name
            Control name.

        @return @true if the control was successfully created or @false if
                 creation failed.
    */
    bool Create(wxWindow* parent, wxWindowID id,
                const wxFont& font = wxNullFont,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxFNTP_DEFAULT_STYLE,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxFontPickerCtrlNameStr);

    /**
        Returns the maximum point size value allowed for the user-chosen font.
    */
    unsigned int GetMaxPointSize() const;

    /**
        Returns the currently selected font.
        Note that this function is completely different from wxWindow::GetFont.
    */
    wxFont GetSelectedFont() const;

    /**
        Sets the maximum point size value allowed for the user-chosen font.

        The default value is 100. Note that big fonts can require a lot of memory and
        CPU time both for creation and for rendering; thus, specially because the user
        has the option to specify the fontsize through a text control
        (see wxFNTP_USE_TEXTCTRL), it's a good idea to put a limit to the maximum
        font size when huge fonts do not make much sense.
    */
    void SetMaxPointSize(unsigned int max);

    /**
        Sets the currently selected font.
        Note that this function is completely different from wxWindow::SetFont.
    */
    void SetSelectedFont(const wxFont& font);
};



/**
    @class wxFontPickerEvent

    This event class is used for the events generated by
    wxFontPickerCtrl.

    @beginEventTable{wxFontPickerEvent}
    @event{EVT_FONTPICKER_CHANGED(id, func)}
        Generated whenever the selected font changes.
    @endEventTable

    @library{wxcore}
    @category{events}

    @see wxFontPickerCtrl
*/
class wxFontPickerEvent : public wxCommandEvent
{
public:
    /**
        The constructor is not normally used by the user code.
    */
    wxFontPickerEvent(wxObject* generator, int id,
                      const wxFont& font);

    /**
        Retrieve the font the user has just selected.
    */
    wxFont GetFont() const;

    /**
        Set the font associated with the event.
    */
    void SetFont(const wxFont& f);
};

