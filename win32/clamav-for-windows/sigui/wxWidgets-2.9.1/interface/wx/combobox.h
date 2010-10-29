/////////////////////////////////////////////////////////////////////////////
// Name:        combobox.h
// Purpose:     interface of wxComboBox
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxComboBox

    A combobox is like a combination of an edit control and a listbox.

    It can be displayed as static list with editable or read-only text field;
    or a drop-down list with text field; or a drop-down list without a text
    field.

    A combobox permits a single selection only. Combobox items are numbered
    from zero.

    If you need a customized combobox, have a look at wxComboCtrl,
    wxOwnerDrawnComboBox, wxComboPopup and the ready-to-use wxBitmapComboBox.

    Please refer to wxTextEntry documentation for the description of methods
    operating with the text entry part of the combobox.

    @beginStyleTable
    @style{wxCB_SIMPLE}
           Creates a combobox with a permanently displayed list. Windows only.
    @style{wxCB_DROPDOWN}
           Creates a combobox with a drop-down list.
    @style{wxCB_READONLY}
           Same as wxCB_DROPDOWN but only the strings specified as the combobox
           choices can be selected, it is impossible to select (even from a
           program) a string which is not in the choices list.
    @style{wxCB_SORT}
           Sorts the entries in the list alphabetically.
    @style{wxTE_PROCESS_ENTER}
           The control will generate the event wxEVT_COMMAND_TEXT_ENTER
           (otherwise pressing Enter key is either processed internally by the
           control or used for navigation between dialog controls). Windows
           only.
    @endStyleTable

    @beginEventEmissionTable{wxCommandEvent}
    @event{EVT_COMBOBOX(id, func)}
           Process a wxEVT_COMMAND_COMBOBOX_SELECTED event, when an item on
           the list is selected. Note that calling GetValue() returns the new
           value of selection.
    @event{EVT_TEXT(id, func)}
           Process a wxEVT_COMMAND_TEXT_UPDATED event, when the combobox text
           changes.
    @event{EVT_TEXT_ENTER(id, func)}
           Process a wxEVT_COMMAND_TEXT_ENTER event, when RETURN is pressed in
           the combobox (notice that the combobox must have been created with
           wxTE_PROCESS_ENTER style to receive this event).
    @event{EVT_COMBOBOX_DROPDOWN(id, func)}
           Process a wxEVT_COMMAND_COMBOBOX_DROPDOWN event, which is generated
           when the list box part of the combo box is shown (drops down).
           Notice that this event is currently only supported by wxMSW and
           wxGTK with GTK+ 2.10 or later.
    @event{EVT_COMBOBOX_CLOSEUP(id, func)}
           Process a wxEVT_COMMAND_COMBOBOX_CLOSEUP event, which is generated
           when the list box of the combo box disappears (closes up). This
           event is only generated for the same platforms as
           wxEVT_COMMAND_COMBOBOX_DROPDOWN above. Also note that only wxMSW
           supports adding or deleting items in this event.
    @endEventTable

    @library{wxcore}
    @category{ctrl}
    @appearance{combobox.png}

    @see wxListBox, wxTextCtrl, wxChoice, wxCommandEvent
*/
class wxComboBox : public wxControl,
                   public wxItemContainer,
                   public wxTextEntry
{
public:
    /**
        Default constructor.
    */
    wxComboBox();

    /**
        Constructor, creating and showing a combobox.

        @param parent
            Parent window. Must not be @NULL.
        @param id
            Window identifier. The value wxID_ANY indicates a default value.
        @param value
            Initial selection string. An empty string indicates no selection.
            Notice that for the controls with @c wxCB_READONLY style this
            string must be one of the valid choices if it is not empty.
        @param pos
            Window position.
            If ::wxDefaultPosition is specified then a default position is chosen.
        @param size
            Window size. 
            If ::wxDefaultSize is specified then the window is sized appropriately.
        @param n
            Number of strings with which to initialise the control.
        @param choices
            An array of strings with which to initialise the control.
        @param style
            Window style. See wxComboBox.
        @param validator
            Window validator.
        @param name
            Window name.

        @beginWxPythonOnly
        The wxComboBox constructor in wxPython reduces the @a n and @a choices
        arguments are to a single argument, which is a list of strings.
        @endWxPythonOnly

        @beginWxPerlOnly
        Not supported by wxPerl.
        @endWxPerlOnly

        @see Create(), wxValidator
    */
    wxComboBox(wxWindow* parent, wxWindowID id,
               const wxString& value = wxEmptyString,
               const wxPoint& pos = wxDefaultPosition,
               const wxSize& size = wxDefaultSize,
               int n = 0,
               const wxString choices[] = NULL,
               long style = 0,
               const wxValidator& validator = wxDefaultValidator,
               const wxString& name = wxComboBoxNameStr);
    /**
        Constructor, creating and showing a combobox.

        @param parent
            Parent window. Must not be @NULL.
        @param id
            Window identifier. The value wxID_ANY indicates a default value.
        @param value
            Initial selection string. An empty string indicates no selection.
        @param pos
            Window position.
        @param size
            Window size. If wxDefaultSize is specified then the window is sized
            appropriately.
        @param choices
            An array of strings with which to initialise the control.
        @param style
            Window style. See wxComboBox.
        @param validator
            Window validator.
        @param name
            Window name.

        @beginWxPythonOnly
        The wxComboBox constructor in wxPython reduces the @a n and @a choices
        arguments are to a single argument, which is a list of strings.
        @endWxPythonOnly

        @beginWxPerlOnly
        Use an array reference for the @a choices parameter.
        @endWxPerlOnly

        @see Create(), wxValidator
    */
    wxComboBox(wxWindow* parent, wxWindowID id,
               const wxString& value,
               const wxPoint& pos,
               const wxSize& size,
               const wxArrayString& choices,
               long style = 0,
               const wxValidator& validator = wxDefaultValidator,
               const wxString& name = wxComboBoxNameStr);

    /**
        Destructor, destroying the combobox.
    */
    virtual ~wxComboBox();

    //@{
    /**
        Creates the combobox for two-step construction. Derived classes should
        call or replace this function. See wxComboBox() for further details.
    */
    bool Create(wxWindow *parent, wxWindowID id,
                const wxString& value = wxEmptyString,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                int n = 0, const wxString choices[] = (const wxString *) NULL,
                long style = 0,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxComboBoxNameStr);
    bool Create(wxWindow *parent, wxWindowID id,
                const wxString& value,
                const wxPoint& pos,
                const wxSize& size,
                const wxArrayString& choices,
                long style = 0,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxComboBoxNameStr);
    //@}

    /**
        Returns the item being selected right now.

        This function does the same things as wxChoice::GetCurrentSelection()
        and returns the item currently selected in the dropdown list if it's
        open or the same thing as wxControlWithItems::GetSelection() otherwise.
    */
    virtual int GetCurrentSelection() const;

    /**
        Same as wxTextEntry::GetInsertionPoint().

        @note Under wxMSW, this function always returns 0 if the combobox
              doesn't have the focus.
    */
    virtual long GetInsertionPoint() const;

    /**
        Same as wxTextEntry::SetSelection().

        @beginWxPythonOnly
        This method is called SetMark() in wxPython, "SetSelection" is kept for
        wxControlWithItems::SetSelection().
        @endWxPythonOnly
    */
    virtual void SetSelection(long from, long to);

    /**
        Sets the text for the combobox text field.

        Notice that this method will generate a wxEVT_COMMAND_TEXT_UPDATED
        event, use wxTextEntry::ChangeValue() if this is undesirable.

        @note For a combobox with @c wxCB_READONLY style the string must be in
              the combobox choices list, otherwise the call to SetValue() is
              ignored.

        @param text
            The text to set.
    */
    virtual void SetValue(const wxString& text);

    /**
        Shows the list box portion of the combo box.

        Currently only implemented in wxMSW and wxGTK.

        Notice that calling this function will generate a
        wxEVT_COMMAND_COMBOBOX_DROPDOWN event.

        @since 2.9.1
    */
    virtual void Popup();

    /**
        Hides the list box portion of the combo box.

        Currently only implemented in wxMSW and wxGTK.

        Notice that calling this function will generate a
        wxEVT_COMMAND_COMBOBOX_CLOSEUP event.

        @since 2.9.1
    */
    virtual void Dismiss();
};

