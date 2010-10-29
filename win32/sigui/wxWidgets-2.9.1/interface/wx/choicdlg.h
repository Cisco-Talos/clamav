/////////////////////////////////////////////////////////////////////////////
// Name:        choicdlg.h
// Purpose:     interface of wx[Multi|Single]ChoiceDialog
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxMultiChoiceDialog

    This class represents a dialog that shows a list of strings, and allows the
    user to select one or more.

    @library{wxbase}
    @category{cmndlg}

    @see @ref overview_cmndlg_multichoice, wxSingleChoiceDialog
*/
class wxMultiChoiceDialog : public wxDialog
{
public:
    //@{
    /**
        Constructor taking an array of wxString choices.

        @param parent
            Parent window.
        @param message
            Message to show on the dialog.
        @param caption
            The dialog caption.
        @param n
            The number of choices.
        @param choices
            An array of strings, or a string list, containing the choices.
        @param style
            A dialog style (bitlist) containing flags chosen from standard
            dialog style and the ones listed below. The default value is
            equivalent to wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER | wxOK |
            wxCANCEL | wxCENTRE.
        @param pos
            Dialog position. Not Windows.

        @beginStyleTable
        @style{wxOK}
            Show an OK button.
        @style{wxCANCEL}
            Show a Cancel button.
        @style{wxCENTRE}
            Centre the message. Not Windows.
        @endStyleTable

        @remarks Use ShowModal() to show the dialog.

        @beginWxPythonOnly

        For Python the two parameters @a n and @a choices are collapsed into a
        multi parameter @a choices which is expected to be a Python list of
        strings.

        @endWxPythonOnly

        @beginWxPerlOnly
        Not supported by wxPerl.
        @endWxPerlOnly
    */
    wxMultiChoiceDialog(wxWindow* parent, const wxString& message,
                        const wxString& caption,
                        int n, const wxString* choices,
                        long style = wxCHOICEDLG_STYLE,
                        const wxPoint& pos = wxDefaultPosition);
    /**
        Constructor taking an array of wxString choices.

        @param parent
            Parent window.
        @param message
            Message to show on the dialog.
        @param caption
            The dialog caption.
        @param choices
            An array of strings, or a string list, containing the choices.
        @param style
            A dialog style (bitlist) containing flags chosen from standard
            dialog style and the ones listed below. The default value is
            equivalent to wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER | wxOK |
            wxCANCEL | wxCENTRE.
        @param pos
            Dialog position. Not Windows.

        @beginStyleTable
        @style{wxOK}
            Show an OK button.
        @style{wxCANCEL}
            Show a Cancel button.
        @style{wxCENTRE}
            Centre the message. Not Windows.
        @endStyleTable

        @remarks Use ShowModal() to show the dialog.

        @beginWxPythonOnly

        For Python the two parameters @a n and @a choices are collapsed into a
        multi parameter @a choices which is expected to be a Python list of
        strings.

        @endWxPythonOnly

        @beginWxPerlOnly
        Use an array reference for the @a choices parameter.
        @endWxPerlOnly
    */
    wxMultiChoiceDialog(wxWindow* parent,
                        const wxString& message,
                        const wxString& caption,
                        const wxArrayString& choices,
                        long style = wxCHOICEDLG_STYLE,
                        const wxPoint& pos = wxDefaultPosition);
    //@}

    /**
        Returns array with indexes of selected items.
    */
    wxArrayInt GetSelection() const;

    /**
        Sets selected items from the array of selected items' indexes.
    */
    void SetSelections(const wxArrayInt& selections);

    /**
        Shows the dialog, returning either wxID_OK or wxID_CANCEL.
    */
    int ShowModal();
};



/**
    @class wxSingleChoiceDialog

    This class represents a dialog that shows a list of strings, and allows the
    user to select one. Double-clicking on a list item is equivalent to
    single-clicking and then pressing OK.

    @library{wxbase}
    @category{cmndlg}

    @see @ref overview_cmndlg_singlechoice, wxMultiChoiceDialog
*/
class wxSingleChoiceDialog : public wxDialog
{
public:
    //@{
    /**
        Constructor, taking an array of wxString choices and optional client
        data.

        @param parent
            Parent window.
        @param message
            Message to show on the dialog.
        @param caption
            The dialog caption.
        @param n
            The number of choices.
        @param choices
            An array of strings, or a string list, containing the choices.
        @param clientData
            An array of client data to be associated with the items. See
            GetSelectionClientData().
        @param style
            A dialog style (bitlist) containing flags chosen from standard
            dialog styles and the ones listed below. The default value is
            equivalent to wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER | wxOK |
            wxCANCEL | wxCENTRE.
        @param pos
            Dialog position. Not Windows.

        @beginStyleTable
        @style{wxOK}
            Show an OK button.
        @style{wxCANCEL}
            Show a Cancel button.
        @style{wxCENTRE}
            Centre the message. Not Windows.
        @endStyleTable

        @remarks Use ShowModal() to show the dialog.

        @beginWxPythonOnly

        For Python the two parameters @a n and @a choices are collapsed into a
        multi parameter @a choices which is expected to be a Python list of
        strings.

        @endWxPythonOnly

        @beginWxPerlOnly
        Not supported by wxPerl.
        @endWxPerlOnly
    */
    wxSingleChoiceDialog(wxWindow* parent, const wxString& message,
                         const wxString& caption,
                         int n, const wxString* choices,
                         void** clientData = NULL,
                         long style = wxCHOICEDLG_STYLE,
                         const wxPoint& pos = wxDefaultPosition);
    /**
        Constructor, taking an array of wxString choices and optional client
        data.

        @param parent
            Parent window.
        @param message
            Message to show on the dialog.
        @param caption
            The dialog caption.
        @param choices
            An array of strings, or a string list, containing the choices.
        @param clientData
            An array of client data to be associated with the items. See
            GetSelectionClientData().
        @param style
            A dialog style (bitlist) containing flags chosen from standard
            dialog styles and the ones listed below. The default value is
            equivalent to wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER | wxOK |
            wxCANCEL | wxCENTRE.
        @param pos
            Dialog position. Not Windows.

        @beginStyleTable
        @style{wxOK}
            Show an OK button.
        @style{wxCANCEL}
            Show a Cancel button.
        @style{wxCENTRE}
            Centre the message. Not Windows.
        @endStyleTable

        @remarks Use ShowModal() to show the dialog.

        @beginWxPythonOnly

        For Python the two parameters @a n and @a choices are collapsed into a
        multi parameter @a choices which is expected to be a Python list of
        strings.

        @endWxPythonOnly

        @beginWxPerlOnly
        Use an array reference for the @a choices parameter.
        @endWxPerlOnly
    */
    wxSingleChoiceDialog(wxWindow* parent,
                         const wxString& message,
                         const wxString& caption,
                         const wxArrayString& choices,
                         void** clientData = NULL,
                         long style = wxCHOICEDLG_STYLE,
                         const wxPoint& pos = wxDefaultPosition);
    //@}

    /**
        Returns the index of selected item.
    */
    int GetSelection() const;

    /**
        Returns the client data associated with the selection.
    */
    char* GetSelectionClientData() const;

    /**
        Returns the selected string.
    */
    wxString GetStringSelection() const;

    /**
        Sets the index of the initially selected item.
    */
    void SetSelection(int selection);

    /**
        Shows the dialog, returning either wxID_OK or wxID_CANCEL.
    */
    int ShowModal();
};



// ============================================================================
// Global functions/macros
// ============================================================================

/** @addtogroup group_funcmacro_dialog */
//@{

/**
    Same as wxGetSingleChoice() but returns the index representing the
    selected string. If the user pressed cancel, -1 is returned.

    @header{wx/choicdlg.h}

    @beginWxPerlOnly
    Use an array reference for the @a aChoices parameter.
    @endWxPerlOnly
*/
int wxGetSingleChoiceIndex(const wxString& message,
                           const wxString& caption,
                           const wxArrayString& aChoices,
                           wxWindow* parent = NULL,
                           int x = -1,
                           int y = -1,
                           bool centre = true,
                           int width = 150,
                           int height = 200,
                           int initialSelection = 0);

int wxGetSingleChoiceIndex(const wxString& message,
                           const wxString& caption,
                           int n,
                           const wxString& choices[],
                           wxWindow* parent = NULL,
                           int x = -1,
                           int y = -1,
                           bool centre = true,
                           int width = 150,
                           int height = 200,
                           int initialSelection = 0);


int wxGetSingleChoiceIndex(const wxString& message,
                           const wxString& caption,
                           const wxArrayString& choices,
                           int initialSelection,
                           wxWindow *parent = NULL);

int wxGetSingleChoiceIndex(const wxString& message,
                           const wxString& caption,
                           int n, const wxString *choices,
                           int initialSelection,
                           wxWindow *parent = NULL);
//@}

/** @addtogroup group_funcmacro_dialog */
//@{

/**
    Pops up a dialog box containing a message, OK/Cancel buttons and a
    single-selection listbox. The user may choose an item and press OK to
    return a string or Cancel to return the empty string. Use
    wxGetSingleChoiceIndex() if empty string is a valid choice and if you want
    to be able to detect pressing Cancel reliably.

    You may pass the list of strings to choose from either using @c choices
    which is an array of @a n strings for the listbox or by using a single
    @c aChoices parameter of type wxArrayString.

    If @c centre is @true, the message text (which may include new line
    characters) is centred; if @false, the message is left-justified.

    @header{wx/choicdlg.h}

    @beginWxPerlOnly
    Use an array reference for the @a choices parameter.
    @endWxPerlOnly
*/
wxString wxGetSingleChoice(const wxString& message,
                           const wxString& caption,
                           const wxArrayString& aChoices,
                           wxWindow* parent = NULL,
                           int x = -1,
                           int y = -1,
                           bool centre = true,
                           int width = 150,
                           int height = 200
                           int initialSelection = 0);
wxString wxGetSingleChoice(const wxString& message,
                           const wxString& caption,
                           int n,
                           const wxString& choices[],
                           wxWindow* parent = NULL,
                           int x = -1,
                           int y = -1,
                           bool centre = true,
                           int width = 150,
                           int height = 200
                           int initialSelection = 0);


wxString wxGetSingleChoice(const wxString& message,
                           const wxString& caption,
                           const wxArrayString& choices,
                           int initialSelection,
                           wxWindow *parent = NULL);

wxString wxGetSingleChoice(const wxString& message,
                           const wxString& caption,
                           int n, const wxString *choices,
                           int initialSelection,
                           wxWindow *parent = NULL);

//@}

/** @addtogroup group_funcmacro_dialog */
//@{

/**
    Same as wxGetSingleChoice but takes an array of client data pointers
    corresponding to the strings, and returns one of these pointers or @NULL
    if Cancel was pressed. The @c client_data array must have the same number
    of elements as @c choices or @c aChoices!

    @header{wx/choicdlg.h}

    @beginWxPerlOnly
    Use an array reference for the @a aChoices and @a client_data parameters.
    @endWxPerlOnly
*/
wxString wxGetSingleChoiceData(const wxString& message,
                               const wxString& caption,
                               const wxArrayString& aChoices,
                               const wxString& client_data[],
                               wxWindow* parent = NULL,
                               int x = -1,
                               int y = -1,
                               bool centre = true,
                               int width = 150,
                               int height = 200
                               int initialSelection = 0);

wxString wxGetSingleChoiceData(const wxString& message,
                               const wxString& caption,
                               int n,
                               const wxString& choices[],
                               const wxString& client_data[],
                               wxWindow* parent = NULL,
                               int x = -1,
                               int y = -1,
                               bool centre = true,
                               int width = 150,
                               int height = 200
                               int initialSelection = 0);

void* wxGetSingleChoiceData(const wxString& message,
                            const wxString& caption,
                            const wxArrayString& choices,
                            void **client_data,
                            int initialSelection,
                            wxWindow *parent = NULL);

void* wxGetSingleChoiceData(const wxString& message,
                            const wxString& caption,
                            int n, const wxString *choices,
                            void **client_data,
                            int initialSelection,
                            wxWindow *parent = NULL);

//@}

/** @addtogroup group_funcmacro_dialog */
//@{

/**
    Pops up a dialog box containing a message, OK/Cancel buttons and a
    multiple-selection listbox. The user may choose an arbitrary (including 0)
    number of items in the listbox whose indices will be returned in
    @c selections array. The initial contents of this array will be used to
    select the items when the dialog is shown. If the user cancels the dialog,
    the function returns -1 and @c selections array is left unchanged.

    You may pass the list of strings to choose from either using @c choices
    which is an array of @a n strings for the listbox or by using a single
    @c aChoices parameter of type wxArrayString.

    If @c centre is @true, the message text (which may include new line
    characters) is centred; if @false, the message is left-justified.

    @header{wx/choicdlg.h}

    @beginWxPerlOnly
    Use an array reference for the @a choices parameter.
    In wxPerl there is no @a selections parameter; the function
    returns an array containing the user selections.
    @endWxPerlOnly
*/
int wxGetSelectedChoices(wxArrayInt& selections,
                            const wxString& message,
                            const wxString& caption,
                            const wxArrayString& aChoices,
                            wxWindow* parent = NULL,
                            int x = -1,
                            int y = -1,
                            bool centre = true,
                            int width = 150,
                            int height = 200);

int wxGetSelectedChoices(wxArrayInt& selections,
                            const wxString& message,
                            const wxString& caption,
                            int n,
                            const wxString& choices[],
                            wxWindow* parent = NULL,
                            int x = -1,
                            int y = -1,
                            bool centre = true,
                            int width = 150,
                            int height = 200);

//@}

