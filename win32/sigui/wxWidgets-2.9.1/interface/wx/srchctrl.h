/////////////////////////////////////////////////////////////////////////////
// Name:        srchctrl.h
// Purpose:     interface of wxSearchCtrl
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxSearchCtrl

    A search control is a composite control with a search button, a text
    control, and a cancel button.

    @beginStyleTable
    @style{wxTE_PROCESS_ENTER}
           The control will generate the event wxEVT_COMMAND_TEXT_ENTER
           (otherwise pressing Enter key is either processed internally by the
           control or used for navigation between dialog controls).
    @style{wxTE_PROCESS_TAB}
           The control will receive wxEVT_CHAR events for TAB pressed -
           normally, TAB is used for passing to the next control in a dialog
           instead. For the control created with this style, you can still use
           Ctrl-Enter to pass to the next control from the keyboard.
    @style{wxTE_NOHIDESEL}
           By default, the Windows text control doesn't show the selection
           when it doesn't have focus - use this style to force it to always
           show it. It doesn't do anything under other platforms.
    @style{wxTE_LEFT}
           The text in the control will be left-justified (default).
    @style{wxTE_CENTRE}
           The text in the control will be centered (currently wxMSW and
           wxGTK2 only).
    @style{wxTE_RIGHT}
           The text in the control will be right-justified (currently wxMSW
           and wxGTK2 only).
    @style{wxTE_CAPITALIZE}
           On PocketPC and Smartphone, causes the first letter to be
           capitalized.
    @endStyleTable

    @beginEventEmissionTable{wxCommandEvent}
    To retrieve actual search queries, use EVT_TEXT and EVT_TEXT_ENTER events,
    just as you would with wxTextCtrl.
    @event{EVT_SEARCHCTRL_SEARCH_BTN(id, func)}
        Respond to a wxEVT_SEARCHCTRL_SEARCH_BTN event, generated when the
        search button is clicked. Note that this does not initiate a search on
        its own, you need to perform the appropriate action in your event
        handler. You may use @code event.GetString() @endcode to retrieve the
        string to search for in the event handler code.
    @event{EVT_SEARCHCTRL_CANCEL_BTN(id, func)}
        Respond to a wxEVT_SEARCHCTRL_CANCEL_BTN event, generated when the
        cancel button is clicked.
    @endEventTable

    @library{wxcore}
    @category{ctrl}
    @appearance{searchctrl.png}

    @see wxTextCtrl::Create, wxValidator
*/
class wxSearchCtrl : public wxTextCtrl
{
public:
    /**
      Default constructor
    */
    wxSearchCtrl();

    /**
        Constructor, creating and showing a text control.

        @param parent
            Parent window. Should not be @NULL.
        @param id
            Control identifier. A value of -1 denotes a default value.
        @param value
            Default text value.
        @param pos
            Text control position.
        @param size
            Text control size.
        @param style
            Window style. See wxSearchCtrl.
        @param validator
            Window validator.
        @param name
            Window name.

        @see wxTextCtrl::Create, wxValidator
    */
    wxSearchCtrl(wxWindow* parent, wxWindowID id,
                 const wxString& value = wxEmptyString,
                 const wxPoint& pos = wxDefaultPosition,
                 const wxSize& size = wxDefaultSize,
                 long style = 0,
                 const wxValidator& validator = wxDefaultValidator,
                 const wxString& name = wxSearchCtrlNameStr);

    /**
        Destructor, destroying the search control.
    */
    virtual ~wxSearchCtrl();

    /**
        Returns a pointer to the search control's menu object or @NULL if there is no
        menu attached.
    */
    virtual wxMenu* GetMenu();

    /**
        Returns the search button visibility value.
        If there is a menu attached, the search button will be visible regardless of
        the search button visibility value.

        This always returns @false in Mac OS X v10.3
    */
    virtual bool IsSearchButtonVisible() const;

    /**
        Sets the search control's menu object.
        If there is already a menu associated with the search control it is deleted.

        @param menu
            Menu to attach to the search control.
    */
    virtual void SetMenu(wxMenu* menu);

    /**
        Shows or hides the cancel button.
    */
    virtual void ShowCancelButton(bool show);

    /**
        Sets the search button visibility value on the search control.
        If there is a menu attached, the search button will be visible regardless of
        the search button visibility value.

        This has no effect in Mac OS X v10.3
    */
    virtual void ShowSearchButton(bool show);
};

