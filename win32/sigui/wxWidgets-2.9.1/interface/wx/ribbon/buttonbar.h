///////////////////////////////////////////////////////////////////////////////
// Name:        ribbon/buttonbar.h
// Purpose:     interface of wxRibbonButtonBar
// Author:      Peter Cawley
// RCS-ID:      $Id$
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

/**
    Flags for button bar button size and state.
    
    Buttons on a ribbon button bar can each come in three sizes: small, medium,
    and large. In some places this is called the size class, and the term size
    used for the pixel width and height associated with a particular size
    class.
    
    A button can also be in zero or more hovered or active states, or in the
    disabled state.
*/
enum wxRibbonButtonBarButtonState
{
    /**
        Button is small (the interpretation of small is dependant upon the art
        provider, but it will be smaller than medium).
    */
    wxRIBBON_BUTTONBAR_BUTTON_SMALL     = 0 << 0,
    
    /**
        Button is medium sized (the interpretation of medium is dependant upon
        the art provider, but it will be between small and large).
    */
    wxRIBBON_BUTTONBAR_BUTTON_MEDIUM    = 1 << 0,
    
    /**
        Button is large (the interpretation of large is dependant upon the art
        provider, but it will be larger than medium).
    */
    wxRIBBON_BUTTONBAR_BUTTON_LARGE     = 2 << 0,
    
    /**
        A mask to extract button size from a combination of flags.
    */
    wxRIBBON_BUTTONBAR_BUTTON_SIZE_MASK = 3 << 0,

    /**
        The normal (non-dropdown) region of the button is being hovered over by
        the mouse cursor. Only applicable to normal and hybrid buttons.
    */
    wxRIBBON_BUTTONBAR_BUTTON_NORMAL_HOVERED    = 1 << 3,
    
    /**
        The dropdown region of the button is being hovered over by the mouse
        cursor. Only applicable to dropdown and hybrid buttons.
    */
    wxRIBBON_BUTTONBAR_BUTTON_DROPDOWN_HOVERED  = 1 << 4,
    
    /**
        A mask to extract button hover state from a combination of flags.
    */
    wxRIBBON_BUTTONBAR_BUTTON_HOVER_MASK        = wxRIBBON_BUTTONBAR_BUTTON_NORMAL_HOVERED | wxRIBBON_BUTTONBAR_BUTTON_DROPDOWN_HOVERED,
    
    /**
        The normal (non-dropdown) region of the button is being pressed.
        Only applicable to normal and hybrid buttons.
    */
    wxRIBBON_BUTTONBAR_BUTTON_NORMAL_ACTIVE     = 1 << 5,
    
    /**
        The dropdown region of the button is being pressed.
        Only applicable to dropdown and hybrid buttons.
    */
    wxRIBBON_BUTTONBAR_BUTTON_DROPDOWN_ACTIVE   = 1 << 6,
    
    /**
        The button is disabled. Hover flags may still be set when a button
        is disabled, but should be ignored during drawing if the button is
        disabled.
    */
    wxRIBBON_BUTTONBAR_BUTTON_DISABLED          = 1 << 7,
    
    /**
        A mask to extract button state from a combination of flags.
    */
    wxRIBBON_BUTTONBAR_BUTTON_STATE_MASK        = 0xF8,
};

/**
    @class wxRibbonButtonBar
    
    A ribbon button bar is similar to a traditional toolbar. It contains one or
    more buttons (button bar buttons, not wxButtons), each of which has a label
    and an icon. It differs from a wxRibbonToolBar in several ways:
      @li Individual buttons can grow and contract.
      @li Buttons have labels as well as bitmaps.
      @li Bitmaps are typically larger (at least 32x32 pixels) on a button bar
        compared to a tool bar (which typically has 16x15).
      @li There is no grouping of buttons on a button bar
      @li A button bar typically has a border around each individual button,
        whereas a tool bar typically has a border around each group of buttons.
    
    @beginEventEmissionTable{wxRibbonButtonBarEvent}
    @event{EVT_RIBBONBUTTONBAR_CLICKED(id, func)}
        Triggered when the normal (non-dropdown) region of a button on the
        button bar is clicked.
    @event{EVT_RIBBONBUTTONBAR_DROPDOWN_CLICKED(id, func)}
        Triggered when the dropdown region of a button on the button bar is
        clicked. wxRibbonButtonBarEvent::PopupMenu() should be called by the
        event handler if it wants to display a popup menu (which is what most
        dropdown buttons should be doing).
    @endEventTable
    
    @library{wxribbon}
    @category{ribbon}
*/
class wxRibbonButtonBar : public wxRibbonControl
{
public:
    /**
        Default constructor.
        With this constructor, Create() should be called in order to create
        the button bar.
    */
    wxRibbonButtonBar();

    /**
        Construct a ribbon button bar with the given parameters.
        
        @param parent
            Parent window for the button bar (typically a wxRibbonPanel).
        @param id
            An identifier for the button bar. @c wxID_ANY is taken to mean a default.
        @param pos
            Initial position of the button bar.
        @param size
            Initial size of the button bar.
        @param style
            Button bar style, currently unused.
    */
    wxRibbonButtonBar(wxWindow* parent,
                  wxWindowID id = wxID_ANY,
                  const wxPoint& pos = wxDefaultPosition,
                  const wxSize& size = wxDefaultSize,
                  long style = 0);

    /**
        Destructor.
    */
    virtual ~wxRibbonButtonBar();

    /**
        Create a button bar in two-step button bar construction.
        Should only be called when the default constructor is used, and
        arguments have the same meaning as in the full constructor.
    */
    bool Create(wxWindow* parent,
                wxWindowID id = wxID_ANY,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0);

    /**
        Add a button to the button bar (simple version).
    */
    virtual wxRibbonButtonBarButtonBase* AddButton(
                int button_id,
                const wxString& label,
                const wxBitmap& bitmap,
                const wxString& help_string,
                wxRibbonButtonBarButtonKind kind = wxRIBBON_BUTTONBAR_BUTTON_NORMAL);

    /**
        Add a dropdown button to the button bar (simple version).
        
        @see AddButton()
    */
    virtual wxRibbonButtonBarButtonBase* AddDropdownButton(
                int button_id,
                const wxString& label,
                const wxBitmap& bitmap,
                const wxString& help_string = wxEmptyString);

    /**
        Add a hybrid button to the button bar (simple version).
        
        @see AddButton()
    */
    virtual wxRibbonButtonBarButtonBase* AddHybridButton(
                int button_id,
                const wxString& label,
                const wxBitmap& bitmap,
                const wxString& help_string = wxEmptyString);
    
    /**
        Add a button to the button bar.
        
        @param button_id
            ID of the new button (used for event callbacks).
        @param label
            Label of the new button.
        @param bitmap
            Large bitmap of the new button. Must be the same size as all other
            large bitmaps used on the button bar.
        @param bitmap_small
            Small bitmap of the new button. If left as null, then a small
            bitmap will be automatically generated. Must be the same size as
            all other small bitmaps used on the button bar.
        @param bitmap_disabled
            Large bitmap of the new button when it is disabled. If left as
            null, then a bitmap will be automatically generated from @a bitmap.
        @param bitmap_small_disabled
            Small bitmap of the new button when it is disabled. If left as
            null, then a bitmap will be automatically generated from @a
            bitmap_small.
        @param kind
            The kind of button to add.
        @param help_string
            The UI help string to associate with the new button.
        @param client_data
            Client data to associate with the new button.
        
        @return An opaque pointer which can be used only with other button bar
            methods.
            
        @see AddDropdownButton()
        @see AddHybridButton()
    */
    virtual wxRibbonButtonBarButtonBase* AddButton(
                int button_id,
                const wxString& label,
                const wxBitmap& bitmap,
                const wxBitmap& bitmap_small = wxNullBitmap,
                const wxBitmap& bitmap_disabled = wxNullBitmap,
                const wxBitmap& bitmap_small_disabled = wxNullBitmap,
                wxRibbonButtonBarButtonKind kind = wxRIBBON_BUTTONBAR_BUTTON_NORMAL,
                const wxString& help_string = wxEmptyString,
                wxObject* client_data = NULL);

    /**
        Calculate button layouts and positions.
        
        Must be called after buttons are added to the button bar, as otherwise
        the newly added buttons will not be displayed. In normal situations, it
        will be called automatically when wxRibbonBar::Realize() is called.
    */
    virtual bool Realize();
    
    /**
        Delete all buttons from the button bar.
        
        @see DeleteButton()
    */
    virtual void ClearButtons();
    
    /**
        Delete a single button from the button bar.
        
        @see ClearButtons()
    */
    virtual bool DeleteButton(int button_id);
    
    /**
        Enable or disable a single button on the bar.
        
        @param button_id
            ID of the button to enable or disable.
        @param enable
            @true to enable the button, @false to disable it.
    */
    virtual void EnableButton(int button_id, bool enable = true);
};

/**
    @class wxRibbonButtonBarEvent

    Event used to indicate various actions relating to a button on a
    wxRibbonButtonBar.

    See wxRibbonButtonBar for available event types.

    @library{wxribbon}
    @category{events,ribbon}

    @see wxRibbonBar
*/
class wxRibbonButtonBarEvent : public wxCommandEvent
{
public:
    /**
        Constructor.
    */
    wxRibbonButtonBarEvent(wxEventType command_type = wxEVT_NULL,
                       int win_id = 0,
                       wxRibbonButtonBar* bar = NULL);

    /**
        Returns the bar which contains the button which the event relates to.
    */
    wxRibbonButtonBar* GetBar();
        
    /**
        Sets the button bar relating to this event.
    */
    void SetBar(wxRibbonButtonBar* bar);
    
    /**
        Display a popup menu as a result of this (dropdown clicked) event.
    */
    bool PopupMenu(wxMenu* menu);
};
