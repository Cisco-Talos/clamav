///////////////////////////////////////////////////////////////////////////////
// Name:        ribbon/bar.h
// Purpose:     interface of wxRibbonBar
// Author:      Peter Cawley
// RCS-ID:      $Id$
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

/**
    @class wxRibbonBarEvent

    Event used to indicate various actions relating to a wxRibbonBar.

    See wxRibbonBar for available event types.

    @library{wxribbon}
    @category{events,ribbon}

    @see wxRibbonBar
*/
class wxRibbonBarEvent : public wxNotifyEvent
{
public:
    /**
        Constructor.
    */
    wxRibbonBarEvent(wxEventType command_type = wxEVT_NULL,
                     int win_id = 0,
                     wxRibbonPage* page = NULL);

    /**
        Returns the page being changed to, or being clicked on.
    */
    wxRibbonPage* GetPage();
    
    /**
        Sets the page relating to this event.
    */
    void SetPage(wxRibbonPage* page);
};

/**
    @class wxRibbonBar

    Top-level control in a ribbon user interface. Serves as a tabbed container
    for wxRibbonPage - a ribbon user interface typically has a ribbon bar,
    which contains one or more wxRibbonPages, which in turn each contain one
    or more wxRibbonPanels, which in turn contain controls.
    
    While a wxRibbonBar has tabs similar to a wxNotebook, it does not follow
    the same API for adding pages. Containers like wxNotebook can contain any
    type of window as a page, hence the normal procedure is to create the
    sub-window and then call wxBookCtrlBase::AddPage(). As wxRibbonBar can only
    have wxRibbonPage as children (and a wxRibbonPage can only have a
    wxRibbonBar as parent), when a page is created, it is automatically added
    to the bar - there is no AddPage equivalent to call.
    
    After all pages have been created, and all controls and panels placed on
    those pages, Realize() must be called.
    
    @sa wxRibbonPage
    @sa wxRibbonPanel
    
    @beginStyleTable
    @style{wxRIBBON_BAR_DEFAULT_STYLE}
        Defined as wxRIBBON_BAR_FLOW_HORIZONTAL |
        wxRIBBON_BAR_SHOW_PAGE_LABELS | wxRIBBON_BAR_SHOW_PANEL_EXT_BUTTONS
    @style{wxRIBBON_BAR_FOLDBAR_STYLE}
        Defined as wxRIBBON_BAR_FLOW_VERTICAL | wxRIBBON_BAR_SHOW_PAGE_ICONS
        | wxRIBBON_BAR_SHOW_PANEL_EXT_BUTTONS |
        wxRIBBON_BAR_SHOW_PANEL_MINIMISE_BUTTONS
    @style{wxRIBBON_BAR_SHOW_PAGE_LABELS}
        Causes labels to be shown on the tabs in the ribbon bar.
    @style{wxRIBBON_BAR_SHOW_PAGE_ICONS}
        Causes icons to be shown on the tabs in the ribbon bar.
    @style{wxRIBBON_BAR_FLOW_HORIZONTAL}
        Causes panels within pages to stack horizontally.
    @style{wxRIBBON_BAR_FLOW_VERTICAL}
        Causes panels within pages to stack vertically.
    @style{wxRIBBON_BAR_SHOW_PANEL_EXT_BUTTONS}
        Causes extension buttons to be shown on panels (where the panel has
        such a button).
    @style{wxRIBBON_BAR_SHOW_PANEL_MINIMISE_BUTTONS}
        Causes minimise buttons to be shown on panels (where the panel has
        such a button).
    @endStyleTable


    @beginEventEmissionTable{wxRibbonBarEvent}
    @event{EVT_RIBBONBAR_PAGE_CHANGED(id, func)}
        Triggered after the transition from one page being active to a different
        page being active.
    @event{EVT_RIBBONBAR_PAGE_CHANGING(id, func)}
        Triggered prior to the transition from one page being active to a
        different page being active, and can veto the change.
    @event{EVT_RIBBONBAR_TAB_MIDDLE_DOWN(id, func)}
        Triggered when the middle mouse button is pressed on a tab.
    @event{EVT_RIBBONBAR_TAB_MIDDLE_UP(id, func)}
        Triggered when the middle mouse button is released on a tab.
    @event{EVT_RIBBONBAR_TAB_RIGHT_DOWN(id, func)}
        Triggered when the right mouse button is pressed on a tab.
    @event{EVT_RIBBONBAR_TAB_RIGHT_UP(id, func)}
        Triggered when the right mouse button is released on a tab.
    @endEventTable

    @library{wxribbon}
    @category{ribbon}
*/
class wxRibbonBar : public wxRibbonControl
{
public:
    /**
        Default constructor.
        With this constructor, Create() should be called in order to create
        the ribbon bar.
    */
    wxRibbonBar();

    /**
        Construct a ribbon bar with the given parameters.
    */
    wxRibbonBar(wxWindow* parent,
                wxWindowID id = wxID_ANY,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxRIBBON_BAR_DEFAULT_STYLE);
    
    /**
        Create a ribbon bar in two-step ribbon bar construction.
        Should only be called when the default constructor is used, and
        arguments have the same meaning as in the full constructor.
    */
    bool Create(wxWindow* parent,
                wxWindowID id = wxID_ANY,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxRIBBON_BAR_DEFAULT_STYLE);

    /**
        Destructor.
    */
    virtual ~wxRibbonBar();

    /**
        Set the margin widths (in pixels) on the left and right sides of the
        tab bar region of the ribbon bar. These margins will be painted with
        the tab background, but tabs and scroll buttons will never be painted
        in the margins.
        
        The left margin could be used for rendering something equivalent to the
        "Office Button", though this is not currently implemented. The right
        margin could be used for rendering a help button, and/or MDI buttons,
        but again, this is not currently implemented.
    */
    void SetTabCtrlMargins(int left, int right);

    /**
        Set the art provider to be used be the ribbon bar. Also sets the art
        provider on all current wxRibbonPage children, and any wxRibbonPage
        children added in the future.
        
        Note that unlike most other ribbon controls, the ribbon bar creates a
        default art provider when initialised, so an explicit call to
        SetArtProvider() is not required if the default art provider is
        sufficient. Alos unlike other ribbon controls, the ribbon bar takes
        ownership of the given pointer, and will delete it when the art
        provider is changed or the bar is destroyed. If this behaviour is not
        desired, then clone the art provider before setting it.
    */
    void SetArtProvider(wxRibbonArtProvider* art);

    /**
        Set the active page by index, without triggering any events.
        
        @param page
            The zero-based index of the page to activate.
        @return @true if the specified page is now active, @false if it could
            not be activated (for example because the page index is invalid).
    */
    bool SetActivePage(size_t page);
    
    /**
        Set the active page, without triggering any events.
        
        @param page
            The page to activate.
        @return @true if the specified page is now active, @false if it could
            not be activated (for example because the given page is not a child
            of the ribbon bar).
    */
    bool SetActivePage(wxRibbonPage* page);
    
    /**
        Get the index of the active page.
        
        In the rare case of no page being active, -1 is returned.
    */
    int GetActivePage() const;
    
    /**
        Get a page by index.
        
        NULL will be returned if the given index is out of range.
    */
    wxRibbonPage* GetPage(int n);
    
    /**
        Dismiss the expanded panel of the currently active page.
        
        Calls and returns the value fromwxRibbonPage::DismissExpandedPanel()
        for the currently active page, or @false if there is no active page.
    */
    bool DismissExpandedPanel();
    
    /**
        Perform initial layout and size calculations of the bar and its
        children. This must be called after all of the bar's children have been
        created (and their children created, etc.) - if it is not, then windows
        may not be laid out or sized correctly.
        
        Also calls wxRibbonPage::Realize() on each child page.
    */
    virtual bool Realize();
};
