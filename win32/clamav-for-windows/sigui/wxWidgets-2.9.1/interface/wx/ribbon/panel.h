///////////////////////////////////////////////////////////////////////////////
// Name:        ribbon/panel.h
// Purpose:     interface of wxRibbonPage
// Author:      Peter Cawley
// RCS-ID:      $Id$
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

/**
    @class wxRibbonPanel

    Serves as a container for a group of (ribbon) controls. A wxRibbonPage will
    typically have panels for children, with the controls for that page placed
    on the panels.
    
    A panel adds a border and label to a group of controls, and can be
    minimised (either automatically to conserve space, or manually by the user).
    
    @sa wxRibbonPage
    
    @beginStyleTable
    @style{wxRIBBON_PANEL_DEFAULT_STYLE}
        Defined as no other flags set.
    @style{wxRIBBON_PANEL_NO_AUTO_MINIMISE}
        Prevents the panel from automatically minimising to conserve screen
        space.
    @style{wxRIBBON_PANEL_EXT_BUTTON}
        Causes an extension button to be shown in the panel's chrome (if the
        bar in which it is contained has wxRIBBON_BAR_SHOW_PANEL_EXT_BUTTONS
        set). The behaviour of this button is application controlled, but
        typically will show an extended drop-down menu relating to the
        panel.
    @style{wxRIBBON_PANEL_MINIMISE_BUTTON}
        Causes a (de)minimise button to be shown in the panel's chrome (if
        the bar in which it is contained has the
        wxRIBBON_BAR_SHOW_PANEL_MINIMISE_BUTTONS style set). This flag is
        typically combined with wxRIBBON_PANEL_NO_AUTO_MINIMISE to make a
        panel which the user always has manual control over when it
        minimises.
    @endStyleTable

    @library{wxribbon}
    @category{ribbon}
*/
class wxRibbonPanel : public wxRibbonControl
{
public:
    /**
        Default constructor. 
        With this constructor, Create() should be called in order to create
        the ribbon panel.
    */
    wxRibbonPanel();

    /**
        Constructs a ribbon panel.
    
        @param parent
            Pointer to a parent window, which is typically a wxRibbonPage,
            though it can be any window.
        @param id
            Window identifier.
        @param label
            Label to be used in the wxRibbonPanel's chrome.
        @param minimised_icon
            Icon to be used in place of the panel's children when the panel
            is minimised.
        @param pos
            The initial position of the panel. Not relevant when the parent is
            a ribbon page, as the position and size of the panel will be
            dictated by the page.
        @param size
            The initial size of the panel. Not relevant when the parent is a
            ribbon page, as the position and size of the panel will be
            dictated by the page.
        @param style
            Style flags for the panel.
    */
    wxRibbonPanel(wxWindow* parent,
                  wxWindowID id = wxID_ANY,
                  const wxString& label = wxEmptyString,
                  const wxBitmap& minimised_icon = wxNullBitmap,
                  const wxPoint& pos = wxDefaultPosition,
                  const wxSize& size = wxDefaultSize,
                  long style = wxRIBBON_PANEL_DEFAULT_STYLE);
    
    /**
        Create a ribbon panel in two-step ribbon panel construction.
        Should only be called when the default constructor is used, and
        arguments have the same meaning as in the full constructor.
    */
    bool Create(wxWindow* parent,
                wxWindowID id = wxID_ANY,
                const wxString& label = wxEmptyString,
                const wxBitmap& icon = wxNullBitmap,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxRIBBON_PANEL_DEFAULT_STYLE);

    /**
        Destructor.
    */
    virtual ~wxRibbonPanel();

    /**
        Get the bitmap to be used in place of the panel children when it is
        minimised.
    */
    wxBitmap& GetMinimisedIcon();
    const wxBitmap& GetMinimisedIcon() const;
    
    /**
        Query if the panel is currently minimised.
    */
    bool IsMinimised() const;
    
    /**
        Query if the panel would be minimised at a given size.
    */
    bool IsMinimised(wxSize at_size) const;
    
    /**
        Query is the mouse is currently hovered over the panel.
        @return @true if the cursor is within the bounds of the panel (i.e.
            hovered over the panel or one of its children), @false otherwise.
    */
    bool IsHovered() const;
    
    /**
        Query if the panel can automatically minimise itself at small sizes.
    */
    bool CanAutoMinimise() const;
    
    /**
        Show the panel externally expanded.
        
        When a panel is minimised, it can be shown full-size in a pop-out
        window, which is refered to as being (externally) expanded. Note that
        when a panel is expanded, there exist two panels - the original panel
        (which is refered to as the dummy panel) and the expanded panel. The
        original is termed a dummy as it sits in the ribbon bar doing nothing,
        while the expanded panel holds the panel children.
        
        @return @true if the panel was expanded, @false if it was not (possibly
            due to it not being minimised, or already being expanded).
            
        @see HideExpanded()
        @see GetExpandedPanel()
    */
    bool ShowExpanded();
    
    /**
        Hide the panel's external expansion.
        
        @return @true if the panel was un-expanded, @false if it was not
            (normally due to it not being expanded in the first place).
        
        @see HideExpanded()
        @see GetExpandedPanel()
    */
    bool HideExpanded();

    /**
        Set the art provider to be used. Normally called automatically by
        wxRibbonPage when the panel is created, or the art provider changed on the
        page.
    
        The new art provider will be propagated to the children of the panel.
    */
    void SetArtProvider(wxRibbonArtProvider* art);
    
    /**
        Realize all children of the panel.
    */
    bool Realize();
    
    /**
        Get the dummy panel of an expanded panel.
        
        Note that this should be called on an expanded panel to get the dummy
        associated with it - it will return NULL when called on the dummy
        itself.
        
        @see ShowExpanded()
        @see GetExpandedPanel()
    */
    wxRibbonPanel* GetExpandedDummy();
    
    /**
        Get the expanded panel of a dummy panel.
        
        Note that this should be called on a dummy panel to get the expanded
        panel associated with it - it will return NULL when called on the
        expanded panel itself.
        
        @see ShowExpanded()
        @see GetExpandedDummy()
    */
    wxRibbonPanel* GetExpandedPanel();
};
