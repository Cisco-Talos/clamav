///////////////////////////////////////////////////////////////////////////////
// Name:        ribbon/toolbar.h
// Purpose:     interface of wxRibbonToolBar
// Author:      Peter Cawley
// RCS-ID:      $Id$
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

/**
    @class wxRibbonToolBar
    
    A ribbon tool bar is similar to a traditional toolbar which has no labels.
    It contains one or more tool groups, each of which contains one or more
    tools. Each tool is represented by a (generally small, i.e. 16x15) bitmap.
    
    @beginEventEmissionTable{wxRibbonToolBarEvent}
    @event{EVT_RIBBONTOOLBAR_CLICKED(id, func)}
        Triggered when the normal (non-dropdown) region of a tool on the tool
        bar is clicked.
    @event{EVT_RIBBONTOOLBAR_DROPDOWN_CLICKED(id, func)}
        Triggered when the dropdown region of a tool on the tool bar is
        clicked. wxRibbonToolBarEvent::PopupMenu() should be called by the
        event handler if it wants to display a popup menu (which is what most
        dropdown tools should be doing).
    @endEventTable
    
    @library{wxribbon}
    @category{ribbon}
*/
class wxRibbonToolBar : public wxRibbonControl
{
public:
    /**
        Default constructor.
        With this constructor, Create() should be called in order to create
        the tool bar.
    */
    wxRibbonToolBar();

    /**
        Construct a ribbon tool bar with the given parameters.
        
        @param parent
            Parent window for the tool bar (typically a wxRibbonPanel).
        @param id
            An identifier for the toolbar. @c wxID_ANY is taken to mean a default.
        @param pos
            Initial position of the tool bar.
        @param size
            Initial size of the tool bar.
        @param style
            Tool bar style, currently unused.
    */
    wxRibbonToolBar(wxWindow* parent,
                  wxWindowID id = wxID_ANY,
                  const wxPoint& pos = wxDefaultPosition,
                  const wxSize& size = wxDefaultSize,
                  long style = 0);

    /**
        Destructor.
    */
    virtual ~wxRibbonToolBar();

    /**
        Create a tool bar in two-step tool bar construction.
        Should only be called when the default constructor is used, and
        arguments have the same meaning as in the full constructor.
    */
    bool Create(wxWindow* parent,
                wxWindowID id = wxID_ANY,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0);

    /**
        Add a tool to the tool bar (simple version).
    */
    virtual wxRibbonToolBarToolBase* AddTool(
                int tool_id,
                const wxBitmap& bitmap,
                const wxString& help_string,
                wxRibbonButtonKind kind = wxRIBBON_BUTTON_NORMAL);

    /**
        Add a dropdown tool to the tool bar (simple version).
        
        @see AddTool()
    */
    virtual wxRibbonToolBarToolBase* AddDropdownTool(
                int tool_id,
                const wxBitmap& bitmap,
                const wxString& help_string = wxEmptyString);

    /**
        Add a hybrid tool to the tool bar (simple version).
        
        @see AddTool()
    */
    virtual wxRibbonToolBarToolBase* AddHybridTool(
                int tool_id,
                const wxBitmap& bitmap,
                const wxString& help_string = wxEmptyString);

    /**
        Add a tool to the tool bar.
        
        @param tool_id
            ID of the new tool (used for event callbacks).
        @param bitmap
            Bitmap to use as the foreground for the new tool. Does not have
            to be the same size as other tool bitmaps, but should be similar
            as otherwise it will look visually odd.
        @param bitmap_disabled
            Bitmap to use when the tool is disabled. If left as wxNullBitmap,
            then a bitmap will be automatically generated from @a bitmap.
        @param help_string
            The UI help string to associate with the new tool.
        @param kind
            The kind of tool to add.
        @param client_data
            Client data to associate with the new tool.
        
        @return An opaque pointer which can be used only with other tool bar
            methods.
            
        @see AddDropdownTool(), AddHybridTool(), AddSeparator()
    */
    virtual wxRibbonToolBarToolBase* AddTool(
                int tool_id,
                const wxBitmap& bitmap,
                const wxBitmap& bitmap_disabled = wxNullBitmap,
                const wxString& help_string = wxEmptyString,
                wxRibbonButtonKind kind = wxRIBBON_BUTTON_NORMAL,
                wxObject* client_data = NULL);

    /**
        Add a separator to the tool bar.
        
        Separators are used to separate tools into groups. As such, a separator
        is not explicity drawn, but is visually seen as the gap between tool
        groups.
    */
    virtual wxRibbonToolBarToolBase* AddSeparator();

    /**
        Set the number of rows to distribute tool groups over.
        
        Tool groups can be distributed over a variable number of rows. The way
        in which groups are assigned to rows is not specificed, and the order
        of groups may change, but they will be distributed in such a way as to
        minimise the overall size of the tool bar.
        
        @param nMin
            The minimum number of rows to use.
        @param nMax
            The maximum number of rows to use (defaults to nMin).
    */
    virtual void SetRows(int nMin, int nMax = -1);
};
