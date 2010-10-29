/////////////////////////////////////////////////////////////////////////////
// Name:        propgrid.h
// Purpose:     interface of wxPropertyGrid
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


/**
    @section propgrid_window_styles wxPropertyGrid Window Styles

    SetWindowStyleFlag method can be used to modify some of these at run-time.
    @{
*/
enum wxPG_WINDOW_STYLES
{

/**
    This will cause Sort() automatically after an item is added.
    When inserting a lot of items in this mode, it may make sense to
    use Freeze() before operations and Thaw() afterwards to increase
    performance.
*/
wxPG_AUTO_SORT                      = 0x00000010,

/**
    Categories are not initially shown (even if added).
    IMPORTANT NOTE: If you do not plan to use categories, then this
    style will waste resources.
    This flag can also be changed using wxPropertyGrid::EnableCategories method.
*/
wxPG_HIDE_CATEGORIES                = 0x00000020,

/**
    This style combines non-categoric mode and automatic sorting.
*/
wxPG_ALPHABETIC_MODE                = (wxPG_HIDE_CATEGORIES|wxPG_AUTO_SORT),

/**
    Modified values are shown in bold font. Changing this requires Refresh()
    to show changes.
*/
wxPG_BOLD_MODIFIED                  = 0x00000040,

/**
    When wxPropertyGrid is resized, splitter moves to the center. This
    behavior stops once the user manually moves the splitter.
*/
wxPG_SPLITTER_AUTO_CENTER           = 0x00000080,

/**
    Display tool tips for cell text that cannot be shown completely. If
    wxUSE_TOOLTIPS is 0, then this doesn't have any effect.
*/
wxPG_TOOLTIPS                       = 0x00000100,

/**
    Disables margin and hides all expand/collapse buttons that would appear
    outside the margin (for sub-properties). Toggling this style automatically
    expands all collapsed items.
*/
wxPG_HIDE_MARGIN                    = 0x00000200,

/**
    This style prevents user from moving the splitter.
*/
wxPG_STATIC_SPLITTER                = 0x00000400,

/**
    Combination of other styles that make it impossible for user to modify
    the layout.
*/
wxPG_STATIC_LAYOUT                  = (wxPG_HIDE_MARGIN|wxPG_STATIC_SPLITTER),

/**
    Disables wxTextCtrl based editors for properties which
    can be edited in another way. Equals calling
    wxPropertyGrid::LimitPropertyEditing() for all added properties.
*/
wxPG_LIMITED_EDITING                = 0x00000800,

/**
    wxPropertyGridManager only: Show tool bar for mode and page selection.
*/
wxPG_TOOLBAR                        = 0x00001000,

/**
    wxPropertyGridManager only: Show adjustable text box showing description
    or help text, if available, for currently selected property.
*/
wxPG_DESCRIPTION                    = 0x00002000,

/** wxPropertyGridManager only: don't show an internal border around the
    property grid. Recommended if you use a header.
*/
wxPG_NO_INTERNAL_BORDER             = 0x00004000

};

enum wxPG_EX_WINDOW_STYLES
{

/**
    NOTE: wxPG_EX_xxx are extra window styles and must be set using SetExtraStyle()
    member function.

    Speeds up switching to wxPG_HIDE_CATEGORIES mode. Initially, if
    wxPG_HIDE_CATEGORIES is not defined, the non-categorized data storage is not
    activated, and switching the mode first time becomes somewhat slower.
    wxPG_EX_INIT_NOCAT activates the non-categorized data storage right away.

    NOTE: If you do plan not switching to non-categoric mode, or if
    you don't plan to use categories at all, then using this style will result
    in waste of resources.
*/
wxPG_EX_INIT_NOCAT                  = 0x00001000,

/**
    Extended window style that sets wxPropertyGridManager tool bar to not
    use flat style.
*/
wxPG_EX_NO_FLAT_TOOLBAR             = 0x00002000,

/**
    Shows alphabetic/categoric mode buttons from tool bar.
*/
wxPG_EX_MODE_BUTTONS                = 0x00008000,

/**
    Show property help strings as tool tips instead as text on the status bar.
    You can set the help strings using SetPropertyHelpString member function.
*/
wxPG_EX_HELP_AS_TOOLTIPS            = 0x00010000,

/**
    Allows relying on native double-buffering.
*/
wxPG_EX_NATIVE_DOUBLE_BUFFERING         = 0x00080000,

/**
    Set this style to let user have ability to set values of properties to
    unspecified state. Same as setting wxPG_PROP_AUTO_UNSPECIFIED for
    all properties.
*/
wxPG_EX_AUTO_UNSPECIFIED_VALUES         = 0x00200000,

/**
    If this style is used, built-in attributes (such as wxPG_FLOAT_PRECISION and
    wxPG_STRING_PASSWORD) are not stored into property's attribute storage (thus
    they are not readable).

    Note that this option is global, and applies to all wxPG property containers.
*/
wxPG_EX_WRITEONLY_BUILTIN_ATTRIBUTES    = 0x00400000,

/**
    Hides page selection buttons from tool bar.
*/
wxPG_EX_HIDE_PAGE_BUTTONS               = 0x01000000,

/** Allows multiple properties to be selected by user (by pressing SHIFT
    when clicking on a property, or by dragging with left mouse button
    down).

    You can get array of selected properties with
    wxPropertyGridInterface::GetSelectedProperties(). In multiple selection
    mode wxPropertyGridInterface::GetSelection() returns
    property which has editor active (usually the first one
    selected). Other useful member functions are ClearSelection(),
    AddToSelection() and RemoveFromSelection().
*/
wxPG_EX_MULTIPLE_SELECTION              = 0x02000000,

/**
    This enables top-level window tracking which allows wxPropertyGrid to
    notify the application of last-minute property value changes by user.

    This style is not enabled by default because it may cause crashes when
    wxPropertyGrid is used in with wxAUI or similar system.

    @remarks If you are not in fact using any system that may change
             wxPropertyGrid's top-level parent window on its own, then you
             are recommended to enable this style.
*/
wxPG_EX_ENABLE_TLP_TRACKING             = 0x04000000,

/** Don't show divider above toolbar, on Windows.
*/
wxPG_EX_NO_TOOLBAR_DIVIDER              = 0x04000000,

/** Show a separator below the toolbar.
*/
wxPG_EX_TOOLBAR_SEPARATOR               = 0x08000000

};

/** Combines various styles.
*/
#define wxPG_DEFAULT_STYLE          (0)

/** Combines various styles.
*/
#define wxPGMAN_DEFAULT_STYLE       (0)

/** @}
*/

// -----------------------------------------------------------------------

/**
    @section propgrid_vfbflags wxPropertyGrid Validation Failure Behavior Flags
    @{
*/

enum wxPG_VALIDATION_FAILURE_BEHAVIOR_FLAGS
{

/**
    Prevents user from leaving property unless value is valid. If this
    behavior flag is not used, then value change is instead cancelled.
*/
wxPG_VFB_STAY_IN_PROPERTY           = 0x01,

/**
    Calls wxBell() on validation failure.
*/
wxPG_VFB_BEEP                       = 0x02,

/**
    Cell with invalid value will be marked (with red colour).
*/
wxPG_VFB_MARK_CELL                  = 0x04,

/**
    Display a text message explaining the situation. 

    To customize the way the message is displayed, you need to
    reimplement wxPropertyGrid::DoShowPropertyError() in a
    derived class. Default behavior is to display the text on
    the top-level frame's status bar, if present, and otherwise
    using wxMessageBox.
*/
wxPG_VFB_SHOW_MESSAGE               = 0x08,

/**
    Similar to wxPG_VFB_SHOW_MESSAGE, except always displays the
    message using wxMessageBox.
*/
wxPG_VFB_SHOW_MESSAGEBOX            = 0x10,

/**
    Similar to wxPG_VFB_SHOW_MESSAGE, except always displays the
    message on the status bar (when present - you can reimplement
    wxPropertyGrid::GetStatusBar() in a derived class to specify
    this yourself).
*/
wxPG_VFB_SHOW_MESSAGE_ON_STATUSBAR  = 0x20,

/**
    Defaults.
*/
wxPG_VFB_DEFAULT                    = wxPG_VFB_MARK_CELL |
                                      wxPG_VFB_SHOW_MESSAGEBOX,
};

/** @}
*/

typedef wxByte wxPGVFBFlags;

/**
    wxPGValidationInfo

    Used to convey validation information to and from functions that
    actually perform validation. Mostly used in custom property classes.
*/
class wxPGValidationInfo
{
public:
    /**
        @return Returns failure behavior which is a combination of
            @ref propgrid_vfbflags.
    */
    wxPGVFBFlags GetFailureBehavior();

    /**
        Returns current failure message.
    */
    const wxString& GetFailureMessage() const;

    /**
        Returns reference to pending value.
    */
    wxVariant& GetValue();

    /** Set validation failure behavior

        @param failureBehavior
            Mixture of @ref propgrid_vfbflags.
    */
    void SetFailureBehavior(wxPGVFBFlags failureBehavior);

    /**
        Set current failure message.
    */
    void SetFailureMessage(const wxString& message);
};

// -----------------------------------------------------------------------

/**
    @section propgrid_keyboard_actions wxPropertyGrid Action Identifiers

    These are used with wxPropertyGrid::AddActionTrigger() and
    wxPropertyGrid::ClearActionTriggers().
    @{
*/

enum wxPG_KEYBOARD_ACTIONS
{
    wxPG_ACTION_INVALID = 0,
    wxPG_ACTION_NEXT_PROPERTY,
    wxPG_ACTION_PREV_PROPERTY,
    wxPG_ACTION_EXPAND_PROPERTY,
    wxPG_ACTION_COLLAPSE_PROPERTY,
    wxPG_ACTION_CANCEL_EDIT,
    wxPG_ACTION_MAX
};

/** @}
*/

/** This callback function is used for sorting properties.

    Call wxPropertyGrid::SetSortFunction() to set it.

    Sort function should return a value greater than 0 if position of p1 is
    after p2. So, for instance, when comparing property names, you can use
    following implementation:

        @code
            int MyPropertySortFunction(wxPropertyGrid* propGrid,
                                       wxPGProperty* p1,
                                       wxPGProperty* p2)
            {
                return p1->GetBaseName().compare( p2->GetBaseName() );
            }
        @endcode
*/
typedef int (*wxPGSortCallback)(wxPropertyGrid* propGrid,
                                wxPGProperty* p1,
                                wxPGProperty* p2);

// -----------------------------------------------------------------------

/**
    @class wxPropertyGrid

    wxPropertyGrid is a specialized grid for editing properties - in other
    words name = value pairs. List of ready-to-use property classes include
    strings, numbers, flag sets, fonts, colours and many others. It is possible,
    for example, to categorize properties, set up a complete tree-hierarchy,
    add more than two columns, and set arbitrary per-property attributes.

    Please note that most member functions are inherited and as such not
    documented on this page. This means you will probably also want to read
    wxPropertyGridInterface class reference.

    See also @ref overview_propgrid.

    @section propgrid_window_styles_ Window Styles

    See @ref propgrid_window_styles.

    @section propgrid_event_handling Event Handling

    To process input from a property grid control, use these event handler macros
    to direct input to member functions that take a wxPropertyGridEvent argument.

    @beginEventEmissionTable{wxPropertyGridEvent}
    @event{EVT_PG_SELECTED (id, func)}
        Respond to wxEVT_PG_SELECTED event, generated when a property selection
        has been changed, either by user action or by indirect program
        function. For instance, collapsing a parent property programmatically
        causes any selected child property to become unselected, and may
        therefore cause this event to be generated.
    @event{EVT_PG_CHANGED(id, func)}
        Respond to wxEVT_PG_CHANGED event, generated when property value
        has been changed by the user.
    @event{EVT_PG_CHANGING(id, func)}
        Respond to wxEVT_PG_CHANGING event, generated when property value
        is about to be changed by user. Use wxPropertyGridEvent::GetValue()
        to take a peek at the pending value, and wxPropertyGridEvent::Veto()
        to prevent change from taking place, if necessary.
    @event{EVT_PG_HIGHLIGHTED(id, func)}
        Respond to wxEVT_PG_HIGHLIGHTED event, which occurs when mouse
        moves over a property. Event's property is NULL if hovered area does
        not belong to any property.
    @event{EVT_PG_RIGHT_CLICK(id, func)}
        Respond to wxEVT_PG_RIGHT_CLICK event, which occurs when property is
        clicked on with right mouse button.
    @event{EVT_PG_DOUBLE_CLICK(id, func)}
        Respond to wxEVT_PG_DOUBLE_CLICK event, which occurs when property is
        double-clicked on with left mouse button.
    @event{EVT_PG_ITEM_COLLAPSED(id, func)}
        Respond to wxEVT_PG_ITEM_COLLAPSED event, generated when user collapses
        a property or category.
    @event{EVT_PG_ITEM_EXPANDED(id, func)}
        Respond to wxEVT_PG_ITEM_EXPANDED event, generated when user expands
        a property or category.
    @event{EVT_PG_LABEL_EDIT_BEGIN(id, func)}
        Respond to wxEVT_PG_LABEL_EDIT_BEGIN event, generated when user is
        about to begin editing a property label. You can veto this event to
        prevent the action.
    @event{EVT_PG_LABEL_EDIT_ENDING(id, func)}
        Respond to wxEVT_PG_LABEL_EDIT_ENDING event, generated when user is
        about to end editing of a property label. You can veto this event to
        prevent the action.
    @event{EVT_PG_COL_BEGIN_DRAG(id, func)}
        Respond to wxEVT_PG_COL_BEGIN_DRAG event, generated when user
        starts resizing a column - can be vetoed.
    @event{EVT_PG_COL_DRAGGING,(id, func)}
        Respond to wxEVT_PG_COL_DRAGGING, event, generated when a
        column resize by user is in progress. This event is also generated
        when user double-clicks the splitter in order to recenter
        it.
    @event{EVT_PG_COL_END_DRAG(id, func)}
        Respond to wxEVT_PG_COL_END_DRAG event, generated after column
        resize by user has finished.
    @endEventTable

    @remarks
    Use Freeze() and Thaw() respectively to disable and enable drawing.
    This will also delay sorting etc. miscellaneous calculations to the last
    possible moment.

    @library{wxpropgrid}
    @category{propgrid}
    @appearance{propertygrid.png}
*/
class wxPropertyGrid : public wxScrolledWindow, public wxPropertyGridInterface
{
public:
    /**
        Two step constructor.
        Call Create() when this constructor is called to build up the wxPropertyGrid
    */
    wxPropertyGrid();

    /**
        Constructor.
        The styles to be used are styles valid for the wxWindow and wxScrolledWindow.

        @see @ref propgrid_window_styles.
    */
    wxPropertyGrid( wxWindow *parent, wxWindowID id = wxID_ANY,
                    const wxPoint& pos = wxDefaultPosition,
                    const wxSize& size = wxDefaultSize,
                    long style = wxPG_DEFAULT_STYLE,
                    const wxChar* name = wxPropertyGridNameStr );

    /** Destructor */
    virtual ~wxPropertyGrid();

    /**
        Adds given key combination to trigger given action.

        Here is a sample code to make Enter key press move focus to
        the next property.

        @code
            propGrid->AddActionTrigger(wxPG_ACTION_NEXT_PROPERTY,
                                       WXK_RETURN);
            propGrid->DedicateKey(WXK_RETURN);
        @endcode

        @param action
            Which action to trigger. See @ref propgrid_keyboard_actions.
        @param keycode
            Which keycode triggers the action.
        @param modifiers
            Which key event modifiers, in addition to keycode, are needed to
            trigger the action.
    */
    void AddActionTrigger( int action, int keycode, int modifiers = 0 );

    /**
        Adds given property into selection. If wxPG_EX_MULTIPLE_SELECTION
        extra style is not used, then this has same effect as
        calling SelectProperty().

        @remarks Multiple selection is not supported for categories. This
                 means that if you have properties selected, you cannot
                 add category to selection, and also if you have category
                 selected, you cannot add other properties to selection.
                 This member function will fail silently in these cases,
                 even returning true.
    */
    bool AddToSelection( wxPGPropArg id );

    /**
        This static function enables or disables automatic use of
        wxGetTranslation() for following strings: wxEnumProperty list labels,
        wxFlagsProperty child property labels.

        Default is false.
    */
    static void AutoGetTranslation( bool enable );

    /**
        Creates label editor wxTextCtrl for given column, for property
        that is currently selected. When multiple selection is
        enabled, this applies to whatever property GetSelection()
        returns.

        @param colIndex
            Which column's label to edit. Note that you should not
            use value 1, which is reserved for property value
            column.

        @see EndLabelEdit(), MakeColumnEditable()
    */
    void BeginLabelEdit( unsigned int colIndex = 0 );

    /**
        Changes value of a property, as if from an editor. Use this instead of
        SetPropertyValue() if you need the value to run through validation
        process, and also send the property change event.

        @return Returns true if value was successfully changed.
    */
    bool ChangePropertyValue( wxPGPropArg id, wxVariant newValue );

    /**
        Centers the splitter.

        @param enableAutoResizing
            If @true, automatic column resizing is enabled (only applicapple
            if window style wxPG_SPLITTER_AUTO_CENTER is used).
    */
    void CenterSplitter( bool enableAutoResizing = false );

    /**
        Deletes all properties.
    */
    virtual void Clear();

    /**
        Clears action triggers for given action.

        @param action
            Which action to trigger. @ref propgrid_keyboard_actions.
    */
    void ClearActionTriggers( int action );

    /**
        Forces updating the value of property from the editor control.
        Note that wxEVT_PG_CHANGING and wxEVT_PG_CHANGED are dispatched using
        ProcessEvent, meaning your event handlers will be called immediately.

        @return Returns @true if anything was changed.
    */
    virtual bool CommitChangesFromEditor( wxUint32 flags = 0 );

    /**
        Two step creation. Whenever the control is created without any
        parameters, use Create to actually create it. Don't access the control's
        public methods before this is called

        @see @ref propgrid_window_styles.
    */
    bool Create( wxWindow *parent, wxWindowID id = wxID_ANY,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxPG_DEFAULT_STYLE,
                const wxChar* name = wxPropertyGridNameStr );

    /**
        Dedicates a specific keycode to wxPropertyGrid. This means that such
        key presses will not be redirected to editor controls.

        Using this function allows, for example, navigation between
        properties using arrow keys even when the focus is in the editor
        control.
    */
    void DedicateKey( int keycode );

    /**
        Enables or disables (shows/hides) categories according to parameter
        enable.

        @remarks This functions deselects selected property, if any. Validation
                failure option wxPG_VFB_STAY_IN_PROPERTY is not respected, ie.
                selection is cleared even if editor had invalid value.
    */
    bool EnableCategories( bool enable );

    /**
        Destroys label editor wxTextCtrl, if any.

        @param commit
            Use @true (default) to store edited label text in
            property cell data.

        @see BeginLabelEdit(), MakeColumnEditable()
    */
    void EndLabelEdit( bool commit = true );

    /**
        Scrolls and/or expands items to ensure that the given item is visible.

        @return Returns @true if something was actually done.
    */
    bool EnsureVisible( wxPGPropArg id );

    /**
        Reduces column sizes to minimum possible, while still retaining
        fully visible grid contents (labels, images).

        @return Minimum size for the grid to still display everything.

        @remarks Does not work well with wxPG_SPLITTER_AUTO_CENTER window style.

                This function only works properly if grid size prior to call was
                already fairly large.

                Note that you can also get calculated column widths by calling
                GetState->GetColumnWidth() immediately after this function
                returns.
    */
    wxSize FitColumns();

    /**
        Returns currently active label editor, NULL if none.
    */
    wxTextCtrl* GetLabelEditor() const;

    /**
        Returns wxWindow that the properties are painted on, and which should be
        used as the parent for editor controls.
    */
    wxWindow* GetPanel();

    /**
        Returns current category caption background colour.
    */
    wxColour GetCaptionBackgroundColour() const;

    /**
        Returns current category caption font.
    */
    wxFont& GetCaptionFont();

    /**
        Returns current category caption text colour.
    */
    wxColour GetCaptionForegroundColour() const;

    /**
        Returns current cell background colour.
    */
    wxColour GetCellBackgroundColour() const;

    /**
        Returns current cell text colour when disabled.
    */
    wxColour GetCellDisabledTextColour() const;

    /**
        Returns current cell text colour.
    */
    wxColour GetCellTextColour() const;

    /**
        Returns number of columns currently on grid.
    */
    unsigned int GetColumnCount() const;

    /**
        Returns colour of empty space below properties.
    */
    wxColour GetEmptySpaceColour() const;

    /**
        Returns height of highest characters of used font.
    */
    int GetFontHeight() const;

    /**
        Returns pointer to itself. Dummy function that enables same kind
        of code to use wxPropertyGrid and wxPropertyGridManager.
    */
    wxPropertyGrid* GetGrid();

    /**
        Returns rectangle of custom paint image.

        @param property
            Return image rectangle for this property.

        @param item
            Which choice of property to use (each choice may have
            different image).
    */
    wxRect GetImageRect( wxPGProperty* property, int item ) const;

    /**
        Returns size of the custom paint image in front of property.

        @param property
            Return image rectangle for this property.
            If this argument is NULL, then preferred size is returned.

        @param item
            Which choice of property to use (each choice may have
            different image).
    */
    wxSize GetImageSize( wxPGProperty* property = NULL, int item = -1 ) const;

    /**
        Returns last item which could be iterated using given flags.

        @param flags
            See @ref propgrid_iterator_flags.
    */
    wxPGProperty* GetLastItem( int flags = wxPG_ITERATE_DEFAULT );

    /**
        Returns colour of lines between cells.
    */
    wxColour GetLineColour() const;

    /**
        Returns background colour of margin.
    */
    wxColour GetMarginColour() const;

    /**
        Returns "root property". It does not have name, etc. and it is not
        visible. It is only useful for accessing its children.
    */
    wxPGProperty* GetRoot() const;

    /**
        Returns height of a single grid row (in pixels).
    */
    int GetRowHeight() const;

    /**
        Returns currently selected property.
    */
    wxPGProperty* GetSelectedProperty() const;

    /**
        Returns currently selected property.
    */
    wxPGProperty* GetSelection() const;

    /**
        Returns current selection background colour.
    */
    wxColour GetSelectionBackgroundColour() const;

    /**
        Returns current selection text colour.
    */
    wxColour GetSelectionForegroundColour() const;

    /**
        Returns the property sort function (default is @NULL).

        @see SetSortFunction
    */
    wxPGSortCallback GetSortFunction() const;

    /**
        Returns current splitter x position.
    */
    int GetSplitterPosition( unsigned int splitterIndex = 0 ) const;

    /**
        Returns wxTextCtrl active in currently selected property, if any. Takes
        wxOwnerDrawnComboBox into account.
    */
    wxTextCtrl* GetEditorTextCtrl() const;

    /**
        Returns current appearance of unspecified value cells.

        @see SetUnspecifiedValueAppearance()
    */
    const wxPGCell& GetUnspecifiedValueAppearance() const;

    /**
        Returns (visual) text representation of the unspecified
        property value.

        @param argFlags For internal use only.
    */
    wxString GetUnspecifiedValueText( int argFlags = 0 ) const;

    /**
        Returns current vertical spacing.
    */
    int GetVerticalSpacing() const;

    /**
        Returns information about arbitrary position in the grid.

        @param pt
            Coordinates in the virtual grid space. You may need to use
            wxScrolledWindow::CalcScrolledPosition() for translating
            wxPropertyGrid client coordinates into something this member
            function can use.
    */
    wxPropertyGridHitTestResult HitTest( const wxPoint& pt ) const;

    /**
        Returns true if any property has been modified by the user.
    */
    bool IsAnyModified() const;

    /**
        Returns @true if a property editor control has focus.
    */
    bool IsEditorFocused() const;

    /**
        Returns true if updating is frozen (ie. Freeze() called but not
        yet Thaw() ).
    */
    bool IsFrozen() const;

    /**
        Makes given column editable by user.

        @param column
            The index of the column to make editable.
        @param editable
            Using @false here will disable column from being editable.

        @see BeginLabelEdit(), EndLabelEdit()
    */
    void MakeColumnEditable( unsigned int column, bool editable = true );

    /**
        It is recommended that you call this function any time your code causes
        wxPropertyGrid's top-level parent to change. wxPropertyGrid's OnIdle()
        handler should be able to detect most changes, but it is not perfect.

        @param newTLP
            New top-level parent that is about to be set. Old top-level parent
            window should still exist as the current one.

        @remarks This function is automatically called from wxPropertyGrid::
                 Reparent() and wxPropertyGridManager::Reparent(). You only
                 need to use it if you reparent wxPropertyGrid indirectly.
    */
    void OnTLPChanging( wxWindow* newTLP );

    /**
        Refreshes any active editor control.
    */
    void RefreshEditor();

    /**
        Redraws given property.
    */
    virtual void RefreshProperty( wxPGProperty* p );

    /**
        Registers a new editor class.

        @return Returns pointer  to the editor class instance that should be used.
    */
    static wxPGEditor* RegisterEditorClass( wxPGEditor* editor,
                                            const wxString& name,
                                            bool noDefCheck = false );

    /**
        Resets all colours to the original system values.
    */
    void ResetColours();

    /**
        Resets column sizes and splitter positions, based on proportions.

        @param enableAutoResizing
            If @true, automatic column resizing is enabled (only applicapple
            if window style wxPG_SPLITTER_AUTO_CENTER is used).

        @see wxPropertyGridInterface::SetColumnProportion()
    */
    void ResetColumnSizes( bool enableAutoResizing = false );

    /**
        Removes given property from selection. If property is not selected,
        an assertion failure will occur.
    */
    bool RemoveFromSelection( wxPGPropArg id );

    /**
        Selects a property. Editor widget is automatically created, but
        not focused unless focus is true.

        @param id
            Property to select (name or pointer).

        @param focus
            If @true, move keyboard focus to the created editor right away.

        @return returns @true if selection finished successfully. Usually only
        fails if current value in editor is not valid.

        @remarks In wxPropertyGrid 1.4, this member function used to generate
                 wxEVT_PG_SELECTED. In wxWidgets 2.9 and later, it no longer
                 does that.

        @remarks This clears any previous selection.

        @see wxPropertyGridInterface::ClearSelection()
    */
    bool SelectProperty( wxPGPropArg id, bool focus = false );

    /**
        Changes keyboard shortcut to push the editor button.

        @remarks You can set default with keycode 0. Good value for the platform
                is guessed, but don't expect it to be very accurate.
    */
    void SetButtonShortcut( int keycode, bool ctrlDown = false, bool altDown = false );

    /**
        Sets category caption background colour.
    */
    void SetCaptionBackgroundColour(const wxColour& col);

    /**
        Sets category caption text colour.
    */
    void SetCaptionTextColour(const wxColour& col);

    /**
        Sets default cell background colour - applies to property cells.
        Note that appearance of editor widgets may not be affected.
    */
    void SetCellBackgroundColour(const wxColour& col);

    /**
        Sets cell text colour for disabled properties.
    */
    void SetCellDisabledTextColour(const wxColour& col);

    /**
        Sets default cell text colour - applies to property name and value text.
        Note that appearance of editor widgets may not be affected.
    */
    void SetCellTextColour(const wxColour& col);

    /**
        Set number of columns (2 or more).
    */
    void SetColumnCount( int colCount );

    /**
        Sets the 'current' category - Append will add non-category properties
        under it.
    */
    void SetCurrentCategory( wxPGPropArg id );

    /**
        Sets colour of empty space below properties.
    */
    void SetEmptySpaceColour(const wxColour& col);

    /**
        Sets colour of lines between cells.
    */
    void SetLineColour(const wxColour& col);

    /**
        Sets background colour of margin.
    */
    void SetMarginColour(const wxColour& col);

    /**
        Set entire new selection from given list of properties.
    */
    void SetSelection( const wxArrayPGProperty& newSelection );

    /**
        Sets selection background colour - applies to selected property name
        background.
    */
    void SetSelectionBackgroundColour(const wxColour& col);

    /**
        Sets selection foreground colour - applies to selected property name text.
    */
    void SetSelectionTextColour(const wxColour& col);


    /**
        Sets the property sorting function.

        @param sortFunction
            The sorting function to be used. It should return a value greater
            than 0 if position of p1 is after p2. So, for instance, when
            comparing property names, you can use following implementation:

            @code
                int MyPropertySortFunction(wxPropertyGrid* propGrid,
                                           wxPGProperty* p1,
                                           wxPGProperty* p2)
                {
                    return p1->GetBaseName().compare( p2->GetBaseName() );
                }
            @endcode

        @remarks
            Default property sort function sorts properties by their labels
            (case-insensitively).

        @see GetSortFunction, wxPropertyGridInterface::Sort,
             wxPropertyGridInterface::SortChildren
    */
    void SetSortFunction( wxPGSortCallback sortFunction );

    /**
        Sets x coordinate of the splitter.

        @remarks Splitter position cannot exceed grid size, and therefore setting
                it during form creation may fail as initial grid size is often
                smaller than desired splitter position, especially when sizers
                are being used.
    */
    void SetSplitterPosition( int newxpos, int col = 0 );

    /**
        Moves splitter as left as possible, while still allowing all
        labels to be shown in full.

        @param privateChildrenToo
            If @false, will still allow private children to be cropped.
    */
    void SetSplitterLeft( bool privateChildrenToo = false );

    /**
        Sets appearance of value cells representing an unspecified property
        value. Default appearance is blank.

        @remarks If you set the unspecified value to have any
                 textual representation, then that will override
                 "InlineHelp" attribute.

        @see wxPGProperty::SetValueToUnspecified(),
             wxPGProperty::IsValueUnspecified()
    */
    void SetUnspecifiedValueAppearance( const wxPGCell& cell );

    /**
        Sets vertical spacing. Can be 1, 2, or 3 - a value relative to font
        height. Value of 2 should be default on most platforms.
    */
    void SetVerticalSpacing( int vspacing );

    /**
        @name wxPropertyGrid customization

        Reimplement these member functions in derived class for better
        control over wxPropertyGrid behavior.
    */
    //@{
    
    /**
        Override in derived class to display error messages in custom manner
        (these message usually only result from validation failure).

        @remarks If you implement this, then you also need to implement
                 DoHidePropertyError() - possibly to do nothing, if error
                 does not need hiding (e.g. it was logged or shown in a
                 message box).

        @see DoHidePropertyError()
    */
    virtual void DoShowPropertyError( wxPGProperty* property,
                                      const wxString& msg );

    /**
        Override in derived class to hide an error displayed by
        DoShowPropertyError().

        @see DoShowPropertyError()
    */
    virtual void DoHidePropertyError( wxPGProperty* property );

    /**
        Return wxStatusBar that is used by this wxPropertyGrid. You can
        reimplement this member function in derived class to override
        the default behavior of using the top-level wxFrame's status
        bar, if any.
    */
    virtual wxStatusBar* GetStatusBar();

    //@}

    /**
        @name Property development functions

        These member functions are usually only called when creating custom
        user properties.
    */
    //@{

    /**
        Call when editor widget's contents is modified. For example, this is
        called when changes text in wxTextCtrl (used in wxStringProperty and
        wxIntProperty).

        @remarks This function should only be called by custom properties.

        @see wxPGProperty::OnEvent()
    */
    void EditorsValueWasModified();

    /**
        Reverse of EditorsValueWasModified().

        @remarks This function should only be called by custom properties.
    */
    void EditorsValueWasNotModified();

    /**
        Returns most up-to-date value of selected property. This will return
        value different from GetSelectedProperty()->GetValue() only when text
        editor is activate and string edited by user represents valid,
        uncommitted property value.
    */
    wxVariant GetUncommittedPropertyValue();

    /**
        Returns true if editor's value was marked modified.
    */
    bool IsEditorsValueModified() const;

    /**
        Shows an brief error message that is related to a property.
    */
    void ShowPropertyError( wxPGPropArg id, const wxString& msg );

    /**
        You can use this member function, for instance, to detect in
        wxPGProperty::OnEvent() if wxPGProperty::SetValueInEvent() was
        already called in wxPGEditor::OnEvent(). It really only detects
        if was value was changed using wxPGProperty::SetValueInEvent(), which
        is usually used when a 'picker' dialog is displayed. If value was
        written by "normal means" in wxPGProperty::StringToValue() or
        IntToValue(), then this function will return false (on the other hand,
        wxPGProperty::OnEvent() is not even called in those cases).
    */
    bool WasValueChangedInEvent() const;

    //@}
};


/**
    @class wxPropertyGridEvent

    A property grid event holds information about events associated with
    wxPropertyGrid objects.

    @library{wxpropgrid}
    @category{propgrid}
*/
class wxPropertyGridEvent : public wxCommandEvent
{
public:

    /** Constructor. */
    wxPropertyGridEvent(wxEventType commandType=0, int id=0);

    /** Copy constructor. */
    wxPropertyGridEvent(const wxPropertyGridEvent& event);

    /** Destructor. */
    ~wxPropertyGridEvent();

    /**
        Returns true if you can veto the action that the event is signaling.
    */
    bool CanVeto() const;

    /**
        Returns the column index associated with this event.
        For the column dragging events, it is the column to the left
        of the splitter being dragged
    */
    unsigned int GetColumn() const;

    /**
        Returns highest level non-category, non-root parent of property for
        which event occurred. Useful when you have nested properties with
        children.

        @remarks If immediate parent is root or category, this will return the
                property itself.
    */
    wxPGProperty* GetMainParent() const;

    /**
        Returns property associated with this event.

        @remarks You should assume that this property can always be NULL.
                 For instance, wxEVT_PG_SELECTED is emitted not only when
                 a new property is selected, but also when selection is
                 cleared by user activity.
    */
    wxPGProperty* GetProperty() const;

    /**
        Returns current validation failure flags.
    */
    wxPGVFBFlags GetValidationFailureBehavior() const;

    /**
        Returns name of the associated property.

        @remarks Property name is stored in event, so it remains
                 accessible even after the associated property or
                 the property grid has been deleted.
    */
    wxString GetPropertyName() const;

    /**
        Returns value of the associated property. Works for all event
        types, but for wxEVT_PG_CHANGING this member function returns
        the value that is pending, so you can call Veto() if the
        value is not satisfactory.

        @remarks Property value is stored in event, so it remains
                 accessible even after the associated property or
                 the property grid has been deleted.
    */
    wxVariant GetPropertyValue() const

    /**
        @see GetPropertyValue()
    */
    wxVariant GetValue() const;

    /**
        Set if event can be vetoed.
    */
    void SetCanVeto( bool canVeto );

    /** Changes the property associated with this event. */
    void SetProperty( wxPGProperty* p );

    /**
        Set override validation failure behavior. Only effective if Veto() was
        also called, and only allowed if event type is wxEVT_PG_CHANGING.
    */
    void SetValidationFailureBehavior( wxPGVFBFlags flags );

    /**
        Sets custom failure message for this time only. Only applies if
        wxPG_VFB_SHOW_MESSAGE is set in validation failure flags.
    */
    void SetValidationFailureMessage( const wxString& message );

    /**
        Call this from your event handler to veto action that the event is
        signaling. You can only veto a shutdown if wxPropertyGridEvent::CanVeto()
        returns true.

        @remarks Currently only wxEVT_PG_CHANGING supports vetoing.
    */
    void Veto( bool veto = true );

    /**
        Returns @true if event was vetoed.
    */
    bool WasVetoed() const;
};
