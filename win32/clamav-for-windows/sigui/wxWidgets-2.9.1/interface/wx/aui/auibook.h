/////////////////////////////////////////////////////////////////////////////
// Name:        aui/auibook.h
// Purpose:     interface of wxAuiNotebook
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxAuiNotebook

    wxAuiNotebook is part of the wxAUI class framework.
    See also @ref overview_aui.

    wxAuiNotebook is a notebook control which implements many features common in
    applications with dockable panes.
    Specifically, wxAuiNotebook implements functionality which allows the user to
    rearrange tab order via drag-and-drop, split the tab window into many different
    splitter configurations, and toggle through different themes to customize
    the control's look and feel.

    An effort has been made to try to maintain an API as similar to that of
    wxNotebook (note that wxAuiNotebook does not derive from wxNotebook!).

    The default theme that is used is wxAuiDefaultTabArt, which provides a modern,
    glossy look and feel.
    The theme can be changed by calling wxAuiNotebook::SetArtProvider.

    @beginStyleTable
    @style{wxAUI_NB_DEFAULT_STYLE}
           Defined as wxAUI_NB_TOP | wxAUI_NB_TAB_SPLIT | wxAUI_NB_TAB_MOVE |
           wxAUI_NB_SCROLL_BUTTONS | wxAUI_NB_CLOSE_ON_ACTIVE_TAB.
    @style{wxAUI_NB_TAB_SPLIT}
           Allows the tab control to be split by dragging a tab.
    @style{wxAUI_NB_TAB_MOVE}
           Allows a tab to be moved horizontally by dragging.
    @style{wxAUI_NB_TAB_EXTERNAL_MOVE}
           Allows a tab to be moved to another tab control.
    @style{wxAUI_NB_TAB_FIXED_WIDTH}
           With this style, all tabs have the same width.
    @style{wxAUI_NB_SCROLL_BUTTONS}
           With this style, left and right scroll buttons are displayed.
    @style{wxAUI_NB_WINDOWLIST_BUTTON}
           With this style, a drop-down list of windows is available.
    @style{wxAUI_NB_CLOSE_BUTTON}
           With this style, a close button is available on the tab bar.
    @style{wxAUI_NB_CLOSE_ON_ACTIVE_TAB}
           With this style, the close button is visible on the active tab.
    @style{wxAUI_NB_CLOSE_ON_ALL_TABS}
           With this style, the close button is visible on all tabs.
    @style{wxAUI_NB_TOP}
           With this style, tabs are drawn along the top of the notebook.
    @style{wxAUI_NB_BOTTOM}
           With this style, tabs are drawn along the bottom of the notebook.
    @endStyleTable


    @beginEventEmissionTable{wxAuiNotebookEvent}
    @event{EVT_AUINOTEBOOK_PAGE_CLOSE(id, func)}
        Provide description.
    @event{EVT_AUINOTEBOOK_PAGE_CHANGED(id, func)}
        Provide description.
    @event{EVT_AUINOTEBOOK_PAGE_CHANGING(id, func)}
        Provide description.
    @event{EVT_AUINOTEBOOK_BUTTON(id, func)}
        Provide description.
    @event{EVT_AUINOTEBOOK_BEGIN_DRAG(id, func)}
        Provide description.
    @event{EVT_AUINOTEBOOK_END_DRAG(id, func)}
        Provide description.
    @event{EVT_AUINOTEBOOK_DRAG_MOTION(id, func)}
        Provide description.
    @event{EVT_AUINOTEBOOK_ALLOW_DND(id, func)}
        Provide description.
    @endEventTable

    @todo provide description for the events above.

    @library{wxaui}
    @category{aui}
*/
class wxAuiNotebook : public wxControl
{
public:
    /**
        Default ctor.
    */
    wxAuiNotebook();

    /**
        Constructor. Creates a wxAuiNotebok control.
    */
    wxAuiNotebook(wxWindow* parent, wxWindowID id = wxID_ANY,
                  const wxPoint& pos = wxDefaultPosition,
                  const wxSize& size = wxDefaultSize,
                  long style = wxAUI_NB_DEFAULT_STYLE);

    /**
        Adds a page.
        If the @a select parameter is @true, calling this will generate a page change event.
    */
    bool AddPage(wxWindow* page, const wxString& caption,
                 bool select = false,
                 const wxBitmap& bitmap = wxNullBitmap);

    /**
        Sets the selection to the next or previous page.
    */
    void AdvanceSelection(bool forward = true);

    /**
        Creates the notebook window.
    */
    bool Create(wxWindow* parent, wxWindowID id = wxID_ANY,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0);

    /**
        Deletes a page at the given index.
        Calling this method will generate a page change event.
    */
    bool DeletePage(size_t page);

    /**
        Returns the associated art provider.
    */
    wxAuiTabArt* GetArtProvider() const;

    /**
        Returns the desired height of the notebook for the given page height.
        Use this to fit the notebook to a given page size.
    */
    int GetHeightForPageHeight(int pageHeight);

    /**
        Returns the page specified by the given index.
    */
    wxWindow* GetPage(size_t page_idx) const;

    /**
        Returns the tab bitmap for the page.
    */
    wxBitmap GetPageBitmap(size_t page) const;

    /**
        Returns the number of pages in the notebook.
    */
    size_t GetPageCount() const;

    /**
        Returns the page index for the specified window.
        If the window is not found in the notebook, wxNOT_FOUND is returned.
    */
    int GetPageIndex(wxWindow* page_wnd) const;

    /**
        Returns the tab label for the page.
    */
    wxString GetPageText(size_t page) const;

    /**
        Returns the currently selected page.
    */
    int GetSelection() const;

    /**
        Returns the height of the tab control.
    */
    int GetTabCtrlHeight() const;

    /**
        InsertPage() is similar to AddPage, but allows the ability to specify the
        insert location.
        If the @a select parameter is @true, calling this will generate a page change
        event.
    */
    bool InsertPage(size_t page_idx, wxWindow* page,
                    const wxString& caption,
                    bool select = false,
                    const wxBitmap& bitmap = wxNullBitmap);

    /**
        Removes a page, without deleting the window pointer.
    */
    bool RemovePage(size_t page);

    /**
        Sets the art provider to be used by the notebook.
    */
    void SetArtProvider(wxAuiTabArt* art);

    /**
        Sets the font for drawing the tab labels, using a bold version of the font for
        selected tab labels.
    */
    virtual bool SetFont(const wxFont& font);

    /**
        Sets the font for measuring tab labels.
    */
    void SetMeasuringFont(const wxFont& font);

    /**
        Sets the font for drawing unselected tab labels.
    */
    void SetNormalFont(const wxFont& font);

    /**
        Sets the bitmap for the page.  To remove a bitmap from the tab caption, pass
        wxNullBitmap.
    */
    bool SetPageBitmap(size_t page, const wxBitmap& bitmap);

    /**
        Sets the tab label for the page.
    */
    bool SetPageText(size_t page, const wxString& text);

    /**
        Sets the font for drawing selected tab labels.
    */
    void SetSelectedFont(const wxFont& font);

    /**
        Sets the page selection.  Calling this method will generate a page change event.
    */
    size_t SetSelection(size_t new_page);

    /**
        Sets the tab height. By default, the tab control height is calculated
        by measuring the text height and bitmap sizes on the tab captions. Calling this
        method will override that calculation and set the tab control to the specified
        height parameter. A call to this method will override any call to
        SetUniformBitmapSize().

        Specifying -1 as the height will return the control to its default auto-sizing
        behaviour.
    */
    virtual void SetTabCtrlHeight(int height);

    //@{
    /**
        Split performs a split operation programmatically. The argument @a page
        indicates the page that will be split off.  This page will also become the
        active page after the split.

        The @a direction argument specifies where the pane should go, it should be one
        of the following: wxTOP, wxBOTTOM, wxLEFT, or wxRIGHT.
    */
    virtual void SetUniformBitmapSize(const wxSize& size);
    virtual void Split(size_t page, int direction);
    //@}

    /**
        Shows the window menu for the active tab control associated with this notebook,
        and returns @true if a selection was made.
    */
    bool ShowWindowMenu();
};



/**
    @class wxAuiTabArt

    Tab art class.

    @todo BETTER DESCRIPTION NEEDED

    @library{wxaui}
    @category{aui}
*/
class wxAuiTabArt
{
public:
    /**
        Constructor.
    */
    wxAuiTabArt();

    /**
        Clones the art object.
    */
    virtual wxAuiTabArt* Clone() = 0;

    /**
        Draws a background on the given area.
    */
    virtual void DrawBackground(wxDC& dc, wxWindow* wnd, const wxRect& rect) = 0;

    /**
        Draws a button.
    */
    virtual void DrawButton(wxDC& dc, wxWindow* wnd, const wxRect& in_rect,
                            int bitmap_id, int button_state, int orientation,
                            wxRect* out_rect) = 0;

    /**
        Draws a tab.
    */
    virtual void DrawTab(wxDC& dc, wxWindow* wnd, const wxAuiNotebookPage& page,
                         const wxRect& rect, int close_button_state,
                         wxRect* out_tab_rect, wxRect* out_button_rect, int* x_extent) = 0;

    /**
        Returns the tab control size.
    */
    virtual int GetBestTabCtrlSize(wxWindow*, const wxAuiNotebookPageArray&, const wxSize&) = 0;

    /**
        Returns the indent size.
    */
    virtual int GetIndentSize() = 0;

    /**
        Returns the tab size for the given caption, bitmap and state.
    */
    virtual wxSize GetTabSize(wxDC& dc, wxWindow* wnd, const wxString& caption,
                              const wxBitmap& bitmap, bool active,
                              int close_button_state, int* x_extent) = 0;

    /**
        Sets flags.
    */
    virtual void SetFlags(unsigned int flags) = 0;

    /**
        Sets the font used for calculating measurements.
    */
    virtual void SetMeasuringFont(const wxFont& font) = 0;

    /**
        Sets the normal font for drawing labels.
    */
    virtual void SetNormalFont(const wxFont& font) = 0;

    /**
        Sets the font for drawing text for selected UI elements.
    */
    virtual void SetSelectedFont(const wxFont& font) = 0;

    /**
        Sets sizing information.
    */
    virtual void SetSizingInfo(const wxSize& tab_ctrl_size, size_t tab_count) = 0;
};

