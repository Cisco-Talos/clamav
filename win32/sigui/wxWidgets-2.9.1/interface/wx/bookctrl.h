/////////////////////////////////////////////////////////////////////////////
// Name:        bookctrl.h
// Purpose:     interface of wxBookCtrlBase
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxBookCtrlBase

    A book control is a convenient way of displaying multiple pages of information,
    displayed one page at a time. wxWidgets has five variants of this control:

    @li wxChoicebook: controlled by a wxChoice
    @li wxListbook: controlled by a wxListCtrl
    @li wxNotebook: uses a row of tabs
    @li wxTreebook: controlled by a wxTreeCtrl
    @li wxToolbook: controlled by a wxToolBar

    This abstract class is the parent of all these book controls, and provides
    their basic interface.
    This is a pure virtual class so you cannot allocate it directly.

    @library{wxcore}
    @category{bookctrl}

    @see @ref overview_bookctrl
*/
class wxBookCtrlBase : public wxControl
{
public:
    /**
        Default ctor.
    */
    wxBookCtrlBase();

    /**
        Constructs the book control with the given parameters.
        See Create() for two-step construction.
    */
    wxBookCtrlBase(wxWindow *parent,
                   wxWindowID winid,
                   const wxPoint& pos = wxDefaultPosition,
                   const wxSize& size = wxDefaultSize,
                   long style = 0,
                   const wxString& name = wxEmptyString);

    /**
        Constructs the book control with the given parameters.
    */
    bool Create(wxWindow *parent,
                wxWindowID winid,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0,
                const wxString& name = wxEmptyString);


    /**
        @name Image list functions

        Each page may have an attached image.
        The functions of this group manipulate that image.
    */
    //@{

    /**
        Sets the image list for the page control and takes ownership of the list.

        @see wxImageList, SetImageList()
    */
    void AssignImageList(wxImageList* imageList);

    /**
        Returns the associated image list.

        @see wxImageList, SetImageList()
    */
    wxImageList* GetImageList() const;

    /**
        Returns the image index for the given page.
    */
    virtual int GetPageImage(size_t nPage) const = 0;

    /**
        Sets the image list for the page control.
        It does not take ownership of the image list, you must delete it yourself.

        @see wxImageList, AssignImageList()
    */
    virtual void SetImageList(wxImageList* imageList);

    /**
        Sets the image index for the given page. @a image is an index into
        the image list which was set with SetImageList().
    */
    virtual bool SetPageImage(size_t page, int image) = 0;

    //@}



    /**
        @name Page text functions

        Each page has a text string attached.
        The functions of this group manipulate that text.
    */
    //@{

    /**
        Returns the string for the given page.
    */
    virtual wxString GetPageText(size_t nPage) const = 0;

    /**
        Sets the text for the given page.
    */
    virtual bool SetPageText(size_t page, const wxString& text) = 0;
    //@}



    /**
        @name Selection functions

        The functions of this group manipulate the selection.
    */
    //@{

    /**
        Returns the currently selected page, or @c wxNOT_FOUND if none was selected.

        Note that this method may return either the previously or newly
        selected page when called from the @c EVT_BOOKCTRL_PAGE_CHANGED handler
        depending on the platform and so wxBookCtrlEvent::GetSelection should be
        used instead in this case.
    */
    virtual int GetSelection() const = 0;

    /**
        Returns the currently selected page or @NULL.
    */
    wxWindow* GetCurrentPage() const;

    /**
        Sets the selection for the given page, returning the previous selection.

        Notice that the call to this function generates the page changing
        events, use the ChangeSelection() function if you don't want these
        events to be generated.

        @see GetSelection()
    */
    virtual int SetSelection(size_t page) = 0;

    /**
        Cycles through the tabs.
        The call to this function generates the page changing events.
    */
    void AdvanceSelection(bool forward = true);

    /**
        Changes the selection for the given page, returning the previous selection.

        This function behaves as SetSelection() but does @em not generate the
        page changing events.

        See @ref overview_events_prog for more information.
    */
    virtual int ChangeSelection(size_t page) = 0;

    //@}



    /**
        Sets the width and height of the pages.

        @note This method is currently not implemented for wxGTK.
    */
    virtual void SetPageSize(const wxSize& size);

    /**
        Returns the index of the tab at the specified position or @c wxNOT_FOUND
        if none. If @a flags parameter is non-@NULL, the position of the point
        inside the tab is returned as well.

        @param pt
            Specifies the point for the hit test.
        @param flags
            Return value for detailed information. One of the following values:
            <TABLE><TR><TD>wxBK_HITTEST_NOWHERE</TD>
            <TD>There was no tab under this point.</TD></TR>
            <TR><TD>wxBK_HITTEST_ONICON</TD>
            <TD>The point was over an icon (currently wxMSW only).</TD></TR>
            <TR><TD>wxBK_HITTEST_ONLABEL</TD>
            <TD>The point was over a label (currently wxMSW only).</TD></TR>
            <TR><TD>wxBK_HITTEST_ONITEM</TD>
            <TD>The point was over an item, but not on the label or icon.</TD></TR>
            <TR><TD>wxBK_HITTEST_ONPAGE</TD>
            <TD>The point was over a currently selected page, not over any tab.
            Note that this flag is present only if wxNOT_FOUND is returned.</TD></TR>
            </TABLE>

        @return Returns the zero-based tab index or @c wxNOT_FOUND if there is no
                tab at the specified position.
    */
    virtual int HitTest(const wxPoint& pt, long* flags = NULL) const;



    /**
        @name Page management functions

        Functions for adding/removing pages from this control.
    */
    //@{

    /**
        Adds a new page.
        The call to this function may generate the page changing events.

        @param page
            Specifies the new page.
        @param text
            Specifies the text for the new page.
        @param select
            Specifies whether the page should be selected.
        @param imageId
            Specifies the optional image index for the new page.

        @return @true if successful, @false otherwise.

        @remarks Do not delete the page, it will be deleted by the book control.

        @see InsertPage()
    */
    virtual bool AddPage(wxWindow* page, const wxString& text,
                         bool select = false, int imageId = wxNOT_FOUND);

    /**
        Deletes all pages.
    */
    virtual bool DeleteAllPages();

    /**
        Deletes the specified page, and the associated window.
        The call to this function generates the page changing events.
    */
    virtual bool DeletePage(size_t page);

    /**
        Inserts a new page at the specified position.

        @param index
            Specifies the position for the new page.
        @param page
            Specifies the new page.
        @param text
            Specifies the text for the new page.
        @param select
            Specifies whether the page should be selected.
        @param imageId
            Specifies the optional image index for the new page.

        @return @true if successful, @false otherwise.

        @remarks Do not delete the page, it will be deleted by the book control.

        @see AddPage()
    */
    virtual bool InsertPage(size_t index,
                            wxWindow* page,
                            const wxString& text,
                            bool select = false,
                            int imageId = wxNOT_FOUND) = 0;

    /**
        Deletes the specified page, without deleting the associated window.
    */
    virtual bool RemovePage(size_t page);

    /**
        Returns the number of pages in the control.
    */
    virtual size_t GetPageCount() const;

    /**
        Returns the window at the given page position.
    */
    wxWindow* GetPage(size_t page) const;

    //@}


/*
    other functions which may be worth documenting:

    // geometry
    // --------

    // calculate the size of the control from the size of its page
    virtual wxSize CalcSizeFromPage(const wxSize& sizePage) const = 0;

    // get/set size of area between book control area and page area
    unsigned int GetInternalBorder() const { return m_internalBorder; }
    void SetInternalBorder(unsigned int border) { m_internalBorder = border; }

    // Sets/gets the margin around the controller
    void SetControlMargin(int margin) { m_controlMargin = margin; }
    int GetControlMargin() const { return m_controlMargin; }

    // returns true if we have wxBK_TOP or wxBK_BOTTOM style
    bool IsVertical() const { return HasFlag(wxBK_BOTTOM | wxBK_TOP); }

    // set/get option to shrink to fit current page
    void SetFitToCurrentPage(bool fit) { m_fitToCurrentPage = fit; }
    bool GetFitToCurrentPage() const { return m_fitToCurrentPage; }

    // returns the sizer containing the control, if any
    wxSizer* GetControlSizer() const { return m_controlSizer; }

    // we do have multiple pages
    virtual bool HasMultiplePages() const { return true; }

    // we don't want focus for ourselves
    virtual bool AcceptsFocus() const { return false; }

    // returns true if the platform should explicitly apply a theme border
    virtual bool CanApplyThemeBorder() const { return false; }
*/
};

/**
    wxBookCtrl is defined to one of the 'real' book controls.

    See @ref overview_bookctrl for more info.
*/
#define wxBookCtrl      TheBestBookCtrlForTheCurrentPlatform


/**
    @class wxBookCtrlEvent

    This class represents the events generated by book controls (wxNotebook,
    wxListbook, wxChoicebook, wxTreebook).

    The PAGE_CHANGING events are sent before the current page is changed.
    It allows the program to examine the current page (which can be retrieved
    with wxBookCtrlEvent::GetOldSelection) and to veto the page change by calling
    wxNotifyEvent::Veto if, for example, the current values in the controls
    of the old page are invalid.

    The PAGE_CHANGED events are sent after the page has been changed and the
    program cannot veto it any more, it just informs it about the page change.

    To summarize, if the program is interested in validating the page values
    before allowing the user to change it, it should process the PAGE_CHANGING
    event, otherwise PAGE_CHANGED is probably enough. In any case, it is
    probably unnecessary to process both events at once.

    @library{wxcore}
    @category{events,bookctrl}

    @see wxNotebook, wxListbook, wxChoicebook, wxTreebook, wxToolbook
*/
class wxBookCtrlEvent : public wxNotifyEvent
{
public:
    /**
        Constructor (used internally by wxWidgets only).
    */
    wxBookCtrlEvent(wxEventType eventType = wxEVT_NULL, int id = 0,
                    int sel = wxNOT_FOUND, int oldSel = wxNOT_FOUND);

    /**
        Returns the page that was selected before the change, @c wxNOT_FOUND if
        none was selected.
    */
    int GetOldSelection() const;

    /**
        Returns the currently selected page, or @c wxNOT_FOUND if none was
        selected.

        @note under Windows, GetSelection() will return the same value as
              GetOldSelection() when called from the @c EVT_BOOKCTRL_PAGE_CHANGING
              handler and not the page which is going to be selected.
    */
    int GetSelection() const;

    /**
        Sets the id of the page selected before the change.
    */
    void SetOldSelection(int page);

    /**
        Sets the selection member variable.
    */
    void SetSelection(int page);
};

