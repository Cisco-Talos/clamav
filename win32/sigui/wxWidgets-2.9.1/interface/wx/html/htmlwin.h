/////////////////////////////////////////////////////////////////////////////
// Name:        html/htmlwin.h
// Purpose:     interface of wxHtmlWindow
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxHtmlWindow

    wxHtmlWindow is probably the only class you will directly use unless you want
    to do something special (like adding new tag handlers or MIME filters).

    The purpose of this class is to display HTML pages (either local file or
    downloaded via HTTP protocol) in a window.
    The width of the window is constant - given in the constructor - and virtual height
    is changed dynamically depending on page size.
    Once the window is created you can set its content by calling SetPage(text),
    LoadPage(filename) or wxHtmlWindow::LoadFile.

    @note
    wxHtmlWindow uses the wxImage class for displaying images.
    Don't forget to initialize all image formats you need before loading any page!
    (See ::wxInitAllImageHandlers and wxImage::AddHandler.)

    @beginStyleTable
    @style{wxHW_SCROLLBAR_NEVER}
           Never display scrollbars, not even when the page is larger than the
           window.
    @style{wxHW_SCROLLBAR_AUTO}
           Display scrollbars only if page's size exceeds window's size.
    @style{wxHW_NO_SELECTION}
           Don't allow the user to select text.
    @endStyleTable


    @beginEventEmissionTable{wxHtmlCellEvent, wxHtmlLinkEvent}
    @event{EVT_HTML_CELL_CLICKED(id, func)}
        A wxHtmlCell was clicked.
    @event{EVT_HTML_CELL_HOVER(id, func)}
        The mouse passed over a wxHtmlCell.
    @event{EVT_HTML_LINK_CLICKED(id, func)}
        A wxHtmlCell which contains an hyperlink was clicked.
    @endEventTable

    @library{wxhtml}
    @category{html}

    @see wxHtmlLinkEvent, wxHtmlCellEvent
*/
class wxHtmlWindow : public wxScrolledWindow
{
public:
    /**
        Default ctor.
    */
    wxHtmlWindow();

    /**
        Constructor.
        The parameters are the same as wxScrolled::wxScrolled() constructor.
    */
    wxHtmlWindow(wxWindow *parent, wxWindowID id = wxID_ANY,
                 const wxPoint& pos = wxDefaultPosition,
                 const wxSize& size = wxDefaultSize,
                 long style = wxHW_DEFAULT_STYLE,
                 const wxString& name = "htmlWindow");

    /**
        Adds @ref overview_html_filters "input filter" to the static list of available
        filters. These filters are present by default:
        - @c text/html MIME type
        - @c image/* MIME types
        - Plain Text filter (this filter is used if no other filter matches)
    */
    static void AddFilter(wxHtmlFilter* filter);

    /**
        Appends HTML fragment to currently displayed text and refreshes the window.

        @param source
            HTML code fragment

        @return @false if an error occurred, @true otherwise.
    */
    bool AppendToPage(const wxString& source);

    /**
        Returns pointer to the top-level container.

        @see @ref overview_html_cells, @ref overview_printing
    */
    wxHtmlContainerCell* GetInternalRepresentation() const;

    /**
        Returns anchor within currently opened page (see wxHtmlWindow::GetOpenedPage).
        If no page is opened or if the displayed page wasn't produced by call to
        LoadPage(), empty string is returned.
    */
    wxString GetOpenedAnchor() const;

    /**
        Returns full location of the opened page.
        If no page is opened or if the displayed page wasn't produced by call to
        LoadPage(), empty string is returned.
    */
    wxString GetOpenedPage() const;

    /**
        Returns title of the opened page or wxEmptyString if current page does not
        contain \<TITLE\> tag.
    */
    wxString GetOpenedPageTitle() const;

    /**
        Returns the related frame.
    */
    wxFrame* GetRelatedFrame() const;

    /**
        Moves back to the previous page.
        (each page displayed using LoadPage() is stored in history list.)
    */
    bool HistoryBack();

    /**
        Returns @true if it is possible to go back in the history
        (i.e. HistoryBack() won't fail).
    */
    bool HistoryCanBack();

    /**
        Returns @true if it is possible to go forward in the history
        (i.e. HistoryBack() won't fail).
    */
    bool HistoryCanForward();

    /**
        Clears history.
    */
    void HistoryClear();

    /**
        Moves to next page in history.
    */
    bool HistoryForward();

    /**
        Loads HTML page from file and displays it.

        @return @false if an error occurred, @true otherwise

        @see LoadPage()
    */
    bool LoadFile(const wxFileName& filename);

    /**
        Unlike SetPage() this function first loads HTML page from @a location
        and then displays it. See example:

        @param location
            The address of document.
            See wxFileSystem for details on address format and behaviour of "opener".

        @return @false if an error occurred, @true otherwise

        @see LoadFile()
    */
    virtual bool LoadPage(const wxString& location);

    /**
        Called when user clicks on hypertext link.
        Default behaviour is to emit a wxHtmlLinkEvent and, if the event was not
        processed or skipped, call LoadPage() and do nothing else.

        Overloading this method is deprecated; intercept the event instead.

        Also see wxHtmlLinkInfo.
    */
    virtual void OnLinkClicked(const wxHtmlLinkInfo& link);

    /**
        Called when an URL is being opened (either when the user clicks on a link or
        an image is loaded). The URL will be opened only if OnOpeningURL() returns
        @c wxHTML_OPEN. This method is called by wxHtmlParser::OpenURL.

        You can override OnOpeningURL() to selectively block some URLs
        (e.g. for security reasons) or to redirect them elsewhere.
        Default behaviour is to always return @c wxHTML_OPEN.

        @param type
            Indicates type of the resource. Is one of
            - wxHTML_URL_PAGE: Opening a HTML page.
            - wxHTML_URL_IMAGE: Opening an image.
            - wxHTML_URL_OTHER: Opening a resource that doesn't fall into
                                any other category.
        @param url
            URL being opened.
        @param redirect
            Pointer to wxString variable that must be filled with an
            URL if OnOpeningURL() returns @c wxHTML_REDIRECT.

        The return value is:
        - wxHTML_OPEN: Open the URL.
        - wxHTML_BLOCK: Deny access to the URL, wxHtmlParser::OpenURL will return @NULL.
        - wxHTML_REDIRECT: Don't open url, redirect to another URL.
          OnOpeningURL() must fill *redirect with the new URL.
          OnOpeningURL() will be called again on returned URL.
    */
    virtual wxHtmlOpeningStatus OnOpeningURL(wxHtmlURLType type,
                                             const wxString& url,
                                             wxString* redirect) const;

    /**
        Called on parsing \<TITLE\> tag.
    */
    virtual void OnSetTitle(const wxString& title);

    /**
        This reads custom settings from wxConfig. It uses the path 'path'
        if given, otherwise it saves info into currently selected path.
        The values are stored in sub-path @c wxHtmlWindow.
        Read values: all things set by SetFonts(), SetBorders().

        @param cfg
            wxConfig from which you want to read the configuration.
        @param path
            Optional path in config tree. If not given current path is used.
    */
    virtual void ReadCustomization(wxConfigBase* cfg,
                                   wxString path = wxEmptyString);

    /**
        Selects all text in the window.

        @see SelectLine(), SelectWord()
    */
    void SelectAll();

    /**
        Selects the line of text that @a pos points at. Note that @e pos
        is relative to the top of displayed page, not to window's origin, use
        wxScrolled::CalcUnscrolledPosition()
        to convert physical coordinate.

        @see SelectAll(), SelectWord()
    */
    void SelectLine(const wxPoint& pos);

    /**
        Selects the word at position @a pos.
        Note that @a pos is relative to the top of displayed page, not to window's
        origin, use wxScrolled::CalcUnscrolledPosition() to convert physical coordinate.

        @see SelectAll(), SelectLine()
    */
    void SelectWord(const wxPoint& pos);

    /**
        Returns current selection as plain text.
        Returns empty string if no text is currently selected.
    */
    wxString SelectionToText();

    /**
        This function sets the space between border of window and HTML contents.
        See image:
        @image html htmlwin_border.png

        @param b
            indentation from borders in pixels
    */
    void SetBorders(int b);

    /**
        This function sets font sizes and faces. See wxHtmlDCRenderer::SetFonts
        for detailed description.

        @see SetSize()
    */
    void SetFonts(const wxString& normal_face, const wxString& fixed_face,
                  const int* sizes = NULL);

    /**
        Sets default font sizes and/or default font size. 
        See wxHtmlDCRenderer::SetStandardFonts for detailed description.
        @see SetFonts()
    */
    void SetStandardFonts(int size = -1,
                          const wxString& normal_face = wxEmptyString,
                          const wxString& fixed_face = wxEmptyString);

    /**
        Sets HTML page and display it. This won't @b load the page!!
        It will display the @e source. See example:
        @code
        htmlwin -> SetPage("<html><body>Hello, world!</body></html>");
        @endcode

        If you want to load a document from some location use LoadPage() instead.

        @param source
            The HTML document source to be displayed.

        @return @false if an error occurred, @true otherwise.
    */
    virtual bool SetPage(const wxString& source);

    /**
        Sets the frame in which page title will be displayed.
        @a format is the format of the frame title, e.g. "HtmlHelp : %s".
        It must contain exactly one %s.
        This %s is substituted with HTML page title.
    */
    void SetRelatedFrame(wxFrame* frame, const wxString& format);

    /**
        @b After calling SetRelatedFrame(), this sets statusbar slot where messages
        will be displayed. (Default is -1 = no messages.)

        @param index
            Statusbar slot number (0..n)
    */
    void SetRelatedStatusBar(int index);

    /**
        @b Sets the associated statusbar where messages will be displayed.
        Call this instead of SetRelatedFrame() if you want statusbar updates only,
        no changing of the frame title.

        @param statusbar
            Statusbar pointer
        @param index
            Statusbar slot number (0..n)

        @since 2.9.0
    */
    void SetRelatedStatusBar(wxStatusBar* statusbar, int index = 0);

    /**
        Returns content of currently displayed page as plain text.
    */
    wxString ToText();

    /**
        Saves custom settings into wxConfig.
        It uses the path 'path' if given, otherwise it saves info into currently
        selected path.
        Regardless of whether the path is given or not, the function creates
        sub-path @c wxHtmlWindow.

        Saved values: all things set by SetFonts(), SetBorders().

        @param cfg
            wxConfig to which you want to save the configuration.
        @param path
            Optional path in config tree. If not given, the current path is used.
    */
    virtual void WriteCustomization(wxConfigBase* cfg,
                                    wxString path = wxEmptyString);

protected:

    /**
        This method is called when a mouse button is clicked inside wxHtmlWindow.
        The default behaviour is to emit a wxHtmlCellEvent and, if the event was
        not processed or skipped, call OnLinkClicked() if the cell contains an
        hypertext link.

        Overloading this method is deprecated; intercept the event instead.

        @param cell
            The cell inside which the mouse was clicked, always a simple
            (i.e. non-container) cell
        @param x
            The logical x coordinate of the click point
        @param y
            The logical y coordinate of the click point
        @param event
            The mouse event containing other information about the click

        @return @true if a link was clicked, @false otherwise.
    */
    virtual bool OnCellClicked(wxHtmlCell* cell, wxCoord x, wxCoord y,
                               const wxMouseEvent& event);

    /**
        This method is called when a mouse moves over an HTML cell.
        Default behaviour is to emit a wxHtmlCellEvent.

        Overloading this method is deprecated; intercept the event instead.

        @param cell
            The cell inside which the mouse is currently, always a simple
            (i.e. non-container) cell
        @param x
            The logical x coordinate of the click point
        @param y
            The logical y coordinate of the click point
    */
    virtual void OnCellMouseHover(wxHtmlCell* cell, wxCoord x, wxCoord y);
};



/**
    @class wxHtmlLinkEvent

    This event class is used for the events generated by wxHtmlWindow.

    @beginEventTable{wxHtmlLinkEvent}
    @event{EVT_HTML_LINK_CLICKED(id, func)}
        User clicked on an hyperlink.
    @endEventTable

    @library{wxhtml}
    @category{html}
*/
class wxHtmlLinkEvent : public wxCommandEvent
{
public:
    /**
        The constructor is not normally used by the user code.
    */
    wxHtmlLinkEvent(int id, const wxHtmlLinkInfo& linkinfo);

    /**
        Returns the wxHtmlLinkInfo which contains info about the cell clicked
        and the hyperlink it contains.
    */
    const wxHtmlLinkInfo& GetLinkInfo() const;
};



/**
    @class wxHtmlCellEvent

    This event class is used for the events generated by wxHtmlWindow.

    @beginEventTable{wxHtmlCellEvent}
    @event{EVT_HTML_CELL_HOVER(id, func)}
        User moved the mouse over a wxHtmlCell.
    @event{EVT_HTML_CELL_CLICKED(id, func)}
        User clicked on a wxHtmlCell. When handling this event, remember to use
        wxHtmlCell::SetLinkClicked(true) if the cell contains a link.
    @endEventTable

    @library{wxhtml}
    @category{html}
*/
class wxHtmlCellEvent : public wxCommandEvent
{
public:
    /**
        The constructor is not normally used by the user code.
    */
    wxHtmlCellEvent(wxEventType commandType, int id,
                    wxHtmlCell* cell,
                    const wxPoint& point,
                    const wxMouseEvent& ev);

    /**
        Returns the wxHtmlCellEvent associated with the event.
    */
    wxHtmlCell* GetCell() const;

    /**
        Returns @true if SetLinkClicked(@true) has previously been called;
        @false otherwise.
    */
    bool GetLinkClicked() const;

    /**
        Returns the wxPoint associated with the event.
    */
    wxPoint GetPoint() const;

    /**
        Call this function with @a linkclicked set to @true if the cell which has
        been clicked contained a link or @false otherwise (which is the default).

        With this function the event handler can return info to the wxHtmlWindow
        which sent the event.
    */
    void SetLinkClicked(bool linkclicked);
};

