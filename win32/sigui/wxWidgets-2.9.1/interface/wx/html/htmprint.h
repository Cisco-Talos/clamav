/////////////////////////////////////////////////////////////////////////////
// Name:        html/htmprint.h
// Purpose:     interface of wxHtmlDCRenderer
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxHtmlDCRenderer

    This class can render HTML document into a specified area of a DC.
    You can use it in your own printing code, although use of wxHtmlEasyPrinting
    or wxHtmlPrintout is strongly recommended.

    @library{wxhtml}
    @category{html}
*/
class wxHtmlDCRenderer : public wxObject
{
public:
    /**
        Constructor.
    */
    wxHtmlDCRenderer();

    /**
        Returns the width of the HTML text in pixels.

        This can be compared with the width parameter of SetSize() to check if
        the document being printed fits into the page boundary.

        @see GetTotalHeight()

        @since 2.9.0
     */
    int GetTotalWidth() const;

    /**
        Returns the height of the HTML text in pixels.

        This is important if area height (see wxHtmlDCRenderer::SetSize) is
        smaller that total height and thus the page cannot fit into it. In that
        case you're supposed to call Render() as long as its return value is
        smaller than GetTotalHeight()'s.

        @see GetTotalWidth()
    */
    int GetTotalHeight() const;

    /**
        Renders HTML text to the DC.

        @param x,y
            position of upper-left corner of printing rectangle (see SetSize()).
        @param known_pagebreaks
            @todo docme
        @param from
            y-coordinate of the very first visible cell.
        @param dont_render
            if @true then this method only returns y coordinate of the next page
            and does not output anything.
        @param to
            y-coordinate of the last visible cell.

        Returned value is y coordinate of first cell than didn't fit onto page.
        Use this value as from in next call to Render() in order to print
        multipages document.

        @note
        The following three methods @b must always be called before any call to
        Render(), in this order:
        - SetDC()
        - SetSize()
        - SetHtmlText()

        @note Render() changes the DC's user scale and does NOT restore it.
    */
    int Render(int x, int y, wxArrayInt& known_pagebreaks, int from = 0,
               int dont_render = false, int to = INT_MAX);

    /**
        Assign DC instance to the renderer.

        @a pixel_scale can be used when rendering to high-resolution DCs (e.g. printer)
        to adjust size of pixel metrics.
        (Many dimensions in HTML are given in pixels -- e.g. image sizes. 300x300
        image would be only one inch wide on typical printer. With pixel_scale = 3.0
        it would be 3 inches.)
    */
    void SetDC(wxDC* dc, double pixel_scale = 1.0);

    /**
        This function sets font sizes and faces.

        @param normal_face
            This is face name for normal (i.e. non-fixed) font.
            It can be either empty string (then the default face is chosen) or
            platform-specific face name. Examples are "helvetica" under Unix or
            "Times New Roman" under Windows.
        @param fixed_face
            The same thing for fixed face ( \<TT\>..\</TT\> )
        @param sizes
            This is an array of 7 items of int type.
            The values represent size of font with HTML size from -2 to +4
            ( \<FONT SIZE=-2\> to \<FONT SIZE=+4\> ).
            Default sizes are used if sizes is @NULL.

        Default font sizes are defined by constants wxHTML_FONT_SIZE_1,
        wxHTML_FONT_SIZE_2, ..., wxHTML_FONT_SIZE_7.
        Note that they differ among platforms. Default face names are empty strings.

        @see SetSize()
    */
    void SetFonts(const wxString& normal_face, const wxString& fixed_face,
                  const int* sizes = NULL);

    /**
        Sets font sizes to be relative to the given size or the system
        default size; use either specified or default font

        @param size 
            Point size of the default HTML text
        @param normal_face
            This is face name for normal (i.e. non-fixed) font. It can be 
            either empty string (then the default face is chosen) or 
            platform-specific face name. Examples are "helvetica" under 
            Unix or "Times New Roman" under Windows.
        @param fixed_face
            The same thing for fixed face ( \<TT\>..\</TT\> ) 

        @see SetSize()
    */
    void SetStandardFonts(int size = -1,
                          const wxString& normal_face = wxEmptyString,
                          const wxString& fixed_face = wxEmptyString);

    /**
        Assign text to the renderer. Render() then draws the text onto DC.

        @param html
            HTML text. This is not a filename.
        @param basepath
            base directory (html string would be stored there if it was in file).
            It is used to determine path for loading images, for example.
        @param isdir
            @false if basepath is filename, @true if it is directory name
            (see wxFileSystem for detailed explanation).
    */
    void SetHtmlText(const wxString& html,
                     const wxString& basepath = wxEmptyString,
                     bool isdir = true);

    /**
        Set size of output rectangle, in pixels. Note that you @b can't change
        width of the rectangle between calls to Render() !
        (You can freely change height.)
    */
    void SetSize(int width, int height);
};



/**
    @class wxHtmlEasyPrinting

    This class provides very simple interface to printing architecture.
    It allows you to print HTML documents using only a few commands.

    @note
    Do not create this class on the stack only. You should create an instance
    on app startup and use this instance for all printing operations.
    The reason is that this class stores various settings in it.

    @library{wxhtml}
    @category{html,printing}
*/
class wxHtmlEasyPrinting : public wxObject
{
public:
    /**
        Constructor.

        @param name
            Name of the printing object. Used by preview frames and setup dialogs.
        @param parentWindow
            pointer to the window that will own the preview frame and setup dialogs.
            May be @NULL.
    */
    wxHtmlEasyPrinting(const wxString& name = "Printing",
                       wxWindow* parentWindow = NULL);

    /**
        Returns the current name being used for preview frames and setup
        dialogs.

        @since 2.8.11 / 2.9.1
    */
    const wxString& GetName() const;

    /**
        Returns a pointer to wxPageSetupDialogData instance used by this class.
        You can set its parameters (via SetXXXX methods).
    */
    wxPageSetupDialogData* GetPageSetupData();

    /**
        Gets the parent window for dialogs.
    */
    wxWindow* GetParentWindow() const;

    /**
        Returns pointer to wxPrintData instance used by this class.
        You can set its parameters (via SetXXXX methods).
    */
    wxPrintData* GetPrintData();

    /**
        Display page setup dialog and allows the user to modify settings.
    */
    void PageSetup();

    /**
        Preview HTML file.

        Returns @false in case of error -- call wxPrinter::GetLastError to get detailed
        information about the kind of the error.
    */
    bool PreviewFile(const wxString& htmlfile);

    /**
        Preview HTML text (not file!).

        Returns @false in case of error -- call wxPrinter::GetLastError to get detailed
        information about the kind of the error.

        @param htmltext
            HTML text.
        @param basepath
            base directory (html string would be stored there if it was in file).
            It is used to determine path for loading images, for example.
    */
    bool PreviewText(const wxString& htmltext,
                     const wxString& basepath = wxEmptyString);

    /**
        Print HTML file.

        Returns @false in case of error -- call wxPrinter::GetLastError to get detailed
        information about the kind of the error.
    */
    bool PrintFile(const wxString& htmlfile);

    /**
        Print HTML text (not file!).

        Returns @false in case of error -- call wxPrinter::GetLastError to get detailed
        information about the kind of the error.

        @param htmltext
            HTML text.
        @param basepath
            base directory (html string would be stored there if it was in file).
            It is used to determine path for loading images, for example.
    */
    bool PrintText(const wxString& htmltext,
                   const wxString& basepath = wxEmptyString);

    /**
        Sets fonts. See wxHtmlDCRenderer::SetFonts for detailed description.
    */
    void SetFonts(const wxString& normal_face, const wxString& fixed_face,
                  const int* sizes = NULL);
  
    /**
        Sets the name used for preview frames and setup dialogs.

        @since 2.8.11 / 2.9.1
    */
    void SetName(const wxString& name);

    /**
        Sets default font sizes and/or default font size. 
        See wxHtmlDCRenderer::SetStandardFonts for detailed description.
        @see SetFonts()
    */
    void SetStandardFonts(int size = -1,
                          const wxString& normal_face = wxEmptyString,
                          const wxString& fixed_face = wxEmptyString);

    /**
        Set page footer. The following macros can be used inside it:
         @@DATE@ is replaced by the current date in default format
         @@PAGENUM@ is replaced by page number
         @@PAGESCNT@ is replaced by total number of pages
         @@TIME@ is replaced by the current time in default format
         @@TITLE@ is replaced with the title of the document

        @param footer
            HTML text to be used as footer.
        @param pg
            one of wxPAGE_ODD, wxPAGE_EVEN and wxPAGE_ALL constants.
    */
    void SetFooter(const wxString& footer, int pg = wxPAGE_ALL);

    /**
        Set page header. The following macros can be used inside it:
        - @@DATE@ is replaced by the current date in default format
        - @@PAGENUM@ is replaced by page number
        - @@PAGESCNT@ is replaced by total number of pages
        - @@TIME@ is replaced by the current time in default format
        - @@TITLE@ is replaced with the title of the document

        @param header
            HTML text to be used as header.
        @param pg
            one of wxPAGE_ODD, wxPAGE_EVEN and wxPAGE_ALL constants.
    */
    void SetHeader(const wxString& header, int pg = wxPAGE_ALL);

    /**
        Sets the parent window for dialogs.
    */
    void SetParentWindow(wxWindow* window);

private:
    /**
        Check whether the document fits into the page area.

        This function is called by the base class OnPreparePrinting()
        implementation and by default checks whether the document fits into
        @a pageArea horizontally and warns the user if it does not, giving him
        the possibility to cancel printing in this case (presumably in order to
        change some layout options and retry it again).

        You may override it to either suppress this check if truncation of the
        HTML being printed is acceptable or, on the contrary, add more checks to
        it, e.g. for the fit in the vertical direction if the document should
        always appear on a single page.

        @return
            @true if wxHtmlPrintout should continue or @false to cancel
            printing.

        @since 2.9.0
     */
    virtual bool CheckFit(const wxSize& pageArea, const wxSize& docArea) const;
};



/**
    @class wxHtmlPrintout

    This class serves as printout class for HTML documents.

    @library{wxhtml}
    @category{html,printing}
*/
class wxHtmlPrintout : public wxPrintout
{
public:
    /**
        Constructor.
    */
    wxHtmlPrintout(const wxString& title = "Printout");

    /**
        Adds a filter to the static list of filters for wxHtmlPrintout.
        See wxHtmlFilter for further information.
    */
    static void AddFilter(wxHtmlFilter* filter);

    /**
        This function sets font sizes and faces. See wxHtmlWindow::SetFonts
        for detailed description.
    */
    void SetFonts(const wxString& normal_face, const wxString& fixed_face,
                  const int* sizes = NULL);

    /**
        Set page footer. The following macros can be used inside it:
        - @@DATE@ is replaced by the current date in default format
        - @@PAGENUM@ is replaced by page number
        - @@PAGESCNT@ is replaced by total number of pages
        - @@TIME@ is replaced by the current time in default format
        - @@TITLE@ is replaced with the title of the document

        @param footer
            HTML text to be used as footer.
        @param pg
            one of wxPAGE_ODD, wxPAGE_EVEN and wxPAGE_ALL constants.
    */
    void SetFooter(const wxString& footer, int pg = wxPAGE_ALL);

    /**
        Set page header. The following macros can be used inside it:
        - @@DATE@ is replaced by the current date in default format
        - @@PAGENUM@ is replaced by page number
        - @@PAGESCNT@ is replaced by total number of pages
        - @@TIME@ is replaced by the current time in default format
        - @@TITLE@ is replaced with the title of the document

        @param header
            HTML text to be used as header.
        @param pg
            one of wxPAGE_ODD, wxPAGE_EVEN and wxPAGE_ALL constants.
    */
    void SetHeader(const wxString& header, int pg = wxPAGE_ALL);

    /**
        Prepare the class for printing this HTML @b file.
        The file may be located on any virtual file system or it may be normal file.
    */
    void SetHtmlFile(const wxString& htmlfile);

    /**
        Prepare the class for printing this HTML text.

        @param html
            HTML text. (NOT file!)
        @param basepath
            base directory (html string would be stored there if it was in file).
            It is used to determine path for loading images, for example.
        @param isdir
            @false if basepath is filename, @true if it is directory name
            (see wxFileSystem for detailed explanation).
    */
    void SetHtmlText(const wxString& html,
                     const wxString& basepath = wxEmptyString,
                     bool isdir = true);

    /**
        Sets margins in millimeters.
        Defaults to 1 inch for margins and 0.5cm for space between text and header
        and/or footer.
    */
    void SetMargins(float top = 25.2, float bottom = 25.2,
                    float left = 25.2,
                    float right = 25.2,
                    float spaces = 5);
};

