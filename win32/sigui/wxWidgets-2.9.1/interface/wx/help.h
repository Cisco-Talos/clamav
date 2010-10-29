/////////////////////////////////////////////////////////////////////////////
// Name:        help.h
// Purpose:     interface of wxHelpController
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxHelpController

    This is a family of classes by which applications may invoke a help viewer
    to provide on-line help.

    A help controller allows an application to display help, at the contents
    or at a particular topic, and shut the help program down on termination.
    This avoids proliferation of many instances of the help viewer whenever the
    user requests a different topic via the application's menus or buttons.

    Typically, an application will create a help controller instance when it starts,
    and immediately call wxHelpController::Initialize to associate a filename with it.
    The help viewer will only get run, however, just before the first call to
    display something.

    Most help controller classes actually derive from wxHelpControllerBase and have
    names of the form wxXXXHelpController or wxHelpControllerXXX.
    An appropriate class is aliased to the name wxHelpController for each platform, as
    follows:
    - On desktop Windows, wxCHMHelpController is used (MS HTML Help).
    - On Windows CE, wxWinceHelpController is used.
    - On all other platforms, wxHtmlHelpController is used if wxHTML is compiled
      into wxWidgets; otherwise wxExtHelpController is used (for invoking an
      external browser).

    The remaining help controller classes need to be named explicitly by an
    application that wishes to make use of them.

    The following help controller classes are defined:
    - wxWinHelpController, for controlling Windows Help.
    - wxCHMHelpController, for controlling MS HTML Help. To use this, you need to
      set wxUSE_MS_HTML_HELP to 1 in setup.h and have the htmlhelp.h header from
      Microsoft's HTML Help kit. (You don't need the VC++-specific htmlhelp.lib
      because wxWidgets loads necessary DLL at runtime and so it works with all
      compilers.)
    - wxBestHelpController, for controlling MS HTML Help or, if Microsoft's runtime
      is not available, wxHtmlHelpController. You need to provide @b both CHM and
      HTB versions of the help file. For wxMSW only.
    - wxExtHelpController, for controlling external browsers under Unix.
      The default browser is Netscape Navigator. The 'help' sample shows its use.
    - wxWinceHelpController, for controlling a simple @c .htm help controller for
      Windows CE applications.
    - wxHtmlHelpController, a sophisticated help controller using wxHTML, in a
      similar style to the Microsoft HTML Help viewer and using some of the same
      files. Although it has an API compatible with other help controllers, it has
      more advanced features, so it is recommended that you use the specific API
      for this class instead. Note that if you use .zip or .htb formats for your
      books, you must add this line to your application initialization:
      @code wxFileSystem::AddHandler(new wxArchiveFSHandler); @endcode
      or nothing will be shown in your help window.

    @library{wxbase}
    @category{help}

    @see wxHtmlHelpController, @ref overview_html
*/
class wxHelpController : public wxHelpControllerBase
{
public:
    /**
        Constructs a help instance object, but does not invoke the help viewer.

        If you provide a window, it will be used by some help controller classes, such as
        wxCHMHelpController, wxWinHelpController and wxHtmlHelpController, as the
        parent for the help window instead of the value of wxApp::GetTopWindow.

        You can also change the parent window later with SetParentWindow().
    */
    wxHelpController(wxWindow* parentWindow = NULL);

    /**
        Destroys the help instance, closing down the viewer if it is running.
    */
    ~wxHelpController();

    /**
        If the help viewer is not running, runs it and displays the file at the given
        block number.

        - @e WinHelp: Refers to the context number.
        - @e MS HTML Help: Refers to the context number.
        - @e External HTML help: the same as for DisplaySection().
        - @e wxHtmlHelpController: @e sectionNo is an identifier as specified in
          the @c .hhc file. See @ref overview_html_helpformats.

        @deprecated
        This function is for backward compatibility only, and applications
        should use DisplaySection() instead.
    */
    virtual bool DisplayBlock(long blockNo);

    /**
        If the help viewer is not running, runs it and displays the contents.
    */
    virtual bool DisplayContents();

    /**
        Displays the section as a popup window using a context id.
        Returns @false if unsuccessful or not implemented.
    */
    virtual bool DisplayContextPopup(int contextId);

    /**
        If the help viewer is not running, runs it and displays the given section.

        The interpretation of section differs between help viewers.
        For most viewers, this call is equivalent to KeywordSearch.
        For MS HTML Help, wxHTML help and external HTML help, if section has a
        .htm or .html extension, that HTML file will be displayed; otherwise a
        keyword search is done.
    */
    virtual bool DisplaySection(const wxString& section);

    /**
        If the help viewer is not running, runs it and displays the given section.

        - @e WinHelp, MS HTML Help @a sectionNo is a context id.
        - @e External HTML help: wxExtHelpController implements @a sectionNo as
          an id in a map file, which is of the form:
        - @e wxHtmlHelpController: @a sectionNo is an identifier as specified in
          the @c .hhc file. See @ref overview_html_helpformats.
          See also the help sample for notes on how to specify section numbers for
          various help file formats.
    */
    virtual bool DisplaySection(int sectionNo);

    /**
        Displays the text in a popup window, if possible.

        Returns @false if unsuccessful or not implemented.
    */
    virtual bool DisplayTextPopup(const wxString& text,
                                  const wxPoint& pos);

    /**
        For wxHtmlHelpController, returns the latest frame size and position
        settings and whether a new frame is drawn with each invocation.
        For all other help controllers, this function does nothing and just returns @NULL.

        @param size
            The most recent frame size.
        @param pos
            The most recent frame position.
        @param newFrameEachTime
            @true if a new frame is drawn with each invocation.
    */
    virtual wxFrame* GetFrameParameters(const wxSize* size = NULL,
                                        const wxPoint* pos = NULL,
                                        bool* newFrameEachTime = NULL);

    /**
        Returns the window to be used as the parent for the help window.
        This window is used by wxCHMHelpController, wxWinHelpController and
        wxHtmlHelpController.
    */
    virtual wxWindow* GetParentWindow() const;

    //@{
    /**
        Initializes the help instance with a help filename, and optionally a server
        socket number if using wxHelp (now obsolete). Does not invoke the help viewer.
        This must be called directly after the help instance object is created and
        before any attempts to communicate with the viewer.

        You may omit the file extension and a suitable one will be chosen.
        For wxHtmlHelpController, the extensions zip, htb and hhp will be appended
        while searching for a suitable file. For WinHelp, the hlp extension is appended.
    */
    virtual bool Initialize(const wxString& file);
    virtual bool Initialize(const wxString& file, int server);
    //@}

    /**
        If the help viewer is not running, runs it, and searches for sections matching
        the given keyword. If one match is found, the file is displayed at this section.
        The optional parameter allows the search the index (wxHELP_SEARCH_INDEX)
        but this currently only supported by the wxHtmlHelpController.

        - @e WinHelp, MS HTML Help:
          If more than one match is found, the first topic is displayed.
        - @e External HTML help, simple wxHTML help:
          If more than one match is found, a choice of topics is displayed.
        - @e wxHtmlHelpController: see wxHtmlHelpController::KeywordSearch.
    */
    virtual bool KeywordSearch(const wxString& keyWord,
                               wxHelpSearchMode mode = wxHELP_SEARCH_ALL);

    /**
        If the help viewer is not running, runs it and loads the given file.
        If the filename is not supplied or is empty, the file specified in
        Initialize() is used.

        If the viewer is already displaying the specified file, it will not be
        reloaded. This member function may be used before each display call in
        case the user has opened another file.

        wxHtmlHelpController ignores this call.
    */
    virtual bool LoadFile(const wxString& file = wxEmptyString);

    /**
        Overrideable member called when this application's viewer is quit by the user.
        This does not work for all help controllers.
    */
    virtual bool OnQuit();

    /**
        If the viewer is running, quits it by disconnecting.
        For Windows Help, the viewer will only close if no other application is using it.
    */
    virtual bool Quit();

    /**
        For wxHtmlHelpController, the title is set (with %s indicating the
        page title) and also the size and position of the frame if the frame is
        already open. @a newFrameEachTime is ignored.

        For all other help controllers this function has no effect.
    */
    virtual void SetFrameParameters(const wxString& title,
                                    const wxSize& size,
                                    const wxPoint& pos = wxDefaultPosition,
                                    bool newFrameEachTime = false);

    /**
        Sets the window to be used as the parent for the help window. This is used
        by wxCHMHelpController, wxWinHelpController and wxHtmlHelpController.
    */
    virtual void SetParentWindow(wxWindow* parentWindow);

    /**
        Sets detailed viewer information.
        So far this is only relevant to wxExtHelpController.
        Some examples of usage:

        @code
        m_help.SetViewer("kdehelp");
        m_help.SetViewer("gnome-help-browser");
        m_help.SetViewer("netscape", wxHELP_NETSCAPE);
        @endcode

        @param viewer
            This defaults to "netscape" for wxExtHelpController.
        @param flags
            This defaults to wxHELP_NETSCAPE for wxExtHelpController, indicating
            that the viewer is a variant of Netscape Navigator.

        @todo modernize this function with ::wxLaunchDefaultBrowser
    */
    virtual void SetViewer(const wxString& viewer, long flags);
};

