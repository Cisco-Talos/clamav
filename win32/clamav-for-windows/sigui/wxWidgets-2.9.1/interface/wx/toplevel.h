/////////////////////////////////////////////////////////////////////////////
// Name:        toplevel.h
// Purpose:     interface of wxTopLevelWindow
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    Styles used with wxTopLevelWindow::RequestUserAttention().
*/
enum
{
    wxUSER_ATTENTION_INFO = 1,  ///< Requests user attention,
    wxUSER_ATTENTION_ERROR = 2  ///< Results in a more drastic action.
};

/**
    Styles used with wxTopLevelWindow::ShowFullScreen().
*/
enum
{
    wxFULLSCREEN_NOMENUBAR   = 0x0001,  ///< Don't display the menu bar.
    wxFULLSCREEN_NOTOOLBAR   = 0x0002,  ///< Don't display toolbar bars.
    wxFULLSCREEN_NOSTATUSBAR = 0x0004,  ///< Don't display the status bar.
    wxFULLSCREEN_NOBORDER    = 0x0008,  ///< Don't display any border.
    wxFULLSCREEN_NOCAPTION   = 0x0010,  ///< Don't display a caption.

    /**
        Combination of all above, will display the least possible.
    */
    wxFULLSCREEN_ALL    = wxFULLSCREEN_NOMENUBAR | wxFULLSCREEN_NOTOOLBAR |
                          wxFULLSCREEN_NOSTATUSBAR | wxFULLSCREEN_NOBORDER |
                          wxFULLSCREEN_NOCAPTION
};

/**
    @class wxTopLevelWindow

    wxTopLevelWindow is a common base class for wxDialog and wxFrame. It is an
    abstract base class meaning that you never work with objects of this class
    directly, but all of its methods are also applicable for the two classes
    above.

    Note that the instances of wxTopLevelWindow are managed by wxWidgets in the
    internal top level window list.

    @beginEventEmissionTable
    @event{EVT_ACTIVATE(id, func)}
        Process a @c wxEVT_MAXIMIZE event. See wxMaximizeEvent.
    @event{EVT_MOVE(func)}
        Process a @c wxEVT_MOVE event, which is generated when a window is moved.
        See wxMoveEvent.
    @event{EVT_MOVE_START(func)}
        Process a @c wxEVT_MOVE_START event, which is generated when the user starts
        to move or size a window. wxMSW only.
        See wxMoveEvent.
    @event{EVT_MOVE_END(func)}
        Process a @c wxEVT_MOVE_END event, which is generated when the user stops
        moving or sizing a window. wxMSW only.
        See wxMoveEvent.
    @endEventTable

    @library{wxcore}
    @category{managedwnd}

    @see wxDialog, wxFrame
*/
class wxTopLevelWindow : public wxWindow
{
public:
    /**
        Default ctor.
    */
    wxTopLevelWindow();

    /**
        Constructor creating the top level window.
    */
    wxTopLevelWindow(wxWindow *parent,
                    wxWindowID winid,
                    const wxString& title,
                    const wxPoint& pos = wxDefaultPosition,
                    const wxSize& size = wxDefaultSize,
                    long style = wxDEFAULT_FRAME_STYLE,
                    const wxString& name = wxFrameNameStr);

    /**
        Destructor. Remember that wxTopLevelWindows do not get immediately
        destroyed when the user (or the app) closes them; they have a
        @b delayed destruction.

        See @ref overview_windowdeletion for more info.
    */
    virtual ~wxTopLevelWindow();

    /**
        Creates the top level window.
    */
    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxString& title,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxDEFAULT_FRAME_STYLE,
                const wxString& name = wxFrameNameStr);

    /**
        Returns @true if the platform supports making the window translucent.

        @see SetTransparent()
    */
    virtual bool CanSetTransparent();

    /**
        A synonym for CentreOnScreen().
    */
    void CenterOnScreen(int direction);

    /**
        Centres the window on screen.

        @param direction
            Specifies the direction for the centering. May be @c wxHORIZONTAL,
            @c wxVERTICAL or @c wxBOTH.

        @see wxWindow::CentreOnParent()
    */
    void CentreOnScreen(int direction = wxBOTH);

    /**
        Enables or disables the Close button (most often in the right upper
        corner of a dialog) and the Close entry of the system menu (most often
        in the left upper corner of the dialog).

        Currently only implemented for wxMSW and wxGTK.

        Returns @true if operation was successful. This may be wrong on X11
        (including GTK+) where the window manager may not support this operation
        and there is no way to find out.
    */
    virtual bool EnableCloseButton(bool enable = true);

    /**
        Returns a pointer to the button which is the default for this window, or
        @c @NULL. The default button is the one activated by pressing the Enter
        key.
    */
    wxWindow* GetDefaultItem() const;

    /**
        Returns the standard icon of the window. The icon will be invalid if it
        hadn't been previously set by SetIcon().

        @see GetIcons()
    */
    wxIcon GetIcon() const;

    /**
        Returns all icons associated with the window, there will be none of them
        if neither SetIcon() nor SetIcons() had been called before. Use
        GetIcon() to get the main icon of the window.

        @see wxIconBundle
    */
    const wxIconBundle& GetIcons() const;

    /**
        Gets a string containing the window title.

        @see SetTitle()
    */
    virtual wxString GetTitle() const;

    /**
        Unique to the wxWinCE port. Responds to showing/hiding SIP (soft input
        panel) area and resize window accordingly. Override this if you want to
        avoid resizing or do additional operations.
    */
    virtual bool HandleSettingChange(WXWPARAM wParam,
                                     WXLPARAM lParam);

    /**
        Iconizes or restores the window.

        @param iconize
            If @true, iconizes the window; if @false, shows and restores it.

        @see IsIconized(), Maximize(), wxIconizeEvent.
    */
    virtual void Iconize(bool iconize = true);

    /**
        Returns @true if this window is currently active, i.e. if the user is
        currently working with it.
    */
    virtual bool IsActive();

    /**
        Returns @true if this window is expected to be always maximized, either
        due to platform policy or due to local policy regarding particular
        class.
    */
    virtual bool IsAlwaysMaximized() const;

    /**
        Returns @true if the window is in fullscreen mode.

        @see ShowFullScreen()
    */
    virtual bool IsFullScreen() const;

    /**
        Returns @true if the window is iconized.
    */
    virtual bool IsIconized() const;

    /**
        Returns @true if the window is maximized.
    */
    virtual bool IsMaximized() const;

    /**
        This method is specific to wxUniversal port.

        Returns @true if this window is using native decorations, @false if we
        draw them ourselves.

        @see UseNativeDecorations(),
             UseNativeDecorationsByDefault()
    */
    bool IsUsingNativeDecorations() const;

    /**
        See wxWindow::SetAutoLayout(): when auto layout is on, this function gets
        called automatically when the window is resized.
    */
    virtual bool Layout();

    /**
        Maximizes or restores the window.

        @param maximize
            If @true, maximizes the window, otherwise it restores it.

        @see Iconize()
    */
    virtual void Maximize(bool maximize = true);

    /**
        Use a system-dependent way to attract users attention to the window when
        it is in background.

        @a flags may have the value of either @c ::wxUSER_ATTENTION_INFO
        (default) or @c ::wxUSER_ATTENTION_ERROR which results in a more drastic
        action. When in doubt, use the default value.


        @note This function should normally be only used when the application
              is not already in foreground.

        This function is currently implemented for Win32 where it flashes
        the window icon in the taskbar, and for wxGTK with task bars
        supporting it.

    */
    virtual void RequestUserAttention(int flags = wxUSER_ATTENTION_INFO);

    /**
        Changes the default item for the panel, usually @a win is a button.

        @see GetDefaultItem()
    */
    wxWindow* SetDefaultItem(wxWindow* win);

    /**
        Sets the icon for this window.

        @param icon
            The wxIcon to associate with this window.

        @remarks The window takes a 'copy' of @a icon, but since it uses
                 reference counting, the copy is very quick. It is safe to
                 delete @a icon after calling this function.

        @note In wxMSW, @a icon must be either 16x16 or 32x32 icon.

        @see wxIcon, SetIcons()
    */
    void SetIcon(const wxIcon& icon);

    /**
        Sets several icons of different sizes for this window: this allows to
        use different icons for different situations (e.g. task switching bar,
        taskbar, window title bar) instead of scaling, with possibly bad looking
        results, the only icon set by SetIcon().

        @param icons
            The icons to associate with this window.

        @note In wxMSW, @a icons must contain a 16x16 or 32x32 icon,
              preferably both.

        @see wxIconBundle
    */
    virtual void SetIcons(const wxIconBundle& icons);

    /**
        Sets action or menu activated by pressing left hardware button on the
        smart phones. Unavailable on full keyboard machines.

        @param id
            Identifier for this button.
        @param label
            Text to be displayed on the screen area dedicated to this hardware
            button.
        @param subMenu
            The menu to be opened after pressing this hardware button.

        @see SetRightMenu().
    */
    void SetLeftMenu(int id = wxID_ANY,
                     const wxString& label = wxEmptyString,
                     wxMenu* subMenu = NULL);

    /**
        A simpler interface for setting the size hints than SetSizeHints().
    */
    virtual void SetMaxSize(const wxSize& size);

    /**
        A simpler interface for setting the size hints than SetSizeHints().
    */
    virtual void SetMinSize(const wxSize& size);

    /**
        Sets action or menu activated by pressing right hardware button on the
        smart phones. Unavailable on full keyboard machines.

        @param id
            Identifier for this button.
        @param label
            Text to be displayed on the screen area dedicated to this hardware
            button.
        @param subMenu
            The menu to be opened after pressing this hardware button.

        @see SetLeftMenu().
    */
    void SetRightMenu(int id = wxID_ANY,
                      const wxString& label = wxEmptyString,
                      wxMenu* subMenu = NULL);

    /**
        If the platform supports it, sets the shape of the window to that
        depicted by @a region. The system will not display or respond to any
        mouse event for the pixels that lie outside of the region. To reset the
        window to the normal rectangular shape simply call SetShape() again with
        an empty wxRegion. Returns @true if the operation is successful.
    */
    virtual bool SetShape(const wxRegion& region);

    /**
        Allows specification of minimum and maximum window sizes, and window
        size increments. If a pair of values is not set (or set to -1), no
        constraints will be used.

        @param minW
            The minimum width.
        @param minH
            The minimum height.
        @param maxW
            The maximum width.
        @param maxH
            The maximum height.
        @param incW
            Specifies the increment for sizing the width (GTK/Motif/Xt only).
        @param incH
            Specifies the increment for sizing the height (GTK/Motif/Xt only).

        @remarks Notice that this function not only prevents the user from
                 resizing the window outside the given bounds but it also
                 prevents the program itself from doing it using
                 wxWindow::SetSize().

    */
    virtual void SetSizeHints(int minW, int minH,
                              int maxW = -1, int maxH = -1,
                              int incW = -1, int incH = -1);

    /**
        Allows specification of minimum and maximum window sizes, and window
        size increments. If a pair of values is not set (or set to -1), no
        constraints will be used.

        @param minSize
            The minimum size of the window.
        @param maxSize
            The maximum size of the window.
        @param incSize
            Increment size (only taken into account under X11-based ports such
            as wxGTK/wxMotif/wxX11).

        @remarks Notice that this function not only prevents the user from
                 resizing the window outside the given bounds but it also
                 prevents the program itself from doing it using
                 wxWindow::SetSize().
    */
    void SetSizeHints(const wxSize& minSize,
                      const wxSize& maxSize = wxDefaultSize,
                      const wxSize& incSize = wxDefaultSize);

    /**
        Sets the window title.

        @param title
            The window title.

        @see GetTitle()
    */
    virtual void SetTitle(const wxString& title);

    /**
        If the platform supports it will set the window to be translucent.

        @param alpha
            Determines how opaque or transparent the window will be, if the
            platform supports the opreration. A value of 0 sets the window to be
            fully transparent, and a value of 255 sets the window to be fully
            opaque.
    */
    virtual bool SetTransparent(wxByte alpha);

    /**
        This virtual function is not meant to be called directly but can be
        overridden to return @false (it returns @true by default) to allow the
        application to close even if this, presumably not very important, window
        is still opened. By default, the application stays alive as long as
        there are any open top level windows.
    */
    virtual bool ShouldPreventAppExit() const;
    
    /**
        This function sets the wxTopLevelWindow's modified state on OS X,
        which currently draws a black dot in the wxTopLevelWindow's close button.
        On other platforms, this method does nothing.
        
        @see OSXIsModified()
    */
    virtual void OSXSetModified(bool modified);
    
    /**
        Returns the current modified state of the wxTopLevelWindow on OS X.
        On other platforms, this method does nothing.
        
        @see OSXSetModified()
    */
    virtual bool OSXIsModified() const;

    /**
        Depending on the value of @a show parameter the window is either shown
        full screen or restored to its normal state. @a style is a bit list
        containing some or all of the following values, which indicate what
        elements of the window to hide in full-screen mode:

        - @c ::wxFULLSCREEN_NOMENUBAR
        - @c ::wxFULLSCREEN_NOTOOLBAR
        - @c ::wxFULLSCREEN_NOSTATUSBAR
        - @c ::wxFULLSCREEN_NOBORDER
        - @c ::wxFULLSCREEN_NOCAPTION
        - @c ::wxFULLSCREEN_ALL (all of the above)

        This function has not been tested with MDI frames.

        @note Showing a window full screen also actually @ref wxWindow::Show()
              "Show()"s the window if it isn't shown.

        @see IsFullScreen()
    */
    virtual bool ShowFullScreen(bool show, long style = wxFULLSCREEN_ALL);

    /**
        This method is specific to wxUniversal port.

        Use native or custom-drawn decorations for this window only. Notice that
        to have any effect this method must be called before really creating the
        window, i.e. two step creation must be used:

        @code
        MyFrame *frame = new MyFrame;       // use default ctor
        frame->UseNativeDecorations(false); // change from default "true"
        frame->Create(parent, title, ...);  // really create the frame
        @endcode

        @see UseNativeDecorationsByDefault(),
             IsUsingNativeDecorations()
    */
    void UseNativeDecorations(bool native = true);

    /**
        This method is specific to wxUniversal port.

        Top level windows in wxUniversal port can use either system-provided
        window decorations (i.e. title bar and various icons, buttons and menus
        in it) or draw the decorations themselves. By default the system
        decorations are used if they are available, but this method can be
        called with @a native set to @false to change this for all windows
        created after this point.

        Also note that if @c WXDECOR environment variable is set, then custom
        decorations are used by default and so it may make sense to call this
        method with default argument if the application can't use custom
        decorations at all for some reason.

        @see UseNativeDecorations()
    */
    void UseNativeDecorationsByDefault(bool native = true);
};

