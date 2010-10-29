/////////////////////////////////////////////////////////////////////////////
// Name:        dialog.h
// Purpose:     interface of wxDialog
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    Modes used for wxDialog::SetLayoutAdaptationMode().
*/
enum wxDialogLayoutAdaptationMode
{
    wxDIALOG_ADAPTATION_MODE_DEFAULT = 0,   ///< Use global adaptation enabled status.
    wxDIALOG_ADAPTATION_MODE_ENABLED = 1,   ///< Enable this dialog overriding global status.
    wxDIALOG_ADAPTATION_MODE_DISABLED = 2   ///< Disable this dialog overriding global status.
};

/**
    @class wxDialog

    A dialog box is a window with a title bar and sometimes a system menu,
    which can be moved around the screen. It can contain controls and other
    windows and is often used to allow the user to make some choice or to
    answer a question.

    Dialogs can be made scrollable, automatically, for computers with low
    resolution screens: please see @ref overview_dialog_autoscrolling for
    further details.

    Dialogs usually contains either a single button allowing to close the
    dialog or two buttons, one accepting the changes and the other one
    discarding them (such button, if present, is automatically activated if the
    user presses the "Esc" key). By default, buttons with the standard wxID_OK
    and wxID_CANCEL identifiers behave as expected. Starting with wxWidgets 2.7
    it is also possible to use a button with a different identifier instead,
    see SetAffirmativeId() and SetEscapeId().

    Also notice that the CreateButtonSizer() should be used to create the
    buttons appropriate for the current platform and positioned correctly
    (including their order which is platform-dependent).

    @section dialog_modal Modal and Modeless

    There are two kinds of dialog, modal and modeless. A modal dialog blocks
    program flow and user input on other windows until it is dismissed, whereas
    a modeless dialog behaves more like a frame in that program flow continues,
    and input in other windows is still possible. To show a modal dialog you
    should use the ShowModal() method while to show a dialog modelessly you
    simply use Show(), just as with frames.

    Note that the modal dialog is one of the very few examples of
    wxWindow-derived objects which may be created on the stack and not on the
    heap. In other words, while most windows would be created like this:

    @code
    void AskUser()
    {
        MyAskDialog *dlg = new MyAskDialog(...);
        if ( dlg->ShowModal() == wxID_OK )
            // ...
        //else: dialog was cancelled or some another button pressed

        dlg->Destroy();
    }
    @endcode

    You can achieve the same result with dialogs by using simpler code:

    @code
    void AskUser()
    {
        MyAskDialog dlg(...);
        if ( dlg.ShowModal() == wxID_OK )
            // ...

        // no need to call Destroy() here
    }
    @endcode

    An application can define a wxCloseEvent handler for the dialog to respond
    to system close events.

    @beginStyleTable
    @style{wxCAPTION}
           Puts a caption on the dialog box.
    @style{wxDEFAULT_DIALOG_STYLE}
           Equivalent to a combination of wxCAPTION, wxCLOSE_BOX and
           wxSYSTEM_MENU (the last one is not used under Unix).
    @style{wxRESIZE_BORDER}
           Display a resizeable frame around the window.
    @style{wxSYSTEM_MENU}
           Display a system menu.
    @style{wxCLOSE_BOX}
           Displays a close box on the frame.
    @style{wxMAXIMIZE_BOX}
           Displays a maximize box on the dialog.
    @style{wxMINIMIZE_BOX}
           Displays a minimize box on the dialog.
    @style{wxTHICK_FRAME}
           Display a thick frame around the window.
    @style{wxSTAY_ON_TOP}
           The dialog stays on top of all other windows.
    @style{wxNO_3D}
           Under Windows, specifies that the child controls should not have 3D
           borders unless specified in the control.
    @style{wxDIALOG_NO_PARENT}
           By default, a dialog created with a @NULL parent window will be
           given the @ref wxApp::GetTopWindow() "application's top level window"
           as parent. Use this style to prevent this from happening and create
           an orphan dialog. This is not recommended for modal dialogs.
    @style{wxDIALOG_EX_CONTEXTHELP}
           Under Windows, puts a query button on the caption. When pressed,
           Windows will go into a context-sensitive help mode and wxWidgets
           will send a wxEVT_HELP event if the user clicked on an application
           window. Note that this is an extended style and must be set by
           calling SetExtraStyle() before Create is called (two-step
           construction).
    @style{wxDIALOG_EX_METAL}
           On Mac OS X, frames with this style will be shown with a metallic
           look. This is an extra style.
    @endStyleTable

    Under Unix or Linux, MWM (the Motif Window Manager) or other window
    managers recognizing the MHM hints should be running for any of these
    styles to have an effect.


    @beginEventEmissionTable{wxCloseEvent}
    @event{EVT_CLOSE(func)}
        The dialog is being closed by the user or programmatically (see wxWindow::Close).
        The user may generate this event clicking the close button
        (typically the 'X' on the top-right of the title bar) if it's present
        (see the @c wxCLOSE_BOX style) or by clicking a button with the
        @c wxID_CANCEL or @c wxID_OK ids.
    @event{EVT_INIT_DIALOG(func)}
        Process a @c wxEVT_INIT_DIALOG event. See wxInitDialogEvent.
    @endEventTable

    @library{wxcore}
    @category{cmndlg}

    @see @ref overview_dialog, wxFrame, @ref overview_validator
*/
class wxDialog : public wxTopLevelWindow
{
public:
    /**
        Default constructor.
    */
    wxDialog();
    /**
        Constructor.

        @param parent
            Can be @NULL, a frame or another dialog box.
        @param id
            An identifier for the dialog. A value of -1 is taken to mean a
            default.
        @param title
            The title of the dialog.
        @param pos
            The dialog position. The value wxDefaultPosition indicates a
            default position, chosen by either the windowing system or
            wxWidgets, depending on platform.
        @param size
            The dialog size. The value wxDefaultSize indicates a default size,
            chosen by either the windowing system or wxWidgets, depending on
            platform.
        @param style
            The window style.
        @param name
            Used to associate a name with the window, allowing the application
            user to set Motif resource values for individual dialog boxes.

        @see Create()
    */
    wxDialog(wxWindow* parent, wxWindowID id, const wxString& title,
             const wxPoint& pos = wxDefaultPosition,
             const wxSize& size = wxDefaultSize,
             long style = wxDEFAULT_DIALOG_STYLE,
             const wxString& name = wxDialogNameStr);

    /**
        Destructor.

        Deletes any child windows before deleting the physical window.

        See @ref overview_windowdeletion for more info.
    */
    virtual ~wxDialog();

    /**
        Adds an identifier to be regarded as a main button for the
        non-scrolling area of a dialog.

        @see @ref overview_dialog_autoscrolling (for more on layout adaptation)
    */
    void AddMainButtonId(wxWindowID id);

    /**
        Returns @true if this dialog can and should perform layout adaptation
        using DoLayoutAdaptation(), usually if the dialog is too large to fit
        on the display.

        @see @ref overview_dialog_autoscrolling (for more on layout adaptation)
    */
    virtual bool CanDoLayoutAdaptation();

    /**
        Centres the dialog box on the display.

        @param direction
            May be wxHORIZONTAL, wxVERTICAL or wxBOTH.
    */
    void Centre(int direction = wxBOTH);

    /**
        Used for two-step dialog box construction.

        @see wxDialog()
    */
    bool Create(wxWindow* parent, wxWindowID id, const wxString& title,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxDEFAULT_DIALOG_STYLE,
                const wxString& name = wxDialogNameStr);

    /**
        Creates a sizer with standard buttons. @a flags is a bit list of the
        following flags: wxOK, wxCANCEL, wxYES, wxNO, wxAPPLY, wxCLOSE, wxHELP,
        wxNO_DEFAULT.

        The sizer lays out the buttons in a manner appropriate to the platform.

        This function uses CreateStdDialogButtonSizer() internally for most
        platforms but doesn't create the sizer at all for the platforms with
        hardware buttons (such as smartphones) for which it sets up the
        hardware buttons appropriately and returns @NULL, so don't forget to
        test that the return value is valid before using it.
    */
    wxSizer* CreateButtonSizer(long flags);

    /**
        Creates a sizer with standard buttons using CreateButtonSizer()
        separated from the rest of the dialog contents by a horizontal
        wxStaticLine.

        @note Just like CreateButtonSizer(), this function may return @NULL if
              no buttons were created.
    */
    wxSizer* CreateSeparatedButtonSizer(long flags);

    /**
        Creates a wxStdDialogButtonSizer with standard buttons. @a flags is a
        bit list of the following flags: wxOK, wxCANCEL, wxYES, wxNO, wxAPPLY,
        wxCLOSE, wxHELP, wxNO_DEFAULT.

        The sizer lays out the buttons in a manner appropriate to the platform.
    */
    wxStdDialogButtonSizer* CreateStdDialogButtonSizer(long flags);

    /**
        Performs layout adaptation, usually if the dialog is too large to fit
        on the display.

        @see @ref overview_dialog_autoscrolling (for more on layout adaptation)
    */
    virtual bool DoLayoutAdaptation();

    /**
        This function is called when the titlebar OK button is pressed
        (PocketPC only). A command event for the identifier returned by
        GetAffirmativeId() is sent by default. You can override this function.
        If the function returns @false, wxWidgets will call Close() for the
        dialog.

        @onlyfor{wxmsw}
    */
    virtual bool DoOK();

    /**
        A static function enabling or disabling layout adaptation for all
        dialogs.

        @see @ref overview_dialog_autoscrolling (for more on layout adaptation)
    */
    static void EnableLayoutAdaptation(bool enable);

    /**
        Ends a modal dialog, passing a value to be returned from the
        ShowModal() invocation.

        @param retCode
            The value that should be returned by ShowModal.

        @see ShowModal(), GetReturnCode(), SetReturnCode()
    */
    virtual void EndModal(int retCode);

    /**
        Gets the identifier of the button which works like standard OK button
        in this dialog.

        @see SetAffirmativeId()
    */
    int GetAffirmativeId() const;

    /**
        Override this to return a window containing the main content of the
        dialog. This is particularly useful when the dialog implements pages,
        such as wxPropertySheetDialog, and allows the
        @ref overview_dialog "layout adaptation code" to know that only the
        pages need to be made scrollable.
    */
    virtual wxWindow* GetContentWindow() const;

    /**
        Gets the identifier of the button to map presses of @c ESC button to.

        @see SetEscapeId()
    */
    int GetEscapeId() const;

    /**
        Returns @true if the dialog has been adapted, usually by making it
        scrollable to work with a small display.

        @see @ref overview_dialog_autoscrolling (for more on layout adaptation)
    */
    bool GetLayoutAdaptationDone() const;

    /**
        Gets a value representing the aggressiveness of search for buttons and
        sizers to be in the non-scrolling part of a layout-adapted dialog. Zero
        switches off adaptation, and 3 allows search for standard buttons
        anywhere in the dialog.

        @see @ref overview_dialog_autoscrolling (for more on layout adaptation)
    */
    int GetLayoutAdaptationLevel() const;

    /**
        Gets the adaptation mode, overriding the global adaptation flag.

        @see @ref overview_dialog_autoscrolling (for more on layout adaptation)
    */
    wxDialogLayoutAdaptationMode GetLayoutAdaptationMode() const;

    /**
        A static function getting the current layout adapter object.

        @see @ref overview_dialog_autoscrolling (for more on layout adaptation)
    */
    static wxDialogLayoutAdapter* GetLayoutAdapter();

    /**
        Returns an array of identifiers to be regarded as the main buttons for
        the non-scrolling area of a dialog.

        @see @ref overview_dialog_autoscrolling (for more on layout adaptation)
    */
    wxArrayInt& GetMainButtonIds();

    /**
        Gets the return code for this window.

        @remarks A return code is normally associated with a modal dialog,
                 where ShowModal() returns a code to the application.

        @see SetReturnCode(), ShowModal(), EndModal()
    */
    int GetReturnCode() const;

    /**
        On PocketPC, a dialog is automatically provided with an empty toolbar.
        This function allows you to access the toolbar and add tools to it.
        Removing tools and adding arbitrary controls are not currently
        supported.

        This function is not available on any other platform.

        @onlyfor{wxmsw}
    */
    wxToolBar* GetToolBar() const;

    /**
        Iconizes or restores the dialog. Windows only.

        @param iconize
            If @true, iconizes the dialog box; if @false, shows and restores it.

        @remarks Note that in Windows, iconization has no effect since dialog
                 boxes cannot be iconized. However, applications may need to
                 explicitly restore dialog boxes under Motif which have
                 user-iconizable frames, and under Windows calling
                 Iconize(@false) will bring the window to the front, as does
                 Show(@true).
    */
    virtual void Iconize(bool iconize = true);

    /**
        Returns @true if the dialog box is iconized. Windows only.

        @remarks Always returns @false under Windows since dialogs cannot be
                 iconized.
    */
    virtual bool IsIconized() const;

    /**
        A static function returning @true if layout adaptation is enabled for
        all dialogs.

        @see @ref overview_dialog_autoscrolling (for more on layout adaptation)
    */
    static bool IsLayoutAdaptationEnabled();

    /**
        Returns @true if @a id is in the array of identifiers to be regarded as
        the main buttons for the non-scrolling area of a dialog.

        @onlyfor{wxmsw}

        @see @ref overview_dialog_autoscrolling (for more on layout adaptation)
    */
    bool IsMainButtonId(wxWindowID id) const;

    /**
        Returns @true if the dialog box is modal, @false otherwise.
    */
    virtual bool IsModal() const;

    /**
        The default handler for wxEVT_SYS_COLOUR_CHANGED.

        @param event
            The colour change event.

        @remarks Changes the dialog's colour to conform to the current settings
                 (Windows only). Add an event table entry for your dialog class
                 if you wish the behaviour to be different (such as keeping a
                 user-defined background colour). If you do override this
                 function, call wxEvent::Skip() to propagate the notification
                 to child windows and controls.

        @see wxSysColourChangedEvent
    */
    void OnSysColourChanged(wxSysColourChangedEvent& event);

    /**
        Sets the identifier to be used as OK button. When the button with this
        identifier is pressed, the dialog calls wxWindow::Validate() and
        wxWindow::TransferDataFromWindow() and, if they both return @true,
        closes the dialog with wxID_OK return code.

        Also, when the user presses a hardware OK button on the devices having
        one or the special OK button in the PocketPC title bar, an event with
        this id is generated.

        By default, the affirmative id is wxID_OK.

        @see GetAffirmativeId(), SetEscapeId()
    */
    void SetAffirmativeId(int id);

    /**
        Sets the identifier of the button which should work like the standard
        "Cancel" button in this dialog. When the button with this id is
        clicked, the dialog is closed. Also, when the user presses @c ESC key
        in the dialog or closes the dialog using the close button in the title
        bar, this is mapped to the click of the button with the specified id.

        By default, the escape id is the special value wxID_ANY meaning that
        wxID_CANCEL button is used if it's present in the dialog and otherwise
        the button with GetAffirmativeId() is used. Another special value for
        @a id is wxID_NONE meaning that @c ESC presses should be ignored. If
        any other value is given, it is interpreted as the id of the button to
        map the escape key to.
    */
    void SetEscapeId(int id);

    /**
        Sets the icon for this dialog.

        @param icon
            The icon to associate with this dialog.

        @see wxIcon
    */
    void SetIcon(const wxIcon& icon);

    /**
        Sets the icons for this dialog.

        @param icons
            The icons to associate with this dialog.

        @see wxIconBundle
    */
    void SetIcons(const wxIconBundle& icons);

    /**
        Marks the dialog as having been adapted, usually by making it
        scrollable to work with a small display.

        @see @ref overview_dialog_autoscrolling (for more on layout adaptation)
    */
    void SetLayoutAdaptationDone(bool done);

    /**
        Sets the aggressiveness of search for buttons and sizers to be in the
        non-scrolling part of a layout-adapted dialog. Zero switches off
        adaptation, and 3 allows search for standard buttons anywhere in the
        dialog.

        @see @ref overview_dialog_autoscrolling (for more on layout adaptation)
    */
    void SetLayoutAdaptationLevel(int level);

    /**
        Sets the adaptation mode, overriding the global adaptation flag.

        @see wxDialogLayoutAdaptationMode, @ref overview_dialog_autoscrolling
             (for more on layout adaptation)
    */
    void SetLayoutAdaptationMode(wxDialogLayoutAdaptationMode mode);

    /**
        A static function for setting the current layout adapter object,
        returning the old adapter. If you call this, you should delete the old
        adapter object.

        @see wxDialogLayoutAdapter, @ref overview_dialog_autoscrolling
    */
    static wxDialogLayoutAdapter* SetLayoutAdapter(wxDialogLayoutAdapter* adapter);

    /**
        @deprecated This function doesn't work for all ports, just use
                    ShowModal() to show a modal dialog instead.

        Allows the programmer to specify whether the dialog box is modal
        (Show() blocks control until the dialog is hidden) or modeless (control
        returns immediately).

        @param flag
            If @true, the dialog will be modal, otherwise it will be modeless.
    */
    void SetModal(bool flag);

    /**
        Sets the return code for this window.

        A return code is normally associated with a modal dialog, where
        ShowModal() returns a code to the application. The function EndModal()
        calls SetReturnCode().

        @param retCode
            The integer return code, usually a control identifier.

        @see GetReturnCode(), ShowModal(), EndModal()
    */
    void SetReturnCode(int retCode);

    /**
        Hides or shows the dialog. The preferred way of dismissing a modal
        dialog is to use EndModal().

        @param show
            If @true, the dialog box is shown and brought to the front,
            otherwise the box is hidden. If @false and the dialog is modal,
            control is returned to the calling program.
    */
    virtual bool Show(bool show = 1);

    /**
        Shows a modal dialog.

        Program flow does not return until the dialog has been dismissed with
        EndModal().

        Notice that it is possible to call ShowModal() for a dialog which had
        been previously shown with Show(), this allows to make an existing
        modeless dialog modal. However ShowModal() can't be called twice
        without intervening EndModal() calls.

        Note that this function creates a temporary event loop which takes
        precedence over the application's main event loop (see wxEventLoopBase)
        and which is destroyed when the dialog is dismissed.
        This also results in a call to wxApp::ProcessPendingEvents().

        @return The value set with SetReturnCode().

        @see EndModal(), GetReturnCode(), SetReturnCode()
    */
    virtual int ShowModal();
};



/**
    @class wxDialogLayoutAdapter

    This abstract class is the base for classes that help wxWidgets peform
    run-time layout adaptation of dialogs. Principally, this is to cater for
    small displays by making part of the dialog scroll, but the application
    developer may find other uses for layout adaption.

    By default, there is one instance of wxStandardDialogLayoutAdapter which
    can perform adaptation for most custom dialogs and dialogs with book
    controls such as wxPropertySheetDialog.

    @library{wxcore}
    @category{winlayout}

    @see @ref overview_dialog_autoscrolling
*/
class wxDialogLayoutAdapter
{
public:
    /**
        Default constructor.
    */
    wxDialogLayoutAdapter();

    /**
        Override this to returns @true if adaptation can and should be done.
    */
    virtual bool CanDoLayoutAdaptation(wxDialog* dialog) = 0;

    /**
        Override this to perform layout adaptation, such as making parts of the
        dialog scroll and resizing the dialog to fit the display. Normally this
        function will be called just before the dialog is shown.
    */
    virtual bool DoLayoutAdaptation(wxDialog* dialog) = 0;
};

