/////////////////////////////////////////////////////////////////////////////
// Name:        button.h
// Purpose:     interface of wxButton
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxButton

    A button is a control that contains a text string, and is one of the most
    common elements of a GUI.

    It may be placed on a @ref wxDialog "dialog box" or on a @ref wxPanel panel,
    or indeed on almost any other window.

    @beginStyleTable
    @style{wxBU_LEFT}
        Left-justifies the label. Windows and GTK+ only.
    @style{wxBU_TOP}
        Aligns the label to the top of the button. Windows and GTK+ only.
    @style{wxBU_RIGHT}
        Right-justifies the bitmap label. Windows and GTK+ only.
    @style{wxBU_BOTTOM}
        Aligns the label to the bottom of the button. Windows and GTK+ only.
    @style{wxBU_EXACTFIT}
        Creates the button as small as possible instead of making it of the
        standard size (which is the default behaviour ).
    @style{wxBU_NOTEXT}
        Disables the display of the text label in the button even if it has one
        or its id is one of the standard stock ids with an associated label:
        without using this style a button which is only supposed to show a
        bitmap but uses a standard id would display a label too.
    @style{wxBORDER_NONE}
        Creates a button without border. This is currently implemented in MSW,
        GTK2 and OSX/Carbon ports but in the latter only applies to buttons
        with bitmaps and using bitmap of one of the standard sizes only, namely
        128*128, 48*48, 24*24 or 16*16. In all the other cases wxBORDER_NONE is
        ignored under OSX.
    @endStyleTable

    By default, i.e. if none of the alignment styles are specified, the label
    is centered both horizontally and vertically. If the button has both a
    label and a bitmap, the alignment styles above specify the location of the
    rectangle combining both the label and the bitmap and the bitmap position
    set with wxButton::SetBitmapPosition() defines the relative position of the
    bitmap with respect to the label (however currently non-default alignment
    combinations are not implemented on all platforms).

    @beginEventEmissionTable{wxCommandEvent}
    @event{EVT_BUTTON(id, func)}
           Process a wxEVT_COMMAND_BUTTON_CLICKED event, when the button is clicked.
    @endEventTable


    Since version 2.9.1 wxButton supports showing both text and an image
    (currently only when using wxMSW, wxGTK or wxOSX/Cocoa ports), see
    SetBitmap() and SetBitmapLabel(), SetBitmapDisabled() &c methods. In the
    previous wxWidgets versions this functionality was only available in (the
    now trivial) wxBitmapButton class which was only capable of showing an
    image without text.

    A button may have either a single image for all states or different images
    for the following states (different images are not currently supported
    under OS X where the normal image is used for all states):
    @li @b normal: the default state
    @li @b disabled: bitmap shown when the button is disabled.
    @li @b pressed: bitmap shown when the button is pushed (e.g. while the user
        keeps the mouse button pressed on it)
    @li @b focus: bitmap shown when the button has keyboard focus (but is not
        pressed as in this case the button is in the pressed state)
    @li @b current: bitmap shown when the mouse is over the button (but it is
        not pressed although it may have focus). Notice that if current bitmap
        is not specified but the current platform UI uses hover images for the
        buttons (such as Windows XP or GTK+), then the focus bitmap is used for
        hover state as well. This makes it possible to set focus bitmap only to
        get reasonably good behaviour on all platforms.

    All of the bitmaps must be of the same size and the normal bitmap must be
    set first (to a valid bitmap), before setting any other ones.

    The position of the image inside the button be configured using
    SetBitmapPosition(). By default the image is on the left of the text.

    Please also notice that GTK+ uses a global setting called @c
    gtk-button-images to determine if the images should be shown in the buttons
    at all. If it is off (which is the case in e.g. Gnome 2.28 by default), no
    images will be shown, consistently with the native behaviour.

    @library{wxcore}
    @category{ctrl}
    @appearance{button.png}

    @see wxBitmapButton
*/
class wxButton : public wxControl
{
public:
    /**
        Default ctor.
    */
    wxButton();

    /**
        Constructor, creating and showing a button.

        The preferred way to create standard buttons is to use default value of
        @a label. If no label is supplied and @a id is one of standard IDs from
        @ref page_stockitems "this list", a standard label will be used.

        In addition to that, the button will be decorated with stock icons under GTK+ 2.

        @param parent
            Parent window. Must not be @NULL.
        @param id
            Button identifier. A value of wxID_ANY indicates a default value.
        @param label
            Text to be displayed on the button.
        @param pos
            Button position.
        @param size
            Button size. If the default size is specified then the button is sized
            appropriately for the text.
        @param style
            Window style. See wxButton class description.
        @param validator
            Window validator.
        @param name
            Window name.

        @see Create(), wxValidator
    */
    wxButton(wxWindow* parent, wxWindowID id,
             const wxString& label = wxEmptyString,
             const wxPoint& pos = wxDefaultPosition,
             const wxSize& size = wxDefaultSize,
             long style = 0,
             const wxValidator& validator = wxDefaultValidator,
             const wxString& name = wxButtonNameStr);

    /**
        Button creation function for two-step creation.
        For more details, see wxButton().
    */
    bool Create(wxWindow* parent, wxWindowID id,
                const wxString& label = wxEmptyString,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxButtonNameStr);

    /**
        Returns @true if an authentication needed symbol is displayed on the
        button.

        @remarks This method always returns @false if the platform is not
                 Windows Vista or newer.

        @see SetAuthNeeded()

        @since 2.9.1
     */
    bool GetAuthNeeded() const;

    /**
        Return the bitmap shown by the button.

        The returned bitmap may be invalid only if the button doesn't show any
        images.

        @see SetBitmap()

        @since 2.9.1
     */
    wxBitmap GetBitmap() const;

    /**
        Returns the bitmap used when the mouse is over the button, which may be
        invalid.

        @see SetBitmapCurrent()

        @since 2.9.1 (available as wxBitmapButton::GetBitmapHover() in previous
            versions)
    */
    wxBitmap GetBitmapCurrent() const;

    /**
        Returns the bitmap for the disabled state, which may be invalid.

        @see SetBitmapDisabled()

        @since 2.9.1 (available in wxBitmapButton only in previous versions)
    */
    wxBitmap GetBitmapDisabled() const;

    /**
        Returns the bitmap for the focused state, which may be invalid.

        @see SetBitmapFocus()

        @since 2.9.1 (available in wxBitmapButton only in previous versions)
    */
    wxBitmap GetBitmapFocus() const;

    /**
        Returns the bitmap for the normal state.

        This is exactly the same as GetBitmap() but uses a name
        backwards-compatible with wxBitmapButton.

        @see SetBitmap(), SetBitmapLabel()

        @since 2.9.1 (available in wxBitmapButton only in previous versions)
    */
    wxBitmap GetBitmapLabel() const;

    /**
        Returns the bitmap for the pressed state, which may be invalid.

        @see SetBitmapPressed()

        @since 2.9.1 (available as wxBitmapButton::GetBitmapSelected() in
            previous versions)
    */
    wxBitmap GetBitmapPressed() const;

    /**
        Get the margins between the bitmap and the text of the button.

        @see SetBitmapMargins()

        @since 2.9.1
     */
    wxSize GetBitmapMargins();

    /**
        Returns the default size for the buttons. It is advised to make all the dialog
        buttons of the same size and this function allows to retrieve the (platform and
        current font dependent size) which should be the best suited for this.
    */
    static wxSize GetDefaultSize();

    /**
        Returns the string label for the button.

        @see SetLabel()
    */
    wxString GetLabel() const;

    /**
        Sets whether an authentication needed symbol should be displayed on the
        button.

        @remarks This method doesn't do anything if the platform is not Windows
                 Vista or newer.

        @see GetAuthNeeded()

        @since 2.9.1
     */
    void SetAuthNeeded(bool needed = true);

    /**
        Sets the bitmap to display in the button.

        The bitmap is displayed together with the button label. This method
        sets up a single bitmap which is used in all button states, use
        SetBitmapDisabled(), SetBitmapPressed(), SetBitmapCurrent() or
        SetBitmapFocus() to change the individual images used in different
        states.

        @param bitmap
            The bitmap to display in the button. May be invalid to remove any
            currently displayed bitmap.
        @param dir
            The position of the bitmap inside the button. By default it is
            positioned to the left of the text, near to the left button border.
            Other possible values include wxRIGHT, wxTOP and wxBOTTOM.

        @see SetBitmapPosition(), SetBitmapMargins()

        @since 2.9.1
     */
    void SetBitmap(const wxBitmap& bitmap, wxDirection dir = wxLEFT);

    /**
        Sets the bitmap to be shown when the mouse is over the button.

        @see GetBitmapCurrent()

        @since 2.9.1 (available as wxBitmapButton::SetBitmapHover() in previous
            versions)
    */
    void SetBitmapCurrent(const wxBitmap& bitmap);

    /**
        Sets the bitmap for the disabled button appearance.

        @see GetBitmapDisabled(), SetBitmapLabel(),
             SetBitmapPressed(), SetBitmapFocus()

        @since 2.9.1 (available in wxBitmapButton only in previous versions)
    */
    void SetBitmapDisabled(const wxBitmap& bitmap);

    /**
        Sets the bitmap for the button appearance when it has the keyboard
        focus.

        @see GetBitmapFocus(), SetBitmapLabel(),
             SetBitmapPressed(), SetBitmapDisabled()

        @since 2.9.1 (available in wxBitmapButton only in previous versions)
    */
    void SetBitmapFocus(const wxBitmap& bitmap);

    /**
        Sets the bitmap label for the button.

        @remarks This is the bitmap used for the unselected state, and for all
                 other states if no other bitmaps are provided.

        @see SetBitmap(), GetBitmapLabel()

        @since 2.9.1 (available in wxBitmapButton only in previous versions)
    */
    void SetBitmapLabel(const wxBitmap& bitmap);

    /**
        Sets the bitmap for the selected (depressed) button appearance.

        @since 2.9.1 (available as wxBitmapButton::SetBitmapSelected() in
            previous versions)
    */
    void SetBitmapPressed(const wxBitmap& bitmap);

    /**
        Set the margins between the bitmap and the text of the button.

        This method is currently only implemented under MSW. If it is not
        called, default margin is used around the bitmap.

        @see SetBitmap(), SetBitmapPosition()

        @since 2.9.1
     */
    //@{
    void SetBitmapMargins(wxCoord x, wxCoord y);
    void SetBitmapMargins(const wxSize& sz);
    //@}

    /**
        Set the position at which the bitmap is displayed.

        This method should only be called if the button does have an associated
        bitmap.

        @since 2.9.1

        @param dir
            Direction in which the bitmap should be positioned, one of wxLEFT,
            wxRIGHT, wxTOP or wxBOTTOM.
     */
    void SetBitmapPosition(wxDirection dir);

    /**
        This sets the button to be the default item in its top-level window
        (e.g. the panel or the dialog box containing it).

        As normal, pressing return causes the default button to be depressed when
        the return key is pressed.

        See also wxWindow::SetFocus() which sets the keyboard focus for windows
        and text panel items, and wxTopLevelWindow::SetDefaultItem().

        @remarks Under Windows, only dialog box buttons respond to this function.

        @return the old default item (possibly NULL)
    */
    virtual wxWindow* SetDefault();

    /**
        Sets the string label for the button.

        @param label
            The label to set.
    */
    void SetLabel(const wxString& label);
};

