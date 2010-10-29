/////////////////////////////////////////////////////////////////////////////
// Name:        filepicker.h
// Purpose:     interface of wxFilePickerCtrl
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxFilePickerCtrl

    This control allows the user to select a file. The generic implementation is
    a button which brings up a wxFileDialog when clicked. Native implementation
    may differ but this is usually a (small) widget which give access to the
    file-chooser dialog.
    It is only available if @c wxUSE_FILEPICKERCTRL is set to 1 (the default).

    @beginStyleTable
    @style{wxFLP_DEFAULT_STYLE}
           The default style: includes wxFLP_OPEN | wxFLP_FILE_MUST_EXIST and,
           under wxMSW only, wxFLP_USE_TEXTCTRL.
    @style{wxFLP_USE_TEXTCTRL}
           Creates a text control to the left of the picker button which is
           completely managed by the wxFilePickerCtrl and which can be used by
           the user to specify a path (see SetPath). The text control is
           automatically synchronized with button's value. Use functions
           defined in wxPickerBase to modify the text control.
    @style{wxFLP_OPEN}
           Creates a picker which allows the user to select a file to open.
    @style{wxFLP_SAVE}
           Creates a picker which allows the user to select a file to save.
    @style{wxFLP_OVERWRITE_PROMPT}
           Can be combined with wxFLP_SAVE only: ask confirmation to the user
           before selecting a file.
    @style{wxFLP_FILE_MUST_EXIST}
           Can be combined with wxFLP_OPEN only: the selected file must be an
           existing file.
    @style{wxFLP_CHANGE_DIR}
           Change current working directory on each user file selection change.
    @endStyleTable


    @beginEventEmissionTable{wxFileDirPickerEvent}
    @event{EVT_FILEPICKER_CHANGED(id, func)}
        The user changed the file selected in the control either using the
        button or using text control (see wxFLP_USE_TEXTCTRL; note that in
        this case the event is fired only if the user's input is valid,
        e.g. an existing file path if wxFLP_FILE_MUST_EXIST was given).
    @endEventTable

    @library{wxcore}
    @category{pickers}
    @appearance{filepickerctrl.png}

    @see wxFileDialog, wxFileDirPickerEvent
*/
class wxFilePickerCtrl : public wxPickerBase
{
public:
    /**
        Initializes the object and calls Create() with
        all the parameters.
    */
    wxFilePickerCtrl(wxWindow* parent, wxWindowID id,
                     const wxString& path = wxEmptyString,
                     const wxString& message = wxFileSelectorPromptStr,
                     const wxString& wildcard = wxFileSelectorDefaultWildcardStr,
                     const wxPoint& pos = wxDefaultPosition,
                     const wxSize& size = wxDefaultSize,
                     long style = wxFLP_DEFAULT_STYLE,
                     const wxValidator& validator = wxDefaultValidator,
                     const wxString& name = wxFilePickerCtrlNameStr);

    /**
        Creates this widget with the given parameters.

        @param parent
            Parent window, must not be non-@NULL.
        @param id
            The identifier for the control.
        @param path
            The initial file shown in the control. Must be a valid path to a file or
            the empty string.
        @param message
            The message shown to the user in the wxFileDialog shown by the control.
        @param wildcard
            A wildcard which defines user-selectable files (use the same syntax as for
            wxFileDialog's wildcards).
        @param pos
            Initial position.
        @param size
            Initial size.
        @param style
            The window style, see wxFLP_* flags.
        @param validator
            Validator which can be used for additional data checks.
        @param name
            Control name.

        @return @true if the control was successfully created or @false if
                creation failed.
    */
    bool Create(wxWindow* parent, wxWindowID id,
                const wxString& path = wxEmptyString,
                const wxString& message = wxFileSelectorPromptStr,
                const wxString& wildcard = wxFileSelectorDefaultWildcardStr,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxFLP_DEFAULT_STYLE,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxFilePickerCtrlNameStr);

    /**
        Similar to GetPath() but returns the path of the currently selected
        file as a wxFileName object.
    */
    wxFileName GetFileName() const;

    /**
        Returns the absolute path of the currently selected file.
    */
    wxString GetPath() const;

    /**
        This method does the same thing as SetPath() but takes a wxFileName
        object instead of a string.
    */
    void SetFileName(const wxFileName& filename);

    /**
        Sets the absolute path of the currently selected file.
        This must be a valid file if the @c wxFLP_FILE_MUST_EXIST style was given.
    */
    void SetPath(const wxString& filename);
};



/**
    @class wxDirPickerCtrl

    This control allows the user to select a directory. The generic implementation
    is a button which brings up a wxDirDialog when clicked. Native implementation
    may differ but this is usually a (small) widget which give access to the
    dir-chooser dialog.
    It is only available if @c wxUSE_DIRPICKERCTRL is set to 1 (the default).

    @beginStyleTable
    @style{wxDIRP_DEFAULT_STYLE}
           The default style: includes wxDIRP_DIR_MUST_EXIST and, under wxMSW
           only, wxDIRP_USE_TEXTCTRL.
    @style{wxDIRP_USE_TEXTCTRL}
           Creates a text control to the left of the picker button which is
           completely managed by the wxDirPickerCtrl and which can be used by
           the user to specify a path (see SetPath). The text control is
           automatically synchronized with button's value. Use functions
           defined in wxPickerBase to modify the text control.
    @style{wxDIRP_DIR_MUST_EXIST}
           Creates a picker which allows to select only existing directories.
           wxGTK control always adds this flag internally as it does not
           support its absence.
    @style{wxDIRP_CHANGE_DIR}
           Change current working directory on each user directory selection change.
    @endStyleTable

    @beginEventEmissionTable{wxFileDirPickerEvent}
    @event{EVT_DIRPICKER_CHANGED(id, func)}
        The user changed the directory selected in the control either using the
        button or using text control (see wxDIRP_USE_TEXTCTRL; note that in this
        case the event is fired only if the user's input is valid, e.g. an
        existing directory path).
    @endEventTable


    @library{wxcore}
    @category{pickers}
    @appearance{dirpickerctrl.png}

    @see wxDirDialog, wxFileDirPickerEvent
*/
class wxDirPickerCtrl : public wxPickerBase
{
public:
    /**
        Initializes the object and calls Create() with
        all the parameters.
    */
    wxDirPickerCtrl(wxWindow* parent, wxWindowID id,
                    const wxString& path = wxEmptyString,
                    const wxString& message = wxDirSelectorPromptStr,
                    const wxPoint& pos = wxDefaultPosition,
                    const wxSize& size = wxDefaultSize,
                    long style = wxDIRP_DEFAULT_STYLE,
                    const wxValidator& validator = wxDefaultValidator,
                    const wxString& name = wxDirPickerCtrlNameStr);

    /**
        Creates the widgets with the given parameters.

        @param parent
            Parent window, must not be non-@NULL.
        @param id
            The identifier for the control.
        @param path
            The initial directory shown in the control. Must be a valid path to a
            directory or the empty string.
        @param message
            The message shown to the user in the wxDirDialog shown by the control.
        @param pos
            Initial position.
        @param size
            Initial size.
        @param style
            The window style, see wxDIRP_* flags.
        @param validator
            Validator which can be used for additional date checks.
        @param name
            Control name.

        @return @true if the control was successfully created or @false if
                creation failed.
    */
    bool Create(wxWindow* parent, wxWindowID id,
                const wxString& path = wxEmptyString,
                const wxString& message = wxDirSelectorPromptStr,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxDIRP_DEFAULT_STYLE,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxDirPickerCtrlNameStr);

    /**
        Returns the absolute path of the currently selected directory as a
        wxFileName object.
        This function is equivalent to GetPath().
    */
    wxFileName GetDirName() const;

    /**
        Returns the absolute path of the currently selected directory.
    */
    wxString GetPath() const;

    /**
        Just like SetPath() but this function takes a wxFileName object.
    */
    void SetDirName(const wxFileName& dirname);

    /**
        Sets the absolute path of  (the default converter uses current locale's
        charset)the currently selected directory.
        This must be a valid directory if @c wxDIRP_DIR_MUST_EXIST style was given.
    */
    void SetPath(const wxString& dirname);
};



/**
    @class wxFileDirPickerEvent

    This event class is used for the events generated by
    wxFilePickerCtrl and by wxDirPickerCtrl.

    @beginEventTable{wxFileDirPickerEvent}
    @event{EVT_FILEPICKER_CHANGED(id, func)}
        Generated whenever the selected file changes.
    @event{EVT_DIRPICKER_CHANGED(id, func)}
        Generated whenever the selected directory changes.
    @endEventTable

    @library{wxcore}
    @category{events}

    @see wxFilePickerCtrl, wxDirPickerCtrl
*/
class wxFileDirPickerEvent : public wxCommandEvent
{
public:
    /**
        The constructor is not normally used by the user code.
    */
    wxFileDirPickerEvent(wxEventType type, wxObject* generator,
                         int id,
                         const wxString& path);

    /**
        Retrieve the absolute path of the file/directory the user has just selected.
    */
    wxString GetPath() const;

    /**
        Set the absolute path of the file/directory associated with the event.
    */
    void SetPath(const wxString& path);
};

