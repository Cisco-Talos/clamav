/////////////////////////////////////////////////////////////////////////////
// Name:        msgdlg.h
// Purpose:     interface of wxMessageDialog
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxMessageDialog

    This class represents a dialog that shows a single or multi-line message,
    with a choice of OK, Yes, No and Cancel buttons.

    @beginStyleTable
    @style{wxOK}
        Puts an Ok button in the message box. May be combined with @c wxCANCEL.
    @style{wxCANCEL}
        Puts a Cancel button in the message box. Must be combined with
        either @c wxOK or @c wxYES_NO.
    @style{wxYES_NO}
        Puts Yes and No buttons in the message box. It is recommended to always
        use @c wxCANCEL with this style as otherwise the message box won't have
        a close button under wxMSW and the user will be forced to answer it.
    @style{wxNO_DEFAULT}
        Makes the "No" button default, can only be used with @c wxYES_NO.
    @style{wxCANCEL_DEFAULT}
        Makes the "Cancel" button default, can only be used with @c wxCANCEL
    @style{wxYES_DEFAULT}
        Makes the "Yes" button default, this is the default behaviour and
        this flag exists solely for symmetry with @c wxNO_DEFAULT.
    @style{wxOK_DEFAULT}
        Makes the "OK" button default, this is the default behaviour and
        this flag exists solely for symmetry with @c wxCANCEL_DEFAULT.
    @style{wxICON_NONE}
        Displays no icon in the dialog if possible (an icon might still be
        displayed if the current platform mandates its use). This style may be
        used to prevent the dialog from using the default icon based on @c
        wxYES_NO presence as explained in @c wxICON_QUESTION and @c
        wxICON_INFORMATION documentation below.
    @style{wxICON_EXCLAMATION}
        Displays an exclamation, or warning, icon in the dialog.
    @style{wxICON_ERROR}
        Displays an error icon in the dialog.
    @style{wxICON_HAND}
        Displays an error symbol, this is a MSW-inspired synonym for @c wxICON_ERROR.
    @style{wxICON_QUESTION}
        Displays a question mark symbol. This icon is automatically used
        with @c wxYES_NO so it's usually unnecessary to specify it explicitly.
    @style{wxICON_INFORMATION}
        Displays an information symbol. This icon is used by default if
        @c wxYES_NO is not given so it is usually unnecessary to specify it
        explicitly.
    @style{wxSTAY_ON_TOP}
        Makes the message box stay on top of all other windows and not only
        just its parent (currently implemented only under MSW and GTK).
    @style{wxCENTRE}
        Centre the message box on its parent or on the screen if parent is not
        specified (currently only implemented under MSW).
    @endStyleTable

    @library{wxcore}
    @category{cmndlg}

    @see @ref overview_cmndlg_msg
*/
class wxMessageDialog : public wxDialog
{
public:
    /**
        Constructor specifying the message box properties.
        Use ShowModal() to show the dialog.

        @a style may be a bit list of the identifiers described above.

        Notice that not all styles are compatible: only one of @c wxOK and
        @c wxYES_NO may be specified (and one of them must be specified) and at
        most one default button style can be used and it is only valid if the
        corresponding button is shown in the message box.

        @param parent
            Parent window.
        @param message
            Message to show in the dialog.
        @param caption
            The dialog title.
        @param style
            Combination of style flags described above.
        @param pos
            Dialog position (ignored under MSW).
    */
    wxMessageDialog(wxWindow* parent, const wxString& message,
                    const wxString& caption = wxMessageBoxCaptionStr,
                    long style = wxOK | wxCENTRE,
                    const wxPoint& pos = wxDefaultPosition);

    /**
        Sets the extended message for the dialog: this message is usually an
        extension of the short message specified in the constructor or set with
        SetMessage().

        If it is set, the main message appears highlighted -- if supported --
        and this message appears beneath it in normal font. On the platforms
        which don't support extended messages, it is simply appended to the
        normal message with an empty line separating them.

        @since 2.9.0
    */
    virtual void SetExtendedMessage(const wxString& extendedMessage);

    /**
        Sets the message shown by the dialog.

        @since 2.9.0
    */
    virtual void SetMessage(const wxString& message);

    /**
        Overrides the default labels of the OK and Cancel buttons.

        Please see the remarks in SetYesNoLabels() documentation.

        @since 2.9.0
    */
    virtual bool SetOKCancelLabels(const ButtonLabel& ok,
                                   const ButtonLabel& cancel);

    /**
        Overrides the default label of the OK button.

        Please see the remarks in SetYesNoLabels() documentation.

        @since 2.9.0
    */
    virtual bool SetOKLabel(const ButtonLabel& ok);

    /**
        Overrides the default labels of the Yes, No and Cancel buttons.

        Please see the remarks in SetYesNoLabels() documentation.

        @since 2.9.0
    */
    virtual bool SetYesNoCancelLabels(const ButtonLabel& yes,
                                      const ButtonLabel& no,
                                      const ButtonLabel& cancel);

    /**
        Overrides the default labels of the Yes and No buttons.

        The arguments of this function can be either strings or one of the
        standard identifiers, such as @c wxID_APPLY or @c wxID_OPEN. Notice
        that even if the label is specified as an identifier, the return value
        of the dialog ShowModal() method still remains one of @c wxID_OK, @c
        wxID_CANCEL, @c wxID_YES or @c wxID_NO values, i.e. this identifier
        changes only the label appearance but not the return code generated by
        the button. It is possible to mix stock identifiers and string labels
        in the same function call, for example:
        @code
        wxMessageDialog dlg(...);
        dlg.SetYesNoLabels(wxID_SAVE, _("&Don't save"));
        @endcode

        Also notice that this function is not currently available on all
        platforms (although as of wxWidgets 2.9.0 it is implemented in all
        major ports), so it may return @false to indicate that the labels
        couldn't be changed. If it returns @true, the labels were set
        successfully.

        Typically, if the function was used successfully, the main dialog
        message may need to be changed, e.g.:
        @code
        wxMessageDialog dlg(...);
        if ( dlg.SetYesNoLabels(_("&Quit"), _("&Don't quit")) )
            dlg.SetMessage(_("What do you want to do?"));
        else // buttons have standard "Yes"/"No" values, so rephrase the question
            dlg.SetMessage(_("Do you really want to quit?"));
        @endcode

        @since 2.9.0
    */
    virtual bool SetYesNoLabels(const ButtonLabel& yes, const ButtonLabel& no);

    /**
        Shows the dialog, returning one of wxID_OK, wxID_CANCEL, wxID_YES, wxID_NO.

        Notice that this method returns the identifier of the button which was
        clicked unlike wxMessageBox() function.
    */
    virtual int ShowModal();
};



// ============================================================================
// Global functions/macros
// ============================================================================

/** @addtogroup group_funcmacro_dialog */
//@{

/**
    Show a general purpose message dialog.

    This is a convenient function which is usually used instead of using
    wxMessageDialog directly. Notice however that some of the features, such as
    extended text and custom labels for the message box buttons, are not
    provided by this function but only by wxMessageDialog.

    The return value is one of: @c wxYES, @c wxNO, @c wxCANCEL or @c wxOK
    (notice that this return value is @b different from the return value of
    wxMessageDialog::ShowModal()).

    For example:
    @code
    int answer = wxMessageBox("Quit program?", "Confirm",
                              wxYES_NO | wxCANCEL, main_frame);
    if (answer == wxYES)
        main_frame->Close();
    @endcode

    @a message may contain newline characters, in which case the message will
    be split into separate lines, to cater for large messages.

    @param message
        Message to show in the dialog.
    @param caption
        The dialog title.
    @param parent
        Parent window.
    @param style
        Combination of style flags described in wxMessageDialog documentation.
    @param x
        Horizontal dialog position (ignored under MSW). Use ::wxDefaultCoord
        for @a x and @a y to let the system position the window.
    @param y
        Vertical dialog position (ignored under MSW).
    @header{wx/msgdlg.h}
*/
int wxMessageBox(const wxString& message,
                 const wxString& caption = "Message",
                 int style = wxOK,
                 wxWindow* parent = NULL,
                 int x = wxDefaultCoord,
                 int y = wxDefaultCoord);

//@}

