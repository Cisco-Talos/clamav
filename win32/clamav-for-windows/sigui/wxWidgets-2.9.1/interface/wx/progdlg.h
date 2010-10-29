/////////////////////////////////////////////////////////////////////////////
// Name:        progdlg.h
// Purpose:     interface of wxProgressDialog
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxProgressDialog

    This class represents a dialog that shows a short message and a
    progress bar. Optionally, it can display ABORT and SKIP buttons, and
    the elapsed, remaining and estimated time for the end of the progress.

    Note that you must be aware that wxProgressDialog internally calls
    wxEventLoopBase::YieldFor with @c wxEVT_CATEGORY_UI and @c wxEVT_CATEGORY_USER_INPUT
    and this may cause unwanted re-entrancies or the out-of-order processing
    of pending events (to help preventing the last problem if you're using
    wxProgressDialog in a multi-threaded application you should be sure to use
    wxThreadEvent for your inter-threads communications).

    @beginStyleTable
    @style{wxPD_APP_MODAL}
           Make the progress dialog modal. If this flag is not given, it is
           only "locally" modal - that is the input to the parent window is
           disabled, but not to the other ones.
    @style{wxPD_AUTO_HIDE}
           Causes the progress dialog to disappear from screen as soon as the
           maximum value of the progress meter has been reached.
           If this style is not present, the dialog will become a modal dialog
           (see wxDialog::ShowModal) once the maximum value has been reached;
           this results in processing of pending events and may cause
           unwanted re-entrancies.
    @style{wxPD_SMOOTH}
           Causes smooth progress of the gauge control (uses a wxGauge with the
           @c wxGA_SMOOTH style).
    @style{wxPD_CAN_ABORT}
           This flag tells the dialog that it should have a "Cancel" button
           which the user may press. If this happens, the next call to
           Update() will return @false.
    @style{wxPD_CAN_SKIP}
           This flag tells the dialog that it should have a "Skip" button
           which the user may press. If this happens, the next call to
           Update() will return @true in its skip parameter.
    @style{wxPD_ELAPSED_TIME}
           This flag tells the dialog that it should show elapsed time (since
           creating the dialog).
    @style{wxPD_ESTIMATED_TIME}
           This flag tells the dialog that it should show estimated time.
    @style{wxPD_REMAINING_TIME}
           This flag tells the dialog that it should show remaining time.
    @endStyleTable

    @library{wxbase}
    @category{cmndlg}
*/
class wxProgressDialog : public wxDialog
{
public:
    /**
        Constructor. Creates the dialog, displays it and disables user input
        for other windows, or, if @c wxPD_APP_MODAL flag is not given, for its
        parent window only.

        @param title
            Dialog title to show in titlebar.
        @param message
            Message displayed above the progress bar.
        @param maximum
            Maximum value for the progress bar.
            In the generic implementation the progress bar is constructed
            only if this value is greater than zero.
        @param parent
            Parent window.
        @param style
            The dialog style. See wxProgressDialog.
    */
    wxProgressDialog(const wxString& title, const wxString& message,
                     int maximum = 100,
                     wxWindow* parent = NULL,
                     int style = wxPD_AUTO_HIDE | wxPD_APP_MODAL);

    /**
        Destructor. Deletes the dialog and enables all top level windows.
    */
    virtual ~wxProgressDialog();

    /**
        Returns the last value passed to the Update() function or
        @c wxNOT_FOUND if the dialog has no progress bar.

        @since 2.9.0
    */
    int GetValue() const;

    /**
        Returns the maximum value of the progress meter, as passed to
        the constructor or @c wxNOT_FOUND if the dialog has no progress bar.

        @since 2.9.0
    */
    int GetRange() const;

    /**
        Returns the last message passed to the Update() function;
        if you always passed wxEmptyString to Update() then the message
        set through the constructor is returned.

        @since 2.9.0
    */
    wxString GetMessage() const;

    /**
        Like Update() but makes the gauge control run in indeterminate mode.

        In indeterminate mode the remaining and the estimated time labels (if
        present) are set to to "Unknown" or to @a newmsg (if it's non-empty).
        Each call to this function moves the progress bar a bit to indicate
        that some progress was done.

        @see wxGauge::Pulse(), Update()
    */
    virtual bool Pulse(const wxString& newmsg = wxEmptyString, bool* skip = NULL);

    /**
        Can be used to continue with the dialog, after the user had clicked the "Abort" button.
    */
    void Resume();

    /**
        Changes the maximum value of the progress meter given in the constructor.
        This function can only be called (with a positive value) if the value passed 
        in the constructor was positive.

        @since 2.9.1
    */
    void SetRange(int maximum);


      /**
         Returns true if the "Cancel" button was pressed.

         Normally a Cancel button press is indicated by Update() returning
         @false but sometimes it may be more convenient to check if the dialog
         was cancelled from elsewhere in the code and this function allows to
         do it.

         It always returns @false if the Cancel button is not shown at all.

         @since 2.9.1
     */
    bool WasCancelled() const;

     /**
         Returns true if the "Skip" button was pressed.

         This is similar to WasCancelled() but returns @true if the "Skip"
         button was pressed, not the "Cancel" one.

         @since 2.9.1
     */
    bool WasSkipped() const;


    /**
        Updates the dialog, setting the progress bar to the new value and
        updating the message if new one is specified.

        Returns @true unless the "Cancel" button has been pressed.

        If @false is returned, the application can either immediately destroy the
        dialog or ask the user for the confirmation and if the abort is not confirmed
        the dialog may be resumed with Resume() function.

        Notice that you may want to call Fit() to change the dialog size to
        conform to the length of the new message if desired. The dialog does
        not do this automatically.

        @param value
            The new value of the progress meter. It should be less than or equal to
            the maximum value given to the constructor.
            See @c wxPD_AUTO_HIDE style for more info about the behaviour of
            wxProgressDialog when @a value is the maximum value given in the ctor.
        @param newmsg
            The new messages for the progress dialog text, if it is
            empty (which is the default) the message is not changed.
        @param skip
            If "Skip" button was pressed since last Update() call,
            this is set to @true.
    */
    virtual bool Update(int value, const wxString& newmsg = wxEmptyString,
                        bool* skip = NULL);
};

