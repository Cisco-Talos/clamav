/////////////////////////////////////////////////////////////////////////////
// Name:        pickerbase.h
// Purpose:     interface of wxPickerBase
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxPickerBase

    Base abstract class for all pickers which support an auxiliary text control.

    This class handles all positioning and sizing of the text control like a
    an horizontal wxBoxSizer would do, with the text control on the left of the
    picker button.

    The proportion (see wxSizer documentation for more info about proportion values)
    of the picker control defaults to 1 when there isn't a text control associated
    (see @c wxPB_USE_TEXTCTRL style) and to 0 otherwise.

    @beginStyleTable
    @style{wxPB_USE_TEXTCTRL}
           Creates a text control to the left of the picker which is
           completely managed by this wxPickerBase class.
    @endStyleTable

    @library{wxcore}
    @category{pickers}

    @see wxColourPickerCtrl
*/
class wxPickerBase : public wxControl
{
public:
    /**
        Returns the margin (in pixel) between the picker and the text control.

        This function can be used only when HasTextCtrl() returns @true.
    */
    int GetInternalMargin() const;

    /**
        Returns the proportion value of the picker.
    */
    int GetPickerCtrlProportion() const;

    /**
        Returns a pointer to the text control handled by this window or @NULL if the
        @c wxPB_USE_TEXTCTRL style was not specified when this control was created.

        @remarks
        The contents of the text control could be an invalid representation of
        the entity which can be chosen through the picker
        (e.g. when the user enters an invalid colour syntax because of a typo).
        Thus you should never parse the content of the textctrl to get the
        user's input; rather use the derived-class getter
        (e.g. wxColourPickerCtrl::GetColour(), wxFilePickerCtrl::GetPath(), etc).
    */
    wxTextCtrl* GetTextCtrl();

    /**
        Returns the native implementation of the real picker control.

        @note
        The returned control in the generic implementation of wxFilePickerCtrl,
        wxDirPickerCtrl, wxFontPickerCtrl and wxColourPickerCtrl is a specialized
        wxButton class so that you can change its label doing, e.g.:
        @code
            #ifdef __WXMSW__
                // wxMSW is one of the platforms where the generic implementation
                // of wxFilePickerCtrl is used...

                wxButton *pButt = wx_static_cast(wxButton*, myFilePickerCtrl->GetPickerCtrl());
                if (pButt)
                    pButt->SetLabel("Custom browse string");
            #endif
        @endcode
    */
    wxControl* GetPickerCtrl();

    /**
        Returns the proportion value of the text control.

        This function can be used only when HasTextCtrl() returns @true.
    */
    int GetTextCtrlProportion() const;

    /**
        Returns @true if this window has a valid text control (i.e. if the @c
        wxPB_USE_TEXTCTRL style was given when creating this control).
    */
    bool HasTextCtrl() const;

    /**
        Returns @true if the picker control is growable.
    */
    bool IsPickerCtrlGrowable() const;

    /**
        Returns @true if the text control is growable.

        This function can be used only when HasTextCtrl() returns @true.
    */
    bool IsTextCtrlGrowable() const;

    /**
        Sets the margin (in pixel) between the picker and the text control.

        This function can be used only when HasTextCtrl() returns @true.
    */
    void SetInternalMargin(int margin);

    /**
        Sets the picker control as growable when @c grow is @true.
    */
    void SetPickerCtrlGrowable(bool grow = true);

    /**
        Sets the proportion value of the picker.

        Look at the detailed description of wxPickerBase for more info.
    */
    void SetPickerCtrlProportion(int prop);

    /**
        Sets the text control as growable when @c grow is @true.

        This function can be used only when HasTextCtrl() returns @true.
    */
    void SetTextCtrlGrowable(bool grow = true);

    /**
        Sets the proportion value of the text control.

        Look at the detailed description of wxPickerBase for more info.

        This function can be used only when HasTextCtrl() returns @true.
    */
    void SetTextCtrlProportion(int prop);
};

