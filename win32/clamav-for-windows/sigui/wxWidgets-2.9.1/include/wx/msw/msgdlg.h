/////////////////////////////////////////////////////////////////////////////
// Name:        wx/msw/msgdlg.h
// Purpose:     wxMessageDialog class
// Author:      Julian Smart
// Modified by:
// Created:     01/02/97
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_MSGBOXDLG_H_
#define _WX_MSGBOXDLG_H_

class WXDLLIMPEXP_CORE wxMessageDialog : public wxMessageDialogWithCustomLabels
{
public:
    wxMessageDialog(wxWindow *parent,
                    const wxString& message,
                    const wxString& caption = wxMessageBoxCaptionStr,
                    long style = wxOK|wxCENTRE,
                    const wxPoint& WXUNUSED(pos) = wxDefaultPosition)
        : wxMessageDialogWithCustomLabels(parent, message, caption, style)
    {
        m_hook = NULL;
    }

    virtual int ShowModal();

    // implementation-specific

    // return the font used for the text in the message box
    static wxFont GetMessageFont();

private:
    // hook procedure used to adjust the message box beyond what the standard
    // MessageBox() function can do for us
    static WXLRESULT wxCALLBACK HookFunction(int code, WXWPARAM, WXLPARAM);

    static const struct ButtonAccessors
    {
        int id;
        wxString (wxMessageDialog::*getter)() const;
    } ms_buttons[];

    // replace the static text control with a text control in order to show
    // scrollbar (and also, incidentally, allow text selection)
    void ReplaceStaticWithEdit();

    // adjust the button labels
    //
    // this is called from HookFunction() and our HWND is valid at this moment
    void AdjustButtonLabels();

    // offset all buttons starting from the first one given by dx to the right
    void OffsetButtonsStartingFrom(int first, int dx);


    WXHANDLE m_hook; // HHOOK used to position the message box

    DECLARE_DYNAMIC_CLASS(wxMessageDialog)
    wxDECLARE_NO_COPY_CLASS(wxMessageDialog);
};


#endif // _WX_MSGBOXDLG_H_
