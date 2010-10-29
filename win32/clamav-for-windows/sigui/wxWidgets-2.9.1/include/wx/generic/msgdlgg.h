/////////////////////////////////////////////////////////////////////////////
// Name:        wx/generic/msgdlgg.h
// Purpose:     Generic wxMessageDialog
// Author:      Julian Smart
// Modified by:
// Created:     01/02/97
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_GENERIC_MSGDLGG_H_
#define _WX_GENERIC_MSGDLGG_H_

class WXDLLIMPEXP_CORE wxGenericMessageDialog : public wxMessageDialogBase
{
public:
    wxGenericMessageDialog(wxWindow *parent,
                           const wxString& message,
                           const wxString& caption = wxMessageBoxCaptionStr,
                           long style = wxOK|wxCENTRE,
                           const wxPoint& pos = wxDefaultPosition);

    virtual int ShowModal();

protected:
    void OnYes(wxCommandEvent& event);
    void OnNo(wxCommandEvent& event);
    void OnCancel(wxCommandEvent& event);

private:
    void DoCreateMsgdialog();

    wxPoint m_pos;
    bool m_created;

    DECLARE_EVENT_TABLE()
    DECLARE_DYNAMIC_CLASS(wxGenericMessageDialog)
};

#endif // _WX_GENERIC_MSGDLGG_H_
