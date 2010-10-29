/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/radiobut.h
// Purpose:     wxRadioButton class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - native wxRadioButton implementation
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_RADIOBUT_H_
#define _WX_RADIOBUT_H_

class WXDLLIMPEXP_CORE wxRadioButton: public wxControl
{
public:
    // ctors and creation functions
    wxRadioButton() { Init(); }

    wxRadioButton(wxWindow *parent,
                  wxWindowID id,
                  const wxString& label,
                  const wxPoint& pos = wxDefaultPosition,
                  const wxSize& size = wxDefaultSize,
                  long style = 0,
                  const wxValidator& validator = wxDefaultValidator,
                  const wxString& name = wxRadioButtonNameStr)
    {
        Init();

        Create(parent, id, label, pos, size, style, validator, name);
    }

    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxString& label,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxRadioButtonNameStr);

    // implement the radio button interface
    virtual void SetValue(bool value);
    virtual bool GetValue() const;

    // implementation only from now on
    virtual void Command(wxCommandEvent& event);
    void SetGroup(uint8_t group);

    // send a notification event, return true if processed
    bool SendClickEvent();

protected:
    virtual wxSize DoGetBestSize() const;

private:
    // common part of all ctors
    void Init();

    uint8_t m_groupID;

    // pushButtonCtl or checkboxCtl
    int m_radioStyle;
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxRadioButton)
};

#endif
    // _WX_RADIOBUT_H_
