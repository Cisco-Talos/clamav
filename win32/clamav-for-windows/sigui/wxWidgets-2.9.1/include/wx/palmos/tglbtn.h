/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/tglbtn.h
// Purpose:     Declaration of the wxToggleButton class, which implements a
//              toggle button under Palm OS.
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - native implementation
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_TOGGLEBUTTON_H_
#define _WX_TOGGLEBUTTON_H_

#include "wx/checkbox.h" // wxCheckBoxNameStr, in datacmn.cpp
//WXDLLIMPEXP_DATA_CORE(extern const wxChar) wxCheckBoxNameStr[];

// Checkbox item (single checkbox)
class WXDLLIMPEXP_CORE wxToggleButton : public wxToggleButtonBase
{
public:
    wxToggleButton() {}
    wxToggleButton(wxWindow *parent,
                   wxWindowID id,
                   const wxString& label,
                   const wxPoint& pos = wxDefaultPosition,
                   const wxSize& size = wxDefaultSize,
                   long style = 0,
                   const wxValidator& validator = wxDefaultValidator,
                   const wxString& name = wxCheckBoxNameStr)
    {
        Create(parent, id, label, pos, size, style, validator, name);
    }

    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxString& label,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxCheckBoxNameStr);

    virtual void SetValue(bool value);
    virtual bool GetValue() const ;

    virtual void Command(wxCommandEvent& event);

    // send a notification event, return true if processed
    bool SendClickEvent();

protected:
    virtual wxSize DoGetBestSize() const;
    virtual wxBorder GetDefaultBorder() const;

private:
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxToggleButton)
};

#endif // _WX_TOGGLEBUTTON_H_

