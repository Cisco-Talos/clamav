/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/button.h
// Purpose:     wxButton class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - native wxButton implementation
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_BUTTON_H_
#define _WX_BUTTON_H_

// ----------------------------------------------------------------------------
// Pushbutton
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxButton : public wxButtonBase
{
public:
    wxButton() { }
    wxButton(wxWindow *parent,
             wxWindowID id,
             const wxString& label = wxEmptyString,
             const wxPoint& pos = wxDefaultPosition,
             const wxSize& size = wxDefaultSize,
             long style = 0,
             const wxValidator& validator = wxDefaultValidator,
             const wxString& name = wxButtonNameStr)
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
                const wxString& name = wxButtonNameStr);

    virtual ~wxButton();

    virtual wxWindow *SetDefault();

    // implementation from now on
    virtual void Command(wxCommandEvent& event);

    // send a notification event, return true if processed
    bool SendClickEvent();

protected:

    // default button handling
    void SetTmpDefault();
    void UnsetTmpDefault();

    // set or unset BS_DEFPUSHBUTTON style
    static void SetDefaultStyle(wxButton *btn, bool on);

    // usually overridden base class virtuals
    virtual wxSize DoGetBestSize() const;

private:
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxButton)
};

#endif
    // _WX_BUTTON_H_
