/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/datectrl.h
// Purpose:     wxDatePickerCtrl for PalmOS
// Author:      Wlodzimierz ABX Skiba
// Modified by:
// Created:     02/15/05
// RCS-ID:      $Id$
// Copyright:   (c) Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_PALMOS_DATECTRL_H_
#define _WX_PALMOS_DATECTRL_H_

// ----------------------------------------------------------------------------
// wxDatePickerCtrl
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_ADV wxDatePickerCtrl : public wxDatePickerCtrlBase
{
public:
    // ctors
    wxDatePickerCtrl() { Init(); }

    wxDatePickerCtrl(wxWindow *parent,
                     wxWindowID id,
                     const wxDateTime& dt = wxDefaultDateTime,
                     const wxPoint& pos = wxDefaultPosition,
                     const wxSize& size = wxDefaultSize,
                     long style = wxDP_DEFAULT | wxDP_SHOWCENTURY,
                     const wxValidator& validator = wxDefaultValidator,
                     const wxString& name = wxDatePickerCtrlNameStr)
    {
        Init();
        Create(parent, id, dt, pos, size, style, validator, name);
    }

    bool Create(wxWindow *parent,
                wxWindowID id,
                const wxDateTime& dt = wxDefaultDateTime,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxDP_DEFAULT | wxDP_SHOWCENTURY,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxDatePickerCtrlNameStr);

    // set/get the date
    virtual void SetValue(const wxDateTime& dt);
    virtual wxDateTime GetValue() const;

    // set/get the allowed valid range for the dates, if either/both of them
    // are invalid, there is no corresponding limit and if neither is set
    // GetRange() returns false
    virtual void SetRange(const wxDateTime& dt1, const wxDateTime& dt2);
    virtual bool GetRange(wxDateTime *dt1, wxDateTime *dt2) const;

    // send a notification event, return true if processed
    bool SendClickEvent();

protected:
    virtual wxSize DoGetBestSize() const;

private:
    wxDateTime m_dt;

    void Init() { m_dt = wxDateTime::Today(); }


    DECLARE_DYNAMIC_CLASS_NO_COPY(wxDatePickerCtrl)
};

#endif // _WX_PALMOS_DATECTRL_H_
