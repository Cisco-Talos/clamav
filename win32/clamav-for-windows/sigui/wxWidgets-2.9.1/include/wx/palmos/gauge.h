/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/gauge.h
// Purpose:     wxGauge class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _GAUGE_H_
#define _GAUGE_H_

#if wxUSE_GAUGE

WXDLLIMPEXP_DATA_CORE(extern const wxChar) wxGaugeNameStr[];

// Group box
class WXDLLIMPEXP_CORE wxGauge : public wxGaugeBase
{
public:
    wxGauge() { }

    wxGauge(wxWindow *parent,
              wxWindowID id,
              int range,
              const wxPoint& pos = wxDefaultPosition,
              const wxSize& size = wxDefaultSize,
              long style = wxGA_HORIZONTAL,
              const wxValidator& validator = wxDefaultValidator,
              const wxString& name = wxGaugeNameStr)
    {
        (void)Create(parent, id, range, pos, size, style, validator, name);
    }

    bool Create(wxWindow *parent,
                wxWindowID id,
                int range,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxGA_HORIZONTAL,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxGaugeNameStr);

    // set gauge range/value
    virtual void SetRange(int range);
    virtual void SetValue(int pos);

    // overriden base class virtuals
    virtual bool SetForegroundColour(const wxColour& col);
    virtual bool SetBackgroundColour(const wxColour& col);

protected:
    virtual WXDWORD MSWGetStyle(long style, WXDWORD *exstyle) const;
    virtual wxSize DoGetBestSize() const;


    DECLARE_DYNAMIC_CLASS_NO_COPY(wxGauge)
};

#endif // wxUSE_GAUGE

#endif
    // _GAUGE_H_
