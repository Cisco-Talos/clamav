/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/slider.h
// Purpose:     wxSlider class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Wlodzimierz ABX Skiba - native implementation
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne, Wlodzimierz Skiba
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _SLIDERPALM_H_
#define _SLIDERPALM_H_

// Slider
class WXDLLIMPEXP_CORE wxSlider : public wxSliderBase
{
public:
    wxSlider()
    {
        Init();
    }

    wxSlider(wxWindow *parent, wxWindowID id,
            int value, int minValue, int maxValue,
            const wxPoint& pos = wxDefaultPosition,
            const wxSize& size = wxDefaultSize,
            long style = wxSL_HORIZONTAL,
            const wxValidator& validator = wxDefaultValidator,
            const wxString& name = wxSliderNameStr)
    {
        Init();
        Create(parent, id, value, minValue, maxValue, pos, size, style, validator, name);
    }

    virtual ~wxSlider();

    bool Create(wxWindow *parent, wxWindowID id,
            int value, int minValue, int maxValue,
            const wxPoint& pos = wxDefaultPosition,
            const wxSize& size = wxDefaultSize,
            long style = wxSL_HORIZONTAL,
            const wxValidator& validator = wxDefaultValidator,
            const wxString& name = wxSliderNameStr);

    virtual int GetValue() const;
    virtual void SetValue(int);

    void SetRange(int minValue, int maxValue);

    int GetMin() const;
    int GetMax() const;

    // For trackbars only
    void SetTickFreq(int n, int pos);
    int GetTickFreq() const;
    void SetPageSize(int pageSize);
    int GetPageSize() const;
    void ClearSel();
    void ClearTicks();
    void SetLineSize(int lineSize);
    int GetLineSize() const;
    int GetSelEnd() const;
    int GetSelStart() const;
    void SetSelection(int minPos, int maxPos);
    void SetThumbLength(int len);
    int GetThumbLength() const;
    void SetTick(int tickPos);

    // implementation
    void Command(wxCommandEvent& event);

    // send a notification event, return true if processed
    bool SendUpdatedEvent();
    bool SendScrollEvent(WXEVENTPTR event);

protected:

    virtual wxSize DoGetBestSize() const;

private:

    void Init();

    int m_oldPos;    // needed for tracing thumb position during scrolling
    int m_oldValue;  // needed for comparing thumb position before and after scrolling
    int m_lineSize;  // imitate line size

    DECLARE_DYNAMIC_CLASS_NO_COPY(wxSlider)
};

#endif
    // _SLIDERPALM_H_
