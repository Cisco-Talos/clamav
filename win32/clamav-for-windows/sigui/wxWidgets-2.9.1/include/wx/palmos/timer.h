/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/timer.h
// Purpose:     wxTimer class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_TIMER_H_
#define _WX_TIMER_H_

class WXDLLIMPEXP_BASE wxTimer : public wxTimerBase
{
friend void wxProcessTimer(wxTimer& timer);

public:
    wxTimer() { Init(); }
    wxTimer(wxEvtHandler *owner, int id = -1) : wxTimerBase(owner, id)
        { Init(); }
    virtual ~wxTimer();

    virtual bool Start(int milliseconds = -1, bool oneShot = FALSE);
    virtual void Stop();

    virtual bool IsRunning() const { return m_id != 0; }

protected:
    void Init();

    unsigned long m_id;

private:
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxTimer)
};

#endif
    // _WX_TIMERH_
