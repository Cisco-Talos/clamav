/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/private/timer.h
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

#include "wx/private/timer.h"

class WXDLLIMPEXP_CORE wxPalmOSTimerImpl : public wxTimerImpl
{
friend void wxProcessTimer(wxTimer& timer);

public:
    wxPalmOSTimerImpl(wxTimer* timer) : wxTimerImpl(timer) { Init(); }
    virtual ~wxPalmOSTimerImpl();

    virtual bool Start(int milliseconds = -1, bool oneShot = FALSE);
    virtual void Stop();

    virtual bool IsRunning() const { return m_id != 0; }

protected:
    void Init();

    unsigned long m_id;
};

#endif
    // _WX_TIMERH_
