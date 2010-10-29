/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/timer.cpp
// Purpose:     wxTimer implementation
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/motif/private/timer.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/hashmap.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

WX_DECLARE_VOIDPTR_HASH_MAP(wxMotifTimerImpl*, wxTimerHashMap);

static wxTimerHashMap gs_timers;

void wxTimerCallback (wxMotifTimerImpl *timer)
{
    // Check to see if it's still on
    if ( gs_timers.find(timer) == gs_timers.end() )
        return;

    if ( !timer->IsRunning() )
        return;            // Avoid to process spurious timer events

    timer->Notify();
}

wxMotifTimerImpl::~wxMotifTimerImpl()
{
    gs_timers.erase(this);
}

void wxMotifTimerImpl::DoStart()
{
    m_id = XtAppAddTimeOut((XtAppContext) wxTheApp->GetAppContext(),
                            m_milli,
                            (XtTimerCallbackProc) wxTimerCallback,
                            (XtPointer) this);
}

bool wxMotifTimerImpl::Start(int milliseconds, bool mode)
{
    if ( !wxTimerImpl::Start(milliseconds, mode) )
        return false;

    if ( gs_timers.find(this) == gs_timers.end() )
        gs_timers[this] = this;

    DoStart();

    return true;
}

void wxMotifTimerImpl::Stop()
{
    XtRemoveTimeOut (m_id);
    m_id = 0;
}

void wxMotifTimerImpl::Notify()
{
    if ( IsOneShot() )
    {
        // nothing to do, timeout is removed automatically by X
        m_id = 0;
    }
    else // rearm the timer
    {
        DoStart();
    }

    wxTimerImpl::Notify();
}

