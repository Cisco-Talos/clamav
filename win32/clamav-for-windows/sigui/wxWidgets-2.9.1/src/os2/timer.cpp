/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/timer.cpp
// Purpose:     wxTimer implementation
// Author:      David Webster
// Modified by:
// Created:     10/17/99
// RCS-ID:      $Id$
// Copyright:   (c) David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/os2/private/timer.h"

#ifndef WX_PRECOMP
    #include "wx/list.h"
    #include "wx/window.h"
    #include "wx/event.h"
    #include "wx/app.h"
    #include "wx/intl.h"
    #include "wx/log.h"
#endif

#include "wx/os2/private.h"

#include <time.h>
#include <sys/types.h>

#include <sys/timeb.h>

// ----------------------------------------------------------------------------
// private globals
// ----------------------------------------------------------------------------

// define a hash containing all the timers: it is indexed by timer id and
// contains the corresponding timer
WX_DECLARE_HASH_MAP(unsigned long, wxOS2TimerImpl *, wxIntegerHash, wxIntegerEqual,
                    wxTimerMap);

// instead of using a global here, wrap it in a static function as otherwise it
// could have been used before being initialized if a timer object were created
// globally
static wxTimerMap& TimerMap()
{
    static wxTimerMap s_timerMap;

    return s_timerMap;
}

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

// timer callback used for all timers
ULONG wxTimerProc(HWND hwnd, ULONG, int nIdTimer, ULONG);

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxTimer class
// ----------------------------------------------------------------------------

bool wxOS2TimerImpl::Start( int nMilliseconds, bool bOneShot )
{
    if ( !wxTimerImpl::Start( nMilliseconds, bOneShot ) )
        return false;

    wxWindow* pWin = NULL;

    if (m_owner)
    {
        pWin = (wxWindow*)m_owner;
        m_ulId = ::WinStartTimer( m_Hab
                                 ,pWin->GetHWND()
                                 ,m_idTimer
                                 ,(ULONG)nMilliseconds
                                );
    }
    else
    {
        m_ulId = ::WinStartTimer( m_Hab
                                 ,NULLHANDLE
                                 ,0
                                 ,(ULONG)nMilliseconds
                                );
    }

    if (m_ulId > 0L)
    {
        // check that SetTimer() didn't reuse an existing id: according to
        // the MSDN this can happen and this would be catastrophic to us as
        // we rely on ids uniquely identifying the timers because we use
        // them as keys in the hash
        if ( TimerMap().find(m_ulId) != TimerMap().end() )
        {
            wxLogError(_("Timer creation failed."));

            ::WinStopTimer(m_Hab, pWin?(pWin->GetHWND()):NULL, m_ulId);
            m_ulId = 0;

            return false;
        }

        TimerMap()[m_ulId] = this;

        return true;
    }
    else
    {
        wxLogSysError(_("Couldn't create a timer"));

        return false;
    }
}

void wxOS2TimerImpl::Stop()
{
    if ( m_ulId )
    {
        if (m_owner)
        {
            wxWindow*                   pWin = (wxWindow*)m_owner;

            ::WinStopTimer(m_Hab, pWin->GetHWND(), m_ulId);
        }
        else
            ::WinStopTimer(m_Hab, NULLHANDLE, m_ulId);

        TimerMap().erase(m_ulId);
    }
    m_ulId = 0L;
}

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

void wxProcessTimer(
  wxOS2TimerImpl&                          rTimer
)
{
    //
    // Avoid to process spurious timer events
    //
    if (rTimer.m_ulId == 0L)
        return;

    if (rTimer.IsOneShot())
        rTimer.Stop();

    rTimer.Notify();
}

ULONG wxTimerProc(
  HWND                              WXUNUSED(hwnd)
, ULONG
, int                               nIdTimer
, ULONG
)
{
    wxTimerMap::iterator node = TimerMap().find((ULONG)nIdTimer);

    wxCHECK_MSG(node != TimerMap().end(), 0,
                wxT("bogus timer id in wxTimerProc") );
    wxProcessTimer(*(node->second));
    return 0;
}
