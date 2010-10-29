/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/timer.cpp
// Purpose:     wxTimer implementation
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_TIMER

#include "wx/palmos/private/timer.h"

#ifndef WX_PRECOMP
    #include "wx/list.h"
    #include "wx/window.h"
    #include "wx/event.h"
    #include "wx/app.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/hashmap.h"
#endif

// ----------------------------------------------------------------------------
// private globals
// ----------------------------------------------------------------------------

// define a hash containing all the timers: it is indexed by timer id and
// contains the corresponding timer
WX_DECLARE_HASH_MAP(unsigned long, wxPalmOSTimerImpl*, wxIntegerHash, wxIntegerEqual,
                    wxTimerMap);

static wxTimerMap g_timerMap;

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxTimer class
// ----------------------------------------------------------------------------

void wxPalmOSTimerImpl::Init()
{
}

wxPalmOSTimerImpl::~wxPalmOSTimerImpl()
{
}

bool wxPalmOSTimerImpl::Start(int milliseconds, bool oneShot)
{
    return false;
}

void wxPalmOSTimerImpl::Stop()
{
}

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

void wxProcessTimer(wxPalmOSTimerImpl& timer)
{
}

#endif // wxUSE_TIMER
