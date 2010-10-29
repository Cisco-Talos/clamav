///////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/evtloop.cpp
// Purpose:     implements wxGUIEventLoop for Palm OS
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10.14.04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/window.h"
    #include "wx/app.h"
#endif //WX_PRECOMP

#include "wx/evtloop.h"

#include "wx/tooltip.h"
#include "wx/except.h"

#if wxUSE_THREADS
    #include "wx/thread.h"

    // define the array of MSG strutures
    WX_DECLARE_OBJARRAY(MSG, wxMsgArray);

    #include "wx/arrimpl.cpp"

    WX_DEFINE_OBJARRAY(wxMsgArray);
#endif // wxUSE_THREADS

#include <Event.h>
#include <SystemMgr.h>
#include <Menu.h>
#include <Form.h>

// ============================================================================
// wxGUIEventLoop implementation
// ============================================================================

// ----------------------------------------------------------------------------
// ctor/dtor
// ----------------------------------------------------------------------------

wxGUIEventLoop::wxGUIEventLoop()
{
    m_shouldExit = false;
    m_exitcode = 0;
}

// ----------------------------------------------------------------------------
// wxGUIEventLoop message processing
// ----------------------------------------------------------------------------

void wxGUIEventLoop::ProcessMessage(WXMSG *msg)
{
}

bool wxGUIEventLoop::PreProcessMessage(WXMSG *msg)
{
    return false;
}

// ----------------------------------------------------------------------------
// wxGUIEventLoop running and exiting
// ----------------------------------------------------------------------------

bool wxGUIEventLoop::IsRunning() const
{
    return true;
}

int wxGUIEventLoop::Run()
{
    status_t    error;
    EventType    event;

    wxEventLoopActivator activate(this);

    do {
        wxTheApp && wxTheApp->ProcessIdle();

        EvtGetEvent(&event, evtWaitForever);

        if (SysHandleEvent(&event))
            continue;

        if (MenuHandleEvent(0, &event, &error))
            continue;

        FrmDispatchEvent(&event);

    } while (event.eType != appStopEvent);

    return 0;
}

void wxGUIEventLoop::Exit(int rc)
{
    FrmCloseAllForms();

    EventType AppStop;
    AppStop.eType=appStopEvent;
    EvtAddEventToQueue(&AppStop);
}

// ----------------------------------------------------------------------------
// wxGUIEventLoop message processing dispatching
// ----------------------------------------------------------------------------

bool wxGUIEventLoop::Pending() const
{
    return false;
}

bool wxGUIEventLoop::Dispatch()
{
    return false;
}

int wxGUIEventLoop::DispatchTimeout(unsigned long timeout)
{
    return -1;
}

void wxGUIEventLoop::WakeUp()
{
    return;
}

bool wxGUIEventLoop::YieldFor(long eventsToProcess)
{
    return true;
}

