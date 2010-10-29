///////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/apptrait.h
// Purpose:     class implementing wxAppTraits for Palm OS
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Yunhui Fu
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#ifndef _WX_PALM_APPTRAIT_H_
#define _WX_PALM_APPTRAIT_H_

#if wxUSE_TIMER
#include "wx/palmos/private/timer.h" // wxPalmOSTimerImpl
#endif // wxUSE_TIMER

// ----------------------------------------------------------------------------
// wxGUI/ConsoleAppTraits: must derive from wxAppTraits, not wxAppTraitsBase
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_BASE wxConsoleAppTraits : public wxConsoleAppTraitsBase
{
public:
#if wxUSE_CONSOLE_EVENTLOOP
    virtual wxEventLoopBase *CreateEventLoop();
#endif // wxUSE_CONSOLE_EVENTLOOP
    virtual void *BeforeChildWaitLoop();
    virtual void AfterChildWaitLoop(void *data);
#if wxUSE_TIMER
    virtual wxTimerImpl *CreateTimerImpl(wxTimer *timer) { return new wxPalmOSTimerImpl(timer); }
#endif
    virtual bool DoMessageFromThreadWait();
    virtual WXDWORD WaitForThread(WXHANDLE hThread);
};

#if wxUSE_GUI

class WXDLLIMPEXP_CORE wxGUIAppTraits : public wxGUIAppTraitsBase
{
public:
    virtual wxEventLoopBase *CreateEventLoop();
    virtual void *BeforeChildWaitLoop();
    virtual void AfterChildWaitLoop(void *data);
#if wxUSE_TIMER
    // there is no wxTimer support yet
    virtual wxTimerImpl *CreateTimerImpl(wxTimer *timer);
#endif
    virtual bool DoMessageFromThreadWait();
    virtual wxPortId GetToolkitVersion(int *majVer = NULL, int *minVer = NULL) const;
};

#endif // wxUSE_GUI

#endif // _WX_PALM_APPTRAIT_H_

