///////////////////////////////////////////////////////////////////////////////
// Name:        wx/cocoa/evtloop.h
// Purpose:     declaration of wxGUIEventLoop for wxCocoa
// Author:      Vadim Zeitlin
// Created:     2008-12-28
// RCS-ID:      $Id$
// Copyright:   (c) 2008 Vadim Zeitlin <vadim@wxwidgets.org>
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#ifndef _WX_COCOA_EVTLOOP_H_
#define _WX_COCOA_EVTLOOP_H_

// ----------------------------------------------------------------------------
// wxGUIEventLoop for wxCocoa
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxGUIEventLoop : public wxEventLoopBase
{
public:
    wxGUIEventLoop() { m_exitcode = 0; }

    virtual int Run();
    virtual void Exit(int rc = 0);
    virtual bool Pending() const;
    virtual bool Dispatch();
    virtual int DispatchTimeout(unsigned long timeout);
    virtual void WakeUp() { }
    virtual bool YieldFor(long eventsToProcess);

protected:
    int m_exitcode;

    wxDECLARE_NO_COPY_CLASS(wxGUIEventLoop);
};

#endif // _WX_COCOA_EVTLOOP_H_

